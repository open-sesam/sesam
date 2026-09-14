package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"filippo.io/age"
	"golang.org/x/sync/errgroup"
)

// SecretManager is the high level API to manage secrets,
// i.e. seal & reveal them and also add/remove/change secrets.
type SecretManager struct {
	// SesamDir is the absolute path to the sesam repository (the dir the
	// .sesam directory is in). It is kept only for operations that cannot go
	// through root: the renameat2 directory swap and handing paths to git.
	SesamDir string

	// root confines all of sesam's own file I/O to the repository. Every
	// path passed to it is relative to SesamDir.
	root *os.Root

	// Identities are the private keys the current user of sesam supplies.
	Identities Identities

	// Signer is our way to sign things with a per-user generated key.
	Signer Signer

	// Keyring is a collection of public keys
	Keyring Keyring

	// AuditLog is the log we can write our new entries to.
	AuditLog *AuditLog

	// State is the state won by replaying the audit log.
	State *VerifiedState

	base string
}

// SealAdvice is what a caller already knows about one plaintext, so Seal does
// not have to compare it with its object again. The zero value compares.
type SealAdvice int

const (
	// AdviceCompare decides by comparing plaintext and object (NeedsSeal).
	AdviceCompare SealAdvice = iota

	// AdviceChanged: the plaintext changed, seal it.
	AdviceChanged

	// AdviceUnchanged: the plaintext matches the object, reseal only when the
	// recipients changed.
	AdviceUnchanged

	// AdviceKeep: the plaintext is older than the object, leave the object alone.
	AdviceKeep
)

// ObjectMatch is how the plaintext of a secret relates to one sealed object -
// not necessarily the one on disk: any version git holds can be asked.
type ObjectMatch struct {
	// Content: the plaintext is what this object was sealed from.
	Content bool

	// Recipients: the object was sealed for the recipients the secret has now.
	Recipients bool
}

// SetBase points the manager's sesam-internal paths at base (a stage's fork
// dir, e.g. ".sesam-tmp"). Worktree (plaintext) paths are unaffected. Must be
// called before any sealing if the manager operates on a stage.
func (sm *SecretManager) SetBase(base string) { sm.base = base }

// BuildSecretManager uses the passed facilities to build a new SecretManager.
// root confines all file I/O to the repository; sesamDir is its absolute path,
// kept for the directory swap and git interop. `base` is the sesam-internal
// prefix the manager works under ("" for the live tree, a stage's fork dir
// otherwise) - it has to be known here because the scratch dir is scrubbed
// below, and a fork must not empty the live one.
func BuildSecretManager(
	sesamDir string,
	root *os.Root,
	identities Identities,
	signer Signer,
	keyring Keyring,
	log *AuditLog,
	state *VerifiedState,
	base string,
) (*SecretManager, error) {
	mgr := &SecretManager{
		SesamDir:   sesamDir,
		root:       root,
		Identities: identities,
		Signer:     signer,
		Keyring:    keyring,
		AuditLog:   log,
		State:      state,
		base:       base,
	}

	// Clear tmp dir before continuing:
	tmpDir := sesamTmpDir(base)
	_ = root.RemoveAll(tmpDir)
	_ = root.MkdirAll(tmpDir, 0o700)

	return mgr, nil
}

// recipientsFor returns the recipients that may reveal `revealedPath`,
// derived from the current verified state and keyring. The set of secrets
// lives in sm.State.Secrets - the source of truth - so the recipient list
// is always recomputed here rather than cached.
func (sm *SecretManager) recipientsFor(revealedPath string) Recipients {
	return sm.Keyring.Recipients(sm.State.UsersForSecret(revealedPath))
}

// The path helpers return repo-relative paths (relative to SesamDir). Callers
// needing an absolute path (the directory swap, the external git-diff tree)
// join them with SesamDir explicitly.

func (sm *SecretManager) cryptPath(path string) string {
	return filepath.Join(sm.objectsDir(), path+".sesam")
}

func (sm *SecretManager) objectsDir() string {
	return filepath.Join(sesamBase(sm.base), "objects")
}

// SealedPath returns the repo-relative path of the encrypted object for path.
func (sm *SecretManager) SealedPath(path string) string {
	return sm.cryptPath(path)
}

// SecretAdd adds a new secret to be managed by sesam. It returns the resulting
// verified secret, or nil when nothing changed.
func (sm *SecretManager) SecretAdd(revealedPath string, groups []string, additive bool) (*VerifiedSecret, error) {
	return sm.addOrChangeSecret(revealedPath, groups, additive)
}

// SecretChangeGroups changes the access groups for the secret at `revealedPath`.
func (sm *SecretManager) SecretChangeGroups(revealedPath string, groups []string) error {
	if _, err := sm.addOrChangeSecret(revealedPath, groups, false); err != nil {
		return err
	}
	return nil
}

// addOrChangeSecret emits a secret.add entry for a new secret and a
// secret.change_access entry for an existing one, deciding which based on
// whether the secret is already known. When additive and the secret exists, the
// given groups are merged into its current access list rather than replacing
// it. It returns the resulting verified secret.
func (sm *SecretManager) addOrChangeSecret(revealedPath string, groups []string, additive bool) (*VerifiedSecret, error) {
	if err := validSecretPath(sm.root, revealedPath); err != nil {
		return nil, fmt.Errorf("invalid secret path (%s): %w", revealedPath, err)
	}

	var auditEntry *AuditEntry
	existing, exists := sm.State.SecretExists(revealedPath)
	if !exists {
		// Secret does not exist yet: this is an add.
		auditEntry = newAuditEntry(sm.Signer.UserName(), &DetailSecretAdd{
			RevealedPath: revealedPath,
			AccessGroups: groups,
		})
	} else {
		if additive {
			// "admin" is implicit for secrets, so strip it from the current
			// list before merging to keep it out of the persisted set.
			groups = unionGroups(withoutAdmin(existing.AccessGroups), groups)
		}

		if len(groups) == 0 {
			// if no groups were given, there is nothing to change.
			return existing, nil
		}

		// Secret already exists: this is an access-list change.
		auditEntry = newAuditEntry(sm.Signer.UserName(), &DetailSecretChangeAccess{
			RevealedPath: revealedPath,
			AccessGroups: groups,
		})
	}

	if err := sm.State.FeedEntry(sm.Signer, auditEntry); err != nil {
		return nil, err
	}

	vs, _ := sm.State.SecretExists(revealedPath)
	return vs, nil
}

// Seal (re-)seals the known secrets. With all=false only secrets whose plaintext
// or recipient set drifted are re-encrypted; unchanged ones keep their existing
// ciphertext. When nothing was re-sealed or pruned, no audit entry is written,
// so a no-op seal (e.g. the pre-commit hook on a commit that touched no secrets)
// does not churn the log.
// Seal writes every secret's plaintext into its object. `all` reseals even what
// is in sync; otherwise `advice` (may be nil) says per plaintext what is already
// known about it, and everything else is compared with its object.
func (sm *SecretManager) Seal(all bool, advice map[string]SealAdvice) error {
	objects := sm.objectsDir()
	if err := sm.root.MkdirAll(objects, 0o700); err != nil {
		return fmt.Errorf("create objects dir: %w", err)
	}

	// jobs are partly I/O bound, so allow more than we have cores.
	parallelJobs := 4 * runtime.GOMAXPROCS(0)
	errg := &errgroup.Group{}
	errg.SetLimit(parallelJobs)

	mu := sync.Mutex{}
	wanted := make(map[string]bool, len(sm.State.Secrets))
	sigs := make([]*secretFooter, 0, len(sm.State.Secrets))

	for _, vsecret := range sm.State.Secrets {
		errg.Go(func() error {
			sig, err := sm.sealOrPreserve(vsecret.RevealedPath, all, advice[vsecret.RevealedPath])
			if err != nil {
				return fmt.Errorf("seal %s: %w", vsecret.RevealedPath, err)
			}

			mu.Lock()
			wanted[sm.cryptPath(vsecret.RevealedPath)] = true
			sigs = append(sigs, sig)
			mu.Unlock()
			return nil
		})
	}

	if err := errg.Wait(); err != nil {
		return err
	}

	// safety net: remove left over files or anything that was manually created.
	if err := sm.pruneObjects(wanted); err != nil {
		return fmt.Errorf("prune stale objects: %w", err)
	}

	// Check if the root hash actually changed, we might be able to just skip
	// adding the seal entry because nothing effectively happened.
	//
	// The exception are operations like "adding a user that has access to nothing"
	// That will still trigger the warning that we should seal, but in this case
	// we can just append the audit entry anyways.
	rootHash := buildRootHash(sigs)
	if rootHash == sm.State.LastSealRootHash && sm.State.SealRequiredSeqID == 0 {
		return nil
	}

	return sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSeal{
			RootHash:    rootHash,
			FilesSealed: len(sigs),
		}),
	)
}

// sealOrPreserve seals revealedPath in place under objects/. With access to the
// plaintext it re-encrypts (renameio replaces the object); otherwise it leaves
// the existing ciphertext untouched and reads back its footer. It is an error
// if there is neither plaintext nor an existing object.
func (sm *SecretManager) sealOrPreserve(revealedPath string, all bool, advice SealAdvice) (*secretFooter, error) {
	dest := sm.cryptPath(revealedPath)
	if err := sm.root.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return nil, fmt.Errorf("create objects subdir: %w", err)
	}

	switch _, err := sm.root.Stat(revealedPath); {
	case err == nil:
		sealer := sm.Signer.UserName()
		if sm.State.SealerAuthorized(sealer, revealedPath) {
			seal, footer, err := sm.decideSeal(revealedPath, all, advice)
			if err != nil {
				return nil, fmt.Errorf("failed to check whether reseal is needed: %w", err)
			}

			if !seal {
				return footer, nil
			}

			return sealSecret(sm, revealedPath, sm.recipientsFor(revealedPath), dest, sealer)
		}

		// Expected for non-recipients: they cannot re-seal what they cannot
		// read, so the existing ciphertext is preserved below. Debug, not Warn.
		slog.Debug(
			"not re-sealing path: user not authorized, preserving existing ciphertext",
			slog.String("user", sealer),
			slog.String("path", revealedPath),
		)
	case !os.IsNotExist(err):
		return nil, fmt.Errorf("stat plaintext: %w", err)
	}

	// No (authorized) plaintext: the existing ciphertext stays in place.
	if _, err := sm.root.Stat(dest); err != nil {
		return nil, fmt.Errorf(
			"no plaintext at %q and no existing ciphertext at %q",
			revealedPath, dest,
		)
	}

	return sm.readSecretFooter(dest)
}

// decideSeal says whether the plaintext at revealedPath has to be sealed. When
// it read the existing object's footer on the way, it hands that back so the
// caller need not read it again.
func (sm *SecretManager) decideSeal(revealedPath string, all bool, advice SealAdvice) (bool, *secretFooter, error) {
	switch {
	case all, advice == AdviceChanged:
		return true, nil, nil
	case advice == AdviceKeep, advice == AdviceUnchanged:
		footer, err := sm.readSecretFooter(sm.cryptPath(revealedPath))
		if errors.Is(err, os.ErrNotExist) {
			// Nothing to keep or compare with; the plaintext is all there is.
			return true, nil, nil
		}
		if err != nil {
			return false, nil, err
		}

		if advice == AdviceKeep {
			return false, footer, nil
		}

		drifted, err := sm.recipientsDrifted(footer, revealedPath)
		return drifted, footer, err
	default:
		return sm.needsSeal(revealedPath)
	}
}

// pruneObjects removes object files under objects/ whose sesam-relative path is
// not in `wanted` (the set just sealed/preserved). Empty directories are left in
// place.
func (sm *SecretManager) pruneObjects(wanted map[string]bool) error {
	objects := sm.objectsDir()
	if _, err := sm.root.Stat(objects); os.IsNotExist(err) {
		return nil
	}

	var stale []string
	err := fs.WalkDir(sm.root.FS(), filepath.ToSlash(objects), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".sesam") {
			return nil
		}
		if rel := filepath.FromSlash(p); !wanted[rel] {
			stale = append(stale, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, p := range stale {
		if err := sm.root.Remove(p); err != nil {
			return fmt.Errorf("remove stale object %s: %w", p, err)
		}
	}

	// Drop directories left empty by the removals. The old stage->objects swap
	// rebuilt the tree and never carried empty dirs; this keeps that property.
	if _, err := PruneEmptyDirs(sm.root, objects, nil, nil); err != nil {
		return err
	}
	return nil
}

func (sm *SecretManager) readSecretFooter(path string) (*secretFooter, error) {
	fd, err := sm.root.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer closeLogged(fd)

	_, footer, err := readFooter(fd)
	if err != nil {
		return nil, fmt.Errorf("read footer of %s: %w", path, err)
	}
	return footer, nil
}

// RevealAll writes out every secret the user can read, whatever the plaintext
// holds right now.
func (sm *SecretManager) RevealAll() error {
	return sm.reveal(nil)
}

// RevealPaths writes out the named secrets, whatever their plaintext holds.
// Unknown or inaccessible paths are skipped, so callers can pass a raw list
// from git.
func (sm *SecretManager) RevealPaths(paths []string) error {
	want := make(map[string]bool, len(paths))
	for _, p := range paths {
		want[p] = true
	}

	return sm.reveal(want)
}

// reveal writes out every secret in want, or all of them when want is nil. The
// nil case stays in here: an empty RevealPaths must reveal nothing, not everything.
func (sm *SecretManager) reveal(want map[string]bool) error {
	parallelJobs := 4 * runtime.GOMAXPROCS(0)
	g := new(errgroup.Group)
	g.SetLimit(parallelJobs)

	for _, vsecret := range sm.State.Secrets {
		g.Go(func() error {
			if want != nil && !want[vsecret.RevealedPath] {
				return nil
			}

			if !sm.State.UserHasAccess(sm.Signer.UserName(), vsecret.AccessGroups) {
				// ignore files we can't decrypt:
				return nil
			}

			if err := revealSecret(sm, vsecret.RevealedPath); err != nil {
				return fmt.Errorf("failed to reveal %s: %w", vsecret.RevealedPath, err)
			}

			return nil
		})
	}

	return g.Wait()
}

// RevealTo reveals one known secret to dstPath.
func (sm *SecretManager) RevealTo(revealedPath, dstPath string) error {
	return revealSecretToPath(sm, revealedPath, dstPath)
}

// SecretRemove removes a secret from sesam's management.
// The encrypted files (+associated) are deleted, but the original file is not touched.
func (sm *SecretManager) SecretRemove(revealedPath string) error {
	if _, exists := sm.State.SecretExists(revealedPath); !exists {
		return fmt.Errorf("no such secret")
	}

	if err := sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSecretRemove{
			RevealedPath: revealedPath,
		}),
	); err != nil {
		return fmt.Errorf("failed to add secret remove entry: %w", err)
	}

	return sm.root.RemoveAll(sm.cryptPath(revealedPath))
}

func (sm *SecretManager) SecretMove(oldRevealedPath, newRevealedPath string) error {
	if _, exists := sm.State.SecretExists(oldRevealedPath); !exists {
		return fmt.Errorf("failed to move non-existing secret: %s", oldRevealedPath)
	}

	_, statErr := sm.root.Stat(oldRevealedPath)
	needsReveal := statErr != nil
	if needsReveal {
		// Not yet revealed; reveal so the rename has plaintext to move. The
		// secret was not revealed before, so it must not be left revealed on
		// ANY exit path. Defer the cleanup (rather than only on success) so a
		// partial failure does not strand plaintext in the worktree — which a
		// Stage.Rollback could not remove, since it lives outside the fork.
		// The plaintext may sit at the old path (failure before rename) or the
		// new path (after), so remove both best-effort.
		if err := revealSecret(sm, oldRevealedPath); err != nil {
			return err
		}
		defer func() {
			_ = sm.root.Remove(newRevealedPath)
			_ = sm.root.Remove(oldRevealedPath)
		}()
	}

	if err := sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSecretMove{
			OldRevealedPath: oldRevealedPath,
			NewRevealedPath: newRevealedPath,
		}),
	); err != nil {
		return fmt.Errorf("failed to add secret move entry: %w", err)
	}

	if err := sm.root.MkdirAll(filepath.Dir(newRevealedPath), 0o700); err != nil {
		return err
	}

	if err := sm.root.Rename(oldRevealedPath, newRevealedPath); err != nil {
		return err
	}

	if err := sm.root.RemoveAll(sm.cryptPath(oldRevealedPath)); err != nil {
		return err
	}

	// Materialize the moved object so it survives the cleanup above and the
	// caller's Seal can preserve it. No per-move seal entry is emitted: the
	// caller runs a single Seal after the whole move cascade, which writes
	// the one authoritative seal entry (instead of one per moved secret).
	_, err := sealSecret(
		sm,
		newRevealedPath,
		sm.recipientsFor(newRevealedPath),
		sm.cryptPath(newRevealedPath),
		sm.Signer.UserName(),
	)
	return err
}

// ShowSecret outputs the secret content of `path` to `dst`.
// It uses `ids` to decrypt it.
//
// `path` can be a path of an encrypted file (.sesam) or a revealed path.
//
// NOTE: This is primarily used to calculate content diffs. For performance reasons
// it does not verify signatures - this requires parsing all of the audit log.
// As a consequence it also does not check whether the sealer was authorized
// to seal this path. Use `sesam reveal` or `sesam verify --all` for that.
func ShowSecret(root *os.Root, ids Identities, path string, dst io.Writer) (bool, error) {
	if !strings.HasSuffix(path, ".sesam") {
		if err := validSecretPath(root, path); err == nil {
			// user apparently gave the direct revealed path. Let's map it to the
			// actual object file as a convenience feature.
			path = filepath.Join(".sesam", "objects", path+".sesam")
		}
	}

	srcFd, err := openForShow(root, path)
	if err != nil {
		// assume it's not something we can "show"
		return false, nil
	}

	defer closeLogged(srcFd)

	_, _, _, err = RevealStream(srcFd, dst, ids.AgeIdentities())
	return true, err
}

// openForShow reads in-repo paths through the root. An absolute path comes
// from git's diff textconv, which extracts the blob to a temp file outside the
// repo and passes that path; those are opened directly. Showing is a read-only
// decryption for display, so reading outside the root sandbox is acceptable.
func openForShow(root *os.Root, path string) (*os.File, error) {
	if filepath.IsAbs(path) {
		//nolint:gosec // textconv hands us an external blob temp path to read.
		return os.Open(path)
	}
	return root.Open(path)
}

// needsSeal is the fallback when nothing is known about a plaintext: the object
// has to be resealed if the recipients changed or the plaintext is not what it
// was sealed from. A missing plaintext or object counts as "needs seal" rather
// than an error. When the object is read, its footer is returned so the caller
// can reuse it instead of reading it again.
//
// The recipient check works off the signed footer alone (no decryption), so it
// holds even when the current sealer cannot read the existing object; only the
// plaintext comparison decrypts the sealed file's age key.
func (sm *SecretManager) needsSeal(revealedPath string) (bool, *secretFooter, error) {
	// TODO: During seal we can get the file key directly without re-reading, should be a parameter here.
	sealFd, err := sm.root.Open(sm.cryptPath(revealedPath))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	defer closeLogged(sealFd)

	if _, err := sm.root.Stat(revealedPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil, nil
		}

		return false, nil, err
	}

	_, footer, err := readFooter(sealFd)
	if err != nil {
		return false, nil, err
	}

	drifted, err := sm.recipientsDrifted(footer, revealedPath)
	if err != nil || drifted {
		return drifted, footer, err
	}

	matches, err := sm.plaintextMatches(revealedPath, sealFd, footer)
	if err != nil {
		return false, footer, err
	}

	return !matches, footer, nil
}

// MatchObject compares the plaintext at revealedPath with one sealed object,
// on disk or fished out of git history, and says whether it is what the object
// was sealed from and whether the object still names the secret's recipients.
func (sm *SecretManager) MatchObject(revealedPath string, object io.ReadSeeker) (ObjectMatch, error) {
	_, footer, err := readFooter(object)
	if err != nil {
		return ObjectMatch{}, err
	}

	drifted, err := sm.recipientsDrifted(footer, revealedPath)
	if err != nil {
		return ObjectMatch{}, err
	}

	matches, err := sm.plaintextMatches(revealedPath, object, footer)

	var noIdentity *age.NoIdentityMatchError
	if errors.As(err, &noIdentity) {
		return ObjectMatch{Recipients: !drifted}, nil
	}

	return ObjectMatch{Content: matches, Recipients: !drifted}, err
}

// plaintextMatches hashes the plaintext the way footer says and compares under
// the object's age key. `object` has to be positioned at the start of the age
// stream (readFooter leaves it there).
func (sm *SecretManager) plaintextMatches(revealedPath string, object io.Reader, footer *secretFooter) (bool, error) {
	newHash, hashCode, err := hasherForStored(footer.CipherTextHash)
	if err != nil {
		return false, err
	}

	ageKey, err := readAgeEncryptionKey(object, sm.Identities.AgeIdentities())
	if err != nil {
		return false, err
	}

	plainFd, err := sm.root.Open(revealedPath)
	if err != nil {
		return false, err
	}
	defer closeLogged(plainFd)

	plainContentHash := newHash()
	if _, err := io.Copy(plainContentHash, plainFd); err != nil {
		return false, err
	}
	_, _ = plainContentHash.Write([]byte(revealedPath))

	got := MulticodeEncode(keyContentHash(newHash, ageKey, plainContentHash.Sum(nil)), hashCode)
	return got == footer.HMACContentHash, nil
}

// recipientsDrifted reports whether the footer was sealed for a different
// recipient set than revealedPath has now. Footer only, no decryption.
func (sm *SecretManager) recipientsDrifted(footer *secretFooter, revealedPath string) (bool, error) {
	newHash, hashCode, err := hasherForStored(footer.CipherTextHash)
	if err != nil {
		return false, err
	}

	want := MulticodeEncode(recipientsHash(newHash, sm.recipientsFor(revealedPath)), hashCode)
	return footer.RecipientsHash != want, nil
}
