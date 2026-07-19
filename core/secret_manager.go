package core

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/sha3"
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

// SetBase points the manager's sesam-internal paths at base (a stage's fork
// dir, e.g. ".sesam-tmp"). Worktree (plaintext) paths are unaffected. Must be
// called before any sealing if the manager operates on a stage.
func (sm *SecretManager) SetBase(base string) { sm.base = base }

// BuildSecretManager uses the passed facilities to build a new SecretManager.
// root confines all file I/O to the repository; sesamDir is its absolute path,
// kept for the directory swap and git interop.
func BuildSecretManager(
	sesamDir string,
	root *os.Root,
	identities Identities,
	signer Signer,
	keyring Keyring,
	log *AuditLog,
	state *VerifiedState,
) (*SecretManager, error) {
	mgr := &SecretManager{
		SesamDir:   sesamDir,
		root:       root,
		Identities: identities,
		Signer:     signer,
		Keyring:    keyring,
		AuditLog:   log,
		State:      state,
	}

	// Clear tmp dir before continuing:
	tmpDir := SesamTmpDir()
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
func (sm *SecretManager) Seal(all bool) error {
	objects := sm.objectsDir()
	if err := sm.root.MkdirAll(objects, 0o700); err != nil {
		return fmt.Errorf("create objects dir: %w", err)
	}

	wanted := make(map[string]bool, len(sm.State.Secrets))
	sigs := make([]*secretFooter, 0, len(sm.State.Secrets))
	for _, vsecret := range sm.State.Secrets {
		sig, err := sm.sealOrPreserve(vsecret.RevealedPath, all)
		if err != nil {
			return fmt.Errorf("seal %s: %w", vsecret.RevealedPath, err)
		}
		sigs = append(sigs, sig)
		wanted[sm.cryptPath(vsecret.RevealedPath)] = true
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
func (sm *SecretManager) sealOrPreserve(revealedPath string, all bool) (*secretFooter, error) {
	dest := sm.cryptPath(revealedPath)
	if err := sm.root.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return nil, fmt.Errorf("create objects subdir: %w", err)
	}

	switch _, err := sm.root.Stat(revealedPath); {
	case err == nil:
		sealer := sm.Signer.UserName()
		if sm.State.SealerAuthorized(sealer, revealedPath) {
			// Unless forced (all), skip the reseal when the existing object still
			// matches both the plaintext and the recipient set. NeedsSeal hands
			// back the footer it read so we can return it without a second read.
			if !all {
				needsSeal, footer, err := sm.NeedsSeal(revealedPath)
				if err != nil {
					return nil, fmt.Errorf("failed to check whether reseal is needed: %w", err)
				}
				if !needsSeal {
					return footer, nil
				}
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

// RevealAll reveals all known secrets.
func (sm *SecretManager) RevealAll() error {
	for _, vsecret := range sm.State.Secrets {
		if !sm.State.UserHasAccess(sm.Signer.UserName(), vsecret.AccessGroups) {
			// ignore files we can't decrypt:
			continue
		}

		if err := revealSecret(sm, vsecret.RevealedPath); err != nil {
			return fmt.Errorf("failed to reveal %s: %w", vsecret.RevealedPath, err)
		}
	}
	return nil
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

	_, _, _, err = revealStream(srcFd, dst, ids.AgeIdentities())
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

// NeedsSeal reports whether revealedPath must be (re-)sealed: its recipient set
// or its plaintext drifted from the sealed object, or either the sealed object
// or the plaintext is missing. A missing file is reported as "needs seal"
// rather than an error, so callers (Seal, `sesam status`) can probe freely
// without pre-checking existence. When the object is read, its footer is
// returned so the caller can reuse it instead of reading it a second time.
//
// The recipient check works off the signed footer alone (no decryption), so it
// holds even when the current sealer cannot read the existing object; only the
// plaintext comparison decrypts the sealed file's age key.
func (sm *SecretManager) NeedsSeal(revealedPath string) (bool, *secretFooter, error) {
	sealFd, err := sm.root.Open(sm.cryptPath(revealedPath))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	defer closeLogged(sealFd)

	plainFd, err := sm.root.Open(revealedPath)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	defer closeLogged(plainFd)

	_, footer, err := readFooter(sealFd)
	if err != nil {
		return false, nil, err
	}

	want := MulticodeEncode(recipientsHash(sm.recipientsFor(revealedPath)), MhSHA3_256)
	if footer.RecipientsHash != want {
		return true, footer, nil
	}

	ageKey, err := readAgeEncryptionKey(sealFd, sm.Identities.AgeIdentities())
	if err != nil {
		return false, footer, err
	}

	plainContentHash := sha3.New256()
	if _, err := io.Copy(plainContentHash, plainFd); err != nil {
		return false, footer, err
	}
	_, _ = plainContentHash.Write([]byte(revealedPath))

	plainHmacContentHash := MulticodeEncode(keyContentHash(ageKey, plainContentHash.Sum(nil)), MhSHA3_256)
	return plainHmacContentHash != footer.HMACContentHash, footer, nil
}
