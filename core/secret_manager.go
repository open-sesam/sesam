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

	"filippo.io/age"
	"github.com/google/renameio/v2"
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

// SecretAdd adds a new secret to be managed by sesam
func (sm *SecretManager) SecretAdd(revealedPath string, groups []string) error {
	return sm.addOrChangeSecret(revealedPath, groups)
}

// SecretChangeGroups changes the access groups for the secret at `revealedPath`.
func (sm *SecretManager) SecretChangeGroups(revealedPath string, groups []string) error {
	return sm.addOrChangeSecret(revealedPath, groups)
}

// addOrChangeSecret emits a secret.add entry for a new secret and a
// secret.change_access entry for an existing one, deciding which based on
// whether the secret is already known.
func (sm *SecretManager) addOrChangeSecret(revealedPath string, groups []string) error {
	if err := validSecretPath(sm.root, revealedPath); err != nil {
		return fmt.Errorf("invalid secret path (%s): %w", revealedPath, err)
	}

	var auditEntry *AuditEntry
	if _, exists := sm.State.SecretExists(revealedPath); !exists {
		// Secret does not exist yet: this is an add.
		auditEntry = newAuditEntry(sm.Signer.UserName(), &DetailSecretAdd{
			RevealedPath: revealedPath,
			AccessGroups: groups,
		})
	} else {
		if len(groups) == 0 {
			// if no groups were given, there is nothing to change.
			return nil
		}

		// Secret already exists: this is an access-list change.
		auditEntry = newAuditEntry(sm.Signer.UserName(), &DetailSecretChangeAccess{
			RevealedPath: revealedPath,
			AccessGroups: groups,
		})
	}

	return sm.State.FeedEntry(sm.Signer, auditEntry)
}

// Seal seals all known secrets.
// This would have advantages on merging -> nothing really changed -> nothing needs to be sealed.
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

	return sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSeal{
			RootHash:    buildRootHash(sigs),
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
			// Unless forced (all), skip the reseal only when the existing object
			// still matches both the plaintext and the recipient set. NeedsSeal
			// hands back the footer it read so we can return it without a second
			// read when nothing changed.
			needsSeal, footer := true, (*secretFooter)(nil)
			if !all {
				if needsSeal, footer, err = sm.NeedsSeal(revealedPath); err != nil {
					return nil, fmt.Errorf("failed to check whether reseal is needed: %w", err)
				}
			}

			if needsSeal {
				return sealSecret(sm, revealedPath, sm.recipientsFor(revealedPath), dest, sealer)
			}

			return footer, nil
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
// not in `wanted` (the set just sealed/preserved). Empty directories are left in place.
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

// RevealBlob decrypts src and writes the plaintext to sesamDir/revealedPath.
//
// revealedPath is the repo-relative plain path (e.g. "secrets/token"), derived
// by the caller from git's %f argument so no footer read-back is needed.
//
// When `kr` is non-nil the footer signature is verified against the keyring,
// and when `authorize` is also non-nil the named sealer is checked against
// the predicate (see VerifiedState.SealerAuthorized). Both nil preserves
// the historical "decrypt and ask no questions" behaviour, which is what
// low-level test fixtures need when no audit log is available.
//
// Returns (true, nil) on success. Returns (false, nil) when the caller is not
// a recipient - the blob is not meant for them and is silently skipped.
//
// On *AuthorizationError the decryption succeeded but the sealer was not in
// the access list. The plaintext is still landed (`true` is returned) and
// the typed error is propagated so callers can pick a policy: the smudge
// filter logs the mismatch and treats it as success; CLI tools may prefer
// to refuse. This split lets `git checkout` survive history written before
// the auth check shipped while still surfacing the deviation loudly.
func RevealBlob(
	sesamDir string,
	ids Identities,
	src io.ReadSeeker,
	revealedPath string,
	kr Keyring,
	authorize func(user, path string) bool,
) (bool, error) {
	dstPath := filepath.Join(sesamDir, revealedPath)
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o700); err != nil {
		return false, fmt.Errorf("creating revealed dir: %w", err)
	}

	tmpDir := filepath.Join(sesamDir, ".sesam", "tmp")
	dst, err := renameio.TempFile(tmpDir, dstPath)
	if err != nil {
		return false, fmt.Errorf("creating temp file: %w", err)
	}
	defer func() { _ = dst.Cleanup() }()

	var revealErr error
	if kr != nil {
		revealErr = revealStreamAndVerify(src, dst, ids.AgeIdentities(), kr, authorize)
	} else {
		_, _, _, revealErr = revealStream(src, dst, ids.AgeIdentities())
	}

	if revealErr != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(revealErr, &noMatch) {
			// count as no error, checking out old state is a best effort.
			return false, nil
		}

		var authErr *BadSealerError
		if errors.As(revealErr, &authErr) {
			// Decryption succeeded; only the policy check failed. Land
			// the plaintext and propagate the typed error - the caller
			// decides whether to warn or refuse.
			_ = dst.Chmod(0o600)
			if closeErr := dst.CloseAtomicallyReplace(); closeErr != nil {
				return false, closeErr
			}
			return true, revealErr
		}

		return false, revealErr
	}

	_ = dst.Chmod(0o600)
	return true, dst.CloseAtomicallyReplace()
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
