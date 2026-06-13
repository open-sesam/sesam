package core

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/google/renameio"
)

// SecretManager is the high level API to manage secrets,
// i.e. seal & reveal them and also add/remove/change secrets.
type SecretManager struct {
	// SesamDir is the path to sesam repository.
	// It is the dir the .sesam directory is in.
	SesamDir string

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
}

// BuildSecretManager uses the passed facilities to build a new SecretManager
func BuildSecretManager(
	sesamDir string,
	identities Identities,
	signer Signer,
	keyring Keyring,
	log *AuditLog,
	state *VerifiedState,
) (*SecretManager, error) {
	mgr := &SecretManager{
		SesamDir:   sesamDir,
		Identities: identities,
		Signer:     signer,
		Keyring:    keyring,
		AuditLog:   log,
		State:      state,
	}

	// Clear tmp dir before continuing:
	tmpDir := mgr.tmpDir()
	_ = os.RemoveAll(tmpDir)
	_ = os.MkdirAll(tmpDir, 0o700)

	return mgr, nil
}

// recipientsFor returns the recipients that may reveal `revealedPath`,
// derived from the current verified state and keyring. The set of secrets
// lives in sm.State.Secrets - the source of truth - so the recipient list
// is always recomputed here rather than cached.
func (sm *SecretManager) recipientsFor(revealedPath string) Recipients {
	return sm.Keyring.Recipients(sm.State.UsersForSecret(revealedPath))
}

func (sm *SecretManager) cryptPath(path string) string {
	return filepath.Join(sm.objectsDir(), path+".sesam")
}

func (sm *SecretManager) tmpDir() string {
	return filepath.Join(sm.SesamDir, ".sesam", "tmp")
}

func (sm *SecretManager) objectsDir() string {
	return filepath.Join(sm.SesamDir, ".sesam", "objects")
}

func (sm *SecretManager) stageDir() string {
	return filepath.Join(sm.SesamDir, ".sesam", "seal-stage")
}

// AddSecret adds a new secret to be managed by sesam
func (sm *SecretManager) AddSecret(revealedPath string, groups []string) error {
	return sm.addOrChangeSecret(revealedPath, groups)
}

// ChangeSecretGroups changes the access groups for the secret at `revealedPath`.
func (sm *SecretManager) ChangeSecretGroups(revealedPath string, groups []string) error {
	return sm.addOrChangeSecret(revealedPath, groups)
}

// addOrChangeSecret emits a secret.add entry for a new secret and a
// secret.change_access entry for an existing one, deciding which based on
// whether the secret is already known.
func (sm *SecretManager) addOrChangeSecret(revealedPath string, groups []string) error {
	if err := validSecretPath(sm.SesamDir, revealedPath); err != nil {
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
		// Secret already exists: this is an access-list change.
		auditEntry = newAuditEntry(sm.Signer.UserName(), &DetailSecretChangeAccess{
			RevealedPath: revealedPath,
			AccessGroups: groups,
		})
	}

	return sm.State.FeedEntry(sm.Signer, auditEntry)
}

// SealAll seals all known secrets.
//
// Strategy: stage the full new objects tree under .sesam/seal-stage,
// append the seal entry to the audit log, then atomically swap stage
// with .sesam/objects. If a secret has no plaintext available (typically
// because the current user is not a recipient and therefore can't decrypt
// it), the existing ciphertext is copied over verbatim so it survives the
// swap.
//
// The audit log append is the single commit point:
//
//  1. stage written: nothing committed; on failure, drop the stage dir.
//  2. audit entry appended: state is final; recovery must drive disk to it.
//  3. swap done: disk matches the log.
//
// If we crash between (2) and (3) the stage dir is left in place and
// recoverIncompleteSeal (in Verify) finishes the swap on the next load by
// matching stage's root hash against the audit log's RootHash.
func (sm *SecretManager) SealAll() error {
	stage := sm.stageDir()
	objects := sm.objectsDir()

	// Any leftover stage from a prior crash is normally cleaned by Verify
	// on load, but rebuild a fresh one here defensively.
	if err := os.RemoveAll(stage); err != nil {
		return fmt.Errorf("clear stage dir: %w", err)
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fmt.Errorf("create stage dir: %w", err)
	}
	// renameat2(EXCHANGE) requires both endpoints to exist.
	// Double-bolt this is the case.
	if err := os.MkdirAll(objects, 0o700); err != nil {
		return fmt.Errorf("create objects dir: %w", err)
	}

	sigs := make([]*secretFooter, 0, len(sm.State.Secrets))
	for _, vsecret := range sm.State.Secrets {
		sig, _, err := sm.stageSecret(vsecret.RevealedPath, stage)
		if err != nil {
			_ = os.RemoveAll(stage)
			return fmt.Errorf("stage %s: %w", vsecret.RevealedPath, err)
		}
		sigs = append(sigs, sig)
	}

	rootHash := buildRootHash(sigs)

	// Audit entry FIRST so the log is the commit point. If this fails
	// nothing was committed and the stage dir is just throwaway work.
	if err := sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSeal{
			RootHash:    rootHash,
			FilesSealed: len(sigs),
		}),
	); err != nil {
		_ = os.RemoveAll(stage)
		return fmt.Errorf("append audit seal entry: %w", err)
	}

	if err := atomicSwapDirs(stage, objects); err != nil {
		// Audit entry already committed: leave stage in place so the
		// next Verify can match its root hash and finish the swap.
		return fmt.Errorf("swap stage dir into place: %w", err)
	}

	// stage now holds the OLD objects tree. Reap it last so the
	// commit-on-disk and commit-in-log windows are not separated by an
	// expensive recursive delete.
	if err := os.RemoveAll(stage); err != nil {
		// Not fatal: the next Verify will retry the cleanup.
		slog.Warn(
			"failed to remove old objects after seal swap",
			slog.String("err", err.Error()),
		)
	}
	return nil
}

// stageSecret writes the sealed form of `revealedPath` into the staging tree
// rooted at `stageRoot`. If we have access to the plaintext we encrypt it
// fresh; if the plaintext is missing we copy the existing ciphertext from the
// live objects/ tree so the file survives the swap. It is an error if neither
// is available.
func (sm *SecretManager) stageSecret(revealedPath, stageRoot string) (*secretFooter, bool, error) {
	stageDest := filepath.Join(stageRoot, revealedPath+".sesam")
	if err := os.MkdirAll(filepath.Dir(stageDest), 0o700); err != nil {
		return nil, false, fmt.Errorf("create stage subdir: %w", err)
	}

	plainPath := filepath.Join(sm.SesamDir, revealedPath)
	switch _, err := os.Stat(plainPath); {
	case err == nil:
		// Good-citizen guard: an honest client refuses to produce a
		// footer it knows the verifier will reject. The "preserve
		// existing ciphertext" branch below does not hit this because
		// it does not change SealedBy.
		sealer := sm.Signer.UserName()
		if sm.State.SealerAuthorized(sealer, revealedPath) {
			sig, err := sealSecret(
				sm,
				revealedPath,
				sm.recipientsFor(revealedPath),
				stageDest,
				sealer,
			)
			return sig, true, err
		}

		slog.Warn(
			"ignoring path because user is not authorized",
			slog.String("user", sealer),
			slog.String("path", revealedPath),
		)
	case !os.IsNotExist(err):
		return nil, false, fmt.Errorf("stat plaintext: %w", err)
	}

	// No plaintext: preserve the existing ciphertext if we have one.
	existing := sm.cryptPath(revealedPath)
	if !pathExists(existing) {
		return nil, false, fmt.Errorf(
			"no plaintext at %q and no existing ciphertext at %q to preserve",
			plainPath, existing,
		)
	}

	if err := copyFile(existing, stageDest); err != nil {
		return nil, false, err
	}

	sig, err := readSecretFooter(stageDest)
	return sig, false, err
}

func readSecretFooter(path string) (*secretFooter, error) {
	//nolint:gosec
	fd, err := os.Open(path)
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
		if err := revealSecret(sm, vsecret.RevealedPath); err != nil {
			return fmt.Errorf("failed to reveal %s: %w", vsecret.RevealedPath, err)
		}
	}
	return nil
}

// RemoveSecret removes a secret from sesam's management.
// The encrypted files (+associated) are deleted, but the original file is not touched.
func (sm *SecretManager) RemoveSecret(revealedPath string) error {
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

	return os.RemoveAll(sm.cryptPath(revealedPath))
}

func (sm *SecretManager) MoveSecret(oldRevealedPath, newRevealedPath string) error {
	if _, exists := sm.State.SecretExists(oldRevealedPath); !exists {
		return fmt.Errorf("failed to move non-existing secret: %s", oldRevealedPath)
	}

	needsReveal := !pathExists(filepath.Join(sm.SesamDir, oldRevealedPath))
	if needsReveal {
		// not yet revealed, do it before the rename entry, otherwise reveal would fail
		if err := revealSecret(sm, oldRevealedPath); err != nil {
			return err
		}
	}

	// NOTE: This is not particularly crash-safe. We could use the SealAll()
	// mechanism of using a stageDir, but without re-rencrypting everything to
	// make things better.

	if err := sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSecretRename{
			OldRevealedPath: oldRevealedPath,
			NewRevealedPath: newRevealedPath,
		}),
	); err != nil {
		return fmt.Errorf("failed to add secret remove entry: %w", err)
	}

	if err := os.Rename(
		filepath.Join(sm.SesamDir, oldRevealedPath),
		filepath.Join(sm.SesamDir, newRevealedPath),
	); err != nil {
		return err
	}

	if err := os.RemoveAll(sm.cryptPath(oldRevealedPath)); err != nil {
		return err
	}

	_, err := sealSecret(
		sm,
		newRevealedPath,
		sm.recipientsFor(newRevealedPath),
		sm.cryptPath(newRevealedPath),
		sm.Signer.UserName(),
	)
	if err != nil {
		return err
	}

	// If we'd cache signatures, we could skip reading all of them. But for now good enough.
	sigs, err := readAllSignatures(sm.SesamDir)
	if err != nil {
		return err
	}

	if err := sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSeal{
			RootHash:    buildRootHash(sigs),
			FilesSealed: 1,
		}),
	); err != nil {
		return fmt.Errorf("failed to add secret remove entry: %w", err)
	}

	if needsReveal {
		// file was not revealed before, to be consistent we should remove it again.
		return os.Remove(filepath.Join(sm.SesamDir, newRevealedPath))
	}

	return nil
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
func ShowSecret(sesamDir string, ids Identities, path string, dst io.Writer) (bool, error) {
	if !strings.HasSuffix(path, ".sesam") {
		if err := validSecretPath(sesamDir, path); err == nil {
			// user apparently gave the direct revealed path. Let's map it to the
			// actual object file as a convenience feature.
			path = filepath.Join(".sesam", "objects", path+".sesam")
		}
	}

	// Resolve relative inputs against sesamDir so the lookup works regardless
	// of the caller's cwd. Absolute paths (e.g. mgr.cryptPath() output) are
	// used as-is — joining two absolute paths with filepath.Join would
	// produce a double-prefixed nonsense path.
	if !filepath.IsAbs(path) {
		path = filepath.Join(sesamDir, path)
	}

	//nolint:gosec
	srcFd, err := os.Open(path)
	if err != nil {
		// assume it's not something we can "show"
		return false, nil
	}

	defer closeLogged(srcFd)

	_, _, _, err = revealStream(srcFd, dst, ids.AgeIdentities())
	return true, err
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
