package core

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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

	secrets []secret
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

	for _, vsecret := range state.Secrets {
		accessUsers := state.UsersForSecret(vsecret.RevealedPath)
		recps := keyring.Recipients(accessUsers)
		mgr.secrets = append(mgr.secrets, secret{
			Mgr:          mgr,
			RevealedPath: vsecret.RevealedPath,
			Recipients:   recps,
		})
	}

	return mgr, nil
}

func (sm *SecretManager) cryptPath(path string) string {
	return filepath.Join(sm.SesamDir, ".sesam", "objects", path+".sesam")
}

func (sm *SecretManager) tmpDir() string {
	return filepath.Join(sm.SesamDir, ".sesam", "tmp")
}

// AddSecret adds a new secret to be managed by sesam
func (sm *SecretManager) AddSecret(revealedPath string, groups []string) error {
	return sm.addOrChangeSecret(revealedPath, groups)
}

// ChangeSecretGroups changes the access groups for the secret at `revealedPath`
// NOTE: It is currently valid to call AddSecret instead.
func (sm *SecretManager) ChangeSecretGroups(revealedPath string, groups []string) error {
	return sm.addOrChangeSecret(revealedPath, groups)
}

// NOTE: right now add/change is the same operation. Later we can do different things on add/change,
// the API is already split in case we want to go that route.
func (sm *SecretManager) addOrChangeSecret(revealedPath string, groups []string) error {
	if err := validSecretPath(sm.SesamDir, revealedPath); err != nil {
		return fmt.Errorf("invalid secret path (%s): %w", revealedPath, err)
	}

	idx := slices.IndexFunc(sm.secrets, func(s secret) bool {
		return s.RevealedPath == revealedPath
	})

	accessUsers := sm.State.UserForGroups(groups)
	recps := sm.Keyring.Recipients(accessUsers)

	if idx < 0 {
		sm.secrets = append(sm.secrets, secret{
			Mgr:          sm,
			RevealedPath: revealedPath,
			Recipients:   recps,
		})
	} else {
		sm.secrets[idx].Recipients = recps
	}

	return sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSecretChange{
			RevealedPath: revealedPath,
			Groups:       groups,
		}))
}

// SealAll seals all kown secrets.
func (sm *SecretManager) SealAll() error {
	sigs := make([]*secretFooter, 0, len(sm.secrets))

	for _, secret := range sm.secrets {
		sig, err := secret.Seal(sm.Signer.UserName())
		if err != nil {
			return fmt.Errorf("seal of %s failed: %w", secret.RevealedPath, err)
		}

		sigs = append(sigs, sig)
	}

	return sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSeal{
			RootHash:    buildRootHash(sigs),
			FilesSealed: len(sigs),
		}),
	)
}

// RevealAll reveals all known secrets.
func (sm *SecretManager) RevealAll() error {
	for _, secret := range sm.secrets {
		if err := secret.Reveal(); err != nil {
			return fmt.Errorf("failed to reveal %s: %w", secret.RevealedPath, err)
		}
	}
	return nil
}

// RemoveSecret removes a secret from sesam's management.
// The encrypted files (+associated) are deleted, but the original file is not touched.
func (sm *SecretManager) RemoveSecret(revealedPath string) error {
	idx := slices.IndexFunc(sm.secrets, func(s secret) bool {
		return s.RevealedPath == revealedPath
	})

	if idx < 0 {
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

	if err := os.RemoveAll(sm.cryptPath(revealedPath)); err != nil {
		return err
	}

	sm.secrets = slices.Delete(sm.secrets, idx, idx+1)
	return nil
}

// ShowSecret outputs the secret content of `path` to `dst`.
// It uses `ids` to decrypt it.
//
// `path` can be a path of an encrypted file (.sesam) or a revealed path.
//
// NOTE: This is primarily used to calculate content diffs. For performance reasons
// it does not verify signatures - this requires parsing all of the audit log.
func ShowSecret(sesamDir string, ids Identities, path string, dst io.Writer) (bool, error) {
	if !strings.HasSuffix(path, ".sesam") {
		if err := validSecretPath(sesamDir, path); err == nil {
			// user apparently gave the direct revealed path. Let's map it to the
			// actual object file as a convenience feature.
			path = filepath.Join(".sesam", "objects", path+".sesam")
		}
	}

	//nolint:gosec
	srcFd, err := os.Open(path)
	if err != nil {
		// assume it's not something we can "show"
		return false, nil
	}

	defer closeLogged(srcFd)

	_, _, err = revealStream(srcFd, dst, ids.AgeIdentities())
	return true, err
}

// RevealBlob decrypts src and writes the plaintext to sesamDir/revealedPath.
//
// revealedPath is the repo-relative plain path (e.g. "secrets/token"), derived
// by the caller from git's %f argument so no footer read-back is needed.
//
// Returns (true, nil) on success. Returns (false, nil) when the caller is not
// a recipient - the blob is not meant for them and is silently skipped.
//
// This function should only be called for quick decryption (i.e. git diff or smudge)
// and when we only have access to the encrypted file and not the audit log.
// For most cases, uses SecretManager.
func RevealBlob(sesamDir string, ids Identities, src io.ReadSeeker, revealedPath string) (bool, error) {
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

	_, _, err = revealStream(src, dst, ids.AgeIdentities())
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			// count as no error, checking out old state is a best effort.
			return false, nil
		}

		return false, err
	}

	_ = dst.Chmod(0o600)
	return true, dst.CloseAtomicallyReplace()
}
