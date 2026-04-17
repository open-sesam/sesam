package core

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// SecretManager is the high level API to manage secrets,
// i.e. seal & reveal them and also add/remove/change secrets.
type SecretManager struct {
	// RepoDir is the path to sesam repository.
	// It is the dir the .sesam directory is in.
	RepoDir string

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
	repoDir string,
	identities Identities,
	signer Signer,
	keyring Keyring,
	log *AuditLog,
	state *VerifiedState,
) (*SecretManager, error) {
	mgr := &SecretManager{
		RepoDir:    repoDir,
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
	return filepath.Join(sm.RepoDir, ".sesam", "objects", path+".age")
}

func (sm *SecretManager) sigPath(path string) string {
	return filepath.Join(sm.RepoDir, ".sesam", "objects", path+".sig.json")
}

func (sm *SecretManager) cryptWriter(path string) (*os.File, string, error) {
	cryptPath := sm.cryptPath(path)

	// TODO: Move that to an init module and add a .donotdelete file in it so that git does not kill it.
	// .sesam/tmp should be also part of gitignore
	if err := os.MkdirAll(filepath.Dir(cryptPath), 0o700); err != nil {
		return nil, "", err
	}

	//nolint:gosec
	fd, err := os.Create(cryptPath)
	return fd, cryptPath, err
}

func (sm *SecretManager) tmpDir() string {
	return filepath.Join(sm.RepoDir, ".sesam", "tmp")
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
	if err := validSecretPath(sm.RepoDir, revealedPath); err != nil {
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
	sigs := make([]*secretSignature, 0, len(sm.secrets))

	for _, secret := range sm.secrets {
		fmt.Println("SEAL", secret.RevealedPath)
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
		fmt.Println("REVEAL", secret.RevealedPath)
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

	if err := os.RemoveAll(sm.cryptPath(revealedPath)); err != nil {
		return err
	}

	if err := os.RemoveAll(sm.sigPath(revealedPath)); err != nil {
		return err
	}

	sm.secrets = slices.Delete(sm.secrets, idx, idx+1)

	return sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSecretRemove{
			RevealedPath: revealedPath,
		}),
	)
}
