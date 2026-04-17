package core

import (
	"fmt"
	"os"
	"path/filepath"
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

func (sm *SecretManager) AddOrChangeSecret(revealedPath string, groups []string) error {
	if err := validSecretPath(sm.RepoDir, revealedPath); err != nil {
		return fmt.Errorf("invalid secret path (%s): %w", revealedPath, err)
	}

	accessUsers := sm.State.UserForGroups(groups)
	sm.secrets = append(sm.secrets, secret{
		Mgr:          sm,
		RevealedPath: revealedPath,
		Recipients:   sm.Keyring.Recipients(accessUsers),
	})

	return sm.State.FeedEntry(
		sm.Signer,
		newAuditEntry(sm.Signer.UserName(), &DetailSecretChange{
			RevealedPath: revealedPath,
			Groups:       groups,
		}))
}

// SealAll seals all kown secrets.
func (sm *SecretManager) SealAll() error {
	var sigs []*secretSignature

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
