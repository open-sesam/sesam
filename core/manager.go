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

	// WhoAmI is the user tied to the current Identities.
	WhoAmI string

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
	whoami string,
	identities Identities,
	signer Signer,
	keyring Keyring,
	log *AuditLog,
	state *VerifiedState,
) (*SecretManager, error) {
	mgr := &SecretManager{
		RepoDir:    repoDir,
		WhoAmI:     whoami,
		Identities: identities,
		Signer:     signer,
		Keyring:    keyring,
		AuditLog:   log,
		State:      state,
	}

	// Clear tmp dir before continuing:
	tmpDir := mgr.tmpDir()
	_ = os.RemoveAll(tmpDir)
	_ = os.MkdirAll(tmpDir, 0700)

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
	if err := os.MkdirAll(filepath.Dir(cryptPath), 0700); err != nil {
		return nil, "", err
	}

	fd, err := os.Create(cryptPath)
	return fd, cryptPath, err
}

func (sm *SecretManager) tmpDir() string {
	return filepath.Join(sm.RepoDir, ".sesam", "tmp")
}

func (sm *SecretManager) AddOrChangeSecret(revealedPath string, groups []string) error {
	accessUsers := sm.State.UserForGroups(groups)
	sm.secrets = append(sm.secrets, secret{
		Mgr:          sm,
		RevealedPath: revealedPath,
		Recipients:   sm.Keyring.Recipients(accessUsers),
	})

	entry := newAuditEntry(sm.WhoAmI, &DetailSecretChange{
		RevealedPath: revealedPath,
		Groups:       groups,
	})

	if _, err := sm.AuditLog.AddEntry(sm.Signer, entry); err != nil {
		return fmt.Errorf("audit add entry: %w", err)
	}

	if err := sm.State.Update(); err != nil {
		return fmt.Errorf("failed to verify new entries: %w", err)
	}

	if err := sm.AuditLog.Store(); err != nil {
		return fmt.Errorf("storing log failed: %w", err)
	}

	return nil
}

// SealAll seals all kown secrets.
func (sm *SecretManager) SealAll() error {
	var sigs []*secretSignature

	for _, secret := range sm.secrets {
		fmt.Println("SEAL", secret.RevealedPath)
		sig, err := secret.Seal(sm.WhoAmI)
		if err != nil {
			return fmt.Errorf("seal of %s failed: %w", secret.RevealedPath, err)
		}

		sigs = append(sigs, sig)
	}

	entry := newAuditEntry(sm.WhoAmI, &DetailSeal{
		RootHash:    buildRootHash(sigs),
		FilesSealed: len(sigs),
	})

	if _, err := sm.AuditLog.AddEntry(sm.Signer, entry); err != nil {
		return fmt.Errorf("audit add entry: %w", err)
	}

	if err := sm.State.Update(); err != nil {
		return fmt.Errorf("failed to verify new entries: %w", err)
	}

	if err := sm.AuditLog.Store(); err != nil {
		return fmt.Errorf("storing log failed: %w", err)
	}

	return nil
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
