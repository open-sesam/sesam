package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type SecretManager struct {
	// RepoDir is the path to sesam repository.
	// It is the dir the .sesam directory is in.
	RepoDir string

	WhoAmI string

	// Identities are the private keys the current user of sesam supplies.
	Identities Identities

	// Signer is our way to sign things with a per-user generated key.
	Signer Signer

	// Keyring is a collection of public keys
	Keyring Keyring

	AuditLog *AuditLog

	State *VerifiedState

	secrets []Secret
}

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

	for _, vsecret := range state.Secrets {
		accessUsers := state.UsersForSecret(vsecret.RevealedPath)
		recps := keyring.Recipients(accessUsers)
		mgr.secrets = append(mgr.secrets, Secret{
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

func (sm *SecretManager) cryptWriter(path string) (io.WriteCloser, string, error) {
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
	tmpDir := filepath.Join(sm.RepoDir, ".sesam", "tmp")
	_ = os.MkdirAll(tmpDir, 0700)
	return tmpDir
}

func (sm *SecretManager) AddOrChangeSecret(revealedPath string, groups []string) error {
	accessUsers := sm.State.UserForGroups(groups)
	sm.secrets = append(sm.secrets, Secret{
		Mgr:          sm,
		RevealedPath: revealedPath,
		Recipients:   sm.Keyring.Recipients(accessUsers),
	})

	entry := NewAuditEntry(sm.WhoAmI, &DetailSecretChange{
		RevealedPath: revealedPath,
		Groups:       groups,
	})

	if _, err := sm.AuditLog.AddEntry(entry); err != nil {
		return fmt.Errorf("audit add entry: %w", err)
	}

	if err := sm.State.Update(); err != nil {
		return fmt.Errorf("failed to verify new entries: %w", err)
	}

	if err := sm.AuditLog.Store(); err != nil {
		return fmt.Errorf("storing log failed: %v", err)
	}

	return nil
}

func (sm *SecretManager) SealAll() error {
	var sigs []*SecretSignature

	for _, secret := range sm.secrets {
		fmt.Println("SEAL", secret.RevealedPath)
		sig, err := secret.Seal(sm.WhoAmI)
		if err != nil {
			return fmt.Errorf("seal of %s failed: %w", sig.RevealedPath, err)
		}

		sigs = append(sigs, sig)
	}

	entry := NewAuditEntry(sm.WhoAmI, &DetailSeal{
		RootHash:    BuildRootHash(sigs),
		FilesSealed: len(sigs),
	})

	if _, err := sm.AuditLog.AddEntry(entry); err != nil {
		return fmt.Errorf("audit add entry: %w", err)
	}

	if err := sm.State.Update(); err != nil {
		return fmt.Errorf("failed to verify new entries: %w", err)
	}

	if err := sm.AuditLog.Store(); err != nil {
		return fmt.Errorf("storing log failed: %v", err)
	}

	return nil
}

func (sm *SecretManager) RevealAll() error {
	for _, secret := range sm.secrets {
		fmt.Println("REVEAL", secret.RevealedPath)
		if err := secret.Reveal(); err != nil {
			return fmt.Errorf("failed to reveal %s: %w", secret.RevealedPath, err)
		}
	}
	return nil
}
