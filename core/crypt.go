package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
)

type SecretManager struct {
	RepoDir string

	// TOOD: Needs to be parsed from a list of private keys supplied by the user.
	Identities []age.Identity
}

func (sm *SecretManager) cryptPath(path string) string {
	return filepath.Join(sm.RepoDir, ".sesam", "objects", path)
}

func (sm *SecretManager) cryptWriter(path string) (io.WriteCloser, error) {
	cryptPath := sm.cryptPath(path)
	if err := os.MkdirAll(filepath.Dir(cryptPath), 0700); err != nil {
		return nil, err
	}

	return os.Create(cryptPath)
}

type Secret struct {
	Mgr *SecretManager

	// RevealedPath is relative to Mgr.RepoDir
	// TODO: enforce this. Also make sure that path is not a symbolic link and contains no ".." or similar.
	RevealedPath string

	// TODO: Needs to be parsed from a recipient file or public key list using age.ParseRecipient
	Recipients []age.Recipient
}

func (s *Secret) Seal() error {
	fmt.Println("SEAL", s.RevealedPath)
	rd, err := os.Open(filepath.Join(s.Mgr.RepoDir, s.RevealedPath))
	if err != nil {
		return fmt.Errorf("failed to open secret: %w", err)
	}
	defer rd.Close()

	wc, err := s.Mgr.cryptWriter(s.RevealedPath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file in repo: %w", err)
	}
	defer wc.Close()

	encW, err := age.Encrypt(wc, s.Recipients...)
	if err != nil {
		return fmt.Errorf("failed to initiate encryption: %w", err)
	}

	_, err = io.Copy(encW, rd)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret %s: %w", s.RevealedPath, err)
	}

	// TODO: Write hash + signature as well too.
	return encW.Close()
}

func (s *Secret) Reveal() error {
	cryptPath := s.Mgr.cryptPath(s.RevealedPath)
	fmt.Println("REVEAL", cryptPath)
	srcFd, err := os.Open(cryptPath)
	if err != nil {
		// if it does not exist, it probably means that the secret was not encrypted yet.
		return fmt.Errorf("opening secret file failed: %w", err)
	}

	// TODO: Verify signature in .sesam/ dir as well.

	defer srcFd.Close()

	encR, err := age.Decrypt(srcFd, s.Mgr.Identities...)
	if err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", s.RevealedPath, err)
	}

	dstFd, err := os.Create(filepath.Join(s.Mgr.RepoDir, s.RevealedPath))
	if err != nil {
		return fmt.Errorf("failed to create revealed file: %w", err)
	}

	_, err = io.Copy(dstFd, encR)
	if err != nil {
		return fmt.Errorf("failed to copy decrypted secret back in place: %w", err)
	}

	return nil
}
