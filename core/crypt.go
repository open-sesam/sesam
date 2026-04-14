package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/renameio"
	"golang.org/x/crypto/sha3"

	"filippo.io/age"
)

type Signer interface {
	Sign(data []byte) (string, error)
	PublicKey() []byte
	UserName() string
}

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

type Secret struct {
	Mgr *SecretManager

	// RevealedPath is relative to Mgr.RepoDir
	// TODO: enforce this. Also make sure that path is not a symbolic link and contains no ".." or similar.
	RevealedPath string

	// TODO: Needs to be parsed from a recipient file or public key list using age.ParseRecipient
	Recipients Recipients
}

type SecretSignature struct {
	RevealedPath string `json:"path"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature"`
	SealedBy     string `json:"sealed_by"`
}

func (s *Secret) Seal(sealedByUser string) (*SecretSignature, error) {
	rd, err := os.Open(filepath.Join(s.Mgr.RepoDir, s.RevealedPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open secret: %w", err)
	}
	defer closeLogged(rd)

	wc, encryptedPath, err := s.Mgr.cryptWriter(s.RevealedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted file in repo: %w", err)
	}
	defer closeLogged(wc)

	// use the stream to compute the hash, what is written to wc, is also written to the hash:
	h := sha3.New256()
	mw := io.MultiWriter(wc, h)

	encW, err := age.Encrypt(mw, s.Recipients.AgeRecipients()...)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate encryption: %w", err)
	}

	_, err = io.Copy(encW, rd)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret %s: %w", s.RevealedPath, err)
	}

	if err := encW.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	// NOTE: We use the path as well to make sure files cannot just be moved around.
	_, _ = h.Write([]byte(s.RevealedPath))
	hashBytes := h.Sum(nil)

	sig, err := s.Mgr.Signer.Sign(hashBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compute signature for %s: %w", encryptedPath, err)
	}

	ss := SecretSignature{
		RevealedPath: s.RevealedPath,
		Hash:         MulticodeEncode(hashBytes, MhSHA3_256),
		Signature:    sig,
		SealedBy:     sealedByUser,
	}

	// Write signature to buffer:
	sigBuf := &bytes.Buffer{}
	enc := json.NewEncoder(sigBuf)
	enc.SetIndent("", "  ")
	_ = enc.Encode(ss)

	// write the signature file along the encrypted file:
	sigPath := SignaturePath(s.Mgr.RepoDir, s.RevealedPath)
	if err := renameio.WriteFile(sigPath, sigBuf.Bytes(), 0600); err != nil {
		return nil, err
	}

	return &ss, nil
}

// Reveal decrypts secret `s` and verifies its detached signature.
// No error is only returned if the reveal has been fully successful.
func (s *Secret) Reveal() error {
	cryptPath := s.Mgr.cryptPath(s.RevealedPath)
	srcFd, err := os.Open(cryptPath)
	if err != nil {
		// if it does not exist, it probably means that the secret was not encrypted yet.
		return fmt.Errorf("opening secret file failed: %w", err)
	}

	defer closeLogged(srcFd)

	// Setup hashing parallel to decrypting:
	h := sha3.New256()
	tr := io.TeeReader(srcFd, h)

	ageIds := s.Mgr.Identities.AgeIdentities()
	encR, err := age.Decrypt(tr, ageIds...)
	if err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", s.RevealedPath, err)
	}

	// Write revealed file to a temp file first, so we can get rid of it later easily:
	dstPath := filepath.Join(s.Mgr.RepoDir, s.RevealedPath)
	dstFd, err := renameio.TempFile(s.Mgr.tmpDir(), dstPath)
	if err != nil {
		return fmt.Errorf("failed to create revealed file: %w", err)
	}

	defer func() {
		// This will be a no-op when reaching CloseAtomicallyReplace() down.
		_ = dstFd.Cleanup()
	}()

	// Kick-off the decrypting and hashing:
	_, err = io.Copy(dstFd, encR)
	if err != nil {
		return fmt.Errorf("failed to copy decrypted secret back in place: %w", err)
	}

	sigDesc, err := ReadStoredSignature(s.Mgr.RepoDir, s.RevealedPath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Finish hash (includes path to make sure it is )
	_, _ = h.Write([]byte(s.RevealedPath))
	sha3HashBytes := h.Sum(nil)

	// Verify the signature, but check before if hashes are the same at all as quick check:
	expectedHash := MulticodeEncode(sha3HashBytes, MhSHA3_256)
	if expectedHash != sigDesc.Hash {
		return fmt.Errorf("encrypted file changed (exp: %s, got: %s)", expectedHash, sigDesc.Hash)
	}

	if _, err := s.Mgr.Keyring.Verify(
		sha3HashBytes,
		sigDesc.Signature,
		sigDesc.SealedBy,
	); err != nil {
		// verification failed, abort.
		return err
	}

	// TODO: Seal and reveal should carry over permissions and other attrs from the original file.
	// Git can only differentiate between executable and normal files, not between 0600 and 0644.
	// So default to 0600 to avoid troubles with ssh keys for now?
	_ = dstFd.Chmod(0600)
	return dstFd.CloseAtomicallyReplace()
}
