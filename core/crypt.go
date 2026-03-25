package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/renameio"
	"golang.org/x/crypto/sha3"

	"filippo.io/age"
)

type Signer interface {
	Sign(data []byte) (string, error)
	Verify(data []byte, signature string) error
	PublicKey() []byte
}

type SecretManager struct {
	RepoDir string

	// TOOD: Needs to be parsed from a list of private keys supplied by the user.
	Identities []age.Identity

	Signer Signer
}

func (sm *SecretManager) cryptPath(path string) string {
	return filepath.Join(sm.RepoDir, ".sesam", "objects", path)
}

func (sm *SecretManager) cryptWriter(path string) (io.WriteCloser, string, error) {
	cryptPath := sm.cryptPath(path)
	if err := os.MkdirAll(filepath.Dir(cryptPath), 0700); err != nil {
		return nil, "", err
	}

	fd, err := os.Create(cryptPath)
	return fd, cryptPath, err
}

type Secret struct {
	Mgr *SecretManager

	// RevealedPath is relative to Mgr.RepoDir
	// TODO: enforce this. Also make sure that path is not a symbolic link and contains no ".." or similar.
	RevealedPath string

	// TODO: Needs to be parsed from a recipient file or public key list using age.ParseRecipient
	Recipients []age.Recipient
}

// NOTE: Signature strategy:
//
// - Hash file using sha3 after encrypt.
// - Decrypt signing key to memory.
// - Sign hash with private signing key.
// - Zero out signing key in memory. (if all files done)
// - Write hash + signature to .sesam/objects/$path.sig.json

// TODO: use self describing hashes like ipfs?
type SecretSignature struct {
	Path      string `json:"path"`
	Hash      string `json:"hash"`
	Signature string `json:"signature"`
}

func (s *Secret) Seal() error {
	fmt.Println("SEAL", s.RevealedPath)

	rd, err := os.Open(filepath.Join(s.Mgr.RepoDir, s.RevealedPath))
	if err != nil {
		return fmt.Errorf("failed to open secret: %w", err)
	}
	defer rd.Close()

	wc, encryptedPath, err := s.Mgr.cryptWriter(s.RevealedPath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file in repo: %w", err)
	}
	defer wc.Close()

	// use the stream to compute the hash, what is written to wc, is also written to the hash.
	h := sha3.New256()
	mw := io.MultiWriter(wc, h)

	encW, err := age.Encrypt(mw, s.Recipients...)
	if err != nil {
		return fmt.Errorf("failed to initiate encryption: %w", err)
	}

	_, err = io.Copy(encW, rd)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret %s: %w", s.RevealedPath, err)
	}

	if err := encW.Close(); err != nil {
		return fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	// NOTE: We use the path as well to make sure files cannot just be moved around.
	fmt.Println("HASH", s.RevealedPath)
	h.Write([]byte(s.RevealedPath))
	hashBytes := h.Sum(nil)

	sig, err := s.Mgr.Signer.Sign(hashBytes)
	if err != nil {
		return fmt.Errorf("failed to compuite signature for %s: %w", encryptedPath, err)
	}

	sigBuf := &bytes.Buffer{}
	enc := json.NewEncoder(sigBuf)
	enc.SetIndent("", "  ")
	enc.Encode(SecretSignature{
		Path:      s.RevealedPath,
		Hash:      base64.StdEncoding.EncodeToString(hashBytes),
		Signature: sig,
	})

	signaturePath := strings.TrimSuffix(encryptedPath, ".age") + ".sig.json"

	// write the signature file along the encrypted file:
	return renameio.WriteFile(signaturePath, sigBuf.Bytes(), 0600)
}

func (s *Secret) Reveal() error {
	cryptPath := s.Mgr.cryptPath(s.RevealedPath)
	fmt.Println("REVEAL", cryptPath)
	srcFd, err := os.Open(cryptPath)
	if err != nil {
		// if it does not exist, it probably means that the secret was not encrypted yet.
		return fmt.Errorf("opening secret file failed: %w", err)
	}

	h := sha3.New256()
	tr := io.TeeReader(srcFd, h)

	encR, err := age.Decrypt(tr, s.Mgr.Identities...)
	if err != nil {
		_ = srcFd.Close()
		return fmt.Errorf("failed to decrypt %s: %w", s.RevealedPath, err)
	}

	dstFd, err := os.Create(filepath.Join(s.Mgr.RepoDir, s.RevealedPath))
	if err != nil {
		_ = srcFd.Close()
		return fmt.Errorf("failed to create revealed file: %w", err)
	}

	_, err = io.Copy(dstFd, encR)
	if err != nil {
		_ = srcFd.Close()
		_ = dstFd.Close()
		return fmt.Errorf("failed to copy decrypted secret back in place: %w", err)
	}

	_ = srcFd.Close()
	_ = dstFd.Close()

	// Verify the signature:
	h.Write([]byte(s.RevealedPath))
	sha3HashBytes := h.Sum(nil)
	signaturePath := strings.TrimSuffix(cryptPath, ".age") + ".sig.json"
	fd, err := os.Open(signaturePath)
	if err != nil {
		return fmt.Errorf("failed to open signature json: %w", err)
	}
	defer fd.Close()

	var sigDesc SecretSignature
	dec := json.NewDecoder(fd)
	if err := dec.Decode(&sigDesc); err != nil {
		return fmt.Errorf("failed to decode signature json %s: %w", signaturePath, err)
	}

	expectedHash := base64.StdEncoding.EncodeToString(sha3HashBytes[:])
	if expectedHash != sigDesc.Hash {
		return fmt.Errorf("encrypted file changed (exp: %s, got: %s)", expectedHash, sigDesc.Hash)
	}

	if err := s.Mgr.Signer.Verify(sha3HashBytes, sigDesc.Signature); err != nil {
		// verification failed; abort. TODO: We already decrypted the file though. Remove it again?
		return err
	}

	return nil
}
