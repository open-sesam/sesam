package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/google/renameio"
	"golang.org/x/crypto/sha3"

	"filippo.io/age"
)

// assumption: signature fits into one page, a file with less that one page is suspicious here.
const maxFooterSize = 4096

type secret struct {
	Mgr *SecretManager

	// RevealedPath is relative to Mgr.SesamDir
	RevealedPath string

	// Recipients are the people that may reveal this secret.
	Recipients Recipients
}

type secretFooter struct {
	RevealedPath string `json:"path"`
	Hash         string `json:"hash"`
	Signature    string `json:"signature"`
	SealedBy     string `json:"sealed_by"`
}

// Seal encrypts `s` into .sesam/objects/$revealed_path.sesam
// The `sealedByUser` is the user that initiated the seal.
// The `tee` writer is optional and can be used to get a hold on the encrypted stream that is
// written to the disk.
func (s *secret) Seal(sealedByUser string) (*secretFooter, error) {
	rd, err := os.Open(filepath.Join(s.Mgr.SesamDir, s.RevealedPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open secret: %w", err)
	}
	defer closeLogged(rd)

	cryptPath := s.Mgr.cryptPath(s.RevealedPath)
	if err := os.MkdirAll(filepath.Dir(cryptPath), 0o700); err != nil {
		return nil, err
	}

	tmpDir := filepath.Join(s.Mgr.SesamDir, ".sesam", "tmp")
	wc, err := renameio.TempFile(tmpDir, cryptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted file in repo: %w", err)
	}

	defer func() {
		_ = wc.Cleanup()
	}()

	// use the stream to compute the hash, what is written to wc, is also written to the hash:
	h := sha3.New256()
	mw := io.MultiWriter(wc, h)

	encW, err := age.Encrypt(mw, s.Recipients.AgeRecipients()...)
	if err != nil {
		_ = os.Remove(wc.Name())
		return nil, fmt.Errorf("failed to initiate encryption: %w", err)
	}

	_, err = io.Copy(encW, rd)
	if err != nil {
		_ = os.Remove(wc.Name())
		return nil, fmt.Errorf("failed to encrypt secret %s: %w", s.RevealedPath, err)
	}

	if err := encW.Close(); err != nil {
		_ = os.Remove(wc.Name())
		return nil, fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	// NOTE: We use the path as well to make sure files cannot just be moved around.
	_, _ = h.Write([]byte(s.RevealedPath))
	hashBytes := h.Sum(nil)

	sig, err := s.Mgr.Signer.Sign(SesamDomainSignSecretTag, hashBytes)
	if err != nil {
		_ = os.Remove(wc.Name())
		return nil, fmt.Errorf("failed to compute signature for %s: %w", cryptPath, err)
	}

	ss := secretFooter{
		RevealedPath: s.RevealedPath,
		Hash:         MulticodeEncode(hashBytes, MhSHA3_256),
		Signature:    sig,
		SealedBy:     sealedByUser,
	}

	// Write signature to buffer, delimited by newline:
	if _, err := wc.Write([]byte("\n")); err != nil {
		return nil, err
	}

	sigJSONBytes, err := json.Marshal(ss)
	if err != nil {
		return nil, err
	}

	if len(sigJSONBytes) > maxFooterSize {
		slog.Warn("footer bigger than page", slog.Int("size", len(sigJSONBytes)))
	}

	if _, err := wc.Write(sigJSONBytes); err != nil {
		return nil, err
	}

	return &ss, wc.CloseAtomicallyReplace()
}

// readSignature seeks to the footer & parses it.
// It returns a reader that sees only the age content and the parsed signature.
func readSignature(fd io.ReadSeeker) (io.Reader, *secretFooter, error) {
	fileSize, err := fd.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, nil, err
	}

	readBack := min(fileSize, maxFooterSize)
	footerPageOffset, err := fd.Seek(-readBack, io.SeekEnd)
	if err != nil {
		return nil, nil, err
	}

	footerBuf := make([]byte, fileSize-footerPageOffset)
	if _, err := io.ReadFull(fd, footerBuf); err != nil {
		return nil, nil, err
	}

	idx := bytes.LastIndexByte(footerBuf, '\n')
	if idx < 0 {
		return nil, nil, fmt.Errorf("contains no signature footer or footer too big")
	}

	var ss secretFooter
	if err := json.Unmarshal(footerBuf[idx+1:], &ss); err != nil {
		return nil, nil, err
	}

	// move file cursor back to start for decryption.
	if _, err := fd.Seek(0, io.SeekStart); err != nil {
		return nil, nil, err
	}

	jsonTrailerSize := fileSize - (footerPageOffset + int64(idx))
	ageSize := fileSize - jsonTrailerSize
	return io.LimitReader(fd, ageSize), &ss, nil
}

// Reveal decrypts secret `s` and verifies its detached signature.
// No error is only returned if the reveal has been fully successful.
func (s *secret) Reveal() error {
	cryptPath := s.Mgr.cryptPath(s.RevealedPath)

	//nolint:gosec
	srcFd, err := os.Open(cryptPath)
	if err != nil {
		// if it does not exist, it probably means that the secret was not encrypted yet.
		return fmt.Errorf("opening secret file failed: %w", err)
	}

	defer closeLogged(srcFd)

	// Write revealed file to a temp file first, so we can get rid of it later easily:
	dstPath := filepath.Join(s.Mgr.SesamDir, s.RevealedPath)
	dstFd, err := renameio.TempFile(s.Mgr.tmpDir(), dstPath)
	if err != nil {
		return fmt.Errorf("failed to create revealed file: %w", err)
	}

	defer func() {
		// This will be a no-op when reaching CloseAtomicallyReplace() down.
		_ = dstFd.Cleanup()
	}()

	ids := s.Mgr.Identities.AgeIdentities()
	if err := revealStreamAndVerify(
		srcFd,
		dstFd,
		ids,
		s.Mgr.Keyring,
	); err != nil {
		return err
	}

	// TODO: Seal and reveal should carry over permissions and other attrs from the original file.
	// Git can only differentiate between executable and normal files, not between 0600 and 0644.
	// So default to 0600 to avoid troubles with ssh keys for now?
	_ = dstFd.Chmod(0o600)
	return dstFd.CloseAtomicallyReplace()
}

func revealStreamAndVerify(srcFd io.ReadSeeker, dstFd io.Writer, ageIds []age.Identity, kr Keyring) error {
	sha3HashBytes, sigDesc, err := revealStream(srcFd, dstFd, ageIds)
	if err != nil {
		return err
	}

	// Verify the signature, but check before if hashes are the same at all as quick check:
	computedhash := MulticodeEncode(sha3HashBytes, MhSHA3_256)
	if computedhash != sigDesc.Hash {
		return fmt.Errorf("encrypted file changed (exp: %s, got: %s)", computedhash, sigDesc.Hash)
	}

	if _, err := kr.Verify(
		SesamDomainSignSecretTag,
		sha3HashBytes,
		sigDesc.Signature,
		sigDesc.SealedBy,
	); err != nil {
		return fmt.Errorf("signature verification failed for %s: %w", sigDesc.RevealedPath, err)
	}

	return nil
}

func revealStream(srcFd io.ReadSeeker, dstFd io.Writer, ageIds []age.Identity) ([]byte, *secretFooter, error) {
	ageRd, sigDesc, err := readSignature(srcFd)
	if err != nil {
		return nil, nil, err
	}

	// Setup hashing parallel to decrypting:
	h := sha3.New256()
	tr := io.TeeReader(ageRd, h)

	encR, err := age.Decrypt(tr, ageIds...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt %s: %w", sigDesc.RevealedPath, err)
	}

	// Kick-off the decrypting and hashing:
	_, err = io.Copy(dstFd, encR)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy decrypted secret back in place: %w", err)
	}

	// Finish hash (includes path to make sure it is non-movable)
	_, _ = h.Write([]byte(sigDesc.RevealedPath))
	sha3HashBytes := h.Sum(nil)
	return sha3HashBytes, sigDesc, nil
}
