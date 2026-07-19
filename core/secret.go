package core

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"

	"github.com/sahib/renameio/v2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	"filippo.io/age"
)

// assumption: signature fits into one page, a file with less that one page is suspicious here.
const maxFooterSize = 4096

type secretFooter struct {
	RevealedPath    string `json:"path"`
	CipherTextHash  string `json:"cipher_text_hash"`
	HMACContentHash string `json:"hmac_content_hash"`
	RecipientsHash  string `json:"recipients_hash"`
	Signature       string `json:"signature"`
	SealedBy        string `json:"sealed_by"`
	Version         int    `json:"version"`
}

// recipientsHash digests the recipients' public keys, order-independent, so
// Seal can detect a changed recipient set (e.g. a user told into a group)
// without decrypting the object. It is folded into the footer signature, so a
// forged hash is caught by verification.
func recipientsHash(recipients Recipients) []byte {
	keys := make([]string, 0, len(recipients))
	for _, r := range recipients {
		keys = append(keys, r.String())
	}
	slices.Sort(keys)

	h := sha3.New256()
	for _, k := range keys {
		_, _ = h.Write([]byte(k))
		_, _ = h.Write([]byte{0}) // separate entries so a||b != ab
	}
	return h.Sum(nil)
}

func readAgeEncryptionKey(r io.Reader, ageIds []age.Identity) ([]byte, error) {
	hdrBytes, err := age.ExtractHeader(r)
	if err != nil {
		return nil, fmt.Errorf("failed to extract age header: %w", err)
	}

	ageKey, err := age.DecryptHeader(hdrBytes, ageIds...)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt age header: %w", err)
	}

	return ageKey, nil
}

func keyContentHash(ageKey, contentHash []byte) []byte {
	const info = "sesam.contenthash.v1"

	// derive actual key from the age encryption key:
	finalKey := make([]byte, 32)
	keyReader := hkdf.New(sha3.New256, ageKey, nil, []byte(info))

	_, _ = io.ReadFull(keyReader, finalKey)
	hm := hmac.New(sha3.New256, finalKey)
	_, _ = hm.Write(contentHash)
	hmacContentHash := hm.Sum(nil)
	return hmacContentHash
}

// sealSecret encrypts the plaintext at revealedPath to `destPath` (both
// repo-relative) for `recipients`, recording `sealedByUser` in the footer. The
// destination directory is created if missing; the write goes through a
// renameio temp file confined to the root so the final destination is replaced
// atomically.
func sealSecret(
	sm *SecretManager,
	revealedPath string,
	recipients Recipients,
	destPath, sealedByUser string,
) (*secretFooter, error) {
	rd, err := sm.root.Open(revealedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open secret: %w", err)
	}
	defer closeLogged(rd)

	if err := sm.root.MkdirAll(filepath.Dir(destPath), 0o700); err != nil {
		return nil, err
	}

	wc, err := renameio.NewPendingFile(destPath, renameio.WithRoot(sm.root), renameio.WithTempDir(sesamTmpDir(sm.base)), renameio.WithPermissions(0o600))
	if err != nil {
		return nil, fmt.Errorf("failed to open encrypted file in repo: %w", err)
	}

	defer func() {
		_ = wc.Cleanup()
	}()

	// use the stream to compute the hash, what is written to wc, is also written to the hash:
	ciphertextHash := sha3.New256()
	contentHash := sha3.New256()
	mw := io.MultiWriter(wc, ciphertextHash)

	encW, err := age.Encrypt(mw, recipients.AgeRecipients()...)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate encryption: %w", err)
	}

	_, err = io.Copy(encW, io.TeeReader(rd, contentHash))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt secret %s: %w", revealedPath, err)
	}

	if err := encW.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	// NOTE: We use the path as well to make sure files cannot just be moved around.
	_, _ = ciphertextHash.Write([]byte(revealedPath))
	_, _ = contentHash.Write([]byte(revealedPath))

	if _, err := wc.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek back to crypt file: %w", err)
	}

	ageKey, err := readAgeEncryptionKey(wc.File, sm.Identities.AgeIdentities())
	if err != nil {
		return nil, fmt.Errorf("failed to read age key: %w", err)
	}

	hmacContentHash := keyContentHash(ageKey, contentHash.Sum(nil))
	ciphertextHashBytes := ciphertextHash.Sum(nil)
	recipientsHashBytes := recipientsHash(recipients)
	sig, err := sm.Signer.Sign(
		SesamDomainSignSecretTag,
		slices.Concat(ciphertextHashBytes, hmacContentHash, recipientsHashBytes),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to compute signature for %s: %w", destPath, err)
	}

	ss := secretFooter{
		RevealedPath:    revealedPath,
		CipherTextHash:  MulticodeEncode(ciphertextHashBytes, MhSHA3_256),
		Signature:       sig,
		SealedBy:        sealedByUser,
		HMACContentHash: MulticodeEncode(hmacContentHash, MhSHA3_256),
		RecipientsHash:  MulticodeEncode(recipientsHashBytes, MhSHA3_256),
		Version:         1,
	}

	if _, err := wc.Seek(0, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("failed to seek back to crypt file: %w", err)
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
		// This might in theory happen for very very long paths and/or exceedingly long users.
		// If this ever becomes a real use case/problem we could go and make this dynamic.
		return nil, fmt.Errorf("footer bigger than page: %d - please file a bug", len(sigJSONBytes))
	}

	if _, err := wc.Write(sigJSONBytes); err != nil {
		return nil, err
	}

	return &ss, wc.CloseAtomicallyReplace()
}

// readFooter seeks to the footer & parses it.
// It returns a reader that sees only the age content and the parsed signature.
func readFooter(fd io.ReadSeeker) (io.ReadSeeker, *secretFooter, error) {
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

	// cap max reading size:
	return struct {
		io.Reader
		io.Seeker
	}{
		Seeker: fd,
		Reader: io.LimitReader(fd, ageSize),
	}, &ss, nil
}

// revealSecret decrypts the secret at `revealedPath` and verifies its
// detached signature. No error is only returned if the reveal has been
// fully successful.
func revealSecret(sm *SecretManager, revealedPath string) error {
	cryptPath := sm.cryptPath(revealedPath)

	srcFd, err := sm.root.Open(cryptPath)
	if err != nil {
		// if it does not exist, it probably means that the secret was not encrypted yet.
		return fmt.Errorf("opening secret file failed: %w", err)
	}

	defer closeLogged(srcFd)

	if err := sm.root.MkdirAll(filepath.Dir(revealedPath), 0o700); err != nil {
		return fmt.Errorf("failed to create revealed dir: %w", err)
	}

	// Write revealed file to a temp file first, so we can get rid of it later easily:
	dstFd, err := renameio.NewPendingFile(revealedPath, renameio.WithRoot(sm.root), renameio.WithTempDir(sesamTmpDir(sm.base)), renameio.WithPermissions(0o600))
	if err != nil {
		return fmt.Errorf("failed to create revealed file: %w", err)
	}

	defer func() {
		// This will be a no-op when reaching CloseAtomicallyReplace() down.
		_ = dstFd.Cleanup()
	}()

	ids := sm.Identities.AgeIdentities()
	if err := revealStreamAndVerify(
		srcFd,
		dstFd,
		ids,
		sm.Keyring,
		sm.State.SealerAuthorized,
	); err != nil {
		return err
	}

	// TODO: Seal and reveal should carry over permissions and other attrs from the original file.
	// Git can only differentiate between executable and normal files, not between 0600 and 0644.
	// So default to 0600 to avoid troubles with ssh keys for now?
	//
	// Ideas:
	// - Either give each secret in the config a permission param
	// - or store the original permission in the audit log, which is then used to restore it.
	_ = dstFd.Chmod(0o600)
	return dstFd.CloseAtomicallyReplace()
}

// BadSealerError is returned by revealStreamAndVerify when the
// footer's signature is cryptographically valid but the named sealer is
// not in the access list for that path. The decryption itself
// succeeded, so callers may choose to accept the plaintext anyway -
// the git smudge filter does this so `git checkout` keeps working
// against history written before the auth-check shipped.
type BadSealerError struct {
	SealedBy string
	Path     string
}

func (e *BadSealerError) Error() string {
	return fmt.Sprintf("sealer %s was not authorized to seal %s", e.SealedBy, e.Path)
}

// revealStreamAndVerify decrypts the stream in `srcFd`, then validates the footer.
// The result is piped to `dstFd`. For decryption the identities in `ageIds` are used.
// For verification `kr` checks if the signature fits to the encrypted content and
// using `authorize` we can check if the user was actually allowed to seal this file
// (to avoid having users overwrite secrets they have no access to).
//
// Authorization failure is returned as a typed *BadSealerError so callers
// can distinguish "decryption succeeded, policy says no" from cryptographic
// failures and apply different policies.
func revealStreamAndVerify(
	srcFd io.ReadSeeker,
	dstFd io.Writer,
	ageIds []age.Identity,
	kr Keyring,
	authorize func(user, path string) bool,
) error {
	cipherTextHash, contentHashBytes, footer, err := revealStream(srcFd, dstFd, ageIds)
	if err != nil {
		return err
	}

	// Verify the signature, but check before if hashes are the same at all as quick check:
	computedhash := MulticodeEncode(cipherTextHash, MhSHA3_256)
	if computedhash != footer.CipherTextHash {
		return fmt.Errorf("encrypted file changed (exp: %s, got: %s)", computedhash, footer.CipherTextHash)
	}

	recipientsHashBytes, _, err := multicodeDecode(footer.RecipientsHash)
	if err != nil {
		return fmt.Errorf("failed to decode recipients hash for %s: %w", footer.RevealedPath, err)
	}

	sealer, err := kr.Verify(
		SesamDomainSignSecretTag,
		slices.Concat(cipherTextHash, contentHashBytes, recipientsHashBytes),
		footer.Signature,
		footer.SealedBy,
	)
	if err != nil {
		return fmt.Errorf("signature verification failed for %s: %w", footer.RevealedPath, err)
	}

	if authorize != nil && !authorize(sealer, footer.RevealedPath) {
		return &BadSealerError{SealedBy: sealer, Path: footer.RevealedPath}
	}

	return nil
}

func revealStream(srcFd io.ReadSeeker, dstFd io.Writer, ageIds []age.Identity) ([]byte, []byte, *secretFooter, error) {
	ageRd, sigDesc, err := readFooter(srcFd)
	if err != nil {
		return nil, nil, nil, err
	}

	ageKey, err := readAgeEncryptionKey(srcFd, ageIds)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read age key: %w", err)
	}

	// set back to start so age.Decrypt works.
	if _, err := ageRd.Seek(0, io.SeekStart); err != nil {
		return nil, nil, nil, fmt.Errorf("seek to start failed: %w", err)
	}

	// Setup hashing parallel to decrypting:
	cipherTextHash := sha3.New256()
	tr := io.TeeReader(ageRd, cipherTextHash)

	encR, err := age.Decrypt(tr, ageIds...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decrypt %s: %w", sigDesc.RevealedPath, err)
	}

	contentHash := sha3.New256()

	// Kick-off the decrypting and hashing:
	_, err = io.Copy(dstFd, io.TeeReader(encR, contentHash))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to copy decrypted secret back in place: %w", err)
	}

	// Finish hashses (includes path to make sure it is non-movable)
	_, _ = cipherTextHash.Write([]byte(sigDesc.RevealedPath))
	_, _ = contentHash.Write([]byte(sigDesc.RevealedPath))

	hmacContentHash := keyContentHash(ageKey, contentHash.Sum(nil))
	return cipherTextHash.Sum(nil), hmacContentHash, sigDesc, nil
}
