package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/google/renameio"
)

type ed25519Signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func (es *ed25519Signer) Sign(data []byte) (string, error) {
	sig, err := es.priv.Sign(rand.Reader, data, &ed25519.Options{})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(sig), nil
}

func (es *ed25519Signer) Verify(data []byte, signature string) error {
	sigData, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	ok := ed25519.Verify(es.pub, data, sigData)
	if !ok {
		return fmt.Errorf("could not validate signature '%s'", signature)
	}

	return nil
}

func (es *ed25519Signer) PublicKey() []byte {
	return es.pub
}

// LoadSignKey will load a signer specific to a user and decrypt it via `userIdentity`
func LoadSignKey(repoDir, user string, userIdentity age.Identity) (Signer, error) {
	signKeyPath := filepath.Join(repoDir, ".sesam", "signkey", user+".age")
	cryptedSignPrivKeyFd, err := os.Open(signKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key %s: %w", signKeyPath, err)
	}

	dr, err := age.Decrypt(io.LimitReader(cryptedSignPrivKeyFd, 1024), userIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt header of signing key: %v", err)
	}

	defer closeLogged(cryptedSignPrivKeyFd)

	signingKeyBase64, err := io.ReadAll(dr)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt signing key: %v", err)
	}

	signPrivKeyRaw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(signingKeyBase64)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode sign key %s: %w", signKeyPath, err)
	}

	// ed25519 priv keys should always be 64 bytes.
	if l := len(signPrivKeyRaw); l != 64 {
		return nil, fmt.Errorf("signing key has an unexpected length (%d) and not 64", l)
	}

	// TODO: Verify the loaded public key is the same as in the config.
	// 			 If so we should error out.
	//       This should also be done as part of verify.

	signPrivKey := ed25519.PrivateKey(signPrivKeyRaw)
	return &ed25519Signer{
		pub:  signPrivKey.Public().(ed25519.PublicKey),
		priv: signPrivKey,
	}, nil
}

// GenerateSignKey will generate a new ed25519 signing key only accessible to `userRecipient`
func GenerateSignKey(repoDir, user string, userRecipient age.Recipient) (Signer, error) {
	signKeyPath := filepath.Join(repoDir, ".sesam", "signkey", user+".age")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key %s: %w", signKeyPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(signKeyPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to mkdir signing key dir: %w", err)
	}

	ageBuf := &bytes.Buffer{}
	wc, err := age.Encrypt(ageBuf, userRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt signing key: %w", err)
	}

	if _, err := wc.Write([]byte(base64.StdEncoding.EncodeToString(priv[:]))); err != nil {
		return nil, fmt.Errorf("failed to encrypt hash: %w", err)
	}

	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("failed to close encrypted writer: %w", err)
	}

	if err := renameio.WriteFile(signKeyPath, ageBuf.Bytes(), 0600); err != nil {
		return nil, fmt.Errorf("failed to write signing key %s: %w", signKeyPath, err)
	}

	// TODO:
	// - The signing key is stored encrypted via age on disk.
	// - It is used to sign the hash of encrypted files.
	// - The encryption itself is not signed, i.e. someone could just replace it without us noticing.
	// - We therefore need to store the public key (and maybe a hash of the private key)
	//   (hash is not necessary probably, because )
	fmt.Println("TODO: Store this in admin signed config", base64.StdEncoding.EncodeToString(pub))
	return &ed25519Signer{
		pub:  pub,
		priv: priv,
	}, nil
}

func SignaturePath(repoDir, revealedPath string) string {
	return filepath.Join(repoDir, ".sesam", "objects", revealedPath+".sig.json")
}

// ReadStoredSignature will open the signature file belonging to `revealedPath`.
// You will get an error if it has not been sealed yet.
func ReadStoredSignature(repoDir, revealedPath string) (SecretSignature, error) {
	sigPath := SignaturePath(repoDir, revealedPath)
	sigFd, err := os.Open(sigPath)
	if err != nil {
		return SecretSignature{}, fmt.Errorf("failed to open signature json: %w", err)
	}

	defer closeLogged(sigFd)

	var sigDesc SecretSignature
	dec := json.NewDecoder(io.LimitReader(sigFd, 1024))
	if err := dec.Decode(&sigDesc); err != nil {
		return SecretSignature{}, fmt.Errorf("failed to decode signature json %s: %w", sigPath, err)
	}

	return sigDesc, nil
}
