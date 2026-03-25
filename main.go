package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/google/renameio"
	"github.com/open-sesam/sesam/core"
)

// TODO: Move a lot of this stuff to a proper init module.

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

func loadSignKey(repoDir, user string, userIdentity age.Identity) (core.Signer, error) {
	signKeyPath := filepath.Join(repoDir, ".sesam", "signkey", user+".age")

	// TODO: io.LimitReader() to avoid ddos when substituting a large file
	cryptedSignPrivKey, err := os.ReadFile(signKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key %s: %w", signKeyPath, err)
	}

	dr, err := age.Decrypt(bytes.NewReader(cryptedSignPrivKey), userIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt header of signing key: %v", err)
	}

	signingKeyBase64, err := io.ReadAll(dr)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt signing key: %v", err)
	}

	signPrivKeyRaw, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(signingKeyBase64)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode sign key %s: %w", signKeyPath, err)
	}

	if l := len(signPrivKeyRaw); l != 64 {
		return nil, fmt.Errorf("signing key has an unexpected length (%d) and not 64", l)
	}

	// TODO: Verify the loaded public key is the same as in the config. If so we should error out.
	//       This should also be done as part of verify.

	signPrivKey := ed25519.PrivateKey(signPrivKeyRaw)
	return &ed25519Signer{
		pub:  signPrivKey.Public().(ed25519.PublicKey),
		priv: signPrivKey,
	}, nil
}

func genSignKey(repoDir, user string, userRecipient age.Recipient) (core.Signer, error) {
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

func main() {
	rawPubKey, err := core.ResolveRecipient(
		context.Background(),
		".",
		"github:sahib",
		core.CacheModeReadWrite,
	)
	if err != nil {
		log.Fatalf("failed to download recipient: %v", err)
	}

	recp, err := core.ParseRecipient(rawPubKey)
	if err != nil {
		log.Fatalf("failed to parse recipient: %v", err)
	}

	privKey, err := os.ReadFile("/home/chris/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("failed to read private key: %v", err)
	}

	ids, err := core.ParseIdentities(privKey, &core.KeyringPassphraseProvider{
		KeyFingerprint: "sesam.id.chris",
		Fallback:       &core.StdinPassphraseProvider{},
	})
	if err != nil {
		log.Fatalf("failed to parse identities: %v", err)
	}

	if _, err := genSignKey(".", "sahib", recp); err != nil {
		log.Fatalf("failed to gen signing key: %v", err)
	}

	signer, err := loadSignKey(".", "sahib", ids[0])
	if err != nil {
		log.Fatalf("failed to load signing key: %v", err)
	}

	sm := &core.SecretManager{
		RepoDir:    ".",
		Identities: ids,
		Signer:     signer,
	}

	secret := &core.Secret{
		Mgr:          sm,
		RevealedPath: "DESIGN.new",
		Recipients:   []age.Recipient{recp},
	}

	if err := secret.Seal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}

	if err := secret.Reveal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}
}
