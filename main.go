package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"filippo.io/age"
	"github.com/open-sesam/sesam/core"
)

// TODO: Move a lot of this stuff to a proper init module.

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

	signer, err := core.LoadSignKey(".", "sahib", ids[0])
	if err != nil {
		signer, err = core.GenerateSignKey(".", "sahib", recp)
		if err != nil {
			log.Fatalf("failed to load/gen signing key: %v", err)
		}
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

	fmt.Println("SEAL", secret.RevealedPath)
	if err := secret.Seal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}

	fmt.Println("REVEAL", secret.RevealedPath)
	if err := secret.Reveal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}
}
