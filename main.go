package main

import (
	"context"
	"log"
	"os"

	"filippo.io/age"
	"github.com/open-sesam/sesam/core"
)

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

	sm := &core.SecretManager{
		RepoDir:    ".",
		Identities: ids,
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
