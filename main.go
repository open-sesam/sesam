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

	id, err := core.ParseIdentity(string(privKey), &core.KeyringPassphraseProvider{
		KeyFingerprint: "sesam.id.chris",
		Fallback:       &core.StdinPassphraseProvider{},
	})
	if err != nil {
		log.Fatalf("failed to parse identities: %v", err)
	}

	signer, err := core.LoadSignKey(".", "sahib", id)
	if err != nil {
		signer, err = core.GenerateSignKey(".", "sahib", recp)
		if err != nil {
			log.Fatalf("failed to load/gen signing key: %v", err)
		}
	}

	sm := &core.SecretManager{
		RepoDir:    ".",
		Identities: core.Identities{id},
		Signer:     signer,
	}

	secret := &core.Secret{
		Mgr:          sm,
		RevealedPath: "DESIGN.new",
		Recipients:   []age.Recipient{recp},
	}

	auditLog, err := core.LoadAuditLog(
		".",
		signer,
	)
	if err != nil {
		log.Fatalf("failed to create audit log: %w", err)
	}

	fmt.Println("SEAL", secret.RevealedPath)
	if err := secret.Seal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}

	if err := auditLog.AddEntry(core.OpSeal, "sahib", core.AuditEntrySeal{
		RootHash:    core.Hash([]byte("blub")), // TODO: build util method to create this hash, for now dummy.
		FilesSealed: 1,
	}); err != nil {
		log.Fatalf("add seal audit failed: %w", err)
	}

	if err := auditLog.Store(); err != nil {
		log.Fatalf("storing log failed: %w", err)
	}

	fmt.Println("REVEAL", secret.RevealedPath)
	if err := secret.Reveal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}
}
