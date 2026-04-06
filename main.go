package main

import (
	"context"
	"fmt"
	"log"
	"os"

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

	whoami, err := core.IdentityToUser(id, map[string]*core.Recipient{
		"sahib": recp,
	})
	if err != nil {
		log.Fatalf("failed to identity ourselves: %v", err)
	}

	fmt.Println("I am:", whoami)

	signer, err := core.LoadSignKey(".", "sahib", id)
	if err != nil {
		signer, err = core.GenerateSignKey(".", "sahib", recp.Recipient)
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
		Recipients:   core.Recipients{recp},
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

	entry := core.NewAuditEntry(core.OpSeal, "sahib", &core.DetailSeal{
		RootHash:    core.Hash([]byte("blub")), // TODO: build util method to create this hash, for now dummy.
		FilesSealed: 1,
	})

	if err := auditLog.AddEntry(entry); err != nil {
		log.Fatalf("add seal audit failed: %v", err)
	}

	if err := auditLog.Store(); err != nil {
		log.Fatalf("storing log failed: %v", err)
	}

	fmt.Println("REVEAL", secret.RevealedPath)
	if err := secret.Reveal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}

	if err := core.Verify(auditLog); err != nil {
		log.Fatalf("failed to verify log: %v", err)
	}
}
