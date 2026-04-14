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
		// TODO: This mapping will later come from the config or audit log.
		// 			 Should we double check there is no mismatch between audit and config?
		"sahib": recp,
	})
	if err != nil {
		log.Fatalf("failed to identity ourselves: %v", err)
	}

	fmt.Println("I am:", whoami)

	isInit := false

	signer, err := core.LoadSignKey(".", whoami, id)
	if err != nil {
		signer, err = core.GenerateSignKey(".", whoami, recp.Recipient)
		if err != nil {
			log.Fatalf("failed to load/gen signing key: %v", err)
		}

		isInit = true
	}

	keyring := core.NewMemoryKeyring()
	keyring.AddSignPubKey(whoami, signer.PublicKey())
	keyring.AddRecipient(whoami, recp)

	auditLog, err := core.LoadAuditLog(
		".",
		signer,
		keyring,
	)

	if isInit {
		signKeyStr := core.MulticodeEncode(signer.PublicKey(), core.MhEd25519Pub)
		entry := core.NewAuditEntry(core.OpUserTell, whoami, &core.DetailUserTell{
			User:        whoami,
			Groups:      []string{"admin"},
			PubKeys:     []string{recp.String()},
			SignPubKeys: []string{signKeyStr},
		})
		auditLog.AddEntry(entry)
	}

	sm := &core.SecretManager{
		RepoDir:    ".",
		Identities: core.Identities{id},
		Signer:     signer,
		Keyring:    keyring,
	}

	secret := &core.Secret{
		Mgr:          sm,
		RevealedPath: "DESIGN.new",
		Recipients:   keyring.Recipients([]string{"sahib"}),
	}

	if err != nil {
		log.Fatalf("failed to create audit log: %v", err)
	}

	fmt.Println("SEAL", secret.RevealedPath)

	sig, err := secret.Seal(whoami)
	if err != nil {
		log.Fatalf("seal failed: %v", err)
	}

	entry := core.NewAuditEntry(core.OpSeal, whoami, &core.DetailSeal{
		RootHash:    core.BuildRootHash([]*core.SecretSignature{sig}),
		FilesSealed: 1,
	})

	if _, err := auditLog.AddEntry(entry); err != nil {
		log.Fatalf("add seal audit failed: %v", err)
	}

	if err := auditLog.Store(); err != nil {
		log.Fatalf("storing log failed: %v", err)
	}

	fmt.Println("REVEAL", secret.RevealedPath)
	if err := secret.Reveal(); err != nil {
		log.Fatalf("seal failed: %v", err)
	}

	if err := core.VerifyInitFileUnchanged("."); err != nil {
		log.Fatalf("init file was changed")
	}

	// TODO: We also need to check that audit lo was not truncated:
	// 			 By checking git history of .sesam/audit/init
	// NOTE: normally we would do that before much else.
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		log.Fatalf("failed to verify log: %v", err)
	}

	fmt.Printf("state: %+v\n", vstate)
}
