package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

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

	fmt.Println("Who am I:", whoami)

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

	var auditLog *core.AuditLog
	if isInit {
		signKeyStr := core.MulticodeEncode(signer.PublicKey(), core.MhEd25519Pub)
		auditLog, err = core.EmptyLog(".", signer, keyring, core.DetailUserTell{
			User:        whoami,
			Groups:      []string{"admin"},
			PubKeys:     []string{recp.String()},
			SignPubKeys: []string{signKeyStr},
		})
		if err != nil {
			log.Fatalf("failed to init audit log: %v", err)
		}

		_ = auditLog.Store()
	} else {
		auditLog, err = core.LoadAuditLog(
			".",
			signer,
			keyring,
		)
		if err != nil {
			log.Fatalf("failed to load audit log: %v", err)
		}
	}

	verifyStart := time.Now()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		log.Fatalf("failed to verify log: %v", err)
	}

	fmt.Println("verify took", time.Since(verifyStart))

	// TODO: an extended verify could also check if last root hash == sm.RootHash + also check every physical file.

	sm, err := core.BuildSecretManager(
		".",
		whoami,
		core.Identities{id},
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		log.Fatalf("failed to build secret manager: %v", err)
	}

	if isInit {
		err = sm.AddOrChangeSecret("DESIGN.new", []string{"admin"})
		if err != nil {
			log.Fatalf("failed to add secret: %v", err)
		}

		_ = auditLog.Store()
	}

	err = sm.SealAll()
	if err != nil {
		log.Fatalf("failed to create audit log: %v", err)
	}

	if err := sm.RevealAll(); err != nil {
		log.Fatalf("reveal failed: %v", err)
	}
}
