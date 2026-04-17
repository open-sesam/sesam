package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/open-sesam/sesam/core"
)

// initMain shows the setup done during init
func initMain(id *core.Identity) *core.SecretManager {
	whoami := "sahib" // given as argument on init

	// core.ResolveRecipient and core.ParseRecipient only has to be done once per user add.
	// init means adding an initial user, so assume we get the public key here via the config or something.
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

	signer, err := core.GenerateSignKey(".", whoami, recp.Recipient)
	if err != nil {
		log.Fatalf("failed to gen signing key: %v", err)
	}

	keyring := core.NewMemoryKeyring()

	signKeyStr := core.MulticodeEncode(signer.PublicKey(), core.MhEd25519Pub)
	auditLog, err := core.InitLog(".", signer, core.DetailUserTell{
		User:        signer.UserName(),
		Groups:      []string{"admin"},
		PubKeys:     []string{recp.String()},
		SignPubKeys: []string{signKeyStr},
	})
	if err != nil {
		log.Fatalf("failed to init audit log: %v", err)
	}

	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		log.Fatalf("failed to verify log: %v", err)
	}

	sm, err := core.BuildSecretManager(
		".",
		core.Identities{id},
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		log.Fatalf("failed to build secret manager: %v", err)
	}

	err = sm.AddSecret("DESIGN.new", []string{"admin"})
	if err != nil {
		log.Fatalf("failed to add secret: %v", err)
	}

	return sm
}

// regularMain shows the setup done in all commands after init
func regularMain(id *core.Identity) *core.SecretManager {
	keyring := core.NewMemoryKeyring()

	auditLog, err := core.LoadAuditLog(".")
	if err != nil {
		log.Fatalf("failed to load audit log: %v", err)
	}

	verifyStart := time.Now()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		log.Fatalf("failed to verify log: %v", err)
	}
	fmt.Println("verify took", time.Since(verifyStart))

	// Verify populates the keyring. We can now check to what user our identity maps to.
	whoami, err := core.IdentityToUser(id, keyring.ListUsers())
	if err != nil {
		log.Fatalf("failed to identity ourselves: %v", err)
	}

	fmt.Println("Who am I:", whoami)

	signer, err := core.LoadSignKey(".", whoami, id)
	if err != nil {
		log.Fatalf("failed to load sign key: %v", err)
	}

	sm, err := core.BuildSecretManager(
		".",
		core.Identities{id},
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		log.Fatalf("failed to build secret manager: %v", err)
	}

	// Optional, just a double check, can be done later on the `verify` command.
	report := core.VerifyIntegrity(".", vstate, keyring)
	if !report.OK() {
		fmt.Println(report.String())
	}

	return sm
}

func main() {
	// change that path to fit your key path and github:sahib to your key name
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

	var sm *core.SecretManager
	if _, err := os.Stat(".sesam/audit"); os.IsNotExist(err) {
		fmt.Println("INIT")
		sm = initMain(id)
	} else {
		fmt.Println("REGULAR")
		sm = regularMain(id)
	}

	err = sm.SealAll()
	if err != nil {
		log.Fatalf("failed to create audit log: %v", err)
	}

	if err := sm.RevealAll(); err != nil {
		log.Fatalf("reveal failed: %v", err)
	}

	_ = sm.AuditLog.Close()
}
