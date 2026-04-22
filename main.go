package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/open-sesam/sesam/cli"
	"github.com/open-sesam/sesam/core"
)

// initMain shows the setup done during init
func initMain(id *core.Identity) *core.SecretManager {
	signer, auditLog, err := core.InitAdminUser(
		context.Background(),
		".",
		"sahib",
		"github:sahib",
	)
	if err != nil {
		log.Fatalf("failed to init admin user: %v", err)
	}

	keyring := core.EmptyKeyring()
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
	keyring := core.EmptyKeyring()
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
	if err := cli.Main(os.Args); err != nil {
		slog.Error("exit", slog.Any("error", err))
		os.Exit(1)
	}

}
