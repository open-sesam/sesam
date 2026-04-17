package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestIntegrationInitAndRegular mirrors the two-phase flow in main.go:
//
//  1. "init" — create repo, generate sign key, init audit log, add a secret,
//     seal everything, store.
//  2. "regular" — load audit log, verify, resolve identity → user, load sign
//     key, build manager, run integrity check, seal + reveal.
func TestIntegrationInitAndRegular(t *testing.T) {
	repoDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")
	whoami := admin.Name

	// ── Phase 1: init ────────────────────────────────────────────────
	signer, err := GenerateSignKey(repoDir, whoami, admin.Recipient.Recipient)
	require.NoError(t, err)

	keyring := EmptyKeyring()
	signKeyStr := MulticodeEncode(signer.PublicKey(), MhEd25519Pub)

	auditLog, err := InitAuditLog(repoDir, signer, DetailUserTell{
		User:        whoami,
		Groups:      []string{"admin"},
		PubKeys:     []string{admin.Recipient.String()},
		SignPubKeys: []string{signKeyStr},
	})
	require.NoError(t, err)

	gitCommitAll(t, repo, "sesam init")

	vstate, err := Verify(auditLog, keyring)
	require.NoError(t, err, "Verify after init")

	sm, err := BuildSecretManager(
		repoDir,
		Identities{admin.Identity},
		signer, keyring, auditLog, vstate,
	)
	require.NoError(t, err)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(repoDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	secretPath := "secrets/db_password"
	writeSecret(t, repoDir, secretPath, "hunter2")
	require.NoError(t, sm.AddSecret(secretPath, []string{"admin"}))
	require.NoError(t, sm.SealAll())

	gitCommitAll(t, repo, "add secret and seal")

	agePath := filepath.Join(repoDir, ".sesam", "objects", secretPath+".age")
	require.FileExists(t, agePath)

	// Remove plaintext to simulate a fresh clone.
	os.Remove(filepath.Join(repoDir, secretPath))

	// ── Phase 2: regular (simulates opening an existing repo) ────────
	require.NoError(t, auditLog.Close())
	keyring2 := EmptyKeyring()
	auditLog2, err := LoadAuditLog(repoDir)
	require.NoError(t, err)

	vstate2, err := Verify(auditLog2, keyring2)
	require.NoError(t, err, "Verify on reload")

	resolvedUser, err := IdentityToUser(admin.Identity, keyring2.ListUsers())
	require.NoError(t, err)
	require.Equal(t, whoami, resolvedUser)

	signer2, err := LoadSignKey(repoDir, resolvedUser, admin.Identity)
	require.NoError(t, err)

	sm2, err := BuildSecretManager(
		repoDir,
		Identities{admin.Identity},
		signer2, keyring2, auditLog2, vstate2,
	)
	require.NoError(t, err)

	report := VerifyIntegrity(repoDir, vstate2, keyring2)
	require.True(t, report.OK(), "integrity check failed: %s", report.String())

	require.NoError(t, sm2.RevealAll())
	got, err := os.ReadFile(filepath.Join(repoDir, secretPath))
	require.NoError(t, err)
	require.Equal(t, "hunter2", string(got))
}

// TestIntegrationMultiUser exercises adding a second user and verifying
// they can seal/reveal secrets assigned to their group.
func TestIntegrationMultiUser(t *testing.T) {
	repoDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")

	signer, err := GenerateSignKey(repoDir, "admin", admin.Recipient.Recipient)
	require.NoError(t, err)

	keyring := EmptyKeyring()
	signKeyStr := MulticodeEncode(signer.PublicKey(), MhEd25519Pub)
	al, err := InitAuditLog(repoDir, signer, DetailUserTell{
		User:        "admin",
		Groups:      []string{"admin"},
		PubKeys:     []string{admin.Recipient.String()},
		SignPubKeys: []string{signKeyStr},
	})
	require.NoError(t, err)
	gitCommitAll(t, repo, "init")

	vstate, err := Verify(al, keyring)
	require.NoError(t, err)

	// ── Admin adds bob ──
	bob := newTestUser(t, "bob")
	bobSignKey, err := GenerateSignKey(repoDir, "bob", bob.Recipient.Recipient)
	require.NoError(t, err)

	bobSignKeyStr := MulticodeEncode(bobSignKey.PublicKey(), MhEd25519Pub)
	_, err = al.AddEntry(signer, newAuditEntry("admin", &DetailUserTell{
		User:        "bob",
		Groups:      []string{"dev"},
		PubKeys:     []string{bob.Recipient.String()},
		SignPubKeys: []string{bobSignKeyStr},
	}), nil)
	require.NoError(t, err)

	secretPath := "secrets/api_key"
	writeSecret(t, repoDir, secretPath, "sk-12345")

	_, err = al.AddEntry(signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: secretPath,
		Groups:       []string{"dev"},
	}), nil)
	require.NoError(t, err)

	gitCommitAll(t, repo, "add bob and secret")

	// Re-verify to pick up the new entries.
	vstate, err = Verify(al, keyring)
	require.NoError(t, err)

	smBob, err := BuildSecretManager(
		repoDir,
		Identities{bob.Identity},
		bobSignKey, keyring, al, vstate,
	)
	require.NoError(t, err)
	require.NoError(t, smBob.SealAll())
	gitCommitAll(t, repo, "seal")

	os.Remove(filepath.Join(repoDir, secretPath))
	require.NoError(t, smBob.RevealAll())

	got, err := os.ReadFile(filepath.Join(repoDir, secretPath))
	require.NoError(t, err)
	require.Equal(t, "sk-12345", string(got))

	// Full reload + verify from scratch.
	keyring3 := EmptyKeyring()
	al3, err := LoadAuditLog(repoDir)
	require.NoError(t, err)

	vstate3, err := Verify(al3, keyring3)
	require.NoError(t, err, "full re-verify")

	require.Len(t, vstate3.Users, 2)
	require.Len(t, vstate3.Secrets, 1)

	report := VerifyIntegrity(repoDir, vstate3, keyring3)
	require.True(t, report.OK(), "integrity failed: %s", report.String())
}

// TestIntegrationTamperDetection verifies that modifying the init file
// after two commits is detected by the exported Verify() path.
func TestIntegrationTamperDetection(t *testing.T) {
	repoDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")

	signer, err := GenerateSignKey(repoDir, "admin", admin.Recipient.Recipient)
	require.NoError(t, err)

	signKeyStr := MulticodeEncode(signer.PublicKey(), MhEd25519Pub)
	al, err := InitAuditLog(repoDir, signer, DetailUserTell{
		User:        "admin",
		Groups:      []string{"admin"},
		PubKeys:     []string{admin.Recipient.String()},
		SignPubKeys: []string{signKeyStr},
	})
	require.NoError(t, err)
	gitCommitAll(t, repo, "init")

	// Tamper: rewrite the init file and commit again.
	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("tampered-hash"), 0o600))
	gitCommitAll(t, repo, "tamper")

	keyring := EmptyKeyring()
	_, err = Verify(al, keyring)
	require.Error(t, err, "should detect init file tampering")
}

// TestIntegrationSecretLifecycle runs through add → seal → change groups → re-seal → remove → seal.
func TestIntegrationSecretLifecycle(t *testing.T) {
	repoDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")

	signer, err := GenerateSignKey(repoDir, "admin", admin.Recipient.Recipient)
	require.NoError(t, err)

	signKeyStr := MulticodeEncode(signer.PublicKey(), MhEd25519Pub)
	al, err := InitAuditLog(repoDir, signer, DetailUserTell{
		User:        "admin",
		Groups:      []string{"admin"},
		PubKeys:     []string{admin.Recipient.String()},
		SignPubKeys: []string{signKeyStr},
	})
	require.NoError(t, err)
	gitCommitAll(t, repo, "init")

	kr := EmptyKeyring()
	vs, err := Verify(al, kr)
	require.NoError(t, err)

	sm, err := BuildSecretManager(
		repoDir,
		Identities{admin.Identity},
		signer,
		kr,
		al,
		vs,
	)
	require.NoError(t, err)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(repoDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	// 1. Add secret.
	writeSecret(t, repoDir, "secrets/token", "tok-abc")
	require.NoError(t, sm.AddSecret("secrets/token", []string{"admin"}))

	// 2. Seal.
	require.NoError(t, sm.SealAll())
	gitCommitAll(t, repo, "add and seal")

	// 3. Change groups (add dev).
	_, err = al.AddEntry(signer, newAuditEntry("admin", &DetailSecretChange{
		RevealedPath: "secrets/token",
		Groups:       []string{"admin", "dev"},
	}), nil)
	require.NoError(t, err)

	// 4. Re-seal.
	writeSecret(t, repoDir, "secrets/token", "tok-abc")
	vs, err = Verify(al, kr)
	require.NoError(t, err)
	sm, err = BuildSecretManager(
		repoDir,
		Identities{admin.Identity},
		signer,
		kr,
		al,
		vs,
	)
	require.NoError(t, err)
	require.NoError(t, sm.SealAll())
	gitCommitAll(t, repo, "change groups and reseal")

	// 5. Remove secret and clean up files.
	_, err = al.AddEntry(signer, newAuditEntry("admin", &DetailSecretRemove{
		RevealedPath: "secrets/token",
	}), nil)
	require.NoError(t, err)

	os.Remove(filepath.Join(repoDir, ".sesam", "objects", "secrets", "token.age"))
	os.Remove(signaturePath(repoDir, "secrets/token"))

	_, err = al.AddEntry(signer, newAuditEntry("admin", &DetailSeal{
		RootHash:    buildRootHash(nil),
		FilesSealed: 0,
	}), nil)
	require.NoError(t, err)

	gitCommitAll(t, repo, "remove secret")

	// Full re-verify.
	kr2 := EmptyKeyring()
	al2, err := LoadAuditLog(repoDir)
	require.NoError(t, err)

	vs2, err := Verify(al2, kr2)
	require.NoError(t, err, "final verify")
	require.Empty(t, vs2.Secrets)
}
