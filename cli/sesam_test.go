package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// Those test are written with AI, I didn't look over them yet
// TODO: refine the tests to cover our needs


func TestMainSealRequiresFlags(t *testing.T) {
	err := Main([]string{"sesam", "seal"})
	if err == nil {
		t.Fatal("expected error when required flags are missing")
	}

	for _, flagName := range []string{"secret", "recipient", "user"} {
		if !strings.Contains(err.Error(), flagName) {
			t.Fatalf("expected error to mention %q, got: %v", flagName, err)
		}
	}
}

func TestMainRevealRequiresFlags(t *testing.T) {
	err := Main([]string{"sesam", "reveal"})
	if err == nil {
		t.Fatal("expected error when required flags are missing")
	}

	for _, flagName := range []string{"secret", "user"} {
		if !strings.Contains(err.Error(), flagName) {
			t.Fatalf("expected error to mention %q, got: %v", flagName, err)
		}
	}
}

func TestMainSealMissingIdentity(t *testing.T) {
	repoDir := t.TempDir()
	missingIdentity := filepath.Join(repoDir, "missing-identity.txt")
	writeSecretFile(t, repoDir, "example.txt")

	err := Main([]string{
		"sesam",
		"seal",
		"--secret", "example.txt",
		"--recipient", "not-used-in-this-test",
		"--user", "alice",
		"--repo", repoDir,
		"--identity", missingIdentity,
	})
	if err == nil {
		t.Fatal("expected missing identity error")
	}

	if !strings.Contains(err.Error(), "failed to read identity") {
		t.Fatalf("expected identity read error, got: %v", err)
	}
}

func TestMainSealInvalidRecipient(t *testing.T) {
	repoDir := t.TempDir()
	identityPath := writeIdentityFile(t, repoDir)
	writeSecretFile(t, repoDir, "example.txt")

	err := Main([]string{
		"sesam",
		"seal",
		"--secret", "example.txt",
		"--recipient", "not-a-recipient",
		"--user", "alice",
		"--repo", repoDir,
		"--identity", identityPath,
	})
	if err == nil {
		t.Fatal("expected invalid recipient error")
	}

	if !strings.Contains(err.Error(), "failed to parse recipient") {
		t.Fatalf("expected recipient parse error, got: %v", err)
	}
}

func TestMainSealMissingSecretFile(t *testing.T) {
	repoDir := t.TempDir()
	identityPath, recipient := writeIdentityFileWithRecipient(t, repoDir)

	err := Main([]string{
		"sesam",
		"seal",
		"--secret", "does-not-exist.txt",
		"--recipient", recipient,
		"--user", "alice",
		"--repo", repoDir,
		"--identity", identityPath,
	})
	if err == nil {
		t.Fatal("expected missing secret error")
	}

	if !strings.Contains(err.Error(), "secret file") {
		t.Fatalf("expected missing secret message, got: %v", err)
	}
}

func TestMainRevealMissingSignKey(t *testing.T) {
	repoDir := t.TempDir()
	identityPath := writeIdentityFile(t, repoDir)

	err := Main([]string{
		"sesam",
		"reveal",
		"--secret", "example.txt",
		"--user", "alice",
		"--repo", repoDir,
		"--identity", identityPath,
	})
	if err == nil {
		t.Fatal("expected missing sign key error")
	}

	if !strings.Contains(err.Error(), "failed to load signing key") {
		t.Fatalf("expected signing key error, got: %v", err)
	}
}

func writeIdentityFile(t *testing.T, dir string) string {
	t.Helper()

	identityPath, _ := writeIdentityFileWithRecipient(t, dir)
	return identityPath
}

func writeIdentityFileWithRecipient(t *testing.T, dir string) (string, string) {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	identityPath := filepath.Join(dir, "identity.txt")
	identityData := []byte(id.String() + "\n")
	if err := os.WriteFile(identityPath, identityData, 0600); err != nil {
		t.Fatalf("failed to write identity file: %v", err)
	}

	return identityPath, id.Recipient().String()
}

func writeSecretFile(t *testing.T, dir, relPath string) {
	t.Helper()

	secretPath := filepath.Join(dir, relPath)
	if err := os.WriteFile(secretPath, []byte("secret-data"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}
}
