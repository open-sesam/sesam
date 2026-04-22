package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestMainSealRequiresInitializedRepo(t *testing.T) {
	repoDir := makeTempDir(t)
	initGitRepo(t, repoDir)
	identityPath := writeIdentityFile(t, repoDir)

	err := Main([]string{
		"sesam",
		"seal",
		"--repo", repoDir,
		"--identity", identityPath,
	})
	if err == nil {
		t.Fatal("expected seal to fail without audit log")
	}

	if !strings.Contains(err.Error(), "failed to load audit log") {
		t.Fatalf("expected audit-log error, got: %v", err)
	}
}

func TestMainRevealRequiresInitializedRepo(t *testing.T) {
	repoDir := makeTempDir(t)
	initGitRepo(t, repoDir)
	identityPath := writeIdentityFile(t, repoDir)

	err := Main([]string{
		"sesam",
		"reveal",
		"--repo", repoDir,
		"--identity", identityPath,
	})
	if err == nil {
		t.Fatal("expected reveal to fail without audit log")
	}

	if !strings.Contains(err.Error(), "failed to load audit log") {
		t.Fatalf("expected audit-log error, got: %v", err)
	}
}

func TestMainSealMissingIdentity(t *testing.T) {
	repoDir := makeTempDir(t)
	initGitRepo(t, repoDir)
	missingIdentity := filepath.Join(repoDir, "missing-identity.txt")

	err := Main([]string{
		"sesam",
		"seal",
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

func writeIdentityFile(t *testing.T, dir string) string {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	identityPath := filepath.Join(dir, "identity.txt")
	identityData := []byte(id.String() + "\n")
	if err := os.WriteFile(identityPath, identityData, 0o600); err != nil {
		t.Fatalf("failed to write identity file: %v", err)
	}

	return identityPath
}

func TestMainInitSealRevealRoundTrip(t *testing.T) {
	repoRoot := makeTempDir(t)
	initGitRepo(t, repoRoot)

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	identityPath := filepath.Join(repoRoot, "identity.txt")
	if err := os.WriteFile(identityPath, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatalf("failed to write identity: %v", err)
	}

	err = Main([]string{
		"sesam",
		"init",
		"--repo", repoRoot,
		"--user", "alice",
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	original := "super-secret\nanother super important secret\n"
	secretPath := filepath.Join(repoRoot, "example.secret")
	if err := os.WriteFile(secretPath, []byte(original), 0o600); err != nil {
		t.Fatalf("failed to write plaintext secret: %v", err)
	}

	err = Main([]string{
		"sesam",
		"seal",
		"--repo", repoRoot,
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}

	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "objects", "example.secret.age"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "objects", "example.secret.sig.json"))

	if err := os.Remove(secretPath); err != nil {
		t.Fatalf("failed to remove plaintext secret: %v", err)
	}

	err = Main([]string{
		"sesam",
		"reveal",
		"--repo", repoRoot,
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("reveal failed: %v", err)
	}

	revealed, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatalf("failed to read revealed secret: %v", err)
	}

	if string(revealed) != original {
		t.Fatalf("revealed secret mismatch\nwant: %q\n got: %q", original, string(revealed))
	}
}
