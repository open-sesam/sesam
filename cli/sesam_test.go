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
		"--sesam-dir", repoDir,
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
		"--sesam-dir", repoDir,
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
		"--sesam-dir", repoDir,
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

func TestMainInitSealRevealWithoutTrackedSecrets(t *testing.T) {
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
		"--sesam-dir", repoRoot,
		"--user", "alice",
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	err = Main([]string{
		"sesam",
		"seal",
		"--sesam-dir", repoRoot,
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("seal failed: %v", err)
	}

	err = Main([]string{
		"sesam",
		"reveal",
		"--sesam-dir", repoRoot,
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("reveal failed: %v", err)
	}

	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "README.md"))
}
