package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestMainInitCreatesStructureInGitRoot(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, ".git"), 0700); err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}

	nestedPath := filepath.Join(repoRoot, "nested", "dir")
	if err := os.MkdirAll(nestedPath, 0700); err != nil {
		t.Fatalf("failed to create nested path: %v", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	err = Main([]string{
		"sesam",
		"init",
		"--repo", nestedPath,
		"--user", "alice",
		"--recipient", id.Recipient().String(),
	})
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	assertPathExists(t, filepath.Join(repoRoot, ".sesam"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "signkeys"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "signkeys", "alice.age"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "signkeys", "alice.pub"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "bin", "git-sesam"))
	assertPathExists(t, filepath.Join(repoRoot, "sesam.yml"))
	assertPathExists(t, filepath.Join(repoRoot, ".gitignore"))
	assertPathExists(t, filepath.Join(repoRoot, ".gitattributes"))
	assertPathExists(t, filepath.Join(repoRoot, ".git", "hooks", "pre-commit"))

	configData, err := os.ReadFile(filepath.Join(repoRoot, "sesam.yml"))
	if err != nil {
		t.Fatalf("failed to read generated config: %v", err)
	}

	if !strings.Contains(string(configData), "name: 'alice'") {
		t.Fatalf("expected config to include initial user, got:\n%s", string(configData))
	}

	if !strings.Contains(string(configData), "admin:") {
		t.Fatalf("expected config to include admin group, got:\n%s", string(configData))
	}
}

func TestMainInitDoesNotOverwriteExistingConfig(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, ".git"), 0700); err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}

	originalConfig := "version: 1\ncustom: true\n"
	configPath := filepath.Join(repoRoot, "sesam.yml")
	if err := os.WriteFile(configPath, []byte(originalConfig), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	err = Main([]string{
		"sesam",
		"init",
		"--repo", repoRoot,
		"--user", "alice",
		"--recipient", id.Recipient().String(),
	})
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	configData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	if string(configData) != originalConfig {
		t.Fatalf("expected existing config to remain unchanged, got:\n%s", string(configData))
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}
