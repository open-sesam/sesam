package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestMainInitCreatesStructureInGitRoot(t *testing.T) {
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
		"--recipient", id.Recipient().String(),
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("init failed: %v", err)
	}

	assertPathExists(t, filepath.Join(repoRoot, ".sesam"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "signkey"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "signkey", "alice.age"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "tmp"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "tmp", ".donotdelete"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "bin", "git-sesam"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "README.md"))
	assertPathExists(t, filepath.Join(repoRoot, "sesam.yml"))
	assertPathExists(t, filepath.Join(repoRoot, ".gitignore"))
	assertPathExists(t, filepath.Join(repoRoot, ".gitattributes"))
	assertPathExists(t, filepath.Join(repoRoot, "example.secret"))
	assertPathExists(t, filepath.Join(repoRoot, ".git", "hooks", "pre-commit"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "audit", "init"))
	assertPathExists(t, filepath.Join(repoRoot, ".sesam", "audit", "log.jsonl"))

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

func TestMainInitAllowsRepoPathInsideGitWorktree(t *testing.T) {
	repoRoot := makeTempDir(t)
	initGitRepo(t, repoRoot)

	nestedPath := filepath.Join(repoRoot, "nested", "dir")
	if err := os.MkdirAll(nestedPath, 0o700); err != nil {
		t.Fatalf("failed to create nested path: %v", err)
	}

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
		"--sesam-dir", nestedPath,
		"--user", "alice",
		"--recipient", id.Recipient().String(),
		"--identity", identityPath,
	})
	if err != nil {
		t.Fatalf("expected init to succeed inside worktree, got: %v", err)
	}

	assertPathExists(t, filepath.Join(nestedPath, ".sesam"))
	assertPathExists(t, filepath.Join(repoRoot, ".git", "hooks", "pre-commit"))
}

func TestMainInitFailsWhenAlreadyInitialized(t *testing.T) {
	repoRoot := makeTempDir(t)
	initGitRepo(t, repoRoot)

	originalConfig := "version: 1\ncustom: true\n"
	configPath := filepath.Join(repoRoot, "sesam.yml")
	if err := os.WriteFile(configPath, []byte(originalConfig), 0600); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

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
		"--recipient", id.Recipient().String(),
		"--identity", identityPath,
	})
	if err == nil {
		t.Fatal("expected init to fail for already initialized repository")
	}

	if !strings.Contains(err.Error(), "already has sesam config") {
		t.Fatalf("expected already-initialized error, got: %v", err)
	}
}

func TestMainInitRequiresUseRootForBusyRepoPath(t *testing.T) {
	repoRoot := makeTempDir(t)
	initGitRepo(t, repoRoot)

	for idx := 0; idx < 30; idx++ {
		path := filepath.Join(repoRoot, "busy-"+strconv.Itoa(idx)+".txt")
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatalf("failed to write busy file: %v", err)
		}
	}

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
	if err == nil {
		t.Fatal("expected init to fail for busy repo path without --use-root")
	}

	if !strings.Contains(err.Error(), "--use-root") {
		t.Fatalf("expected use-root guidance, got: %v", err)
	}

	err = Main([]string{
		"sesam",
		"init",
		"--sesam-dir", repoRoot,
		"--user", "alice",
		"--identity", identityPath,
		"--use-root",
	})
	if err != nil {
		t.Fatalf("expected init to succeed with --use-root, got: %v", err)
	}
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}

func initGitRepo(t *testing.T, repoRoot string) {
	t.Helper()

	runGit(t, repoRoot, "init")
	runGit(t, repoRoot, "config", "user.email", "sesam-test@example.com")
	runGit(t, repoRoot, "config", "user.name", "sesam-test")

	seedPath := filepath.Join(repoRoot, ".seed")
	if err := os.WriteFile(seedPath, []byte("seed\n"), 0o600); err != nil {
		t.Fatalf("failed to write seed file: %v", err)
	}

	runGit(t, repoRoot, "add", ".seed")
	runGit(t, repoRoot, "commit", "-m", "test seed")
}

func runGit(t *testing.T, repoRoot string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
}

func makeTempDir(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "sesam-cli-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})

	return dir
}
