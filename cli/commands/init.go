package commands

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/google/renameio"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

//go:embed assets/gitignore.default
var gitignoreTemplate string

//go:embed assets/gitattributes.default
var gitattributesTemplate string

//go:embed assets/pre-commit_hook.default
var preCommitHookTemplate string

//go:embed assets/Readme.default
var sesamReadmeTemplate string

//go:embed assets/secret.example
var exampleSecretContent string

//go:embed assets/config.default
var configTemplate string

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) error {
	// NOTE: This init workflow only works well if the repo contains only secrets and nothing else.
	// TODO: We need to discuss how we want to handle it when sesam is initialized in an existing repo.
	// My suggestion would be to have a `secrets/` folder where all secrets are stored,
	// and a `.sesam/` folder for sesam internals.
	//
	// - `.sesam/.gitattributes` for `.sesam/objects/** filter=sesam diff=sesam`
	// - `.sesam/.gitignore` for `.sesam/tmp/`, local helper files, etc.
	// - `secrets/.gitignore` if plaintext secrets should stay only in that folder and never be committed.
	//
	// - `repo/.git/hooks` must stay at repo level, because hooks cannot live in subdirs.
	//   It is important to check if hooks already exist before writing pre-commit,
	//   so we do not overwrite existing hooks and only append the sesam hook at the end.

	repoRoot, err := resolveRepoRoot(cmd.String("repo"))
	if err != nil {
		return err
	}

	if err := ensureNotInitialized(repoRoot); err != nil {
		return err
	}

	if err := ensureInitPathChoice(repoRoot, cmd.Bool("use-root")); err != nil {
		return err
	}

	initialUser := strings.TrimSpace(cmd.String("user"))
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	if err := core.ValidUserName(initialUser); err != nil {
		return fmt.Errorf("invalid initial user %q: %w", initialUser, err)
	}

	identities, err := loadIdentities(cmd.String("identity"), "sesam.id."+initialUser)
	if err != nil {
		return err
	}

	_, recipientText, err := resolveInitialRecipient(ctx, cmd.String("recipient"), repoRoot, identities)
	if err != nil {
		return err
	}

	if err := ensureSesamDirs(repoRoot); err != nil {
		return err
	}

	return withRepoLock(repoRoot, 5*time.Second, func() error {
		configPath := resolveConfigPath(repoRoot, cmd.String("config"), cmd.IsSet("config"))
		if err := createInitialConfig(configPath, initialUser, recipientText); err != nil {
			return err
		}

		mgr, err := buildInitialSecretManager(
			ctx,
			repoRoot,
			initialUser,
			recipientText,
			identities,
		)
		if err != nil {
			return err
		}
		defer func() {
			_ = mgr.AuditLog.Close()
		}()

		if err := ensureDefaultGitIgnore(repoRoot); err != nil {
			return err
		}

		if err := ensureDefaultGitAttributes(repoRoot); err != nil {
			return err
		}

		if err := ensureVerifyHook(repoRoot); err != nil {
			return err
		}

		if err := ensureGitSesamShim(repoRoot); err != nil {
			return err
		}

		if err := ensureExampleSecret(repoRoot); err != nil {
			return err
		}

		if err := withWorkingDir(repoRoot, func() error {
			return mgr.AddSecret("example.secret", []string{"admin"})
		}); err != nil {
			return fmt.Errorf("failed to bootstrap example secret: %w", err)
		}

		if err := ensureSesamReadme(repoRoot); err != nil {
			return err
		}

		if err := ensureTmpKeepFile(repoRoot); err != nil {
			return err
		}

		if err := stageInitFiles(repoRoot, configPath); err != nil {
			return err
		}

		return nil
	})
}

// resolveRepoRoot validates the repo input path from the user and requires .git at that path.
func resolveRepoRoot(repoPath string) (string, error) {
	if strings.TrimSpace(repoPath) == "" {
		repoPath = "."
	}
	repoPath = filepath.Clean(repoPath)

	repoInfo, err := os.Stat(repoPath)
	if err != nil {
		return "", fmt.Errorf("failed to access repo path %s: %w", repoPath, err)
	}

	if !repoInfo.IsDir() {
		return "", fmt.Errorf("repo path %s is not a directory", repoPath)
	}

	_, err = resolveGitDir(repoPath)
	if err != nil {
		return "", fmt.Errorf("no git repository found at %s: %w", repoPath, err)
	}

	return repoPath, nil
}

// ensureNotInitialized rejects re-running init on a configured repository.
func ensureNotInitialized(repoRoot string) error {
	configPath := filepath.Join(repoRoot, "sesam.yml")
	sesamDir := filepath.Join(repoRoot, ".sesam")

	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("repository already has sesam config at %s", configPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", configPath, err)
	}

	if _, err := os.Stat(sesamDir); err == nil {
		return fmt.Errorf("repository already has sesam directory at %s", sesamDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", sesamDir, err)
	}

	return nil
}

func ensureInitPathChoice(repoRoot string, useRoot bool) error {
	const maxRecommendedFiles = 25

	fileCount, err := countRepoFiles(repoRoot, maxRecommendedFiles+1)
	if err != nil {
		return err
	}

	if fileCount <= maxRecommendedFiles || useRoot {
		return nil
	}

	return fmt.Errorf(
		"repository path %s already contains many files (%d); prefer a dedicated secrets sub-directory or rerun with --use-root",
		repoRoot,
		fileCount,
	)
}

func countRepoFiles(repoRoot string, stopAfter int) (int, error) {
	if stopAfter <= 0 {
		return 0, nil
	}

	var count int
	stopErr := fmt.Errorf("stop")
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", ".sesam":
				return filepath.SkipDir
			}

			return nil
		}

		count++
		if count >= stopAfter {
			return stopErr
		}

		return nil
	})
	if err != nil && err != stopErr {
		return 0, fmt.Errorf("failed to inspect repository files: %w", err)
	}

	return count, nil
}

// ensureSesamDirs creates required internal sesam directories.
func ensureSesamDirs(repoRoot string) error {
	dirs := []string{
		filepath.Join(repoRoot, ".sesam"),
		filepath.Join(repoRoot, ".sesam", "signkey"),
		filepath.Join(repoRoot, ".sesam", "tmp"),
		filepath.Join(repoRoot, ".sesam", "bin"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := ensureTmpKeepFile(repoRoot); err != nil {
		return err
	}

	slog.Info("initialized sesam directory", slog.String("path", filepath.Join(repoRoot, ".sesam")))
	return nil
}

func ensureTmpKeepFile(repoRoot string) error {
	keepPath := filepath.Join(repoRoot, ".sesam", "tmp", ".donotdelete")
	if _, err := os.Stat(keepPath); os.IsNotExist(err) {
		if err := renameio.WriteFile(keepPath, []byte("\n"), 0o600); err != nil {
			return fmt.Errorf("failed to create %s: %w", keepPath, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to access %s: %w", keepPath, err)
	}

	return nil
}

// resolveConfigPath preserves explicit user paths and keeps default under repo root.
func resolveConfigPath(repoRoot, configPath string, configExplicit bool) string {
	if filepath.IsAbs(configPath) {
		return configPath
	}

	if configExplicit {
		return configPath
	}

	return filepath.Join(repoRoot, configPath)
}

// resolveInitialRecipient determines the initial admin recipient key.
func resolveInitialRecipient(ctx context.Context, recipientArg string, repoRoot string, identities core.Identities) (age.Recipient, string, error) {
	recipientArg = strings.TrimSpace(recipientArg)

	var resolved core.Recipients
	if recipientArg != "" {
		rawRecipient, err := core.ResolveRecipient(ctx, repoRoot, recipientArg, core.CacheModeReadWrite)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve recipient %q: %w", recipientArg, err)
		}

		resolved, err = core.ParseRecipients(rawRecipient)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse recipient %q: %w", recipientArg, err)
		}
	}

	if len(resolved) > 0 {
		for _, recipient := range resolved {
			for _, identity := range identities {
				if identityCanDecryptRecipient(identity, recipient.Recipient) {
					return recipient.Recipient, recipient.String(), nil
				}
			}
		}

		return nil, "", fmt.Errorf("none of the resolved recipients matches the selected identity")
	}

	recipient, err := core.ParseRecipient(identities[0].Public().String())
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive recipient from identity: %w", err)
	}

	return recipient.Recipient, identities[0].Public().String(), nil
}

// identityCanDecryptRecipient checks if identity corresponds to recipient.
func identityCanDecryptRecipient(identity *core.Identity, recipient age.Recipient) bool {
	const probe = "sesam-init-match"

	var encrypted bytes.Buffer
	w, err := age.Encrypt(&encrypted, recipient)
	if err != nil {
		return false
	}

	if _, err := w.Write([]byte(probe)); err != nil {
		return false
	}

	if err := w.Close(); err != nil {
		return false
	}

	r, err := age.Decrypt(bytes.NewReader(encrypted.Bytes()), identity)
	if err != nil {
		return false
	}

	decrypted, err := io.ReadAll(r)
	if err != nil {
		return false
	}

	return string(decrypted) == probe
}

// createInitialConfig writes sesam.yml using the embedded template.
func createInitialConfig(configPath, initialUser, recipientText string) error {
	if _, err := os.Stat(configPath); err == nil {
		return fmt.Errorf("config already exists at %s", configPath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access config path %s: %w", configPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return fmt.Errorf("failed to create config directory for %s: %w", configPath, err)
	}

	tmpl, err := template.
		New("config.default").
		Delims("[[", "]]").
		Funcs(template.FuncMap{"yaml": quoteYAMLString}).
		Parse(configTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse config template: %w", err)
	}

	var out bytes.Buffer
	err = tmpl.Execute(&out, struct {
		InitialUser      string
		InitialRecipient string
	}{
		InitialUser:      initialUser,
		InitialRecipient: recipientText,
	})
	if err != nil {
		return fmt.Errorf("failed to render config template: %w", err)
	}

	if err := renameio.WriteFile(configPath, out.Bytes(), 0o600); err != nil {
		return fmt.Errorf("failed to create sample config %s: %w", configPath, err)
	}

	slog.Info("created sample config", slog.String("path", configPath))
	return nil
}

// quoteYAMLString single-quotes and escapes values for YAML templates.
func quoteYAMLString(value string) string {
	escaped := strings.ReplaceAll(value, "'", "''")
	return "'" + escaped + "'"
}

// buildInitialSecretManager bootstraps audit/keyring state for init-time actions.
func buildInitialSecretManager(
	ctx context.Context,
	repoRoot string,
	initialUser string,
	recipientText string,
	identities core.Identities,
) (*core.SecretManager, error) {
	signer, auditLog, err := core.InitAdminUser(ctx, repoRoot, initialUser, recipientText)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize admin user: %w", err)
	}

	keyring := core.EmptyKeyring()
	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	mgr, err := core.BuildSecretManager(
		repoRoot,
		identities,
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	return mgr, nil
}

// ensureDefaultGitIgnore appends sesam rules to .gitignore.
func ensureDefaultGitIgnore(repoRoot string) error {
	gitignorePath := filepath.Join(repoRoot, ".gitignore")
	return appendMissingLines(gitignorePath, gitignoreTemplate, 0o600)
}

// ensureDefaultGitAttributes appends sesam filter rules to .gitattributes.
func ensureDefaultGitAttributes(repoRoot string) error {
	gitAttributesPath := filepath.Join(repoRoot, ".gitattributes")
	return appendMissingLines(gitAttributesPath, gitattributesTemplate, 0o644)
}

// appendMissingLines appends only lines not already present in a file.
func appendMissingLines(path string, content string, mode os.FileMode) error {
	var existing string
	fileMissing := false
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	} else if os.IsNotExist(err) {
		fileMissing = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", path, err)
	}

	b := strings.Builder{}
	b.WriteString(existing)

	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.Contains(existing, line+"\n") || strings.HasSuffix(existing, line) {
			continue
		}

		if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
			b.WriteString("\n")
		}

		b.WriteString(line)
		b.WriteString("\n")
	}

	if b.String() == existing {
		if fileMissing {
			if err := renameio.WriteFile(path, []byte(existing), mode); err != nil {
				return fmt.Errorf("failed to create %s: %w", path, err)
			}
		}

		return nil
	}

	if err := renameio.WriteFile(path, []byte(b.String()), mode); err != nil {
		return fmt.Errorf("failed to update %s: %w", path, err)
	}

	return nil
}

// ensureVerifyHook installs the default pre-commit verification hook.
func ensureVerifyHook(repoRoot string) error {
	gitDir, err := resolveGitDir(repoRoot)
	if err != nil {
		return fmt.Errorf("no git repository detected at %s: %w", repoRoot, err)
	}

	hookPath := filepath.Join(gitDir, "hooks", "pre-commit")
	if _, err := os.Stat(hookPath); err == nil {
		slog.Info("pre-commit hook already exists; leaving unchanged", slog.String("path", hookPath))
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access hook %s: %w", hookPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o700); err != nil {
		return fmt.Errorf("failed to create hook directory for %s: %w", hookPath, err)
	}

	if err := renameio.WriteFile(hookPath, []byte(preCommitHookTemplate), 0o755); err != nil {
		return fmt.Errorf("failed to create pre-commit hook at %s: %w", hookPath, err)
	}

	slog.Info("created pre-commit hook", slog.String("path", hookPath))
	return nil
}

// resolveGitDir resolves both directory and indirection-file .git layouts.
//
// It returns the effective git metadata directory path.
func resolveGitDir(repoRoot string) (string, error) {
	repo, err := git.PlainOpenWithOptions(repoRoot, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", err
	}

	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to access git worktree: %w", err)
	}

	gitPath := filepath.Join(wt.Filesystem.Root(), ".git")

	info, err := os.Stat(gitPath)
	if err != nil {
		return "", fmt.Errorf("failed to access git metadata at %s: %w", gitPath, err)
	}

	if info.IsDir() {
		return gitPath, nil
	}

	// In worktrees/submodules .git can be a file that points to the real
	// metadata directory via "gitdir: <path>". Parse that indirection so we
	// install hooks and read metadata from the effective git directory.
	data, err := os.ReadFile(gitPath)
	if err != nil {
		return "", fmt.Errorf("failed to read git metadata at %s: %w", gitPath, err)
	}

	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(strings.ToLower(line), prefix) {
		return "", fmt.Errorf("unsupported .git format in %s", gitPath)
	}

	resolvedPath := strings.TrimSpace(line[len(prefix):])
	if resolvedPath == "" {
		return "", fmt.Errorf("empty gitdir in %s", gitPath)
	}

	if filepath.IsAbs(resolvedPath) {
		return resolvedPath, nil
	}

	return filepath.Clean(filepath.Join(repoRoot, resolvedPath)), nil
}

// ensureGitSesamShim installs a repo-local git-sesam helper.
func ensureGitSesamShim(repoRoot string) error {
	shimPath := filepath.Join(repoRoot, ".sesam", "bin", "git-sesam")
	if _, err := os.Stat(shimPath); err == nil {
		slog.Info("git-sesam shim already exists", slog.String("path", shimPath))
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access git-sesam shim %s: %w", shimPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(shimPath), 0o700); err != nil {
		return fmt.Errorf("failed to create shim directory for %s: %w", shimPath, err)
	}

	script := "#!/bin/sh\nexec sesam \"$@\"\n"
	if err := renameio.WriteFile(shimPath, []byte(script), 0o755); err != nil {
		return fmt.Errorf("failed to create git-sesam shim at %s: %w", shimPath, err)
	}

	slog.Info("created git-sesam shim", slog.String("path", shimPath), slog.String("hint", "add .sesam/bin to your PATH"))
	return nil
}

// ensureExampleSecret creates a starter secret file for first-time usage.
func ensureExampleSecret(repoRoot string) error {
	examplePath := filepath.Join(repoRoot, "example.secret")
	if _, err := os.Stat(examplePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", examplePath, err)
	}

	if err := renameio.WriteFile(examplePath, []byte(exampleSecretContent), 0o600); err != nil {
		return fmt.Errorf("failed to create example secret %s: %w", examplePath, err)
	}

	slog.Info("created example secret", slog.String("path", examplePath))
	return nil
}

// ensureSesamReadme writes a short onboarding note into .sesam.
func ensureSesamReadme(repoRoot string) error {
	readmePath := filepath.Join(repoRoot, ".sesam", "README.md")
	if _, err := os.Stat(readmePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", readmePath, err)
	}

	if err := renameio.WriteFile(readmePath, []byte(sesamReadmeTemplate), 0o600); err != nil {
		return fmt.Errorf("failed to create sesam readme %s: %w", readmePath, err)
	}

	slog.Info("created sesam readme", slog.String("path", readmePath))
	return nil
}

// stageInitFiles tries to stage init artifacts with git add.
//
// Failure is non-fatal and reported as warning output.
func stageInitFiles(repoRoot, configPath string) error {
	files := []string{
		filepath.Join(repoRoot, ".sesam"),
		configPath,
		filepath.Join(repoRoot, ".gitignore"),
		filepath.Join(repoRoot, ".gitattributes"),
		filepath.Join(repoRoot, "example.secret"),
	}

	args := append([]string{"add"}, files...)
	cmd := exec.Command("git", args...)
	cmd.Dir = repoRoot

	if output, err := cmd.CombinedOutput(); err != nil {
		slog.Warn("failed to stage init files automatically", slog.Any("error", err), slog.String("output", strings.TrimSpace(string(output))))
		return nil
	}

	return nil
}

func withWorkingDir(dir string, fn func() error) error {
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to read current directory: %w", err)
	}

	if err := os.Chdir(dir); err != nil {
		return fmt.Errorf("failed to switch directory to %s: %w", dir, err)
	}

	defer func() {
		_ = os.Chdir(originalDir)
	}()

	return fn()
}
