package repo

import (
	"bytes"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-git/go-git/v5"
	"github.com/google/renameio"
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

// ResolveSesamDir validates the directory where .sesam will live.
//
// The returned path is the sesam target directory, which may be a
// sub-directory inside a larger git worktree.
func ResolveSesamDir(repoPath string) (string, error) {
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

func IsInitialized(repoRoot string) error {
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

func EnsureInitPathChoice(repoRoot string, useRoot bool) error {
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

func EnsureSesamDirs(repoRoot string) error {
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

	if err := EnsureTmpKeepFile(repoRoot); err != nil {
		return err
	}

	slog.Info("initialized sesam directory", slog.String("path", filepath.Join(repoRoot, ".sesam")))
	return nil
}

func EnsureTmpKeepFile(repoRoot string) error {
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

func ResolveConfigPath(repoRoot, configPath string, configExplicit bool) string {
	if filepath.IsAbs(configPath) {
		return configPath
	}

	if configExplicit {
		return configPath
	}

	return filepath.Join(repoRoot, configPath)
}

func CreateInitialConfig(configPath, initialUser, recipientText string) error {
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

func quoteYAMLString(value string) string {
	escaped := strings.ReplaceAll(value, "'", "''")
	return "'" + escaped + "'"
}

func EnsureDefaultGitIgnore(repoRoot string) error {
	gitignorePath := filepath.Join(repoRoot, ".gitignore")
	return appendMissingLines(gitignorePath, gitignoreTemplate, 0o600)
}

func EnsureDefaultGitAttributes(repoRoot string) error {
	gitAttributesPath := filepath.Join(repoRoot, ".gitattributes")
	return appendMissingLines(gitAttributesPath, gitattributesTemplate, 0o644)
}

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

func EnsureVerifyHook(repoRoot string) error {
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

func EnsureGitSesamShim(repoRoot string) error {
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

func EnsureExampleSecret(repoRoot string) error {
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

func EnsureSesamReadme(repoRoot string) error {
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

func StageInitFiles(repoRoot, configPath string) error {
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

func WithWorkingDir(dir string, fn func() error) error {
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
