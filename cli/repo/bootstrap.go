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
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/google/renameio"
)

const initRootFileThreshold = 25

//go:embed assets/gitignore.default
var gitignoreTemplate string

//go:embed assets/gitattributes.default
var gitattributesTemplate string

//go:embed assets/pre-commit_hook.default
var preCommitHookTemplate string

//go:embed assets/Readme.default
var sesamReadmeTemplate string

//go:embed assets/config.default
var configTemplate string

// ResolveSesamDir validates the directory where .sesam will live.
//
// The returned path is the sesam target directory, which may be a
// sub-directory inside a larger git worktree.
func ResolveSesamDir(sesamPath string) (string, error) {
	if strings.TrimSpace(sesamPath) == "" {
		sesamPath = "."
	}
	sesamPath = filepath.Clean(sesamPath)

	repoInfo, err := os.Stat(sesamPath)
	if err != nil {
		return "", fmt.Errorf("failed to access repo path %s: %w", sesamPath, err)
	}

	if !repoInfo.IsDir() {
		return "", fmt.Errorf("repo path %s is not a directory", sesamPath)
	}

	_, err = resolveGitDir(sesamPath)
	if err != nil {
		return "", fmt.Errorf("no git repository found at %s: %w", sesamPath, err)
	}

	return sesamPath, nil
}

func IsInitialized(sesamRoot string) error {
	configPath := filepath.Join(sesamRoot, "sesam.yml")
	sesamDir := filepath.Join(sesamRoot, ".sesam")

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

func EnsureInitPathChoice(sesamRoot string, useRoot bool) error {
	if useRoot {
		return nil
	}

	fileCount, err := countRepoFiles(sesamRoot)
	if err != nil {
		return err
	}

	// TODO: Need to improve on that heuristic.
	if fileCount > initRootFileThreshold {
		return fmt.Errorf("refusing to initialize in %s: found %d files; use a sub-directory with --sesam-dir or pass --use-root to proceed", sesamRoot, fileCount)
	}

	return nil
}

func countRepoFiles(root string) (int, error) {
	count := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".sesam" {
				return filepath.SkipDir
			}
			return nil
		}

		if d.Type().IsRegular() {
			count++
		}

		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("failed to scan %s: %w", root, err)
	}

	return count, nil
}

func EnsureSesamDirs(sesamDir string) error {
	dirs := []string{
		filepath.Join(sesamDir, ".sesam"),
		filepath.Join(sesamDir, ".sesam", "signkeys"),
		filepath.Join(sesamDir, ".sesam", "tmp"),
		filepath.Join(sesamDir, ".sesam", "bin"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := EnsureTmpKeepFile(sesamDir); err != nil {
		return err
	}

	slog.Info("initialized sesam directory", slog.String("path", filepath.Join(sesamDir, ".sesam")))
	return nil
}

func EnsureTmpKeepFile(sesamDir string) error {
	keepPath := filepath.Join(sesamDir, ".sesam", "tmp", ".gitkeep")
	if _, err := os.Stat(keepPath); os.IsNotExist(err) {
		if err := renameio.WriteFile(keepPath, []byte("\n"), 0o600); err != nil {
			return fmt.Errorf("failed to create %s: %w", keepPath, err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to access %s: %w", keepPath, err)
	}

	return nil
}

func ResolveConfigPath(sesamDir, configPath string, configExplicit bool) string {
	if filepath.IsAbs(configPath) {
		return configPath
	}

	if configExplicit {
		return configPath
	}

	return filepath.Join(sesamDir, configPath)
}

func CreateInitialConfig(configPath, initialUser string, initialRecipients []string) error {
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
		InitialUser       string
		InitialRecipients []string
	}{
		InitialUser:       initialUser,
		InitialRecipients: initialRecipients,
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

func EnsureDefaultGitIgnore(sesamDir string) error {
	gitignorePath := filepath.Join(sesamDir, ".gitignore")
	return appendMissingLines(gitignorePath, gitignoreTemplate, 0o600)
}

func EnsureDefaultGitAttributes(sesamDir string) error {
	gitAttributesPath := filepath.Join(sesamDir, ".gitattributes")
	return appendMissingLines(gitAttributesPath, gitattributesTemplate, 0o644)
}

func EnsureDefaultGitConfig() error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}
	return EnsureGitConfigAt(cwd)
}

func EnsureGitConfigAt(dir string) error {
	r, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return fmt.Errorf("no git repository found: %w", err)
	}

	return ensureGitConfig(r)
}

func ensureGitConfig(r *git.Repository) error {
	cfg, err := r.ConfigScoped(gogitconfig.LocalScope)
	if err != nil {
		return fmt.Errorf("read local git config: %w", err)
	}

	// canary: if the merge driver is present, assume all drivers are configured
	if cfg.Raw.Section("merge").Subsection("sesam-merge").Option("driver") != "" {
		return nil
	}

	s := cfg.Raw.Section("merge").Subsection("sesam-merge")
	s.SetOption("name", "merge the audit log of sesam")
	s.SetOption("driver", "sesam audit merge %O %A %B %L %P")

	s = cfg.Raw.Section("diff").Subsection("sesam-diff")
	s.SetOption("textconv", "sesam show")

	s = cfg.Raw.Section("filter").Subsection("sesam-filter")
	s.SetOption("smudge", "sesam smudge %f")
	s.SetOption("clean", "cat")
	s.SetOption("required", "false")

	if err := r.SetConfig(cfg); err != nil {
		return fmt.Errorf("write git config: %w", err)
	}

	return nil
}

func appendMissingLines(path string, content string, mode os.FileMode) error {
	var existing string
	fileMissing := false
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec
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

func EnsureVerifyHook(sesamDir string) error {
	gitDir, err := resolveGitDir(sesamDir)
	if err != nil {
		return fmt.Errorf("no git repository detected at %s: %w", sesamDir, err)
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

func resolveGitDir(sesamDir string) (string, error) {
	repo, err := git.PlainOpenWithOptions(sesamDir, &git.PlainOpenOptions{DetectDotGit: true})
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

	data, err := os.ReadFile(gitPath) //nolint:gosec
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

	return filepath.Clean(filepath.Join(sesamDir, resolvedPath)), nil
}

func EnsureGitSesamShim(sesamDir string) error {
	shimPath := filepath.Join(sesamDir, ".sesam", "bin", "git-sesam")
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

func EnsureSesamReadme(sesamDir string) error {
	readmePath := filepath.Join(sesamDir, "README.md")
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

func StageInitFiles(sesamDir, configPath string) error {
	files := []string{
		filepath.Join(sesamDir, ".sesam"),
		configPath,
		filepath.Join(sesamDir, ".gitignore"),
		filepath.Join(sesamDir, ".gitattributes"),
	}

	args := append([]string{"add", "-f"}, files...)
	cmd := exec.Command("git", args...) //nolint:gosec,noctx
	cmd.Dir = sesamDir

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
