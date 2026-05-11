package repo

import (
	"bytes"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
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

func EnsureGitConfigAt(sesamDir string) error {
	r, err := OpenGitRepo(sesamDir)
	if err != nil {
		return fmt.Errorf("no git repository found: %w", err)
	}

	return ensureGitConfig(r, sesamDir)
}

func ensureGitConfig(r *git.Repository, sesamDir string) error {
	cfg, err := r.ConfigScoped(gogitconfig.LocalScope)
	if err != nil {
		return fmt.Errorf("read local git config: %w", err)
	}

	mergeSection := cfg.Raw.Section("merge").Subsection("sesam-merge")
	filterSection := cfg.Raw.Section("filter").Subsection("sesam-filter")

	mergeConfigured := mergeSection.Option("driver") != ""
	processConfigured := filterSection.Option("process") != ""

	// Both legacy drivers and the long-running filter process are already
	// installed; nothing to do.
	if mergeConfigured && processConfigured {
		return nil
	}

	// Every git driver below is `sesam <subcommand>` run through the
	// shell with cwd = worktree root; for nested layouts each one
	// needs the same --sesam-dir treatment to find `.sesam/`.
	mergeCmd, err := sesamCmd(r, sesamDir, "audit", "merge", "%O", "%A", "%B", "%L", "%P")
	if err != nil {
		return err
	}
	textconvCmd, err := sesamCmd(r, sesamDir, "show")
	if err != nil {
		return err
	}
	smudgeCmd, err := sesamCmd(r, sesamDir, "smudge")
	if err != nil {
		return err
	}

	if !mergeConfigured {
		mergeSection.SetOption("name", "merge the audit log of sesam")
		mergeSection.SetOption("driver", mergeCmd)

		diffSection := cfg.Raw.Section("diff").Subsection("sesam-diff")
		diffSection.SetOption("textconv", textconvCmd)
	}

	if !processConfigured {
		// required=false means a smudge failure doesn't abort
		// `git checkout`; the encrypted bytes land instead. We rely
		// on this to keep history bisects working when the audit log
		// is unavailable.
		filterSection.SetOption("required", "false")

		// Long-running filter process - amortises identity loading
		// across all blobs in a single git operation AND lets the
		// handler load the audit log once per session for the
		// sealer-vs-access check. Requires git >= 2.11 (Dec 2016).
		filterSection.SetOption("process", smudgeCmd)
	}

	if err := r.SetConfig(cfg); err != nil {
		return fmt.Errorf("write git config: %w", err)
	}

	return nil
}

// sesamCmd builds a shell-safe `sesam ...` invocation suitable for git
// config strings. The --sesam-dir flag is included only when
// sesamDir is not the worktree root, and its value is shell-quoted.
// Subcommand args are emitted as-is - callers must pass already-safe
// tokens, e.g. git's %X placeholders or fixed verbs.
//
// The flag is positioned at the top level (`sesam --sesam-dir=... sub`)
// so it's uniformly attached to the binary regardless of how deep the
// subcommand path is.
func sesamCmd(r *git.Repository, sesamDir string, args ...string) (string, error) {
	rel, err := relSesamDir(r, sesamDir)
	if err != nil {
		return "", err
	}
	parts := []string{"sesam"}
	if rel != "." && rel != "" {
		parts = append(parts, "--sesam-dir="+shellQuote(rel))
	}
	parts = append(parts, args...)
	return strings.Join(parts, " "), nil
}

func relSesamDir(r *git.Repository, sesamDir string) (string, error) {
	wt, err := r.Worktree()
	if err != nil {
		return "", fmt.Errorf("worktree: %w", err)
	}
	absSesam, err := filepath.Abs(sesamDir)
	if err != nil {
		return "", fmt.Errorf("absolute sesam dir: %w", err)
	}
	rel, err := filepath.Rel(wt.Filesystem.Root(), absSesam)
	if err != nil {
		return "", fmt.Errorf("relative sesam dir: %w", err)
	}
	return filepath.ToSlash(rel), nil
}

// shellQuote returns s wrapped in POSIX single-quotes if it contains
// any character that the shell would interpret. Inner single quotes
// are escaped via the standard '\” dance ("close, escaped quote, open").
// For ordinary paths (alphanumerics, /, -, _, .) this returns s
// unchanged.
func shellQuote(s string) string {
	const safeMeta = "/-_.+:@~"
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			strings.ContainsRune(safeMeta, r):
			continue
		default:
			return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
		}
	}
	return s
}

func appendMissingLines(path, content string, mode os.FileMode) error {
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
	repo, err := OpenGitRepo(sesamDir)
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
		configPath,
		filepath.Join(sesamDir, ".gitignore"),
		filepath.Join(sesamDir, ".gitattributes"),
		filepath.Join(sesamDir, ".sesam"),
	}

	// Paths above are worktree-relative (or absolute, for an explicit
	// --config). Run `git add` from the worktree root so a nested layout
	// like `--sesam-dir sub` doesn't double-prefix to `sub/sub/...`.
	repo, err := OpenGitRepo(sesamDir)
	if err != nil {
		slog.Warn("failed to open git repo for staging init files", slog.Any("error", err))
		return nil
	}
	wt, err := repo.Worktree()
	if err != nil {
		slog.Warn("failed to read git worktree for staging init files", slog.Any("error", err))
		return nil
	}

	for _, file := range files {
		if _, err := wt.Add(file); err != nil {
			slog.Warn(
				"failed to stage init files",
				slog.String("path", file),
				slog.Any("error", err),
			)
		}
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
