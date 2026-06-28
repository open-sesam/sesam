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
	"github.com/google/renameio/v2"
	"github.com/open-sesam/sesam/core"
)

//go:embed assets/gitignore.default
var gitignoreTemplate string

//go:embed assets/gitattributes.default
var gitattributesTemplate string

//go:embed assets/README.default
var sesamReadmeTemplate string

//go:embed assets/config.default
var configTemplate string

// resolveSesamDirAndGit resolves the sesam repository root and opens the git
// repository close to it.
//
// It starts at sesamPath and walks upward until the git worktree root,
// returning the first directory that contains .sesam. If none is found, it
// returns sesamPath (used by init before .sesam exists).
func resolveSesamDirAndGit(sesamPath string) (string, *git.Repository, error) {
	if strings.TrimSpace(sesamPath) == "" {
		sesamPath = "."
	}

	absPath, err := filepath.Abs(filepath.Clean(sesamPath))
	if err != nil {
		return "", nil, fmt.Errorf("failed to resolve repo path %s: %w", sesamPath, err)
	}

	repoInfo, err := os.Stat(absPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to access repo path %s: %w", absPath, err)
	}

	if !repoInfo.IsDir() {
		return "", nil, fmt.Errorf("repo path %s is not a directory", absPath)
	}

	gitRepo, err := git.PlainOpenWithOptions(absPath, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", nil, fmt.Errorf("no git repository found at %s: %w", absPath, err)
	}

	wt, err := gitRepo.Worktree()
	if err != nil {
		return "", nil, fmt.Errorf("failed to access git worktree: %w", err)
	}

	worktreeRoot := filepath.Clean(wt.Filesystem.Root())
	current := absPath
	for {
		if _, err := os.Stat(filepath.Join(current, sesamSuffix)); err == nil {
			return current, gitRepo, nil
		}

		if current == worktreeRoot {
			break
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	return absPath, gitRepo, nil
}

// resolveSesamDir is a convenience wrapper that drops the git handle.
func resolveSesamDir(sesamPath string) (string, error) {
	sesamDir, _, err := resolveSesamDirAndGit(sesamPath)
	return sesamDir, err
}

func isInitialized(sesamRoot string) error {
	configPath := filepath.Join(sesamRoot, "sesam.yml")
	sesamDir := filepath.Join(sesamRoot, sesamSuffix)

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

func ensureSesamDirs(sesamDir string) error {
	dirs := []string{
		filepath.Join(sesamDir, sesamSuffix),
		filepath.Join(sesamDir, sesamSuffix, "signkeys"),
		filepath.Join(sesamDir, sesamSuffix, "tmp"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	slog.Debug("initialized sesam directory", slog.String("path", filepath.Join(sesamDir, sesamSuffix)))
	return nil
}

func createInitialConfig(configPath, initialUser string, initialRecipients []string) error {
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

	slog.Debug("created sample config", slog.String("path", configPath))
	return nil
}

func quoteYAMLString(value string) string {
	escaped := strings.ReplaceAll(value, "'", "''")
	return "'" + escaped + "'"
}

func configureGitIntegration(gitRepo *git.Repository, sesamDir string, opts RepoInitOpts) error {
	opts.PrintStep("Adjusting .gitignore to ignore all revealed files…")
	if err := ensureDefaultGitIgnore(sesamDir); err != nil {
		return err
	}

	opts.PrintStep("Telling git when to call sesam…")
	if err := ensureDefaultGitAttributes(sesamDir); err != nil {
		return err
	}

	opts.PrintStep("Adjusting git config…")
	if err := ensureGitConfig(gitRepo, sesamDir, opts); err != nil {
		return err
	}

	return nil
}

func ensureDefaultGitIgnore(sesamDir string) error {
	gitignorePath := filepath.Join(sesamDir, ".gitignore")
	return appendMissingLines(gitignorePath, gitignoreTemplate, 0o600)
}

func ensureDefaultGitAttributes(sesamDir string) error {
	gitAttributesPath := filepath.Join(sesamDir, ".gitattributes")
	return appendMissingLines(gitAttributesPath, gitattributesTemplate, 0o600)
}

// mergeDriverName is the display name git shows for sesam's audit-log merge
// driver. Shared by ensureGitConfig (which sets it) and expectedGitConfig
// (which `sesam doctor` checks against).
const mergeDriverName = "merge the audit log of sesam"

// gitConfigEntry is one git-config key sesam manages, together with the value
// `sesam init` installs for it.
type gitConfigEntry struct {
	display    string // dotted path, e.g. "merge.sesam-merge.driver"
	section    string
	subsection string // empty for plain sections such as "alias"
	option     string
	value      string
}

// expectedGitConfig returns the git-config entries `sesam init` installs for the
// repository at sesamDir. It is the single source of truth for both writing the
// config (ensureGitConfig) and checking it (CheckGitConfig); the driver command
// strings come from sesamCmd, so writer and checker can never drift.
func expectedGitConfig(r *git.Repository, sesamDir string) ([]gitConfigEntry, error) {
	// Every git driver below is `sesam <subcommand>` run through the
	// shell with cwd = worktree root; for nested layouts each one
	// needs the same --sesam-dir treatment to find `.sesam/`.
	mergeCmd, err := sesamCmd(r, sesamDir, "audit", "merge", "%O", "%A", "%B", "%L", "%P")
	if err != nil {
		return nil, err
	}

	textconvCmd, err := sesamCmd(r, sesamDir, "show")
	if err != nil {
		return nil, err
	}

	smudgeCmd, err := sesamCmd(r, sesamDir, "smudge")
	if err != nil {
		return nil, err
	}

	aliasCmd, err := sesamCmd(r, sesamDir)
	if err != nil {
		return nil, err
	}

	return []gitConfigEntry{
		{"merge.sesam-merge.name", "merge", "sesam-merge", "name", mergeDriverName},
		{"merge.sesam-merge.driver", "merge", "sesam-merge", "driver", mergeCmd},
		{"diff.sesam-diff.textconv", "diff", "sesam-diff", "textconv", textconvCmd},
		{"filter.sesam-filter.required", "filter", "sesam-filter", "required", "false"},
		{"filter.sesam-filter.process", "filter", "sesam-filter", "process", smudgeCmd},
		{"alias.sesam", "alias", "", "sesam", "!" + aliasCmd},
	}, nil
}

func ensureGitConfig(r *git.Repository, sesamDir string, opts RepoInitOpts) error {
	cfg, err := r.ConfigScoped(gogitconfig.LocalScope)
	if err != nil {
		return fmt.Errorf("read local git config: %w", err)
	}

	mergeSection := cfg.Raw.Section("merge").Subsection("sesam-merge")
	filterSection := cfg.Raw.Section("filter").Subsection("sesam-filter")
	aliasSection := cfg.Raw.Section("alias")

	mergeConfigured := mergeSection.Option("driver") != ""
	processConfigured := filterSection.Option("process") != ""
	aliasConfigured := aliasSection.Option("sesam") != ""

	if mergeConfigured && processConfigured && aliasConfigured {
		return nil
	}

	entries, err := expectedGitConfig(r, sesamDir)
	if err != nil {
		return err
	}
	val := func(display string) string {
		for _, e := range entries {
			if e.display == display {
				return e.value
			}
		}
		return ""
	}

	if !mergeConfigured {
		opts.PrintStep("  • Installing merge driver…")

		mergeSection.SetOption("name", val("merge.sesam-merge.name"))
		mergeSection.SetOption("driver", val("merge.sesam-merge.driver"))

		opts.PrintStep("  • installing diff driver…")
		diffSection := cfg.Raw.Section("diff").Subsection("sesam-diff")
		diffSection.SetOption("textconv", val("diff.sesam-diff.textconv"))
	}

	if !processConfigured {
		opts.PrintStep("  • Installing smudge filter…")

		// required=false means a smudge failure doesn't abort
		// `git checkout`; the encrypted bytes land instead. We rely
		// on this to keep history bisects working when the audit log
		// is unavailable.
		filterSection.SetOption("required", val("filter.sesam-filter.required"))

		// Long-running filter process - amortises identity loading
		// across all blobs in a single git operation AND lets the
		// handler load the audit log once per session for the
		// sealer-vs-access check. Requires git >= 2.11 (Dec 2016).
		filterSection.SetOption("process", val("filter.sesam-filter.process"))
	}

	if !aliasConfigured {
		// `!` makes git execute the value as a shell command instead of
		// looking for `git-sesam` on PATH, so users get `git sesam ...`
		// without any PATH plumbing. Git runs the command with cwd =
		// worktree root, which is what sesam wants anyway.
		opts.PrintStep("  • Making sure sesam can be called as `git sesam`…")
		aliasSection.SetOption("sesam", val("alias.sesam"))
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
	rel, err := core.SesamGitPrefix(r, sesamDir)
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

func ensureSesamReadme(sesamDir string) error {
	readmePath := filepath.Join(sesamDir, "README.md")
	if _, err := os.Stat(readmePath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access %s: %w", readmePath, err)
	}

	if err := renameio.WriteFile(readmePath, []byte(sesamReadmeTemplate), 0o600); err != nil {
		return fmt.Errorf("failed to create sesam readme %s: %w", readmePath, err)
	}

	slog.Debug("created sesam readme", slog.String("path", readmePath))
	return nil
}

func stageInitFiles(r *git.Repository, sesamDir, configPath string) error {
	files := []string{
		configPath,
		filepath.Join(sesamDir, ".gitignore"),
		filepath.Join(sesamDir, ".gitattributes"),
		filepath.Join(sesamDir, ".sesam"),
	}

	wt, err := r.Worktree()
	if err != nil {
		slog.Warn("failed to open git worktree for staging", slog.Any("error", err))
		return nil
	}

	worktreeRoot := wt.Filesystem.Root()
	for _, filePath := range files {
		relPath, err := filepath.Rel(worktreeRoot, filePath)
		if err != nil {
			slog.Warn("failed to resolve path for staging", slog.String("path", filePath), slog.Any("error", err))
			continue
		}

		if strings.HasPrefix(relPath, "..") {
			slog.Warn("skipping path outside git worktree", slog.String("path", filePath))
			continue
		}

		if _, err := wt.Add(relPath); err != nil {
			slog.Warn("failed to stage path", slog.String("path", relPath), slog.Any("error", err))
		}
	}

	return nil
}
