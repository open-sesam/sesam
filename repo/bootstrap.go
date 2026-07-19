package repo

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/sahib/renameio/v2"
	"opensesam.org/sesam/core"
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
	suffix, err := sesamSubsectionSuffix(gitRepo, sesamDir)
	if err != nil {
		return err
	}
	if err := ensureDefaultGitAttributes(sesamDir, suffix); err != nil {
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

func ensureDefaultGitAttributes(sesamDir, suffix string) error {
	content, err := renderGitAttributes(suffix)
	if err != nil {
		return err
	}
	return appendMissingLines(filepath.Join(sesamDir, ".gitattributes"), content, 0o600)
}

func clearGitAttributes(sesamDir, suffix string) error {
	content, err := renderGitAttributes(suffix)
	if err != nil {
		return err
	}
	return removeManagedLines(filepath.Join(sesamDir, ".gitattributes"), content, 0o600)
}

func clearGitIgnore(sesamDir string) error {
	gitignorePath := filepath.Join(sesamDir, ".gitignore")
	return removeManagedLines(gitignorePath, gitignoreTemplate, 0o600)
}

// gitConfigEntry is one git-config key sesam manages, together with the value
// `sesam init` installs for it.
type gitConfigEntry struct {
	display    string // dotted path, e.g. "merge.sesam-merge.driver"
	section    string
	subsection string // empty for plain sections such as "alias"
	option     string
	value      string
	report     bool
}

// expectedGitConfig returns the git-config entries `sesam init` installs for the
// repository at sesamDir. It is the single source of truth for both writing the
// config (ensureGitConfig) and checking it (CheckGitConfig); the driver command
// strings come from sesamCmd, so writer and checker can never drift.
func expectedGitConfig(r *git.Repository, sesamDir string) ([]gitConfigEntry, error) {
	// Every git driver below is `sesam <subcommand>` run through the
	// shell with cwd = worktree root; for nested layouts each one
	// needs the same --sesam-dir treatment to find `.sesam/`.
	mergeSecretCmd, err := sesamCmd(r, sesamDir, "merge", "secret", "%O", "%A", "%B", "%L", "%P")
	if err != nil {
		return nil, err
	}

	mergeLogCmd, err := sesamCmd(r, sesamDir, "merge", "log", "%O", "%A", "%B", "%L", "%P")
	if err != nil {
		return nil, err
	}

	textconvCmd, err := sesamCmd(r, sesamDir, "show")
	if err != nil {
		return nil, err
	}

	preCommitCmd, err := sesamCmd(r, sesamDir, "hook", "pre-commit")
	if err != nil {
		return nil, err
	}

	postCheckoutCmd, err := sesamCmd(r, sesamDir, "hook", "post-checkout")
	if err != nil {
		return nil, err
	}

	// suffix uniquifies the subsection names per sesam repo so several sesam
	// repos can coexist in one git repo without clobbering each other's config
	// (and, for hooks, so all of them fire). It also lands in .gitattributes as
	// the driver name; keep the two in sync via this one function. The display
	// path stays unsuffixed so `sesam doctor` shows stable labels.
	suffix, err := sesamSubsectionSuffix(r, sesamDir)
	if err != nil {
		return nil, err
	}

	baseEntries := []gitConfigEntry{
		{"merge.sesam-merge.name", "merge", "sesam-merge-secret" + suffix, "name", "sesam-secret merge driver", true},
		{"merge.sesam-merge.driver", "merge", "sesam-merge-secret" + suffix, "driver", mergeSecretCmd, true},
		{"merge.sesam-merge.name", "merge", "sesam-merge-log" + suffix, "name", "sesam-audit-log merge driver", false},
		{"merge.sesam-merge.driver", "merge", "sesam-merge-log" + suffix, "driver", mergeLogCmd, false},
		{"diff.sesam-diff.textconv", "diff", "sesam-diff" + suffix, "textconv", textconvCmd, true},
		{"alias.sesam", "alias", "", "sesam", "!sesam", true},
	}

	var gitSupportsConfigHooks bool
	ver, err := ReadGitVersion(context.Background())
	if err != nil {
		slog.Warn("failed to figure out git --version", slog.Any("err", err))
	}

	// See: https://github.blog/open-source/git/highlights-from-git-2-54/#h-config-based-hooks
	if ver.GreaterThanEqual(semver.MustParse("2.54.0")) {
		gitSupportsConfigHooks = true
	} else {
		slog.Warn("not installing hooks, because git >= 2.54.0 is needed")
	}

	if gitSupportsConfigHooks {
		baseEntries = append(baseEntries, []gitConfigEntry{
			{"hook.sesam-precommit.event", "hook", "sesam-precommit" + suffix, "event", "pre-commit", false},
			{"hook.sesam-precommit.command", "hook", "sesam-precommit" + suffix, "command", wrapHookCmd(preCommitCmd), true},
			{"hook.sesam-postcheckout.event", "hook", "sesam-postcheckout" + suffix, "event", "post-checkout", false},
			{"hook.sesam-postcheckout.command", "hook", "sesam-postcheckout" + suffix, "command", wrapHookCmd(postCheckoutCmd), true},
		}...)
	}

	return baseEntries, nil
}

func ensureGitConfig(r *git.Repository, sesamDir string, opts RepoInitOpts) error {
	cfg, err := r.ConfigScoped(gogitconfig.LocalScope)
	if err != nil {
		return fmt.Errorf("read local git config: %w", err)
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

	if opts.GitConfigOpts.InstallMerge {
		opts.PrintStep("  • Installing merge driver…")
		for _, entry := range entries {
			if strings.HasPrefix(entry.display, "merge.") {
				section := cfg.Raw.Section(entry.section).Subsection(entry.subsection)
				section.SetOption(entry.option, entry.value)
			}
		}
	}

	if opts.GitConfigOpts.InstallDiff {
		opts.PrintStep("  • installing diff driver…")
		for _, entry := range entries {
			if strings.HasPrefix(entry.display, "diff.") {
				section := cfg.Raw.Section(entry.section).Subsection(entry.subsection)
				section.SetOption(entry.option, entry.value)
			}
		}
	}

	if opts.GitConfigOpts.InstallAlias {
		opts.PrintStep("  • Making sure sesam can be called as `git sesam`…")
		aliasSection := cfg.Raw.Section("alias")
		aliasSection.SetOption("sesam", val("alias.sesam"))
	}

	if opts.GitConfigOpts.InstallHooks {
		opts.PrintStep("  • Installing pre-commit+post-checkout hooks…")
		for _, entry := range entries {
			if strings.HasPrefix(entry.display, "hook.") {
				section := cfg.Raw.Section(entry.section).Subsection(entry.subsection)
				section.SetOption(entry.option, entry.value)
			}
		}
	}

	if err := r.SetConfig(cfg); err != nil {
		return fmt.Errorf("write git config: %w", err)
	}

	return nil
}

func clearGitConfig(r *git.Repository, sesamDir, sectionPrefix string) error {
	cfg, err := r.ConfigScoped(gogitconfig.LocalScope)
	if err != nil {
		return fmt.Errorf("read local git config: %w", err)
	}

	entries, err := expectedGitConfig(r, sesamDir)
	if err != nil {
		return fmt.Errorf("expected config: %w", err)
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.section, sectionPrefix) {
			if entry.subsection == "" {
				cfg.Raw.Section(entry.section).RemoveOption(entry.option)
			} else {
				cfg.Raw = cfg.Raw.RemoveSubsection(entry.section, entry.subsection)
			}
		}
	}

	if err := r.SetConfig(cfg); err != nil {
		return fmt.Errorf("write git config: %w", err)
	}

	return nil
}

// sesamSubsectionSuffix returns the suffix appended to sesam's git-config
// subsection names (and the driver names in .gitattributes) so several sesam
// repos can coexist in one git repo without clobbering each other. It is empty
// for a repo at the worktree root; otherwise it is "-" + the worktree-relative
// sesam dir, percent-encoded (url.PathEscape) so it is a valid, whitespace-free
// git-config subsection name and .gitattributes driver token.
//
// Note: the suffix pins the sesam dir at install time. Moving the sesam dir
// (e.g. `git mv`) leaves stale names and a wrong --sesam-dir in the command;
// re-run `sesam init` to refresh the git integration after such a move.
func sesamSubsectionSuffix(r *git.Repository, sesamDir string) (string, error) {
	rel, err := core.SesamGitPrefix(r, sesamDir)
	if err != nil {
		return "", err
	}
	if rel == "." || rel == "" {
		return "", nil
	}
	return "-" + url.PathEscape(rel), nil
}

// renderGitAttributes fills the .gitattributes template with the per-repo driver
// suffix so its merge=/diff= references match the installed git-config
// subsections (see sesamSubsectionSuffix).
func renderGitAttributes(suffix string) (string, error) {
	tmpl, err := template.New("gitattributes").Parse(gitattributesTemplate)
	if err != nil {
		return "", fmt.Errorf("parse gitattributes template: %w", err)
	}

	var out bytes.Buffer
	if err := tmpl.Execute(&out, struct{ Suffix string }{Suffix: suffix}); err != nil {
		return "", fmt.Errorf("render gitattributes template: %w", err)
	}
	return out.String(), nil
}

// wrapHookCmd makes a config-based hook a no-op when sesam is not on PATH,
// instead of aborting the commit/checkout with "command not found". git runs the
// value as `sh -c '<value> "$@"' … <hook-args>`, so the sesam invocation must
// stay last for the appended "$@" to reach it. When sesam is present its exit
// status is honored, so pre-commit can still block a bad commit.
func wrapHookCmd(sesamHookCmd string) string {
	return "command -v sesam >/dev/null 2>&1 || exit 0; exec " + sesamHookCmd
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

// removeManagedLines strips every line sesam appended (the non-blank lines of
// content, matched after trimming, as appendMissingLines writes them) from the
// file at path, keeping any lines the user added. If nothing sesam-managed is
// left the file is removed, since sesam created it. A missing file is a no-op.
func removeManagedLines(path, content string, mode os.FileMode) error {
	data, err := os.ReadFile(path) //nolint:gosec
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to access %s: %w", path, err)
	}

	managed := make(map[string]bool)
	for line := range strings.SplitSeq(content, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			managed[line] = true
		}
	}

	kept := make([]string, 0)
	for _, line := range strings.Split(string(data), "\n") {
		if managed[strings.TrimSpace(line)] {
			continue
		}
		kept = append(kept, line)
	}

	remaining := strings.Join(kept, "\n")
	if strings.TrimSpace(remaining) == "" {
		// Only sesam's lines were in the file: drop the file sesam created.
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
		return nil
	}

	if err := renameio.WriteFile(path, []byte(remaining), mode); err != nil {
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
