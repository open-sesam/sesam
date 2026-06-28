package repo

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
)

// GitConfigCheck reports whether one git-config entry sesam manages matches the
// value `sesam init` would install.
type GitConfigCheck struct {
	Path     string // dotted path, e.g. "merge.sesam-merge.driver"
	Expected string
	Actual   string // empty when unset
	OK       bool
}

// ManagedFileCheck reports which expected lines are missing from a file sesam
// maintains (.gitignore / .gitattributes).
type ManagedFileCheck struct {
	Path    string // absolute path that was inspected
	Exists  bool
	Missing []string
}

// doctorGitConfigPaths is the subset of managed git-config entries `sesam
// doctor` reports on. The filter driver and `filter…required` are intentionally
// left out here; doctor focuses on the merge/diff/alias wiring.
var doctorGitConfigPaths = map[string]bool{
	"merge.sesam-merge.name":   true,
	"merge.sesam-merge.driver": true,
	"diff.sesam-diff.textconv": true,
	"alias.sesam":              true,
}

// GitWorktreeRoot opens the git repository containing dir (searching upward for
// a .git) and returns the absolute path of its worktree root. It errors when
// dir is not inside a git repository.
func GitWorktreeRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	gitRepo, err := git.PlainOpenWithOptions(abs, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", err
	}

	wt, err := gitRepo.Worktree()
	if err != nil {
		return "", err
	}

	return wt.Filesystem.Root(), nil
}

// ReadGitVersion runs `git --version` and parses the result into a semver.
func ReadGitVersion(ctx context.Context) (*semver.Version, error) {
	out, err := exec.CommandContext(ctx, "git", "--version").Output()
	if err != nil {
		return nil, fmt.Errorf("run git --version: %w", err)
	}
	return parseGitVersion(string(out))
}

// parseGitVersion extracts the version from `git --version` output. The format
// is "git version X.Y.Z", with vendor noise on some platforms - a "(Apple
// Git-154)" suffix on macOS, a ".windows.1" suffix on Windows - so we take the
// third field and keep only its leading numeric-dotted run before parsing.
func parseGitVersion(raw string) (*semver.Version, error) {
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return nil, fmt.Errorf("malformed git version: %q", raw)
	}

	core := strings.TrimRight(leadingVersionCore(fields[2]), ".")
	v, err := semver.NewVersion(core)
	if err != nil {
		return nil, fmt.Errorf("malformed git version %q: %w", raw, err)
	}
	return v, nil
}

// leadingVersionCore returns the leading run of digits and dots in s, dropping
// any vendor suffix (e.g. "2.45.1.macos.1" -> "2.45.1.").
func leadingVersionCore(s string) string {
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return s[:i]
}

// CheckGitConfig compares the merge/diff/alias git-config entries sesam relies
// on against what `sesam init` would install for the repo at sesamDir.
func CheckGitConfig(sesamDir string) ([]GitConfigCheck, error) {
	resolvedDir, gitRepo, err := resolveSesamDirAndGit(sesamDir)
	if err != nil {
		return nil, err
	}

	entries, err := expectedGitConfig(gitRepo, resolvedDir)
	if err != nil {
		return nil, err
	}

	cfg, err := gitRepo.ConfigScoped(gogitconfig.LocalScope)
	if err != nil {
		return nil, fmt.Errorf("read local git config: %w", err)
	}

	var checks []GitConfigCheck
	for _, e := range entries {
		if !doctorGitConfigPaths[e.display] {
			continue
		}

		section := cfg.Raw.Section(e.section)
		actual := section.Option(e.option)
		if e.subsection != "" {
			actual = section.Subsection(e.subsection).Option(e.option)
		}

		checks = append(checks, GitConfigCheck{
			Path:     e.display,
			Expected: e.value,
			Actual:   actual,
			OK:       actual == e.value,
		})
	}

	return checks, nil
}

// CheckGitIgnore reports whether the repo's .gitignore still contains the lines
// `sesam init` writes.
func CheckGitIgnore(sesamDir string) (ManagedFileCheck, error) {
	return checkManagedFile(sesamDir, ".gitignore", gitignoreTemplate)
}

// CheckGitAttributes reports whether the repo's .gitattributes still contains
// the lines `sesam init` writes.
func CheckGitAttributes(sesamDir string) (ManagedFileCheck, error) {
	return checkManagedFile(sesamDir, ".gitattributes", gitattributesTemplate)
}

func checkManagedFile(sesamDir, name, template string) (ManagedFileCheck, error) {
	resolvedDir, err := resolveSesamDir(sesamDir)
	if err != nil {
		return ManagedFileCheck{}, err
	}

	path := filepath.Join(resolvedDir, name)
	res := ManagedFileCheck{Path: path}

	data, err := os.ReadFile(path) //nolint:gosec // path derived from the repo root
	if err != nil {
		if os.IsNotExist(err) {
			res.Missing = templateLines(template)
			return res, nil
		}
		return res, fmt.Errorf("read %s: %w", path, err)
	}

	res.Exists = true
	existing := string(data)
	for _, line := range templateLines(template) {
		// Mirror appendMissingLines' membership test so the check agrees
		// with what init would (not) re-append.
		if strings.Contains(existing, line+"\n") || strings.HasSuffix(existing, line) {
			continue
		}
		res.Missing = append(res.Missing, line)
	}

	return res, nil
}

// templateLines returns the significant (non-blank, non-comment) lines of a
// managed-file template - the ones whose presence actually matters.
func templateLines(template string) []string {
	var lines []string
	for _, raw := range strings.Split(template, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
