package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// CheckGitConfig compares the git-config entries sesam surfaces in `sesam
// doctor` (those flagged report in expectedGitConfig - merge/diff/alias and, on
// git >= 2.54, the hook commands) against what `sesam init` would install for
// the repo at sesamDir.
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
		if !e.report {
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
