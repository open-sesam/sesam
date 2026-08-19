package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"opensesam.org/sesam/repo"
)

// mergeKind names the in-progress git operation. All of them drive our merge
// drivers, but each is continued and aborted differently.
type mergeKind int

const (
	mergeKindNone mergeKind = iota
	mergeKindMerge
	mergeKindRebase
	mergeKindCherryPick
	mergeKindRevert
	// mergeKindOther: unmerged index with no state ref to explain it, e.g. a
	// conflicted `git stash pop`.
	mergeKindOther
)

var mergeKinds = map[mergeKind]struct {
	name  string
	cont  string
	abort string
}{
	mergeKindNone:  {name: "none"},
	mergeKindMerge: {name: "merge", cont: "git commit", abort: "git merge --abort"},
	mergeKindRebase: {
		name: "rebase", cont: "git rebase --continue", abort: "git rebase --abort",
	},
	mergeKindCherryPick: {
		name: "cherry-pick", cont: "git cherry-pick --continue", abort: "git cherry-pick --abort",
	},
	mergeKindRevert: {
		name: "revert", cont: "git revert --continue", abort: "git revert --abort",
	},
	// Nothing to continue or abort: resolving the files is the whole job.
	mergeKindOther: {name: "conflicted operation"},
}

func (k mergeKind) String() string      { return mergeKinds[k].name }
func (k mergeKind) InProgress() bool    { return k != mergeKindNone }
func (k mergeKind) ContinueCmd() string { return mergeKinds[k].cont }
func (k mergeKind) AbortCmd() string    { return mergeKinds[k].abort }

// mergeState reports which merge-like operation is in progress. Refs are checked
// before the index, since a rebase or cherry-pick also leaves unmerged entries.
func mergeState(sesamDir string) mergeKind {
	worktreeRoot, err := repo.GitWorktreeRoot(sesamDir)
	if err != nil {
		return mergeKindNone
	}

	gitDir, err := gitOutput(worktreeRoot, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return mergeKindNone
	}

	// A rebase has no ref until it stops, but its state dir lives for the whole
	// run (rebase-apply is the older `git am` backend).
	for _, dir := range []string{"rebase-merge", "rebase-apply"} {
		if _, err := os.Stat(filepath.Join(gitDir, dir)); err == nil {
			return mergeKindRebase
		}
	}

	for _, probe := range []struct {
		ref  string
		kind mergeKind
	}{
		{"CHERRY_PICK_HEAD", mergeKindCherryPick},
		{"REVERT_HEAD", mergeKindRevert},
		{"MERGE_HEAD", mergeKindMerge},
	} {
		if _, err := gitOutput(worktreeRoot, "rev-parse", "-q", "--verify", probe.ref); err == nil {
			return probe.kind
		}
	}

	// MERGE_HEAD is only written once the tree merge is done, so mid-driver this
	// env var is all we have. A hint only: a miss costs a vaguer message, nothing
	// more. git exports it to hooks too, so never use this to detect "still busy".
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GITHEAD_") {
			return mergeKindMerge
		}
	}

	// Nothing named it, but the index is still unmerged.
	if out, err := gitOutput(worktreeRoot, "ls-files", "--unmerged"); err == nil && out != "" {
		return mergeKindOther
	}

	return mergeKindNone
}

// mergeTouchedSesam reports whether an in-progress merge changed anything under
// the sesam dir (staged index vs HEAD).
func mergeTouchedSesam(sesamDir string) (bool, error) {
	worktreeRoot, prefix, err := worktreePrefix(sesamDir)
	if err != nil {
		return false, err
	}

	// `git diff --cached --quiet` exits 0 for no change, 1 for a change.
	//nolint:gosec // fixed git subcommand; pathspec is derived from the repo layout.
	cmd := exec.CommandContext(
		context.Background(),
		"git", "diff", "--cached", "--quiet", "HEAD", "--",
		filepath.Join(prefix, ".sesam"),
	)
	cmd.Dir = worktreeRoot
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err == nil {
		return false, nil
	}

	exitErr := new(exec.ExitError)
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return true, nil
	}

	return false, fmt.Errorf("git diff for merge check: %w", err)
}

// stagedSecretPaths returns the revealed paths whose object is about to be
// committed. Those objects are authoritative - git may have taken one side
// without calling our driver. Conflicted secrets never show up here: their
// object is untouched.
func stagedSecretPaths(sesamDir string) ([]string, error) {
	return changedSecretPaths(sesamDir, "diff", "--cached", "--name-only", "HEAD")
}

// mergedSecretPaths returns the revealed paths whose object the merge that just
// finished changed. HEAD has already moved by then, so ORIG_HEAD is the handle.
func mergedSecretPaths(sesamDir string) ([]string, error) {
	return changedSecretPaths(sesamDir, "diff", "--name-only", "ORIG_HEAD", "HEAD")
}

func changedSecretPaths(sesamDir string, gitArgs ...string) ([]string, error) {
	worktreeRoot, prefix, err := worktreePrefix(sesamDir)
	if err != nil {
		return nil, err
	}

	objectsDir := filepath.ToSlash(filepath.Join(prefix, ".sesam", "objects"))
	out, err := gitOutput(worktreeRoot, append(gitArgs, "--", objectsDir)...)
	if err != nil {
		return nil, fmt.Errorf("git diff for changed objects: %w", err)
	}

	var paths []string
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		rel, err := filepath.Rel(objectsDir, line)
		if err != nil {
			continue
		}

		paths = append(paths, strings.TrimSuffix(filepath.ToSlash(rel), ".sesam"))
	}

	return paths, nil
}

// worktreePrefix returns the git worktree root and the sesam dir relative to it.
func worktreePrefix(sesamDir string) (root, prefix string, err error) {
	root, err = repo.GitWorktreeRoot(sesamDir)
	if err != nil {
		return "", "", fmt.Errorf("locate worktree root: %w", err)
	}

	absSesam, err := filepath.Abs(sesamDir)
	if err != nil {
		return "", "", err
	}

	prefix, err = filepath.Rel(root, absSesam)
	if err != nil {
		return "", "", err
	}

	return root, prefix, nil
}

// gitOutput runs git in dir and returns its trimmed stdout.
func gitOutput(dir string, args ...string) (string, error) {
	//nolint:gosec // fixed git subcommands; args are constants from this file.
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir

	var buf bytes.Buffer
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}
