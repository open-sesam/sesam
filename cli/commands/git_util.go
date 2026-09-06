package commands

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"opensesam.org/sesam/core"
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
	mergeKindSquash
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
	// A squash has no merge commit to abort; `git merge --abort` refuses.
	mergeKindSquash: {name: "squash merge", cont: "git commit"},
	// Nothing to continue or abort: resolving the files is the whole job.
	mergeKindOther: {name: "conflicted operation"},
}

func (k mergeKind) String() string      { return mergeKinds[k].name }
func (k mergeKind) InProgress() bool    { return k != mergeKindNone }
func (k mergeKind) ContinueCmd() string { return mergeKinds[k].cont }
func (k mergeKind) AbortCmd() string    { return mergeKinds[k].abort }

// RunsPreCommit reports whether this operation ends in a `git commit`, the only
// thing that fires the pre-commit hook - and with it everything the drivers
// defer to the finalize. `git rebase|cherry-pick|revert --continue` commit
// without running any hook, so there the user has to seal by hand.
func (k mergeKind) RunsPreCommit() bool {
	return mergeKinds[k].cont == "git commit"
}

// mergeState reports which merge-like operation is in progress. Refs are checked
// before the index, since a rebase or cherry-pick also leaves unmerged entries.
func mergeState(sesamDir string) mergeKind {
	kind, _ := inspectMerge(sesamDir)
	return kind
}

// mergeSource resolves the commit being merged in. Falls back to `theirPath`,
// the blob git handed the driver, when git names the operation but not its
// source (a cherry-pick sets no ref until it stops).
func mergeSource(sesamDir, theirPath string) (string, error) {
	_, rev := inspectMerge(sesamDir)
	if rev != "" {
		return rev, nil
	}

	worktreeRoot, err := repo.GitWorktreeRoot(sesamDir)
	if err != nil {
		return "", err
	}

	if sha := commitContaining(worktreeRoot, theirPath); sha != "" {
		return sha, nil
	}

	// A stash pop merges against the stash entry, which git keeps out of --all
	// so commitContaining never finds it. Verifying against the wrong revision
	// only ever refuses the merge, so this is safe as a last guess.
	if sha, err := gitOutput(worktreeRoot, "rev-parse", "-q", "--verify", "refs/stash"); err == nil && sha != "" {
		return sha, nil
	}

	return "", errors.New("cannot tell which branch is being merged in")
}

// inspectMerge asks git once what is going on and, where git says so, which
// commit is coming in. The two questions read the same markers, so they are
// answered together rather than by two probes that can disagree.
func inspectMerge(sesamDir string) (mergeKind, string) {
	worktreeRoot, err := repo.GitWorktreeRoot(sesamDir)
	if err != nil {
		return mergeKindNone, ""
	}

	gitDir, err := gitOutput(worktreeRoot, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return mergeKindNone, ""
	}

	// A rebase has no ref until it stops, but its state dir lives for the whole
	// run (rebase-apply is the older `git am` backend).
	for _, dir := range []string{"rebase-merge", "rebase-apply"} {
		if _, err := os.Stat(filepath.Join(gitDir, dir)); err == nil {
			return mergeKindRebase, rebasePickedCommit(gitDir)
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
		if sha, err := gitOutput(worktreeRoot, "rev-parse", "-q", "--verify", probe.ref); err == nil {
			return probe.kind, sha
		}
	}

	// A squash merge leaves no ref and no merge commit - only this file, until the
	// user commits. Without it the finalize would skip a squash entirely.
	if _, err := os.Stat(filepath.Join(gitDir, "SQUASH_MSG")); err == nil {
		return mergeKindSquash, ""
	}

	// A plain merge exports one GITHEAD_<sha> per merge head while a strategy
	// runs. git sets it in no documented place, so it is a hint: worth taking for
	// the revision, never trusted to mean "still busy" (hooks see it too).
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GITHEAD_") {
			continue
		}

		sha, _, _ := strings.Cut(strings.TrimPrefix(kv, "GITHEAD_"), "=")
		return mergeKindMerge, sha
	}

	// Nothing named it, but the index is still unmerged - a conflicted stash pop
	// looks like this, and the stash entry is what it merged against.
	if out, err := gitOutput(worktreeRoot, "ls-files", "--unmerged"); err == nil && out != "" {
		stash, _ := gitOutput(worktreeRoot, "rev-parse", "-q", "--verify", "refs/stash")
		return mergeKindOther, stash
	}

	return mergeKindNone, ""
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
		filepath.Join(prefix, core.SesamDir()),
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

	objectsDir := filepath.ToSlash(filepath.Join(prefix, core.SesamObjectsDir()))

	// -z gives raw NUL-separated bytes. Without it git C-quotes any path holding
	// non-ASCII, a control char, a quote or a backslash ("h\303\251llo") - which
	// then matches no real path, gets skipped here, and the seal afterwards
	// writes our stale plaintext back over the incoming object. Setting
	// core.quotePath=false is not enough: a newline or quote in the name stays
	// escaped either way.
	args := slices.Concat(gitArgs, []string{"-z", "--", objectsDir})
	out, err := gitOutputRaw(worktreeRoot, args...)
	if err != nil {
		return nil, fmt.Errorf("git diff for changed objects: %w", err)
	}

	var paths []string
	for line := range strings.SplitSeq(out, "\x00") {
		if line == "" {
			continue
		}

		rel, err := filepath.Rel(prefix, line)
		if err != nil {
			continue
		}

		revealed, ok := core.RevealedPath(rel)
		if !ok {
			continue
		}

		paths = append(paths, revealed)
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
	out, err := gitOutputRaw(dir, args...)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(out), nil
}

// gitOutputRaw is gitOutput without the trim - for output where whitespace is
// data, i.e. path lists (a file name may start or end with a space).
func gitOutputRaw(dir string, args ...string) (string, error) {
	//nolint:gosec // fixed git subcommands; args are constants from this file.
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir

	var buf bytes.Buffer
	cmd.Stdout = &buf
	// Without this git's diagnostics go to /dev/null and callers can only report
	// "exit status N". Our probes pass -q, so a healthy repo stays quiet.
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// rebasePickedCommit reads the commit a rebase is currently replaying.
func rebasePickedCommit(gitDir string) string {
	for _, name := range []string{"rebase-merge/stopped-sha", "rebase-merge/done", "rebase-apply/original-commit"} {
		//nolint:gosec // path is built from the git dir and a fixed name.
		data, err := os.ReadFile(filepath.Join(gitDir, filepath.FromSlash(name)))
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		fields := strings.Fields(lines[len(lines)-1])

		switch len(fields) {
		case 0:
			continue
		case 1:
			return fields[0] // a bare sha, as in stopped-sha
		default:
			// "<command> <sha> # subject", but `fixup -C <sha>` and (with
			// --rebase-merges) `merge -C <sha> <label>` put a flag in the middle.
			if strings.HasPrefix(fields[1], "-") && len(fields) > 2 {
				return fields[2]
			}

			return fields[1]
		}
	}

	return ""
}

// extractSesamDir unpacks the .sesam directory of `rev` into destDir. A worktree
// would be the obvious way, but `git worktree add` fires post-checkout, which
// would have sesam clean and reveal into the temporary tree.
func extractSesamDir(ctx context.Context, sesamDir, rev, destDir string) error {
	worktreeRoot, prefix, err := worktreePrefix(sesamDir)
	if err != nil {
		return err
	}

	if err := os.RemoveAll(destDir); err != nil {
		return err
	}

	//nolint:gosec // fixed git subcommand; rev is a sha we resolved ourselves.
	cmd := exec.CommandContext(ctx, "git", "archive", "--format=tar", rev, "--",
		filepath.ToSlash(filepath.Join(prefix, ".sesam")))
	cmd.Dir = worktreeRoot

	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := untar(out, destDir, filepath.ToSlash(prefix)); err != nil {
		_ = cmd.Wait()
		return err
	}

	return cmd.Wait()
}

// commitContaining finds a commit that carries the blob in `file`. Picking the
// wrong one is safe: its audit log would not vouch for the object either, and
// the verification refuses.
func commitContaining(worktreeRoot, file string) string {
	blob, err := gitOutput(worktreeRoot, "hash-object", "--", file)
	if err != nil {
		return ""
	}

	sha, err := gitOutput(worktreeRoot, "log", "--all", "--format=%H", "-n", "1", "--find-object="+blob)
	if err != nil {
		return ""
	}

	return sha
}
