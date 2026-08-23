package commands

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

	// A squash merge leaves no ref and no merge commit - only this file, until the
	// user commits. Without it the finalize would skip a squash entirely.
	if _, err := os.Stat(filepath.Join(gitDir, "SQUASH_MSG")); err == nil {
		return mergeKindSquash
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

// resolveTheirRevision finds the commit being merged in. git names it differently
// per operation and, for a cherry-pick or stash pop, not at all - hence the
// index-free fallbacks.
func resolveTheirRevision(sesamDir, theirPath string) (string, error) {
	worktreeRoot, err := repo.GitWorktreeRoot(sesamDir)
	if err != nil {
		return "", fmt.Errorf("locate worktree root: %w", err)
	}

	// A plain merge exports one GITHEAD_<sha> per merge head. That variable is set
	// by git when it invokes a strategy and appears in no documentation, so treat
	// it as a hint and keep the blob search below as the real answer.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GITHEAD_") {
			continue
		}

		if sha, _, _ := strings.Cut(strings.TrimPrefix(kv, "GITHEAD_"), "="); sha != "" {
			return sha, nil
		}
	}

	gitDir, err := gitOutput(worktreeRoot, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", err
	}

	// A rebase is replaying a commit; while the drivers run it is the last line of
	// `done` ("pick <sha> # subject"). stopped-sha only appears once it stops.
	if sha := rebasePickedCommit(gitDir); sha != "" {
		return sha, nil
	}

	for _, ref := range []string{"CHERRY_PICK_HEAD", "REVERT_HEAD", "MERGE_HEAD", "refs/stash"} {
		if sha, err := gitOutput(worktreeRoot, "rev-parse", "-q", "--verify", ref); err == nil && sha != "" {
			return sha, nil
		}
	}

	// Last resort, and the only one that needs no ref and no env: find the commit
	// carrying the very blob git handed us.
	if sha := commitContaining(worktreeRoot, theirPath); sha != "" {
		return sha, nil
	}

	return "", errors.New("cannot tell which branch is being merged in")
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
			return fields[1] // "<command> <sha> # subject"
		}
	}

	return ""
}

// extractSesamDir unpacks the .sesam directory of `rev` into destDir. A worktree
// would be the obvious way, but `git worktree add` fires post-checkout, which
// would have sesam clean and reveal into the temporary tree.
func extractSesamDir(ctx context.Context, sesamDir, rev, destDir string) error {
	worktreeRoot, err := repo.GitWorktreeRoot(sesamDir)
	if err != nil {
		return err
	}

	prefix, err := filepath.Rel(worktreeRoot, sesamDir)
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

// untar writes the archive below destDir, dropping `strip` from every path so a
// nested sesam dir lands at the root of the extraction.
func untar(rd io.Reader, destDir, strip string) error {
	root, err := makeRoot(destDir)
	if err != nil {
		return err
	}

	defer func() { _ = root.Close() }()

	tr := tar.NewReader(rd)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		name := strings.TrimPrefix(filepath.ToSlash(hdr.Name), strip+"/")
		if name == "" || name == "." {
			// git archive emits an entry for the prefix directory itself.
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := root.MkdirAll(filepath.Dir(name), 0o700); err != nil {
				return err
			}

			fd, err := root.Create(name)
			if err != nil {
				return err
			}

			//nolint:gosec // archive comes from our own git repo.
			if _, err := io.Copy(fd, tr); err != nil {
				_ = fd.Close()
				return err
			}

			if err := fd.Close(); err != nil {
				return err
			}
		}
	}
}

func makeRoot(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	return os.OpenRoot(dir)
}

// commitContaining finds a commit that carries the blob in `file`. Picking the
// wrong one is safe: its audit log would not vouch for the object either, and
// the verification refuses.
func commitContaining(worktreeRoot, file string) string {
	blob, err := gitOutput(worktreeRoot, "hash-object", file)
	if err != nil {
		return ""
	}

	sha, err := gitOutput(worktreeRoot, "log", "--all", "--format=%H", "-n", "1", "--find-object="+blob)
	if err != nil {
		return ""
	}

	return sha
}
