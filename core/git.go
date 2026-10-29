package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // git's object format, not a security primitive here.
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Git runs the git binary for the worktree that contains a sesam dir.
type Git struct {
	// root is the worktree root, spelled like the directory it was opened from
	// so sesam paths can be relativized against it.
	root string

	// newHash matches the repository's object format.
	newHash func() hash.Hash
}

// GitObjects reads objects through one long-running `git cat-file
// --batch-command`, for loops that would otherwise start git per object.
// Not safe for concurrent use.
type GitObjects struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
}

// GitCommit is a commit hash and its parents' hashes.
type GitCommit struct {
	Hash    string
	Parents []string
}

// OpenGit finds the git worktree that contains dir.
func OpenGit(dir string) (*Git, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	out, err := runGit(abs, "rev-parse", "--show-object-format", "--show-toplevel", "--show-prefix")
	if err != nil {
		return nil, err
	}

	// --show-prefix prints an empty line at the worktree root.
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != 3 {
		return nil, fmt.Errorf("unexpected git rev-parse output %q", out)
	}

	g := &Git{root: lines[1]}
	switch lines[0] {
	case "sha1":
		g.newHash = sha1.New
	case "sha256":
		g.newHash = sha256.New
	default:
		return nil, fmt.Errorf("unsupported git object format %q", lines[0])
	}

	// git prints the root with symlinks resolved. Keep the caller's spelling when
	// it names the same directory, or paths relativized against it would break.
	candidate := abs
	for range strings.Count(lines[2], "/") {
		candidate = filepath.Dir(candidate)
	}
	if sameDir(candidate, g.root) {
		g.root = candidate
	}

	return g, nil
}

func sameDir(a, b string) bool {
	aInfo, err := os.Stat(a)
	if err != nil {
		return false
	}

	bInfo, err := os.Stat(b)
	if err != nil {
		return false
	}

	return os.SameFile(aInfo, bInfo)
}

// runGit runs git in dir and returns its stdout. stderr ends up in the error.
func runGit(dir string, args ...string) ([]byte, error) {
	//nolint:gosec // fixed git subcommands; args come from sesam itself.
	cmd := exec.CommandContext(context.Background(), "git", args...)
	cmd.Dir = dir

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}

	return out, nil
}

// gitExitCode is the exit code of a git command that ran and failed, or -1.
func gitExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// Root returns the absolute path of the worktree root.
func (g *Git) Root() string {
	return g.root
}

// Output runs git in the worktree root and returns its stdout.
func (g *Git) Output(args ...string) ([]byte, error) {
	return runGit(g.root, args...)
}

// BlobHash returns the object id git gives a blob with this content.
func (g *Git) BlobHash(data []byte) string {
	h := g.newHash()
	_, _ = fmt.Fprintf(h, "blob %d\x00", len(data))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// Head returns the commit HEAD points to, or "" on an unborn branch.
func (g *Git) Head() (string, error) {
	out, err := g.Output("rev-parse", "-q", "--verify", "HEAD^{commit}")
	if gitExitCode(err) == 1 {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

// ResolveCommit returns the commit rev names.
func (g *Git) ResolveCommit(rev string) (string, error) {
	out, err := g.Output("rev-parse", "--verify", "--end-of-options", rev+"^{commit}")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

// IsAncestor reports whether commit a is an ancestor of (or equal to) b.
func (g *Git) IsAncestor(a, b string) (bool, error) {
	_, err := g.Output("merge-base", "--is-ancestor", a, b)
	switch gitExitCode(err) {
	case -1:
		return err == nil, err
	case 1:
		return false, nil
	default:
		return false, err
	}
}

// TrackedFiles returns the worktree-relative paths in git's index under dir,
// a worktree-relative directory ("." for all of them).
func (g *Git) TrackedFiles(dir string) ([]string, error) {
	out, err := g.Output("--literal-pathspecs", "ls-files", "-z", "--", dir)
	if err != nil {
		return nil, err
	}

	return splitNUL(out), nil
}

// UnmergedFiles returns the worktree-relative paths git lists as conflicted.
func (g *Git) UnmergedFiles() ([]string, error) {
	out, err := g.Output("ls-files", "-u", "-z")
	if err != nil {
		return nil, err
	}

	// Each entry is "<mode> <object> <stage>\t<path>", one per stage.
	var paths []string
	for _, e := range splitNUL(out) {
		if _, p, ok := strings.Cut(e, "\t"); ok {
			paths = append(paths, p)
		}
	}

	return paths, nil
}

func splitNUL(out []byte) []string {
	var parts []string
	for p := range strings.SplitSeq(string(out), "\x00") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// Objects starts a reader for git objects. The caller must Close it.
func (g *Git) Objects() (*GitObjects, error) {
	cmd := exec.CommandContext(context.Background(), "git", "cat-file", "--batch-command")
	cmd.Dir = g.root
	cmd.Stderr = os.Stderr

	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}

	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start git cat-file: %w", err)
	}

	return &GitObjects{cmd: cmd, in: in, out: bufio.NewReader(out)}, nil
}

// Close stops the reader's git process.
func (o *GitObjects) Close() error {
	_ = o.in.Close()
	return o.cmd.Wait()
}

// request sends one batch command and parses the header of its answer. ok is
// false when rev names no object.
func (o *GitObjects) request(command, rev string) (oid, typ string, size int, ok bool, err error) {
	if strings.ContainsAny(rev, "\n") {
		return "", "", 0, false, fmt.Errorf("git object name %q contains a newline", rev)
	}

	if _, err := fmt.Fprintf(o.in, "%s %s\n", command, rev); err != nil {
		return "", "", 0, false, fmt.Errorf("write to git cat-file: %w", err)
	}

	line, err := o.out.ReadString('\n')
	if err != nil {
		return "", "", 0, false, fmt.Errorf("read from git cat-file: %w", err)
	}
	line = strings.TrimSuffix(line, "\n")

	if line == rev+" missing" || line == rev+" ambiguous" {
		return "", "", 0, false, nil
	}

	fields := strings.Fields(line)
	if len(fields) != 3 {
		return "", "", 0, false, fmt.Errorf("unexpected git cat-file header %q", line)
	}

	size, err = strconv.Atoi(fields[2])
	if err != nil {
		return "", "", 0, false, fmt.Errorf("unexpected git cat-file header %q", line)
	}

	return fields[0], fields[1], size, true, nil
}

// contents reads the object rev names; ok is false when there is none.
func (o *GitObjects) contents(rev string) (oid, typ string, data []byte, ok bool, err error) {
	oid, typ, size, ok, err := o.request("contents", rev)
	if !ok || err != nil {
		return "", "", nil, ok, err
	}

	// The content is followed by a newline.
	data = make([]byte, size+1)
	if _, err := io.ReadFull(o.out, data); err != nil {
		return "", "", nil, false, fmt.Errorf("read object %s: %w", oid, err)
	}

	return oid, typ, data[:size], true, nil
}

// Blob returns the id of the blob rev names, e.g. "<commit>:<path>". ok is
// false when rev names no blob.
func (o *GitObjects) Blob(rev string) (string, bool, error) {
	oid, typ, _, ok, err := o.request("info", rev)
	return oid, ok && typ == "blob", err
}

// ReadBlob returns the content of the blob rev names. ok is false when rev
// names no blob.
func (o *GitObjects) ReadBlob(rev string) ([]byte, bool, error) {
	_, typ, data, ok, err := o.contents(rev)
	return data, ok && typ == "blob", err
}

// Commit reads the commit rev names. ok is false when rev names no commit.
func (o *GitObjects) Commit(rev string) (*GitCommit, bool, error) {
	oid, typ, data, ok, err := o.contents(rev)
	if !ok || err != nil || typ != "commit" {
		return nil, false, err
	}

	c := &GitCommit{Hash: oid}
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			break // end of the header
		}

		if parent, ok := strings.CutPrefix(line, "parent "); ok {
			c.Parents = append(c.Parents, parent)
		}
	}

	return c, true, nil
}

// SesamGitPrefix returns sesamDir as a forward-slash path relative to the git
// worktree root. .sesam/ lives in sesamDir, but .git/ may be in an ancestor
// directory, and git addresses index/tree paths relative to the worktree root
// using forward slashes. sesamDir must be absolute.
func SesamGitPrefix(g *Git, sesamDir string) (string, error) {
	rel, err := filepath.Rel(g.root, sesamDir)
	if err != nil {
		return "", fmt.Errorf("failed to relativize sesam dir against worktree root: %w", err)
	}

	return filepath.ToSlash(rel), nil
}

// verifyInitFileUnchanged checks via git that .sesam/audit/init keeps the same
// content throughout history: it is written once at `sesam init` and must never
// change. It inspects both the committed history and the working tree / index.
//
// The check keys on the init blob, not the number of commits: merges and
// rebases can leave the file touched by several commits with identical content,
// which is harmless. Only more than one distinct content across history is
// tampering.
//
// Returns the anchor (earliest) commit hash and nil when the content is
// constant and there are no pending changes; "" and an error otherwise. If
// sesamDir is not a git repo a warning-level error is returned (caller decides
// whether to treat it as fatal).
func verifyInitFileUnchanged(sesamDir string) (string, error) {
	g, err := OpenGit(sesamDir)
	if err != nil {
		return "", fmt.Errorf("not a git repository (skipping init-file history check): %w", err)
	}

	return verifyInitFileUnchangedWithRepo(sesamDir, g)
}

func verifyInitFileUnchangedWithRepo(sesamDir string, g *Git) (string, error) {
	prefix, err := SesamGitPrefix(g, sesamDir)
	if err != nil {
		return "", err
	}

	initRel := path.Join(prefix, ".sesam", "audit", "init")

	head, err := g.Head()
	if err != nil {
		return "", err
	}
	if head == "" {
		// No commits yet (fine during sesam init before the first commit).
		return "", nil
	}

	// Walk the full history and look the init blob up by path per commit. A
	// path-limited log would simplify history and hide which commits carry it.
	revs, err := g.Output("rev-list", "--parents", head)
	if err != nil {
		return "", err
	}

	objs, err := g.Objects()
	if err != nil {
		return "", err
	}
	defer func() { _ = objs.Close() }()

	// Collect the distinct init blobs across the commits that carry the file.
	// Commits from before init existed (or on the far side of a rename) simply
	// lack the file at this path and are skipped.
	blobs := make(map[string]struct{})
	carriers := make(map[string][]string) // commit -> its parents
	var order []string
	var wantBlob string
	for line := range strings.Lines(string(revs)) {
		hashes := strings.Fields(line)
		blob, ok, err := objs.Blob(hashes[0] + ":" + initRel)
		if err != nil {
			return "", err
		}

		if ok {
			blobs[blob] = struct{}{}
			wantBlob = blob
			carriers[hashes[0]] = hashes[1:]
			order = append(order, hashes[0])
		}
	}

	// The anchor is the commit that introduced the file: none of its parents
	// carry it. Log order alone does not say which one that is - past a merge,
	// the last commit visited may well sit on a branch that forked after init.
	var introducers []string
	for _, h := range order {
		if !slices.ContainsFunc(carriers[h], func(p string) bool { _, ok := carriers[p]; return ok }) {
			introducers = append(introducers, h)
		}
	}

	anchorHash, err := pickInitAnchor(g, objs, head, introducers)
	if err != nil {
		return "", err
	}

	switch len(blobs) {
	case 0:
		// File was never committed (or never present at this path).
		// Fine during `sesam init` before the first commit.
		return "", nil
	case 1:
		// A single content wherever it appears: unchanged.
	default:
		return "", fmt.Errorf(
			".sesam/audit/init was modified: found %d distinct contents in history",
			len(blobs),
		)
	}

	// The on-disk anchor must match the committed content. Compare that one
	// file's blob hash directly rather than walking the whole worktree.
	initAbs := filepath.Join(sesamDir, ".sesam", "audit", "init")
	onDisk, err := ReadFileLimited(initAbs, 256)
	if err != nil {
		return "", fmt.Errorf("reading .sesam/audit/init: %w", err)
	}

	if g.BlobHash(onDisk) != wantBlob {
		return "", fmt.Errorf(".sesam/audit/init on disk differs from its committed content")
	}

	return anchorHash, nil
}

// pickInitAnchor picks the trust anchor among the commits that introduced init.
// Several are fine only side by side: a squash- or rebase-merge of the branch
// that introduced sesam commits the same init on a parallel line. One
// descending from another means init was deleted and put back, which would move
// the anchor and let an older log start a fresh, shorter history.
func pickInitAnchor(g *Git, objs *GitObjects, head string, introducers []string) (string, error) {
	switch len(introducers) {
	case 0:
		return "", nil
	case 1:
		return introducers[0], nil
	}

	for _, a := range introducers {
		for _, b := range introducers {
			if a == b {
				continue
			}

			if ok, err := g.IsAncestor(a, b); err != nil {
				return "", fmt.Errorf("check ancestry of %s: %w", a, err)
			} else if ok {
				return "", fmt.Errorf(
					".sesam/audit/init was removed and re-added in history (introduced by %s, again by %s)",
					a, b,
				)
			}
		}
	}

	// Prefer the one on HEAD's first-parent chain: that is the line the history
	// walk follows, and where it stops.
	for h := head; ; {
		if slices.Contains(introducers, h) {
			return h, nil
		}

		c, ok, err := objs.Commit(h)
		if err != nil {
			return "", fmt.Errorf("read commit %s: %w", h, err)
		}
		if !ok {
			return "", fmt.Errorf("read commit %s: not a commit", h)
		}
		if len(c.Parents) == 0 {
			break
		}
		h = c.Parents[0]
	}

	// HEAD's mainline got its vault from a merge; the walk crosses over there.
	return introducers[0], nil
}
