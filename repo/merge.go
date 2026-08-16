package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/age"
	"github.com/sahib/renameio/v2"
	"opensesam.org/sesam/core"
)

// runGitMerge line-merges the three decrypted sides via `git merge-file`.
// The three file arguments must be absolute paths!
func runGitMerge(ctx context.Context, revealedPath, ourPath, theirPath, originPath string, conflictMarkerSize int) (io.Reader, int, error) {
	//nolint:gosec // fixed git subcommand; the path args are sesam-controlled tmp files.
	cmd := exec.CommandContext(
		ctx,
		"git",
		"merge-file",
		"--stdout",
		"--marker-size", strconv.Itoa(conflictMarkerSize),
		"-L", "ours/"+revealedPath,
		"-L", "origin/"+revealedPath,
		"-L", "theirs/"+revealedPath,
		ourPath,
		originPath,
		theirPath,
	)

	var buf, errBuf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &errBuf

	err := cmd.Run()

	exitErr := new(exec.ExitError)
	if err != nil && !errors.As(err, &exitErr) {
		// we failed to start the command, must be some general error.
		return nil, 0, fmt.Errorf("run git merge-file: %w", err)
	}

	// exits with 0 (no conflicts), <0 (error) or 1-128 (number of conflicts)
	// or >128 (some other error, most likely due to an unmergeable binary file)
	switch code := cmd.ProcessState.ExitCode(); {
	case code == 0:
		return bytes.NewReader(buf.Bytes()), 0, nil
	case code > 0 && code < 128:
		return bytes.NewReader(buf.Bytes()), code, nil
	default:
		return nil, 0, fmt.Errorf("%w: git merge-file exit %d: %s", errBinaryMerge, code, strings.TrimSpace(errBuf.String()))
	}
}

// errBinaryMerge marks git merge-file refusing to line-merge (binary content).
var errBinaryMerge = errors.New("cannot line-merge (binary content)")

func decryptSecretToBuf(path string, ids []age.Identity) (*bytes.Buffer, error) {
	var buf bytes.Buffer

	// we're opening git paths here, so regular ShowSecret won't work.
	//nolint:gosec // git hands us the O/A/B blob temp paths to read.
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	defer func() { _ = fd.Close() }()

	if _, _, _, err := core.RevealStream(fd, &buf, ids); err != nil {
		return nil, fmt.Errorf("decrypt %s: %w", path, err)
	}

	return &buf, nil
}

func writeSecretTmpBuf(root *os.Root, buf *bytes.Buffer, revealedPath, tag string) (string, error) {
	tmpPath := fmt.Sprintf(
		".sesam/tmp/%s.%s",
		strings.ReplaceAll(revealedPath, "/", "_"),
		tag,
	)

	if err := root.MkdirAll(filepath.Dir(tmpPath), 0o700); err != nil {
		return "", fmt.Errorf("create tmp dir for %s: %w", tmpPath, err)
	}

	fd, err := renameio.NewPendingFile(
		tmpPath,
		renameio.WithRoot(root),
		renameio.WithTempDir(".sesam/tmp"),
		renameio.WithPermissions(0o600),
	)
	if err != nil {
		return "", fmt.Errorf("create pending file %s: %w", tmpPath, err)
	}

	if _, err := io.Copy(fd, buf); err != nil {
		_ = fd.Cleanup()
		return "", fmt.Errorf("write tmp file %s: %w", tmpPath, err)
	}

	if err := fd.CloseAtomicallyReplace(); err != nil {
		return "", fmt.Errorf("finalize tmp file %s: %w", tmpPath, err)
	}

	return tmpPath, nil
}

// MergeSecret three-way merges one secret's decrypted content into its revealed
// file. It returns the number of text conflicts; `binary` is true when the secret
// is binary and could not be line-merged (both sides were written out beside the
// revealed file for manual resolution).
func MergeSecret(ctx context.Context, root *os.Root, ids core.Identities, revealedPath, ourPath, theirPath, originPath string, conflictMarkerSize int) (conflicts int, binary bool, err error) {
	lock, err := TryAcquireMergeLock(root.Name())
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = lock.Unlock() }()

	ageIds := ids.AgeIdentities()

	// Decrypt all three sides up front; the plaintext feeds the text merge and, on
	// a binary refusal, the .ours/.theirs side files.
	originBuf, err := decryptSecretToBuf(originPath, ageIds)
	if err != nil {
		return 0, false, fmt.Errorf("decrypt origin side of %s: %w", revealedPath, err)
	}
	ourBuf, err := decryptSecretToBuf(ourPath, ageIds)
	if err != nil {
		return 0, false, fmt.Errorf("decrypt ours side of %s: %w", revealedPath, err)
	}
	theirBuf, err := decryptSecretToBuf(theirPath, ageIds)
	if err != nil {
		return 0, false, fmt.Errorf("decrypt theirs side of %s: %w", revealedPath, err)
	}

	// Snapshot the two sides before staging drains their buffers - needed for the
	// .ours/.theirs side files if the content turns out to be binary.
	ourBytes := bytes.Clone(ourBuf.Bytes())
	theirBytes := bytes.Clone(theirBuf.Bytes())

	// stageBuf writes a decrypted side to a tmp file under .sesam/tmp and returns
	// its sesam-relative path (for cleanup) and absolute path (git merge-file runs
	// from the worktree root and needs a resolvable path).
	stageBuf := func(tag string, buf *bytes.Buffer) (relPath, absPath string, err error) {
		rel, err := writeSecretTmpBuf(root, buf, revealedPath, tag)
		if err != nil {
			return "", "", fmt.Errorf("stage %s side of %s: %w", tag, revealedPath, err)
		}
		return rel, filepath.Join(root.Name(), rel), nil
	}

	originRel, originAbs, err := stageBuf("origin", originBuf)
	if err != nil {
		return 0, false, err
	}

	ourRel, ourAbs, err := stageBuf("ours", ourBuf)
	if err != nil {
		return 0, false, err
	}

	theirRel, theirAbs, err := stageBuf("theirs", theirBuf)
	if err != nil {
		return 0, false, err
	}

	// The decrypted sides are only needed for the merge itself; drop the
	// plaintext copies afterwards, whatever the outcome.
	defer func() {
		_ = root.Remove(originRel)
		_ = root.Remove(ourRel)
		_ = root.Remove(theirRel)
	}()

	mergedReader, conflicts, err := runGitMerge(
		ctx,
		revealedPath,
		ourAbs,
		theirAbs,
		originAbs,
		conflictMarkerSize,
	)
	if errors.Is(err, errBinaryMerge) {
		// git itself refuses to line-merge binary content. Keep ours as the revealed
		// value and write both decrypted sides beside it for manual resolution.
		if err := writeRevealedFile(root, revealedPath+".ours", ourBytes); err != nil {
			return 0, false, err
		}
		if err := writeRevealedFile(root, revealedPath+".theirs", theirBytes); err != nil {
			return 0, false, err
		}
		if err := writeRevealedFile(root, revealedPath, ourBytes); err != nil {
			return 0, false, err
		}
		return 0, true, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("merge %s: %w", revealedPath, err)
	}

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, mergedReader); err != nil {
		return 0, false, fmt.Errorf("read merged %s: %w", revealedPath, err)
	}
	if err := writeRevealedFile(root, revealedPath, buf.Bytes()); err != nil {
		return 0, false, err
	}

	return conflicts, false, nil
}

// writeRevealedFile atomically writes data to a revealed (root-relative) path.
func writeRevealedFile(root *os.Root, relPath string, data []byte) error {
	if dir := filepath.Dir(relPath); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir for %s: %w", relPath, err)
		}
	}

	fd, err := renameio.NewPendingFile(
		relPath,
		renameio.WithRoot(root),
		renameio.WithTempDir(".sesam/tmp"),
		renameio.WithPermissions(0o600),
	)
	if err != nil {
		return fmt.Errorf("create pending file %s: %w", relPath, err)
	}

	if _, err := fd.Write(data); err != nil {
		_ = fd.Cleanup()
		return fmt.Errorf("write %s: %w", relPath, err)
	}

	if err := fd.CloseAtomicallyReplace(); err != nil {
		return fmt.Errorf("finalize %s: %w", relPath, err)
	}

	return nil
}

// resolveMergeSigner finds which of the caller's identities is the merging user
// and loads its signing key so AuditMerge can re-sign the rebased entries. The
// user is derived by replaying ours' log into a keyring; the sign key is read
// from the live .sesam (checked out during the merge).
func resolveMergeSigner(root *os.Root, ids core.Identities, ourLog *core.AuditLog) (core.Signer, error) {
	// VerifyChain needs a non-empty InitHash, which LoadAuditLogFromPath does not
	// set. The driver trusts the git-provided blob; seed it from the first entry
	// (AuditMerge re-checks M1 across all three logs afterwards).
	if len(ourLog.Entries) > 0 {
		ourLog.InitHash = ourLog.Entries[0].Hash()
	}

	kr := core.EmptyKeyring()
	if _, err := core.VerifyChain(ourLog, kr, nil); err != nil {
		return nil, fmt.Errorf("verify ours for merger resolution: %w", err)
	}

	users := kr.ListUsers()
	for _, id := range ids {
		user, err := core.IdentityToUser(id, users)
		if err != nil {
			continue
		}

		return core.LoadSignKey(root, user, id.Identity)
	}

	return nil, fmt.Errorf("none of the supplied identities maps to a known user; cannot merge")
}

// InMerge reports whether a merge is in progress (MERGE_HEAD exists). The
// pre-commit hook uses it to run the merge reconciliation only when finalizing a
// merge, not on ordinary commits.
func InMerge(sesamDir string) bool {
	worktreeRoot, err := GitWorktreeRoot(sesamDir)
	if err != nil {
		return false
	}

	cmd := exec.CommandContext(context.Background(), "git", "rev-parse", "-q", "--verify", "MERGE_HEAD")
	cmd.Dir = worktreeRoot
	return cmd.Run() == nil // exit 0 => MERGE_HEAD present
}

// MergeTouchedSesam reports whether an in-progress merge changed anything under
// the sesam dir (staged index vs HEAD).
func MergeTouchedSesam(sesamDir string) (bool, error) {
	worktreeRoot, err := GitWorktreeRoot(sesamDir)
	if err != nil {
		return false, fmt.Errorf("locate worktree root: %w", err)
	}

	absSesam, err := filepath.Abs(sesamDir)
	if err != nil {
		return false, err
	}

	prefix, err := filepath.Rel(worktreeRoot, absSesam)
	if err != nil {
		return false, err
	}

	// `git diff --cached --quiet` exits 0 for no change, 1 for a change.
	//nolint:gosec // fixed git subcommand; pathspec is derived from the repo layout.
	cmd := exec.CommandContext(
		context.Background(),
		"git",
		"diff",
		"--cached",
		"--quiet",
		"HEAD",
		"--",
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

func MergeAuditLog(ctx context.Context, root *os.Root, ids core.Identities, ourPath, theirPath, originPath string, conflictMarkerSize int) (*core.ConflictResolution, error) {
	lock, err := TryAcquireMergeLock(root.Name())
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Unlock() }()

	ourAuditLog, err := core.LoadAuditLogFromPath(ourPath, ids)
	if err != nil {
		return nil, err
	}

	defer func() { _ = ourAuditLog.Close() }()

	theirAuditLog, err := core.LoadAuditLogFromPath(theirPath, ids)
	if err != nil {
		return nil, err
	}

	defer func() { _ = theirAuditLog.Close() }()

	originAuditLog, err := core.LoadAuditLogFromPath(originPath, ids)
	if err != nil {
		return nil, err
	}

	defer func() { _ = originAuditLog.Close() }()

	// The merging admin re-signs the rebased entries, so we need their signing
	// key: resolve which identity is us against ours' state, then load its key.
	signer, err := resolveMergeSigner(root, ids, ourAuditLog)
	if err != nil {
		return nil, err
	}

	mergedAuditLog, cr, err := core.AuditMerge(
		ourAuditLog,
		theirAuditLog,
		originAuditLog,
		signer,
		nil, // no interactive plugin UI inside the merge driver (no TTY)
	)
	if err != nil {
		return nil, err
	}

	// verify the log is correct before writing it back.
	kr := core.EmptyKeyring()
	if _, err := core.VerifyChain(mergedAuditLog, kr, nil); err != nil {
		return nil, fmt.Errorf("verify merged audit log: %w", err)
	}

	var mergedBuf bytes.Buffer
	if err := mergedAuditLog.WriteEncrypted(&mergedBuf, core.AllRecipients(kr)); err != nil {
		return nil, fmt.Errorf("serialize merged audit log: %w", err)
	}

	// TODO: We'd also need to adjust sesam.yml accordingly, otherwise we'd have a diff.
	//       `sesam config reset` basically needs to be set once that feature has been build.

	// merge driver should write back to %A (i.e. ourPath)
	if err := renameio.WriteFile(ourPath, mergedBuf.Bytes(), 0o600); err != nil {
		return nil, err
	}

	return cr, nil
}
