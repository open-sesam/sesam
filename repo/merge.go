package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path"
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

	// A cancelled or signal-killed process is a hard error, not a merge result -
	// don't let its -1 exit fall through and read as a "binary" refusal.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, 0, fmt.Errorf("git merge-file: %w", ctxErr)
	}
	ps := cmd.ProcessState
	if ps == nil || !ps.Exited() {
		return nil, 0, fmt.Errorf("git merge-file did not exit normally: %w: %s", err, strings.TrimSpace(errBuf.String()))
	}

	// git merge-file exits 0 (clean) or a small conflict count (git caps it below
	// 128). Anything else on the valid temp files we pass is its "Cannot merge
	// binary files" refusal - defer to git's own decision.
	switch code := ps.ExitCode(); {
	case code == 0:
		return bytes.NewReader(buf.Bytes()), 0, nil
	case code > 0 && code < 128:
		return bytes.NewReader(buf.Bytes()), code, nil
	default:
		return nil, 0, fmt.Errorf("%w: git merge-file exit %d: %s", errBinaryMerge, code, strings.TrimSpace(errBuf.String()))
	}
}

// ClearTmp empties the scratch space.
func ClearTmp(root *os.Root) error {
	entries, err := fs.ReadDir(root.FS(), core.SesamTmpDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	for _, entry := range entries {
		if err := root.RemoveAll(path.Join(core.SesamTmpDir(), entry.Name())); err != nil {
			return err
		}
	}

	return nil
}

// errBinaryMerge marks git merge-file refusing to line-merge (binary content).
var errBinaryMerge = errors.New("cannot line-merge (binary content)")

// decryptBaseToBuf decrypts the merge base (%O), tolerating an empty file: for an
// add/add of the same path there is no common ancestor, so git hands us a 0-byte base.
func decryptBaseToBuf(path string, ids []age.Identity) (*bytes.Buffer, error) {
	if info, err := os.Stat(path); err == nil && info.Size() == 0 {
		return &bytes.Buffer{}, nil
	}

	buf, _, err := decryptSecretToBuf(path, ids)
	return buf, err
}

// decryptSecretToBuf also returns the footer's recipients hash, which is how the
// caller notices that the two sides were sealed for different people.
func decryptSecretToBuf(path string, ids []age.Identity) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer

	// we're opening git paths here, so regular ShowSecret won't work.
	//nolint:gosec // git hands us the O/A/B blob temp paths to read.
	fd, err := os.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", path, err)
	}

	defer func() { _ = fd.Close() }()

	_, _, footer, err := core.RevealStream(fd, &buf, ids)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt %s: %w", path, err)
	}

	return &buf, footer.RecipientsHash, nil
}

// TheirStateFunc yields the verified state of the branch being merged in. The
// driver asks for it the first time it has to check an incoming object; how it
// is obtained (and cached) is the caller's business.
type TheirStateFunc func() (*core.VerifiedState, error)

// decryptTheirSecret decrypts the incoming side and checks it against the state
// of the branch it comes from. Without that check an object nobody was allowed
// to seal would be merged in and resealed under the merging user's key.
func decryptTheirSecret(ids core.Identities, revealedPath, theirPath string, theirState TheirStateFunc) (*bytes.Buffer, string, error) {
	state, err := theirState()
	if err != nil {
		// The provider's errors already name the branch and what went wrong.
		return nil, "", err
	}

	kr, err := core.KeyringFromState(state)
	if err != nil {
		return nil, "", fmt.Errorf("keyring of the incoming branch: %w", err)
	}

	//nolint:gosec // git hands us the B blob temp path to read.
	fd, err := os.Open(theirPath)
	if err != nil {
		return nil, "", fmt.Errorf("open %s: %w", theirPath, err)
	}

	defer func() { _ = fd.Close() }()

	var buf bytes.Buffer
	footer, err := core.RevealStreamAndVerify(
		fd,
		&buf,
		ids.AgeIdentities(),
		kr,
		state.SealerAuthorized,
		revealedPath,
	)
	if err != nil {
		return nil, "", fmt.Errorf("verify their %s: %w", revealedPath, err)
	}

	return &buf, footer.RecipientsHash, nil
}

func writeSecretTmpBuf(root *os.Root, buf *bytes.Buffer, revealedPath, tag string) (string, error) {
	tmpPath := fmt.Sprintf(
		core.SesamTmpDir()+"/%s.%s",
		strings.ReplaceAll(revealedPath, "/", "_"),
		tag,
	)

	if err := root.MkdirAll(filepath.Dir(tmpPath), 0o700); err != nil {
		return "", fmt.Errorf("create tmp dir for %s: %w", tmpPath, err)
	}

	fd, err := renameio.NewPendingFile(
		tmpPath,
		renameio.WithRoot(root),
		renameio.WithTempDir(core.SesamTmpDir()),
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

// MergeSealOutcome says what became of %A on a conflict-free merge.
type MergeSealOutcome int

const (
	// MergeSealSkipped: not attempted, e.g. because the merge conflicted.
	MergeSealSkipped MergeSealOutcome = iota

	// MergeSealDone: %A holds the merged content; we were able to write it back.
	MergeSealDone

	// MergeSealDeferred: left to the finalize on purpose, which knows more than
	// this driver invocation does.
	MergeSealDeferred

	// MergeSealFailed: we wanted to seal and could not.
	MergeSealFailed
)

func (mso MergeSealOutcome) String() string {
	switch mso {
	case MergeSealSkipped:
		return "skipped"
	case MergeSealDone:
		return "sealed"
	case MergeSealDeferred:
		return "defer"
	case MergeSealFailed:
		return "failed"
	default:
		return ""
	}
}

// MergeSecretResult reports what the secret driver did with one object.
type MergeSecretResult struct {
	// Conflicts left in the revealed file.
	Conflicts int

	// Binary content: git refused to line-merge, both sides were written out
	// beside the revealed file.
	Binary bool

	// Seal is what happened to %A.
	Seal MergeSealOutcome
}

// MergeSecret three-way merges one secret's decrypted content into its revealed
// file. A clean merge is also sealed back into %A: a rebase or cherry-pick
// finishes without ever calling a sesam hook, so nothing else would.
func MergeSecret(ctx context.Context, root *os.Root, ids core.Identities, revealedPath, ourPath, theirPath, originPath string, conflictMarkerSize int, theirState TheirStateFunc) (res MergeSecretResult, err error) {
	lock, err := TryAcquireMergeLock(root.Name())
	if err != nil {
		return res, err
	}
	defer func() { _ = lock.Unlock() }()

	ageIds := ids.AgeIdentities()

	// Decrypt all three sides up front; the plaintext feeds the text merge and, on
	// a binary refusal, the .ours/.theirs side files.
	originBuf, err := decryptBaseToBuf(originPath, ageIds)
	if err != nil {
		return res, fmt.Errorf("decrypt origin side of %s: %w", revealedPath, err)
	}
	ourBuf, ourRecps, err := decryptSecretToBuf(ourPath, ageIds)
	if err != nil {
		return res, fmt.Errorf("decrypt ours side of %s: %w", revealedPath, err)
	}
	theirBuf, theirRecps, err := decryptTheirSecret(ids, revealedPath, theirPath, theirState)
	if err != nil {
		return res, err
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
		return res, err
	}

	ourRel, ourAbs, err := stageBuf("ours", ourBuf)
	if err != nil {
		return res, err
	}

	theirRel, theirAbs, err := stageBuf("theirs", theirBuf)
	if err != nil {
		return res, err
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
			return res, err
		}
		if err := writeRevealedFile(root, revealedPath+".theirs", theirBytes); err != nil {
			return res, err
		}
		if err := writeRevealedFile(root, revealedPath, ourBytes); err != nil {
			return res, err
		}

		res.Binary = true
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("merge %s: %w", revealedPath, err)
	}

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, mergedReader); err != nil {
		return res, fmt.Errorf("read merged %s: %w", revealedPath, err)
	}
	if err := writeRevealedFile(root, revealedPath, buf.Bytes()); err != nil {
		return res, err
	}

	res.Conflicts = conflicts
	if conflicts > 0 {
		// Needs a human first, so %A keeps ours until someone reseals.
		return res, nil
	}

	if ourRecps != theirRecps {
		// Access changed on one side, so ours' log is not a safe source for who to
		// encrypt to. Leave %A to the finalize, which has the merged log.
		res.Seal = MergeSealDeferred
		return res, nil
	}

	if err := sealMergedSecret(root, ids, revealedPath, ourPath, buf.Bytes()); err != nil {
		slog.Warn("merge: could not seal merged secret into %A", slog.String("path", revealedPath), slog.Any("err", err))
		res.Seal = MergeSealFailed
		return res, nil
	}

	res.Seal = MergeSealDone
	return res, nil
}

// sealMergedSecret seals `data` to destPath, which is git's %A temp file and thus
// outside the sesam root. The audit log is the worktree's, i.e. still ours - the
// driver runs once per conflicting secret, each in its own process, so there is
// nothing to cache it in.
func sealMergedSecret(root *os.Root, ids core.Identities, revealedPath, destPath string, data []byte) error {
	auditLog, err := core.LoadAuditLog(root, ids)
	if err != nil {
		return fmt.Errorf("load audit log: %w", err)
	}

	defer func() { _ = auditLog.Close() }()

	kr := core.EmptyKeyring()
	state, err := core.VerifyChain(auditLog, kr, nil)
	if err != nil {
		return fmt.Errorf("verify audit log: %w", err)
	}

	recps := kr.Recipients(state.UsersForSecret(revealedPath))
	if len(recps) == 0 {
		return fmt.Errorf("no recipients known for %s", revealedPath)
	}

	signer, err := signerFor(root, ids, kr)
	if err != nil {
		return err
	}

	//nolint:gosec // git hands us the %A blob temp path to write.
	fd, err := os.OpenFile(destPath, os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", destPath, err)
	}

	defer func() { _ = fd.Close() }()

	if _, err := core.SealStream(
		bytes.NewReader(data),
		fd,
		revealedPath,
		recps,
		ids.AgeIdentities(),
		signer,
		signer.UserName(),
	); err != nil {
		return fmt.Errorf("seal %s: %w", revealedPath, err)
	}

	return fd.Close()
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
		renameio.WithTempDir(core.SesamTmpDir()),
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

	return signerFor(root, ids, kr)
}

// signerFor picks the identity that maps to a known user and loads its sign key.
func signerFor(root *os.Root, ids core.Identities, kr core.Keyring) (core.Signer, error) {
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
