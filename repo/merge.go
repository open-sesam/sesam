package repo

import (
	"bytes"
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

// runGitMerge line-merges the three decrypted sides via `git merge-file`. The
// three file arguments must be absolute paths: git runs the merge driver from
// the worktree root, which for a nested sesam dir is not the sesam dir, so
// sesam-relative paths would not resolve. conflictStyle and diff algorithm are
// read by git merge-file from the inherited repo config; only the per-path
// marker size (git's %L) has to be forwarded explicitly.
func runGitMerge(revealedPath, ourPath, theirPath, originPath string, conflictMarkerSize int) (io.Reader, int, error) {
	cmd := exec.Command(
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

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	exitErr := new(exec.ExitError)
	if err != nil && !errors.As(err, &exitErr) {
		// we failed to start the command, must be some general error.
		return nil, 0, fmt.Errorf("run git merge-file: %w", err)
	}

	// exits with 0 (no conflicts), <0 (error) or >0 (number of conflicts)
	switch code := cmd.ProcessState.ExitCode(); {
	case code == 0:
		return bytes.NewReader(buf.Bytes()), 0, nil
	case code < 0:
		return nil, 0, fmt.Errorf("git merge-file failed: %w", err)
	case code > 0:
		return bytes.NewReader(buf.Bytes()), code, nil
	default:
		return nil, 0, fmt.Errorf("unreachable")
	}
}

func decryptSecretToBuf(path string, ids []age.Identity) (*bytes.Buffer, error) {
	var buf bytes.Buffer

	// we're opening git paths here, so regular ShowSecret won't work.
	fd, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	defer fd.Close()

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
		renameio.WithPermissions(0600),
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

func MergeSecret(root *os.Root, ids core.Identities, revealedPath, ourPath, theirPath, originPath string, conflictMarkerSize int) (int, error) {
	ageIds := ids.AgeIdentities()

	// stage decrypts one side to a tmp file under .sesam/tmp and returns both
	// its sesam-relative path (for root-relative cleanup) and its absolute path
	// (git merge-file runs from the worktree root and needs a resolvable path).
	stage := func(tag, blobPath string) (relPath, absPath string, err error) {
		buf, err := decryptSecretToBuf(blobPath, ageIds)
		if err != nil {
			return "", "", fmt.Errorf("decrypt %s side of %s: %w", tag, revealedPath, err)
		}

		rel, err := writeSecretTmpBuf(root, buf, revealedPath, tag)
		if err != nil {
			return "", "", fmt.Errorf("stage %s side of %s: %w", tag, revealedPath, err)
		}

		return rel, filepath.Join(root.Name(), rel), nil
	}

	originRel, originAbs, err := stage("origin", originPath)
	if err != nil {
		return 0, err
	}

	ourRel, ourAbs, err := stage("ours", ourPath)
	if err != nil {
		return 0, err
	}

	theirRel, theirAbs, err := stage("theirs", theirPath)
	if err != nil {
		return 0, err
	}

	// The decrypted sides are only needed for the merge itself; drop the
	// plaintext copies afterwards, whatever the outcome.
	defer func() {
		_ = root.Remove(originRel)
		_ = root.Remove(ourRel)
		_ = root.Remove(theirRel)
	}()

	mergedReader, conflicts, err := runGitMerge(
		revealedPath,
		ourAbs,
		theirAbs,
		originAbs,
		conflictMarkerSize,
	)
	if err != nil {
		return 0, fmt.Errorf("merge %s: %w", revealedPath, err)
	}

	fd, err := renameio.NewPendingFile(
		revealedPath,
		renameio.WithRoot(root),
		renameio.WithTempDir(".sesam/tmp"),
		renameio.WithPermissions(0600),
	)
	if err != nil {
		return 0, fmt.Errorf("create pending file %s: %w", revealedPath, err)
	}

	if _, err := io.Copy(fd, mergedReader); err != nil {
		_ = fd.Cleanup()
		return 0, fmt.Errorf("write merged %s: %w", revealedPath, err)
	}

	if err := fd.CloseAtomicallyReplace(); err != nil {
		return 0, fmt.Errorf("finalize merged %s: %w", revealedPath, err)
	}

	return conflicts, nil
}
