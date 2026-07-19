package core

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// SesamGitPrefix returns sesamDir as a forward-slash path relative to the git
// worktree root. .sesam/ lives in sesamDir, but .git/ may be in an ancestor
// directory, and go-git addresses index/tree/status paths relative to the
// worktree root using forward slashes. sesamDir must be absolute.
func SesamGitPrefix(repo *git.Repository, sesamDir string) (string, error) {
	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to open worktree: %w", err)
	}

	rel, err := filepath.Rel(wt.Filesystem.Root(), sesamDir)
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
	repo, err := git.PlainOpenWithOptions(sesamDir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return "", fmt.Errorf("not a git repository (skipping init-file history check): %w", err)
	}

	return verifyInitFileUnchangedWithRepo(sesamDir, repo)
}

func verifyInitFileUnchangedWithRepo(sesamDir string, repo *git.Repository) (string, error) {
	prefix, err := SesamGitPrefix(repo, sesamDir)
	if err != nil {
		return "", err
	}

	initRel := path.Join(prefix, ".sesam", "audit", "init")

	// Walk the full history and look the init blob up by path per commit. A
	// go-git PathFilter would tree-diff every commit against its parents, which
	// is ~20x slower than a direct lookup on repos with deep history.
	logIter, err := repo.Log(&git.LogOptions{})
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			// No commits yet (fine during sesam init before the first commit).
			return "", nil
		}
		return "", fmt.Errorf("git log failed: %w", err)
	}

	// Collect the distinct init blobs across the commits that carry the file, and
	// remember the earliest such commit as the trust anchor. Commits from before
	// init existed (or on the far side of a rename) simply lack the file at this
	// path and are skipped.
	blobs := make(map[plumbing.Hash]struct{})
	var wantBlob plumbing.Hash
	var anchorHash string
	err = logIter.ForEach(func(c *object.Commit) error {
		f, ferr := c.File(initRel)
		if ferr == nil {
			blobs[f.Hash] = struct{}{}
			wantBlob = f.Hash
			anchorHash = c.Hash.String()
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("iterating git log: %w", err)
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
	// file's blob hash directly rather than walking the whole worktree with
	// Status(), which is O(worktree) and pathologically slow in large repos.
	initAbs := filepath.Join(sesamDir, ".sesam", "audit", "init")
	onDisk, err := ReadFileLimited(initAbs, 256)
	if err != nil {
		return "", fmt.Errorf("reading .sesam/audit/init: %w", err)
	}

	if plumbing.ComputeHash(plumbing.BlobObject, onDisk) != wantBlob {
		return "", fmt.Errorf(".sesam/audit/init on disk differs from its committed content")
	}

	return anchorHash, nil
}
