package core

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// verifyInitFileUnchanged checks via git that .sesam/audit/init was never
// modified after its initial commit. It inspects both the committed history
// and the current working tree / index.
//
// Returns the commit hash, nil if the file was committed exactly once and has no pending changes.
// Returns "" and an error describing the problem otherwise.
// If sesamDir is not a git repo a warning-level error is returned
// (caller decides whether to treat it as fatal).
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
	// .sesam/ lives in sesamDir, but .git/ may be in a parent directory.
	// Git paths are relative to the worktree root, so compute accordingly.
	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to open worktree: %w", err)
	}

	// sesamDir is absolute (the resolved repo root), so this join stays
	// absolute and can be made relative to the worktree root below.
	initAbs := filepath.Join(sesamDir, ".sesam", "audit", "init")
	initRel, err := filepath.Rel(wt.Filesystem.Root(), initAbs)
	if err != nil {
		return "", fmt.Errorf("failed to compute relative path: %w", err)
	}

	// go-git always reports tree/status paths with forward slashes, even on
	// Windows where filepath.Rel returns backslashes. Normalize so the
	// PathFilter and status lookups below match.
	initRel = filepath.ToSlash(initRel)

	// Count how many commits touched the init file.
	logIter, err := repo.Log(&git.LogOptions{
		PathFilter: func(path string) bool {
			return path == initRel
		},
	})
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			// No commits yet - treat as commitCount==0 (fine during sesam init).
			return "", nil
		}
		return "", fmt.Errorf("git log failed: %w", err)
	}

	var commitHash string
	var commitCount int
	err = logIter.ForEach(func(c *object.Commit) error {
		commitCount++
		commitHash = c.Hash.String()
		if commitCount > 1 {
			// No need to keep counting.
			return fmt.Errorf("stop")
		}
		return nil
	})

	// ForEach returns our sentinel error when we stop early.
	if err != nil && commitCount <= 1 {
		return "", fmt.Errorf("iterating git log: %w", err)
	}

	if commitCount == 0 {
		// File exists on disk but was never committed.
		// Fine during `sesam init` before the first commit.
		return "", nil
	}

	if commitCount > 1 {
		return "", fmt.Errorf(
			".sesam/audit/init was modified: expected 1 commit, found at least %d",
			commitCount,
		)
	}

	// Exactly 1 commit. Check for uncommitted changes (staged or unstaged).
	status, err := wt.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree status: %w", err)
	}

	if fs, ok := status[initRel]; ok && (fs.Worktree != git.Unmodified || fs.Staging != git.Unmodified) {
		return "", fmt.Errorf(".sesam/audit/init has uncommitted changes")
	}

	return commitHash, nil
}
