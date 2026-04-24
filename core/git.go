package core

import (
	"fmt"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// VerifyInitFileUnchanged checks via git that .sesam/audit/init was never
// modified after its initial commit. It inspects both the committed history
// and the current working tree / index.
//
// Returns nil if the file was committed exactly once and has no pending changes.
// Returns an error describing the problem otherwise.
// If repoDir is not a git repo a warning-level error is returned
// (caller decides whether to treat it as fatal).
func verifyInitFileUnchanged(repoDir string) error {
	repo, err := git.PlainOpenWithOptions(repoDir, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return fmt.Errorf("not a git repository (skipping init-file history check): %w", err)
	}

	// .sesam/ lives in repoDir, but .git/ may be in a parent directory.
	// Git paths are relative to the worktree root, so compute accordingly.
	wt, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to open worktree: %w", err)
	}

	// Keep this absolute so filepath.Rel() below behaves consistently when
	// repoDir was passed as a relative path (for example ".").
	absRepoDir, err := filepath.Abs(repoDir)
	if err != nil {
		return fmt.Errorf("failed to resolve repoDir: %w", err)
	}

	initAbs := filepath.Join(absRepoDir, ".sesam", "audit", "init")
	initRel, err := filepath.Rel(wt.Filesystem.Root(), initAbs)
	if err != nil {
		return fmt.Errorf("failed to compute relative path: %w", err)
	}

	// Count how many commits touched the init file.
	logIter, err := repo.Log(&git.LogOptions{
		PathFilter: func(path string) bool {
			return path == initRel
		},
	})
	if err != nil {
		return fmt.Errorf("git log failed: %w", err)
	}

	var commitCount int
	err = logIter.ForEach(func(c *object.Commit) error {
		commitCount++
		if commitCount > 1 {
			// No need to keep counting.
			return fmt.Errorf("stop")
		}
		return nil
	})

	// ForEach returns our sentinel error when we stop early.
	if err != nil && commitCount <= 1 {
		return fmt.Errorf("iterating git log: %w", err)
	}

	if commitCount == 0 {
		// File exists on disk but was never committed.
		// Fine during `sesam init` before the first commit.
		return nil
	}

	if commitCount > 1 {
		return fmt.Errorf(
			".sesam/audit/init was modified: expected 1 commit, found at least %d",
			commitCount,
		)
	}

	// Exactly 1 commit. Check for uncommitted changes (staged or unstaged).
	status, err := wt.Status()
	if err != nil {
		return fmt.Errorf("failed to get worktree status: %w", err)
	}

	if fs, ok := status[initRel]; ok && fs.Worktree != git.Unmodified && fs.Staging != git.Unmodified {
		return fmt.Errorf(".sesam/audit/init has uncommitted changes")
	}

	return nil
}
