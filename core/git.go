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
	prefix, err := SesamGitPrefix(repo, sesamDir)
	if err != nil {
		return "", err
	}

	initRel := path.Join(prefix, ".sesam", "audit", "init")

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
	wt, err := repo.Worktree()
	if err != nil {
		return "", fmt.Errorf("failed to open worktree: %w", err)
	}

	status, err := wt.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get worktree status: %w", err)
	}

	if fs, ok := status[initRel]; ok && (fs.Worktree != git.Unmodified || fs.Staging != git.Unmodified) {
		return "", fmt.Errorf(".sesam/audit/init has uncommitted changes")
	}

	return commitHash, nil
}
