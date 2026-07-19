package core

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

func TestVerifyInitFileUnchangedNoCommitsTouchingInit(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	// Create a dummy file and commit so HEAD exists, but don't touch init.
	writeSecret(t, sesamDir, "dummy.txt", "hi")
	gitCommitAll(t, repo, "initial")

	// Write init file but don't commit it.
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0o600))

	_, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err)
}

func TestVerifyInitFileUnchangedOneCommit(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0o600))
	gitCommitAll(t, repo, "init commit")

	_, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err)
}

func TestVerifyInitFileUnchangedMultipleCommits(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("hash1"), 0o600))
	gitCommitAll(t, repo, "first commit")

	// Modify the init file and commit again - should be detected.
	require.NoError(t, os.WriteFile(initPath, []byte("hash2"), 0o600))
	gitCommitAll(t, repo, "tampered commit")

	_, err := verifyInitFileUnchanged(sesamDir)
	require.Error(t, err, "should detect init file modification")
}

func TestVerifyInitFileUnchangedMultipleCommitsUnchanged(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	gitCommitAll(t, repo, "first commit")

	// Commit other changes but don't touch init.
	writeSecret(t, sesamDir, "other.txt", "data")
	gitCommitAll(t, repo, "second commit")

	_, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err, "init was not changed across commits")
}

// A merge that re-touches init with content identical to its main-line parent
// shows up under `git log --full-history` (which go-git's path filter mirrors),
// but is not a modification. This is the rebase artifact seen in the wild.
func TestVerifyInitFileUnchangedMergeSameContent(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	wt, err := repo.Worktree()
	require.NoError(t, err)

	sig := func() *object.Signature {
		return &object.Signature{Name: "Test", Email: "t@t.com", When: time.Now()}
	}
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")

	// Base commit without init.
	writeSecret(t, sesamDir, "base.txt", "base")
	_, err = wt.Add(".")
	require.NoError(t, err)
	base, err := wt.Commit("base", &git.CommitOptions{Author: sig()})
	require.NoError(t, err)

	// Main line adds init.
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	_, err = wt.Add(".")
	require.NoError(t, err)
	mainLine, err := wt.Commit("add init", &git.CommitOptions{Author: sig()})
	require.NoError(t, err)

	// Side line off base, without init.
	_, err = wt.Remove(filepath.Join(".sesam", "audit", "init"))
	require.NoError(t, err)
	writeSecret(t, sesamDir, "side.txt", "side")
	_, err = wt.Add(".")
	require.NoError(t, err)
	side, err := wt.Commit("side change", &git.CommitOptions{
		Author:  sig(),
		Parents: []plumbing.Hash{base},
	})
	require.NoError(t, err)

	// Merge that restores init with content identical to the main line.
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	_, err = wt.Add(".")
	require.NoError(t, err)
	_, err = wt.Commit("chores: merge with main", &git.CommitOptions{
		Author:  sig(),
		Parents: []plumbing.Hash{mainLine, side},
	})
	require.NoError(t, err)

	_, err = verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err, "merge re-touching init with identical content is not a modification")
}

func TestVerifyInitFileUnchangedNotAGitRepo(t *testing.T) {
	sesamDir := testRepo(t) // no git init

	_, err := verifyInitFileUnchanged(sesamDir)
	require.Error(t, err, "should fail for non-git directory")
}

func TestVerifyInitFileUnchangedNoCommitsAtAll(t *testing.T) {
	sesamDir, _ := testGitRepo(t)
	// Zero commits - repo.Log() returns ErrReferenceNotFound, treated as "fine during init".
	_, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err)
}
