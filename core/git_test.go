package core

import (
	"os"
	"path/filepath"
	"testing"

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

	require.NoError(t, verifyInitFileUnchanged(sesamDir))
}

func TestVerifyInitFileUnchangedOneCommit(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0o600))
	gitCommitAll(t, repo, "init commit")

	require.NoError(t, verifyInitFileUnchanged(sesamDir))
}

func TestVerifyInitFileUnchangedMultipleCommits(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("hash1"), 0o600))
	gitCommitAll(t, repo, "first commit")

	// Modify the init file and commit again - should be detected.
	require.NoError(t, os.WriteFile(initPath, []byte("hash2"), 0o600))
	gitCommitAll(t, repo, "tampered commit")

	err := verifyInitFileUnchanged(sesamDir)
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

	require.NoError(t, verifyInitFileUnchanged(sesamDir), "init was not changed across commits")
}

func TestVerifyInitFileUnchangedNotAGitRepo(t *testing.T) {
	sesamDir := testRepo(t) // no git init

	err := verifyInitFileUnchanged(sesamDir)
	require.Error(t, err, "should fail for non-git directory")
}

func TestVerifyInitFileUnchangedNoCommitsAtAll(t *testing.T) {
	sesamDir, _ := testGitRepo(t)
	// Zero commits - repo.Log() returns ErrReferenceNotFound, treated as "fine during init".
	require.NoError(t, verifyInitFileUnchanged(sesamDir))
}
