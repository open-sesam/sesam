package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyInitFileUnchangedNoCommitsTouchingInit(t *testing.T) {
	repoDir, repo := testGitRepo(t)

	// Create a dummy file and commit so HEAD exists, but don't touch init.
	writeSecret(t, repoDir, "dummy.txt", "hi")
	gitCommitAll(t, repo, "initial")

	// Write init file but don't commit it.
	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0600))

	require.NoError(t, verifyInitFileUnchanged(repoDir))
}

func TestVerifyInitFileUnchangedOneCommit(t *testing.T) {
	repoDir, repo := testGitRepo(t)

	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0600))
	gitCommitAll(t, repo, "init commit")

	require.NoError(t, verifyInitFileUnchanged(repoDir))
}

func TestVerifyInitFileUnchangedMultipleCommits(t *testing.T) {
	repoDir, repo := testGitRepo(t)

	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("hash1"), 0600))
	gitCommitAll(t, repo, "first commit")

	// Modify the init file and commit again — should be detected.
	require.NoError(t, os.WriteFile(initPath, []byte("hash2"), 0600))
	gitCommitAll(t, repo, "tampered commit")

	err := verifyInitFileUnchanged(repoDir)
	require.Error(t, err, "should detect init file modification")
}

func TestVerifyInitFileUnchangedMultipleCommitsUnchanged(t *testing.T) {
	repoDir, repo := testGitRepo(t)

	initPath := filepath.Join(repoDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0600))
	gitCommitAll(t, repo, "first commit")

	// Commit other changes but don't touch init.
	writeSecret(t, repoDir, "other.txt", "data")
	gitCommitAll(t, repo, "second commit")

	require.NoError(t, verifyInitFileUnchanged(repoDir), "init was not changed across commits")
}

func TestVerifyInitFileUnchangedNotAGitRepo(t *testing.T) {
	repoDir := testRepo(t) // no git init

	err := verifyInitFileUnchanged(repoDir)
	require.Error(t, err, "should fail for non-git directory")
}
