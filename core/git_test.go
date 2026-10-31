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

// Deleting init and putting the same bytes back moves the anchor to the
// re-adding commit, so an older log would pass as a fresh history.
func TestVerifyInitFileUnchangedRemovedAndReadded(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	gitCommitAll(t, repo, "init")

	gitRemove(t, sesamDir, ".sesam/audit/init")
	writeSecret(t, sesamDir, "other.txt", "data")
	gitCommitAll(t, repo, "drop init")

	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	gitCommitAll(t, repo, "restore init")

	_, err := verifyInitFileUnchanged(sesamDir)
	require.ErrorContains(t, err, "removed and re-added")
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
// shows up under `git log --full-history`, but is not a modification. This is
// the rebase artifact seen in the wild.
func TestVerifyInitFileUnchangedMergeSameContent(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")

	// Base commit without init.
	writeSecret(t, sesamDir, "base.txt", "base")
	base := gitCommit(t, repo, "base")

	// Main line adds init.
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	mainLine := gitCommit(t, repo, "add init")

	// Side line off base, without init.
	gitRemove(t, sesamDir, filepath.Join(".sesam", "audit", "init"))
	writeSecret(t, sesamDir, "side.txt", "side")
	side := gitCommit(t, repo, "side change", base)

	// Merge that restores init with content identical to the main line.
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	gitCommit(t, repo, "chores: merge with main", mainLine, side)

	_, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err, "merge re-touching init with identical content is not a modification")
}

// The anchor is the commit that introduced init, not whichever carrier the log
// walk visits last: past a merge, that is a commit on the merged-in branch.
func TestVerifyInitFileUnchangedAnchorAcrossMerge(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	commit := func(msg string, parents ...string) string {
		writeSecret(t, sesamDir, "file.txt", msg)
		return gitCommit(t, repo, msg, parents...)
	}

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
	initCommit := commit("init")
	mainLine := commit("main", initCommit)
	side := commit("side", initCommit)
	commit("merge", mainLine, side)

	anchor, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err)
	require.Equal(t, initCommit, anchor)
}

// A squash-merged intro branch commits the same init on a parallel line. That is
// no re-add; the anchor is the introducer on HEAD's first-parent chain.
func TestVerifyInitFileUnchangedParallelIntroducers(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	commit := func(msg string, withInit bool, parents ...string) string {
		writeSecret(t, sesamDir, "file.txt", msg)
		if withInit {
			require.NoError(t, os.MkdirAll(filepath.Dir(initPath), 0o700))
			require.NoError(t, os.WriteFile(initPath, []byte("stable-hash"), 0o600))
		} else {
			require.NoError(t, os.RemoveAll(filepath.Dir(initPath)))
		}
		return gitCommit(t, repo, msg, parents...)
	}

	root := commit("root", false)
	intro := commit("intro", true, root)
	squashed := commit("squashed intro", true, root)
	commit("merge", true, intro, squashed)

	anchor, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err)
	require.Equal(t, intro, anchor)
}

func TestVerifyInitFileUnchangedNotAGitRepo(t *testing.T) {
	sesamDir := testRepo(t) // no git init

	_, err := verifyInitFileUnchanged(sesamDir)
	require.Error(t, err, "should fail for non-git directory")
}

func TestVerifyInitFileUnchangedNoCommitsAtAll(t *testing.T) {
	sesamDir, _ := testGitRepo(t)
	// Zero commits - an unborn HEAD is treated as "fine during init".
	_, err := verifyInitFileUnchanged(sesamDir)
	require.NoError(t, err)
}

func TestGitObjects(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	content := "has spaces\nand lines\n"
	writeSecret(t, sesamDir, "a dir/missing", content)
	first := gitCommit(t, repo, "first")
	writeSecret(t, sesamDir, "other", "x")
	second := gitCommit(t, repo, "second")

	objs, err := repo.Objects()
	require.NoError(t, err)
	defer func() { require.NoError(t, objs.Close()) }()

	// A path ending in " missing" must not be mistaken for git's "missing" reply.
	oid, ok, err := objs.Blob(second + ":a dir/missing")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, testGit(t, sesamDir, "hash-object", "a dir/missing"), oid)
	require.Equal(t, oid, repo.BlobHash([]byte(content)))

	data, ok, err := objs.ReadBlob(oid)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, content, string(data))

	for _, rev := range []string{second + ":nope", second + ":a dir", "0000000000000000000000000000000000000000"} {
		_, ok, err := objs.Blob(rev)
		require.NoError(t, err)
		require.False(t, ok, rev)
	}

	commit, ok, err := objs.Commit(second)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []string{first}, commit.Parents)

	_, ok, err = objs.Commit(oid)
	require.NoError(t, err)
	require.False(t, ok, "a blob is no commit")

	_, _, err = objs.Blob("a\nb")
	require.Error(t, err)
}
