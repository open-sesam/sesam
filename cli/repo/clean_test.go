package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

// initSesamRepo creates a temp dir with `.sesam/` and a fresh git repo, then
// stages and commits the given files (path → content). Returns the absolute
// sesamRoot and the open repo.
func initSesamRepo(t *testing.T, tracked map[string]string) (string, *git.Repository) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, ".sesam"), 0o700))

	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	for rel, content := range tracked {
		full := filepath.Join(root, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
		_, err := wt.Add(rel)
		require.NoError(t, err)
	}

	return root, repo
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	require.True(t, os.IsNotExist(err), "stat %s: %v", path, err)
	return false
}

func TestCleanupRemovesUntrackedFiles(t *testing.T) {
	root, repo := initSesamRepo(t, map[string]string{
		"sesam.yml":      "config\n",
		".gitattributes": "attrs\n",
	})

	stale := filepath.Join(root, "stale-secret")
	writeFile(t, stale, "leaked plaintext")

	require.NoError(t, Cleanup(repo, root))

	require.False(t, exists(t, stale), "untracked file should have been removed")
	require.True(t, exists(t, filepath.Join(root, "sesam.yml")), "tracked file should be preserved")
	require.True(t, exists(t, filepath.Join(root, ".gitattributes")), "tracked file should be preserved")
}

func TestCleanupPreservesModifiedTrackedFiles(t *testing.T) {
	root, repo := initSesamRepo(t, map[string]string{
		"sesam.yml": "original\n",
	})

	tracked := filepath.Join(root, "sesam.yml")
	writeFile(t, tracked, "modified by user")

	require.NoError(t, Cleanup(repo, root))

	require.True(t, exists(t, tracked), "modified tracked file should survive")
	got, err := os.ReadFile(tracked)
	require.NoError(t, err)
	require.Equal(t, "modified by user", string(got), "user modification should not be reverted")
}

func TestCleanupSkipsSesamAndGitDirs(t *testing.T) {
	root, repo := initSesamRepo(t, nil)

	sesamScratch := filepath.Join(root, ".sesam", "tmp", "leftover")
	writeFile(t, sesamScratch, "internal")

	gitScratch := filepath.Join(root, ".git", "untracked-by-design")
	writeFile(t, gitScratch, "git internal")

	require.NoError(t, Cleanup(repo, root))

	require.True(t, exists(t, sesamScratch), ".sesam contents must not be touched")
	require.True(t, exists(t, gitScratch), ".git contents must not be touched")
}

func TestCleanupRemovesUntrackedInSubdir(t *testing.T) {
	root, repo := initSesamRepo(t, map[string]string{
		"keep/sesam.yml": "config\n",
	})

	stale := filepath.Join(root, "keep", "stale.txt")
	writeFile(t, stale, "junk")

	require.NoError(t, Cleanup(repo, root))

	require.False(t, exists(t, stale), "untracked file in subdir should be removed")
	require.True(t, exists(t, filepath.Join(root, "keep", "sesam.yml")), "tracked sibling should survive")
}

func TestCleanupErrorsOnMissingSesamDir(t *testing.T) {
	root := t.TempDir()
	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)

	err = Cleanup(repo, root)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a sesam directory")
}
