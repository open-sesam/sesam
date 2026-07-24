package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

// openCleanRoot opens an os.Root over dir for the clean tests, closing it on
// cleanup.
func openCleanRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	rt, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rt.Close() })
	return rt
}

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

	require.NoError(t, cleanup(openCleanRoot(t, root), repo, nil))

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

	require.NoError(t, cleanup(openCleanRoot(t, root), repo, nil))

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

	require.NoError(t, cleanup(openCleanRoot(t, root), repo, nil))

	require.True(t, exists(t, sesamScratch), ".sesam contents must not be touched")
	require.True(t, exists(t, gitScratch), ".git contents must not be touched")
}

func TestCleanupRemovesUntrackedInSubdir(t *testing.T) {
	root, repo := initSesamRepo(t, map[string]string{
		"keep/sesam.yml": "config\n",
	})

	stale := filepath.Join(root, "keep", "stale.txt")
	writeFile(t, stale, "junk")

	require.NoError(t, cleanup(openCleanRoot(t, root), repo, nil))

	require.False(t, exists(t, stale), "untracked file in subdir should be removed")
	require.True(t, exists(t, filepath.Join(root, "keep", "sesam.yml")), "tracked sibling should survive")
}

// initNestedSesamRepo creates a git repo whose sesam dir lives in subdir (not at
// the worktree root), commits the given worktree-relative files, and returns the
// worktree root, the absolute sesam dir, and the open repo.
func initNestedSesamRepo(t *testing.T, subdir string, tracked map[string]string) (string, string, *git.Repository) {
	t.Helper()
	root := t.TempDir()
	sesamRoot := filepath.Join(root, subdir)
	require.NoError(t, os.MkdirAll(filepath.Join(sesamRoot, ".sesam"), 0o700))

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

	return root, sesamRoot, repo
}

// A nested sesam dir must not lose its tracked files: index entries are
// worktree-relative (sub/sesam.yml) while the walk is sesam-relative
// (sesam.yml), so cleanup must reconcile the prefix before deciding what is
// untracked.
func TestCleanupPreservesTrackedFilesInNestedSesamDir(t *testing.T) {
	_, sesamRoot, repo := initNestedSesamRepo(t, "sub", map[string]string{
		"sub/sesam.yml":      "config\n",
		"sub/.gitignore":     "*\n",
		"sub/.gitattributes": "attrs\n",
	})

	stale := filepath.Join(sesamRoot, "secret.txt")
	writeFile(t, stale, "leaked plaintext")

	require.NoError(t, cleanup(openCleanRoot(t, sesamRoot), repo, nil))

	require.False(t, exists(t, stale), "untracked plaintext should be removed")
	require.True(t, exists(t, filepath.Join(sesamRoot, "sesam.yml")), "tracked sesam.yml must survive")
	require.True(t, exists(t, filepath.Join(sesamRoot, ".gitignore")), "tracked .gitignore must survive")
	require.True(t, exists(t, filepath.Join(sesamRoot, ".gitattributes")), "tracked .gitattributes must survive")
}

func TestCleanupErrorsOnMissingSesamDir(t *testing.T) {
	root := t.TempDir()
	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)

	err = cleanup(openCleanRoot(t, root), repo, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not a sesam directory")
}
