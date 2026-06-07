package config

import (
	"path/filepath"
	"testing"

	"github.com/test-go/testify/require"
)

// buildConfig writes a main sesam.yml, touches every given file and adds them
// via AddSecrets, then saves. It returns the main file path.
func buildConfig(t *testing.T, ownSesamFile bool, files ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	main := writeMainFile(t, dir)

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	for _, f := range files {
		p := filepath.Join(dir, f)
		touch(t, p)
		require.NoError(t, cr.AddSecrets(p, ownSesamFile, []string{"group1"}))
	}
	require.NoError(t, cr.Save())

	return dir, main
}

// TestRemoveSecrets_FileFromMain removes a single secret stored in the main
// file; the rest stay and the plaintext file remains (no purge).
func TestRemoveSecrets_FileFromMain(t *testing.T) {
	dir, main := buildConfig(t, false, "token.txt")

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.RemoveSecrets(filepath.Join(dir, "token.txt"), false))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt"}, resolvedPaths(t, main))
	require.True(t, exists(filepath.Join(dir, "token.txt")), "plaintext kept without purge")
}

// TestRemoveSecrets_FileFromSubfile removes the only secret in a subdirectory
// file: the sub sesam.yml is deleted and its include dropped from main.
func TestRemoveSecrets_FileFromSubfile(t *testing.T) {
	dir, main := buildConfig(t, true, "sub/api.key")

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.RemoveSecrets(filepath.Join(dir, "sub", "api.key"), false))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "empty sub file removed")
	require.True(t, exists(filepath.Join(dir, "sub", "api.key")), "plaintext kept without purge")
}

// TestRemoveSecrets_SubfileKeepsSecret removes one of several secrets in a
// subdirectory file; the file (and its include) survive.
func TestRemoveSecrets_SubfileKeepsSecret(t *testing.T) {
	dir, main := buildConfig(t, true, "sub/b.txt", "sub/c.txt")

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.RemoveSecrets(filepath.Join(dir, "sub", "b.txt"), false))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"c.txt", "existing.txt"}, resolvedPaths(t, main))
	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "non-empty sub file kept")
}

// TestRemoveSecrets_Directory removes a whole subtree, cascading the deletion
// of nested sesam.yml files up to (but not including) the main file.
func TestRemoveSecrets_Directory(t *testing.T) {
	dir, main := buildConfig(t, true, "a.txt", "sub/b.txt", "sub/deep/c.txt")

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.True(t, exists(filepath.Join(dir, "sub", "deep", "sesam.yml")))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.RemoveSecrets(filepath.Join(dir, "sub"), false))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"a.txt", "existing.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.False(t, exists(filepath.Join(dir, "sub", "deep", "sesam.yml")))
}

// TestRemoveSecrets_Purge deletes the plaintext file when purge is set.
func TestRemoveSecrets_Purge(t *testing.T) {
	dir, main := buildConfig(t, false, "token.txt")

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.RemoveSecrets(filepath.Join(dir, "token.txt"), true))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "token.txt")), "plaintext purged")
}

// TestRemoveSecrets_NotFound errors when nothing matches the path.
func TestRemoveSecrets_NotFound(t *testing.T) {
	dir, main := buildConfig(t, false)
	touch(t, filepath.Join(dir, "stray.txt"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.Error(t, cr.RemoveSecrets(filepath.Join(dir, "stray.txt"), false))
}

// TestRemoveSecrets_MissingPath surfaces a stat error for a non-existent path.
func TestRemoveSecrets_MissingPath(t *testing.T) {
	dir, main := buildConfig(t, false)

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.Error(t, cr.RemoveSecrets(filepath.Join(dir, "nope.txt"), false))
}
