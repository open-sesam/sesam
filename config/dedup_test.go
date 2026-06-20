package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAddSecrets_NoDuplicateSameFileTwice: adding the same file into the same
// file twice writes it once.
func TestAddSecrets_NoDuplicateSameFileTwice(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := Load(main)
	require.NoError(t, err)

	added, err := cr.AddSecrets(filepath.Join(dir, "token.txt"), false, []string{"group1"})
	require.NoError(t, err)
	require.Len(t, added, 1)

	added, err = cr.AddSecrets(filepath.Join(dir, "token.txt"), false, []string{"group1"})
	require.NoError(t, err)
	require.Empty(t, added, "second add of the same file must be a no-op")

	require.NoError(t, cr.Save())
	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, main))
}

// TestAddSecrets_NoDuplicateSubThenMain: a file already declared in a sub
// sesam.yml is not re-added to the main file when the same physical file is
// added again with a flat layout.
func TestAddSecrets_NoDuplicateSubThenMain(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := Load(main)
	require.NoError(t, err)

	// Lands in sub/sesam.yml, included from main.
	added, err := cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), true, []string{"group1"})
	require.NoError(t, err)
	require.Len(t, added, 1)

	// Re-add the same physical file flat into main: must be skipped.
	added, err = cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), false, []string{"group1"})
	require.NoError(t, err)
	require.Empty(t, added, "already tracked in sub/sesam.yml; must not be added to main")

	require.NoError(t, cr.Save())
	// Present exactly once across the merged view.
	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, main))
}

// TestAddSecrets_NoDuplicateMainThenSub: the reverse direction — a file already
// declared in the main file is not re-added into its own sub sesam.yml, and no
// empty sub-file or dangling include is produced.
func TestAddSecrets_NoDuplicateMainThenSub(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := Load(main)
	require.NoError(t, err)

	added, err := cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), false, []string{"group1"})
	require.NoError(t, err)
	require.Len(t, added, 1)

	added, err = cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), true, []string{"group1"})
	require.NoError(t, err)
	require.Empty(t, added, "already tracked in main; must not be added to a sub-file")

	require.NoError(t, cr.Save())
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "no empty sub-file created")
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, main))
}
