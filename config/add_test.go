package config

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/test-go/testify/require"
)

// writeMainFile writes a minimal main sesam.yml (one existing secret) into dir
// and returns its path.
func writeMainFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sesam.yml")
	const body = "secrets:\n  - path: existing.txt\n    access:\n      - group1\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func touch(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// resolvedPaths reloads mainPath from disk (Load resolves includes) and returns
// the sorted, merged secret paths.
func resolvedPaths(t *testing.T, mainPath string) []string {
	t.Helper()
	cr := NewConfigRepository()
	require.NoError(t, cr.Load(mainPath))

	var paths []string
	for _, s := range cr.MainFile.Config.Secrets {
		paths = append(paths, s.Path)
	}
	sort.Strings(paths)
	return paths
}

// TestAddSecrets_FileAtMainLevel: a file next to the main sesam.yml is added
// to the main file with its bare name, and no extra sesam.yml is created.
func TestAddSecrets_FileAtMainLevel(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.AddSecrets(filepath.Join(dir, "token.txt"), true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
}

// TestAddSecrets_FileInSubdirOwnFile: a file in a subdirectory with
// ownSesamFile=true gets its own sub/sesam.yml (included from main) and the
// secret path is relative to that sub file.
func TestAddSecrets_FileInSubdirOwnFile(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	// Path is "api.key" (relative to sub/sesam.yml), not "sub/api.key".
	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, main))
}

// TestAddSecrets_FileInSubdirMainFile: a file in a subdirectory with
// ownSesamFile=false is added straight to the main file, keeping its
// subdirectory prefix, and no sub/sesam.yml is created.
func TestAddSecrets_FileInSubdirMainFile(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), false, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, main))
}

// TestAddSecrets_DirectoryFlatten: passing a directory with ownSesamFile=false
// flattens every file in the directory and all subdirectories into the main
// file, keeping subdirectory prefixes and creating no per-directory sesam.yml.
// Re-running is idempotent.
func TestAddSecrets_DirectoryFlatten(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "a.txt"))
	touch(t, filepath.Join(dir, "sub", "b.txt"))
	touch(t, filepath.Join(dir, "sub", "deep", "c.txt"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.AddSecrets(dir, false, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.False(t, exists(filepath.Join(dir, "sub", "deep", "sesam.yml")))

	want := []string{"a.txt", "existing.txt", "sub/b.txt", "sub/deep/c.txt"}
	require.Equal(t, want, resolvedPaths(t, main))

	// Idempotent: a second run over the same tree adds nothing.
	cr2 := NewConfigRepository()
	require.NoError(t, cr2.Load(main))
	require.NoError(t, cr2.AddSecrets(dir, false, []string{"group1"}))
	require.NoError(t, cr2.Save())
	require.Equal(t, want, resolvedPaths(t, main))
}

// TestAddSecrets_DirectoryOwnFile: passing a directory with ownSesamFile=true
// gives every subdirectory its own sesam.yml (chained via includes) while
// top-level files land in the main file.
func TestAddSecrets_DirectoryOwnFile(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "a.txt"))
	touch(t, filepath.Join(dir, "sub", "b.txt"))
	touch(t, filepath.Join(dir, "sub", "deep", "c.txt"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.AddSecrets(dir, true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.True(t, exists(filepath.Join(dir, "sub", "deep", "sesam.yml")))

	// Paths are relative to each owning sesam.yml.
	want := []string{"a.txt", "b.txt", "c.txt", "existing.txt"}
	require.Equal(t, want, resolvedPaths(t, main))
}

// TestAddSecrets_MissingPath surfaces a stat error for a non-existent path.
func TestAddSecrets_MissingPath(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.Error(t, cr.AddSecrets(filepath.Join(dir, "nope.txt"), true, []string{"group1"}))
}
