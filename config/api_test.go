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
	const body = "secrets:\n  - type: password\n    name: existing\n    path: existing.txt\n"
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

// resolvedPaths reloads mainPath from disk and returns the sorted, merged
// secret paths plus the set of files that physically exist.
func resolvedPaths(t *testing.T, mainPath string) []string {
	t.Helper()
	cr := NewConfigRepository()
	require.NoError(t, cr.Load(mainPath))
	require.NoError(t, cr.Resolve())

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
	require.NoError(t, cr.Resolve())
	require.NoError(t, cr.AddSecrets(filepath.Join(dir, "token.txt"), true))
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
	require.NoError(t, cr.Resolve())
	require.NoError(t, cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), true))
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
	require.NoError(t, cr.Resolve())
	require.NoError(t, cr.AddSecrets(filepath.Join(dir, "sub", "api.key"), false))
	require.NoError(t, cr.Save())

	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, main))
}

// TestAddSecrets_Directory: passing a directory nests every subdirectory under
// its own sesam.yml regardless of the flag, while top-level files land in the
// main file. Re-running is idempotent.
func TestAddSecrets_Directory(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "a.txt"))
	touch(t, filepath.Join(dir, "sub", "b.txt"))
	touch(t, filepath.Join(dir, "sub", "deep", "c.txt"))

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.Resolve())
	// ownSesamFile is ignored for directories.
	require.NoError(t, cr.AddSecrets(dir, false))
	require.NoError(t, cr.Save())

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.True(t, exists(filepath.Join(dir, "sub", "deep", "sesam.yml")))

	want := []string{"a.txt", "b.txt", "c.txt", "existing.txt"}
	require.Equal(t, want, resolvedPaths(t, main))

	// Idempotent: a second run over the same tree adds nothing.
	cr2 := NewConfigRepository()
	require.NoError(t, cr2.Load(main))
	require.NoError(t, cr2.Resolve())
	require.NoError(t, cr2.AddSecrets(dir, false))
	require.NoError(t, cr2.Save())
	require.Equal(t, want, resolvedPaths(t, main))
}

// TestAddSecrets_MissingPath surfaces a stat error for a non-existent path.
func TestAddSecrets_MissingPath(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)

	cr := NewConfigRepository()
	require.NoError(t, cr.Load(main))
	require.NoError(t, cr.Resolve())
	require.Error(t, cr.AddSecrets(filepath.Join(dir, "nope.txt"), true))
}
