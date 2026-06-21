package config

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
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
	cr, err := Load(mainPath)
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)

	var paths []string
	for _, s := range secrets {
		paths = append(paths, s.Path)
	}
	sort.Strings(paths)
	return paths
}

// accessFor reloads mainPath and returns the access groups recorded for the
// secret whose Path equals secretPath.
func accessFor(t *testing.T, mainPath, secretPath string) []string {
	t.Helper()
	cr, err := Load(mainPath)
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)

	for _, s := range secrets {
		if s.Path == secretPath {
			return s.Access
		}
	}
	t.Fatalf("secret %q not found", secretPath)
	return nil
}

// TestAddSecret_FileAtMainLevel: a file next to the main sesam.yml is added to
// the main file with its bare name, and no extra sesam.yml is created.
func TestAddSecret_FileAtMainLevel(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := Load(mainPath)
	require.NoError(t, err)

	require.NoError(t, cr.AddSecret(filepath.Join(dir, "token.txt"), true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, mainPath))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
}

// TestAddSecret_FileInSubdirNested: a file in a subdirectory with nested=true
// gets its own sub/sesam.yml (included from main) and the secret path is
// relative to that sub file.
func TestAddSecret_FileInSubdirNested(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := Load(mainPath)
	require.NoError(t, err)

	require.NoError(t, cr.AddSecret(filepath.Join(dir, "sub", "api.key"), true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	// Path is "api.key" (relative to sub/sesam.yml), not "sub/api.key".
	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, mainPath))
}

// TestAddSecret_FileInSubdirFlat: a file in a subdirectory with nested=false is
// added straight to the main file, keeping its subdirectory prefix, and no
// sub/sesam.yml is created.
func TestAddSecret_FileInSubdirFlat(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := Load(mainPath)
	require.NoError(t, err)

	require.NoError(t, cr.AddSecret(filepath.Join(dir, "sub", "api.key"), false, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, mainPath))
}

// TestAddSecret_ReaddChangesAccess: re-adding an already-tracked file is a
// self-deciding upsert — it rewrites the access groups in place rather than
// duplicating the entry.
func TestAddSecret_ReaddChangesAccess(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := Load(mainPath)
	require.NoError(t, err)
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "token.txt"), false, []string{"group1"}))
	require.NoError(t, cr.Save())

	cr2, err := Load(mainPath)
	require.NoError(t, err)
	require.NoError(t, cr2.AddSecret(filepath.Join(dir, "token.txt"), false, []string{"group2"}))
	require.NoError(t, cr2.Save())

	// No duplicate entry, and the access list reflects the latest add.
	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, mainPath))
	require.Equal(t, []string{"group2"}, accessFor(t, mainPath, "token.txt"))
}

// TestAddSecret_MissingPath surfaces a stat error for a non-existent path only
// when the caller resolves it; AddSecret itself does not stat, so adding a path
// that is not yet on disk is allowed (the repo validates existence).
func TestAddSecret_NonExistentPathStillAdded(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)

	cr, err := Load(mainPath)
	require.NoError(t, err)
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "later.txt"), false, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "later.txt"}, resolvedPaths(t, mainPath))
}

// TestAddSecret_NoDuplicateSameFileTwice: adding the same file into the same
// file twice keeps a single entry (the second add upserts its access groups).
func TestAddSecret_NoDuplicateSameFileTwice(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := Load(main)
	require.NoError(t, err)

	require.NoError(t, cr.AddSecret(filepath.Join(dir, "token.txt"), false, []string{"group1"}))
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "token.txt"), false, []string{"group2"}))

	require.NoError(t, cr.Save())
	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, main))
	require.Equal(t, []string{"group2"}, accessFor(t, main, "token.txt"))
}

// TestAddSecret_NoDuplicateSubThenMain: a file already declared in a sub
// sesam.yml is not re-added to the main file when the same physical file is
// added again with a flat layout — it stays in the sub-file (upsert there).
func TestAddSecret_NoDuplicateSubThenMain(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := Load(main)
	require.NoError(t, err)

	// Lands in sub/sesam.yml, included from main.
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "sub", "api.key"), true, []string{"group1"}))
	// Re-add the same physical file flat into main: must not duplicate.
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "sub", "api.key"), false, []string{"group1"}))

	require.NoError(t, cr.Save())
	// Present exactly once across the merged view.
	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, main))
}

// TestAddSecret_NoDuplicateMainThenSub: the reverse direction — a file already
// declared in the main file is not re-added into its own sub sesam.yml, and no
// empty sub-file or dangling include is produced.
func TestAddSecret_NoDuplicateMainThenSub(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := Load(main)
	require.NoError(t, err)

	require.NoError(t, cr.AddSecret(filepath.Join(dir, "sub", "api.key"), false, []string{"group1"}))
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "sub", "api.key"), true, []string{"group1"}))

	require.NoError(t, cr.Save())
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "no empty sub-file created")
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, main))
}

// TestAddSecret_PreservesExistingComments verifies that inserting a new secret
// node leaves the comments on the pre-existing entries untouched — the new node
// is appended, nothing above it shifts.
func TestAddSecret_PreservesExistingComments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # comment-for-alpha
  - path: alpha.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "beta.txt"), false, []string{"group1"}))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)

	require.Contains(t, string(out), "comment-for-alpha", "existing comment was lost on add:\n%s", out)
	require.Contains(t, string(out), "beta.txt", "added secret missing:\n%s", out)
}

// TestAddSecret_PreservesCommentsAndIndentation checks that altering the config
// leaves the existing entry byte-for-byte intact (comment + exact indentation)
// and appends the new entry with the same block-sequence indentation.
func TestAddSecret_PreservesCommentsAndIndentation(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # keep me
  - path: alpha.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.AddSecret(filepath.Join(dir, "beta.txt"), false, []string{"group2"}))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	got := string(out)

	// The original entry — comment and its exact indentation — is untouched.
	require.Contains(t, got, "  # keep me\n  - path: alpha.txt\n    access:\n      - group1\n",
		"existing comment/indentation was altered:\n%s", got)
	// The appended entry matches the same indentation style.
	require.Contains(t, got, "  - path: beta.txt\n    access:\n      - group2\n",
		"added entry has unexpected indentation:\n%s", got)
}
