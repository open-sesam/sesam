package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestChangeSecretGroups_ReplacesAccess rewrites the access list of an existing
// secret in place, leaving the entry's other content alone.
func TestChangeSecretGroups_ReplacesAccess(t *testing.T) {
	dir, main := buildConfig(t, false, "token.txt")

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.ChangeSecretGroups(filepath.Join(dir, "token.txt"), []string{"dev", "ops"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"dev", "ops"}, accessFor(t, main, "token.txt"))
}

// TestChangeSecretGroups_AddsAccessKeyWhenAbsent covers the branch where the
// secret has no access: key yet — it is created rather than replaced.
func TestChangeSecretGroups_AddsAccessKeyWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte("secrets:\n  - path: token.txt\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "token.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.ChangeSecretGroups(filepath.Join(dir, "token.txt"), []string{"dev"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"dev"}, accessFor(t, main, "token.txt"))
}

// TestChangeSecretGroups_PreservesComment keeps the entry's head comment when
// only its access list is rewritten.
func TestChangeSecretGroups_PreservesComment(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # keep me
  - path: token.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "token.txt"), []byte("x"), 0o644))

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.ChangeSecretGroups(filepath.Join(dir, "token.txt"), []string{"group2"}))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	require.Contains(t, string(out), "# keep me", "comment was dropped on change:\n%s", out)
	require.Equal(t, []string{"group2"}, accessFor(t, main, "token.txt"))
}

// TestChangeSecretGroups_NotFound errors when no secret matches the path.
func TestChangeSecretGroups_NotFound(t *testing.T) {
	dir, main := buildConfig(t, false)

	cr, err := Load(main)
	require.NoError(t, err)
	require.Error(t, cr.ChangeSecretGroups(filepath.Join(dir, "nope.txt"), []string{"dev"}))
}
