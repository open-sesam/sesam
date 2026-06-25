package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecretChangeGroups_ReplacesAccess rewrites the access list of an existing
// secret in place, leaving the entry's other content alone.
func TestSecretChangeGroups_ReplacesAccess(t *testing.T) {
	_, main := buildConfig(t, false, "token.txt")

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretChangeGroups("token.txt", []string{"dev", "ops"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"dev", "ops"}, accessFor(t, main, "token.txt"))
}

// TestSecretChangeGroups_AddsAccessKeyWhenAbsent covers the branch where the
// secret has no access: key yet — it is created rather than replaced.
func TestSecretChangeGroups_AddsAccessKeyWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte("secrets:\n  - path: token.txt\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "token.txt"), []byte("x"), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretChangeGroups("token.txt", []string{"dev"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"dev"}, accessFor(t, main, "token.txt"))
}

// TestSecretChangeGroups_PreservesComment keeps the entry's head comment when
// only its access list is rewritten.
func TestSecretChangeGroups_PreservesComment(t *testing.T) {
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

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretChangeGroups("token.txt", []string{"group2"}))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	require.Contains(t, string(out), "# keep me", "comment was dropped on change:\n%s", out)
	require.Equal(t, []string{"group2"}, accessFor(t, main, "token.txt"))
}

// TestSecretChangeGroups_EmptyDropsAccessNode changing access to empty removes
// the access: node (the implicit "admin-only" default) rather than writing a
// noisy `access: []`, leaving other secrets' access untouched.
func TestSecretChangeGroups_EmptyDropsAccessNode(t *testing.T) {
	_, main := buildConfig(t, false, "token.txt") // token.txt: access [group1]

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretChangeGroups("token.txt", []string{}))
	require.NoError(t, cr.Save())

	require.Empty(t, accessFor(t, main, "token.txt"))

	raw, err := os.ReadFile(main)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "access: []", "empty access must drop the node, not write access: []")

	// Other secrets keep their access.
	require.Equal(t, []string{"group1"}, accessFor(t, main, "existing.txt"))
}

// TestSecretChangeGroups_NotFound errors when no secret matches the path.
func TestSecretChangeGroups_NotFound(t *testing.T) {
	_, main := buildConfig(t, false)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.Error(t, cr.SecretChangeGroups("nope.txt", []string{"dev"}))
}
