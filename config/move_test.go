package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecretMove_WithinMain renames a secret in the main file, preserving its
// access groups.
func TestSecretMove_WithinMain(t *testing.T) {
	_, main := buildConfig(t, false, "token.txt")

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretMove(
		"token.txt",
		"renamed.txt",
		false,
	))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "renamed.txt"}, resolvedPaths(t, main))
	require.Equal(t, []string{"group1"}, accessFor(t, main, "renamed.txt"))
}

// TestSecretMove_OutOfSubfilePrunes moves the only secret out of a sub-file into
// the main file; the emptied sub-file (and its include) are pruned.
func TestSecretMove_OutOfSubfilePrunes(t *testing.T) {
	dir, main := buildConfig(t, true, "sub/api.key")

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretMove(
		filepath.Join("sub", "api.key"),
		"api.key",
		false,
	))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "emptied sub-file pruned")
}

// TestSecretMove_NotFound errors when no secret matches the source path.
func TestSecretMove_NotFound(t *testing.T) {
	_, main := buildConfig(t, false)

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.Error(t, cr.SecretMove(
		"nope.txt",
		"renamed.txt",
		false,
	))
}
