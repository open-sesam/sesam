package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMoveSecret_WithinMain renames a secret in the main file, preserving its
// access groups.
func TestMoveSecret_WithinMain(t *testing.T) {
	dir, main := buildConfig(t, false, "token.txt")

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.MoveSecret(
		filepath.Join(dir, "token.txt"),
		filepath.Join(dir, "renamed.txt"),
		false,
	))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "renamed.txt"}, resolvedPaths(t, main))
	require.Equal(t, []string{"group1"}, accessFor(t, main, "renamed.txt"))
}

// TestMoveSecret_OutOfSubfilePrunes moves the only secret out of a sub-file into
// the main file; the emptied sub-file (and its include) are pruned.
func TestMoveSecret_OutOfSubfilePrunes(t *testing.T) {
	dir, main := buildConfig(t, true, "sub/api.key")

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))

	cr, err := Load(main)
	require.NoError(t, err)
	require.NoError(t, cr.MoveSecret(
		filepath.Join(dir, "sub", "api.key"),
		filepath.Join(dir, "api.key"),
		false,
	))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, main))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "emptied sub-file pruned")
}

// TestMoveSecret_NotFound errors when no secret matches the source path.
func TestMoveSecret_NotFound(t *testing.T) {
	dir, main := buildConfig(t, false)

	cr, err := Load(main)
	require.NoError(t, err)
	require.Error(t, cr.MoveSecret(
		filepath.Join(dir, "nope.txt"),
		filepath.Join(dir, "renamed.txt"),
		false,
	))
}
