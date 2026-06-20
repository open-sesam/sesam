package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/test-go/testify/require"
)

// TestLoad_RejectsSelfInclude: a file that includes itself must be rejected
// rather than recursing forever.
func TestLoad_RejectsSelfInclude(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte("secrets:\n  - include: sesam.yml\n"), 0o644))

	_, err := Load(main)
	require.Error(t, err)
	require.Contains(t, err.Error(), "include loop")
}

// TestLoad_RejectsIncludeCycle: a cycle across several files (main → a → main)
// must be detected, so parsing terminates instead of looping endlessly.
func TestLoad_RejectsIncludeCycle(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte("secrets:\n  - include: a.yml\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.yml"), []byte("secrets:\n  - include: sesam.yml\n"), 0o644))

	_, err := Load(main)
	require.Error(t, err)
	require.Contains(t, err.Error(), "include loop")
}
