package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAddSecrets_RelativeConfigPathSameDir reproduces the reported failure: a
// config loaded via a relative path used to return relative revealed paths for
// a secret sitting next to it, which then could not be made relative to the
// sesam dir. Load now resolves the config path to absolute, so the returned
// paths are absolute regardless of how the config was loaded.
func TestAddSecrets_RelativeConfigPathSameDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("sesam.yml",
		[]byte("secrets:\n  - path: existing.txt\n    access:\n      - group1\n"), 0o644))
	require.NoError(t, os.WriteFile("somefile.txt", []byte("x"), 0o644))

	// Loaded with a relative path, and the secret given relatively in the same
	// directory as the config — the exact failure case.
	cr, err := Load("sesam.yml")
	require.NoError(t, err)

	added, err := cr.AddSecrets("somefile.txt", false, []string{"group1"})
	require.NoError(t, err)
	require.Len(t, added, 1)
	require.True(t, filepath.IsAbs(added[0]), "returned revealed path must be absolute, got %q", added[0])
	require.Equal(t, "somefile.txt", filepath.Base(added[0]))

	require.NoError(t, cr.Save())
	require.Equal(t, []string{"existing.txt", "somefile.txt"}, resolvedPaths(t, "sesam.yml"))
}

func Test_readYamlFile(t *testing.T) {
	cr, err := Load("../test/files/test_read_yaml_file.yaml")
	require.NoError(t, err)

	users, err := cr.Users()
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "test_user", users[0].Name)
	require.Equal(t, []string{"key"}, users[0].Key)

	groups, err := cr.Groups()
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"group1": {"test_user"}}, groups)
}

// Test_resolveIncludeSecretsOnly verifies that a sub-file carrying only a
// top-level secrets: key (which goccy parses as a single *ast.MappingValueNode
// rather than an *ast.MappingNode) resolves and merges into the main file.
func Test_resolveIncludeSecretsOnly(t *testing.T) {
	cr, err := Load("../test/files/main_with_include.yaml")
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)

	var paths []string
	for _, s := range secrets {
		paths = append(paths, s.Path)
	}

	// The included secrets-only sub-file is flattened ahead of the main file's
	// own secret, in include order.
	require.Equal(t, []string{"nested.txt", "top.txt"}, paths)
}
