package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecretAdd_RelativeConfigPathSameDir reproduces the reported failure: a
// config loaded via a relative path, with a secret given relatively in the same
// directory, used to mishandle the path. Load resolves the config path to
// absolute, so SecretAdd (which also resolves to absolute) records the secret
// with a clean relative Path regardless of how the config was loaded.
func TestSecretAdd_RelativeConfigPathSameDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	require.NoError(t, os.WriteFile("sesam.yml",
		[]byte("secrets:\n  - path: existing.txt\n    access:\n      - group1\n"), 0o644))
	require.NoError(t, os.WriteFile("somefile.txt", []byte("x"), 0o644))

	// Loaded with a relative path, and the secret given relatively in the same
	// directory as the config — the exact failure case.
	cr, err := Load("sesam.yml")
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd("somefile.txt", false, []string{"group1"}))
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
