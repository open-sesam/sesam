package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// loadConfig opens a root on the config's directory and loads it relative to
// that root, mirroring how the repo wires config in production.
func loadConfig(t *testing.T, mainPath string) (*Config, error) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(mainPath))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = root.Close() })
	return Load(root, filepath.Base(mainPath))
}

// TestSecretAdd_RelativeConfigPathSameDir adds a secret given relative to the
// config's root and checks the recorded Path stays clean and relative.
func TestSecretAdd_RelativeConfigPathSameDir(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "sesam.yml"),
		[]byte("secrets:\n  - path: existing.txt\n    access:\n      - group1\n"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "somefile.txt"), []byte("x"), 0o644))

	cr, err := loadConfig(t, filepath.Join(dir, "sesam.yml"))
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd("somefile.txt", false, []string{"group1"}))
	require.NoError(t, cr.Save())
	require.Equal(t, []string{"existing.txt", "somefile.txt"}, resolvedPaths(t, filepath.Join(dir, "sesam.yml")))
}

func Test_readYamlFile(t *testing.T) {
	cr, err := loadConfig(t, "../test/files/test_read_yaml_file.yaml")
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
	cr, err := loadConfig(t, "../test/files/main_with_include.yaml")
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

	_, err := loadConfig(t, main)
	require.Error(t, err)
	require.Contains(t, err.Error(), "include loop")
}

// TestLoad_RejectsIncludeCycle: a cycle across several files (main → a → main)
// must be detected, so parsing terminates instead of looping endlessly.
func TestLoad_RejectsIncludeCycle(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte("secrets:\n  - include: sub\n"), 0o644))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "sesam.yml"), []byte("secrets:\n  - include: ..\n"), 0o644))

	_, err := loadConfig(t, main)
	require.Error(t, err)
	require.Contains(t, err.Error(), "include loop")
}
