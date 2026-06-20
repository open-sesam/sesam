package config

import (
	"testing"

	"github.com/test-go/testify/require"
)

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
