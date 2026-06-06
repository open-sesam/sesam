package config

import (
	"testing"

	"github.com/test-go/testify/require"
)

func Test_readYamlFile(t *testing.T) {
	cr := NewConfigRepository()
	require.NoError(t, cr.Load("../test/files/test_readYamlFile.yaml"))

	// Compare the data fields only; resolveUsers attaches an unexported origin
	// node that require.Equal would otherwise diff on.
	require.Len(t, cr.MainFile.Config.Users, 1)
	require.Equal(t, "test_user", cr.MainFile.Config.Users[0].Name)
	require.Equal(t, []string{"key"}, cr.MainFile.Config.Users[0].Key)
	require.Equal(t, map[string][]string{"group1": {"test_user"}}, cr.MainFile.Config.Groups)
}

// Test_resolveIncludeSecretsOnly verifies that a sub-file carrying only a
// top-level secrets: key (which goccy parses as a single *ast.MappingValueNode
// rather than an *ast.MappingNode) resolves and merges into the main file.
func Test_resolveIncludeSecretsOnly(t *testing.T) {
	cr := NewConfigRepository()
	require.NoError(t, cr.Load("../test/files/main_with_include.yaml"))

	var paths []string
	for _, s := range cr.MainFile.Config.Secrets {
		paths = append(paths, s.Path)
	}

	// The included secrets-only sub-file is flattened ahead of the main file's
	// own secret, in include order.
	require.Equal(t, []string{"nested.txt", "top.txt"}, paths)
}
