package config

import (
	"testing"

	"github.com/test-go/testify/require"
)

func Test_readYamlFile(t *testing.T) {
	cr := NewConfigRepository()
	require.NoError(t, cr.Load("../test/files/test_readYamlFile.yaml"))
	require.NoError(t, cr.Resolve())

	expected := &Config{
		General: General{
			EncryptAll: false,
		},
		Users: []User{
			{
				Name: "test_user",
			},
		},
		Groups: map[string][]string{"group1": {"test_user"}},
	}

	require.Equal(t, expected.General, cr.MainFile.Config.General)
	require.Equal(t, expected.Users, cr.MainFile.Config.Users)
	require.Equal(t, expected.Groups, cr.MainFile.Config.Groups)
}

// Test_resolveIncludeSecretsOnly verifies that a sub-file carrying only a
// top-level secrets: key (which goccy parses as a single *ast.MappingValueNode
// rather than an *ast.MappingNode) resolves and merges into the main file.
func Test_resolveIncludeSecretsOnly(t *testing.T) {
	cr := NewConfigRepository()
	require.NoError(t, cr.Load("../test/files/main_with_include.yaml"))
	require.NoError(t, cr.Resolve())

	var names []string
	for _, s := range cr.MainFile.Config.Secrets {
		names = append(names, s.Name)
	}

	// The included secrets-only sub-file is flattened ahead of the main file's
	// own secret, in include order.
	require.Equal(t, []string{"nested", "top"}, names)
}
