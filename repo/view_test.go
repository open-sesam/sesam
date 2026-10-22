package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// GitAddConfig stages this repo's config tree, not every sesam.yml below it.
func TestGitAddConfigOnlyOwnTree(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	other := filepath.Join(dir, "nested", "sesam.yml")
	require.NoError(t, os.MkdirAll(filepath.Dir(other), 0o700))
	require.NoError(t, os.WriteFile(other, []byte("secrets: []\n"), 0o600))

	require.NoError(t, r.GitAddConfig(nil))

	idx, err := r.gitRepo.Storer.Index()
	require.NoError(t, err)
	var staged []string
	for _, e := range idx.Entries {
		staged = append(staged, e.Name)
	}
	require.Contains(t, staged, "sesam.yml")
	require.NotContains(t, staged, "nested/sesam.yml")
}
