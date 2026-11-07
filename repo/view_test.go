package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

// TestCommittedConfigPaths checks discovery on a committed tree: the same
// separate-repo boundary as config.Discover, and paths relative to the sesam dir
// when it sits below the worktree root.
func TestCommittedConfigPaths(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		files  []string
		want   []string
	}{
		{
			name:   "sesam dir at worktree root",
			prefix: ".",
			files:  []string{"sesam.yml", "svc/sesam.yml", "other/.sesam/init", "other/sesam.yml", "other/x/sesam.yml"},
			want:   []string{"sesam.yml", "svc/sesam.yml"},
		},
		{
			name:   "sesam dir below worktree root",
			prefix: "box",
			files:  []string{"sesam.yml", "box/sesam.yml", "box/a/b/sesam.yml", "box/c/.sesam/init", "box/c/sesam.yml"},
			want:   []string{"a/b/sesam.yml", "sesam.yml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := freshGitRepo(t)
			for _, name := range tt.files {
				p := filepath.Join(dir, filepath.FromSlash(name))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
				require.NoError(t, os.WriteFile(p, []byte("secrets: []\n"), 0o644))
			}
			gitCommitAll(t, dir, "configs")

			g, err := core.OpenGit(t.Context(), dir)
			require.NoError(t, err)
			head, err := g.Head(t.Context())
			require.NoError(t, err)

			paths, err := committedConfigPaths(t.Context(), g, head, tt.prefix)
			require.NoError(t, err)

			want := make([]string, len(tt.want))
			for i, w := range tt.want {
				want[i] = filepath.FromSlash(w)
			}
			require.Equal(t, want, paths)
		})
	}
}

// GitAddConfig stages this repo's config tree, not a separate repo's sesam.yml
// below it.
func TestGitAddConfigOnlyOwnTree(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	other := filepath.Join(dir, "nested", "sesam.yml")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nested", ".sesam"), 0o700))
	require.NoError(t, os.WriteFile(other, []byte("secrets: []\n"), 0o600))

	require.NoError(t, r.GitAddConfig(t.Context(), nil))

	staged, err := r.gitRepo.TrackedFiles(t.Context(), ".")
	require.NoError(t, err)
	require.Contains(t, staged, "sesam.yml")
	require.NotContains(t, staged, "nested/sesam.yml")
}
