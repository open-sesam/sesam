package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

// TestConfigPaths checks which sesam.yml files discovery picks up. Whole
// relative walk paths must not be compared to the bare ".git"/".sesam"
// constants: a nested one sits at some deeper path and has to be skipped too.
func TestConfigPaths(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{
			name:  "plain sub-config",
			files: map[string]string{"svc/sesam.yml": "secrets: []\n"},
			want:  []string{"sesam.yml", "svc/sesam.yml"},
		},
		{
			name:  "deeply nested sub-config",
			files: map[string]string{"a/b/c/sesam.yml": "secrets: []\n"},
			want:  []string{"a/b/c/sesam.yml", "sesam.yml"},
		},
		{
			name:  "inside a nested .git",
			files: map[string]string{"svc/.git/hooks/sesam.yml": "bogus"},
			want:  []string{"sesam.yml"},
		},
		{
			name:  "inside a nested .sesam",
			files: map[string]string{"nested/.sesam/sesam.yml": "bogus"},
			want:  []string{"sesam.yml"},
		},
		{
			name: "separate sesam repo below",
			files: map[string]string{
				"other/.sesam/audit/init": "x",
				"other/sesam.yml":         "bogus",
				"other/deep/sesam.yml":    "bogus",
			},
			want: []string{"sesam.yml"},
		},
		{
			name:  "inside the fork dir",
			files: map[string]string{".sesam-tmp/sesam.yml": "bogus"},
			want:  []string{"sesam.yml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			admin := writeTestIdentity(t, "admin")
			dir, r := bootstrapRepo(t, admin)

			for name, body := range tt.files {
				p := filepath.Join(dir, filepath.FromSlash(name))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
				require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
			}

			paths, err := r.configPaths()
			require.NoError(t, err)

			want := make([]string, len(tt.want))
			for i, w := range tt.want {
				want[i] = filepath.FromSlash(w)
			}
			require.Equal(t, want, paths)
		})
	}
}

// TestCommittedConfigPaths checks discovery on a committed tree: the same
// separate-repo boundary as configPaths, and paths relative to the sesam dir
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

			gr, err := git.PlainOpen(dir)
			require.NoError(t, err)
			head, err := gr.Head()
			require.NoError(t, err)
			commit, err := gr.CommitObject(head.Hash())
			require.NoError(t, err)
			tree, err := commit.Tree()
			require.NoError(t, err)

			paths, err := committedConfigPaths(tree, tt.prefix)
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
