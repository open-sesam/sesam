package config

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeMainFile writes a minimal main sesam.yml (one existing secret) into dir
// and returns its path.
func writeMainFile(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sesam.yml")
	const body = "secrets:\n  - path: existing.txt\n    access:\n      - group1\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

func touch(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o644))
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// resolvedPaths reloads mainPath from disk (sub-configs included) and returns
// the sorted, merged secret paths.
func resolvedPaths(t *testing.T, mainPath string) []string {
	t.Helper()
	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)

	var paths []string
	for _, s := range secrets {
		paths = append(paths, s.Path)
	}
	sort.Strings(paths)
	return paths
}

// accessFor reloads mainPath and returns the access groups recorded for the
// secret whose Path equals secretPath.
func accessFor(t *testing.T, mainPath, secretPath string) []string {
	t.Helper()
	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)

	for _, s := range secrets {
		if s.Path == secretPath {
			return s.Access
		}
	}
	t.Fatalf("secret %q not found", secretPath)
	return nil
}

// TestSecretAdd_FileAtMainLevel: a file next to the main sesam.yml is added to
// the main file with its bare name, and no extra sesam.yml is created.
func TestSecretAdd_FileAtMainLevel(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd("token.txt", true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, mainPath))
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
}

// TestSecretAdd_FileInSubdirNested: a file in a subdirectory with nested=true
// gets its own sub/sesam.yml and the secret path is
// relative to that sub file.
func TestSecretAdd_FileInSubdirNested(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd(filepath.Join("sub", "api.key"), true, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.True(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	// Path is "api.key" (relative to sub/sesam.yml), not "sub/api.key".
	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, mainPath))
}

// TestSecretAdd_FileInSubdirFlat: a file in a subdirectory with nested=false is
// added straight to the main file, keeping its subdirectory prefix, and no
// sub/sesam.yml is created.
func TestSecretAdd_FileInSubdirFlat(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd(filepath.Join("sub", "api.key"), false, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")))
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, mainPath))
}

// TestSecretAdd_FlatLandsInNearestSubfile: with nested=false a file is added
// to the closest existing sesam.yml above it, not unconditionally to main.
func TestSecretAdd_FlatLandsInNearestSubfile(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		owner   string
		recPath string
	}{
		{"same dir as sub-file", "sub/api.key", "sub/sesam.yml", "api.key"},
		{"below sub-file", "sub/deep/api.key", "sub/sesam.yml", "deep/api.key"},
		{"no covering sub-file", "other/api.key", "sesam.yml", "other/api.key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			mainPath := writeMainFile(t, dir)
			touch(t, filepath.Join(dir, tt.file))
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "sesam.yml"), []byte("secrets: []\n"), 0o644))

			cr, err := loadConfig(t, mainPath)
			require.NoError(t, err)

			require.NoError(t, cr.SecretAdd(filepath.FromSlash(tt.file), false, nil))
			require.NoError(t, cr.Save())

			owner, err := loadConfig(t, filepath.Join(dir, filepath.FromSlash(tt.owner)))
			require.NoError(t, err)
			secrets, err := ownSecrets(owner.MainFile)
			require.NoError(t, err)
			require.Contains(t, secretPaths(secrets), filepath.FromSlash(tt.recPath))
		})
	}
}

func secretPaths(secrets []Secret) []string {
	out := make([]string, len(secrets))
	for i, s := range secrets {
		out[i] = s.Path
	}
	return out
}

// TestSecretAdd_ReaddChangesAccess: re-adding an already-tracked file is a
// self-deciding upsert — it rewrites the access groups in place rather than
// duplicating the entry.
func TestSecretAdd_ReaddChangesAccess(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)
	require.NoError(t, cr.SecretAdd("token.txt", false, []string{"group1"}))
	require.NoError(t, cr.Save())

	cr2, err := loadConfig(t, mainPath)
	require.NoError(t, err)
	require.NoError(t, cr2.SecretAdd("token.txt", false, []string{"group2"}))
	require.NoError(t, cr2.Save())

	// No duplicate entry, and the access list reflects the latest add.
	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, mainPath))
	require.Equal(t, []string{"group2"}, accessFor(t, mainPath, "token.txt"))
}

// TestSecretAdd_ReaddEmptyGroupsPreservesAccess re-adding an already tracked
// secret without any groups is a no-op: the existing access list is left
// untouched rather than cleared. Only an explicit group list replaces it.
func TestSecretAdd_ReaddEmptyGroupsPreservesAccess(t *testing.T) {
	cases := []struct {
		name   string
		access []string
	}{
		{"nil groups", nil},
		{"empty groups", []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mainPath := writeMainFile(t, dir)
			touch(t, filepath.Join(dir, "token.txt"))

			cr, err := loadConfig(t, mainPath)
			require.NoError(t, err)
			require.NoError(t, cr.SecretAdd("token.txt", false, []string{"group1"}))
			require.NoError(t, cr.Save())

			cr2, err := loadConfig(t, mainPath)
			require.NoError(t, err)
			require.NoError(t, cr2.SecretAdd("token.txt", false, tc.access))
			require.NoError(t, cr2.Save())

			require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, mainPath))
			require.Equal(t, []string{"group1"}, accessFor(t, mainPath, "token.txt"))
		})
	}
}

// TestSecretAdd_MissingPath surfaces a stat error for a non-existent path only
// when the caller resolves it; SecretAdd itself does not stat, so adding a path
// that is not yet on disk is allowed (the repo validates existence).
func TestSecretAdd_NonExistentPathStillAdded(t *testing.T) {
	dir := t.TempDir()
	mainPath := writeMainFile(t, dir)

	cr, err := loadConfig(t, mainPath)
	require.NoError(t, err)
	require.NoError(t, cr.SecretAdd("later.txt", false, []string{"group1"}))
	require.NoError(t, cr.Save())

	require.Equal(t, []string{"existing.txt", "later.txt"}, resolvedPaths(t, mainPath))
}

// TestSecretAdd_NoDuplicateSameFileTwice: adding the same file into the same
// file twice keeps a single entry (the second add upserts its access groups).
func TestSecretAdd_NoDuplicateSameFileTwice(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "token.txt"))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd("token.txt", false, []string{"group1"}))
	require.NoError(t, cr.SecretAdd("token.txt", false, []string{"group2"}))

	require.NoError(t, cr.Save())
	require.Equal(t, []string{"existing.txt", "token.txt"}, resolvedPaths(t, main))
	require.Equal(t, []string{"group2"}, accessFor(t, main, "token.txt"))
}

// TestSecretAdd_NoDuplicateSubThenMain: a file already declared in a sub
// sesam.yml is not re-added to the main file when the same physical file is
// added again with a flat layout — it stays in the sub-file (upsert there).
func TestSecretAdd_NoDuplicateSubThenMain(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	// Lands in sub/sesam.yml.
	require.NoError(t, cr.SecretAdd(filepath.Join("sub", "api.key"), true, []string{"group1"}))
	// Re-add the same physical file flat into main: must not duplicate.
	require.NoError(t, cr.SecretAdd(filepath.Join("sub", "api.key"), false, []string{"group1"}))

	require.NoError(t, cr.Save())
	// Present exactly once across the merged view.
	require.Equal(t, []string{"api.key", "existing.txt"}, resolvedPaths(t, main))
}

// TestSecretAdd_NoDuplicateMainThenSub: the reverse direction — a file already
// declared in the main file is not re-added into its own sub sesam.yml, and no
// empty sub-file is produced.
func TestSecretAdd_NoDuplicateMainThenSub(t *testing.T) {
	dir := t.TempDir()
	main := writeMainFile(t, dir)
	touch(t, filepath.Join(dir, "sub", "api.key"))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	require.NoError(t, cr.SecretAdd(filepath.Join("sub", "api.key"), false, []string{"group1"}))
	require.NoError(t, cr.SecretAdd(filepath.Join("sub", "api.key"), true, []string{"group1"}))

	require.NoError(t, cr.Save())
	require.False(t, exists(filepath.Join(dir, "sub", "sesam.yml")), "no empty sub-file created")
	require.Equal(t, []string{"existing.txt", "sub/api.key"}, resolvedPaths(t, main))
}

// TestSecretAdd_PreservesExistingComments verifies that inserting a new secret
// node leaves the comments on the pre-existing entries untouched — the new node
// is appended, nothing above it shifts.
func TestSecretAdd_PreservesExistingComments(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # comment-for-alpha
  - path: alpha.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretAdd("beta.txt", false, []string{"group1"}))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)

	require.Contains(t, string(out), "comment-for-alpha", "existing comment was lost on add:\n%s", out)
	require.Contains(t, string(out), "beta.txt", "added secret missing:\n%s", out)
}

// TestSecretAdd_PreservesCommentsAndIndentation checks that altering the config
// leaves the existing entry byte-for-byte intact (comment + exact indentation)
// and appends the new entry with the same block-sequence indentation.
func TestSecretAdd_PreservesCommentsAndIndentation(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	body := `secrets:
  # keep me
  - path: alpha.txt
    access:
      - group1
`
	require.NoError(t, os.WriteFile(main, []byte(body), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "alpha.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "beta.txt"), []byte("x"), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)
	require.NoError(t, cr.SecretAdd("beta.txt", false, []string{"group2"}))
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	got := string(out)

	// The original entry — comment and its exact indentation — is untouched.
	require.Contains(t, got, "  # keep me\n  - path: alpha.txt\n    access:\n      - group1\n",
		"existing comment/indentation was altered:\n%s", got)
	// The appended entry matches the same indentation style.
	require.Contains(t, got, "  - path: beta.txt\n    access:\n      - group2\n",
		"added entry has unexpected indentation:\n%s", got)
}

// TestMutateEmptyCollections covers the shape a hand-edited (or freshly reset)
// config has before anything is in it: `users: []`, `groups: {}`,
// `secrets: []`. Those empty collections are flow nodes and cannot take block
// entries, so merging into them used to render invalid YAML
// ("users: [   name: bob").
func TestMutateEmptyCollections(t *testing.T) {
	const empty = "users: []\ngroups: {}\nsecrets: []\n"

	tests := []struct {
		name   string
		body   string
		mutate func(c *Config) error
		want   string
	}{
		{
			name:   "user into an empty list",
			body:   empty,
			mutate: func(c *Config) error { return c.UserTell("bob", []string{"age1x"}, []string{"dev"}) },
			want:   "name: bob",
		},
		{
			name:   "group into an empty mapping",
			body:   empty,
			mutate: func(c *Config) error { return c.UserTell("bob", []string{"age1x"}, []string{"dev"}) },
			want:   "dev:",
		},
		{
			name:   "member into an empty group",
			body:   "users:\n  - name: bob\n    key: [age1x]\ngroups:\n  dev: []\nsecrets: []\n",
			mutate: func(c *Config) error { return c.UserTell("carol", []string{"age1y"}, []string{"dev"}) },
			want:   "carol",
		},
		{
			name:   "key into an empty key list",
			body:   "users:\n  - name: bob\n    key: []\ngroups: {}\nsecrets: []\n",
			mutate: func(c *Config) error { return c.UserAddRecipient("bob", []string{"age1y"}) },
			want:   "age1y",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			main := filepath.Join(dir, "sesam.yml")
			require.NoError(t, os.WriteFile(main, []byte(tc.body), 0o644))

			cfg, err := loadConfig(t, main)
			require.NoError(t, err)
			require.NoError(t, tc.mutate(cfg))

			// Save re-parses and validates, so it fails on a broken rendering.
			require.NoError(t, cfg.Save())
			require.Contains(t, cfg.MainFile.RootNode.String(), tc.want)

			// Re-loading proves the file on disk is valid, not just the tree.
			_, err = loadConfig(t, main)
			require.NoError(t, err)
		})
	}
}

// TestSecretAddIntoEmptySecretsList covers the shape a hand-edited config ends
// up with once its last secret is gone: `secrets: []`. That empty list is a
// flow node, which cannot take block items - appending into it used to render
// invalid YAML ("secrets: [   path: a.txt]").
func TestSecretAddIntoEmptySecretsList(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "flow style", body: "secrets: []\n"},
		{name: "with other keys", body: "version: 1\nsecrets: []\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			main := filepath.Join(dir, "sesam.yml")
			require.NoError(t, os.WriteFile(main, []byte(tc.body), 0o644))

			cfg, err := loadConfig(t, main)
			require.NoError(t, err)
			require.NoError(t, cfg.SecretAdd("a.txt", false, []string{"dev"}))
			require.NoError(t, cfg.Save())

			// Re-loading is the real assertion: it validates against the schema
			// and would fail outright on the broken rendering.
			require.Equal(t, []string{"a.txt"}, resolvedPaths(t, main))
			require.Equal(t, []string{"dev"}, accessFor(t, main, "a.txt"))
		})
	}
}

// Block items cannot be merged into flow-style lists or items, so those are
// rewritten in block style first.
func TestFlowStyleListsTakeNewItems(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		mutate func(*Config) error
		check  func(t *testing.T, cr *Config)
	}{
		{
			name:   "secret into flow list",
			body:   "secrets: [{path: README.md, access: [admin]}]\n",
			mutate: func(c *Config) error { return c.SecretAdd("d.txt", false, []string{"dev"}) },
			check: func(t *testing.T, cr *Config) {
				secrets, err := cr.Secrets()
				require.NoError(t, err)
				require.Len(t, secrets, 2)
				require.Equal(t, []string{"dev"}, secrets[1].Access)
			},
		},
		{
			name:   "access on a flow item",
			body:   "secrets:\n  - {path: a.txt}\n  - path: b.txt\n",
			mutate: func(c *Config) error { return c.SecretChangeGroups("a.txt", []string{"y"}) },
			check: func(t *testing.T, cr *Config) {
				secrets, err := cr.Secrets()
				require.NoError(t, err)
				require.Equal(t, []string{"y"}, secrets[0].Access)
			},
		},
		{
			name:   "user into flow list",
			body:   "users: [{name: alice, key: [keyA]}]\ngroups:\n  admin:\n    - alice\nsecrets: []\n",
			mutate: func(c *Config) error { return c.UserTell("bob", []string{"keyB"}, []string{"dev"}) },
			check: func(t *testing.T, cr *Config) {
				users, err := cr.Users()
				require.NoError(t, err)
				require.Len(t, users, 2)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main := filepath.Join(t.TempDir(), "sesam.yml")
			require.NoError(t, os.WriteFile(main, []byte(tt.body), 0o644))

			cr, err := loadConfig(t, main)
			require.NoError(t, err)
			require.NoError(t, tt.mutate(cr))
			require.NoError(t, cr.Save())

			// goccy reads mixed flow/block output back fine; strict parsers don't.
			body, err := os.ReadFile(main)
			require.NoError(t, err)
			require.NotContains(t, string(body), "{")

			cr, err = loadConfig(t, main)
			require.NoError(t, err)
			tt.check(t, cr)
		})
	}
}

// A flow-style groups mapping takes a new group in block style too.
func TestFlowStyleGroupsTakeNewGroup(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config) error
	}{
		{"tell", func(c *Config) error { return c.UserTell("bob", []string{"keyB"}, []string{"dev"}) }},
		{"change groups", func(c *Config) error { return c.UserChangeGroups("alice", []string{"admin", "dev"}) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main := filepath.Join(t.TempDir(), "sesam.yml")
			body := "users:\n  - name: alice\n    key:\n      - keyA\ngroups: {admin: [alice]}\nsecrets: []\n"
			require.NoError(t, os.WriteFile(main, []byte(body), 0o644))

			cr, err := loadConfig(t, main)
			require.NoError(t, err)
			require.NoError(t, tt.mutate(cr))
			require.NoError(t, cr.Save())

			got, err := os.ReadFile(main)
			require.NoError(t, err)
			require.NotContains(t, string(got), "{")

			_, groups := loadUsersGroups(t, main)
			require.Contains(t, groups, "dev")
			require.Equal(t, []string{"alice"}, groups["admin"])
		})
	}
}
