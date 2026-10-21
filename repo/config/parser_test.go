package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/goccy/go-yaml/parser"
	"github.com/stretchr/testify/require"
)

// loadConfig opens a root on the config's directory and loads it relative to
// that root, mirroring how the repo wires config in production. Every
// sesam.yml below the main file's directory is loaded as a sub-config.
func loadConfig(t *testing.T, mainPath string) (*Config, error) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(mainPath))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = root.Close() })

	main := filepath.Base(mainPath)
	var subs []string
	err = fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && d.Name() == "sesam.yml" && p != main {
			subs = append(subs, filepath.FromSlash(p))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return Load(root, main, subs)
}

// fileSourceFromYAML builds a *FileSource straight from a YAML body, without
// going through Load's schema validation - for exercising an AST shape the
// schema itself would already refuse.
func fileSourceFromYAML(t *testing.T, path, body string) *FileSource {
	t.Helper()

	file, err := parser.ParseBytes([]byte(body), parser.ParseComments)
	require.NoError(t, err)

	return &FileSource{Path: path, RootNode: file.Docs[0].Body}
}

// TestOwnSecretsPropagatesDecodeError regresses ownSecrets silently returning
// no secrets when a decode fails, which let trackedRevealedPaths (and so
// SecretAdd's dedup check) miss a file's secrets entirely instead of erroring
// - risking a duplicate declaration for an already-tracked path.
func TestOwnSecretsPropagatesDecodeError(t *testing.T) {
	src := fileSourceFromYAML(t, "sesam.yml", "secrets:\n  - path: {nested: mapping}\n")

	_, err := ownSecrets(src)
	require.Error(t, err)
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
	cr, err := loadConfig(t, "testdata/test_read_yaml_file.yaml")
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

// Test_resolveSubSecretsOnly verifies that a sub-file carrying only a
// top-level secrets: key (which goccy parses as a single *ast.MappingValueNode
// rather than an *ast.MappingNode) resolves and merges into the main file.
func Test_resolveSubSecretsOnly(t *testing.T) {
	cr, err := loadConfig(t, "testdata/main.yaml")
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)

	var paths []string
	for _, s := range secrets {
		paths = append(paths, s.Path)
	}

	// The main file's own secrets come first, then the sub-file's.
	require.Equal(t, []string{"top.txt", "nested.txt"}, paths)
}

func TestMerged(t *testing.T) {
	cr, err := loadConfig(t, "testdata/main.yaml")
	require.NoError(t, err)

	doc, err := cr.Merged()
	require.NoError(t, err)

	// The sub-file is flattened after the main file and its path made
	// relative to the main file.
	require.Equal(t, &Document{
		Users:  []User{{Name: "test_user", Key: []string{"key"}}},
		Groups: map[string][]string{"group1": {"test_user"}},
		Secrets: []Secret{
			{Path: "top.txt", Access: []string{"group1"}},
			{Path: "sub/nested.txt", Access: []string{"group1"}},
		},
	}, doc)
}

// TestSchema_MatchesStructs guards the agreement between sesam_schema.json and
// the structs in config.go, in both directions: a document the schema accepts
// must decode into User/Secret, and any field those structs do not model must
// be rejected. Accepted cases therefore assert on the decode too — a schema
// that allows something the decoder chokes on is exactly the mismatch this
// catches.
func TestSchema_MatchesStructs(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		valid bool
	}{
		// User.Key is []string, so the single-scalar form must not validate.
		{"scalar key", "users:\n  - name: a\n    key: k\nsecrets: []\n", false},
		{"list key", "users:\n  - name: a\n    key:\n      - k\nsecrets: []\n", true},
		{"user without key", "users:\n  - name: a\nsecrets: []\n", false},
		{"empty user name", "users:\n  - name: \"\"\n    key:\n      - k\nsecrets: []\n", false},
		{"unknown user field", "users:\n  - name: a\n    key:\n      - k\n    bogus: 1\nsecrets: []\n", false},

		// Secret fields, including the ones reserved for rotation.
		{"secret name", "secrets:\n  - path: a\n    name: foo\n", true},
		{"secret rotate", "secrets:\n  - path: a\n    rotate:\n      - anything\n", true},
		{"secret swap", "secrets:\n  - path: a\n    swap:\n      - cmd: ssh-copy-id\n", true},
		{"swap unknown field", "secrets:\n  - path: a\n    swap:\n      - cmd: x\n        bogus: y\n", false},
		{"swap without cmd", "secrets:\n  - path: a\n    swap:\n      - {}\n", false},
		{"unknown secret field", "secrets:\n  - path: a\n    bogus: 1\n", false},

		// Only the root tolerates x- keys, so anchors have somewhere to live.
		{"toplevel x- key", "x-anchors:\n  access:\n    - g1\nsecrets:\n  - path: a\n", true},
		{"x- key inside secret", "secrets:\n  - path: a\n    x-foo: 1\n", false},
		{"unknown toplevel key", "bogus: 1\nsecrets: []\n", false},

		// Anchors defined outside the secret they are used in — the whole point
		// of the x- escape hatch. See TestAnchors_ResolveAcrossDocument.
		{"merge key from x- anchor", "x-a: &a\n  access:\n    - g1\nsecrets:\n  - path: p\n    <<: *a\n", true},
		{"alias from sibling secret", "secrets:\n  - path: a\n    access: &d\n      - g1\n  - path: b\n    access: *d\n", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			main := filepath.Join(dir, "sesam.yml")
			require.NoError(t, os.WriteFile(main, []byte(tt.yaml), 0o644))

			cr, err := loadConfig(t, main)
			if !tt.valid {
				require.Error(t, err)
				require.Contains(t, err.Error(), "failed to validate")
				return
			}
			require.NoError(t, err)

			// Whatever the schema let through must survive the struct decode.
			_, err = cr.Users()
			require.NoError(t, err)
			_, err = cr.Secrets()
			require.NoError(t, err)
		})
	}
}

// TestAnchors_ResolveAcrossDocument checks that an alias resolves against an
// anchor declared elsewhere in the same file. Secrets, users and groups are
// each decoded from an isolated sub-node, so without a document-primed decoder
// the anchor is invisible and the decode fails.
func TestAnchors_ResolveAcrossDocument(t *testing.T) {
	const src = `x-shared: &shared
  access:
    - devs
x-keys: &keys
  - ssh-ed25519 AAAA
x-devs: &devs
  - alice

users:
  - name: alice
    key: *keys

groups:
  devs: *devs

secrets:
  - path: a.txt
    <<: *shared
  - path: b.txt
    access: *devs
`

	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte(src), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	secrets, err := cr.Secrets()
	require.NoError(t, err)
	require.Len(t, secrets, 2)
	require.Equal(t, []string{"devs"}, secrets[0].Access, "merge key from a top-level anchor")
	require.Equal(t, []string{"alice"}, secrets[1].Access, "plain alias to a top-level anchor")

	users, err := cr.Users()
	require.NoError(t, err)
	require.Equal(t, []string{"ssh-ed25519 AAAA"}, users[0].Key)

	groups, err := cr.Groups()
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"devs": {"alice"}}, groups)
}

// TestAnchors_SurviveSave pins the constraint that makes anchors usable at all:
// resolving them must not expand them on disk. The AST stays authoritative and
// Save re-renders it verbatim, so a decoded alias is a read-time view only.
func TestAnchors_SurviveSave(t *testing.T) {
	const src = `x-shared: &shared
  access:
    - devs

secrets:
  - path: a.txt
    <<: *shared
`

	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte(src), 0o644))

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	// Force a decode, then write the file back out.
	_, err = cr.Secrets()
	require.NoError(t, err)
	require.NoError(t, cr.Save())

	out, err := os.ReadFile(main)
	require.NoError(t, err)
	require.Contains(t, string(out), "&shared", "anchor definition must survive Save")
	require.Contains(t, string(out), "<<: *shared", "alias must not be expanded on Save")
}

// TestLoad_RejectsInclude: the include: form was replaced by discovery, so a
// leftover entry - in the main file or a sub-file - fails with a hint
// instead of a generic schema error.
func TestLoad_RejectsInclude(t *testing.T) {
	tests := []struct {
		name string
		main string
		sub  string
	}{
		{"in main", "secrets:\n  - include: sub\n", "secrets: []\n"},
		{"in sub", "secrets: []\n", "secrets:\n  - path: a\n  - include: ..\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			main := filepath.Join(dir, "sesam.yml")
			require.NoError(t, os.WriteFile(main, []byte(tt.main), 0o644))
			require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, "sub", "sesam.yml"), []byte(tt.sub), 0o644))

			_, err := loadConfig(t, main)
			require.Error(t, err)
			require.Contains(t, err.Error(), "include is no longer supported")
		})
	}
}

// TestCreate_PrunesUnusedSubs: Create registers known sub-configs as empty, so
// a rebuild puts secrets back into them and Prune deletes the ones that got
// nothing - otherwise their stale content would be loaded next to the rebuild.
func TestCreate_PrunesUnusedSubs(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"keep", "drop"} {
		touch(t, filepath.Join(dir, sub, "x.txt"))
		require.NoError(t, os.WriteFile(filepath.Join(dir, sub, "sesam.yml"), []byte("secrets:\n  - path: x.txt\n"), 0o644))
	}

	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	cr, err := Create(root, "sesam.yml", []string{filepath.Join("keep", "sesam.yml"), filepath.Join("drop", "sesam.yml")})
	require.NoError(t, err)
	require.NoError(t, cr.SecretAdd(filepath.Join("keep", "x.txt"), false, nil))
	require.NoError(t, cr.EnsureSecretsKey())
	require.NoError(t, cr.Prune())
	require.NoError(t, cr.Save())

	require.Equal(t, []string{filepath.Join("drop", "sesam.yml")}, cr.Deleted())
	require.False(t, exists(filepath.Join(dir, "drop", "sesam.yml")))
	require.Equal(t, []string{"x.txt"}, resolvedPaths(t, filepath.Join(dir, "sesam.yml")))
}
