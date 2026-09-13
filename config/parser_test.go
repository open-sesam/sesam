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

// Test_resolveIncludeSecretsOnly verifies that a sub-file carrying only a
// top-level secrets: key (which goccy parses as a single *ast.MappingValueNode
// rather than an *ast.MappingNode) resolves and merges into the main file.
func Test_resolveIncludeSecretsOnly(t *testing.T) {
	cr, err := loadConfig(t, "testdata/main_with_include.yaml")
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

		// Include entries are their own form and take nothing else.
		{"include with extra field", "secrets:\n  - include: sub\n    desc: hi\n", false},

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
