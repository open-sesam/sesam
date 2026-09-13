package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		users   []StateUser
		secrets []StateSecret
	}{
		{
			name: "groups are inverted per user",
			body: `
users:
  - name: alice
    key: [age1alice]
  - name: bob
    key: [age1bob]
groups:
  dev:
    - alice
    - bob
  admin:
    - alice
secrets: []
`,
			users: []StateUser{
				{Name: "alice", Groups: []string{"admin", "dev"}, Keys: []string{"age1alice"}},
				{Name: "bob", Groups: []string{"dev"}, Keys: []string{"age1bob"}},
			},
			secrets: []StateSecret{},
		},
		{
			name: "user without group membership keeps an empty set",
			body: `
users:
  - name: alice
    key: [age1alice]
secrets: []
`,
			users:   []StateUser{{Name: "alice", Groups: []string{}, Keys: []string{"age1alice"}}},
			secrets: []StateSecret{},
		},
		{
			name: "duplicate keys and groups are folded",
			body: `
users:
  - name: alice
    key: [age1alice, github:alice, age1alice]
groups:
  dev: [alice, alice]
secrets: []
`,
			users: []StateUser{
				{Name: "alice", Groups: []string{"dev"}, Keys: []string{"age1alice", "github:alice"}},
			},
			secrets: []StateSecret{},
		},
		{
			name: "declared admin access is dropped, absent access stays empty",
			body: `
secrets:
  - path: explicit.txt
    access: [admin, dev, dev]
  - path: implicit.txt
`,
			users: []StateUser{},
			secrets: []StateSecret{
				{Path: "explicit.txt", Access: []string{"dev"}},
				{Path: "implicit.txt", Access: []string{}},
			},
		},
		{
			name: "paths are cleaned but stay relative to the main file",
			body: `
secrets:
  - path: ./sub/../a.txt
  - path: sub/b.txt
`,
			users: []StateUser{},
			secrets: []StateSecret{
				{Path: "a.txt", Access: []string{}},
				{Path: "sub/b.txt", Access: []string{}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(t, writeConfig(t, tc.body))
			require.NoError(t, err)

			state, err := cfg.State()
			require.NoError(t, err)
			require.Equal(t, tc.users, state.Users)
			require.Equal(t, tc.secrets, state.Secrets)
		})
	}
}

// TestStateIncludedSecretPaths checks that a secret declared in an included
// file is resolved against that file's directory, not the main file's.
func TestStateIncludedSecretPaths(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "svc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "svc", "sesam.yml"), []byte(
		"secrets:\n  - path: token\n    access: [ops]\n",
	), 0o644))

	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte(
		"secrets:\n  - path: top.txt\n  - include: svc/sesam.yml\n",
	), 0o644))

	cfg, err := loadConfig(t, main)
	require.NoError(t, err)

	state, err := cfg.State()
	require.NoError(t, err)
	require.Equal(t, []StateSecret{
		{Path: "top.txt", Access: []string{}},
		{Path: "svc/token", Access: []string{"ops"}},
	}, state.Secrets)
}

func TestStateErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "duplicate user",
			body: `
users:
  - name: alice
    key: [age1alice]
  - name: alice
    key: [age1other]
groups:
  admin: [alice]
secrets: []
`,
			want: `user "alice" is declared more than once`,
		},
		{
			name: "duplicate secret path",
			body: `
secrets:
  - path: a.txt
  - path: ./a.txt
`,
			want: `secret "a.txt" is declared more than once`,
		},
		{
			name: "path escaping the repository",
			body: `
secrets:
  - path: ../outside.txt
`,
			want: `resolves to "../outside.txt", which is outside the repository`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := loadConfig(t, writeConfig(t, tc.body))
			require.NoError(t, err)

			_, err = cfg.State()
			require.ErrorContains(t, err, tc.want)
		})
	}
}

// TestStateReportsEveryProblem checks that a config with several problems
// reports all of them, so a hand-edited file can be fixed in one pass.
func TestStateReportsEveryProblem(t *testing.T) {
	cfg, err := loadConfig(t, writeConfig(t, `
users:
  - name: alice
    key: [age1alice]
  - name: alice
    key: [age1other]
groups:
  admin: [alice]
secrets:
  - path: a.txt
  - path: a.txt
  - path: ../outside.txt
`))
	require.NoError(t, err)

	_, err = cfg.State()
	require.ErrorContains(t, err, `user "alice" is declared more than once`)
	require.ErrorContains(t, err, `secret "a.txt" is declared more than once`)
	require.ErrorContains(t, err, "outside the repository")
}
