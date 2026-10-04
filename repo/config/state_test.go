package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

func TestState(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		users   []StateUser
		secrets []core.SecretAccess
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
				{
					Membership: core.Membership{Name: "alice", Groups: []string{"admin", "dev"}},
					Keys:       []string{"age1alice"},
				},
				{
					Membership: core.Membership{Name: "bob", Groups: []string{"dev"}},
					Keys:       []string{"age1bob"},
				},
			},
			secrets: []core.SecretAccess{},
		},
		{
			name: "user without group membership keeps an empty set",
			body: `
users:
  - name: alice
    key: [age1alice]
secrets: []
`,
			users: []StateUser{{
				Membership: core.Membership{Name: "alice", Groups: []string{}},
				Keys:       []string{"age1alice"},
			}},
			secrets: []core.SecretAccess{},
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
			users: []StateUser{{
				Membership: core.Membership{Name: "alice", Groups: []string{"dev"}},
				Keys:       []string{"age1alice", "github:alice"},
			}},
			secrets: []core.SecretAccess{},
		},
		{
			name: "the implicit admin group is spelled out on both sides",
			body: `
secrets:
  - path: explicit.txt
    access: [admin, dev, dev]
  - path: implicit.txt
`,
			users: []StateUser{},
			secrets: []core.SecretAccess{
				{
					RevealedPath: "explicit.txt",
					AccessGroups: []string{"admin", "dev"},
				},
				{
					RevealedPath: "implicit.txt",
					AccessGroups: []string{"admin"},
				},
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
			secrets: []core.SecretAccess{
				{RevealedPath: "a.txt", AccessGroups: []string{"admin"}},
				{RevealedPath: "sub/b.txt", AccessGroups: []string{"admin"}},
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
	require.Equal(t, []core.SecretAccess{
		{RevealedPath: "top.txt", AccessGroups: []string{"admin"}},
		{
			RevealedPath: "svc/token",
			AccessGroups: []string{"admin", "ops"},
		},
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

// TestStateUserAndSecretLookupFindsLastEntry guards the lazy index behind
// User()/Secret(): building it from a slice that is still being appended to
// (as State() does, to detect duplicates) would cache a stale, partial index
// and make the most recently declared user or secret unfindable.
func TestStateUserAndSecretLookupFindsLastEntry(t *testing.T) {
	cfg, err := loadConfig(t, writeConfig(t, `
users:
  - name: alice
    key: [age1alice]
  - name: bob
    key: [age1bob]
groups:
  admin: [alice]
secrets:
  - path: a.txt
  - path: b.txt
`))
	require.NoError(t, err)

	state, err := cfg.State()
	require.NoError(t, err)

	_, ok := state.User("bob")
	require.True(t, ok, "last-declared user should be found")

	_, ok = state.Secret("b.txt")
	require.True(t, ok, "last-declared secret should be found")

	_, ok = state.User("nobody")
	require.False(t, ok)
}

// TestStateLookupOnHandBuiltState mirrors how repo/diff's tests construct a
// State directly (no State() call): User()/Secret() must still work since
// their index is built lazily from whatever Users/Secrets already hold.
func TestStateLookupOnHandBuiltState(t *testing.T) {
	state := &State{
		Users: []StateUser{
			{Membership: core.Membership{Name: "alice"}},
			{Membership: core.Membership{Name: "bob"}},
		},
		Secrets: []core.SecretAccess{
			{RevealedPath: "a.txt"},
		},
	}

	_, ok := state.User("bob")
	require.True(t, ok)

	_, ok = state.Secret("a.txt")
	require.True(t, ok)

	_, ok = state.Secret("missing.txt")
	require.False(t, ok)
}
