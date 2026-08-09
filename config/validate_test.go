package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeConfig writes src as a main sesam.yml in a fresh temp dir and returns
// its path. Used by tests that need to get a broken config past Load.
func writeConfig(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "sesam.yml")
	require.NoError(t, os.WriteFile(main, []byte(src), 0o644))
	return main
}

func TestValidate_UnknownGroupMember(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want []string // group/user pairs expected to be reported, in order
	}{
		{
			name: "all members known",
			yaml: "users:\n  - name: alice\n    key:\n      - k\ngroups:\n  admin:\n    - alice\nsecrets: []\n",
		},
		{
			name: "no groups at all",
			yaml: "users:\n  - name: alice\n    key:\n      - k\nsecrets: []\n",
		},
		{
			name: "no users at all",
			yaml: "groups:\n  admin:\n    - alice\nsecrets: []\n",
			want: []string{"admin/alice"},
		},
		{
			name: "typo in member name",
			yaml: "users:\n  - name: alice\n    key:\n      - k\ngroups:\n  admin:\n    - alicce\nsecrets: []\n",
			want: []string{"admin/alicce"},
		},
		{
			name: "admin group is not exempt",
			yaml: "users:\n  - name: alice\n    key:\n      - k\ngroups:\n  admin:\n    - alice\n    - ghost\nsecrets: []\n",
			want: []string{"admin/ghost"},
		},
		{
			name: "every problem reported, groups sorted",
			yaml: "users:\n  - name: alice\n    key:\n      - k\n" +
				"groups:\n  zeta:\n    - ghost1\n  admin:\n    - alice\n    - ghost2\nsecrets: []\n",
			want: []string{"admin/ghost2", "zeta/ghost1"},
		},
		{
			name: "member of one group known, of another not",
			yaml: "users:\n  - name: alice\n    key:\n      - k\n" +
				"groups:\n  admin:\n    - alice\n  devs:\n    - alice\n    - bob\nsecrets: []\n",
			want: []string{"devs/bob"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main := writeConfig(t, tt.yaml)

			cr, err := loadConfig(t, main)
			if len(tt.want) == 0 {
				require.NoError(t, err)
				require.NoError(t, cr.Validate())
				return
			}

			// Load must refuse the config outright.
			require.Error(t, err)

			var got []string
			for _, e := range flattenJoined(err) {
				var ugm *UnknownGroupMemberError
				if errors.As(e, &ugm) {
					got = append(got, ugm.Group+"/"+ugm.User)
					require.Equal(t, "sesam.yml", ugm.Path)
				}
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// TestValidate_AnchoredGroupMembers checks the validation sees through aliases
// rather than comparing raw nodes.
func TestValidate_AnchoredGroupMembers(t *testing.T) {
	main := writeConfig(t, "x-team: &team\n  - alice\n"+
		"users:\n  - name: alice\n    key:\n      - k\n"+
		"groups:\n  admin: *team\nsecrets: []\n")

	_, err := loadConfig(t, main)
	require.NoError(t, err)
}

// TestValidate_SaveRejectsInconsistentConfig covers the Save-side assertion:
// killing a user must not leave that user behind in a group.
func TestValidate_SaveRejectsInconsistentConfig(t *testing.T) {
	main := writeConfig(t, "users:\n  - name: alice\n    key:\n      - k\n  - name: bob\n    key:\n      - k\n"+
		"groups:\n  admin:\n    - alice\n  devs:\n    - alice\n    - bob\nsecrets: []\n")

	cr, err := loadConfig(t, main)
	require.NoError(t, err)

	require.NoError(t, cr.UserKill("bob"))
	require.NoError(t, cr.Save())

	// Reloading proves the written file is self-consistent.
	reloaded, err := loadConfig(t, main)
	require.NoError(t, err)

	groups, err := reloaded.Groups()
	require.NoError(t, err)
	require.Equal(t, map[string][]string{"admin": {"alice"}, "devs": {"alice"}}, groups)
}

// flattenJoined unwraps an errors.Join tree into its leaves.
func flattenJoined(err error) []error {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []error{err}
	}

	var out []error
	for _, e := range joined.Unwrap() {
		out = append(out, flattenJoined(e)...)
	}
	return out
}
