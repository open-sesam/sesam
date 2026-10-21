package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUserKill_Groups covers UserKill's group-membership cleanup, including
// members reachable only through a YAML anchor/alias rather than listed
// directly in a group's own sequence.
func TestUserKill_Groups(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		kill string
		want map[string][]string
	}{
		{
			name: "removes member from a plain group, keeps the rest",
			yaml: "users:\n  - name: alice\n    key:\n      - k\n  - name: bob\n    key:\n      - k\n" +
				"groups:\n  admin:\n    - alice\n  devs:\n    - alice\n    - bob\nsecrets: []\n",
			kill: "bob",
			want: map[string][]string{"admin": {"alice"}, "devs": {"alice"}},
		},
		{
			name: "prunes a group left with no members",
			yaml: "users:\n  - name: alice\n    key:\n      - k\n  - name: bob\n    key:\n      - k\n" +
				"groups:\n  admin:\n    - alice\n  devs:\n    - bob\nsecrets: []\n",
			kill: "bob",
			want: map[string][]string{"admin": {"alice"}},
		},
		{
			name: "removes member reachable only through an alias",
			yaml: "x-devs: &devs\n  - bob\n" +
				"users:\n  - name: alice\n    key:\n      - k\n  - name: bob\n    key:\n      - k\n" +
				"groups:\n  admin:\n    - alice\n  devs: *devs\nsecrets: []\n",
			kill: "bob",
			want: map[string][]string{"admin": {"alice"}, "devs": {}},
		},
		{
			name: "removes member from an anchor defined inline in another group",
			yaml: "users:\n  - name: alice\n    key:\n      - k\n  - name: bob\n    key:\n      - k\n" +
				"groups:\n  devs: &devs\n    - alice\n    - bob\n  ops: *devs\nsecrets: []\n",
			kill: "bob",
			want: map[string][]string{"devs": {"alice"}, "ops": {"alice"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			main := writeConfig(t, tt.yaml)

			cr, err := loadConfig(t, main)
			require.NoError(t, err)

			require.NoError(t, cr.UserKill(tt.kill))
			require.NoError(t, cr.Save())

			// Reloading proves the written file is self-consistent and that
			// the emptied/anchor-backed sequences still render as valid YAML.
			reloaded, err := loadConfig(t, main)
			require.NoError(t, err)

			groups, err := reloaded.Groups()
			require.NoError(t, err)
			require.Equal(t, tt.want, groups)
		})
	}
}
