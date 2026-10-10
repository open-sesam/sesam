package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

func TestShortPubKeys(t *testing.T) {
	tests := []struct {
		name string
		pubs []core.UserPubKey
		want string
	}{
		{
			name: "short spec passes through untouched",
			pubs: []core.UserPubKey{{Key: "github:bob"}},
			want: "github:bob",
		},
		{
			name: "several keys are joined",
			pubs: []core.UserPubKey{{Key: "github:bob"}, {Key: "github:alice"}},
			want: "github:bob, github:alice",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, shortPubKeys(tc.pubs, false))
		})
	}
}

// TestShortPubKeysDistinguishesSSHKeys regresses a 12-char cut printing two
// different SSH keys identically: ssh-ed25519's wire format repeats the
// algorithm name inside the base64 blob itself, so real keys share an exact
// 25-character prefix before their actual material begins.
func TestShortPubKeysDistinguishesSSHKeys(t *testing.T) {
	const header = "AAAAC3NzaC1lZDI1NTE5AAAAI" // shared by every ssh-ed25519 key
	key1 := "ssh-ed25519 " + header + "Abcdefghijklmnopqrstuvwxyz1234567890 user1@host"
	key2 := "ssh-ed25519 " + header + "Zyxwvutsrqponmlkjihgfedcba0987654321 user2@host"

	got1 := shortPubKeys([]core.UserPubKey{{Key: key1}}, false)
	got2 := shortPubKeys([]core.UserPubKey{{Key: key2}}, false)

	require.NotEqual(t, got1, got2, "two different SSH keys must not render identically")
}

func TestShortPubKeysFull(t *testing.T) {
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdefghijklmnopqrstuvwxyz1234567890 user@host"

	require.Equal(t, key, shortPubKeys([]core.UserPubKey{{Key: key}}, true), "full must not truncate")
}

// TestUserGroupsNeverFakesAdmin regresses groupsOrAdmin being shared between
// users and secrets: an empty access-group list legitimately means "admin
// only" for a secret, but a user's Groups is never legitimately empty, so
// rendering an empty one as "admin" would show a de-privileged user as if
// they had just been made an admin - the opposite of the truth.
func TestUserGroupsNeverFakesAdmin(t *testing.T) {
	require.Equal(t, "", userGroups(nil))
	require.Equal(t, "", userGroups([]string{}))
	require.Equal(t, "dev, ops", userGroups([]string{"dev", "ops"}))
}

func TestAccessGroupsOrAdmin(t *testing.T) {
	require.Equal(t, "admin", accessGroupsOrAdmin(nil))
	require.Equal(t, "admin", accessGroupsOrAdmin([]string{}))
	require.Equal(t, "admin, dev", accessGroupsOrAdmin([]string{"admin", "dev"}))
}
