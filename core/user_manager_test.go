package core

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildTestUserManager creates a UserManager backed by a fresh audit log with admin as the signer.
func buildTestUserManager(t *testing.T) (*UserManager, *testUser) {
	t.Helper()
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	state := &VerifiedState{auditLog: al, keyring: EmptyKeyring()}
	if err := verify(state); err != nil {
		t.Fatal(err)
	}

	um, err := BuildUserManager(sesamDir, admin.Signer, al, state)
	if err != nil {
		t.Fatal(err)
	}

	return um, admin
}

func TestBuildUserManagerUnknownSigner(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	state := &VerifiedState{auditLog: al, keyring: EmptyKeyring()}
	require.NoError(t, verify(state))

	stranger := newTestUser(t, "stranger")
	_, err := BuildUserManager(sesamDir, stranger.Signer, al, state)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

func TestTellUserSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")

	err := um.TellUser(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"})
	require.NoError(t, err)

	_, exists := um.state.UserExists("bob")
	require.True(t, exists)
}

func TestTellUserNonAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:        "bob",
		Groups:      []string{"dev"},
		PubKeys:     []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	state := &VerifiedState{auditLog: al, keyring: EmptyKeyring()}
	require.NoError(t, verify(state))

	um, err := BuildUserManager(sesamDir, bob.Signer, al, state)
	require.NoError(t, err)

	charlie := newTestUser(t, "charlie")
	err = um.TellUser(context.Background(), "charlie", []string{charlie.Recipient.String()}, []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestTellUserDuplicate(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")

	require.NoError(t, um.TellUser(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))

	err := um.TellUser(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"})
	require.Error(t, err, "re-adding an existing user should fail")
}

func TestTellUserInvalidName(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.TellUser(context.Background(), "Invalid User!", []string{}, []string{"dev"})
	require.Error(t, err)
}

func TestKillUsersSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")

	require.NoError(t, um.TellUser(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))
	_, exists := um.state.UserExists("bob")
	require.True(t, exists)

	require.NoError(t, um.KillUsers("bob"))
	_, exists = um.state.UserExists("bob")
	require.False(t, exists)
}

func TestKillUsersNonAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:        "bob",
		Groups:      []string{"dev"},
		PubKeys:     []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	state := &VerifiedState{auditLog: al, keyring: EmptyKeyring()}
	require.NoError(t, verify(state))

	um, err := BuildUserManager(sesamDir, bob.Signer, al, state)
	require.NoError(t, err)

	err = um.KillUsers("admin")
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestShowUserSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)

	var buf bytes.Buffer
	ok, err := um.ShowUser("admin", &buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.Contains(t, buf.String(), "admin")
}

func TestShowUserNotFound(t *testing.T) {
	um, _ := buildTestUserManager(t)

	ok, err := um.ShowUser("nobody", &bytes.Buffer{})
	require.NoError(t, err)
	require.False(t, ok)
}
