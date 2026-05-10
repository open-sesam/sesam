package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// buildTestUserManager creates a UserManager backed by a fresh audit log with admin as the signer.
func buildTestUserManager(t *testing.T) (*UserManager, *testUser) {
	t.Helper()
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	if err := verify(state); err != nil {
		t.Fatal(err)
	}

	secMgr, err := BuildSecretManager(
		sesamDir, Identities{admin.Identity}, admin.Signer, kr, al, state,
	)
	if err != nil {
		t.Fatal(err)
	}

	um, err := BuildUserManager(sesamDir, admin.Signer, al, state, secMgr)
	if err != nil {
		t.Fatal(err)
	}

	return um, admin
}

func TestBuildUserManagerUnknownSigner(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))

	secMgr, err := BuildSecretManager(
		sesamDir, Identities{admin.Identity}, admin.Signer, kr, al, state,
	)
	require.NoError(t, err)

	stranger := newTestUser(t, "stranger")
	_, err = BuildUserManager(sesamDir, stranger.Signer, al, state, secMgr)
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
		PubKeys:     []string{bob.Recipient.String()},
		SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))

	secMgr, err := BuildSecretManager(
		sesamDir, Identities{bob.Identity}, bob.Signer, kr, al, state,
	)
	require.NoError(t, err)

	um, err := BuildUserManager(sesamDir, bob.Signer, al, state, secMgr)
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
		PubKeys:     []string{bob.Recipient.String()},
		SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))

	secMgr, err := BuildSecretManager(
		sesamDir, Identities{bob.Identity}, bob.Signer, kr, al, state,
	)
	require.NoError(t, err)

	um, err := BuildUserManager(sesamDir, bob.Signer, al, state, secMgr)
	require.NoError(t, err)

	err = um.KillUsers("admin")
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

// Auto-reseal-on-tell: bringing a new user into a group that already
// owns secrets must re-encrypt those secrets to include them, so a
// `sesam tell` is enough - no separate `sesam seal` round-trip.
func TestTellUserResealsForNewRecipient(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))

	secMgr, err := BuildSecretManager(
		sesamDir, Identities{admin.Identity}, admin.Signer, kr, al, state,
	)
	require.NoError(t, err)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(sesamDir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	writeSecret(t, sesamDir, "secrets/api", "shared")
	require.NoError(t, secMgr.AddSecret("secrets/api", []string{"dev", "admin"}))
	require.NoError(t, secMgr.SealAll()) // sealed for admin only; "dev" is empty

	um, err := BuildUserManager(sesamDir, admin.Signer, al, state, secMgr)
	require.NoError(t, err)

	bob := newTestUser(t, "bob")
	require.NoError(t, um.TellUser(
		context.Background(),
		"bob",
		[]string{bob.Recipient.String()},
		[]string{"dev"},
	))

	// Bob should now be able to decrypt the on-disk ciphertext using
	// nothing more than his identity. Before the auto-reseal he
	// would not be a recipient of the existing footer.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/api")))
	cryptFd, err := os.Open(filepath.Join(sesamDir, ".sesam", "objects", "secrets/api.sesam"))
	require.NoError(t, err)
	defer cryptFd.Close()

	ok, err := RevealBlob(sesamDir, Identities{bob.Identity}, cryptFd, "secrets/api")
	require.NoError(t, err)
	require.True(t, ok, "bob must be a recipient after tell")

	got, err := os.ReadFile(filepath.Join(sesamDir, "secrets/api"))
	require.NoError(t, err)
	require.Equal(t, "shared", string(got))
}

// Auto-reseal-on-kill: removing a user from the access list must
// re-encrypt every secret they had access to, so they cannot decrypt
// the *current* ciphertext even if their identity material is intact.
// (Old git-history ciphertext is unavoidably still readable; that
// limitation is documented in design.md.)
func TestKillUserResealsWithoutKilledRecipient(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))

	secMgr, err := BuildSecretManager(
		sesamDir, Identities{admin.Identity}, admin.Signer, kr, al, state,
	)
	require.NoError(t, err)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(sesamDir))
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	um, err := BuildUserManager(sesamDir, admin.Signer, al, state, secMgr)
	require.NoError(t, err)

	bob := newTestUser(t, "bob")
	require.NoError(t, um.TellUser(
		context.Background(),
		"bob",
		[]string{bob.Recipient.String()},
		[]string{"dev"},
	))

	writeSecret(t, sesamDir, "secrets/api", "shared")
	require.NoError(t, secMgr.AddSecret("secrets/api", []string{"dev", "admin"}))
	require.NoError(t, secMgr.SealAll())

	// Sanity: bob can decrypt before kill.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/api")))
	cryptPath := filepath.Join(sesamDir, ".sesam", "objects", "secrets/api.sesam")
	fd, err := os.Open(cryptPath)
	require.NoError(t, err)
	ok, err := RevealBlob(sesamDir, Identities{bob.Identity}, fd, "secrets/api")
	_ = fd.Close()
	require.NoError(t, err)
	require.True(t, ok, "bob should be a recipient before kill")

	// Kill bob. Auto-reseal must drop him from the recipient list.
	require.NoError(t, um.KillUsers("bob"))

	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/api")))
	fd, err = os.Open(cryptPath)
	require.NoError(t, err)
	defer fd.Close()
	ok, err = RevealBlob(sesamDir, Identities{bob.Identity}, fd, "secrets/api")
	require.NoError(t, err)
	require.False(t, ok, "killed user must not be a recipient of the resealed file")
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
