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

func TestUserTellSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")

	err := um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"})
	require.NoError(t, err)

	_, exists := um.state.UserExists("bob")
	require.True(t, exists)
}

func TestUserTellNonAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
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
	err = um.UserTell(context.Background(), "charlie", []string{charlie.Recipient.String()}, []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestUserTellDuplicate(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")

	require.NoError(t, um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))

	err := um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"})
	require.Error(t, err, "re-adding an existing user should fail")
}

func TestUserTellInvalidName(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.UserTell(context.Background(), "Invalid User!", []string{}, []string{"dev"})
	require.Error(t, err)
}

func TestUserKillSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")

	require.NoError(t, um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))
	_, exists := um.state.UserExists("bob")
	require.True(t, exists)

	require.NoError(t, um.UserKill("bob"))
	_, exists = um.state.UserExists("bob")
	require.False(t, exists)
}

func TestUserKillNonAdmin(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
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

	err = um.UserKill("admin")
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

// Tell no longer auto-seals (reseal moved to the CLI). A freshly told user
// therefore cannot read existing ciphertext until an explicit seal re-encrypts
// it to include them. This asserts both halves: invisible before the seal,
// readable after.
func TestTellThenSealGivesNewRecipientAccess(t *testing.T) {
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
	require.NoError(t, secMgr.SecretAdd("secrets/api", []string{"dev", "admin"}))
	require.NoError(t, secMgr.SealAll()) // sealed for admin only; "dev" is empty

	um, err := BuildUserManager(sesamDir, admin.Signer, al, state, secMgr)
	require.NoError(t, err)

	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(
		context.Background(),
		"bob",
		[]string{bob.Recipient.String()},
		[]string{"dev"},
	))

	cryptPath := filepath.Join(sesamDir, ".sesam", "objects", "secrets/api.sesam")

	// Before an explicit seal, the ciphertext is still admin-only: bob cannot read it.
	fd, err := os.Open(cryptPath)
	require.NoError(t, err)
	ok, err := RevealBlob(sesamDir, Identities{bob.Identity}, fd, "secrets/api", nil, nil)
	_ = fd.Close()
	require.NoError(t, err)
	require.False(t, ok, "bob must not be a recipient before an explicit seal")

	// An explicit seal re-encrypts to include the new "dev" member.
	require.NoError(t, secMgr.SealAll())

	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/api")))
	fd, err = os.Open(cryptPath)
	require.NoError(t, err)
	defer fd.Close()
	ok, err = RevealBlob(sesamDir, Identities{bob.Identity}, fd, "secrets/api", nil, nil)
	require.NoError(t, err)
	require.True(t, ok, "bob must be a recipient after the explicit seal")

	got, err := os.ReadFile(filepath.Join(sesamDir, "secrets/api"))
	require.NoError(t, err)
	require.Equal(t, "shared", string(got))
}

// Kill no longer auto-seals; the caller must seal to evict the killed user
// from the ciphertext. After kill + an explicit seal they can no longer
// decrypt the *current* file, even with intact identity material.
// (Old git-history ciphertext is unavoidably still readable; that
// limitation is documented in design.md.)
func TestKillThenSealEvictsRecipient(t *testing.T) {
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
	require.NoError(t, um.UserTell(
		context.Background(),
		"bob",
		[]string{bob.Recipient.String()},
		[]string{"dev"},
	))

	writeSecret(t, sesamDir, "secrets/api", "shared")
	require.NoError(t, secMgr.SecretAdd("secrets/api", []string{"dev", "admin"}))
	require.NoError(t, secMgr.SealAll())

	// Sanity: bob can decrypt before kill.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/api")))
	cryptPath := filepath.Join(sesamDir, ".sesam", "objects", "secrets/api.sesam")
	fd, err := os.Open(cryptPath)
	require.NoError(t, err)
	ok, err := RevealBlob(sesamDir, Identities{bob.Identity}, fd, "secrets/api", nil, nil)
	_ = fd.Close()
	require.NoError(t, err)
	require.True(t, ok, "bob should be a recipient before kill")

	// Kill does not auto-seal; an explicit seal must drop bob from the recipients.
	require.NoError(t, um.UserKill("bob"))
	require.NoError(t, secMgr.SealAll())

	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/api")))
	fd, err = os.Open(cryptPath)
	require.NoError(t, err)
	defer fd.Close()
	ok, err = RevealBlob(sesamDir, Identities{bob.Identity}, fd, "secrets/api", nil, nil)
	require.NoError(t, err)
	require.False(t, ok, "killed user must not be a recipient of the resealed file")
}

// nonAdminUserManager returns a UserManager signed by bob (a non-admin "dev"
// user) sharing one audit log and state with the admin who created the repo.
// Used to exercise the admin-only guards on rename / change-groups.
func nonAdminUserManager(t *testing.T) *UserManager {
	t.Helper()
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
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
	return um
}

func TestUserRenameSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))

	require.NoError(t, um.UserRename("bob", "robert"))

	_, exists := um.state.UserExists("bob")
	require.False(t, exists, "old name must be gone from state")
	vu, exists := um.state.UserExists("robert")
	require.True(t, exists, "new name must exist in state")
	require.Equal(t, []string{"dev"}, vu.Groups, "groups must carry over to the new name")

	// The keyring entry moved with the rename, so recipients resolve under
	// the new name and no longer under the old one.
	require.Len(t, um.secMgr.Keyring.Recipients([]string{"robert"}), 1)
	require.Empty(t, um.secMgr.Keyring.Recipients([]string{"bob"}))
}

func TestUserRenameNonAdmin(t *testing.T) {
	um := nonAdminUserManager(t)

	err := um.UserRename("admin", "root")
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestUserRenameNotFound(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.UserRename("ghost", "phantom")
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

func TestUserRenameToExistingName(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))

	err := um.UserRename("bob", "admin")
	require.Error(t, err)
	require.Contains(t, err.Error(), "already exists")
}

func TestUserRenameInvalidNewName(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.UserRename("admin", "Invalid Name!")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid new user name")
}

func TestUserChangeGroupsSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"}))

	require.NoError(t, um.UserChangeGroups("bob", []string{"dev", "ops"}))

	vu, exists := um.state.UserExists("bob")
	require.True(t, exists)
	require.ElementsMatch(t, []string{"dev", "ops"}, vu.Groups)

	// Membership changes require a re-seal so ciphertext recipients catch up.
	require.NotZero(t, um.state.SealRequiredSeqID, "group change must mark a seal as pending")
}

func TestUserChangeGroupsNonAdmin(t *testing.T) {
	um := nonAdminUserManager(t)

	err := um.UserChangeGroups("admin", []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestUserChangeGroupsUnknownUser(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.UserChangeGroups("ghost", []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

// Stripping the admin group from the sole admin would lock everyone out of
// future admin operations, so verify must refuse it.
func TestUserChangeGroupsLastAdmin(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.UserChangeGroups("admin", []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "last admin")
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

// --- add / remove recipients ----------------------------------------------

func TestUserAddRecipientSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(
		context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"},
	))

	// A second key for bob, e.g. a new device.
	bobDevice := newTestUser(t, "bob")
	require.NoError(t, um.UserAddRecipient(
		context.Background(), "bob", []string{bobDevice.Recipient.String()},
	))

	vu, exists := um.state.UserExists("bob")
	require.True(t, exists)
	require.Len(t, vu.Recps, 2, "state must hold both of bob's recipients")
	require.Len(t, um.state.keyring.Recipients([]string{"bob"}), 2)

	// The audit key was re-encrypted, so the new key alone can load and replay
	// the log.
	al := loadAuditLog(t, um.sesamDir, bobDevice)
	_, err := VerifyChain(al, EmptyKeyring(), nil)
	require.NoError(t, err, "newly added recipient must be able to decrypt and replay the log")
}

func TestUserAddRecipientNonAdmin(t *testing.T) {
	um := nonAdminUserManager(t)
	intruder := newTestUser(t, "intruder")

	err := um.UserAddRecipient(context.Background(), "admin", []string{intruder.Recipient.String()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestUserAddRecipientUnknownUser(t *testing.T) {
	um, _ := buildTestUserManager(t)
	ghost := newTestUser(t, "ghost")

	err := um.UserAddRecipient(context.Background(), "ghost", []string{ghost.Recipient.String()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}

func TestUserRmRecipientSuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	bobDevice := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(
		context.Background(), "bob",
		[]string{bob.Recipient.String(), bobDevice.Recipient.String()},
		[]string{"dev"},
	))
	require.Len(t, um.state.keyring.Recipients([]string{"bob"}), 2)

	require.NoError(t, um.UserRmRecipient(
		context.Background(), "bob", []string{bobDevice.Recipient.String()},
	))

	vu, _ := um.state.UserExists("bob")
	require.Len(t, vu.Recps, 1)
	require.True(t, vu.Recps[0].Equal(bob.Recipient), "the surviving recipient must be the one we kept")

	// The audit key was rotated: the removed device is locked out of the log...
	_, err := LoadAuditLog(um.sesamDir, Identities{bobDevice.Identity})
	require.Error(t, err, "removed recipient must no longer decrypt the rotated audit log")

	// ...while a surviving recipient can still load and replay it.
	al := loadAuditLog(t, um.sesamDir, bob)
	_, err = VerifyChain(al, EmptyKeyring(), nil)
	require.NoError(t, err)
}

func TestUserRmRecipientLastRecipient(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(
		context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"},
	))

	err := um.UserRmRecipient(context.Background(), "bob", []string{bob.Recipient.String()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "only one")

	// The rejected removal must leave the last recipient intact.
	require.Len(t, um.state.keyring.Recipients([]string{"bob"}), 1)
}

func TestUserRmRecipientNonAdmin(t *testing.T) {
	um := nonAdminUserManager(t)
	intruder := newTestUser(t, "intruder")

	err := um.UserRmRecipient(context.Background(), "admin", []string{intruder.Recipient.String()})
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

// --- regenerate signing key ------------------------------------------------

func TestUserRegenerateSignKeySuccess(t *testing.T) {
	um, _ := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(
		context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"},
	))

	before, _ := um.state.UserExists("bob")
	oldPub := before.SignPubKey
	// The signing key generated at tell time, loaded from disk before regen.
	oldSigner, err := LoadSignKey(um.sesamDir, "bob", bob.Identity)
	require.NoError(t, err)

	require.NoError(t, um.UserRegenerateSignKey("bob"))

	after, _ := um.state.UserExists("bob")
	require.NotEqual(t, oldPub, after.SignPubKey, "regen must change the recorded signing pubkey")

	// The on-disk signing key matches the newly recorded pubkey and verifies as
	// bob - this catches both the encode/decode bug and a log/disk mismatch.
	newSigner, err := LoadSignKey(um.sesamDir, "bob", bob.Identity)
	require.NoError(t, err)
	require.Equal(t, after.SignPubKey, MulticodeEncode(newSigner.PublicKey(), MhEd25519Pub),
		"on-disk signing key must match the pubkey recorded in the audit log")

	data := []byte("regen check")
	sig, err := newSigner.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)
	who, err := um.state.keyring.Verify(SesamDomainSignSecretTag, data, sig, "bob")
	require.NoError(t, err)
	require.Equal(t, "bob", who)

	// The pre-regen signing key was replaced and must no longer verify.
	oldSig, err := oldSigner.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)
	_, err = um.state.keyring.Verify(SesamDomainSignSecretTag, data, oldSig, "bob")
	require.Error(t, err, "the replaced signing key must no longer verify")
}

func TestUserRegenerateSignKeyReloads(t *testing.T) {
	um, admin := buildTestUserManager(t)
	bob := newTestUser(t, "bob")
	require.NoError(t, um.UserTell(
		context.Background(), "bob", []string{bob.Recipient.String()}, []string{"dev"},
	))
	require.NoError(t, um.UserRegenerateSignKey("bob"))

	// Replaying the log from disk (including the regenerate entry) must verify
	// cleanly and yield the new pubkey.
	al := loadAuditLog(t, um.sesamDir, admin)
	state, err := VerifyChain(al, EmptyKeyring(), nil)
	require.NoError(t, err)

	reloaded, ok := state.UserExists("bob")
	require.True(t, ok)
	after, _ := um.state.UserExists("bob")
	require.Equal(t, after.SignPubKey, reloaded.SignPubKey)
}

func TestUserRegenerateSignKeyNonAdmin(t *testing.T) {
	um := nonAdminUserManager(t)

	err := um.UserRegenerateSignKey("admin")
	require.Error(t, err)
	require.Contains(t, err.Error(), "admin")
}

func TestUserRegenerateSignKeyUnknownUser(t *testing.T) {
	um, _ := buildTestUserManager(t)

	err := um.UserRegenerateSignKey("ghost")
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not exist")
}
