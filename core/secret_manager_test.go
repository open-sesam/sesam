package core

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildSecretManager(t *testing.T) {
	mgr := testSecretManagerFull(t)
	require.Equal(t, "admin", mgr.Signer.UserName())
	require.Len(t, mgr.secrets, 1)
}

func TestAddSecret(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.SesamDir, "secrets/new", "new-content")

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets", "new"), []byte("blub"), 0o600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, mgr.AddSecret("secrets/new", []string{"admin"}))
	require.Len(t, mgr.secrets, 2)

	_, exists := mgr.State.SecretExists("secrets/new")
	require.True(t, exists)
}

func TestAddSecretDuplicate(t *testing.T) {
	mgr := sealedSecretManager(t)

	// Adding the same path again should update recipients, not add a second entry.
	require.NoError(t, mgr.AddSecret("secrets/test", []string{"admin"}))
	require.Len(t, mgr.secrets, 1, "should not duplicate the secret in the internal list")
}

func TestChangeSecretGroups(t *testing.T) {
	mgr := sealedSecretManager(t)

	require.NoError(t, mgr.ChangeSecretGroups("secrets/test", []string{"admin", "dev"}))
	require.Len(t, mgr.secrets, 1, "should still be one secret")

	vs, exists := mgr.State.SecretExists("secrets/test")
	require.True(t, exists)
	require.Contains(t, vs.AccessGroups, "dev")
}

func TestAddSecretEmptyGroups(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.SesamDir, "secrets/bad", "data")

	err := mgr.AddSecret("secrets/bad", []string{})
	require.Error(t, err, "empty groups should fail verification")
}

func TestSealAllAndRevealAll(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.SesamDir, "secrets/test", "secret-content")

	require.NoError(t, mgr.SealAll())
	require.FileExists(t, mgr.cryptPath("secrets/test"))

	// Remove plaintext, then reveal.
	os.Remove(filepath.Join(mgr.SesamDir, "secrets/test"))
	require.NoError(t, mgr.RevealAll())

	got, _ := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/test"))
	require.Equal(t, "secret-content", string(got))
}

func TestSealAllFailsMissingPlaintext(t *testing.T) {
	mgr := testSecretManagerFull(t)
	// Don't write the secret file - seal should fail.
	err := mgr.SealAll()
	require.Error(t, err, "seal should fail when plaintext file is missing")
}

func TestRevealAllFailsMissingAge(t *testing.T) {
	mgr := testSecretManagerFull(t)
	// No .sesam files exist, so reveal should fail.
	err := mgr.RevealAll()
	require.Error(t, err, "reveal should fail when .sesam file is missing")
}

// sealedSecretManager returns a SecretManager with one sealed secret ("secrets/test")
// and cwd set to the repo dir. The .sesam file exists on disk.
func sealedSecretManager(t *testing.T) *SecretManager {
	t.Helper()
	mgr := testSecretManagerFull(t)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(mgr.SesamDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	writeSecret(t, mgr.SesamDir, "secrets/test", "secret-content")
	require.NoError(t, mgr.SealAll())
	return mgr
}

func TestRemoveSecret(t *testing.T) {
	mgr := sealedSecretManager(t)

	sesamPath := mgr.cryptPath("secrets/test")
	require.FileExists(t, sesamPath)

	require.NoError(t, mgr.RemoveSecret("secrets/test"))

	// Encrypted file should be gone.
	require.NoFileExists(t, sesamPath)

	// Audit log should record the removal.
	_, exists := mgr.State.SecretExists("secrets/test")
	require.False(t, exists, "secret should be removed from verified state")

	// Original plaintext should still exist.
	plaintext, err := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/test"))
	require.NoError(t, err)
	require.Equal(t, "secret-content", string(plaintext))
}

func TestRemoveSecretNotFound(t *testing.T) {
	mgr := testSecretManagerFull(t)
	err := mgr.RemoveSecret("secrets/nonexistent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such secret")
}

func TestRemoveSecretNotSealed(t *testing.T) {
	mgr := testSecretManagerFull(t)

	// Secret is in the manager's list but was never sealed - no .sesam file on disk.
	// RemoveAll is used internally, so missing files are not an error.
	// The audit entry should still be recorded.
	require.NoError(t, mgr.RemoveSecret("secrets/test"))
	_, exists := mgr.State.SecretExists("secrets/test")
	require.False(t, exists, "secret should be removed from verified state")
}

// Regression: RemoveSecret must call FeedEntry before touching the .sesam file.
// If the audit entry is rejected (caller lacks access), the encrypted file
// must survive - otherwise any authenticated user could corrupt the repo
// (audit log still lists the secret while its ciphertext is gone, breaking
// Verify / VerifyIntegrity for everyone).
func TestRemoveSecretKeepsFilesOnAuthFailure(t *testing.T) {
	mgr := sealedSecretManager(t) // admin manager with secrets/test sealed for "admin"

	sesamPath := mgr.cryptPath("secrets/test")
	require.FileExists(t, sesamPath)

	// Add non-admin bob (in "dev") to the audit log and re-verify.
	bob := newTestUser(t, "bob")
	_, err := mgr.AuditLog.AddEntry(mgr.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []string{bob.Recipient.String()}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)
	require.NoError(t, verify(mgr.State))

	bobMgr, err := BuildSecretManager(
		mgr.SesamDir, Identities{bob.Identity}, bob.Signer,
		mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)

	// Bob has no access to the admin-only secret. FeedEntry must reject,
	// and the on-disk files must NOT be deleted.
	require.Error(t, bobMgr.RemoveSecret("secrets/test"))

	require.FileExists(t, sesamPath, "ciphertext must survive rejected remove")
	_, exists := mgr.State.SecretExists("secrets/test")
	require.True(t, exists, "secret must remain in verified state")
}

func TestRevealBlobHappyPath(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/token", "top-secret")
	_, err := secret.Seal(secret.Mgr.cryptPath(secret.RevealedPath), "testuser")
	require.NoError(t, err)

	//nolint:gosec
	src, err := os.Open(mgr.cryptPath("secrets/token"))
	require.NoError(t, err)
	defer src.Close()

	os.Remove(filepath.Join(mgr.SesamDir, "secrets/token"))

	ok, err := RevealBlob(mgr.SesamDir, mgr.Identities, src, "secrets/token", nil, nil)
	require.NoError(t, err)
	require.True(t, ok)

	got, err := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/token"))
	require.NoError(t, err)
	require.Equal(t, "top-secret", string(got))
}

func TestRevealBlobNonRecipient(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/token", "top-secret")
	_, err := secret.Seal(secret.Mgr.cryptPath(secret.RevealedPath), "testuser")
	require.NoError(t, err)

	//nolint:gosec
	src, err := os.Open(mgr.cryptPath("secrets/token"))
	require.NoError(t, err)
	defer src.Close()

	stranger := newTestUser(t, "stranger")
	ok, err := RevealBlob(mgr.SesamDir, Identities{stranger.Identity}, src, "secrets/token", nil, nil)
	require.NoError(t, err)
	require.False(t, ok, "non-recipient should return (false, nil)")
}

func TestRevealBlobCorruptedFile(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/token", "top-secret")
	_, err := secret.Seal(secret.Mgr.cryptPath(secret.RevealedPath), "testuser")
	require.NoError(t, err)

	os.WriteFile(mgr.cryptPath("secrets/token"), []byte("not-a-valid-sesam-file"), 0o600)

	//nolint:gosec
	src, err := os.Open(mgr.cryptPath("secrets/token"))
	require.NoError(t, err)
	defer src.Close()

	ok, err := RevealBlob(mgr.SesamDir, mgr.Identities, src, "secrets/token", nil, nil)
	require.Error(t, err)
	require.False(t, ok)
}

// RevealBlob's policy split: an authorize-mismatch must NOT swallow the
// plaintext. The smudge filter relies on this to keep `git checkout`
// non-blocking against history written before the auth check shipped -
// the typed *AuthorizationError lets the caller pick a policy.
func TestRevealBlobAuthMismatchLandsPlaintext(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	kr := testKeyring(t, admin, bob)

	state := &VerifiedState{
		Users: []VerifiedUser{
			{Name: "admin", Groups: []string{"admin"}},
			{Name: "bob", Groups: []string{"dev"}},
		},
		Secrets: []VerifiedSecret{
			{RevealedPath: "secrets/admin-only", AccessGroups: []string{"admin"}},
		},
	}

	// Admin seals the secret normally.
	adminMgr := &SecretManager{
		SesamDir:   sesamDir,
		Identities: Identities{admin.Identity},
		Signer:     admin.Signer,
		Keyring:    kr,
		State:      state,
	}
	writeSecret(t, sesamDir, "secrets/admin-only", "real payload")
	legit := &secret{
		Mgr:          adminMgr,
		RevealedPath: "secrets/admin-only",
		Recipients:   kr.Recipients([]string{"admin", "bob"}),
	}
	cryptPath := adminMgr.cryptPath("secrets/admin-only")
	_, err := legit.Seal(cryptPath, "admin")
	require.NoError(t, err)

	// Bob substitutes the file (bypasses the seal-time guard, which
	// honest clients run but a patched client would not).
	bobMgr := &SecretManager{SesamDir: sesamDir, Signer: bob.Signer}
	writeSecret(t, sesamDir, "secrets/admin-only", "bob's substituted payload")
	bad := &secret{
		Mgr:          bobMgr,
		RevealedPath: "secrets/admin-only",
		Recipients:   kr.Recipients([]string{"admin", "bob"}),
	}
	_, err = bad.Seal(cryptPath, "bob")
	require.NoError(t, err)

	// Reveal via RevealBlob with kr+authorize wired up. Bob's name in
	// `sealed_by` is cryptographically valid (real bob signature) but
	// the access list does not include bob.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/admin-only")))
	src, err := os.Open(cryptPath)
	require.NoError(t, err)
	defer src.Close()

	ok, err := RevealBlob(
		sesamDir,
		Identities{admin.Identity},
		src,
		"secrets/admin-only",
		kr,
		state.SealerAuthorized,
	)
	require.True(t, ok, "plaintext must still land - smudge needs this")
	var authErr *BadSealerError
	require.True(t, errors.As(err, &authErr), "expected *AuthorizationError, got %T: %v", err, err)
	require.Equal(t, "bob", authErr.SealedBy)
	require.Equal(t, "secrets/admin-only", authErr.Path)

	// And the plaintext is the substituted bytes - the user can see
	// what was substituted, which combined with the loud log is the
	// signal they need to act.
	got, err := os.ReadFile(filepath.Join(sesamDir, "secrets/admin-only"))
	require.NoError(t, err)
	require.Equal(t, "bob's substituted payload", string(got))
}

func TestRemoveSecretThenSealAll(t *testing.T) {
	mgr := sealedSecretManager(t)

	// Add a second secret so SealAll still has work to do.
	writeSecret(t, mgr.SesamDir, "secrets/other", "other-content")
	require.NoError(t, mgr.AddSecret("secrets/other", []string{"admin"}))
	require.NoError(t, mgr.SealAll())

	require.NoError(t, mgr.RemoveSecret("secrets/test"))

	// SealAll after removal should only seal the remaining secret.
	writeSecret(t, mgr.SesamDir, "secrets/other", "other-content")
	require.NoError(t, mgr.SealAll())

	require.NoFileExists(t, mgr.cryptPath("secrets/test"))
	require.FileExists(t, mgr.cryptPath("secrets/other"))
}

func TestSealAllMultiple(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	for _, p := range []string{"secrets/a", "secrets/b"} {
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretChange{
			RevealedPath: p,
			Groups:       []string{"admin"},
		}), nil)
	}

	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "placeholder", FilesSealed: 0,
	}), nil)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	verify(state)

	mgr, _ := BuildSecretManager(
		sesamDir,
		Identities{admin.Identity},
		admin.Signer,
		kr,
		al,
		state,
	)

	writeSecret(t, sesamDir, "secrets/a", "aaa")
	writeSecret(t, sesamDir, "secrets/b", "bbb")

	require.NoError(t, mgr.SealAll())

	for _, p := range []string{"secrets/a", "secrets/b"} {
		require.FileExists(t, mgr.cryptPath(p))
	}
}

// A non-admin who does not have access to a secret must not be able to
// seal it via the normal path. The seal-time guard catches this even in
// honest clients - the cryptographic defense lives in revealStreamAndVerify.
func TestSealRejectsUnauthorizedUser(t *testing.T) {
	mgr := sealedSecretManager(t) // admin-only secrets/test

	bob := newTestUser(t, "bob")
	_, err := mgr.AuditLog.AddEntry(mgr.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []string{bob.Recipient.String()}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)
	require.NoError(t, verify(mgr.State))

	bobMgr, err := BuildSecretManager(
		mgr.SesamDir, Identities{bob.Identity}, bob.Signer,
		mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)

	// Bob has plaintext on disk (left over from sealedSecretManager)
	// but no access to secrets/test. SealAll must refuse.
	err = bobMgr.SealAll()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authorized")
}

func TestSealAllCleansStageAndMarker(t *testing.T) {
	mgr := sealedSecretManager(t)

	require.NoDirExists(t, mgr.stageDir(), "stage dir must be gone after a successful seal")
	require.NoFileExists(t, mgr.sealMarkerPath(), "marker must be gone after a successful seal")
}

// A failed seal must not touch the live objects/ tree.
func TestSealAllFailureLeavesObjectsUntouched(t *testing.T) {
	mgr := sealedSecretManager(t) // writes secrets/test sealed

	original, err := os.ReadFile(mgr.cryptPath("secrets/test"))
	require.NoError(t, err)

	// Add a second secret with plaintext but never seal it; then remove
	// the plaintext. SealAll will iterate both: the first re-encrypts
	// fine, the second has neither plaintext nor ciphertext and must
	// abort the whole transaction. The live secrets/test ciphertext
	// must remain byte-identical.
	writeSecret(t, mgr.SesamDir, "secrets/missing", "x")
	require.NoError(t, mgr.AddSecret("secrets/missing", []string{"admin"}))
	require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, "secrets/missing")))

	err = mgr.SealAll()
	require.Error(t, err, "seal must fail when a secret has neither plaintext nor ciphertext")

	current, err := os.ReadFile(mgr.cryptPath("secrets/test"))
	require.NoError(t, err)
	require.Equal(t, original, current, "live ciphertext must be unchanged on seal failure")

	require.NoDirExists(t, mgr.stageDir(), "stage dir must be cleaned on failure")
	require.NoFileExists(t, mgr.sealMarkerPath(), "marker must be removed when swap never happened")
}

// A non-admin who does not have access to a secret must still be able to seal:
// they re-encrypt what they can decrypt and copy the existing ciphertext for
// what they cannot. The copied ciphertext must be byte-identical and the
// RootHash must remain consistent with what is on disk.
func TestSealAllNonAdminPreservesCiphertextItCannotDecrypt(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	// Add bob to the dev group.
	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:        "bob",
		Groups:      []string{"dev"},
		PubKeys:     []string{bob.Recipient.String()},
		SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	// Two secrets: one admin-only (bob cannot decrypt), one shared with dev.
	for _, sc := range []DetailSecretChange{
		{RevealedPath: "secrets/admin-only", Groups: []string{"admin"}},
		{RevealedPath: "secrets/dev-shared", Groups: []string{"dev"}},
	} {
		_, err = al.AddEntry(admin.Signer, newAuditEntry("admin", &sc), nil)
		require.NoError(t, err)
	}

	_, err = al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "placeholder", FilesSealed: 0,
	}), nil)
	require.NoError(t, err)

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: al, keyring: kr}
	require.NoError(t, verify(state))

	adminMgr, err := BuildSecretManager(
		sesamDir, Identities{admin.Identity}, admin.Signer, kr, al, state,
	)
	require.NoError(t, err)

	writeSecret(t, sesamDir, "secrets/admin-only", "admin payload")
	writeSecret(t, sesamDir, "secrets/dev-shared", "dev payload")
	require.NoError(t, adminMgr.SealAll())

	adminOnlyBefore, err := os.ReadFile(adminMgr.cryptPath("secrets/admin-only"))
	require.NoError(t, err)
	devSharedBefore, err := os.ReadFile(adminMgr.cryptPath("secrets/dev-shared"))
	require.NoError(t, err)

	// Bob takes over. He has plaintext only for the dev secret. Wipe both
	// plaintexts here and recreate just the dev one to make the scenario
	// explicit.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/admin-only")))
	writeSecret(t, sesamDir, "secrets/dev-shared", "dev payload")

	bobMgr, err := BuildSecretManager(
		sesamDir, Identities{bob.Identity}, bob.Signer, kr, al, state,
	)
	require.NoError(t, err)

	require.NoError(t, bobMgr.SealAll(), "non-admin should be able to seal")

	adminOnlyAfter, err := os.ReadFile(bobMgr.cryptPath("secrets/admin-only"))
	require.NoError(t, err)
	require.Equal(t, adminOnlyBefore, adminOnlyAfter,
		"admin-only ciphertext must be copied byte-for-byte by a non-recipient")

	devSharedAfter, err := os.ReadFile(bobMgr.cryptPath("secrets/dev-shared"))
	require.NoError(t, err)
	require.NotEqual(t, devSharedBefore, devSharedAfter,
		"dev-shared must be re-encrypted by bob (age uses fresh randomness)")

	require.NoDirExists(t, bobMgr.stageDir())
	require.NoFileExists(t, bobMgr.sealMarkerPath())
}

func TestBuildSecretManagerClearsLeftoverStage(t *testing.T) {
	mgr := testSecretManagerFull(t)

	// Plant a stale stage dir as if a previous seal had crashed before the swap.
	stage := mgr.stageDir()
	require.NoError(t, os.MkdirAll(filepath.Join(stage, "junk"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stage, "junk", "leftover"), []byte("x"), 0o600))

	// Re-build the manager - recovery should clear the stage dir.
	mgr2, err := BuildSecretManager(
		mgr.SesamDir, mgr.Identities, mgr.Signer, mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)
	require.NoDirExists(t, mgr2.stageDir())
}

func TestBuildSecretManagerKeepsOrphanMarker(t *testing.T) {
	mgr := testSecretManagerFull(t)

	// Marker without stage = "swap completed but audit entry never made it".
	// Recovery should leave the marker in place so the next load surfaces it.
	require.NoError(t, os.WriteFile(mgr.sealMarkerPath(), []byte("some-hash\n"), 0o600))

	mgr2, err := BuildSecretManager(
		mgr.SesamDir, mgr.Identities, mgr.Signer, mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)
	require.FileExists(t, mgr2.sealMarkerPath(),
		"orphan marker must persist so the inconsistency is not silently forgotten")
}

func TestBuildSecretManagerDropsMarkerWhenStageStillPresent(t *testing.T) {
	mgr := testSecretManagerFull(t)

	require.NoError(t, os.MkdirAll(mgr.stageDir(), 0o700))
	require.NoError(t, os.WriteFile(mgr.sealMarkerPath(), []byte("stale\n"), 0o600))

	mgr2, err := BuildSecretManager(
		mgr.SesamDir, mgr.Identities, mgr.Signer, mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)
	require.NoDirExists(t, mgr2.stageDir())
	require.NoFileExists(t, mgr2.sealMarkerPath(),
		"marker must be dropped when stage is also present (swap never committed)")
}

func TestShowSecretSuccessSesamPath(t *testing.T) {
	mgr := testSecretManager(t)
	s := testSecret(t, mgr, "secrets/tok", "content123")
	_, err := s.Seal(s.Mgr.cryptPath(s.RevealedPath), "testuser")
	require.NoError(t, err)

	var buf bytes.Buffer
	ok, err := ShowSecret(mgr.SesamDir, mgr.Identities, mgr.cryptPath("secrets/tok"), &buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "content123", buf.String())
}

func TestShowSecretNotFound(t *testing.T) {
	mgr := testSecretManager(t)
	ok, err := ShowSecret(mgr.SesamDir, mgr.Identities, "/no/such/file.sesam", &bytes.Buffer{})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestShowSecretRevealedPathConvenience(t *testing.T) {
	mgr := testSecretManager(t)
	s := testSecret(t, mgr, "secrets/tok", "content123")
	_, err := s.Seal(s.Mgr.cryptPath(s.RevealedPath), "testuser")
	require.NoError(t, err)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(mgr.SesamDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	var buf bytes.Buffer
	ok, err := ShowSecret(mgr.SesamDir, mgr.Identities, "secrets/tok", &buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "content123", buf.String())
}
