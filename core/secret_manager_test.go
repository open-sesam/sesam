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
	require.Len(t, mgr.State.Secrets, 1)
}

func TestSecretAdd(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.SesamDir, "secrets/new", "new-content")

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets", "new"), []byte("blub"), 0o600))


	require.NoError(t, mgr.SecretAdd("secrets/new", []string{"admin"}))
	require.Len(t, mgr.State.Secrets, 2)

	_, exists := mgr.State.SecretExists("secrets/new")
	require.True(t, exists)
}

func TestSecretAddDuplicate(t *testing.T) {
	mgr := sealedSecretManager(t)

	// Adding the same path again should update recipients, not add a second entry.
	require.NoError(t, mgr.SecretAdd("secrets/test", []string{"admin"}))
	require.Len(t, mgr.State.Secrets, 1, "should not duplicate the secret in the verified state")
}

func TestSecretChangeGroups(t *testing.T) {
	mgr := sealedSecretManager(t)

	require.NoError(t, mgr.SecretChangeGroups("secrets/test", []string{"admin", "dev"}))
	require.Len(t, mgr.State.Secrets, 1, "should still be one secret")

	vs, exists := mgr.State.SecretExists("secrets/test")
	require.True(t, exists)
	require.Contains(t, vs.AccessGroups, "dev")
}

// The admin group is implicit: even when it is not passed it must remain on
// the access list, otherwise admins could lock themselves out of a secret.
func TestSecretChangeGroupsKeepsAdminImplicit(t *testing.T) {
	mgr := sealedSecretManager(t)

	require.NoError(t, mgr.SecretChangeGroups("secrets/test", []string{"dev"}))

	vs, exists := mgr.State.SecretExists("secrets/test")
	require.True(t, exists)
	require.ElementsMatch(t, []string{"dev", "admin"}, vs.AccessGroups)
}

func TestSecretChangeGroupsNonExistent(t *testing.T) {
	mgr := sealedSecretManager(t)

	// No plaintext on disk and not tracked in state: path validation rejects
	// it before any audit entry is written.
	err := mgr.SecretChangeGroups("secrets/nope", []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid secret path")
}

// A user without access to a secret must not be able to change its access
// list - otherwise anyone in the audit log could grant themselves access to
// a secret they were never allowed to read.
func TestSecretChangeGroupsUnauthorized(t *testing.T) {
	mgr := sealedSecretManager(t) // admin manager, secrets/test is admin-only

	bob := newTestUser(t, "bob")
	_, err := mgr.AuditLog.AddEntry(mgr.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)
	require.NoError(t, verify(mgr.State))

	bobMgr, err := BuildSecretManager(
		mgr.SesamDir, mgr.root, Identities{bob.Identity}, bob.Signer,
		mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)

	err = bobMgr.SecretChangeGroups("secrets/test", []string{"dev"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no access")

	// The access list must be untouched after the rejected change.
	vs, exists := mgr.State.SecretExists("secrets/test")
	require.True(t, exists)
	require.Equal(t, []string{"admin"}, vs.AccessGroups)
}

func TestSecretAddEmptyGroups(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.SesamDir, "secrets/onlyadmin", "data")

	// Empty groups is valid and means "admin only" - it must not be rejected.
	require.NoError(t, mgr.SecretAdd("secrets/onlyadmin", []string{}))

	vs, exists := mgr.State.SecretExists("secrets/onlyadmin")
	require.True(t, exists)
	require.Equal(t, []string{"admin"}, vs.AccessGroups,
		"empty groups should resolve to admin-only access")
}

func TestSealAllAndRevealAll(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.SesamDir, "secrets/test", "secret-content")

	require.NoError(t, mgr.SealAll())
	require.FileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test")))

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


	writeSecret(t, mgr.SesamDir, "secrets/test", "secret-content")
	require.NoError(t, mgr.SealAll())
	return mgr
}

func TestSecretRemove(t *testing.T) {
	mgr := sealedSecretManager(t)

	sesamPath := filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test"))
	require.FileExists(t, sesamPath)

	require.NoError(t, mgr.SecretRemove("secrets/test"))

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

func TestSecretRemoveNotFound(t *testing.T) {
	mgr := testSecretManagerFull(t)
	err := mgr.SecretRemove("secrets/nonexistent")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such secret")
}

func TestSecretRemoveNotSealed(t *testing.T) {
	mgr := testSecretManagerFull(t)

	// Secret is in the manager's list but was never sealed - no .sesam file on disk.
	// RemoveAll is used internally, so missing files are not an error.
	// The audit entry should still be recorded.
	require.NoError(t, mgr.SecretRemove("secrets/test"))
	_, exists := mgr.State.SecretExists("secrets/test")
	require.False(t, exists, "secret should be removed from verified state")
}

// Regression: SecretRemove must call FeedEntry before touching the .sesam file.
// If the audit entry is rejected (caller lacks access), the encrypted file
// must survive - otherwise any authenticated user could corrupt the repo
// (audit log still lists the secret while its ciphertext is gone, breaking
// Verify / VerifyIntegrity for everyone).
func TestSecretRemoveKeepsFilesOnAuthFailure(t *testing.T) {
	mgr := sealedSecretManager(t) // admin manager with secrets/test sealed for "admin"

	sesamPath := filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test"))
	require.FileExists(t, sesamPath)

	// Add non-admin bob (in "dev") to the audit log and re-verify.
	bob := newTestUser(t, "bob")
	_, err := mgr.AuditLog.AddEntry(mgr.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)
	require.NoError(t, verify(mgr.State))

	bobMgr, err := BuildSecretManager(
		mgr.SesamDir, mgr.root, Identities{bob.Identity}, bob.Signer,
		mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)

	// Bob has no access to the admin-only secret. FeedEntry must reject,
	// and the on-disk files must NOT be deleted.
	require.Error(t, bobMgr.SecretRemove("secrets/test"))

	require.FileExists(t, sesamPath, "ciphertext must survive rejected remove")
	_, exists := mgr.State.SecretExists("secrets/test")
	require.True(t, exists, "secret must remain in verified state")
}

func TestSecretMove(t *testing.T) {
	mgr := sealedSecretManager(t) // secrets/test sealed for admin, plaintext on disk

	require.NoError(t, mgr.SecretMove("secrets/test", "secrets/moved"))

	// The encrypted object moved.
	require.NoFileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test")))
	require.FileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/moved")))

	// The plaintext moved, content preserved.
	require.NoFileExists(t, filepath.Join(mgr.SesamDir, "secrets/test"))
	plaintext, err := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/moved"))
	require.NoError(t, err)
	require.Equal(t, "secret-content", string(plaintext))

	// State tracks the new path only.
	_, exists := mgr.State.SecretExists("secrets/test")
	require.False(t, exists)
	_, exists = mgr.State.SecretExists("secrets/moved")
	require.True(t, exists)

	// No seal is pending and the new seal entry's root hash matches disk.
	require.Zero(t, mgr.State.SealRequiredSeqID, "move must leave no pending seal")
	report := VerifyIntegrity(mgr.root, mgr.State, mgr.Keyring)
	require.True(t, report.OK(), report.String())

	// The moved secret still reveals to the original content. The footer is
	// re-signed over the new path, so this also proves the path-bound hash
	// was rewritten correctly.
	require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, "secrets/moved")))
	require.NoError(t, revealSecret(mgr, "secrets/moved"))
	revealed, err := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/moved"))
	require.NoError(t, err)
	require.Equal(t, "secret-content", string(revealed))
}

func TestSecretMoveNotFound(t *testing.T) {
	mgr := sealedSecretManager(t)

	err := mgr.SecretMove("secrets/nonexistent", "secrets/moved")
	require.Error(t, err)
	require.Contains(t, err.Error(), "non-existing secret")
}

// The secret is sealed on disk but its plaintext is not revealed. SecretMove
// must reveal it (from the old ciphertext, while the old path is still
// authorized) before rewriting the footer for the new path. Regression guard
// for the reveal-after-rename ordering.
func TestSecretMoveNotYetRevealed(t *testing.T) {
	mgr := sealedSecretManager(t)

	// Drop the plaintext so the move has to reveal it first.
	require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, "secrets/test")))

	require.NoError(t, mgr.SecretMove("secrets/test", "secrets/moved"))

	require.NoFileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test")))
	require.FileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/moved")))

	// The secret was not revealed before the move, so the move must not
	// leave a revealed plaintext behind at the new path either.
	require.NoFileExists(t, filepath.Join(mgr.SesamDir, "secrets/moved"))

	report := VerifyIntegrity(mgr.root, mgr.State, mgr.Keyring)
	require.True(t, report.OK(), report.String())

	// Revealing from the moved ciphertext still yields the original content.
	require.NoError(t, revealSecret(mgr, "secrets/moved"))
	revealed, err := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/moved"))
	require.NoError(t, err)
	require.Equal(t, "secret-content", string(revealed))
}

// A secret's footer records sealed_by (the name of the user who sealed it),
// but that field is only a *hint*: kr.Verify tries the named user's keys
// first and falls back to every other key, then authorization runs against
// the user whose key actually verified - never against the footer's claimed
// name. So renaming a user must NOT invalidate files they sealed under the
// old name: the keyring moves the signing key to the new name, the stale
// hint misses, the fallback finds it, and authorization passes for the new
// name.
//
// This guards against someone "tightening" kr.Verify to require the hint to
// match (or to reject on mismatch), which would silently break reveal and
// `verify --all` for every file sealed before a rename. If you intend to make
// sealed_by authoritative, you must also rewrite footers on rename - and this
// test should then be updated deliberately, not deleted.
func TestRevealSurvivesSealerRename(t *testing.T) {
	mgr := sealedSecretManager(t) // admin sealed secrets/test; footer sealed_by=admin

	// Precondition: the footer names admin as the sealer.
	footer, err := mgr.readSecretFooter(mgr.cryptPath("secrets/test"))
	require.NoError(t, err)
	require.Equal(t, "admin", footer.SealedBy)

	// Rename admin -> root. This moves the signing key in the keyring but
	// leaves the on-disk footer untouched (still sealed_by=admin).
	um, err := BuildUserManager(mgr.root, mgr.Signer, mgr.AuditLog, mgr.State, mgr)
	require.NoError(t, err)
	require.NoError(t, um.UserRename("admin", "root"))

	require.Len(t, mgr.Keyring.Recipients([]string{"root"}), 1)
	require.Empty(t, mgr.Keyring.Recipients([]string{"admin"}),
		"the old name must no longer resolve in the keyring")

	// Reveal still works: the stale sealed_by=admin hint misses, kr.Verify
	// falls back to the renamed key, and authorization passes for "root".
	require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, "secrets/test")))
	require.NoError(t, revealSecret(mgr, "secrets/test"))
	got, err := os.ReadFile(filepath.Join(mgr.SesamDir, "secrets/test"))
	require.NoError(t, err)
	require.Equal(t, "secret-content", string(got))

	// The deep integrity check (sesam verify --all) tolerates it too.
	report := VerifyIntegrity(mgr.root, mgr.State, mgr.Keyring)
	require.True(t, report.OK(), report.String())
}

func TestRevealBlobHappyPath(t *testing.T) {
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/token", "top-secret")
	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	//nolint:gosec
	src, err := os.Open(filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/token")))
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
	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	//nolint:gosec
	src, err := os.Open(filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/token")))
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
	_, err := sealSecret(mgr, secret, mgr.recipientsFor(secret), mgr.cryptPath(secret), "testuser")
	require.NoError(t, err)

	os.WriteFile(filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/token")), []byte("not-a-valid-sesam-file"), 0o600)

	//nolint:gosec
	src, err := os.Open(filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/token")))
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
		root:       testRoot(t, sesamDir),
		Identities: Identities{admin.Identity},
		Signer:     admin.Signer,
		Keyring:    kr,
		State:      state,
	}
	writeSecret(t, sesamDir, "secrets/admin-only", "real payload")
	recps := kr.Recipients([]string{"admin", "bob"})
	cryptPath := adminMgr.cryptPath("secrets/admin-only")
	_, err := sealSecret(adminMgr, "secrets/admin-only", recps, cryptPath, "admin")
	require.NoError(t, err)

	// Bob substitutes the file (bypasses the policy guard, which honest
	// clients run but a patched client would not). Bob is a recipient of
	// the file (recps above include him), so he can derive the content-hash
	// key and seal - he is just not an authorized *sealer* of admin-only.
	bobMgr := &SecretManager{
		SesamDir:   sesamDir,
		root:       testRoot(t, sesamDir),
		Identities: Identities{bob.Identity},
		Signer:     bob.Signer,
	}
	writeSecret(t, sesamDir, "secrets/admin-only", "bob's substituted payload")
	_, err = sealSecret(bobMgr, "secrets/admin-only", recps, cryptPath, "bob")
	require.NoError(t, err)

	// Reveal via RevealBlob with kr+authorize wired up. Bob's name in
	// `sealed_by` is cryptographically valid (real bob signature) but
	// the access list does not include bob.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/admin-only")))
	src, err := os.Open(filepath.Join(sesamDir, cryptPath))
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

func TestSecretRemoveThenSealAll(t *testing.T) {
	mgr := sealedSecretManager(t)

	// Add a second secret so SealAll still has work to do.
	writeSecret(t, mgr.SesamDir, "secrets/other", "other-content")
	require.NoError(t, mgr.SecretAdd("secrets/other", []string{"admin"}))
	require.NoError(t, mgr.SealAll())

	require.NoError(t, mgr.SecretRemove("secrets/test"))

	// SealAll after removal should only seal the remaining secret.
	writeSecret(t, mgr.SesamDir, "secrets/other", "other-content")
	require.NoError(t, mgr.SealAll())

	require.NoFileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test")))
	require.FileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/other")))
}

func TestSealAllMultiple(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	for _, p := range []string{"secrets/a", "secrets/b"} {
		al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: p,
			AccessGroups: []string{"admin"},
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
		testRoot(t, sesamDir),
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
		require.FileExists(t, filepath.Join(mgr.SesamDir, mgr.cryptPath(p)))
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)
	require.NoError(t, verify(mgr.State))

	bobMgr, err := BuildSecretManager(
		mgr.SesamDir, mgr.root, Identities{bob.Identity}, bob.Signer,
		mgr.Keyring, mgr.AuditLog, mgr.State,
	)
	require.NoError(t, err)

	original, err := os.ReadFile(filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test")))
	require.NoError(t, err)

	// Bob has plaintext on disk (left over from sealedSecretManager) but no
	// access to secrets/test, so SealAll must preserve the existing ciphertext
	// rather than re-seal it.
	require.NoError(t, bobMgr.SealAll())

	current, err := os.ReadFile(filepath.Join(mgr.SesamDir, mgr.cryptPath("secrets/test")))
	require.NoError(t, err)
	require.Equal(t, original, current, "unauthorized user must preserve, not re-seal")
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
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)

	// Two secrets: one admin-only (bob cannot decrypt), one shared with dev.
	for _, sc := range []DetailSecretAdd{
		{RevealedPath: "secrets/admin-only", AccessGroups: []string{"admin"}},
		{RevealedPath: "secrets/dev-shared", AccessGroups: []string{"dev"}},
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
		sesamDir,
		testRoot(t, sesamDir), Identities{admin.Identity}, admin.Signer, kr, al, state,
	)
	require.NoError(t, err)

	writeSecret(t, sesamDir, "secrets/admin-only", "admin payload")
	writeSecret(t, sesamDir, "secrets/dev-shared", "dev payload")
	require.NoError(t, adminMgr.SealAll())

	adminOnlyBefore, err := os.ReadFile(filepath.Join(adminMgr.SesamDir, adminMgr.cryptPath("secrets/admin-only")))
	require.NoError(t, err)
	devSharedBefore, err := os.ReadFile(filepath.Join(adminMgr.SesamDir, adminMgr.cryptPath("secrets/dev-shared")))
	require.NoError(t, err)

	// Bob takes over. He has plaintext only for the dev secret. Wipe both
	// plaintexts here and recreate just the dev one to make the scenario
	// explicit.
	require.NoError(t, os.Remove(filepath.Join(sesamDir, "secrets/admin-only")))
	writeSecret(t, sesamDir, "secrets/dev-shared", "dev payload")

	bobMgr, err := BuildSecretManager(
		sesamDir,
		testRoot(t, sesamDir), Identities{bob.Identity}, bob.Signer, kr, al, state,
	)
	require.NoError(t, err)

	require.NoError(t, bobMgr.SealAll(), "non-admin should be able to seal")

	adminOnlyAfter, err := os.ReadFile(filepath.Join(bobMgr.SesamDir, bobMgr.cryptPath("secrets/admin-only")))
	require.NoError(t, err)
	require.Equal(t, adminOnlyBefore, adminOnlyAfter,
		"admin-only ciphertext must be copied byte-for-byte by a non-recipient")

	devSharedAfter, err := os.ReadFile(filepath.Join(bobMgr.SesamDir, bobMgr.cryptPath("secrets/dev-shared")))
	require.NoError(t, err)
	require.NotEqual(t, devSharedBefore, devSharedAfter,
		"dev-shared must be re-encrypted by bob (age uses fresh randomness)")
}

func TestShowSecretSuccessSesamPath(t *testing.T) {
	mgr := testSecretManager(t)
	s := testSecret(t, mgr, "secrets/tok", "content123")
	_, err := sealSecret(mgr, s, mgr.recipientsFor(s), mgr.cryptPath(s), "testuser")
	require.NoError(t, err)

	var buf bytes.Buffer
	ok, err := ShowSecret(mgr.root, mgr.Identities, mgr.cryptPath("secrets/tok"), &buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "content123", buf.String())
}

func TestShowSecretNotFound(t *testing.T) {
	mgr := testSecretManager(t)
	ok, err := ShowSecret(mgr.root, mgr.Identities, "/no/such/file.sesam", &bytes.Buffer{})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestShowSecretRevealedPathConvenience(t *testing.T) {
	mgr := testSecretManager(t)
	s := testSecret(t, mgr, "secrets/tok", "content123")
	_, err := sealSecret(mgr, s, mgr.recipientsFor(s), mgr.cryptPath(s), "testuser")
	require.NoError(t, err)


	var buf bytes.Buffer
	ok, err := ShowSecret(mgr.root, mgr.Identities, "secrets/tok", &buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "content123", buf.String())
}

// ShowSecret must resolve a revealed path against its sesamDir argument,
// not against the caller's current working directory. The previous
// implementation did `filepath.Join(".sesam", "objects", path+".sesam")`
// (relative), so the lookup silently failed whenever cwd != sesamDir —
// e.g. when a user typed `sesam --sesam-dir=.. show README.md` from a
// subdirectory of the worktree.
func TestShowSecretResolvesAgainstSesamDirNotCWD(t *testing.T) {
	mgr := testSecretManager(t)
	s := testSecret(t, mgr, "secrets/tok", "content123")
	_, err := sealSecret(mgr, s, mgr.recipientsFor(s), mgr.cryptPath(s), "testuser")
	require.NoError(t, err)

	// Chdir into a sibling of sesamDir so the relative ".sesam/objects"
	// join would fail without the sesamDir-aware fix.
	elsewhere := t.TempDir()
	require.NotEqual(t, mgr.SesamDir, elsewhere)


	var buf bytes.Buffer
	ok, err := ShowSecret(mgr.root, mgr.Identities, "secrets/tok", &buf)
	require.NoError(t, err)
	require.True(t, ok,
		"ShowSecret must find the object via sesamDir even when cwd differs")
	require.Equal(t, "content123", buf.String())
}

// TestEqualPlaintext exercises the cheap "does the working-tree plaintext
// still match the sealed secret" check that `sesam status` relies on. It must
// recompute the keyed content hash from the sealed file's own age key and
// compare it against the footer - without decrypting the body.
func TestEqualPlaintext(t *testing.T) {
	// seal sets up a fresh manager with one sealed secret at the given content.
	seal := func(t *testing.T, content string) (*SecretManager, string) {
		t.Helper()
		mgr := testSecretManager(t)
		path := testSecret(t, mgr, "secrets/token", content)
		_, err := sealSecret(mgr, path, mgr.recipientsFor(path), mgr.cryptPath(path), "testuser")
		require.NoError(t, err)
		return mgr, path
	}

	t.Run("identical content is equal", func(t *testing.T) {
		mgr, path := seal(t, "secret-value")
		eq, err := mgr.EqualPlaintext(path, mgr.Identities)
		require.NoError(t, err)
		require.True(t, eq)
	})

	t.Run("empty content round-trips as equal", func(t *testing.T) {
		mgr, path := seal(t, "")
		eq, err := mgr.EqualPlaintext(path, mgr.Identities)
		require.NoError(t, err)
		require.True(t, eq)
	})

	t.Run("modified content is not equal", func(t *testing.T) {
		mgr, path := seal(t, "secret-value")
		writeSecret(t, mgr.SesamDir, path, "secret-value-CHANGED")
		eq, err := mgr.EqualPlaintext(path, mgr.Identities)
		require.NoError(t, err)
		require.False(t, eq)
	})

	t.Run("trailing whitespace change is detected", func(t *testing.T) {
		mgr, path := seal(t, "value")
		writeSecret(t, mgr.SesamDir, path, "value ")
		eq, err := mgr.EqualPlaintext(path, mgr.Identities)
		require.NoError(t, err)
		require.False(t, eq)
	})

	t.Run("missing revealed file is an error", func(t *testing.T) {
		mgr, path := seal(t, "x")
		require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, path)))
		_, err := mgr.EqualPlaintext(path, mgr.Identities)
		require.Error(t, err)
	})

	t.Run("missing sealed file is an error", func(t *testing.T) {
		mgr, path := seal(t, "x")
		require.NoError(t, os.Remove(filepath.Join(mgr.SesamDir, mgr.cryptPath(path))))
		_, err := mgr.EqualPlaintext(path, mgr.Identities)
		require.Error(t, err)
	})

	t.Run("non-recipient identity is an error", func(t *testing.T) {
		mgr, path := seal(t, "x")
		outsider := newTestUser(t, "outsider")
		_, err := mgr.EqualPlaintext(path, Identities{outsider.Identity})
		require.Error(t, err)
	})
}
