package core

import (
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
	writeSecret(t, mgr.RepoDir, "secrets/new", "new-content")

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
	writeSecret(t, mgr.RepoDir, "secrets/bad", "data")

	err := mgr.AddSecret("secrets/bad", []string{})
	require.Error(t, err, "empty groups should fail verification")
}

func TestSealAllAndRevealAll(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.RepoDir, "secrets/test", "secret-content")

	require.NoError(t, mgr.SealAll())
	require.FileExists(t, mgr.cryptPath("secrets/test"))

	// Remove plaintext, then reveal.
	os.Remove(filepath.Join(mgr.RepoDir, "secrets/test"))
	require.NoError(t, mgr.RevealAll())

	got, _ := os.ReadFile(filepath.Join(mgr.RepoDir, "secrets/test"))
	require.Equal(t, "secret-content", string(got))
}

func TestSealAllFailsMissingPlaintext(t *testing.T) {
	mgr := testSecretManagerFull(t)
	// Don't write the secret file — seal should fail.
	err := mgr.SealAll()
	require.Error(t, err, "seal should fail when plaintext file is missing")
}

func TestRevealAllFailsMissingAge(t *testing.T) {
	mgr := testSecretManagerFull(t)
	// No .age files exist, so reveal should fail.
	err := mgr.RevealAll()
	require.Error(t, err, "reveal should fail when .age file is missing")
}

// sealedSecretManager returns a SecretManager with one sealed secret ("secrets/test")
// and cwd set to the repo dir. Both .age and .sig.json exist on disk.
func sealedSecretManager(t *testing.T) *SecretManager {
	t.Helper()
	mgr := testSecretManagerFull(t)

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(mgr.RepoDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	writeSecret(t, mgr.RepoDir, "secrets/test", "secret-content")
	require.NoError(t, mgr.SealAll())
	return mgr
}

func TestRemoveSecret(t *testing.T) {
	mgr := sealedSecretManager(t)

	agePath := mgr.cryptPath("secrets/test")
	sigPath := signaturePath(mgr.RepoDir, "secrets/test")
	require.FileExists(t, agePath)
	require.FileExists(t, sigPath)

	require.NoError(t, mgr.RemoveSecret("secrets/test"))

	// Encrypted file and signature should be gone.
	require.NoFileExists(t, agePath)
	require.NoFileExists(t, sigPath)

	// Audit log should record the removal.
	_, exists := mgr.State.SecretExists("secrets/test")
	require.False(t, exists, "secret should be removed from verified state")

	// Original plaintext should still exist.
	plaintext, err := os.ReadFile(filepath.Join(mgr.RepoDir, "secrets/test"))
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

	// Secret is in the manager's list but was never sealed — no .age/.sig.json on disk.
	// RemoveAll is used internally, so missing files are not an error.
	// The audit entry should still be recorded.
	require.NoError(t, mgr.RemoveSecret("secrets/test"))
	_, exists := mgr.State.SecretExists("secrets/test")
	require.False(t, exists, "secret should be removed from verified state")
}

func TestRemoveSecretThenSealAll(t *testing.T) {
	mgr := sealedSecretManager(t)

	// Add a second secret so SealAll still has work to do.
	writeSecret(t, mgr.RepoDir, "secrets/other", "other-content")
	require.NoError(t, mgr.AddSecret("secrets/other", []string{"admin"}))
	require.NoError(t, mgr.SealAll())

	require.NoError(t, mgr.RemoveSecret("secrets/test"))

	// SealAll after removal should only seal the remaining secret.
	writeSecret(t, mgr.RepoDir, "secrets/other", "other-content")
	require.NoError(t, mgr.SealAll())

	require.NoFileExists(t, mgr.cryptPath("secrets/test"))
	require.FileExists(t, mgr.cryptPath("secrets/other"))
}

func TestSealAllMultiple(t *testing.T) {
	repoDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, repoDir, admin)

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
		repoDir,
		Identities{admin.Identity},
		admin.Signer,
		kr,
		al,
		state,
	)

	writeSecret(t, repoDir, "secrets/a", "aaa")
	writeSecret(t, repoDir, "secrets/b", "bbb")

	require.NoError(t, mgr.SealAll())

	for _, p := range []string{"secrets/a", "secrets/b"} {
		require.FileExists(t, mgr.cryptPath(p))
	}
}
