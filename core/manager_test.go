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

func TestAddOrChangeSecret(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.RepoDir, "secrets/new", "new-content")

	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "secrets"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "secrets", "new"), []byte("blub"), 0600))

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { os.Chdir(origDir) })

	require.NoError(t, mgr.AddOrChangeSecret("secrets/new", []string{"admin"}))
	require.Len(t, mgr.secrets, 2)

	_, exists := mgr.State.SecretExists("secrets/new")
	require.True(t, exists)
}

func TestAddOrChangeSecretEmptyGroups(t *testing.T) {
	mgr := testSecretManagerFull(t)
	writeSecret(t, mgr.RepoDir, "secrets/bad", "data")

	err := mgr.AddOrChangeSecret("secrets/bad", []string{})
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

	kr := NewMemoryKeyring()
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
