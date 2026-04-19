package core

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateAndLoadSignKey(t *testing.T) {
	repoDir := testRepo(t)
	user := newTestUser(t, "alice")

	signer, err := GenerateSignKey(repoDir, "alice", user.Recipient.Recipient)
	require.NoError(t, err)
	require.Equal(t, "alice", signer.UserName())

	loaded, err := LoadSignKey(repoDir, "alice", user.Identity)
	require.NoError(t, err)
	require.Equal(t, "alice", loaded.UserName())

	// Cross-verify: sign with generated, verify with loaded's pubkey.
	data := []byte("test data")
	sig, err := signer.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)

	kr := EmptyKeyring()
	kr.AddSignPubKey("alice", loaded.PublicKey())
	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestLoadSignKeyMissing(t *testing.T) {
	repoDir := testRepo(t)
	user := newTestUser(t, "alice")
	_, err := LoadSignKey(repoDir, "alice", user.Identity)
	require.Error(t, err, "should fail when sign key file does not exist")
}

func TestLoadSignKeyWrongIdentity(t *testing.T) {
	repoDir := testRepo(t)
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	// Generate key encrypted to alice.
	_, err := GenerateSignKey(repoDir, "alice", alice.Recipient.Recipient)
	require.NoError(t, err)

	// Try loading with bob's identity — should fail to decrypt.
	_, err = LoadSignKey(repoDir, "alice", bob.Identity)
	require.Error(t, err, "should fail when decrypting with wrong identity")
}

func TestReadAllSignatures(t *testing.T) {
	mgr := testSecretManager(t)

	for _, p := range []string{"secrets/a", "secrets/b", "nested/c"} {
		s := testSecret(t, mgr, p, "content-"+p)
		_, err := s.Seal("testuser")
		require.NoError(t, err)
	}

	sigs, err := readAllSignatures(mgr.RepoDir)
	require.NoError(t, err)
	require.Len(t, sigs, 3)
}

func TestReadAllSignaturesEmpty(t *testing.T) {
	repoDir := testRepo(t)
	sigs, err := readAllSignatures(repoDir)
	require.NoError(t, err)
	require.Empty(t, sigs)
}

func TestReadAllSignaturesNoObjectsDir(t *testing.T) {
	// When the objects dir doesn't exist at all (e.g. fresh init before any seal).
	repoDir := t.TempDir()
	sigs, err := readAllSignatures(repoDir)
	require.NoError(t, err, "should not fail when objects dir does not exist")
	require.Empty(t, sigs)
}

func TestReadStoredSignatureMissing(t *testing.T) {
	repoDir := testRepo(t)
	_, err := readStoredSignature(repoDir, "does/not/exist")
	require.Error(t, err)
}

func TestReadStoredSignatureCorrupt(t *testing.T) {
	repoDir := testRepo(t)
	sigPath := signaturePath(repoDir, "secrets/corrupt")
	os.MkdirAll(filepath.Dir(sigPath), 0o700)
	os.WriteFile(sigPath, []byte("not json"), 0o600)

	_, err := readStoredSignature(repoDir, "secrets/corrupt")
	require.Error(t, err, "should fail on corrupt sig JSON")
}

func TestSignCrossDomain(t *testing.T) {
	repoDir := testRepo(t)
	user := newTestUser(t, "alice")

	signer, err := GenerateSignKey(repoDir, "alice", user.Recipient.Recipient)
	require.NoError(t, err)
	require.Equal(t, "alice", signer.UserName())

	loaded, err := LoadSignKey(repoDir, "alice", user.Identity)
	require.NoError(t, err)
	require.Equal(t, "alice", loaded.UserName())

	data := []byte("test data")
	sig, err := signer.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)

	kr := EmptyKeyring()
	kr.AddSignPubKey("alice", loaded.PublicKey())
	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)

	// Has to fail, different domain.
	_, err = kr.Verify(SesamDomainSignAuditTag, data, sig, "alice")
	require.Error(t, err)
}
