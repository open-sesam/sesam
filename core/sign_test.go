package core

import (
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndLoadSignKey(t *testing.T) {
	sesamDir := testRepo(t)
	user := newTestUser(t, "alice")

	signer, err := GenerateSignKey(sesamDir, "alice", []age.Recipient{user.Recipient.Recipient})
	require.NoError(t, err)
	require.Equal(t, "alice", signer.UserName())

	loaded, err := LoadSignKey(sesamDir, "alice", user.Identity)
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
	sesamDir := testRepo(t)
	user := newTestUser(t, "alice")
	_, err := LoadSignKey(sesamDir, "alice", user.Identity)
	require.Error(t, err, "should fail when sign key file does not exist")
}

func TestLoadSignKeyWrongIdentity(t *testing.T) {
	sesamDir := testRepo(t)
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	// Generate key encrypted to alice.
	_, err := GenerateSignKey(sesamDir, "alice", []age.Recipient{alice.Recipient.Recipient})
	require.NoError(t, err)

	// Try loading with bob's identity — should fail to decrypt.
	_, err = LoadSignKey(sesamDir, "alice", bob.Identity)
	require.Error(t, err, "should fail when decrypting with wrong identity")
}

func TestReadAllSignatures(t *testing.T) {
	mgr := testSecretManager(t)

	for _, p := range []string{"secrets/a", "secrets/b", "nested/c"} {
		s := testSecret(t, mgr, p, "content-"+p)
		_, err := s.Seal("testuser")
		require.NoError(t, err)
	}

	sigs, err := readAllSignatures(mgr.SesamDir)
	require.NoError(t, err)
	require.Len(t, sigs, 3)
}

func TestReadAllSignaturesEmpty(t *testing.T) {
	sesamDir := testRepo(t)
	sigs, err := readAllSignatures(sesamDir)
	require.NoError(t, err)
	require.Empty(t, sigs)
}

func TestReadAllSignaturesNoObjectsDir(t *testing.T) {
	// When the objects dir doesn't exist at all (e.g. fresh init before any seal).
	sesamDir := t.TempDir()
	sigs, err := readAllSignatures(sesamDir)
	require.NoError(t, err, "should not fail when objects dir does not exist")
	require.Empty(t, sigs)
}

func TestSignCrossDomain(t *testing.T) {
	sesamDir := testRepo(t)
	user := newTestUser(t, "alice")

	signer, err := GenerateSignKey(sesamDir, "alice", []age.Recipient{user.Recipient.Recipient})
	require.NoError(t, err)
	require.Equal(t, "alice", signer.UserName())

	loaded, err := LoadSignKey(sesamDir, "alice", user.Identity)
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
