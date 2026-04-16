package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryKeyringAddAndVerify(t *testing.T) {
	kr := NewMemoryKeyring()
	user := newTestUser(t, "alice")
	kr.AddSignPubKey("alice", user.Signer.PublicKey())

	data := []byte("hello world")
	sig, err := user.Signer.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)

	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestMemoryKeyringVerifyHintVariants(t *testing.T) {
	kr := NewMemoryKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	kr.AddSignPubKey("alice", alice.Signer.PublicKey())
	kr.AddSignPubKey("bob", bob.Signer.PublicKey())

	data := []byte("test")

	t.Run("correct hint", func(t *testing.T) {
		sig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, data)
		who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
		require.NoError(t, err)
		require.Equal(t, "alice", who)
	})

	t.Run("wrong hint finds correct user", func(t *testing.T) {
		sig, _ := bob.Signer.Sign(SesamDomainSignSecretTag, data)
		who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice") // hint says alice, bob signed
		require.NoError(t, err)
		require.Equal(t, "bob", who)
	})

	t.Run("empty hint", func(t *testing.T) {
		sig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, data)
		who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "")
		require.NoError(t, err)
		require.Equal(t, "alice", who)
	})

	t.Run("nonexistent hint", func(t *testing.T) {
		sig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, data)
		who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "ghost")
		require.NoError(t, err)
		require.Equal(t, "alice", who)
	})
}

func TestMemoryKeyringVerifyNegative(t *testing.T) {
	kr := NewMemoryKeyring()
	alice := newTestUser(t, "alice")
	kr.AddSignPubKey("alice", alice.Signer.PublicKey())

	t.Run("unknown key", func(t *testing.T) {
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		otherSigner := &ed25519Signer{pub: otherPriv.Public().(ed25519.PublicKey), priv: otherPriv, user: "other"}
		sig, _ := otherSigner.Sign(SesamDomainSignSecretTag, []byte("test"))
		_, err := kr.Verify(SesamDomainSignSecretTag, []byte("test"), sig, "alice")
		require.Error(t, err)
	})

	t.Run("wrong data", func(t *testing.T) {
		sig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, []byte("original"))
		_, err := kr.Verify(SesamDomainSignSecretTag, []byte("tampered"), sig, "alice")
		require.Error(t, err)
	})

	t.Run("invalid signature encoding", func(t *testing.T) {
		_, err := kr.Verify(SesamDomainSignSecretTag, []byte("data"), "not-valid-multicode", "alice")
		require.Error(t, err)
	})

	t.Run("empty keyring", func(t *testing.T) {
		emptyKr := NewMemoryKeyring()
		sig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, []byte("test"))
		_, err := emptyKr.Verify(SesamDomainSignSecretTag, []byte("test"), sig, "alice")
		require.Error(t, err)
	})
}

func TestMemoryKeyringDeleteUser(t *testing.T) {
	kr := NewMemoryKeyring()
	user := newTestUser(t, "alice")
	kr.AddRecipient("alice", user.Recipient)
	kr.AddSignPubKey("alice", user.Signer.PublicKey())

	require.True(t, kr.DeleteUser("alice"))
	require.False(t, kr.DeleteUser("ghost"))

	// After deletion, recipients should be gone.
	recps := kr.Recipients([]string{"alice"})
	require.Empty(t, recps, "recipients should be empty after deletion")
}

func TestMemoryKeyringRecipients(t *testing.T) {
	kr := NewMemoryKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	kr.AddRecipient("alice", alice.Recipient)
	kr.AddRecipient("bob", bob.Recipient)

	require.Len(t, kr.Recipients([]string{"alice", "bob"}), 2)
	require.Len(t, kr.Recipients([]string{"alice"}), 1)
	require.Len(t, kr.Recipients([]string{"ghost"}), 0)
	require.Len(t, kr.Recipients(nil), 0)
}

func TestMemoryKeyringRecipientDedup(t *testing.T) {
	kr := NewMemoryKeyring()
	user := newTestUser(t, "alice")

	kr.AddRecipient("alice", user.Recipient)
	kr.AddRecipient("alice", user.Recipient)
	require.Len(t, kr.Recipients([]string{"alice"}), 1)
}

func TestMemoryKeyringSignKeyDedup(t *testing.T) {
	kr := NewMemoryKeyring()
	user := newTestUser(t, "alice")

	kr.AddSignPubKey("alice", user.Signer.PublicKey())
	kr.AddSignPubKey("alice", user.Signer.PublicKey())

	// Should still work (and not return duplicate matches).
	sig, _ := user.Signer.Sign(SesamDomainSignSecretTag, []byte("test"))
	who, err := kr.Verify(SesamDomainSignSecretTag, []byte("test"), sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestMemoryKeyringAddSignPubKeyAppend(t *testing.T) {
	// Exercises the append path: adding a second *different* key for the same user.
	kr := NewMemoryKeyring()
	alice := newTestUser(t, "alice")
	alice2 := newTestUser(t, "alice") // different key material, same name

	kr.AddSignPubKey("alice", alice.Signer.PublicKey())
	kr.AddSignPubKey("alice", alice2.Signer.PublicKey())

	// Both keys should verify.
	data := []byte("test")
	sig1, _ := alice.Signer.Sign(SesamDomainSignSecretTag, data)
	sig2, _ := alice2.Signer.Sign(SesamDomainSignSecretTag, data)

	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig1, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)

	who, err = kr.Verify(SesamDomainSignSecretTag, data, sig2, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestMemoryKeyringAddRecipientAppend(t *testing.T) {
	// Exercises the append path: adding a second *different* recipient for the same user.
	kr := NewMemoryKeyring()
	alice1 := newTestUser(t, "alice")
	alice2 := newTestUser(t, "alice") // different key material

	kr.AddRecipient("alice", alice1.Recipient)
	kr.AddRecipient("alice", alice2.Recipient)

	recps := kr.Recipients([]string{"alice"})
	require.Len(t, recps, 2, "should have two different recipients for alice")
}

func TestMemoryKeyringAddSignPubKeyMultipleUsers(t *testing.T) {
	kr := NewMemoryKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	kr.AddSignPubKey("alice", alice.Signer.PublicKey())
	kr.AddSignPubKey("bob", bob.Signer.PublicKey())

	// Each user's key should verify only their signatures.
	data := []byte("shared data")
	aliceSig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, data)
	bobSig, _ := bob.Signer.Sign(SesamDomainSignSecretTag, data)

	who, err := kr.Verify(SesamDomainSignSecretTag, data, aliceSig, "")
	require.NoError(t, err)
	require.Equal(t, "alice", who)

	who, err = kr.Verify(SesamDomainSignSecretTag, data, bobSig, "")
	require.NoError(t, err)
	require.Equal(t, "bob", who)
}

func TestMemoryKeyringListUsers(t *testing.T) {
	kr := NewMemoryKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	kr.AddRecipient("alice", alice.Recipient)
	kr.AddRecipient("bob", bob.Recipient)

	users := kr.ListUsers()
	require.Len(t, users, 2)
	require.Contains(t, users, "alice")
	require.Contains(t, users, "bob")
}
