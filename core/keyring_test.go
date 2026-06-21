package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryKeyringAddAndVerify(t *testing.T) {
	kr := EmptyKeyring()
	user := newTestUser(t, "alice")
	require.NoError(t, kr.SetSignPubKey("alice", user.Signer.PublicKey()))

	data := []byte("hello world")
	sig, err := user.Signer.Sign(SesamDomainSignSecretTag, data)
	require.NoError(t, err)

	who, err := kr.Verify(SesamDomainSignSecretTag, data, sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestMemoryKeyringVerifyHintVariants(t *testing.T) {
	kr := EmptyKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	require.NoError(t, kr.SetSignPubKey("alice", alice.Signer.PublicKey()))
	require.NoError(t, kr.SetSignPubKey("bob", bob.Signer.PublicKey()))

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
	kr := EmptyKeyring()
	alice := newTestUser(t, "alice")
	require.NoError(t, kr.SetSignPubKey("alice", alice.Signer.PublicKey()))

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
		emptyKr := EmptyKeyring()
		sig, _ := alice.Signer.Sign(SesamDomainSignSecretTag, []byte("test"))
		_, err := emptyKr.Verify(SesamDomainSignSecretTag, []byte("test"), sig, "alice")
		require.Error(t, err)
	})
}

func TestMemoryKeyringDeleteUser(t *testing.T) {
	kr := EmptyKeyring()
	user := newTestUser(t, "alice")
	require.NoError(t, kr.AddRecipient("alice", user.Recipient))
	require.NoError(t, kr.SetSignPubKey("alice", user.Signer.PublicKey()))

	require.True(t, kr.DeleteUser("alice"))
	require.False(t, kr.DeleteUser("ghost"))

	// After deletion, recipients should be gone.
	recps := kr.Recipients([]string{"alice"})
	require.Empty(t, recps, "recipients should be empty after deletion")
}

func TestMemoryKeyringRecipients(t *testing.T) {
	kr := EmptyKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	require.NoError(t, kr.AddRecipient("alice", alice.Recipient))
	require.NoError(t, kr.AddRecipient("bob", bob.Recipient))

	require.Len(t, kr.Recipients([]string{"alice", "bob"}), 2)
	require.Len(t, kr.Recipients([]string{"alice"}), 1)
	require.Len(t, kr.Recipients([]string{"ghost"}), 0)
	require.Len(t, kr.Recipients(nil), 0)
}

func TestMemoryKeyringRecipientDedup(t *testing.T) {
	kr := EmptyKeyring()
	user := newTestUser(t, "alice")

	// Adding the same recipient twice for the same user is a no-op, not an error.
	require.NoError(t, kr.AddRecipient("alice", user.Recipient))
	require.NoError(t, kr.AddRecipient("alice", user.Recipient))
	require.Len(t, kr.Recipients([]string{"alice"}), 1)
}

func TestMemoryKeyringSignKeyDedup(t *testing.T) {
	kr := EmptyKeyring()
	user := newTestUser(t, "alice")

	// Setting the same signing key twice for the same user is idempotent, not an error.
	require.NoError(t, kr.SetSignPubKey("alice", user.Signer.PublicKey()))
	require.NoError(t, kr.SetSignPubKey("alice", user.Signer.PublicKey()))

	// Should still work (and not return duplicate matches).
	sig, _ := user.Signer.Sign(SesamDomainSignSecretTag, []byte("test"))
	who, err := kr.Verify(SesamDomainSignSecretTag, []byte("test"), sig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestMemoryKeyringSetSignPubKeyReplaces(t *testing.T) {
	// A user has exactly one signing key: SetSignPubKey replaces the previous
	// one rather than appending. After a replace the old key must no longer
	// verify - this is what makes a regen a real revocation of the old key.
	kr := EmptyKeyring()
	oldKey := newTestUser(t, "alice")
	newKey := newTestUser(t, "alice") // different key material, same name

	require.NoError(t, kr.SetSignPubKey("alice", oldKey.Signer.PublicKey()))
	require.NoError(t, kr.SetSignPubKey("alice", newKey.Signer.PublicKey()))

	data := []byte("test")
	oldSig, _ := oldKey.Signer.Sign(SesamDomainSignSecretTag, data)
	newSig, _ := newKey.Signer.Sign(SesamDomainSignSecretTag, data)

	// The new key verifies as alice.
	who, err := kr.Verify(SesamDomainSignSecretTag, data, newSig, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", who)

	// The replaced key must no longer verify.
	_, err = kr.Verify(SesamDomainSignSecretTag, data, oldSig, "alice")
	require.Error(t, err, "replaced signing key must no longer verify")
}

func TestMemoryKeyringAddRecipientAppend(t *testing.T) {
	// Exercises the append path: adding a second *different* recipient for the same user.
	kr := EmptyKeyring()
	alice1 := newTestUser(t, "alice")
	alice2 := newTestUser(t, "alice") // different key material

	require.NoError(t, kr.AddRecipient("alice", alice1.Recipient))
	require.NoError(t, kr.AddRecipient("alice", alice2.Recipient))

	recps := kr.Recipients([]string{"alice"})
	require.Len(t, recps, 2, "should have two different recipients for alice")
}

func TestMemoryKeyringRemoveRecipient(t *testing.T) {
	first := newTestUser(t, "alice")
	second := newTestUser(t, "alice") // different key material, same name

	t.Run("removes one of several", func(t *testing.T) {
		kr := EmptyKeyring()
		require.NoError(t, kr.AddRecipient("alice", first.Recipient))
		require.NoError(t, kr.AddRecipient("alice", second.Recipient))

		require.NoError(t, kr.RemoveRecipient("alice", first.Recipient))

		recps := kr.Recipients([]string{"alice"})
		require.Len(t, recps, 1)
		require.True(t, recps[0].Equal(second.Recipient), "the surviving recipient must be the one we kept")
	})

	t.Run("refuses to remove the last recipient", func(t *testing.T) {
		kr := EmptyKeyring()
		require.NoError(t, kr.AddRecipient("alice", first.Recipient))

		err := kr.RemoveRecipient("alice", first.Recipient)
		require.Error(t, err)
		require.Contains(t, err.Error(), "only one")
		require.Len(t, kr.Recipients([]string{"alice"}), 1, "the last recipient must be left intact")
	})

	t.Run("unknown user", func(t *testing.T) {
		kr := EmptyKeyring()
		err := kr.RemoveRecipient("ghost", first.Recipient)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no such user")
	})

	t.Run("recipient not held by user", func(t *testing.T) {
		kr := EmptyKeyring()
		require.NoError(t, kr.AddRecipient("alice", first.Recipient))

		err := kr.RemoveRecipient("alice", second.Recipient)
		require.Error(t, err)
		require.Len(t, kr.Recipients([]string{"alice"}), 1)
	})
}

func TestMemoryKeyringSetSignPubKeyMultipleUsers(t *testing.T) {
	kr := EmptyKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")

	require.NoError(t, kr.SetSignPubKey("alice", alice.Signer.PublicKey()))
	require.NoError(t, kr.SetSignPubKey("bob", bob.Signer.PublicKey()))

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

func TestAllRecipients(t *testing.T) {
	kr := EmptyKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	require.NoError(t, kr.AddRecipient("alice", alice.Recipient))
	require.NoError(t, kr.AddRecipient("bob", bob.Recipient))

	recps := AllRecipients(kr)
	require.Len(t, recps, 2)
}

func TestAllRecipientsEmpty(t *testing.T) {
	require.Empty(t, AllRecipients(EmptyKeyring()))
}

func TestMemoryKeyringAddRecipientDuplicateAcrossUsers(t *testing.T) {
	// A recipient already held by one user may not be claimed by another:
	// keys must stay unique across users so `sesam id` resolves to one user.
	kr := EmptyKeyring()
	user := newTestUser(t, "alice")

	require.NoError(t, kr.AddRecipient("alice", user.Recipient))

	err := kr.AddRecipient("bob", user.Recipient)
	require.Error(t, err)

	var dupErr *DuplicatePubkeyError
	require.ErrorAs(t, err, &dupErr)
	require.Equal(t, "bob", dupErr.user)

	// The duplicate must not have been recorded for bob.
	require.Empty(t, kr.Recipients([]string{"bob"}))
	require.Len(t, kr.Recipients([]string{"alice"}), 1)
}

func TestMemoryKeyringSetSignPubKeyDuplicateAcrossUsers(t *testing.T) {
	// Same uniqueness rule for signing keys.
	kr := EmptyKeyring()
	user := newTestUser(t, "alice")

	require.NoError(t, kr.SetSignPubKey("alice", user.Signer.PublicKey()))

	err := kr.SetSignPubKey("bob", user.Signer.PublicKey())
	require.Error(t, err)

	var dupErr *DuplicatePubkeyError
	require.ErrorAs(t, err, &dupErr)
	require.Equal(t, "bob", dupErr.user)

	// The key must still resolve to alice only; bob must not have stolen it.
	sig, err := user.Signer.Sign(SesamDomainSignSecretTag, []byte("test"))
	require.NoError(t, err)
	who, err := kr.Verify(SesamDomainSignSecretTag, []byte("test"), sig, "")
	require.NoError(t, err)
	require.Equal(t, "alice", who)
}

func TestMemoryKeyringListUsers(t *testing.T) {
	kr := EmptyKeyring()
	alice := newTestUser(t, "alice")
	bob := newTestUser(t, "bob")
	require.NoError(t, kr.AddRecipient("alice", alice.Recipient))
	require.NoError(t, kr.AddRecipient("bob", bob.Recipient))

	users := kr.ListUsers()
	require.Len(t, users, 2)
	require.Contains(t, users, "alice")
	require.Contains(t, users, "bob")
}
