package core

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEncryptedLogIsNotPlaintext is a sanity check: nothing recognisable
// from a typical entry should leak through to the on-disk file.
func TestEncryptedLogIsNotPlaintext(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	raw, err := os.ReadFile(logPath)
	require.NoError(t, err)

	require.NotContains(t, string(raw), `"operation"`)
	require.NotContains(t, string(raw), `"init"`)
	require.NotContains(t, string(raw), admin.Name)
}

func TestLoadWithWrongIdentityFails(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	stranger := newTestUser(t, "stranger")
	_, err := LoadAuditLog(sesamDir, Identities{stranger.Identity})
	require.Error(t, err, "stranger is not a recipient and must not be able to load")
}

func TestAddEntryAfterCloseRejected(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSeal{
		RootHash: "x", FilesSealed: 0,
	}), nil)
	require.ErrorIs(t, err, os.ErrClosed)
}

func TestCloseIsIdempotent(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	require.NoError(t, al.Close())
	require.NoError(t, al.Close(), "second Close should be a no-op, not return ErrClosed")
}

// TestRotateKeyPreservesChain verifies rotation is transparent at the chain
// layer: signatures, SeqIDs, and PreviousHash links must survive untouched.
// This is the load-bearing invariant - if rotation re-signed entries, the
// init trust anchor would no longer match and verification would fail for
// every entry not signed by the rotator.
func TestRotateKeyPreservesChain(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	pre := make([]auditEntrySigned, len(al.Entries))
	copy(pre, al.Entries)
	preInitHash := al.InitHash

	require.NoError(t, al.RotateKey(admin.Signer, Recipients{admin.Recipient}))

	require.Len(t, al.Entries, len(pre))
	for i := range pre {
		require.Equal(t, pre[i].Signature, al.Entries[i].Signature, "entry %d signature must be preserved", i)
		require.Equal(t, pre[i].SeqID, al.Entries[i].SeqID, "entry %d SeqID", i)
		require.Equal(t, pre[i].PreviousHash, al.Entries[i].PreviousHash, "entry %d PreviousHash", i)
		require.Equal(t, pre[i].Hash(), al.Entries[i].Hash(), "entry %d Hash", i)
	}
	require.Equal(t, preInitHash, al.InitHash, "init trust anchor must not move")

	require.NoError(t, al.Close())
	loaded := loadAuditLog(t, sesamDir, admin)
	defer loaded.Close()

	require.Len(t, loaded.Entries, len(pre))
	kr := testKeyring(t, admin)
	for i := range loaded.Entries {
		_, err := loaded.Entries[i].Verify(kr)
		require.NoErrorf(t, err, "entry %d signature must still verify after rotation", i)
		require.Equal(t, pre[i].Signature, loaded.Entries[i].Signature)
	}
}

func TestRotateKeyAllowsContinuedAppend(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	require.NoError(t, al.RotateKey(admin.Signer, Recipients{admin.Recipient}))

	// In-memory state was swapped - the fresh fd / aead must accept new entries.
	bob := newTestUser(t, "bob")
	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)
	require.Len(t, al.Entries, 2)

	require.NoError(t, al.Close())
	loaded := loadAuditLog(t, sesamDir, admin)
	defer loaded.Close()

	require.Len(t, loaded.Entries, 2)
	require.Equal(t, opUserTell, loaded.Entries[1].Operation)
}

// TestRotateKeyChangesRecipientSet covers the kill scenario: the recipient
// removed from the new wrap can no longer load (they have the old K_old in
// git history but the live log is now under K_new which they can't unwrap).
func TestRotateKeyChangesRecipientSet(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	require.NoError(t, al.RotateKey(admin.Signer, Recipients{bob.Recipient}))
	require.NoError(t, al.Close())

	// Bob (new recipient) can load.
	loaded, err := LoadAuditLog(sesamDir, Identities{bob.Identity})
	require.NoError(t, err)
	require.NoError(t, loaded.Close())

	// Admin (removed from recipients) can no longer unwrap the new K.
	_, err = LoadAuditLog(sesamDir, Identities{admin.Identity})
	require.Error(t, err)
}

func TestWriteAuditKeyExtendsRecipients(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")
	al := initAuditLog(t, sesamDir, admin)

	// The cheap "tell" path: rewrap the existing K for an extended recipient set
	// without re-encrypting the log.
	require.NoError(t, al.WriteAuditKey(Recipients{admin.Recipient, bob.Recipient}))
	require.NoError(t, al.Close())

	loaded, err := LoadAuditLog(sesamDir, Identities{bob.Identity})
	require.NoError(t, err)
	require.Len(t, loaded.Entries, 1)
	require.NoError(t, loaded.Close())
}

// TestRecoveryDeletesOrphanedTmpFiles: if a crash left renameio tmp files
// (named ".log.jsonlXXXXXX") in the audit dir, LoadAuditLog removes them.
func TestRecoveryDeletesOrphanedTmpFiles(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	// Simulate a leftover renameio tmp file.
	auditDir := filepath.Join(sesamDir, ".sesam", "audit")
	orphan := filepath.Join(auditDir, ".log.jsonlXXXXXX")
	require.NoError(t, os.WriteFile(orphan, []byte("orphan"), 0o600))

	loaded, err := LoadAuditLog(sesamDir, Identities{admin.Identity})
	require.NoError(t, err)
	require.Len(t, loaded.Entries, 1)
	require.NoError(t, loaded.Close())

	_, err = os.Stat(orphan)
	require.Truef(t, errors.Is(err, fs.ErrNotExist), "orphan tmp should be gone, got: %v", err)
}
