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
	require.Error(t, err, "stranger has no stanza in key.age and must not be able to load")
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
// This is the load-bearing invariant — if rotation re-signed entries, the
// init trust anchor would no longer match and verification would fail for
// every entry not signed by the rotator.
func TestRotateKeyPreservesChain(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []string{bob.Recipient.String()}, SignPubKeys: []string{bob.SignPubKey},
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

	// In-memory state was swapped — the fresh fd / aead must accept new entries.
	bob := newTestUser(t, "bob")
	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []string{bob.Recipient.String()}, SignPubKeys: []string{bob.SignPubKey},
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

// TestRecoveryRollForwardOnInterruptedRotation: if the process crashed between
// the log rename and the key rename, only key.age.tmp remains — load must
// complete the second rename so the log/key pair is consistent again.
func TestRecoveryRollForwardOnInterruptedRotation(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	// Rekey to itself, but intercept after the first rename: copy the new
	// key.age aside, then reset on-disk state to "log renamed, key.age.tmp present".
	require.NoError(t, al.RotateKey(admin.Signer, Recipients{admin.Recipient}))
	require.NoError(t, al.Close())

	keyPath := filepath.Join(sesamDir, ".sesam", "audit", "key.age")
	tmpKeyPath := keyPath + ".tmp"

	// Stage the post-rotation key.age as if rename2 hadn't happened yet:
	// move the live key.age aside and back, leaving a copy at key.age.tmp.
	live, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(tmpKeyPath, live, 0o600))
	// Corrupt the "live" key.age to make sure the recovery actually uses the .tmp.
	require.NoError(t, os.WriteFile(keyPath, []byte("corrupt"), 0o600))

	loaded, err := LoadAuditLog(sesamDir, Identities{admin.Identity})
	require.NoError(t, err, "recovery should have replaced corrupt key.age with the tmp")
	require.Len(t, loaded.Entries, 1)
	require.NoError(t, loaded.Close())

	_, err = os.Stat(tmpKeyPath)
	require.Truef(t, errors.Is(err, fs.ErrNotExist), "tmp key should be gone after recovery, got: %v", err)
}

// TestRecoveryRollBackWhenOnlyTmpLogExists: a crash between writing the tmp log
// and writing the tmp key leaves an orphaned tmp log. Load deletes it (rollback)
// and proceeds with the original state.
func TestRecoveryRollBackWhenOnlyTmpLogExists(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	tmpLogPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl.tmp")
	require.NoError(t, os.WriteFile(tmpLogPath, []byte("orphan"), 0o600))

	loaded, err := LoadAuditLog(sesamDir, Identities{admin.Identity})
	require.NoError(t, err)
	require.Len(t, loaded.Entries, 1)
	require.NoError(t, loaded.Close())

	_, err = os.Stat(tmpLogPath)
	require.Truef(t, errors.Is(err, fs.ErrNotExist), "orphan tmp log should be gone, got: %v", err)
}

// TestRecoveryRollBackWhenBothTmpsExist: rotation crashed after writing both
// tmps but before either rename. Recovery rolls back (delete both) — the live
// state was untouched so reload from the original files succeeds.
func TestRecoveryRollBackWhenBothTmpsExist(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	keyPath := filepath.Join(sesamDir, ".sesam", "audit", "key.age")
	tmpKeyPath := keyPath + ".tmp"
	tmpLogPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl.tmp")

	require.NoError(t, os.WriteFile(tmpKeyPath, []byte("staged key"), 0o600))
	require.NoError(t, os.WriteFile(tmpLogPath, []byte("staged log"), 0o600))

	loaded, err := LoadAuditLog(sesamDir, Identities{admin.Identity})
	require.NoError(t, err)
	require.Len(t, loaded.Entries, 1)
	require.NoError(t, loaded.Close())

	for _, path := range []string{tmpKeyPath, tmpLogPath} {
		_, err := os.Stat(path)
		require.Truef(t, errors.Is(err, fs.ErrNotExist), "%s should be gone, got: %v", path, err)
	}
}
