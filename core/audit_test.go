package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOperationFor(t *testing.T) {
	cases := []struct {
		detail any
		want   Operation
	}{
		{&DetailInit{}, OpInit},
		{&DetailUserTell{}, OpUserTell},
		{&DetailUserKill{}, OpUserKill},
		{&DetailSecretAdd{}, OpSecretAdd},
		{&DetailSecretRemove{}, OpSecretRemove},
		{&DetailSeal{}, OpSeal},
	}

	for _, tc := range cases {
		got := operationFor(tc.detail)
		require.Equal(t, tc.want, got, "operationFor(%T)", tc.detail)
	}
}

func TestOperationForPanicsOnUnknown(t *testing.T) {
	require.Panics(t, func() {
		operationFor("not a detail")
	})
}

func TestNewAuditEntryDerivesOperation(t *testing.T) {
	e := newAuditEntry("alice", &DetailSeal{RootHash: "abc", FilesSealed: 3})
	require.Equal(t, OpSeal, e.Operation)
	require.Equal(t, "alice", e.ChangedBy)
	require.False(t, e.Time.IsZero(), "Time should be set")
}

func TestNewAuditEntryDetailRoundtrip(t *testing.T) {
	detail := &DetailSecretAdd{RevealedPath: "secrets/x", AccessGroups: []string{"dev"}}
	entry := newAuditEntry("bob", detail)

	signed := &AuditEntrySigned{AuditEntry: *entry}
	got, err := parseDetail[DetailSecretAdd](signed)
	require.NoError(t, err)
	require.Equal(t, "secrets/x", got.RevealedPath)
	require.Equal(t, []string{"dev"}, got.AccessGroups)
}

func TestParseDetailCache(t *testing.T) {
	entry := newAuditEntry("alice", &DetailInit{InitUUID: "test-uuid"})
	signed := &AuditEntrySigned{AuditEntry: *entry}

	d1, err := parseDetail[DetailInit](signed)
	require.NoError(t, err)

	// Second call should return cached pointer.
	d2, err := parseDetail[DetailInit](signed)
	require.NoError(t, err)
	require.Same(t, d1, d2, "expected cached pointer")
}

func TestParseDetailWrongType(t *testing.T) {
	entry := newAuditEntry("alice", &DetailInit{InitUUID: "test"})
	signed := &AuditEntrySigned{AuditEntry: *entry}

	// Parse as Init first (caches it).
	_, err := parseDetail[DetailInit](signed)
	require.NoError(t, err)

	// Now try to parse as a different type - should fail.
	_, err = parseDetail[DetailSeal](signed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not *")
}

func TestParseDetailCorruptJSON(t *testing.T) {
	entry := newAuditEntry("alice", &DetailInit{InitUUID: "test"})
	signed := &AuditEntrySigned{AuditEntry: *entry}
	signed.Detail = []byte("not json")
	signed.unmarshaledDetail = nil // clear cache

	_, err := parseDetail[DetailInit](signed)
	require.Error(t, err, "should fail on corrupt JSON")
}

func TestAddEntryChaining(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	e := newAuditEntry("admin", &DetailUserTell{
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
	})

	_, err := al.AddEntry(admin.Signer, e, nil)
	require.NoError(t, err)
	require.Len(t, al.Entries, 2)

	require.Equal(t, uint64(1), al.Entries[0].SeqID)
	require.Equal(t, uint64(2), al.Entries[1].SeqID)

	// PreviousHash of entry 2 should be hash of entry 1.
	require.Equal(t, al.Entries[0].Hash(), al.Entries[1].PreviousHash)
}

func TestAddEntryFirstPrevHash(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	expected := hashData([]byte(sesamInitialHashSeed))
	require.Equal(t, expected, al.Entries[0].PreviousHash)
}

func TestStoreAndLoad(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	_, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}},
		SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)

	require.NoError(t, al.Close())
	loaded, err := LoadAuditLog(testRoot(t, sesamDir), Identities{admin.Identity})
	require.NoError(t, err)
	require.Len(t, loaded.Entries, len(al.Entries))
	require.Equal(t, al.InitHash, loaded.InitHash)

	for i := range al.Entries {
		require.Equal(t, al.Entries[i].SeqID, loaded.Entries[i].SeqID, "entry %d SeqID", i)
		require.Equal(t, al.Entries[i].Signature, loaded.Entries[i].Signature, "entry %d Signature", i)
	}
}

func TestLoadMissingInitFile(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	require.NoError(t, os.WriteFile(logPath, nil, 0o600))

	_, err := LoadAuditLog(testRoot(t, sesamDir), Identities{admin.Identity})
	require.Error(t, err)
}

func TestLoadMissingLogFile(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0o600))

	_, err := LoadAuditLog(testRoot(t, sesamDir), Identities{admin.Identity})
	require.Error(t, err)
}

// TestLoadCorruptTrailingEntryRejected: with the encrypted log we no longer
// auto-truncate partial trailing entries - any line that fails to decrypt
// must surface as an error instead of silently being discarded.
func TestLoadCorruptTrailingEntryRejected(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	// Append a base64-shaped but bogus line to the encrypted log.
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = LoadAuditLog(testRoot(t, sesamDir), Identities{admin.Identity})
	require.Error(t, err, "garbage trailing entry should be rejected, not truncated")
}

func TestBuildRootHash(t *testing.T) {
	t.Run("order independent", func(t *testing.T) {
		sigs1 := []*secretFooter{
			{RevealedPath: "b", CipherTextHash: "hash-b"},
			{RevealedPath: "a", CipherTextHash: "hash-a"},
		}
		sigs2 := []*secretFooter{
			{RevealedPath: "a", CipherTextHash: "hash-a"},
			{RevealedPath: "b", CipherTextHash: "hash-b"},
		}

		h1 := buildRootHash(sigs1)
		h2 := buildRootHash(sigs2)
		require.NotEmpty(t, h1)
		require.Equal(t, h1, h2)
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		h1 := buildRootHash([]*secretFooter{{RevealedPath: "a", CipherTextHash: "hash-a"}})
		h2 := buildRootHash([]*secretFooter{{RevealedPath: "a", CipherTextHash: "hash-different"}})
		require.NotEqual(t, h1, h2)
	})

	t.Run("empty sigs", func(t *testing.T) {
		h := buildRootHash(nil)
		require.NotEmpty(t, h, "empty sigs should still produce a hash")
	})

	t.Run("single sig", func(t *testing.T) {
		h := buildRootHash([]*secretFooter{{RevealedPath: "a", CipherTextHash: "h"}})
		require.NotEmpty(t, h)
	})
}

func TestInitLogCreatesFiles(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	data, err := os.ReadFile(initPath)
	require.NoError(t, err)
	require.Equal(t, al.InitHash, string(data))

	require.Len(t, al.Entries, 1)
	require.Equal(t, OpInit, al.Entries[0].Operation)
}

func TestAuditEntrySignedHash(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	h1 := al.Entries[0].Hash()
	h2 := al.Entries[0].Hash()
	require.Equal(t, h1, h2, "Hash() should be deterministic")
	require.NotEmpty(t, h1)
}

func TestAuditEntrySignedVerify(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	kr := testKeyring(t, admin)

	who, err := al.Entries[0].Verify(kr)
	require.NoError(t, err)
	require.Equal(t, "admin", who)
}

func TestAuditEntrySignedVerifyTampered(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	kr := testKeyring(t, admin)

	// Tamper with the entry after signing.
	al.Entries[0].ChangedBy = "eve"
	_, err := al.Entries[0].Verify(kr)
	require.Error(t, err, "verify should fail for tampered entry")
}

func TestIterate(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	var count int
	err := al.Iterate(func(idx int, entry *AuditEntrySigned) error {
		count++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestIterateStopsOnError(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)

	bob := newTestUser(t, "bob")
	al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailUserTell{
		User: "bob", Groups: []string{"dev"},
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)

	var count int
	err := al.Iterate(func(idx int, entry *AuditEntrySigned) error {
		count++
		return fmt.Errorf("stop")
	})
	require.Error(t, err)
	require.Equal(t, 1, count, "should stop after first error")
}

func TestIterateEmpty(t *testing.T) {
	al := &AuditLog{}
	var count int
	err := al.Iterate(func(idx int, entry *AuditEntrySigned) error {
		count++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestAuditEntrySignedString(t *testing.T) {
	e := newAuditEntry("alice", &DetailSeal{RootHash: "abc", FilesSealed: 3})
	signed := &AuditEntrySigned{AuditEntry: *e}
	s := signed.String()
	require.NotEmpty(t, s)
	require.Contains(t, s, "abc")
}

func TestShowAuditLogSuccess(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	var buf bytes.Buffer
	ok, err := ShowAuditLog(Identities{admin.Identity}, logPath, &buf)
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, strings.Contains(buf.String(), `"operation"`))
	require.True(t, strings.Contains(buf.String(), `"init"`))
}

func TestShowAuditLogNotFound(t *testing.T) {
	ok, err := ShowAuditLog(Identities{}, "/nonexistent/log.jsonl", &bytes.Buffer{})
	require.NoError(t, err)
	require.False(t, ok)
}

func TestShowAuditLogWrongIdentity(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	stranger := newTestUser(t, "stranger")
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	ok, err := ShowAuditLog(Identities{stranger.Identity}, logPath, &bytes.Buffer{})
	require.True(t, ok)
	require.Error(t, err, "wrong identity should fail to decrypt audit key")
}

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
	_, err := LoadAuditLog(testRoot(t, sesamDir), Identities{stranger.Identity})
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)

	pre := make([]AuditEntrySigned, len(al.Entries))
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
		PubKeys: []UserPubKey{{Key: bob.Recipient.String(), Source: KeySourceManual}}, SignPubKey: bob.SignPubKey,
	}), nil)
	require.NoError(t, err)
	require.Len(t, al.Entries, 2)

	require.NoError(t, al.Close())
	loaded := loadAuditLog(t, sesamDir, admin)
	defer loaded.Close()

	require.Len(t, loaded.Entries, 2)
	require.Equal(t, OpUserTell, loaded.Entries[1].Operation)
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
	loaded, err := LoadAuditLog(testRoot(t, sesamDir), Identities{bob.Identity})
	require.NoError(t, err)
	require.NoError(t, loaded.Close())

	// Admin (removed from recipients) can no longer unwrap the new K.
	_, err = LoadAuditLog(testRoot(t, sesamDir), Identities{admin.Identity})
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

	loaded, err := LoadAuditLog(testRoot(t, sesamDir), Identities{bob.Identity})
	require.NoError(t, err)
	require.Len(t, loaded.Entries, 1)
	require.NoError(t, loaded.Close())
}

// TestDivergentBranchesDoNotShareKeystream is the regression guard for the
// nonce: it used to be the seq id, so two branches appending at the same seq
// under the same key produced ciphertexts whose XOR was the XOR of the two
// plaintexts - recoverable by anyone who could read the repo but not decrypt it.
func TestDivergentBranchesDoNotShareKeystream(t *testing.T) {
	base, admin, _ := mergeBase(t)
	base.key = newAuditKey()

	// Two branches off a shared base, same key, both appending at the same seq.
	ours := cloneLog(base)
	ours.key = base.key
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	theirs.key = base.key
	feed(t, theirs, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "sec"}})

	// feed-built logs have no init file, so seed the anchor VerifyChain checks.
	ours.InitHash = ours.Entries[0].Hash()

	kr := EmptyKeyring()
	_, err := VerifyChain(ours, kr, nil)
	require.NoError(t, err)

	var ourBuf, theirBuf bytes.Buffer
	require.NoError(t, ours.WriteEncrypted(&ourBuf, AllRecipients(kr)))
	require.NoError(t, theirs.WriteEncrypted(&theirBuf, AllRecipients(kr)))

	ourLine := entryLine(t, ourBuf.Bytes(), len(base.Entries)+1)
	theirLine := entryLine(t, theirBuf.Bytes(), len(base.Entries)+1)
	require.NotEqual(t, ourLine, theirLine, "the two sides must not encrypt to the same bytes")

	// With a shared keystream the XOR is plaintext-vs-plaintext, so the long
	// identical stretches of two similar entries show up as runs of zero bytes.
	// Independent keystreams leave XOR uniformly random, i.e. ~1/256 zeros.
	body := min(len(ourLine), len(theirLine))
	var zeros int
	for i := range body {
		if ourLine[i]^theirLine[i] == 0 {
			zeros++
		}
	}

	require.Less(t, zeros, body/16, "ciphertexts share a keystream (%d/%d zero bytes in XOR)", zeros, body)
}

// TestEntryIsBoundToItsPosition: the seq id moved from the nonce into the
// associated data, so a line that gets moved must still fail to decrypt.
func TestEntryIsBoundToItsPosition(t *testing.T) {
	key := newAuditKey()
	aead, err := newAuditAEAD(key[:])
	require.NoError(t, err)

	admin := newTestUser(t, "admin")
	entry := newAuditEntry("admin", &DetailSecretAdd{RevealedPath: "s/x", AccessGroups: []string{"admin"}})
	entry.SeqID = 7
	signed, err := entry.Sign(admin.Signer)
	require.NoError(t, err)

	line, err := signed.Encrypt(aead)
	require.NoError(t, err)

	raw := make([]byte, base64.RawStdEncoding.DecodedLen(len(line)-1))
	n, err := base64.RawStdEncoding.Decode(raw, line[:len(line)-1])
	require.NoError(t, err)

	ns := aead.NonceSize()
	_, err = aead.Open(nil, raw[:ns], raw[ns:n], seqAssociatedData(7))
	require.NoError(t, err, "decrypts at its own position")

	_, err = aead.Open(nil, raw[:ns], raw[ns:n], seqAssociatedData(8))
	require.Error(t, err, "must not decrypt at a different position")
}

// entryLine returns the decoded ciphertext of entry `seq` from a serialized log
// (line 1 holds the wrapped key).
func entryLine(t *testing.T, log []byte, seq int) []byte {
	t.Helper()

	lines := bytes.Split(bytes.TrimRight(log, "\n"), []byte("\n"))
	require.Greater(t, len(lines), seq)

	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(lines[seq])))
	n, err := base64.RawStdEncoding.Decode(out, lines[seq])
	require.NoError(t, err)
	return out[:n]
}

// buildBenchAuditLog initializes an audit log with the admin and `entries`
// additional secret-change entries, all written to disk. It returns the
// sesam dir and the admin user (whose identity decrypts the audit key).
func buildBenchAuditLog(b testing.TB, entries int) (string, *testUser) {
	b.Helper()

	sesamDir := testRepo(b)
	admin := newTestUser(b, "admin")
	al := initAuditLog(b, sesamDir, admin)
	b.Cleanup(func() { _ = al.Close() })

	// Entry 1 is the init entry; add the rest as distinct secret changes,
	// which the admin is always allowed to make.
	for i := 1; i < entries; i++ {
		if _, err := al.AddEntry(admin.Signer, newAuditEntry("admin", &DetailSecretAdd{
			RevealedPath: fmt.Sprintf("secrets/bench/secret-%06d", i),
			AccessGroups: []string{"admin"},
		}), nil); err != nil {
			b.Fatalf("seed entry %d: %v", i, err)
		}
	}

	return sesamDir, admin
}

// BenchmarkAuditLog measures loading a large audit log from disk and replaying
// it into a VerifiedState - the work that happens on every sesam invocation.
func BenchmarkAuditLog(b *testing.B) {
	const entries = 20_000

	sesamDir, admin := buildBenchAuditLog(b, entries)
	ids := Identities{admin.Identity}

	// Sanity check the seeded log before timing anything.
	al, err := LoadAuditLog(testRoot(b, sesamDir), ids)
	if err != nil {
		b.Fatalf("initial load: %v", err)
	}
	if got := len(al.Entries); got != entries {
		b.Fatalf("seeded %d entries, loaded %d", entries, got)
	}
	if _, err := VerifyChain(al, EmptyKeyring(), nil); err != nil {
		b.Fatalf("initial verify: %v", err)
	}
	_ = al.Close()

	// Load only: read every line from disk and decrypt it.
	b.Run("Load", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			al, err := LoadAuditLog(testRoot(b, sesamDir), ids)
			if err != nil {
				b.Fatal(err)
			}
			if err := al.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})

	// Load + verify: the full cost of deriving the trusted state from disk.
	b.Run("LoadAndVerify", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			al, err := LoadAuditLog(testRoot(b, sesamDir), ids)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := VerifyChain(al, EmptyKeyring(), nil); err != nil {
				b.Fatal(err)
			}
			if err := al.Close(); err != nil {
				b.Fatal(err)
			}
		}
	})
}
