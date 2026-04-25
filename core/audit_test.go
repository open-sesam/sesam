package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOperationFor(t *testing.T) {
	cases := []struct {
		detail any
		want   operation
	}{
		{&DetailInit{}, opInit},
		{&DetailUserTell{}, opUserTell},
		{&DetailUserKill{}, opUserKill},
		{&DetailSecretChange{}, opSecretChange},
		{&DetailSecretRemove{}, opSecretRemove},
		{&DetailSeal{}, opSeal},
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
	require.Equal(t, opSeal, e.Operation)
	require.Equal(t, "alice", e.ChangedBy)
	require.False(t, e.Time.IsZero(), "Time should be set")
}

func TestNewAuditEntryDetailRoundtrip(t *testing.T) {
	detail := &DetailSecretChange{RevealedPath: "secrets/x", Groups: []string{"dev"}}
	entry := newAuditEntry("bob", detail)

	signed := &auditEntrySigned{auditEntry: *entry}
	got, err := parseDetail[DetailSecretChange](signed)
	require.NoError(t, err)
	require.Equal(t, "secrets/x", got.RevealedPath)
	require.Equal(t, []string{"dev"}, got.Groups)
}

func TestParseDetailCache(t *testing.T) {
	entry := newAuditEntry("alice", &DetailInit{InitUUID: "test-uuid"})
	signed := &auditEntrySigned{auditEntry: *entry}

	d1, err := parseDetail[DetailInit](signed)
	require.NoError(t, err)

	// Second call should return cached pointer.
	d2, err := parseDetail[DetailInit](signed)
	require.NoError(t, err)
	require.Same(t, d1, d2, "expected cached pointer")
}

func TestParseDetailWrongType(t *testing.T) {
	entry := newAuditEntry("alice", &DetailInit{InitUUID: "test"})
	signed := &auditEntrySigned{auditEntry: *entry}

	// Parse as Init first (caches it).
	_, err := parseDetail[DetailInit](signed)
	require.NoError(t, err)

	// Now try to parse as a different type — should fail.
	_, err = parseDetail[DetailSeal](signed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not *")
}

func TestParseDetailCorruptJSON(t *testing.T) {
	entry := newAuditEntry("alice", &DetailInit{InitUUID: "test"})
	signed := &auditEntrySigned{auditEntry: *entry}
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
		User:        "bob",
		Groups:      []string{"dev"},
		PubKeys:     []string{bob.Recipient.String()},
		SignPubKeys: []string{bob.SignPubKey},
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
		User:        "bob",
		Groups:      []string{"dev"},
		PubKeys:     []string{bob.Recipient.String()},
		SignPubKeys: []string{bob.SignPubKey},
	}), nil)
	require.NoError(t, err)

	require.NoError(t, al.Close())
	loaded, err := LoadAuditLog(sesamDir)
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
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	require.NoError(t, os.WriteFile(logPath, []byte(`{"entries":[]}`), 0o600))

	_, err := LoadAuditLog(sesamDir)
	require.Error(t, err)
}

func TestLoadMissingLogFile(t *testing.T) {
	sesamDir := testRepo(t)
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("somehash"), 0o600))

	_, err := LoadAuditLog(sesamDir)
	require.Error(t, err)
}

func TestLoadCorruptTrailingEntry(t *testing.T) {
	sesamDir := testRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	require.NoError(t, al.Close())

	// Append garbage after the valid entry to simulate a crash mid-write.
	logPath := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = f.WriteString(`{"operation":"seal","changed_by":"adm`)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Should recover: truncate the partial entry and load the valid one.
	loaded, err := LoadAuditLog(sesamDir)
	require.NoError(t, err)
	require.Len(t, loaded.Entries, 1, "should have the one valid init entry")
	require.NoError(t, loaded.Close())
}

func TestBuildRootHash(t *testing.T) {
	t.Run("order independent", func(t *testing.T) {
		sigs1 := []*secretSignature{
			{RevealedPath: "b", Hash: "hash-b"},
			{RevealedPath: "a", Hash: "hash-a"},
		}
		sigs2 := []*secretSignature{
			{RevealedPath: "a", Hash: "hash-a"},
			{RevealedPath: "b", Hash: "hash-b"},
		}

		h1 := buildRootHash(sigs1)
		h2 := buildRootHash(sigs2)
		require.NotEmpty(t, h1)
		require.Equal(t, h1, h2)
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		h1 := buildRootHash([]*secretSignature{{RevealedPath: "a", Hash: "hash-a"}})
		h2 := buildRootHash([]*secretSignature{{RevealedPath: "a", Hash: "hash-different"}})
		require.NotEqual(t, h1, h2)
	})

	t.Run("empty sigs", func(t *testing.T) {
		h := buildRootHash(nil)
		require.NotEmpty(t, h, "empty sigs should still produce a hash")
	})

	t.Run("single sig", func(t *testing.T) {
		h := buildRootHash([]*secretSignature{{RevealedPath: "a", Hash: "h"}})
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
	require.Equal(t, opInit, al.Entries[0].Operation)
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
	err := al.Iterate(func(idx int, entry *auditEntrySigned) error {
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
		PubKeys: []string{bob.Recipient.String()}, SignPubKeys: []string{bob.SignPubKey},
	}), nil)

	var count int
	err := al.Iterate(func(idx int, entry *auditEntrySigned) error {
		count++
		return fmt.Errorf("stop")
	})
	require.Error(t, err)
	require.Equal(t, 1, count, "should stop after first error")
}

func TestIterateEmpty(t *testing.T) {
	al := &AuditLog{}
	var count int
	err := al.Iterate(func(idx int, entry *auditEntrySigned) error {
		count++
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestAuditEntrySignedString(t *testing.T) {
	e := newAuditEntry("alice", &DetailSeal{RootHash: "abc", FilesSealed: 3})
	signed := &auditEntrySigned{auditEntry: *e}
	s := signed.String()
	require.NotEmpty(t, s)
	require.Contains(t, s, "abc")
}
