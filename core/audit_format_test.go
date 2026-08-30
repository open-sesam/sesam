package core

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

// The audit log is the repo's history: every entry is signed, and each links to
// the hash of the one before it. That makes the on-disk shape of an entry part
// of the format - rename a field, reorder the JSON, change the hash or the
// signature encoding, and every existing log in the wild stops verifying.
//
// This pins a chain built from one entry of every operation. The head hash
// covers all of them, so any change to the entry layout, a detail struct, the
// chaining, or the hash algorithm moves it. Updating the constant is fine; doing
// so without meaning to is what this catches.
const auditChainHeadHash = "HiBEyyrdHk608NzcBx/VTIy2cSuk9BOVZ//oNVz6ytbnaQ=="

// fixedTime keeps the entries deterministic - Time is part of what gets signed.
var fixedTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

// formatSigner is a signer with a hardcoded key, so signatures are reproducible.
func formatSigner(t *testing.T) *ed25519Signer {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	return &ed25519Signer{
		pub:  priv.Public().(ed25519.PublicKey),
		priv: priv,
		user: "admin",
	}
}

func feedFixed[T AuditDetail](t *testing.T, al *AuditLog, signer Signer, detail *T) {
	t.Helper()

	e := newAuditEntry("admin", detail)
	e.Time = fixedTime
	e.SeqID = uint64(len(al.Entries)) + 1
	if len(al.Entries) > 0 {
		e.PreviousHash = al.Entries[len(al.Entries)-1].Hash()
	} else {
		e.PreviousHash = hashData([]byte(sesamInitialHashSeed))
	}

	aes, err := e.Sign(signer)
	require.NoError(t, err)
	al.Entries = append(al.Entries, *aes)
}

// formatReferenceLog builds one entry per operation, with fixed content.
func formatReferenceLog(t *testing.T) *AuditLog {
	t.Helper()

	signer := formatSigner(t)
	al := &AuditLog{}

	admin := DetailUserTell{
		User:       "admin",
		Groups:     []string{"admin"},
		PubKeys:    []UserPubKey{{Key: "age1reference0000000000000000000000000000000000000000000000", Source: KeySourceManual}},
		SignPubKey: "7QEgreference0000000000000000000000000000000=",
	}

	feedFixed(t, al, signer, &DetailInit{InitUUID: "00000000-0000-0000-0000-000000000000", Admin: admin})
	feedFixed(t, al, signer, &DetailUserTell{
		User:       "bob",
		Groups:     []string{"dev"},
		PubKeys:    []UserPubKey{{Key: "age1reference1111111111111111111111111111111111111111111111", Source: KeySourceManual}},
		SignPubKey: "7QEgreference1111111111111111111111111111111=",
	})
	feedFixed(t, al, signer, &DetailSecretAdd{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}})
	feedFixed(t, al, signer, &DetailSeal{RootHash: "FiAreference00000000000000000000000000000000="})
	feedFixed(t, al, signer, &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})
	feedFixed(t, al, signer, &DetailUserAddRecipients{
		User:    "bob",
		PubKeys: []UserPubKey{{Key: "age1reference2222222222222222222222222222222222222222222222", Source: KeySourceManual}},
	})
	feedFixed(t, al, signer, &DetailUserRmRecipients{
		User:    "bob",
		PubKeys: []UserPubKey{{Key: "age1reference1111111111111111111111111111111111111111111111", Source: KeySourceManual}},
	})
	feedFixed(t, al, signer, &DetailUserRegenerateSignKey{User: "bob", NewSignPubKey: "7QEgreference2222222222222222222222222222222="})
	feedFixed(t, al, signer, &DetailUserRename{OldName: "bob", NewName: "bobby"})
	feedFixed(t, al, signer, &DetailSecretChangeAccess{RevealedPath: "s/db", AccessGroups: []string{"admin"}})
	feedFixed(t, al, signer, &DetailSecretMove{OldRevealedPath: "s/db", NewRevealedPath: "s/api"})
	feedFixed(t, al, signer, &DetailSecretRemove{RevealedPath: "s/api"})
	feedFixed(t, al, signer, &DetailMerge{
		BaseSeqID: 1, OurTipSeqID: 2, TheirTipSeqID: 3, Applied: 1, Dropped: 0,
	})
	feedFixed(t, al, signer, &DetailUserKill{User: "bobby"})

	return al
}

// TestAuditChainHeadHashIsStable is the reference: the head hash must not move
// unless the format deliberately changed.
func TestAuditChainHeadHashIsStable(t *testing.T) {
	al := formatReferenceLog(t)
	head := al.Entries[len(al.Entries)-1].Hash()

	require.Equal(t, auditChainHeadHash, head,
		"the audit entry format changed - existing logs would no longer verify. "+
			"If that is intended, update auditChainHeadHash.")
}

// TestFormatReferenceCoversEveryOperation keeps the reference honest: a new
// operation has to be added to it, or it pins nothing about that operation.
func TestFormatReferenceCoversEveryOperation(t *testing.T) {
	seen := map[Operation]bool{}
	for _, e := range formatReferenceLog(t).Entries {
		seen[e.Operation] = true
	}

	for _, op := range []Operation{
		OpInit, OpUserTell, OpUserKill, OpSecretAdd, OpSecretRemove, OpSeal, OpMerge,
		OpUserRename, OpUserChangeGroups, OpSecretMove, OpSecretChangeAccess,
		OpUserAddRecipients, OpUserRmRecipients, OpUserRegenerateSignKey,
	} {
		require.True(t, seen[op], "operation %s is missing from the format reference", op)
	}
}

// The reference above pins the plaintext shape of an entry. It says nothing
// about the container: line 1 wraps the symmetric key for the recipients, and
// every entry line is its own nonce plus an XChaCha20-Poly1305 ciphertext with
// the seq id as associated data. Change any of that and existing logs stop
// decrypting, while the entry hashes stay identical.
//
// So a real encrypted log is committed under testdata together with the age
// identity that opens it. Regenerate both deliberately with:
//
//	SESAM_UPDATE_FIXTURES=1 go test ./core/ -run TestUpdateAuditLogFixture
const (
	auditLogFixture    = "audit_log_v1.jsonl"
	auditLogFixtureKey = "audit_log_v1.key.age"
)

func TestEncryptedAuditLogFixtureStillOpens(t *testing.T) {
	keyData, err := os.ReadFile(filepath.Join("testdata", auditLogFixtureKey))
	require.NoError(t, err)

	ageID, err := age.ParseX25519Identity(strings.TrimSpace(string(keyData)))
	require.NoError(t, err)

	fd, err := os.Open(filepath.Join("testdata", auditLogFixture))
	require.NoError(t, err)

	defer func() { _ = fd.Close() }()

	ids := Identities{{Identity: ageID, pub: newStringPubKey(ageID.Recipient().String())}}

	al, err := loadAuditLogFromReader(fd, ids)
	require.NoError(t, err, "the audit log container format changed - committed logs no longer decrypt")

	// Decrypting is half of it: the entries must still replay into a state.
	al.InitHash = al.Entries[0].Hash()
	state, err := VerifyChain(al, EmptyKeyring(), nil)
	require.NoError(t, err, "the fixture no longer verifies")

	admin, ok := state.UserExists("admin")
	require.True(t, ok)
	require.True(t, admin.IsAdmin())

	_, ok = state.UserExists("bob")
	require.True(t, ok, "the tell of bob should have replayed")

	secret, ok := state.SecretExists("s/db")
	require.True(t, ok, "the secret should have replayed")
	require.Contains(t, secret.AccessGroups, "dev")
}

// TestUpdateAuditLogFixture rewrites the fixture. It only runs when asked, so a
// format change fails the test above instead of quietly rewriting the evidence.
func TestUpdateAuditLogFixture(t *testing.T) {
	if os.Getenv("SESAM_UPDATE_FIXTURES") == "" {
		t.Skip("set SESAM_UPDATE_FIXTURES=1 to regenerate")
	}

	admin := newTestUser(t, "admin")
	bob := newTestUser(t, "bob")

	al := &AuditLog{}
	initDetail := DetailInit{InitUUID: "fixture-v1", Admin: admin.DetailUserTell([]string{"admin"})}
	feed(t, al, admin.Signer, "admin", &initDetail)

	bobTell := bob.DetailUserTell([]string{"dev"})
	feed(t, al, admin.Signer, "admin", &bobTell)
	feed(t, al, admin.Signer, "admin", &DetailSecretAdd{RevealedPath: "s/db", AccessGroups: []string{"dev"}})
	feed(t, al, admin.Signer, "admin", &DetailSeal{RootHash: "FiAfixture000000000000000000000000000000000="})

	recps, err := ParseRecipients([]string{admin.Recipient.String()}, nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, writeEncryptedLog(&buf, newAuditKey(), recps, al.Entries))
	require.NoError(t, os.WriteFile(filepath.Join("testdata", auditLogFixture), buf.Bytes(), 0o600))

	ageID, ok := admin.Identity.Identity.(*age.X25519Identity)
	require.True(t, ok)
	require.NoError(t, os.WriteFile(
		filepath.Join("testdata", auditLogFixtureKey),
		[]byte(ageID.String()+"\n"),
		0o600,
	))
}
