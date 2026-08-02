package core

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// feed appends a freshly signed entry to an in-memory log, mirroring the
// SeqID/PreviousHash/sign steps of AddEntry but skipping encryption and disk
// I/O. It lets a test synthesize divergent branches from a shared base without
// three on-disk logs.
func feed[T AuditDetail](t *testing.T, al *AuditLog, signer Signer, changedBy string, detail *T) {
	t.Helper()

	e := newAuditEntry(changedBy, detail)
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

// mergeBase builds a shared base log: init (admin) plus a tell of bob (dev).
func mergeBase(t *testing.T) (base *AuditLog, admin, bob *testUser) {
	t.Helper()

	admin = newTestUser(t, "admin")
	bob = newTestUser(t, "bob")

	base = &AuditLog{}
	initDetail := DetailInit{InitUUID: "merge-test", Admin: admin.DetailUserTell([]string{"admin"})}
	feed(t, base, admin.Signer, "admin", &initDetail)

	bobTell := bob.DetailUserTell([]string{"dev"})
	feed(t, base, admin.Signer, "admin", &bobTell)
	return base, admin, bob
}

func cloneLog(base *AuditLog) *AuditLog {
	return &AuditLog{Entries: append([]AuditEntrySigned(nil), base.Entries...)}
}

func signed[T AuditDetail](changedBy string, detail *T) *AuditEntrySigned {
	return &AuditEntrySigned{AuditEntry: *newAuditEntry(changedBy, detail)}
}

// findResolution returns the first resolution record for an operation.
func findResolution(cr *ConflictResolution, op Operation) (ConflictResolutionEntry, bool) {
	for _, r := range cr.Resolutions {
		if r.Operation == op {
			return r, true
		}
	}
	return ConflictResolutionEntry{}, false
}

// plannedGroups returns the merged group set of the last change_groups entry in
// the merged log (for asserting delta-merge results).
func plannedGroups(t *testing.T, merged *AuditLog, user string) []string {
	t.Helper()
	for i := len(merged.Entries) - 1; i >= 0; i-- {
		e := &merged.Entries[i]
		if e.Operation != OpUserChangeGroups {
			continue
		}
		d, err := parseDetail[DetailUserChangeGroups](e)
		require.NoError(t, err)
		if d.User == user {
			return d.NewGroups
		}
	}
	t.Fatalf("no change_groups for %s in merged log", user)
	return nil
}

func TestResolveTheirs(t *testing.T) {
	alice := newTestUser(t, "alice")

	// State helpers: merged/base carry only the fields the resolvers read.
	userState := func(users ...VerifiedUser) *VerifiedState {
		return &VerifiedState{Users: users}
	}
	secretState := func(secrets ...VerifiedSecret) *VerifiedState {
		return &VerifiedState{Secrets: secrets}
	}

	tests := []struct {
		name       string
		their      *AuditEntrySigned
		merged     *VerifiedState
		base       *VerifiedState
		wantAction MergeAction
	}{
		{
			name:       "seal is always dropped",
			their:      signed("admin", &DetailSeal{RootHash: "x"}),
			merged:     userState(),
			base:       userState(),
			wantAction: MergeDropped,
		},
		{
			name:       "U1 kill of present user applies",
			their:      signed("admin", &DetailUserKill{User: "bob"}),
			merged:     userState(VerifiedUser{Name: "bob", Groups: []string{"dev"}}),
			base:       userState(),
			wantAction: MergeApplied,
		},
		{
			name:       "U1 kill of absent user is dropped (dedupe)",
			their:      signed("admin", &DetailUserKill{User: "bob"}),
			merged:     userState(),
			base:       userState(),
			wantAction: MergeDropped,
		},
		{
			name:       "U3 change_groups on killed user is dropped",
			their:      signed("admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"ops"}}),
			merged:     userState(),
			base:       userState(VerifiedUser{Name: "bob", Groups: []string{"dev"}}),
			wantAction: MergeDropped,
		},
		{
			name:  "U3 change_groups delta-merges divergent sets",
			their: signed("admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "sec"}}),
			// ours already added ops; base had dev only.
			merged:     userState(VerifiedUser{Name: "bob", Groups: []string{"dev", "ops"}}),
			base:       userState(VerifiedUser{Name: "bob", Groups: []string{"dev"}}),
			wantAction: MergeRewritten,
		},
		{
			name:  "U3 remove wins over concurrent keep",
			their: signed("admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"ops"}}), // theirs removed dev
			// ours kept dev and added sec.
			merged:     userState(VerifiedUser{Name: "bob", Groups: []string{"dev", "ops", "sec"}}),
			base:       userState(VerifiedUser{Name: "bob", Groups: []string{"dev", "ops"}}),
			wantAction: MergeRewritten,
		},
		{
			name:       "U5 rename with occupied target is dropped",
			their:      signed("admin", &DetailUserRename{OldName: "bob", NewName: "alice"}),
			merged:     userState(VerifiedUser{Name: "bob"}, VerifiedUser{Name: "alice"}),
			base:       userState(),
			wantAction: MergeDropped,
		},
		{
			name:       "U6 regen prefers ours when we already rotated",
			their:      signed("admin", &DetailUserRegenerateSignKey{User: "bob", NewSignPubKey: "their-key"}),
			merged:     userState(VerifiedUser{Name: "bob", SignPubKey: "our-key"}),
			base:       userState(VerifiedUser{Name: "bob", SignPubKey: "base-key"}),
			wantAction: MergeDropped,
		},
		{
			name:       "B1 remove of present secret applies",
			their:      signed("admin", &DetailSecretRemove{RevealedPath: "s/db"}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin"}}),
			base:       secretState(),
			wantAction: MergeApplied,
		},
		{
			name:       "B4 move onto occupied path is dropped",
			their:      signed("admin", &DetailSecretMove{OldRevealedPath: "s/db", NewRevealedPath: "s/api"}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db"}, VerifiedSecret{RevealedPath: "s/api"}),
			base:       secretState(),
			wantAction: MergeDropped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveTheirs(tt.their, tt.merged, tt.base)
			require.Equal(t, tt.wantAction, r.Action)
		})
	}

	// U2: identical vs divergent tell of the same name.
	t.Run("U2 dedupes identical tell", func(t *testing.T) {
		existing := VerifiedUser{Name: alice.Name, SignPubKey: alice.SignPubKey, Recps: Recipients{alice.Recipient}}
		d := alice.DetailUserTell([]string{"dev"})
		r := resolveTheirs(signed("admin", &d), userState(existing), userState())
		require.Equal(t, MergeDropped, r.Action)
		require.False(t, r.conflict, "identical re-tell is not a conflict")
	})

	t.Run("U2 keeps ours on identity clash", func(t *testing.T) {
		existing := VerifiedUser{Name: alice.Name, SignPubKey: "different-key", Recps: Recipients{alice.Recipient}}
		d := alice.DetailUserTell([]string{"dev"})
		r := resolveTheirs(signed("admin", &d), userState(existing), userState())
		require.Equal(t, MergeDropped, r.Action)
		require.True(t, r.conflict, "diverging identity needs review")
	})
}

func TestThreeWaySet(t *testing.T) {
	tests := []struct {
		name                  string
		base, current, theirs []string
		want                  []string
	}{
		{"theirs adds", []string{"dev"}, []string{"dev"}, []string{"dev", "ops"}, []string{"dev", "ops"}},
		{"ours add preserved", []string{"dev"}, []string{"dev", "sec"}, []string{"dev", "ops"}, []string{"dev", "ops", "sec"}},
		{"remove wins over keep", []string{"dev", "ops"}, []string{"dev", "ops", "sec"}, []string{"ops"}, []string{"ops", "sec"}},
		{"both remove same", []string{"dev", "ops"}, []string{"ops"}, []string{"ops"}, []string{"ops"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ElementsMatch(t, tt.want, threeWaySet(tt.base, tt.current, tt.theirs))
		})
	}
}

func TestAuditMergeKillWins(t *testing.T) {
	base, admin, _ := mergeBase(t)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserKill{User: "bob"})

	merged, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	rec, ok := findResolution(cr, OpUserKill)
	require.True(t, ok)
	require.Equal(t, MergeApplied, rec.Action)
	require.Equal(t, "bob", rec.Target)
	require.Equal(t, "admin", rec.ChangedByBeforeMerge)

	// The kill is rebased and re-attributed to the merging admin.
	last := merged.Entries[len(merged.Entries)-1]
	require.Equal(t, OpMerge, last.Operation)
}

func TestAuditMergeModifyOnKilledUserDropped(t *testing.T) {
	base, admin, _ := mergeBase(t)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserKill{User: "bob"})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"ops"}})

	_, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	rec, ok := findResolution(cr, OpUserChangeGroups)
	require.True(t, ok)
	require.Equal(t, MergeDropped, rec.Action)
	require.Contains(t, rec.Reason, "killed")
	require.GreaterOrEqual(t, cr.Conflicts, 1)
}

func TestAuditMergeChangeGroupsDeltaMerge(t *testing.T) {
	base, admin, _ := mergeBase(t) // bob starts in [dev]

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "sec"}})

	merged, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	// A clean three-way delta merge needs no user attention: ours' ops and
	// theirs' sec both survive on top of the shared dev.
	require.Equal(t, 0, cr.Conflicts)
	require.ElementsMatch(t, []string{"dev", "ops", "sec"}, plannedGroups(t, merged, "bob"))
}

func TestAuditMergeNonAdminRejected(t *testing.T) {
	base, admin, bob := mergeBase(t)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)

	// bob is a dev, not an admin: he may not merge.
	_, _, err := AuditMerge(ours, theirs, base, bob.Signer, nil)
	require.ErrorContains(t, err, "not an admin")
}

func TestAuditMergeDifferentInitRejected(t *testing.T) {
	base, admin, _ := mergeBase(t)
	other, _, _ := mergeBase(t) // independent init -> different init hash

	ours := cloneLog(base)
	theirs := cloneLog(base)

	_, _, err := AuditMerge(ours, theirs, other, admin.Signer, nil)
	require.ErrorContains(t, err, "init entry differs")
}

// R1: after a merge kills the last member of an access group, that group is
// flagged as dangling (the reference is kept - it means admin-only).
func TestAuditMergeDanglingGroup(t *testing.T) {
	base, admin, _ := mergeBase(t) // bob is the only "dev"
	feed(t, base, admin.Signer, "admin", &DetailSecretAdd{RevealedPath: "s/db", AccessGroups: []string{"dev"}})

	ours := cloneLog(base)
	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserKill{User: "bob"})

	_, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	var found bool
	for _, r := range cr.Resolutions {
		if r.Action == MergeFlagged && r.Target == "dev" {
			found = true
		}
	}
	require.True(t, found, "expected a dangling-group advisory for 'dev'")
}

// U7: both sides kill a different admin. The per-entry last-admin guard declines
// theirs' kill rather than producing an adminless repo, and the merge succeeds.
// The merged plan must serialize to a real encrypted log that loads and verifies
// (this is what the git merge driver writes to %A).
func TestAuditMergeMaterializeRoundTrip(t *testing.T) {
	base, admin, _ := mergeBase(t)

	ours := cloneLog(base)
	rand.Read(ours.key[:]) // feed-built logs have no key; give a realistic one
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailSecretAdd{RevealedPath: "s/x", AccessGroups: []string{"dev"}})

	merged, _, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	// Serialize the way repo.MergeAuditLog does: derive recipients from the
	// merged state, then encrypt with the reused symmetric key.
	kr := EmptyKeyring()
	_, err = VerifyChain(merged, kr, nil)
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, merged.WriteEncrypted(&buf, AllRecipients(kr)))

	// The bytes must round-trip: decrypt with admin's identity, chain-verify.
	reloaded, err := loadAuditLogFromReader(&buf, Identities{admin.Identity})
	require.NoError(t, err)
	require.Equal(t, len(merged.Entries), len(reloaded.Entries))

	reloaded.InitHash = reloaded.Entries[0].Hash() // loadFromReader has no init file
	_, err = VerifyChain(reloaded, EmptyKeyring(), nil)
	require.NoError(t, err)

	require.Equal(t, OpMerge, reloaded.Entries[len(reloaded.Entries)-1].Operation)
}

func TestAuditMergeZeroAdminDeclined(t *testing.T) {
	admin := newTestUser(t, "admin")
	alice := newTestUser(t, "alice")

	base := &AuditLog{}
	initD := DetailInit{InitUUID: "u7", Admin: admin.DetailUserTell([]string{"admin"})}
	feed(t, base, admin.Signer, "admin", &initD)
	aliceTell := alice.DetailUserTell([]string{"admin"})
	feed(t, base, admin.Signer, "admin", &aliceTell)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserKill{User: "alice"})

	theirs := cloneLog(base)
	feed(t, theirs, alice.Signer, "alice", &DetailUserKill{User: "admin"})

	_, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err) // never blocks: the offending kill is declined

	rec, ok := findResolution(cr, OpUserKill)
	require.True(t, ok)
	require.Equal(t, MergeDropped, rec.Action)
	require.Contains(t, rec.Reason, "last admin")
}
