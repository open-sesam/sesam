package core

import (
	"bytes"
	"crypto/rand"
	"strings"
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
	// The lookup indexes are derived, so a hand-built state needs them too.
	userState := func(users ...VerifiedUser) *VerifiedState {
		state := &VerifiedState{Users: users}
		state.rebuildUserIndex()
		state.rebuildSecretIndex()
		return state
	}
	secretState := func(secrets ...VerifiedSecret) *VerifiedState {
		state := &VerifiedState{Secrets: secrets}
		state.rebuildUserIndex()
		state.rebuildSecretIndex()
		return state
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

		// --- change_access (was entirely untested) ---
		{
			name:       "change_access delta-merges divergent sets",
			their:      signed("admin", &DetailSecretChangeAccess{RevealedPath: "s/db", AccessGroups: []string{"dev", "sec"}}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev", "ops"}}),
			base:       secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			wantAction: MergeRewritten,
		},
		{
			name:       "change_access already covered by ours is dropped",
			their:      signed("admin", &DetailSecretChangeAccess{RevealedPath: "s/db", AccessGroups: []string{"dev"}}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev", "ops"}}),
			base:       secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			wantAction: MergeDropped,
		},
		{
			name:       "change_access equal to theirs applies",
			their:      signed("admin", &DetailSecretChangeAccess{RevealedPath: "s/db", AccessGroups: []string{"dev", "ops"}}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			base:       secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			wantAction: MergeApplied,
		},
		{
			name:       "change_access on removed secret is dropped",
			their:      signed("admin", &DetailSecretChangeAccess{RevealedPath: "s/db", AccessGroups: []string{"dev"}}),
			merged:     secretState(),
			base:       secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			wantAction: MergeDropped,
		},

		// --- secret remove / add conflict branches ---
		{
			name:       "remove wins over concurrent access change",
			their:      signed("admin", &DetailSecretRemove{RevealedPath: "s/db"}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev", "ops"}}),
			base:       secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			wantAction: MergeApplied,
		},
		{
			name:       "add of same path with different access keeps ours",
			their:      signed("admin", &DetailSecretAdd{RevealedPath: "s/db", AccessGroups: []string{"ops"}}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			base:       secretState(),
			wantAction: MergeDropped,
		},
		{
			name:       "add of same path with same access dedupes",
			their:      signed("admin", &DetailSecretAdd{RevealedPath: "s/db", AccessGroups: []string{"dev"}}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db", AccessGroups: []string{"admin", "dev"}}),
			base:       secretState(),
			wantAction: MergeDropped,
		},

		// --- secret move / rename / regen apply branches ---
		{
			name:       "move to a free path applies",
			their:      signed("admin", &DetailSecretMove{OldRevealedPath: "s/db", NewRevealedPath: "s/new"}),
			merged:     secretState(VerifiedSecret{RevealedPath: "s/db"}),
			base:       secretState(),
			wantAction: MergeApplied,
		},
		{
			name:       "move with vanished source is dropped",
			their:      signed("admin", &DetailSecretMove{OldRevealedPath: "s/db", NewRevealedPath: "s/new"}),
			merged:     secretState(),
			base:       secretState(),
			wantAction: MergeDropped,
		},
		{
			name:       "rename to a free name applies",
			their:      signed("admin", &DetailUserRename{OldName: "bob", NewName: "carol"}),
			merged:     userState(VerifiedUser{Name: "bob"}),
			base:       userState(),
			wantAction: MergeApplied,
		},
		{
			name:       "regen applies when ours has not rotated",
			their:      signed("admin", &DetailUserRegenerateSignKey{User: "bob", NewSignPubKey: "their-key"}),
			merged:     userState(VerifiedUser{Name: "bob", SignPubKey: "base-key"}),
			base:       userState(VerifiedUser{Name: "bob", SignPubKey: "base-key"}),
			wantAction: MergeApplied,
		},

		// --- recipient add / remove (were untested) ---
		{
			name:       "add-recipients to a live user applies",
			their:      signed("admin", &DetailUserAddRecipients{User: "bob"}),
			merged:     userState(VerifiedUser{Name: "bob"}),
			base:       userState(),
			wantAction: MergeApplied,
		},
		{
			name:       "add-recipients to a gone user is dropped",
			their:      signed("admin", &DetailUserAddRecipients{User: "bob"}),
			merged:     userState(),
			base:       userState(),
			wantAction: MergeDropped,
		},
		{
			name:       "rm-recipients of a present key applies",
			their:      signed("admin", &DetailUserRmRecipients{User: "bob", PubKeys: []UserPubKey{{Key: alice.Recipient.String()}}}),
			merged:     userState(VerifiedUser{Name: "bob", Recps: Recipients{alice.Recipient}}),
			base:       userState(),
			wantAction: MergeApplied,
		},
		{
			name:       "rm-recipients of an already-gone key is a no-op",
			their:      signed("admin", &DetailUserRmRecipients{User: "bob", PubKeys: []UserPubKey{{Key: alice.Recipient.String()}}}),
			merged:     userState(VerifiedUser{Name: "bob"}),
			base:       userState(),
			wantAction: MergeDropped,
		},
		{
			name:       "rm-recipients from a gone user is a satisfied no-op",
			their:      signed("admin", &DetailUserRmRecipients{User: "bob"}),
			merged:     userState(),
			base:       userState(),
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
	// merged state, then encrypt with the merged log's freshly rotated key.
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
	// theirs kills the merger, which the merger-preserve rule declines first (it
	// front-runs the generic last-admin guard). Either way the merge keeps an admin.
	require.Contains(t, rec.Reason, "merging admin")
}

// TestAuditMergeRevertedTwinIsNotDropped guards the base-relative new-entry
// detection: theirs' delta is computed against the merge base (origin), not
// against ours' full history. When ours performs then reverts a change and theirs
// makes that same change for real, theirs' entry must not be masked by the
// superseded ours entry.
//
// Here ours adds then removes "ops" (net [dev]); theirs adds "ops" (net [dev,ops]).
// The three-way merge must keep "ops" (ours made no net change vs base).
func TestAuditMergeRevertedTwinIsNotDropped(t *testing.T) {
	base, admin, _ := mergeBase(t) // bob starts in [dev]

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	merged, _, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	state, err := VerifyChain(merged, EmptyKeyring(), nil)
	require.NoError(t, err)

	u, ok := state.UserExists("bob")
	require.True(t, ok)
	require.ElementsMatch(t, []string{"dev", "ops"}, u.Groups,
		"theirs added ops and ours made no net change vs base; merge must keep ops")
}

// TestAuditMergePreservesMerger checks that theirs' kill of the merging admin is
// dropped (not applied), so the merge completes instead of aborting mid-replay
// when the merger re-signs the terminal record. The merger must always survive.
func TestAuditMergePreservesMerger(t *testing.T) {
	base, admin, _ := mergeBase(t)

	// A second admin exists so the kill is not blocked by the last-admin guard -
	// it must be blocked specifically because the target is the merger.
	carol := newTestUser(t, "carol")
	carolTell := carol.DetailUserTell([]string{"admin"})
	feed(t, base, admin.Signer, "admin", &carolTell)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, carol.Signer, "carol", &DetailUserKill{User: "admin"}) // theirs removes the merger

	merged, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err, "merge must not abort when theirs kills the merger")

	state, err := VerifyChain(merged, EmptyKeyring(), nil)
	require.NoError(t, err)

	u, ok := state.UserExists("admin")
	require.True(t, ok, "the merging admin must survive the merge")
	require.True(t, u.IsAdmin())

	rec, ok := findResolution(cr, OpUserKill)
	require.True(t, ok)
	require.Equal(t, MergeDropped, rec.Action)
	require.Contains(t, rec.Reason, "merging admin")
}

func TestHasConflictMarkers(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "real conflict",
			in:   "a\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> other\nb\n",
			want: true,
		},
		{
			name: "diff3 conflict (base section) still has start+end",
			in:   "<<<<<<< ours\nx\n||||||| base\ny\n=======\nz\n>>>>>>> theirs\n",
			want: true,
		},
		{
			name: "label-less markers",
			in:   "<<<<<<<\nours\n=======\ntheirs\n>>>>>>>\n",
			want: true,
		},
		{
			name: "lone separator is not a conflict",
			in:   "title\n=======\nunderline-style heading\n",
			want: false,
		},
		{
			name: "start without end is not flagged",
			in:   "<<<<<<< looks like a start but no end marker\ndata\n",
			want: false,
		},
		{
			name: "short runs are not markers",
			in:   "<<<< four\n>>>> four\n",
			want: false,
		},
		{
			name: "markers must be at line start",
			in:   "prefix <<<<<<< HEAD\nprefix >>>>>>> other\n",
			want: false,
		},
		{
			name: "clean file",
			in:   "user = admin\npassword = hunter2\n",
			want: false,
		},
		{
			name: "empty file",
			in:   "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hasConflictMarkers(strings.NewReader(tt.in))
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestAuditMergeRecipientRemoveWins pins A1: theirs re-adding a recipient key our
// side revoked since base must not resurrect it (remove wins). A genuinely new
// key theirs adds is still kept.
func TestAuditMergeRecipientRemoveWins(t *testing.T) {
	userState := func(u ...VerifiedUser) *VerifiedState {
		state := &VerifiedState{Users: u}
		state.rebuildUserIndex()
		state.rebuildSecretIndex()
		return state
	}

	k1 := newTestUser(t, "k1").Recipient
	k2 := newTestUser(t, "k2").Recipient
	k3 := newTestUser(t, "k3").Recipient

	base := userState(VerifiedUser{Name: "bob", Recps: Recipients{k1, k2}})
	ours := userState(VerifiedUser{Name: "bob", Recps: Recipients{k1}}) // ours revoked k2

	t.Run("revoked key alone is dropped", func(t *testing.T) {
		their := signed("admin", &DetailUserAddRecipients{User: "bob", PubKeys: []UserPubKey{{Key: k2.String()}}})
		r := resolveTheirs(their, ours, base)
		require.Equal(t, MergeDropped, r.Action)
		require.True(t, r.conflict)
	})

	t.Run("new key survives, revoked one dropped", func(t *testing.T) {
		their := signed("admin", &DetailUserAddRecipients{User: "bob", PubKeys: []UserPubKey{{Key: k2.String()}, {Key: k3.String()}}})
		r := resolveTheirs(their, ours, base)
		require.Equal(t, MergeRewritten, r.Action)
		d, err := parseDetail[DetailUserAddRecipients](&AuditEntrySigned{AuditEntry: *r.entry})
		require.NoError(t, err)
		require.Len(t, d.PubKeys, 1)
		require.Equal(t, k3.String(), d.PubKeys[0].Key)
	})
}

// TestAuditMergeDroppedRenameOrphansDependents pins A5: theirs renames alice->bob,
// but bob already exists on our side (ours told a different bob). The rename is
// dropped (target occupied); theirs' later change-groups on "bob" must be skipped,
// not silently applied to our unrelated bob.
func TestAuditMergeDroppedRenameOrphansDependents(t *testing.T) {
	base, admin, _ := mergeBase(t) // admin + bob(dev)
	// Add alice at base so theirs can rename her; remove the base bob so our side
	// can introduce its own unrelated bob after divergence.
	alice := newTestUser(t, "alice")
	aliceTell := alice.DetailUserTell([]string{"dev"})
	feed(t, base, admin.Signer, "admin", &aliceTell)
	feed(t, base, admin.Signer, "admin", &DetailUserKill{User: "bob"})

	ours := cloneLog(base)
	ourBob := newTestUser(t, "ourbob")
	bobTell := ourBob.DetailUserTell([]string{"dev"})
	bobTell.User = "bob" // our own, unrelated "bob"
	feed(t, ours, admin.Signer, "admin", &bobTell)

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserRename{OldName: "alice", NewName: "bob"})
	feed(t, theirs, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	merged, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)

	state, err := VerifyChain(merged, EmptyKeyring(), nil)
	require.NoError(t, err)

	// Our bob keeps its original groups; theirs' change-groups did not land on it.
	u, ok := state.UserExists("bob")
	require.True(t, ok)
	require.ElementsMatch(t, []string{"dev"}, u.Groups, "theirs' change-groups must not hit our unrelated bob")

	rec, ok := findResolution(cr, OpUserChangeGroups)
	require.True(t, ok)
	require.Equal(t, MergeDropped, rec.Action)
}

// TestAuditMergeReissuedKillNotDropped pins Finding 1: the base-diff must be a
// multiset. origin killed then re-added zoe (so a "kill zoe" already exists in the
// base history); theirs re-issues "kill zoe" as a genuine new revocation, which
// must NOT be absorbed by the base occurrence.
func TestAuditMergeReissuedKillNotDropped(t *testing.T) {
	base, admin, _ := mergeBase(t)
	zoe := newTestUser(t, "zoe")
	tell1 := zoe.DetailUserTell([]string{"dev"})
	feed(t, base, admin.Signer, "admin", &tell1)
	feed(t, base, admin.Signer, "admin", &DetailUserKill{User: "zoe"})
	tell2 := zoe.DetailUserTell([]string{"dev"})
	feed(t, base, admin.Signer, "admin", &tell2) // zoe present at origin tip

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserKill{User: "zoe"}) // genuine new revocation

	merged, _, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)
	state, err := VerifyChain(merged, EmptyKeyring(), nil)
	require.NoError(t, err)
	_, ok := state.UserExists("zoe")
	require.False(t, ok, "theirs' re-issued kill of zoe must survive the base-diff")
}

// TestAuditMergePreservesMergerRename pins Finding 2: theirs renaming the merging
// admin must be dropped, not applied - applying it would strand the terminal merge
// entry (authored under the old name) and abort the whole merge.
func TestAuditMergePreservesMergerRename(t *testing.T) {
	base, admin, _ := mergeBase(t)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserRename{OldName: "admin", NewName: "root"})

	merged, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err, "renaming the merger must not abort the merge")

	state, err := VerifyChain(merged, EmptyKeyring(), nil)
	require.NoError(t, err)
	u, ok := state.UserExists("admin")
	require.True(t, ok, "the merging admin must survive")
	require.True(t, u.IsAdmin())

	rec, ok := findResolution(cr, OpUserRename)
	require.True(t, ok)
	require.Equal(t, MergeDropped, rec.Action)
}

// TestAuditMergeForgedTheirsRejected guards the merge's trust boundary: theirs
// arrives from git as an opaque blob and is only decrypted on load, so the chain
// has to be verified before any of it is rebased. Otherwise re-signing hands the
// merging admin's authority to whatever the branch happened to contain.
func TestAuditMergeForgedTheirsRejected(t *testing.T) {
	base, admin, bob := mergeBase(t)

	ours := cloneLog(base)
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	// Every active user can decrypt the log, so bob can append a well-formed,
	// correctly chained entry making himself admin. What he cannot do is sign it
	// as the admin - and that is the only thing standing in his way.
	theirs := cloneLog(base)
	feed(t, theirs, bob.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "admin"}})

	_, _, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.ErrorContains(t, err, "verify theirs")
}

// TestAuditMergeRevokedAuthorDropped covers the cross-branch half of the same
// problem: theirs' entries do verify on their branch, but our side killed or
// demoted their author since the base. Rebasing them onto the merger's signature
// must not reinstate what we just took away.
func TestAuditMergeRevokedAuthorDropped(t *testing.T) {
	tests := []struct {
		name       string
		ourChange  func(t *testing.T, ours *AuditLog, admin *testUser)
		wantApply  bool
		wantReason string
	}{
		{
			name: "killed author",
			ourChange: func(t *testing.T, ours *AuditLog, admin *testUser) {
				feed(t, ours, admin.Signer, "admin", &DetailUserKill{User: "carol"})
			},
			wantReason: "was removed on our side",
		},
		{
			name: "demoted author",
			ourChange: func(t *testing.T, ours *AuditLog, admin *testUser) {
				feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "carol", NewGroups: []string{"dev"}})
			},
			wantReason: "no longer an admin",
		},
		{
			name: "untouched author still applies",
			ourChange: func(t *testing.T, ours *AuditLog, admin *testUser) {
				feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})
			},
			wantApply: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// carol is a second admin so demoting/killing her does not trip the
			// last-admin guard, and she is not the merger.
			base, admin, _ := mergeBase(t)
			carol := newTestUser(t, "carol")
			carolTell := carol.DetailUserTell([]string{"admin"})
			feed(t, base, admin.Signer, "admin", &carolTell)

			ours := cloneLog(base)
			tc.ourChange(t, ours, admin)

			theirs := cloneLog(base)
			daveTell := newTestUser(t, "dave").DetailUserTell([]string{"dev"})
			feed(t, theirs, carol.Signer, "carol", &daveTell)

			merged, cr, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
			require.NoError(t, err)

			state, err := VerifyChain(merged, EmptyKeyring(), nil)
			require.NoError(t, err)

			_, daveExists := state.UserExists("dave")
			if tc.wantApply {
				require.True(t, daveExists)
				require.Equal(t, 0, cr.Conflicts)
				return
			}

			require.False(t, daveExists, "a revoked author must not get their entry applied")

			rec, ok := findResolution(cr, OpUserTell)
			require.True(t, ok)
			require.Equal(t, MergeDropped, rec.Action)
			require.Equal(t, "carol", rec.Target)
			require.Contains(t, rec.Reason, tc.wantReason)
		})
	}
}

// TestAuditMergeRotatesKey: a merge can carry a kill from theirs, and the killed
// user already holds ours' symmetric key. Keeping it would let them read every
// entry written after the merge.
func TestAuditMergeRotatesKey(t *testing.T) {
	base, admin, _ := mergeBase(t)

	ours := cloneLog(base)
	ours.key = newAuditKey()
	feed(t, ours, admin.Signer, "admin", &DetailUserChangeGroups{User: "bob", NewGroups: []string{"dev", "ops"}})

	theirs := cloneLog(base)
	feed(t, theirs, admin.Signer, "admin", &DetailUserKill{User: "bob"})

	merged, _, err := AuditMerge(ours, theirs, base, admin.Signer, nil)
	require.NoError(t, err)
	require.NotEqual(t, ours.key, merged.key)
}

// The table is the one place that says what an operation is, so nothing may
// fall out of it silently. verify() is the authority on who may do what; if the
// two disagree, an entry gets rebased that verification would have rejected.
func TestOpTableCoversEveryOperation(t *testing.T) {
	all := []Operation{
		OpInit, OpUserTell, OpUserKill, OpSecretAdd, OpSecretRemove, OpSeal, OpMerge,
		OpUserRename, OpUserChangeGroups, OpSecretMove, OpSecretChangeAccess,
		OpUserAddRecipients, OpUserRmRecipients, OpUserRegenerateSignKey,
	}

	for _, op := range all {
		t.Run(string(op), func(t *testing.T) {
			info, ok := mergeOpTable[op]
			require.True(t, ok, "operation missing from opTable")
			require.NotNil(t, info.resolve, "every operation needs a resolver")
		})
	}

	require.Len(t, mergeOpTable, len(all), "opTable has an entry for an unknown operation")
}

// The user-facing ops are exactly the ones verify() gates on RequireAdmin.
func TestOpTableAdminOnlyMatchesVerify(t *testing.T) {
	adminOnly := map[Operation]bool{
		OpUserTell: true, OpUserKill: true, OpUserRename: true,
		OpUserRegenerateSignKey: true, OpUserChangeGroups: true,
		OpUserAddRecipients: true, OpUserRmRecipients: true, OpMerge: true,
	}

	for op, info := range mergeOpTable {
		require.Equal(t, adminOnly[op], info.adminOnly, "adminOnly mismatch for %s", op)
	}
}
