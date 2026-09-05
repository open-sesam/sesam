package core

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
)

// Audit-log merge: design notes.
//
// The audit log is an event-sourced projection: VerifyChain replays entries
// into a VerifiedState (users, groups, per-secret access, LastSealRootHash).
// That derived state - not sesam.yml - is the source of truth, and only the
// LAST seal's root hash is checked against disk. Merging two logs therefore
// means rebasing theirs' new entries onto ours and re-signing them, so the
// result replays to a coherent merged state. We never concatenate the chains.
//
// Guiding decisions:
//   - Revocation wins: a kill/remove beats a concurrent modify (least privilege).
//   - Set-valued fields (groups, recipients, access lists) three-way delta-merge
//     against theirs' pre-entry state; on an add-vs-remove clash of the same
//     element, remove wins.
//   - Single-valued fields (rename/move target, sign key) prefer ours + warn:
//     there is no union to form.
//   - delete-vs-modify: the delete wins + warn (the modification is discarded).
//   - Time is informational only, never the arbiter (clock skew, spoofable).
//   - Only the re-signature survives: theirs is re-signed by the merging admin.
//     The original author is kept in ChangedByBeforeMerge, and one merge entry
//     records provenance and the decisions that needed a judgement call.
//   - sesam.yml is regenerated from the merged log, so config never conflicts
//     textually.
//   - Best effort, never block: pre-decide for the user and warn. Only a
//     non-admin (who cannot decrypt + re-sign) must abort and ask an admin.
//
// Mechanics:
//   - The init entry must be identical on every side, else a hard error (a
//     different repo or a truncated log, not a conflict).
//   - Find the common base, then feed theirs' new entries onto ours through the
//     ordinary verify path, re-signed by the merger. Its per-entry guards already
//     enforce the invariants: a kill that would drop the last admin, or a rename
//     onto an occupied name, is simply declined and recorded - so most "global"
//     repairs need no separate pass.
//   - The merged log gets a fresh symmetric key: a merge can carry a kill, and
//     the removed user must not keep reading what comes after it.
//   - The terminal seal is deferred to the pre-commit reseal, which recomputes the
//     root hash from the actually-merged objects; both sides' post-base seals are
//     dropped as authorities.
//
// The per-operation resolution rules live as doc comments on the individual
// resolve* functions below.

// ConflictResolution is AuditMerge's in-process result: the noteworthy decisions
// (conflicts plus post-merge advisories) for the UI to show now, and their
// count. Routine applies/dedupes appear only as the counts in the persisted
// DetailMerge; the full breakdown is recomputable from the merge parents.
type ConflictResolution struct {
	Resolutions []ConflictResolutionEntry
	Conflicts   int
}

// mergeStates are the four states a resolver needs to place one of theirs'
// entries. They answer different questions:
//
//   - merged: the running result (ours plus theirs' entries applied so far).
//   - theirPrev: theirs just before this entry, so its delta can be read off.
//   - ours: our side at the point we diverged, frozen. `merged` drifts from it
//     as theirs' entries land, so only `ours` still says what WE decided.
//   - base: what both sides started from. Together with `ours` it identifies
//     what our side revoked, which theirs must not resurrect.
type mergeStates struct {
	merged    *VerifiedState
	theirPrev *VerifiedState
	ours      *VerifiedState
	base      *VerifiedState
}

// oursRemovedGroups returns the groups our side dropped from `user` since the
// base - the ones a re-grant from theirs must not bring back (least privilege).
func (s *mergeStates) oursRemovedGroups(user string) []string {
	return stringSetMinus(userGroups(s.base, user), userGroups(s.ours, user))
}

// oursRemovedAccess is oursRemovedGroups for a secret's access list.
func (s *mergeStates) oursRemovedAccess(path string) []string {
	return stringSetMinus(secretAccess(s.base, path), secretAccess(s.ours, path))
}

// resolution is resolveTheirs' decision for one incoming entry. The embedded
// ConflictResolutionEntry carries the user-facing fields (Action, Reason, ...);
// `entry` is what to apply (nil => drop) and `conflict` marks a judgement call
// the user should review.
type resolution struct {
	ConflictResolutionEntry
	entry    *AuditEntry
	conflict bool
}

func applyAs(their *AuditEntrySigned) resolution {
	e := their.AuditEntry // value copy; caller stamps ChangedBy/provenance
	return resolution{ConflictResolutionEntry: ConflictResolutionEntry{Action: MergeApplied}, entry: &e}
}

// rewriteAs applies a modified version of theirs' entry. `conflict` marks the
// rewrite as a judgement call: set it when the rewrite contradicts what theirs
// asked for, not when it merely unions in something theirs never mentioned.
func rewriteAs(e *AuditEntry, reason string, conflict bool) resolution {
	return resolution{
		ConflictResolutionEntry: ConflictResolutionEntry{Action: MergeRewritten, Reason: reason},
		entry:                   e,
		conflict:                conflict,
	}
}

func dropWith(reason string, conflict bool) resolution {
	return resolution{ConflictResolutionEntry: ConflictResolutionEntry{Action: MergeDropped, Reason: reason}, conflict: conflict}
}

// entryContentKey identifies an entry by WHAT it does, independent of who signed
// it or where it sits in the chain.
func entryContentKey(e *AuditEntry) string {
	return string(e.Operation) + "\x00" + string(e.Detail)
}

// requireSameInit requires the base/init entry to be byte-identical on every
// side. A mismatch means a different repo or a truncated log - a hard
// error, not a conflict. As a side effect it sets each log's InitHash to the
// shared value so the subsequent VerifyChain can validate the init entry (logs
// loaded via LoadAuditLogFromPath have no init file, hence an empty InitHash).
func requireSameInit(logs ...*AuditLog) error {
	var want string
	for i, l := range logs {
		if len(l.Entries) == 0 {
			return errors.New("empty audit log")
		}

		h := l.Entries[0].Hash()
		if i == 0 {
			want = h
		} else if h != want {
			return fmt.Errorf("init entry differs between logs (%s != %s); not the same repository", h, want)
		}

		l.InitHash = h
	}

	return nil
}

// AuditMerge rebases 'theirs' entries onto 'ours', using 'origin' as the merge
// base. `signer` is the merging admin. Every rebased entry is re-attributed to
// and re-signed by them (their original author is preserved in
// ChangedByBeforeMerge).
func AuditMerge(ours, theirs, origin *AuditLog, signer Signer, pluginUI *PluginUI) (*AuditLog, *ConflictResolution, error) {
	if err := requireSameInit(ours, theirs, origin); err != nil {
		return nil, nil, err
	}

	baseState, err := VerifyChain(origin, EmptyKeyring(), pluginUI)
	if err != nil {
		return nil, nil, fmt.Errorf("verify origin: %w", err)
	}

	// Loading only decrypts. Without this, re-signing would launder hand-crafted
	// entries into authority nobody granted - a refusal, not a conflict.
	theirsState, err := VerifyChain(theirs, EmptyKeyring(), pluginUI)
	if err != nil {
		return nil, nil, fmt.Errorf("verify theirs: %w", err)
	}

	originCounts := make(map[string]int, len(origin.Entries))
	for i := range origin.Entries {
		originCounts[entryContentKey(&origin.Entries[i].AuditEntry)]++
	}

	absorbed := make([]bool, len(theirs.Entries))
	for i := range theirs.Entries {
		key := entryContentKey(&theirs.Entries[i].AuditEntry)
		if originCounts[key] > 0 {
			originCounts[key]-- // absorbed by the base
			absorbed[i] = true
		}
	}

	merged := &AuditLog{
		Entries:  append([]AuditEntrySigned(nil), ours.Entries...),
		SesamDir: ours.SesamDir,
		InitHash: ours.InitHash,
		// Rotate for the same reason UserKill does; WriteEncrypted re-encrypts
		// everything anyway, so it is free here.
		key: newAuditKey(),
	}

	mergedState, err := VerifyChain(merged, EmptyKeyring(), pluginUI)
	if err != nil {
		return nil, nil, fmt.Errorf("verify ours: %w", err)
	}

	// Only an admin can merge (decrypt + re-sign). A non-admin must abort.
	merger := signer.UserName()
	if u, ok := mergedState.UserExists(merger); !ok || !u.IsAdmin() {
		// NOTE: Later we could allow a lesser priviledged user here, if there were no user actions.
		return nil, nil, fmt.Errorf("merging user %q is not an admin; abort and ask an admin to merge", merger)
	}

	// theirPrev walks theirs' own log, stopping one entry short of the entry
	// being resolved, so a resolver sees the delta that entry actually made. The
	// base state cannot serve here: it never advances, so anything theirs changed
	// in an earlier entry would read as a change of ours and get union-protected
	// - their own later revert would then be undone.
	theirPrev, err := VerifyChainUntil(theirs, EmptyKeyring(), pluginUI, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("init theirs replay: %w", err)
	}

	// mergedState is mutated as theirs' entries land, so freeze a copy of our
	// side now: it is the only witness left of what WE decided since the base.
	states := &mergeStates{
		merged:    mergedState,
		theirPrev: theirPrev,
		ours:      mergedState.Clone(merged, EmptyKeyring()),
		base:      baseState,
	}

	cr := &ConflictResolution{}
	var resolutions []ConflictResolutionEntry // conflict decisions, persisted in the merge entry
	var applied, dropped int

	orphanedUsers := map[string]bool{}
	orphanedSecrets := map[string]bool{}

	for i := range theirs.Entries {
		their := &theirs.Entries[i]
		if absorbed[i] {
			continue // already in the base, nothing to resolve
		}

		// theirs verified as a whole above, so a failure here is a bug in the
		// merge rather than a conflict.
		if err := theirPrev.AdvanceTo(their.SeqID - 1); err != nil {
			return nil, nil, fmt.Errorf("replay theirs up to seq_id %d: %w", their.SeqID-1, err)
		}

		orphanName := isOrphaned(their, orphanedUsers, orphanedSecrets)

		var r resolution
		switch revoked := authorRevoked(their, mergedState, theirsState); {
		case isMergeAdminKill(their, merger) != "":
			// The merging admin must survive - see isMergeAdminKill.
			r = dropWith(isMergeAdminKill(their, merger), true)
			r.Target = merger
		case orphanName != "":
			r = dropWith("references "+orphanName+", whose rename/move was dropped on merge; skipped", true)
			r.Target = orphanName
		case revoked != "":
			// Verified on their branch, but we revoked the author since the base.
			r = dropWith(revoked, true)
			r.Target = their.ChangedBy
		default:
			r = resolveTheirs(their, states)
		}

		if r.entry != nil {
			// Re-attribute to the merging admin, then feed onto the running state
			// via the normal path. A rejection is a conflict the rules missed.
			r.entry.ChangedBy = merger
			r.entry.ChangedByBeforeMerge = their.ChangedBy

			if err := mergedState.FeedEntry(signer, r.entry); err != nil {
				r.Action = MergeDropped
				r.Reason = fmt.Sprintf("dropped: %v", err)
				r.conflict = true
			}
		}

		if r.Action == MergeDropped {
			dropped++
			recordOrphanedRename(their, mergedState, orphanedUsers, orphanedSecrets)
		} else {
			applied++
		}

		// Only the decisions that needed a judgement call are surfaced/persisted;
		// routine applies and dedupes are covered by the counts. Target is filled
		// by the resolver itself.
		if r.conflict {
			r.Operation = their.Operation
			r.ChangedByBeforeMerge = their.ChangedBy
			resolutions = append(resolutions, r.ConflictResolutionEntry)
			cr.Resolutions = append(cr.Resolutions, r.ConflictResolutionEntry)
		}
	}

	// Checks needing the merged end state. Rename/move collisions and the
	// zero-admins case are already enforced per entry by the reused verify guards
	// (the offending op is declined above); only dangling group references need a
	// full-picture scan. It is advisory and derivable, so it is surfaced to the
	// caller but not persisted in the log.
	cr.Resolutions = append(cr.Resolutions, checkDanglingGroups(mergedState)...)

	// Defensive: the per-entry last-admin guards make an adminless result
	// unreachable. Refuse rather than emit a repo nobody can administer.
	if n, _ := mergedState.AdminUserCount(); n == 0 {
		return nil, nil, fmt.Errorf("merge would leave zero admins (per-entry guards should prevent this)")
	}

	cr.Conflicts = len(cr.Resolutions)

	mergeDetail := &DetailMerge{
		BaseSeqID:     origin.Entries[len(origin.Entries)-1].SeqID,
		OurTipSeqID:   ours.Entries[len(ours.Entries)-1].SeqID,
		TheirTipSeqID: theirs.Entries[len(theirs.Entries)-1].SeqID,
		Applied:       applied,
		Dropped:       dropped,
		Resolutions:   resolutions,
	}

	if err := mergedState.FeedEntry(signer, newAuditEntry(merger, mergeDetail)); err != nil {
		return nil, nil, fmt.Errorf("append merge entry: %w", err)
	}

	return merged, cr, nil
}

// checkDanglingGroups reports access groups that, after the merge, have no
// members left (e.g. their last member was killed). The reference is kept - an
// empty group means admin-only - but flagged, since it usually signals a secret
// that silently narrowed to admins. "admin" is implicit and never dangling.
func checkDanglingGroups(state *VerifiedState) []ConflictResolutionEntry {
	populated := make(map[string]bool)
	for _, u := range state.Users {
		for _, g := range u.Groups {
			populated[g] = true
		}
	}

	seen := make(map[string]bool)
	var out []ConflictResolutionEntry
	for _, s := range state.Secrets {
		for _, g := range s.AccessGroups {
			if g == "admin" || populated[g] || seen[g] {
				continue
			}

			seen[g] = true
			out = append(out, ConflictResolutionEntry{
				Target: g,
				Action: MergeFlagged,
				Reason: fmt.Sprintf("access group %q has no members after merge; secrets granting it are now admin-only", g),
			})
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// isMergeAdminKill checks if `merger` (i.e. us) gets demoted or killed by the change described in `their`.
func isMergeAdminKill(their *AuditEntrySigned, merger string) string {
	if entryUserTarget(their) != merger {
		return ""
	}

	switch their.Operation {
	case OpUserKill:
		return "would remove the merging admin " + merger + "; kept (cannot merge yourself away)"
	case OpUserRegenerateSignKey:
		return "would re-key the merging admin " + merger + " mid-merge; kept ours"
	case OpUserRename:
		return "would rename the merging admin " + merger + " mid-merge; kept ours"
	case OpUserChangeGroups:
		// Only a problem when it takes admin away; other group edits are fine.
		if d, err := parseDetail[DetailUserChangeGroups](their); err == nil &&
			!slices.Contains(d.NewGroups, "admin") {
			return "would strip admin from the merging user " + merger + "; kept ours"
		}
	}

	return ""
}

// authorRevoked reports why theirs' author may no longer perform the entry's
// operation, or "" if they still may. Verifying theirs only proves what they
// could do on their own branch, not what we left them since the base.
func authorRevoked(their *AuditEntrySigned, merged, theirs *VerifiedState) string {
	op, ok := mergeOpTable[their.Operation]
	if !ok || !op.replayed {
		// Unknown or never rebased; resolveTheirs has a better reason to drop it.
		return ""
	}

	author, found := authorInMerged(their, merged, theirs)
	if !found {
		return "author " + their.ChangedBy + " was removed on our side; dropped"
	}

	if op.adminOnly {
		if !author.IsAdmin() {
			return "author " + their.ChangedBy + " is no longer an admin on our side; dropped"
		}

		return ""
	}

	// The rest are gated on access to the path they touch. secret.add names its
	// groups directly; the others act on a secret that has to exist first.
	if their.Operation == OpSecretAdd {
		d, err := parseDetail[DetailSecretAdd](their)
		if err != nil {
			return "" // resolveTheirs reports the parse error
		}

		if !merged.UserHasAccess(author.Name, d.AccessGroups) {
			return "author " + their.ChangedBy + " has no access to " + d.RevealedPath + " on our side; dropped"
		}

		return ""
	}

	path := entrySecretTarget(their)
	if _, exists := merged.SecretExists(path); !exists {
		// Gone on our side - let the resolvers dedupe it.
		return ""
	}

	if !merged.SealerAuthorized(author.Name, path) {
		return "author " + their.ChangedBy + " has no access to " + path + " on our side; dropped"
	}

	return ""
}

// authorInMerged resolves theirs' author in the merged state. A rename on our
// side changes the name but not the sign key, hence the key fallback.
func authorInMerged(their *AuditEntrySigned, merged, theirs *VerifiedState) (*VerifiedUser, bool) {
	if u, ok := merged.UserExists(their.ChangedBy); ok {
		return u, true
	}

	tu, ok := theirs.UserExists(their.ChangedBy)
	if !ok || tu.SignPubKey == "" {
		return nil, false
	}

	var match *VerifiedUser
	for i := range merged.Users {
		if merged.Users[i].SignPubKey != tu.SignPubKey {
			continue
		}
		if match != nil {
			return nil, false // ambiguous, fail closed
		}
		match = &merged.Users[i]
	}

	return match, match != nil
}

// isOrphaned returns the name a modifying op acts on if that name is an
// orphaned rename/move target (its rename was dropped on merge), else "".
func isOrphaned(their *AuditEntrySigned, orphanedUsers, orphanedSecrets map[string]bool) string {
	if n := entryUserTarget(their); n != "" && orphanedUsers[n] {
		return n
	}
	if p := entrySecretTarget(their); p != "" && orphanedSecrets[p] {
		return p
	}
	return ""
}

// recordOrphanedRename remembers that we've dropped a user/secret so that we can later
// decide to do in case of renames.
func recordOrphanedRename(their *AuditEntrySigned, merged *VerifiedState, orphanedUsers, orphanedSecrets map[string]bool) {
	switch their.Operation {
	case OpUserRename:
		d, err := parseDetail[DetailUserRename](their)
		if err != nil {
			return
		}
		_, src := merged.UserExists(d.OldName)
		_, dst := merged.UserExists(d.NewName)
		if orphanedUsers[d.OldName] || (src && dst) {
			orphanedUsers[d.NewName] = true
		}
	case OpSecretMove:
		d, err := parseDetail[DetailSecretMove](their)
		if err != nil {
			return
		}
		_, src := merged.SecretExists(d.OldRevealedPath)
		_, dst := merged.SecretExists(d.NewRevealedPath)
		if orphanedSecrets[d.OldRevealedPath] || (src && dst) {
			orphanedSecrets[d.NewRevealedPath] = true
		}
	}
}

// opInfo is what a merge needs to know about an operation. Keeping it in one
// table means adding an operation is one entry, not an edit in five switches
// that nothing forces you to keep in step.
type opInfo struct {
	// replayed is false for entries a merge never rebases onto ours.
	replayed bool

	// adminOnly mirrors what verify enforces: only an admin may do this.
	adminOnly bool

	// userTarget and secretTarget name what the operation acts on, "" if it acts
	// on neither (or the detail does not parse).
	userTarget   func(*AuditEntrySigned) string
	secretTarget func(*AuditEntrySigned) string

	// resolve decides how the entry integrates on top of the merged state.
	resolve func(their *AuditEntrySigned, s *mergeStates) resolution
}

func detailField[T AuditDetail](pick func(*T) string) func(*AuditEntrySigned) string {
	return func(their *AuditEntrySigned) string {
		d, err := parseDetail[T](their)
		if err != nil {
			return ""
		}

		return pick(d)
	}
}

// This table defines what happens on incoming audit log entries:
var mergeOpTable = map[Operation]opInfo{
	OpSeal: {
		resolve: alwaysDrop("seal superseded by post-merge reseal", false),
	},
	OpInit: {
		resolve: alwaysDrop("unexpected init among new entries", true),
	},
	OpMerge: {
		adminOnly: true,
		resolve:   alwaysDrop("theirs' merge entry is not replayed", false),
	},
	OpUserTell: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserTell) string { return d.User }),
		resolve:    resolveUserTell,
	},
	OpUserKill: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserKill) string { return d.User }),
		resolve:    resolveUserKill,
	},
	OpUserRename: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserRename) string { return d.OldName }),
		resolve:    resolveUserRename,
	},
	OpUserRegenerateSignKey: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserRegenerateSignKey) string { return d.User }),
		resolve:    resolveUserRegenKey,
	},
	OpUserChangeGroups: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserChangeGroups) string { return d.User }),
		resolve:    resolveUserChangeGroups,
	},
	OpUserAddRecipients: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserAddRecipients) string { return d.User }),
		resolve:    resolveUserAddRecipients,
	},
	OpUserRmRecipients: {
		replayed:   true,
		adminOnly:  true,
		userTarget: detailField(func(d *DetailUserRmRecipients) string { return d.User }),
		resolve:    resolveUserRmRecipients,
	},
	// The secret operations are gated on access to the path, not on admin.
	OpSecretAdd: {
		replayed: true,
		resolve:  resolveSecretAdd,
	},
	OpSecretRemove: {
		replayed:     true,
		secretTarget: detailField(func(d *DetailSecretRemove) string { return d.RevealedPath }),
		resolve:      resolveSecretRemove,
	},
	OpSecretChangeAccess: {
		replayed:     true,
		secretTarget: detailField(func(d *DetailSecretChangeAccess) string { return d.RevealedPath }),
		resolve:      resolveSecretChangeAccess,
	},
	OpSecretMove: {
		replayed:     true,
		secretTarget: detailField(func(d *DetailSecretMove) string { return d.OldRevealedPath }),
		resolve:      resolveSecretMove,
	},
}

func alwaysDrop(reason string, conflict bool) func(*AuditEntrySigned, *mergeStates) resolution {
	return func(*AuditEntrySigned, *mergeStates) resolution {
		return dropWith(reason, conflict)
	}
}

// resolveTheirs decides how one of theirs' new entries integrates on top of the
// merged state built so far. See [mergeStates] for what each view is good for.
// It only reads state; applying is the caller's job.
func resolveTheirs(their *AuditEntrySigned, s *mergeStates) resolution {
	op, ok := mergeOpTable[their.Operation]
	if !ok {
		return dropWith(fmt.Sprintf("unknown operation %q", their.Operation), true)
	}

	return op.resolve(their, s)
}

// entryUserTarget returns the existing user a modifying op acts on ("" otherwise).
func entryUserTarget(their *AuditEntrySigned) string {
	if op, ok := mergeOpTable[their.Operation]; ok && op.userTarget != nil {
		return op.userTarget(their)
	}

	return ""
}

// entrySecretTarget returns the existing secret path a modifying op acts on.
func entrySecretTarget(their *AuditEntrySigned) string {
	if op, ok := mergeOpTable[their.Operation]; ok && op.secretTarget != nil {
		return op.secretTarget(their)
	}

	return ""
}

// resolveUserTell dedupes an identical re-tell of the same name; a same-name tell
// with a different identity keeps ours and warns (two identities cannot be fused).
func resolveUserTell(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserTell](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	existing, ok := s.merged.UserExists(d.User)
	if !ok {
		// added and we don't have it.
		return applyAs(their)
	}

	if sameUserIdentity(existing, d, s.merged.pluginUI) {
		return dropWith("duplicate tell for "+d.User, false)
	}

	return dropWith("user "+d.User+" added on both sides with different identity; kept ours", true)
}

// resolveUserKill: a kill wins over a concurrent modify. Killing an already-absent
// user is a no-op dedupe; if our side modified the victim since the base, the
// kill still wins but is flagged (the modification is discarded).
func resolveUserKill(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserKill](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	if _, ok := s.merged.UserExists(d.User); !ok {
		return dropWith("user "+d.User+" already removed", false)
	}

	b, inBase := s.base.UserExists(d.User)
	o, inOurs := s.ours.UserExists(d.User)
	if inBase && inOurs && userModified(b, o) {
		r = applyAs(their)
		r.Reason = "user " + d.User + " was modified on our side but killed on theirs; kill wins"
		r.conflict = true
		return r
	}

	return applyAs(their)
}

// resolveUserRename prefers ours: drop on a vanished source or an occupied target
// (a single-valued field has no union).
func resolveUserRename(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserRename](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.OldName + " -> " + d.NewName }()

	if _, ok := s.merged.UserExists(d.OldName); !ok {
		return dropWith("rename source "+d.OldName+" gone on our side; dropped", true)
	}

	if _, ok := s.merged.UserExists(d.NewName); ok {
		return dropWith("rename target "+d.NewName+" already exists; kept ours", true)
	}

	return applyAs(their)
}

// resolveUserRegenKey prefers ours if our side rotated the user's sign key since
// the base (their private-key holder would be stranded until re-rotated). Theirs
// rotating twice on its own branch is not a clash - only ours diverging is.
func resolveUserRegenKey(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserRegenerateSignKey](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	if _, ok := s.merged.UserExists(d.User); !ok {
		return dropWith("user "+d.User+" gone; dropped sign-key rotation", true)
	}

	b, inBase := s.base.UserExists(d.User)
	o, inOurs := s.ours.UserExists(d.User)
	if inBase && inOurs && o.SignPubKey != b.SignPubKey {
		return dropWith("sign key of "+d.User+" rotated on both sides; kept ours (their key holder is stranded)", true)
	}

	return applyAs(their)
}

// resolveUserChangeGroups three-way delta-merges the group set; remove wins on a
// clash.
func resolveUserChangeGroups(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserChangeGroups](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := s.merged.UserExists(d.User)
	if !ok {
		return dropWith("user "+d.User+" gone (killed); dropped group change", true)
	}

	// theirPrev makes the delta theirs' own; oursRemovedGroups then re-applies our
	// revocations, which the delta cannot see (theirs may never have seen them).
	mergedGroups := threeWaySet(userGroups(s.theirPrev, d.User), cur.Groups, d.NewGroups)
	mergedGroups = stringSetMinus(mergedGroups, s.oursRemovedGroups(d.User))
	if len(mergedGroups) == 0 {
		return dropWith("group merge for "+d.User+" would empty the set; kept ours", true)
	}

	if stringSetEqual(mergedGroups, d.NewGroups) {
		return applyAs(their)
	}

	// Anything theirs asked to keep that did not survive lost to a removal of
	// ours - that is a decision, unlike unioning in groups theirs never saw.
	if lost := stringSetMinus(d.NewGroups, mergedGroups); len(lost) > 0 {
		return rewriteAs(
			newAuditEntry(their.ChangedBy, &DetailUserChangeGroups{User: d.User, NewGroups: mergedGroups}),
			"kept our removal of "+strings.Join(lost, ", ")+" from "+d.User,
			true,
		)
	}

	return rewriteAs(
		newAuditEntry(their.ChangedBy, &DetailUserChangeGroups{User: d.User, NewGroups: mergedGroups}),
		"groups of "+d.User+" delta-merged",
		false,
	)
}

// resolveUserAddRecipients applies onto a live user; verify dedupes keys already
// present.
func resolveUserAddRecipients(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserAddRecipients](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	if _, ok := s.merged.UserExists(d.User); !ok {
		return dropWith("user "+d.User+" gone; dropped recipient add", true)
	}

	// Remove wins: drop any key our side revoked since the base, even if theirs
	// re-added it deliberately. Measured on `ours`, not on the running state -
	// that one already carries theirs' own removals. Keys ours never had apply.
	revoked := stringSet(recipientKeys(s.base, d.User))
	for _, k := range recipientKeys(s.ours, d.User) {
		delete(revoked, k)
	}

	kept := make([]UserPubKey, 0, len(d.PubKeys))
	for _, pk := range d.PubKeys {
		if revoked[pk.Key] {
			continue // ours revoked it
		}
		kept = append(kept, pk)
	}

	switch {
	case len(kept) == len(d.PubKeys):
		return applyAs(their)
	case len(kept) == 0:
		return dropWith("recipients added for "+d.User+" were revoked on our side; kept ours", true)
	default:
		return rewriteAs(
			newAuditEntry(their.ChangedBy, &DetailUserAddRecipients{User: d.User, PubKeys: kept}),
			"kept our revocation of some recipients for "+d.User,
			true,
		)
	}
}

// resolveUserRmRecipients: a removal wins; a no-longer-present user makes it a
// satisfied no-op.
func resolveUserRmRecipients(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailUserRmRecipients](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := s.merged.UserExists(d.User)
	if !ok {
		return dropWith("user "+d.User+" gone; removal already satisfied", false)
	}

	// If none of the keys are still present (e.g. our side already removed the same
	// ones), the removal is a satisfied no-op - a dedupe, not a conflict.
	present := stringSet(cur.Recps.Strings())
	for _, pk := range d.PubKeys {
		if present[pk.Key] {
			return applyAs(their)
		}
	}

	return dropWith("recipients of "+d.User+" already removed", false)
}

// resolveSecretAdd: an add of the same path dedupes; differing access is a
// conflict (content itself is merged by the secret driver).
func resolveSecretAdd(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailSecretAdd](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.RevealedPath }()

	existing, ok := s.merged.SecretExists(d.RevealedPath)
	if !ok {
		return applyAs(their)
	}

	if stringSetEqual(existing.AccessGroups, normalizeAccessGroups(d.AccessGroups)) {
		return dropWith("duplicate add of "+d.RevealedPath, false)
	}

	return dropWith("secret "+d.RevealedPath+" added on both sides with different access; kept ours", true)
}

// resolveSecretRemove: a removal wins; if our side changed the secret's access
// since the base, the removal still wins but is flagged (the change is discarded).
func resolveSecretRemove(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailSecretRemove](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.RevealedPath }()

	if _, ok := s.merged.SecretExists(d.RevealedPath); !ok {
		return dropWith("secret "+d.RevealedPath+" already removed", false)
	}

	if b, ok := s.base.SecretExists(d.RevealedPath); ok &&
		!stringSetEqual(b.AccessGroups, secretAccess(s.ours, d.RevealedPath)) {
		r = applyAs(their)
		r.Reason = "secret " + d.RevealedPath + " had its access changed on our side but was removed on theirs; remove wins"
		r.conflict = true
		return r
	}

	return applyAs(their)
}

// resolveSecretChangeAccess three-way delta-merges the access set; remove wins on
// a clash.
func resolveSecretChangeAccess(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailSecretChangeAccess](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.RevealedPath }()

	cur, ok := s.merged.SecretExists(d.RevealedPath)
	if !ok {
		return dropWith("secret "+d.RevealedPath+" removed; dropped access change", true)
	}

	theirGroups := normalizeAccessGroups(d.AccessGroups)
	mergedGroups := threeWaySet(secretAccess(s.theirPrev, d.RevealedPath), cur.AccessGroups, theirGroups)
	mergedGroups = normalizeAccessGroups(stringSetMinus(mergedGroups, s.oursRemovedAccess(d.RevealedPath)))

	if stringSetEqual(mergedGroups, cur.AccessGroups) {
		return dropWith("access of "+d.RevealedPath+" already covers theirs", false)
	}

	if stringSetEqual(mergedGroups, theirGroups) {
		return applyAs(their)
	}

	// Access theirs asked to keep but that lost to a removal of ours: a narrowing
	// of what theirs intended, so surface it.
	if lost := stringSetMinus(theirGroups, mergedGroups); len(lost) > 0 {
		return rewriteAs(
			newAuditEntry(their.ChangedBy, &DetailSecretChangeAccess{RevealedPath: d.RevealedPath, AccessGroups: mergedGroups}),
			"kept our removal of "+strings.Join(lost, ", ")+" from "+d.RevealedPath,
			true,
		)
	}

	return rewriteAs(
		newAuditEntry(their.ChangedBy, &DetailSecretChangeAccess{RevealedPath: d.RevealedPath, AccessGroups: mergedGroups}),
		"access of "+d.RevealedPath+" delta-merged",
		false,
	)
}

// resolveSecretMove prefers ours: drop on a vanished source or an occupied target.
func resolveSecretMove(their *AuditEntrySigned, s *mergeStates) (r resolution) {
	d, err := parseDetail[DetailSecretMove](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.OldRevealedPath + " -> " + d.NewRevealedPath }()

	if _, ok := s.merged.SecretExists(d.OldRevealedPath); !ok {
		return dropWith("move source "+d.OldRevealedPath+" gone; dropped", true)
	}

	if _, ok := s.merged.SecretExists(d.NewRevealedPath); ok {
		return dropWith("move target "+d.NewRevealedPath+" occupied; kept ours", true)
	}

	return applyAs(their)
}

// sameUserIdentity reports whether an existing user and an incoming tell describe
// the same identity (same signing key and recipient set). A parse failure or any
// difference reads as "not the same", the safe direction (keep ours + warn).
func sameUserIdentity(existing *VerifiedUser, d *DetailUserTell, ui *PluginUI) bool {
	if existing.SignPubKey != d.SignPubKey {
		return false
	}

	theirRecps, err := resolveRecipients(d.PubKeys, ui)
	if err != nil {
		return false
	}

	return existing.Recps.Equal(theirRecps)
}

// userModified reports whether `cur` differs from `b` in any security-relevant
// way (groups, signing key or recipient set) - i.e. whether our side changed the
// user away from the version theirs acted on.
func userModified(b, cur *VerifiedUser) bool {
	return b.SignPubKey != cur.SignPubKey ||
		!stringSetEqual(b.Groups, cur.Groups) ||
		!b.Recps.Equal(cur.Recps)
}

func stringSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// threeWaySet merges a set field: start from `current` (ours, already applied),
// then apply theirs' delta relative to `base` - theirs' additions are unioned
// in, theirs' removals are deleted. Because a removal always wins over the other
// side keeping an element, the genuine add-vs-remove clash resolves to removed.
//
// `base` must be theirs' state just before the entry, not the merge base: only
// then does the delta describe what this entry did. Elements outside theirs'
// view are left to `current` - theirs said nothing about them.
func threeWaySet(base, current, theirs []string) []string {
	baseSet := stringSet(base)
	theirsSet := stringSet(theirs)
	out := stringSet(current)

	for g := range theirsSet {
		if !baseSet[g] {
			out[g] = true // theirs added it
		}
	}

	for g := range baseSet {
		if !theirsSet[g] {
			delete(out, g) // theirs removed it (remove wins)
		}
	}

	return sortedKeys(out)
}

// stringSetMinus returns the sorted elements of `a` that are missing from `b`.
// userGroups / secretAccess / recipientKeys read one field out of a state, empty
// if the user or secret is absent there.
func userGroups(s *VerifiedState, user string) []string {
	if u, ok := s.UserExists(user); ok {
		return u.Groups
	}

	return nil
}

func secretAccess(s *VerifiedState, path string) []string {
	if sec, ok := s.SecretExists(path); ok {
		return sec.AccessGroups
	}

	return nil
}

func recipientKeys(s *VerifiedState, user string) []string {
	if u, ok := s.UserExists(user); ok {
		return u.Recps.Strings()
	}

	return nil
}

func stringSetMinus(a, b []string) []string {
	bm := stringSet(b)
	out := make([]string, 0, len(a))
	for _, v := range a {
		if !bm[v] {
			out = append(out, v)
		}
	}

	sort.Strings(out)
	return out
}

func stringSetEqual(a, b []string) bool {
	am, bm := stringSet(a), stringSet(b)
	if len(am) != len(bm) {
		return false
	}

	return maps.Equal(am, bm)
}

// conflictMarkerMin is the minimum run length of a git conflict marker. git's
// default marker size is 7; a custom size (git's %L) is always >= 7, so requiring
// at least 7 never misses a real marker.
const conflictMarkerMin = 7

// hasConflictMarkers reports whether r contains an unresolved git conflict: both
// a start line ("<<<<<<< …") and an end line (">>>>>>> …"). Requiring the pair
// (rather than a lone "=======") keeps false positives off files that
// legitimately contain separator lines.
func hasConflictMarkers(r io.Reader) (bool, error) {
	var sawStart, sawEnd bool

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		switch {
		case isMarkerLine(line, '<'):
			sawStart = true
		case isMarkerLine(line, '>'):
			sawEnd = true
		}

		if sawStart && sawEnd {
			return true, nil
		}
	}

	return false, sc.Err()
}

// isMarkerLine reports whether line begins with >= conflictMarkerMin copies of c
// followed by a space or end of line - i.e. "<<<<<<< label" or ">>>>>>>".
func isMarkerLine(line []byte, c byte) bool {
	n := 0
	for n < len(line) && line[n] == c {
		n++
	}

	if n < conflictMarkerMin {
		return false
	}

	return n == len(line) || line[n] == ' '
}

// ConflictedSecret is a revealed secret a merge left unresolved: Binary means the
// two sides were written out as .ours/.theirs side files (no in-file markers to
// scan); otherwise the revealed plaintext still carries git conflict markers.
type ConflictedSecret struct {
	Path   string
	Binary bool
}

// ConflictedSecrets returns the secrets a merge left unresolved. git can't flag
// either kind (revealed files are gitignored, the object is ciphertext), so the
// finalize must refuse until they are resolved - sealing a marker'd file, or one
// with side files still present, would bake the conflict into the object.
func ConflictedSecrets(root *os.Root, secrets []VerifiedSecret) ([]ConflictedSecret, error) {
	var conflicted []ConflictedSecret
	for _, s := range secrets {
		// A binary conflict has no markers; the driver leaves .ours/.theirs beside
		// the revealed file for manual resolution.
		if hasSideFile(root, s.RevealedPath+".ours") && hasSideFile(root, s.RevealedPath+".theirs") {
			conflicted = append(conflicted, ConflictedSecret{Path: s.RevealedPath, Binary: true})
			continue
		}

		fd, err := root.Open(s.RevealedPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // not revealed on disk - nothing to seal, nothing to check
			}
			return nil, fmt.Errorf("open revealed %s: %w", s.RevealedPath, err)
		}

		has, err := hasConflictMarkers(fd)
		_ = fd.Close()
		if err != nil {
			return nil, fmt.Errorf("scan revealed %s: %w", s.RevealedPath, err)
		}

		if has {
			conflicted = append(conflicted, ConflictedSecret{Path: s.RevealedPath})
		}
	}

	return conflicted, nil
}

func hasSideFile(root *os.Root, path string) bool {
	_, err := root.Stat(path)
	return err == nil
}
