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
//     against the base; on an add-vs-remove clash of the same element, remove wins.
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
//   - The merged log gets a fresh symmetric key. A merge can carry a kill or an
//     rm-recipients from theirs, and reusing ours' key would let the removed user
//     keep reading everything written after the merge.
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

func rewriteAs(e *AuditEntry, reason string) resolution {
	return resolution{ConflictResolutionEntry: ConflictResolutionEntry{Action: MergeRewritten, Reason: reason}, entry: e}
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

	originState, err := VerifyChain(origin, EmptyKeyring(), pluginUI)
	if err != nil {
		return nil, nil, fmt.Errorf("verify origin: %w", err)
	}

	// Theirs is untrusted input - the driver gets the blob straight from git and
	// loading it only decrypts. Chain-verify it before rebasing anything, else
	// re-signing would launder hand-crafted entries into authority nobody granted.
	// A log that does not verify is tampered or corrupt, not a conflict: refuse.
	theirsState, err := VerifyChain(theirs, EmptyKeyring(), pluginUI)
	if err != nil {
		return nil, nil, fmt.Errorf("verify theirs: %w", err)
	}

	originCounts := make(map[string]int, len(origin.Entries))
	for i := range origin.Entries {
		originCounts[entryContentKey(&origin.Entries[i].AuditEntry)]++
	}

	var theirsNew []AuditEntrySigned
	for i := range theirs.Entries {
		key := entryContentKey(&theirs.Entries[i].AuditEntry)
		if originCounts[key] > 0 {
			originCounts[key]-- // absorbed by the base
			continue
		}
		theirsNew = append(theirsNew, theirs.Entries[i])
	}

	merged := &AuditLog{
		Entries:  append([]AuditEntrySigned(nil), ours.Entries...),
		SesamDir: ours.SesamDir,
		InitHash: ours.InitHash,
		// Rotate: the merge may apply a kill or an rm-recipients from theirs, and
		// those paths rotate for a reason (see AuditLog.RotateKey). WriteEncrypted
		// re-encrypts every entry anyway, so this costs nothing here.
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

	cr := &ConflictResolution{}
	var resolutions []ConflictResolutionEntry // conflict decisions, persisted in the merge entry
	var applied, dropped int

	orphanedUsers := map[string]bool{}
	orphanedSecrets := map[string]bool{}

	for i := range theirsNew {
		their := &theirsNew[i]
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
			// Verified on their branch, but our side revoked the author since the
			// base. Revocation wins here as everywhere else.
			r = dropWith(revoked, true)
			r.Target = their.ChangedBy
		default:
			r = resolveTheirs(their, mergedState, originState)
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
	switch their.Operation {
	case OpUserKill:
		if d, err := parseDetail[DetailUserKill](their); err == nil && d.User == merger {
			return "would remove the merging admin " + merger + "; kept (cannot merge yourself away)"
		}
	case OpUserChangeGroups:
		if d, err := parseDetail[DetailUserChangeGroups](their); err == nil &&
			d.User == merger && !slices.Contains(d.NewGroups, "admin") {
			return "would strip admin from the merging user " + merger + "; kept ours"
		}
	case OpUserRegenerateSignKey:
		if d, err := parseDetail[DetailUserRegenerateSignKey](their); err == nil && d.User == merger {
			return "would re-key the merging admin " + merger + " mid-merge; kept ours"
		}
	case OpUserRename:
		if d, err := parseDetail[DetailUserRename](their); err == nil && d.OldName == merger {
			return "would rename the merging admin " + merger + " mid-merge; kept ours"
		}
	}

	return ""
}

// authorRevoked reports why theirs' author may no longer perform the entry's
// operation, or "" if they still may. Chain-verifying theirs establishes that
// the author had authority on their branch; this catches the cross-branch case
// where our side killed or demoted them since the base. Without it the merger's
// re-signature would silently reinstate the authority we just revoked.
func authorRevoked(their *AuditEntrySigned, merged, theirs *VerifiedState) string {
	switch their.Operation {
	case OpSeal, OpInit, OpMerge:
		// Never replayed; resolveTheirs drops them with a more precise reason.
		return ""
	}

	author, ok := authorInMerged(their, merged, theirs)
	if !ok {
		return "author " + their.ChangedBy + " was removed on our side; dropped"
	}

	switch their.Operation {
	case OpUserTell, OpUserKill, OpUserRename, OpUserRegenerateSignKey,
		OpUserChangeGroups, OpUserAddRecipients, OpUserRmRecipients:
		if !author.IsAdmin() {
			return "author " + their.ChangedBy + " is no longer an admin on our side; dropped"
		}
	case OpSecretAdd:
		d, err := parseDetail[DetailSecretAdd](their)
		if err != nil {
			return "" // resolveTheirs reports the parse error
		}
		if !merged.UserHasAccess(author.Name, d.AccessGroups) {
			return "author " + their.ChangedBy + " has no access to " + d.RevealedPath + " on our side; dropped"
		}
	case OpSecretChangeAccess, OpSecretMove, OpSecretRemove:
		path := entrySecretTarget(their)
		if _, ok := merged.SecretExists(path); !ok {
			// Gone on our side: the resolvers decide (a double remove dedupes).
			return ""
		}
		if !merged.SealerAuthorized(author.Name, path) {
			return "author " + their.ChangedBy + " has no access to " + path + " on our side; dropped"
		}
	}

	return ""
}

// authorInMerged resolves theirs' author in the merged state. A rename on our
// side changes the name but not the signing key, so fall back to an unambiguous
// key match before concluding the author is gone.
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

// entryUserTarget returns the existing user a modifying op acts on ("" otherwise).
func entryUserTarget(their *AuditEntrySigned) string {
	switch their.Operation {
	case OpUserKill:
		if d, err := parseDetail[DetailUserKill](their); err == nil {
			return d.User
		}
	case OpUserChangeGroups:
		if d, err := parseDetail[DetailUserChangeGroups](their); err == nil {
			return d.User
		}
	case OpUserAddRecipients:
		if d, err := parseDetail[DetailUserAddRecipients](their); err == nil {
			return d.User
		}
	case OpUserRmRecipients:
		if d, err := parseDetail[DetailUserRmRecipients](their); err == nil {
			return d.User
		}
	case OpUserRegenerateSignKey:
		if d, err := parseDetail[DetailUserRegenerateSignKey](their); err == nil {
			return d.User
		}
	case OpUserRename:
		if d, err := parseDetail[DetailUserRename](their); err == nil {
			return d.OldName
		}
	}
	return ""
}

// entrySecretTarget returns the existing secret path a modifying op acts on.
func entrySecretTarget(their *AuditEntrySigned) string {
	switch their.Operation {
	case OpSecretChangeAccess:
		if d, err := parseDetail[DetailSecretChangeAccess](their); err == nil {
			return d.RevealedPath
		}
	case OpSecretRemove:
		if d, err := parseDetail[DetailSecretRemove](their); err == nil {
			return d.RevealedPath
		}
	case OpSecretMove:
		if d, err := parseDetail[DetailSecretMove](their); err == nil {
			return d.OldRevealedPath
		}
	}
	return ""
}

// resolveTheirs decides how one of theirs' new entries integrates on top of the
// merged state built so far. base is the merge-base state, needed for the
// three-way set deltas. It only reads state; applying is the caller's job.
func resolveTheirs(their *AuditEntrySigned, merged, base *VerifiedState) resolution {
	switch their.Operation {
	case OpSeal:
		// Post-base seals never survive a merge; the terminal reseal is the only
		// authority afterwards.
		return dropWith("seal superseded by post-merge reseal", false)
	case OpInit:
		// The init check guarantees this never happens; guard anyway.
		return dropWith("unexpected init among new entries", true)
	case OpMerge:
		return dropWith("theirs' merge entry is not replayed", false)
	case OpUserTell:
		return resolveUserTell(their, merged)
	case OpUserKill:
		return resolveUserKill(their, merged, base)
	case OpUserRename:
		return resolveUserRename(their, merged)
	case OpUserRegenerateSignKey:
		return resolveUserRegenKey(their, merged, base)
	case OpUserChangeGroups:
		return resolveUserChangeGroups(their, merged, base)
	case OpUserAddRecipients:
		return resolveUserAddRecipients(their, merged, base)
	case OpUserRmRecipients:
		return resolveUserRmRecipients(their, merged)
	case OpSecretAdd:
		return resolveSecretAdd(their, merged)
	case OpSecretRemove:
		return resolveSecretRemove(their, merged, base)
	case OpSecretChangeAccess:
		return resolveSecretChangeAccess(their, merged, base)
	case OpSecretMove:
		return resolveSecretMove(their, merged)
	default:
		return dropWith(fmt.Sprintf("unknown operation %q", their.Operation), true)
	}
}

// resolveUserTell dedupes an identical re-tell of the same name; a same-name tell
// with a different identity keeps ours and warns (two identities cannot be fused).
func resolveUserTell(their *AuditEntrySigned, merged *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserTell](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	existing, ok := merged.UserExists(d.User)
	if !ok {
		// added and we don't have it.
		return applyAs(their)
	}

	if sameUserIdentity(existing, d, merged.pluginUI) {
		return dropWith("duplicate tell for "+d.User, false)
	}

	return dropWith("user "+d.User+" added on both sides with different identity; kept ours", true)
}

// resolveUserKill: a kill wins over a concurrent modify. Killing an already-absent
// user is a no-op dedupe; if our side modified the victim since base, the kill
// still wins but is flagged (the modification is discarded).
func resolveUserKill(their *AuditEntrySigned, merged, base *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserKill](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := merged.UserExists(d.User)
	if !ok {
		return dropWith("user "+d.User+" already removed", false)
	}

	if b, ok := base.UserExists(d.User); ok && userModified(b, cur) {
		r = applyAs(their)
		r.Reason = "user " + d.User + " was modified on our side but killed on theirs; kill wins"
		r.conflict = true
		return r
	}

	return applyAs(their)
}

// resolveUserRename prefers ours: drop on a vanished source or an occupied target
// (a single-valued field has no union).
func resolveUserRename(their *AuditEntrySigned, merged *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserRename](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.OldName + " -> " + d.NewName }()

	if _, ok := merged.UserExists(d.OldName); !ok {
		return dropWith("rename source "+d.OldName+" gone on our side; dropped", true)
	}

	if _, ok := merged.UserExists(d.NewName); ok {
		return dropWith("rename target "+d.NewName+" already exists; kept ours", true)
	}

	return applyAs(their)
}

// resolveUserRegenKey prefers ours if we already rotated the user's sign key since
// base (their private-key holder would be stranded until re-rotated).
func resolveUserRegenKey(their *AuditEntrySigned, merged, base *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserRegenerateSignKey](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := merged.UserExists(d.User)
	if !ok {
		return dropWith("user "+d.User+" gone; dropped sign-key rotation", true)
	}

	if b, ok := base.UserExists(d.User); ok && cur.SignPubKey != b.SignPubKey {
		return dropWith("sign key of "+d.User+" rotated on both sides; kept ours (their key holder is stranded)", true)
	}

	return applyAs(their)
}

// resolveUserChangeGroups three-way delta-merges the group set; remove wins on a
// clash.
func resolveUserChangeGroups(their *AuditEntrySigned, merged, base *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserChangeGroups](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := merged.UserExists(d.User)
	if !ok {
		return dropWith("user "+d.User+" gone (killed); dropped group change", true)
	}

	var baseGroups []string
	if b, ok := base.UserExists(d.User); ok {
		baseGroups = b.Groups
	}

	mergedGroups := threeWaySet(baseGroups, cur.Groups, d.NewGroups)
	if len(mergedGroups) == 0 {
		return dropWith("group merge for "+d.User+" would empty the set; kept ours", true)
	}

	if stringSetEqual(mergedGroups, d.NewGroups) {
		return applyAs(their)
	}

	return rewriteAs(
		newAuditEntry(their.ChangedBy, &DetailUserChangeGroups{User: d.User, NewGroups: mergedGroups}),
		"groups of "+d.User+" delta-merged",
	)
}

// resolveUserAddRecipients applies onto a live user; verify dedupes keys already
// present.
func resolveUserAddRecipients(their *AuditEntrySigned, merged, base *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserAddRecipients](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := merged.UserExists(d.User)
	if !ok {
		return dropWith("user "+d.User+" gone; dropped recipient add", true)
	}

	// Remove wins: drop any key our side revoked since base (present in base, gone
	// now); theirs re-adding it must not resurrect it. Keys ours never had apply.
	ourKeys := stringSet(cur.Recps.Strings())
	var baseKeys map[string]bool
	if b, ok := base.UserExists(d.User); ok {
		baseKeys = stringSet(b.Recps.Strings())
	}

	kept := make([]UserPubKey, 0, len(d.PubKeys))
	for _, pk := range d.PubKeys {
		if baseKeys[pk.Key] && !ourKeys[pk.Key] {
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
		)
	}
}

// resolveUserRmRecipients: a removal wins; a no-longer-present user makes it a
// satisfied no-op.
func resolveUserRmRecipients(their *AuditEntrySigned, merged *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailUserRmRecipients](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.User }()

	cur, ok := merged.UserExists(d.User)
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
func resolveSecretAdd(their *AuditEntrySigned, merged *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailSecretAdd](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.RevealedPath }()

	existing, ok := merged.SecretExists(d.RevealedPath)
	if !ok {
		return applyAs(their)
	}

	if stringSetEqual(existing.AccessGroups, normalizeAccessGroups(d.AccessGroups)) {
		return dropWith("duplicate add of "+d.RevealedPath, false)
	}

	return dropWith("secret "+d.RevealedPath+" added on both sides with different access; kept ours", true)
}

// resolveSecretRemove: a removal wins; if our side changed the secret's access
// since base, the removal still wins but is flagged (the change is discarded).
func resolveSecretRemove(their *AuditEntrySigned, merged, base *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailSecretRemove](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.RevealedPath }()

	cur, ok := merged.SecretExists(d.RevealedPath)
	if !ok {
		return dropWith("secret "+d.RevealedPath+" already removed", false)
	}

	if b, ok := base.SecretExists(d.RevealedPath); ok && !stringSetEqual(b.AccessGroups, cur.AccessGroups) {
		r = applyAs(their)
		r.Reason = "secret " + d.RevealedPath + " had its access changed on our side but was removed on theirs; remove wins"
		r.conflict = true
		return r
	}

	return applyAs(their)
}

// resolveSecretChangeAccess three-way delta-merges the access set; remove wins on
// a clash.
func resolveSecretChangeAccess(their *AuditEntrySigned, merged, base *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailSecretChangeAccess](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.RevealedPath }()

	cur, ok := merged.SecretExists(d.RevealedPath)
	if !ok {
		return dropWith("secret "+d.RevealedPath+" removed; dropped access change", true)
	}

	var baseGroups []string
	if b, ok := base.SecretExists(d.RevealedPath); ok {
		baseGroups = b.AccessGroups
	}

	theirGroups := normalizeAccessGroups(d.AccessGroups)
	mergedGroups := normalizeAccessGroups(threeWaySet(baseGroups, cur.AccessGroups, theirGroups))

	if stringSetEqual(mergedGroups, cur.AccessGroups) {
		return dropWith("access of "+d.RevealedPath+" already covers theirs", false)
	}

	if stringSetEqual(mergedGroups, theirGroups) {
		return applyAs(their)
	}

	return rewriteAs(
		newAuditEntry(their.ChangedBy, &DetailSecretChangeAccess{RevealedPath: d.RevealedPath, AccessGroups: mergedGroups}),
		"access of "+d.RevealedPath+" delta-merged",
	)
}

// resolveSecretMove prefers ours: drop on a vanished source or an occupied target.
func resolveSecretMove(their *AuditEntrySigned, merged *VerifiedState) (r resolution) {
	d, err := parseDetail[DetailSecretMove](their)
	if err != nil {
		return dropWith(err.Error(), true)
	}
	defer func() { r.Target = d.OldRevealedPath + " -> " + d.NewRevealedPath }()

	if _, ok := merged.SecretExists(d.OldRevealedPath); !ok {
		return dropWith("move source "+d.OldRevealedPath+" gone; dropped", true)
	}

	if _, ok := merged.SecretExists(d.NewRevealedPath); ok {
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

// userModified reports whether `cur` differs from its base version `b` in any
// security-relevant way (groups, signing key or recipient set) - i.e. whether
// our side changed the user since the merge base.
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
