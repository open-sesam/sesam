package core

// Audit-log merge: design notes.
//
// The audit log is an event-sourced projection: VerifyChain replays entries
// into a VerifiedState (users, groups, per-secret access, LastSealRootHash).
// That derived state - not sesam.yml - is the source of truth, and only the
// LAST seal's root hash is checked against disk. Merging two logs therefore
// means: converge on the merged STATE and synthesize a coherent chain that
// replays to it. We never concatenate the two chains.
//
// Guiding decisions:
//   - Revocation wins (kill/remove beats a concurrent modify).
//   - Only the re-signature survives: theirs is rebased onto ours and re-signed
//     by the merging admin. Original authors are kept in ChangedBy; a single
//     "merge" entry (OpMerge/DetailMerge) records provenance and what happened.
//   - sesam.yml is regenerated from the merged log (planned `sesam config
//     reset`), so config never conflicts textually.
//   - Best effort, never block: capture user intent where possible, print
//     warnings for anything lossy so the user can adjust post-merge.
//   - Only admins can merge (decrypt + re-sign); a non-admin must abort and ask
//     an admin (`git merge --abort`).
//
// ---------------------------------------------------------------------------
// Mechanical steps (apply to EVERY non-trivial merge)
// ---------------------------------------------------------------------------
//
//  M1 init: the base/init entry must be identical on both sides. Mismatch means
//     a different repo or a truncated log - HARD ERROR, not a conflict.
//  M2 base: find the common prefix (shared entries up to the merge base).
//  M3 dedupe: identical concurrent entries collapse to one.
//  M4 rebase ours-first: base -> ours' new entries (unchanged order) -> theirs'
//     new entries (kept relative order), each renumbered (SeqID), rechained
//     (PreviousHash), re-encrypted (nonce = SeqID) and re-signed by the merging
//     admin.
//  M5 merge entry: append one OpMerge entry recording provenance (base SeqID,
//     tip SeqIDs of both sides, counts, per-entity overrides/drops, warnings).
//  M6 terminal seal: deferred to the pre-commit reseal, which recomputes the
//     root hash from the actually-merged objects. This is what ties the log to
//     what the secret merges produced. Both sides' post-base seals are dropped
//     as authorities and kept only as history.
//
// ---------------------------------------------------------------------------
// Semantic resolution (three-way merge of state; base = merge-base state)
// ---------------------------------------------------------------------------
//
// Toolbox:
//   - set fields (groups, recipients, access lists): three-way DELTA merge -
//     apply each side's add/remove vs base; on an add-vs-remove clash of the
//     same element, REMOVE wins (revocation / least privilege).
//   - single-valued fields (rename target, move target, sign key): PREFER OURS
//     + warn (no union possible).
//   - delete-vs-modify: the delete (kill/remove) wins + warn.
//   - time is informational only, never the arbiter (clock skew, spoofable).
//
// USER (keyed by name):
//   U1 modify vs kill (tell/change_groups/rename/add|rm_recipients/regen vs
//      kill) -> kill wins. warn.
//   U2 tell vs tell same name: identical -> dedupe; different identity -> keep
//      ours, warn (cannot safely fuse two identities).
//   U3 change_groups divergent -> delta merge; clash -> remove wins.
//   U4 add/rm_recipients divergent -> delta merge; add-vs-remove same key ->
//      remove wins (revocation).
//   U5 rename: both rename same user, or target-name collision, or swap ->
//      prefer ours, drop the conflicting rename, warn.
//   U6 regenerate_sign_key on both -> prefer ours, warn loudly (the other
//      private-key holder is stranded until re-rotated).
//   U7 zero admins after merge (both sides killed different admins) ->
//      auto-repair: decline whichever kill(s) are needed to keep >=1 admin,
//      preferring ours' admin. warn. never block.
//
// SECRET (keyed by revealed path):
//   B1 modify vs remove (change_access/move/seal vs remove) -> remove wins. warn.
//   B2 add vs add same path -> dedupe metadata; access via delta merge; content
//      is merged by the secret driver; keep a single add.
//   B3 change_access divergent -> delta merge; clash -> remove wins.
//   B4 move: both move same secret, or destination collision (move->W vs
//      move/add at W) -> prefer ours, drop the conflicting move, warn.
//
// REFERENTIAL / CLEANUP (after state merge):
//   R1 dangling group reference (access group left with no members after kills)
//      -> keep the reference (empty group == admin-only), warn.
//   R2 authority-under-reorder: theirs' entries were valid on their branch; we
//      do NOT re-check their authority against the reordered chain. The merging
//      admin's re-signature is the post-merge attestation; ChangedBy + the merge
//      entry preserve accountability.
//   R3 the "tell/kill must be followed by a seal with a different root hash"
//      adjacency invariant is satisfied by the terminal reseal (M6).
//
// SEAL:
//   D1 both sides sealed with different root hashes -> neither is authoritative
//      post-merge; superseded by the terminal reseal (M6).
