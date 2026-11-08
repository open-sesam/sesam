package core

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"path"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// auditLogSnapshot pairs an audit log with the commit it was read from,
// so callers can attribute errors to a specific revision. Commit is empty
// for the staged log.
type auditLogSnapshot struct {
	Commit string
	Log    *AuditLog
}

// AuditLogRewrittenError: the log at Newer does not account for every entry
// of the log at Older - entries were dropped or replaced.
type AuditLogRewrittenError struct {
	// Older and Newer are commits; Newer is empty when it is the staged log.
	Older, Newer string

	// SesamPath is the vault's .sesam directory, relative to the worktree root.
	SesamPath string

	Err error
}

func (e *AuditLogRewrittenError) Error() string {
	return fmt.Sprintf(
		"audit log at commit %s is not a prefix of %s: %v",
		e.Older, snapshotName(e.Newer), e.Err,
	)
}

func (e *AuditLogRewrittenError) Unwrap() error { return e.Err }

// snapshotName names where a log was read from: a commit, or the index.
func snapshotName(commit string) string {
	if commit == "" {
		return "the staged changes"
	}
	return "commit " + commit
}

func auditLogHistory(
	ctx context.Context,
	sesamDir string,
	g *Git,
	ids Identities,
	fromRev string,
	initCommitRev string,
	staged bool,
) (iter.Seq2[*auditLogSnapshot, error], error) {
	if initCommitRev == "" {
		// No anchor handed down, so the init-file check has not run for this
		// state (VerifyChain, or a caller without one): walk history for it.
		var err error
		if initCommitRev, err = verifyInitFileUnchangedWithRepo(ctx, sesamDir, g); err != nil {
			return nil, fmt.Errorf("verify init file: %w", err)
		}
	}

	if initCommitRev == "" {
		return func(yield func(*auditLogSnapshot, error) bool) {}, nil
	}

	fromCommit, err := g.ResolveCommit(ctx, fromRev)
	if err != nil {
		return nil, fmt.Errorf("resolve revision %q: %w", fromRev, err)
	}

	prefix, err := SesamGitPrefix(g, sesamDir)
	if err != nil {
		return nil, err
	}
	auditPathRel := path.Join(prefix, ".sesam", "audit", "log.jsonl")

	// Trust anchor: .sesam/audit/init is committed exactly once (verified above)
	// and never changes, so reading it now is equivalent to reading it at any
	// commit in history. We need to populate AuditLog.InitHash for VerifyChain.
	initPathAbs := filepath.Join(sesamDir, ".sesam", "audit", "init")
	initData, err := ReadFileLimited(initPathAbs, 256)
	if err != nil {
		return nil, fmt.Errorf("read init trust anchor: %w", err)
	}
	initHash := strings.TrimSpace(string(initData))

	return func(yield func(*auditLogSnapshot, error) bool) {
		objs, err := g.Objects(ctx)
		if err != nil {
			yield(nil, err)
			return
		}
		defer func() { _ = objs.Close() }()

		_, initHasLog, err := objs.Blob(initCommitRev + ":" + auditPathRel)
		if err != nil {
			yield(nil, fmt.Errorf("read audit log at init commit %s: %w", initCommitRev, err))
			return
		}
		if !initHasLog {
			return
		}

		var lastBlob string

		// The staged log is what the next commit will hold, so it has to cover
		// HEAD's like every commit covers its parent's.
		if staged {
			idx, found, err := objs.Blob(":" + auditPathRel)
			if err != nil {
				yield(nil, fmt.Errorf("read staged audit log: %w", err))
				return
			}

			head, _, err := objs.Blob(fromCommit + ":" + auditPathRel)
			if err != nil {
				yield(nil, fmt.Errorf("read audit log at commit %s: %w", fromCommit, err))
				return
			}

			// Not staged (or conflicted, which git refuses to commit anyway) or
			// unchanged: nothing beyond HEAD to check.
			if found && idx != head {
				snap, err := loadSnapshot(objs, idx, "", sesamDir, initHash, ids)
				if err != nil {
					yield(nil, err)
					return
				}
				if snap.Log == nil {
					yield(nil, errors.New("cannot read the staged audit log with your identity"))
					return
				}

				if !yield(snap, nil) {
					return
				}
				lastBlob = idx
			}
		}

		// Walk FIRST-PARENT (which is always "ours"). On merge commits we take
		// the route the merge driver should have taken as well - except where
		// "ours" never had a vault at all, see the cross-over below.
		hash := fromCommit
		var sawGap bool
		var child *GitCommit // the newer commit this one was reached from
		for {
			if err := ctx.Err(); err != nil {
				yield(nil, err)
				return
			}

			commit, ok, err := objs.Commit(hash)
			if err == nil && !ok {
				err = errors.New("no such commit")
			}
			if err != nil {
				yield(nil, fmt.Errorf("read commit %s: %w", hash, err))
				return
			}

			// stop iterating after the first commit in which the sesam repo existed.
			isInitCommit := commit.Hash == initCommitRev

			blob, found, err := objs.Blob(commit.Hash + ":" + auditPathRel)
			switch {
			case err != nil:
				yield(nil, fmt.Errorf("read audit log at commit %s: %w", commit.Hash, err))
				return
			case !found:
				// "Ours" carries no vault here. If this commit was reached from a
				// merge whose other side still holds the log, that side is where
				// the log's history continues - a vault merged in from a branch,
				// or a merge spliced in front of one to cut this walk short and
				// leave a shortened log with nothing to compare it against.
				// Only if "ours" never had a vault: otherwise the log was deleted
				// here, and crossing over would skip whatever it held.
				if alt, ok := logCarryingParent(ctx, g, objs, initCommitRev, child, commit, auditPathRel); ok {
					hash = alt
					continue
				}

				// Below the commit that introduced the vault - the end of this line
				// of history, not tampering.
				//
				// Keep walking rather than stopping: the log reappearing further
				// back would mean it was deleted in between, which is tampering and
				// still has to be caught.
				sawGap = true
				blob = ""
			case sawGap:
				yield(nil, fmt.Errorf(
					"audit log was removed from history: present at commit %s but missing in a newer one",
					commit.Hash,
				))
				return
			}

			// Only load (and decrypt) when the log blob actually changed from the
			// child we last yielded - unchanged logs are trivially a prefix of each
			// other. This keeps the walk as cheap as the old path-filtered one.
			if blob != "" && blob != lastBlob {
				lastBlob = blob

				snap, err := loadSnapshot(objs, blob, commit.Hash, sesamDir, initHash, ids)
				if err != nil {
					yield(nil, err)
					return
				}

				// Current user had no access at this commit — we have no way
				// to verify further back, but this is not a verification failure.
				if !yield(snap, nil) || snap.Log == nil {
					return
				}
			}

			if isInitCommit || len(commit.Parents) == 0 {
				return
			}

			child = commit
			hash = commit.Parents[0] // follow the mainline (ours) first
		}
	}, nil
}

// loadSnapshot reads the log in blob. A log ids cannot decrypt yields a
// snapshot without Log rather than an error.
func loadSnapshot(objs *GitObjects, blob, commit, sesamDir, initHash string, ids Identities) (*auditLogSnapshot, error) {
	data, _, err := objs.ReadBlob(blob)
	if err != nil {
		return nil, fmt.Errorf("open audit log at %s: %w", snapshotName(commit), err)
	}

	auditLog, err := loadAuditLogFromReader(bytes.NewReader(data), ids)
	if err != nil {
		nie := &age.NoIdentityMatchError{}
		if errors.As(err, &nie) {
			return &auditLogSnapshot{Commit: commit}, nil
		}

		return nil, fmt.Errorf("load audit log at %s: %w", snapshotName(commit), err)
	}

	// loadAuditLogFromReader does not set SesamDir or InitHash; both are
	// needed for VerifyChain. The init trust anchor was captured by the caller.
	auditLog.SesamDir = sesamDir
	auditLog.InitHash = initHash
	return &auditLogSnapshot{Commit: commit, Log: auditLog}, nil
}

// logCarryingParent returns the parent of child - other than the one already
// tried - whose tree still holds the audit log, so the walk can follow the log
// rather than the mainline where the two part ways. Only a parent that really
// carries the log is returned, so the caller cannot bounce back in here.
func logCarryingParent(
	ctx context.Context,
	g *Git,
	objs *GitObjects,
	initCommit string,
	child *GitCommit,
	tried *GitCommit,
	auditPathRel string,
) (string, bool) {
	if child == nil {
		return "", false
	}

	if hadVault, err := g.IsAncestor(ctx, initCommit, tried.Hash); err != nil || hadVault {
		return "", false
	}

	for _, parent := range child.Parents {
		if parent == tried.Hash {
			continue
		}

		if _, ok, err := objs.Blob(parent + ":" + auditPathRel); err == nil && ok {
			return parent, true
		}
	}

	return "", false
}

// auditLogIsPrefix tests if `old` is a prefix of `new`
func auditLogIsPrefix(new, old *AuditLog) error {
	oel, nel := len(old.Entries), len(new.Entries)
	if oel > nel {
		return fmt.Errorf("old audit log is bigger (%d) than new (%d)", oel, nel)
	}

	if oel == 0 || nel == 0 {
		return fmt.Errorf("neither audit log may be completely empty")
	}

	for idx := range old.Entries {
		if new.Entries[idx].Signature != old.Entries[idx].Signature {
			return fmt.Errorf("audit log entries differ at index %d (seq_id %d)", idx, old.Entries[idx].SeqID)
		}
	}

	return nil
}

// auditLogCovers tests that every entry of `old` is accounted for in `new`:
// either `old` is a prefix of `new`, or `new` holds a merge that took in
// exactly `old`. The latter is what a branch looks like that merged its
// upstream and was then squashed into it.
func auditLogCovers(new, old *AuditLog) error {
	prefixErr := auditLogIsPrefix(new, old)
	if prefixErr == nil || mergeTookIn(new.Entries, old.Entries) {
		return nil
	}

	return prefixErr
}

// mergeTookIn reports whether a merge entry in `entries` took in exactly `taken`.
// A merge takes in all of theirs: each entry was in its base, which ours carries
// too, or the merge decided on it.
func mergeTookIn(entries, taken []AuditEntrySigned) bool {
	tip := &taken[len(taken)-1]
	for i := range entries {
		if entries[i].Operation != OpMerge {
			continue
		}

		d, err := parseDetail[DetailMerge](&entries[i])
		if err != nil || d.TheirTipSeqID != tip.SeqID {
			continue
		}

		if d.TheirTipHash != "" {
			if ok, _ := tip.HashMatches(d.TheirTipHash); ok {
				return true
			}

			continue
		}

		// Merges from before TheirTipHash: bind by content instead.
		if legacyMergeTookIn(entries, taken) {
			return true
		}
	}

	return false
}

// legacyMergeTookIn reports whether every removal in `taken` is in `entries`
// or recorded as dropped by one of its merges. Anything else a merge may leave
// out without a record: seals and merge entries are redone, already satisfied
// entries are deduped.
func legacyMergeTookIn(entries, taken []AuditEntrySigned) bool {
	have := make(map[string]int, len(entries))
	recorded := make(map[string]int)
	for i := range entries {
		have[entryOriginKey(&entries[i])]++
		if entries[i].Operation != OpMerge {
			continue
		}

		d, err := parseDetail[DetailMerge](&entries[i])
		if err != nil {
			continue
		}

		for _, r := range d.Resolutions {
			if r.Action == MergeDropped {
				recorded[string(r.Operation)+"\x00"+r.ChangedByBeforeMerge+"\x00"+r.Target]++
			}
		}
	}

	for i := range taken {
		e := &taken[i]
		if !revokesAccess(e.Operation) {
			continue
		}

		if key := entryOriginKey(e); have[key] > 0 {
			have[key]--
			continue
		}

		dropKey := string(e.Operation) + "\x00" + cmp.Or(e.ChangedByBeforeMerge, e.ChangedBy) + "\x00" + entryUserTarget(e)
		if recorded[dropKey] == 0 {
			return false
		}

		recorded[dropKey]--
	}

	return true
}

// entryOriginKey identifies an entry across a merge's re-signing, which keeps
// operation, detail and time but moves the author to ChangedByBeforeMerge.
func entryOriginKey(e *AuditEntrySigned) string {
	return entryContentKey(&e.AuditEntry) + "\x00" +
		e.Time.UTC().Format(time.RFC3339Nano) + "\x00" +
		cmp.Or(e.ChangedByBeforeMerge, e.ChangedBy)
}

// VerifyHistory checks that, along the FIRST-PARENT chain from the staged log
// through HEAD, every older audit log is accounted for in the newer one (see
// auditLogCovers), and that the tip chain-verifies. Where that chain has no
// vault - a merge that brought one in from its second parent - the walk crosses
// over to the parent that does, so the log's own ancestry is followed down to
// the trust anchor.
//
// A merge done WITHOUT sesam's driver (e.g. a hand-resolved log conflict) that
// drops mainline entries is correctly reported as truncation - fix it by
// re-merging through sesam so the log is rebased instead of overwritten.
//
// initCommitRev is the trust anchor commit from Verify (VerifiedState.InitCommit):
// finding it walks the whole history, and Verify already did that. Pass "" to
// have it determined here, which also re-runs the init-file check.
//
// stoppedAt is the commit whose log ids cannot read, where the walk ended
// early; empty when it reached the trust anchor.
//
// CAVEAT: Right now we do not recognize renames: If the sesam repo was moved from secret/ to secrets/
// then this function does not find the old audit log before that rename. We could use git's renames,
// but there will edge cases too if the file was renamed and a user was rotated (git looks for 50% matching content).
func VerifyHistory(
	ctx context.Context,
	sesamDir string,
	g *Git,
	ids Identities,
	pluginUI *PluginUI,
	initCommitRev string,
) (stoppedAt string, err error) {
	prefix, err := SesamGitPrefix(g, sesamDir)
	if err != nil {
		return "", err
	}
	sesamPath := path.Join(prefix, ".sesam")

	auditLogIter, err := auditLogHistory(
		ctx,
		sesamDir,
		g,
		ids,
		"HEAD",
		initCommitRev,
		true,
	)
	if err != nil {
		return "", fmt.Errorf("build audit log history: %w", err)
	}

	var prev *auditLogSnapshot
	for curr, err := range auditLogIter {
		if err != nil {
			return "", err
		}

		if curr.Log == nil {
			return curr.Commit, nil
		}

		if prev == nil {
			// First iteration yields the newest log. We chain-verify it once;
			// older logs inherit validity by being prefixes of it (transitively).
			if _, err := VerifyChain(curr.Log, EmptyKeyring(), pluginUI); err != nil {
				return "", fmt.Errorf("verify audit log chain at %s: %w", snapshotName(curr.Commit), err)
			}
		} else {
			// Walking backward: prev is the newer log, curr is the older one
			// whose entries it has to account for.
			if err := auditLogCovers(prev.Log, curr.Log); err != nil {
				return "", &AuditLogRewrittenError{
					Older:     curr.Commit,
					Newer:     prev.Commit,
					SesamPath: sesamPath,
					Err:       err,
				}
			}
		}

		prev = curr
	}

	return "", nil
}
