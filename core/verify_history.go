package core

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"path"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

// auditLogSnapshot pairs an audit log with the commit it was read from,
// so callers can attribute errors to a specific revision.
type auditLogSnapshot struct {
	Commit string
	Log    *AuditLog
}

func auditLogHistory(
	sesamDir string,
	g *Git,
	ids Identities,
	fromRev string,
	initCommitRev string,
) (iter.Seq2[*auditLogSnapshot, error], error) {
	if initCommitRev == "" {
		// No anchor handed down, so the init-file check has not run for this
		// state (VerifyChain, or a caller without one): walk history for it.
		var err error
		if initCommitRev, err = verifyInitFileUnchangedWithRepo(sesamDir, g); err != nil {
			return nil, fmt.Errorf("verify init file: %w", err)
		}
	}

	if initCommitRev == "" {
		return func(yield func(*auditLogSnapshot, error) bool) {}, nil
	}

	fromCommit, err := g.ResolveCommit(fromRev)
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

	initHasLog, err := hasBlob(g, initCommitRev+":"+auditPathRel)
	if err != nil {
		return nil, fmt.Errorf("read audit log at init commit %s: %w", initCommitRev, err)
	}
	if !initHasLog {
		return func(yield func(*auditLogSnapshot, error) bool) {}, nil
	}

	return func(yield func(*auditLogSnapshot, error) bool) {
		objs, err := g.Objects()
		if err != nil {
			yield(nil, err)
			return
		}
		defer func() { _ = objs.Close() }()

		// Walk FIRST-PARENT (which is always "ours"). On merge commits we take
		// the route the merge driver should have taken as well - except where
		// "ours" never had a vault at all, see the cross-over below.
		hash := fromCommit
		var lastBlob string
		var sawGap bool
		var child *GitCommit // the newer commit this one was reached from
		for {
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
				if alt, ok := logCarryingParent(g, objs, initCommitRev, child, commit, auditPathRel); ok {
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

				data, _, err := objs.ReadBlob(blob)
				if err != nil {
					yield(nil, fmt.Errorf("open audit log at commit %s: %w", commit.Hash, err))
					return
				}

				auditLog, err := loadAuditLogFromReader(bytes.NewReader(data), ids)
				if err != nil {
					nie := &age.NoIdentityMatchError{}
					if errors.As(err, &nie) {
						// Current user had no access at this commit — we have no way
						// to verify further back, but this is not a verification failure.
						return
					}

					yield(nil, fmt.Errorf("load audit log at commit %s: %w", commit.Hash, err))
					return
				}

				// loadAuditLogFromReader does not set SesamDir or InitHash; both are
				// needed for VerifyChain. The init trust anchor was captured above.
				auditLog.SesamDir = sesamDir
				auditLog.InitHash = initHash

				if !yield(&auditLogSnapshot{Commit: commit.Hash, Log: auditLog}, nil) {
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

// logCarryingParent returns the parent of child - other than the one already
// tried - whose tree still holds the audit log, so the walk can follow the log
// rather than the mainline where the two part ways. Only a parent that really
// carries the log is returned, so the caller cannot bounce back in here.
func logCarryingParent(
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

	if hadVault, err := g.IsAncestor(initCommit, tried.Hash); err != nil || hadVault {
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

// hasBlob reports whether rev, e.g. "<commit>:<path>", names a blob.
func hasBlob(g *Git, rev string) (bool, error) {
	objs, err := g.Objects()
	if err != nil {
		return false, err
	}
	defer func() { _ = objs.Close() }()

	_, ok, err := objs.Blob(rev)
	return ok, err
}

// auditLogIsPrefix tests if `old` is a prefix of `new`
// If this is not the case, an error with the specifics are returned.
func auditLogIsPrefix(new, old *AuditLog) error {
	oel, nel := len(old.Entries), len(new.Entries)
	if oel > nel {
		return fmt.Errorf("old audit log is bigger (%d) than new (%d)", oel, nel)
	}

	if oel == 0 || nel == 0 {
		return fmt.Errorf("neither audit log may be completely empty")
	}

	for oldIdx := oel - 1; oldIdx >= 0; oldIdx-- {
		oldEntry := old.Entries[oldIdx]
		newEntry := new.Entries[oldIdx]
		if newEntry.Signature != oldEntry.Signature {
			return fmt.Errorf("audit log entries differ at index %d (seq_id %d)", oldIdx, oldEntry.SeqID)
		}
	}

	return nil
}

// VerifyHistory checks that, along the FIRST-PARENT chain from HEAD, every older
// audit log is a prefix of the newer one (append-only, no truncation), and that
// the tip chain-verifies. Where that chain has no vault - a merge that brought
// one in from its second parent - the walk crosses over to the parent that does,
// so the log's own ancestry is followed down to the trust anchor.
//
// A merge done WITHOUT sesam's driver (e.g. a hand-resolved log conflict) that
// drops mainline entries is correctly reported as truncation - fix it by
// re-merging through sesam so the log is rebased instead of overwritten.
//
// initCommitRev is the trust anchor commit from Verify (VerifiedState.InitCommit):
// finding it walks the whole history, and Verify already did that. Pass "" to
// have it determined here, which also re-runs the init-file check.
//
// CAVEAT: Right now we do not recognize renames: If the sesam repo was moved from secret/ to secrets/
// then this function does not find the old audit log before that rename. We could use git's renames,
// but there will edge cases too if the file was renamed and a user was rotated (git looks for 50% matching content).
func VerifyHistory(
	sesamDir string,
	g *Git,
	ids Identities,
	pluginUI *PluginUI,
	initCommitRev string,
) error {
	auditLogIter, err := auditLogHistory(
		sesamDir,
		g,
		ids,
		"HEAD",
		initCommitRev,
	)
	if err != nil {
		return fmt.Errorf("build audit log history: %w", err)
	}

	var prev *auditLogSnapshot
	for curr, err := range auditLogIter {
		if err != nil {
			return err
		}

		if prev == nil {
			// First iteration yields the newest log. We chain-verify it once;
			// older logs inherit validity by being prefixes of it (transitively).
			if _, err := VerifyChain(curr.Log, EmptyKeyring(), pluginUI); err != nil {
				return fmt.Errorf("verify audit log chain at commit %s: %w", curr.Commit, err)
			}
		} else {
			// Walking backward: prev is the newer (longer) log, curr is the older
			// (shorter) one that should be its prefix.
			if err := auditLogIsPrefix(prev.Log, curr.Log); err != nil {
				return fmt.Errorf(
					"audit log at commit %s is not a prefix of commit %s: %w",
					curr.Commit, prev.Commit, err,
				)
			}
		}

		prev = curr
	}

	return nil
}
