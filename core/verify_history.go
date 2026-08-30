package core

import (
	"errors"
	"fmt"
	"iter"
	"path"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// auditLogSnapshot pairs an audit log with the commit it was read from,
// so callers can attribute errors to a specific revision.
type auditLogSnapshot struct {
	Commit plumbing.Hash
	Log    *AuditLog
}

func auditLogHistory(sesamDir string, repo *git.Repository, ids Identities, fromRev string) (iter.Seq2[*auditLogSnapshot, error], error) {
	initCommitRev, err := verifyInitFileUnchangedWithRepo(sesamDir, repo)
	if err != nil {
		return nil, fmt.Errorf("verify init file: %w", err)
	}

	if initCommitRev == "" {
		return func(yield func(*auditLogSnapshot, error) bool) {}, nil
	}

	fromCommit, err := repo.ResolveRevision(plumbing.Revision(fromRev))
	if err != nil {
		return nil, fmt.Errorf("resolve revision %q: %w", fromRev, err)
	}

	prefix, err := SesamGitPrefix(repo, sesamDir)
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

	initCommit, err := repo.CommitObject(plumbing.NewHash(initCommitRev))
	if err != nil {
		return nil, fmt.Errorf("read init commit %s: %w", initCommitRev, err)
	}
	initTree, err := initCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read init tree at %s: %w", initCommitRev, err)
	}
	if _, err := initTree.File(auditPathRel); errors.Is(err, object.ErrFileNotFound) {
		return func(yield func(*auditLogSnapshot, error) bool) {}, nil
	}

	return func(yield func(*auditLogSnapshot, error) bool) {
		// Walk FIRST-PARENT only (which is always "ours"). On merge commits we
		// should take the route the merge driver should have taken as well.
		hash := *fromCommit
		var lastBlob plumbing.Hash
		var sawGap bool
		for {
			commit, err := repo.CommitObject(hash)
			if err != nil {
				yield(nil, fmt.Errorf("read commit %s: %w", hash, err))
				return
			}

			// stop iterating after the first commit in which the sesam repo existed.
			isInitCommit := commit.Hash.String() == initCommitRev

			tree, err := commit.Tree()
			if err != nil {
				yield(nil, fmt.Errorf("read tree at commit %s: %w", commit.Hash, err))
				return
			}

			file, err := tree.File(auditPathRel)
			switch {
			case errors.Is(err, object.ErrFileNotFound):
				// Below the commit that introduced the vault - the end of this line
				// of history, not tampering. initCommitRev comes from an all-parents
				// walk, so when the vault was created on a side branch it sits off
				// the first-parent chain we follow and we run past it.
				//
				// Keep walking rather than stopping: the log reappearing further
				// back would mean it was deleted in between, which is tampering and
				// still has to be caught.
				sawGap = true
				file = nil
			case err != nil:
				yield(nil, fmt.Errorf("read audit log at commit %s: %w", commit.Hash, err))
				return
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
			if file != nil && file.Hash != lastBlob {
				lastBlob = file.Hash

				rd, err := file.Reader()
				if err != nil {
					yield(nil, fmt.Errorf("open audit log at commit %s: %w", commit.Hash, err))
					return
				}

				auditLog, err := loadAuditLogFromReader(rd, ids)
				_ = rd.Close()
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

			if isInitCommit || len(commit.ParentHashes) == 0 {
				return
			}

			hash = commit.ParentHashes[0] // follow the mainline (ours) only
		}
	}, nil
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
// the tip chain-verifies.
//
// A merge done WITHOUT sesam's driver (e.g. a hand-resolved log conflict) that
// drops mainline entries is correctly reported as truncation - fix it by
// re-merging through sesam so the log is rebased instead of overwritten.
//
// CAVEAT: Right now we do not recognize renames: If the sesam repo was moved from secret/ to secrets/
// then this function does not find the old audit log before that rename. We could use git's renames,
// but there will edge cases too if the file was renamed and a user was rotated (git looks for 50% matching content).
func VerifyHistory(sesamDir string, repo *git.Repository, ids Identities, pluginUI *PluginUI) error {
	auditLogIter, err := auditLogHistory(
		sesamDir,
		repo,
		ids,
		"HEAD",
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
