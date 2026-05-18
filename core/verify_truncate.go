package core

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// auditLogSnapshot pairs an audit log with the commit it was read from,
// so callers can attribute errors to a specific revision.
type auditLogSnapshot struct {
	Commit plumbing.Hash
	Log    *AuditLog
}

func auditLogHistory(sesamDir string, repo *git.Repository, ids Identities, fromRev string) (iter.Seq2[*auditLogSnapshot, error], error) {
	// Check the init anchor before resolving fromRev. If init was never
	// committed (returns "") there is nothing to verify regardless of fromRev,
	// and this case includes "no commits yet at all" — in which case
	// ResolveRevision("HEAD") would otherwise fail spuriously.
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

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("open worktree: %w", err)
	}

	auditPathAbs := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	auditPathRel, err := filepath.Rel(wt.Filesystem.Root(), auditPathAbs)
	if err != nil {
		return nil, fmt.Errorf("compute audit log relative path: %w", err)
	}

	// Trust anchor: .sesam/audit/init is committed exactly once (verified above)
	// and never changes, so reading it now is equivalent to reading it at any
	// commit in history. We need to populate AuditLog.InitHash for VerifyChain.
	initPathAbs := filepath.Join(sesamDir, ".sesam", "audit", "init")
	initData, err := ReadFileLimited(initPathAbs, 256)
	if err != nil {
		return nil, fmt.Errorf("read init trust anchor: %w", err)
	}
	initHash := strings.TrimSpace(string(initData))

	auditPathRel = filepath.ToSlash(auditPathRel)
	iter, err := repo.Log(&git.LogOptions{
		From: *fromCommit,
		PathFilter: func(path string) bool {
			return path == auditPathRel
		},
		All: false,
	})
	if err != nil {
		return nil, fmt.Errorf("open git log from %s: %w", fromCommit, err)
	}

	return func(yield func(*auditLogSnapshot, error) bool) {
		defer iter.Close()

		isInitCommit := false
		for !isInitCommit {
			commit, err := iter.Next()
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				yield(nil, fmt.Errorf("iterate git log: %w", err))
				return
			}

			// we've reached the first commit in which the sesam repo existed;
			// still process this commit, but stop iterating afterwards.
			isInitCommit = commit.Hash.String() == initCommitRev

			tree, err := commit.Tree()
			if err != nil {
				yield(nil, fmt.Errorf("read tree at commit %s: %w", commit.Hash, err))
				return
			}

			file, err := tree.File(auditPathRel)
			if err != nil {
				// NOTE: between init and HEAD the file should always be present.
				// If it's missing we treat it as a hard error for now; renames
				// (see VerifyHistory caveat) would surface here too.
				yield(nil, fmt.Errorf("audit log not found at commit %s: %w", commit.Hash, err))
				return
			}

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

// VerifyHistory will check if all audit logs before this commit are a prefix of the current audit log.
// It will return an error describing the found issues, if any.
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
