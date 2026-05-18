package core

import (
	"errors"
	"fmt"
	"io"
	"iter"
	"path/filepath"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

func auditLogHistory(sesamDir string, repo *git.Repository, ids Identities, fromRev string) (iter.Seq2[*AuditLog, error], error) {
	fromCommit, err := repo.ResolveRevision(plumbing.Revision(fromRev))
	if err != nil {
		return nil, err
	}

	initCommitRev, err := verifyInitFileUnchangedWithRepo(sesamDir, repo)
	if err != nil {
		return nil, err
	}

	if initCommitRev == "" {
		// that's returned by verifyInitFileUnchangedWithRepo() if we only have a single commit,
		// there's no point to do a history check then, return an empty iterator.
		return func(yield func(*AuditLog, error) bool) {}, nil
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to open worktree: %w", err)
	}

	auditPathAbs := filepath.Join(sesamDir, ".sesam", "audit", "log.jsonl")
	auditPathRel, err := filepath.Rel(wt.Filesystem.Root(), auditPathAbs)
	if err != nil {
		return nil, err
	}

	auditPathRel = filepath.ToSlash(auditPathRel)
	iter, err := repo.Log(&git.LogOptions{
		From: *fromCommit,
		PathFilter: func(path string) bool {
			return path == auditPathRel
		},
		All: false,
	})
	if err != nil {
		return nil, err
	}

	return func(yield func(*AuditLog, error) bool) {
		defer iter.Close()

		isInitCommit := false
		for !isInitCommit {
			commit, err := iter.Next()
			if err != nil {
				if err == io.EOF {
					break
				}

				yield(nil, err)
				return
			}

			// we've reached the first commit in which the sesam repo existed
			// we still need to check that commit, but can stop iterating after.
			isInitCommit = commit.Hash.String() == initCommitRev

			tree, err := commit.Tree()
			if err != nil {
				yield(nil, err)
				return
			}

			file, err := tree.File(auditPathRel)
			if err != nil {
				yield(nil, err)
				return
			}

			rd, err := file.Reader()
			if err != nil {
				// NOTE: We also error out here if the file does not exist in this commit.
				// Since it should exist until the init commit this seems wrong.
				// It's not really a  security issue, so we might tolerate that in the future.
				yield(nil, err)
				return
			}

			auditLog, err := loadAuditLogFromReader(rd, ids)
			if err != nil {
				nie := &age.NoIdentityMatchError{}
				if errors.As(err, &nie) {
					// NOTE: This might fail if the the current user had no access in this commit.
					// For that case we should stop iterating - we simply have no way to verify further.
					return
				}

				yield(nil, err)
				return
			}

			if !yield(auditLog, nil) {
				break
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

	// need to do an equal check:
	for oldIdx := oel - 1; oldIdx >= 0; oldIdx-- {
		oldEntry := old.Entries[oldIdx]
		newEntry := new.Entries[oldIdx]
		if newEntry.Signature != oldEntry.Signature {
			return fmt.Errorf("bad signature in")
		}
	}

	return nil
}

// VerifyHistory will check if all audit logs before this commit are a prefix of the current audit log.
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
		return err
	}

	var prev *AuditLog
	for curr, err := range auditLogIter {
		if err != nil {
			// error during reading.
			return err
		}

		if prev != nil {
			err := auditLogIsPrefix(curr, prev)
			if err != nil {
				return err
			}
		} else {
			// For the very first log we need to verify the state. All historic logs
			// can be considered valid if they are just a prefix of the current one.
			_, err = VerifyChain(curr, EmptyKeyring(), pluginUI)
			if err != nil {
				return err
			}
		}

		prev = curr
	}

	return nil
}
