package core

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// historyFixture is a sesam-initialized git repo with the init audit log committed,
// ready for further entries and commits to build out test histories.
//
// We use an on-disk tempdir (not memfs) because sesam's audit log writes go
// through the os package directly; a memory billy filesystem would never see them.
type historyFixture struct {
	SesamDir string
	Repo     *git.Repository
	Admin    *testUser
	AuditLog *AuditLog
	Ids      Identities
}

func newHistoryFixture(t *testing.T) *historyFixture {
	t.Helper()
	sesamDir, repo := testGitRepo(t)
	admin := newTestUser(t, "admin")
	al := initAuditLog(t, sesamDir, admin)
	gitCommitAll(t, repo, "sesam init")

	return &historyFixture{
		SesamDir: sesamDir,
		Repo:     repo,
		Admin:    admin,
		AuditLog: al,
		Ids:      Identities{admin.Identity},
	}
}

// addSeal appends a placeholder seal entry to the open audit log.
func (f *historyFixture) addSeal(t *testing.T) {
	t.Helper()
	_, err := f.AuditLog.AddEntry(f.Admin.Signer, newAuditEntry(f.Admin.Name, &DetailSeal{
		RootHash:    "placeholder",
		FilesSealed: 0,
	}), nil)
	require.NoError(t, err)
}

// commit stages everything and creates a git commit.
func (f *historyFixture) commit(t *testing.T, msg string) {
	t.Helper()
	gitCommitAll(t, f.Repo, msg)
}

// tellUser adds newUser via the UserManager. This rewrites the audit key
// envelope on log.jsonl line 1 to include newUser's recipient, so older
// commits (pre-tell) remain inaccessible to newUser.
func (f *historyFixture) tellUser(t *testing.T, newUser *testUser, groups []string) {
	t.Helper()

	kr := EmptyKeyring()
	state := &VerifiedState{auditLog: f.AuditLog, keyring: kr}
	require.NoError(t, verify(state))

	secMgr, err := BuildSecretManager(
		f.SesamDir, f.AuditLog.root, Identities{f.Admin.Identity}, f.Admin.Signer, kr, f.AuditLog, state,
	)
	require.NoError(t, err)

	um, err := BuildUserManager(f.AuditLog.root, f.Admin.Signer, f.AuditLog, state, secMgr)
	require.NoError(t, err)

	require.NoError(t, um.UserTell(
		context.Background(),
		newUser.Name,
		[]string{newUser.Recipient.String()},
		groups,
	))
}

// deleteLog removes log.jsonl from the worktree and stages the deletion.
// Closes the audit log first. Caller must commit afterwards.
func (f *historyFixture) deleteLog(t *testing.T) {
	t.Helper()
	require.NoError(t, f.AuditLog.Close())
	wt, err := f.Repo.Worktree()
	require.NoError(t, err)
	_, err = wt.Remove(filepath.Join(".sesam", "audit", "log.jsonl"))
	require.NoError(t, err)
}

// truncateLog drops the last entry from log.jsonl on disk, simulating a
// truncation attack. Closes the audit log because the in-memory handle is
// no longer in sync with disk. Caller must commit afterwards.
func (f *historyFixture) truncateLog(t *testing.T) {
	t.Helper()
	require.NoError(t, f.AuditLog.Close())
	logPath := filepath.Join(f.SesamDir, ".sesam", "audit", "log.jsonl")
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Format: "<key>\n<entry1>\n<entry2>\n...\n"
	// SplitAfter keeps the \n with each chunk; trailing empty string follows the final \n.
	lines := bytes.SplitAfter(data, []byte("\n"))
	require.GreaterOrEqual(t, len(lines), 4,
		"need at least key + 2 entries (and trailing empty) to drop one")
	truncated := bytes.Join(lines[:len(lines)-2], nil)
	require.NoError(t, os.WriteFile(logPath, truncated, 0o600))
}

// ---------- auditLogIsPrefix ----------

func TestAuditLogIsPrefix(t *testing.T) {
	mk := func(sigs ...string) *AuditLog {
		entries := make([]AuditEntrySigned, len(sigs))
		for i, s := range sigs {
			entries[i] = AuditEntrySigned{
				AuditEntry: AuditEntry{SeqID: uint64(i + 1)},
				Signature:  s,
			}
		}
		return &AuditLog{Entries: entries}
	}

	tests := []struct {
		name    string
		newLog  *AuditLog
		oldLog  *AuditLog
		wantErr string
	}{
		{"equal logs", mk("a", "b", "c"), mk("a", "b", "c"), ""},
		{"old is proper prefix", mk("a", "b", "c"), mk("a", "b"), ""},
		{"old has only init entry", mk("a", "b", "c"), mk("a"), ""},
		{"old longer than new", mk("a", "b"), mk("a", "b", "c"), "old audit log is bigger"},
		{"old differs at first", mk("a", "b", "c"), mk("a'"), "differ at index 0"},
		{"old differs in middle", mk("a", "b", "c"), mk("a", "b'"), "differ at index 1"},
		{"old differs at last", mk("a", "b", "c"), mk("a", "b", "c'"), "differ at index 2"},
		{"empty old", mk("a"), mk(), "completely empty"},
		{"empty new but non-empty old", mk(), mk("a"), "old audit log is bigger"},
		{"both empty", mk(), mk(), "completely empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := auditLogIsPrefix(tt.newLog, tt.oldLog)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

// ---------- auditLogHistory ----------

func TestAuditLogHistory(t *testing.T) {
	tests := []struct {
		name      string
		setup     func(t *testing.T, f *historyFixture)
		fromRev   string
		ids       func(t *testing.T, f *historyFixture) Identities
		wantSnaps []int  // expected entry counts in yield order (newest-first), nil if expecting an error
		wantErr   string // substring; empty means no error
	}{
		{
			name:      "single init commit",
			setup:     func(t *testing.T, f *historyFixture) {},
			fromRev:   "HEAD",
			ids:       func(t *testing.T, f *historyFixture) Identities { return f.Ids },
			wantSnaps: []int{1},
		},
		{
			name: "two seals add to history",
			setup: func(t *testing.T, f *historyFixture) {
				f.addSeal(t)
				f.commit(t, "seal 1")
				f.addSeal(t)
				f.commit(t, "seal 2")
			},
			fromRev:   "HEAD",
			ids:       func(t *testing.T, f *historyFixture) Identities { return f.Ids },
			wantSnaps: []int{3, 2, 1},
		},
		{
			name:    "unresolvable revision",
			setup:   func(t *testing.T, f *historyFixture) {},
			fromRev: "does-not-exist",
			ids:     func(t *testing.T, f *historyFixture) Identities { return f.Ids },
			wantErr: "resolve revision",
		},
		{
			name: "non-matching identity stops gracefully",
			setup: func(t *testing.T, f *historyFixture) {
				f.addSeal(t)
				f.commit(t, "seal")
			},
			fromRev: "HEAD",
			ids: func(t *testing.T, f *historyFixture) Identities {
				// stranger is not a recipient of any audit log entry; loading
				// will fail with age.NoIdentityMatchError, which the iterator
				// treats as "no access from this point back" and stops cleanly.
				stranger := newTestUser(t, "stranger")
				return Identities{stranger.Identity}
			},
			wantSnaps: []int{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newHistoryFixture(t)
			tt.setup(t, f)

			iter, err := auditLogHistory(f.SesamDir, f.Repo, tt.ids(t, f), tt.fromRev)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			var gotSnaps []int
			for snap, err := range iter {
				require.NoError(t, err)
				gotSnaps = append(gotSnaps, len(snap.Log.Entries))
			}

			if len(tt.wantSnaps) == 0 {
				require.Empty(t, gotSnaps)
			} else {
				require.Equal(t, tt.wantSnaps, gotSnaps)
			}
		})
	}
}

// ---------- VerifyHistory ----------

func TestVerifyHistory(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, f *historyFixture)
		wantErr string // substring; empty means no error
	}{
		{
			name:  "single init commit",
			setup: func(t *testing.T, f *historyFixture) {},
		},
		{
			name: "linear history with multiple commits",
			setup: func(t *testing.T, f *historyFixture) {
				f.addSeal(t)
				f.commit(t, "seal 1")
				f.addSeal(t)
				f.commit(t, "seal 2")
			},
		},
		{
			name: "truncation between commits is caught",
			setup: func(t *testing.T, f *historyFixture) {
				f.addSeal(t)
				f.commit(t, "added seal")
				f.truncateLog(t)
				f.commit(t, "tampered: drop last entry")
			},
			wantErr: "is not a prefix of commit",
		},
		{
			name: "audit log missing in intermediate commit",
			setup: func(t *testing.T, f *historyFixture) {
				f.addSeal(t)
				f.commit(t, "added seal")
				f.deleteLog(t)
				f.commit(t, "removed log.jsonl")
			},
			wantErr: "audit log not found at commit",
		},
		{
			name: "user added after init stops walk gracefully",
			setup: func(t *testing.T, f *historyFixture) {
				// Tell alice. After this, log.jsonl line 1 is re-encrypted to
				// include alice, but the init commit's version is still only
				// encrypted to admin. We then run VerifyHistory as alice: she
				// can read HEAD but not the init commit — the iterator stops
				// gracefully on age.NoIdentityMatchError without erroring.
				alice := newTestUser(t, "alice")
				f.tellUser(t, alice, []string{"users"})
				f.commit(t, "tell alice")
				f.Ids = Identities{alice.Identity}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newHistoryFixture(t)
			tt.setup(t, f)

			err := VerifyHistory(f.SesamDir, f.Repo, f.Ids, NewNonInteractivePluginUI())
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

// TestVerifyHistory_NoCommitsYet covers the case where the repo has no commits
// at all (sesam files may exist on disk, but nothing was ever committed). The
// init-anchor check returns "" via ErrReferenceNotFound, we short-circuit to
// the empty iterator before trying to resolve HEAD, and VerifyHistory returns
// nil because there's nothing to verify.
func TestVerifyHistory_NoCommitsYet(t *testing.T) {
	sesamDir, repo := testGitRepo(t)
	require.NoError(t, VerifyHistory(sesamDir, repo, Identities{}, NewNonInteractivePluginUI()))
}

// TestVerifyHistory_NoSesamInit covers the case where the repo has commits but
// none of them touched .sesam/audit/init — i.e., sesam was never initialized
// in this repo. The init-anchor check returns "" (commitCount == 0), we
// short-circuit to the empty iterator, no error.
func TestVerifyHistory_NoSesamInit(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	require.NoError(t, os.WriteFile(filepath.Join(sesamDir, "README.md"), []byte("hi"), 0o600))
	gitCommitAll(t, repo, "unrelated commit, no sesam init")

	require.NoError(t, VerifyHistory(sesamDir, repo, Identities{}, NewNonInteractivePluginUI()))
}

// TestVerifyHistory_NoLogJsonl exercises the iter.Next() == io.EOF branch:
// the init file is committed (so verifyInitFileUnchangedWithRepo returns its
// hash) but log.jsonl was never committed at the current path, so the
// PathFilter yields zero commits and the iterator EOFs immediately.
//
// Reaching EOF without seeing the init commit is a *successful* termination,
// not an error: the same outcome happens legitimately when a user added after
// init can't decrypt older audit-key envelopes (NoIdentityMatchError stops the
// walk early). Both cases collapse to "stopped without finding tampering."
//
// On the underlying go-git contract: LogIter.Next() returns a bare io.EOF
// sentinel (not wrapped), so `err == io.EOF` works. `errors.Is(err, io.EOF)`
// would be more robust against future wrapping at zero cost.
func TestVerifyHistory_NoLogJsonl(t *testing.T) {
	sesamDir, repo := testGitRepo(t)

	// Commit just the init file. Its content doesn't matter for this test
	// because we never reach the chain-verification step.
	initPath := filepath.Join(sesamDir, ".sesam", "audit", "init")
	require.NoError(t, os.WriteFile(initPath, []byte("placeholder-init-hash\n"), 0o600))

	wt, err := repo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add(".")
	require.NoError(t, err)
	_, err = wt.Commit("init file only, no log.jsonl", &git.CommitOptions{
		Author: &object.Signature{Name: "T", Email: "t@t", When: time.Now()},
	})
	require.NoError(t, err)

	require.NoError(t, VerifyHistory(sesamDir, repo, Identities{}, NewNonInteractivePluginUI()))
}
