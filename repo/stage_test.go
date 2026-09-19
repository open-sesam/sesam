package repo

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// containsUser reports whether name is among the listed users.
func containsUser(users []UserInfo, name string) bool {
	for _, u := range users {
		if u.Name == name {
			return true
		}
	}
	return false
}

// hasUser is a small assertion helper: fetches the (staged or live) user list
// and reports whether name is present.
func hasUser(t *testing.T, lister interface {
	ListUsers() ([]UserInfo, error)
}, name string,
) bool {
	t.Helper()
	users, err := lister.ListUsers()
	require.NoError(t, err)
	return containsUser(users, name)
}

func TestStageCommitPersistsUser(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	require.False(t, hasUser(t, r, "bob"))

	// See-your-own-writes: ListUsers on the stage reflects the staged tell
	// before the commit lands.
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false); err != nil {
			return err
		}
		require.True(t, hasUser(t, s, "bob"))
		return nil
	}))

	// After commit the live Repo view reflects bob (promotion, no reload).
	require.True(t, hasUser(t, r, "bob"))

	// On disk: bob's signing key landed in the live tree and the fork is gone.
	require.True(t, fileExists(t, filepath.Join(dir, ".sesam", "signkeys", "bob.age")))
	require.False(t, fileExists(t, filepath.Join(dir, ".sesam-tmp")))
}

func TestStageCommitSurvivesReload(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	require.NoError(t, r.Update(func(s *Stage) error {
		return s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false)
	}))
	require.NoError(t, r.Close())

	r2 := reloadSesamRepo(t, dir, admin)
	require.True(t, hasUser(t, r2, "bob"))
}

func TestStageRollbackDiscards(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	s, err := r.Stage()
	require.NoError(t, err)
	require.NoError(t, s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false))
	require.True(t, hasUser(t, s, "bob"))

	require.NoError(t, s.Rollback())

	// Live view never saw bob; the fork is reaped.
	require.False(t, hasUser(t, r, "bob"))
	require.False(t, fileExists(t, filepath.Join(dir, ".sesam-tmp")))

	// Rollback is idempotent and a new stage can be opened afterwards.
	require.NoError(t, s.Rollback())
	s2, err := r.Stage()
	require.NoError(t, err)
	require.NoError(t, s2.Rollback())
}

// A failing Update must leave the live state byte-untouched and reap the fork.
// This is the atomicity guarantee that used to live inside Seal's seal-stage
// and now belongs to the stage layer.
func TestStageUpdateErrorLeavesLiveUntouched(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	sentinel := errors.New("boom")
	err := r.Update(func(s *Stage) error {
		// Mutate inside the fork, then fail: nothing should reach the live tree.
		if err := s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false); err != nil {
			return err
		}
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)

	require.False(t, hasUser(t, r, "bob"))
	require.False(t, fileExists(t, filepath.Join(dir, ".sesam", "signkeys", "bob.age")))
	require.False(t, fileExists(t, filepath.Join(dir, ".sesam-tmp")))
}

// sesam.yml is staged too: a rolled-back config edit must leave it untouched,
// and a committed one must land.
func TestStageConfigRollbackAndCommit(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	cfgPath := filepath.Join(dir, "sesam.yml")
	before, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NotContains(t, string(before), "bob")

	// Rolled-back tell: sesam.yml must be byte-identical afterwards.
	s, err := r.Stage()
	require.NoError(t, err)
	require.NoError(t, s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false))
	require.NoError(t, s.Rollback())

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "rolled-back config edit must not touch sesam.yml")

	// Committed tell: sesam.yml now records bob.
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false)
	}))
	committed, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.Contains(t, string(committed), "bob")
}

// A config-free mutation (a plain seal) must not load or rewrite sesam.yml:
// config is lazy-loaded only by config mutators, and Commit skips Save when it
// was never touched. renameio's Save would replace the inode, so SameFile
// staying true proves the file was left alone.
func TestStageSealOnlyLeavesConfigUntouched(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)
	cfgPath := filepath.Join(dir, "sesam.yml")

	before, err := os.Stat(cfgPath)
	require.NoError(t, err)

	require.NoError(t, r.Update(func(s *Stage) error { _, err := s.Seal(SealOpts{All: true}); return err }))

	after, err := os.Stat(cfgPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after),
		"a seal-only commit must not rewrite sesam.yml")
}

// Stages do not nest. Handing out the already-open stage made the second
// Commit finalize the first transaction: its half-finished work went live and
// the first Commit then failed with ErrStageFinalized.
func TestStageSingleInFlight(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	s1, err := r.Stage()
	require.NoError(t, err)

	_, err = r.Stage()
	require.ErrorIs(t, err, ErrStageOpen)

	// Finishing the first one frees the repo for the next.
	require.NoError(t, s1.Rollback())

	s2, err := r.Stage()
	require.NoError(t, err)
	require.NoError(t, s2.Rollback())
}

// The same through Update, which is how commands reach a stage: the inner
// Update fails and takes the outer one down with it, rather than committing
// the outer transaction behind its back.
func TestStageNestedUpdateAborts(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	_, r := bootstrapRepo(t, admin)

	err := r.Update(func(s *Stage) error {
		if err := s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}, false); err != nil {
			return err
		}

		return r.Update(func(*Stage) error { return nil })
	})
	require.ErrorIs(t, err, ErrStageOpen)

	// The outer transaction rolled back, so bob never reached the live view.
	require.False(t, hasUser(t, r, "bob"))
}

// An explicitly named forbidden path must be rejected by add rather than
// silently skipped, so the user learns their secret was never tracked.
func TestStageSecretAddRejectsForbiddenPath(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	cases := []string{
		"sesam.yml",
		".gitattributes",
		".gitignore",
		filepath.Join(".sesam", "audit", "log.jsonl"),
	}

	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			err := r.Update(func(s *Stage) error {
				return s.SecretAdd([]string{path}, []string{"admin"}, false, false)
			})
			require.Error(t, err, "add %q must fail", path)
		})
	}
}

// A move must not be able to route a secret onto a path add would refuse:
// otherwise a legal move can clobber sesam's own config or git filter routing.
// The forbidden destination is rejected and the source stays tracked.
func TestStageSecretMoveRejectsForbiddenDestination(t *testing.T) {
	cases := []string{
		"sesam.yml",
		".gitattributes",
		filepath.Join(".sesam", "stolen"),
	}

	for _, dest := range cases {
		t.Run(dest, func(t *testing.T) {
			admin := writeTestIdentity(t, "admin")
			dir, r := bootstrapRepo(t, admin)

			src := filepath.Join(dir, "secrets", "api.token")
			require.NoError(t, os.MkdirAll(filepath.Dir(src), 0o700))
			require.NoError(t, os.WriteFile(src, []byte("hunter2\n"), 0o600))
			require.NoError(t, r.Update(func(s *Stage) error {
				if err := s.SecretAdd([]string{"secrets/api.token"}, []string{"admin"}, false, false); err != nil {
					return err
				}
				_, err := s.Seal(SealOpts{})
				return err
			}))

			err := r.Update(func(s *Stage) error {
				return s.SecretMove("secrets/api.token", dest, false)
			})
			require.Error(t, err, "move to %q must fail", dest)

			// The rejected move must roll back cleanly: the source is still
			// tracked and no config file was clobbered.
			secrets, err := r.ListSecrets(nil)
			require.NoError(t, err)
			var paths []string
			for _, s := range secrets {
				paths = append(paths, s.RevealedPath)
			}
			require.Contains(t, paths, "secrets/api.token")
			require.NotContains(t, paths, dest)
		})
	}
}

// captureWarnings redirects slog to a buffer for the duration of the test.
func captureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return buf
}

// TestStageRollbackDoesNotNagAboutSeal: a rolled back stage never reached disk,
// so the seal its entries would have required is not the user's problem. The
// warning used to fire on every failed operation, ahead of the actual error.
func TestStageRollbackDoesNotNagAboutSeal(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	warnings := captureWarnings(t)

	err := r.Update(func(s *Stage) error {
		// A tell marks a seal as pending...
		if err := s.UserTell(
			context.Background(), "bob", []string{bob.Recipient}, []string{"dev"}, false,
		); err != nil {
			return err
		}

		// ...and then the operation fails, so none of it happened.
		return errors.New("boom")
	})
	require.ErrorContains(t, err, "boom")

	require.NoError(t, r.Close())
	require.NotContains(t, warnings.String(), "seal is pending")

	// And nothing was left behind to seal in the first place.
	reopened := reloadSesamRepo(t, dir, admin)
	_, exists := reopened.vstate.UserExists("bob")
	require.False(t, exists)
}

// TestStageCommitWithoutSealNagsOnce: the warning is still what it was meant to
// be - advice about the repository the user is about to commit - and it is
// given once, not once per discarded state.
func TestStageCommitWithoutSealNagsOnce(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	_, r := bootstrapRepo(t, admin)

	warnings := captureWarnings(t)

	require.NoError(t, r.Update(func(s *Stage) error {
		// Deliberately no seal, the way --no-seal leaves it.
		return s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"dev"}, false)
	}))

	require.NoError(t, r.Close())
	require.Equal(t, 1, strings.Count(warnings.String(), "seal is pending"), warnings.String())
}
