package repo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
		if err := s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}); err != nil {
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
		return s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"})
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
	require.NoError(t, s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}))
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
		if err := s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}); err != nil {
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
	require.NoError(t, s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"}))
	require.NoError(t, s.Rollback())

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "rolled-back config edit must not touch sesam.yml")

	// Committed tell: sesam.yml now records bob.
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.UserTell(context.Background(), "bob", []string{bob.Recipient}, []string{"admin"})
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

	require.NoError(t, r.Update(func(s *Stage) error { return s.Seal(true) }))

	after, err := os.Stat(cfgPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(before, after),
		"a seal-only commit must not rewrite sesam.yml")
}

func TestStageSingleInFlight(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	s1, err := r.Stage()
	require.NoError(t, err)

	s2, err := r.Stage()
	require.NoError(t, err)

	require.Equal(t, s1, s2)
}
