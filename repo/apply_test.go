package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/diff"
)

// applyConfig runs a full apply the way the CLI does: plan and seal in one
// stage, committed together.
func applyConfig(t *testing.T, r *Repo) ([]diff.Change, error) {
	t.Helper()

	var applied []diff.Change
	err := r.Update(func(s *Stage) error {
		changes, err := s.ConfigApply(context.Background(), ConfigApplyOpts{})
		if err != nil {
			return err
		}
		applied = changes

		if len(applied) == 0 {
			return nil
		}
		return s.Seal(false)
	})

	return applied, err
}

// entryCount is how many entries the audit log holds - the measure of whether
// a failed apply left anything behind.
func entryCount(t *testing.T, r *Repo) int {
	t.Helper()

	count := 0
	require.NoError(t, r.Log(func(*core.AuditEntrySigned) error {
		count++
		return nil
	}))

	return count
}

// tellUser records a second user, so tests have someone to change or remove.
func tellUser(t *testing.T, r *Repo, id *testIdentity, groups ...string) {
	t.Helper()
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.UserTell(context.Background(), id.Name, []string{id.Recipient}, groups, false)
	}))
}

// TestConfigApply walks the whole vocabulary in one go: a hand-edited config
// that tells a user, changes groups, adds and removes a secret and narrows an
// access list must land in the audit log exactly as declared.
func TestConfigApply(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	carol := writeTestIdentity(t, "carol")

	dir, r := bootstrapRepo(t, admin)
	tellUser(t, r, bob, "dev")
	tellUser(t, r, carol, "dev")

	// A secret to add needs its plaintext on disk.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "db.env"), []byte("pw=1"), 0o600))

	// README starts out admin-only; widen it so the config below narrowing it
	// back is a change and not a no-op.
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.SecretAdd([]string{"README.md"}, []string{"dev"}, false, false)
	}))

	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"  - name: bob\n"+
		"    key:\n"+
		"      - "+bob.Recipient+"\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"  ops:\n"+ // bob moves from dev to ops, carol is gone entirely
		"    - bob\n"+
		"secrets:\n"+
		"  - path: README.md\n"+ // access narrowed to admin-only
		"  - path: db.env\n"+
		"    access:\n"+
		"      - ops\n")

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{
		core.OpUserChangeGroups,   // bob: dev -> ops
		core.OpSecretAdd,          // db.env
		core.OpSecretChangeAccess, // README.md -> admin only
		core.OpUserKill,           // carol
	}, opsOf(applied))

	bobUser, exists := r.vstate.UserExists("bob")
	require.True(t, exists)
	require.Equal(t, []string{"ops"}, bobUser.Groups)

	_, exists = r.vstate.UserExists("carol")
	require.False(t, exists)

	dbEnv, exists := r.vstate.SecretExists("db.env")
	require.True(t, exists)
	require.Equal(t, []string{"ops"}, dbEnv.DeclaredGroups())

	readme, exists := r.vstate.SecretExists("README.md")
	require.True(t, exists)
	require.Empty(t, readme.DeclaredGroups())

	// Applying again has nothing left to do - the plan really closed the gap.
	applied, err = applyConfig(t, r)
	require.NoError(t, err)
	require.Empty(t, applied)
}

// TestConfigApplyTellsUser covers the one step that does more than write an
// entry: a new user also needs a signing key and a re-encrypted audit key.
func TestConfigApplyTellsUser(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"  - name: bob\n"+
		"    key:\n"+
		"      - "+bob.Recipient+"\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"  dev:\n"+
		"    - bob\n"+
		"secrets:\n"+
		"  - path: README.md\n"+
		"    access:\n"+
		"      - dev\n")

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpUserTell, core.OpSecretChangeAccess}, opsOf(applied))

	bobUser, exists := r.vstate.UserExists("bob")
	require.True(t, exists)
	require.Equal(t, []string{"dev"}, bobUser.Groups)
	require.Equal(t, []string{bob.Recipient}, bobUser.Recps.Strings())

	// The signing key was generated in the fork and survived the commit.
	require.FileExists(t, filepath.Join(dir, ".sesam", "signkeys", "bob.age"))

	// bob can read what he was given access to.
	require.NoError(t, r.Close())
	bobRepo := reloadSesamRepo(t, dir, bob)
	require.NoError(t, bobRepo.RevealAll())
}

// TestConfigApplyLeavesConfigAlone is the point of bypassing the Stage
// mutators: apply reads sesam.yml, it never writes it back.
func TestConfigApplyLeavesConfigAlone(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// The generated config, with all its comments, plus one edit.
	declared := readFileString(t, filepath.Join(dir, configFileName)) + "      - dev\n"
	writeMainConfig(t, dir, declared)

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpSecretChangeAccess}, opsOf(applied))

	require.Equal(t, declared, readFileString(t, filepath.Join(dir, configFileName)))
}

// TestConfigApplyRollsBack is the transaction: a plan that fails part-way must
// leave the repository exactly as it was, with the reason surfaced.
func TestConfigApplyRollsBack(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	before := entryCount(t, r)

	// bob is told first (step 0 of the plan, succeeds), then a secret whose
	// plaintext does not exist is added (step 1, fails).
	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"  - name: bob\n"+
		"    key:\n"+
		"      - "+bob.Recipient+"\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"  dev:\n"+
		"    - bob\n"+
		"secrets:\n"+
		"  - path: README.md\n"+
		"  - path: missing.env\n"+
		"    access:\n"+
		"      - dev\n")

	_, err := applyConfig(t, r)

	// The error names the step and the reason.
	require.ErrorContains(t, err, "secret missing.env")
	require.ErrorContains(t, err, "missing.env")

	// Nothing was applied: no entries, no user, no signing key, no fork.
	require.Equal(t, before, entryCount(t, r))
	_, exists := r.vstate.UserExists("bob")
	require.False(t, exists)
	require.NoFileExists(t, filepath.Join(dir, ".sesam", "signkeys", "bob.age"))
	require.NoDirExists(t, filepath.Join(dir, ".sesam-tmp"))
}

// TestConfigApplyPreflight rejects plans that would strand the repository or
// the person applying them, before anything is written.
func TestConfigApplyPreflight(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")

	tests := []struct {
		name    string
		config  func(admin, bob *testIdentity) string
		applyAs *testIdentity
		want    string
	}{
		{
			name:    "applying admin is killed",
			applyAs: admin,
			config: func(admin, bob *testIdentity) string {
				return "users:\n" +
					"  - name: bob\n    key:\n      - " + bob.Recipient + "\n" +
					"groups:\n  admin:\n    - bob\n" +
					"secrets:\n  - path: README.md\n"
			},
			want: "who is applying it",
		},
		{
			name:    "applying admin is demoted",
			applyAs: admin,
			config: func(admin, bob *testIdentity) string {
				return "users:\n" +
					"  - name: admin\n    key:\n      - " + admin.Recipient + "\n" +
					"  - name: bob\n    key:\n      - " + bob.Recipient + "\n" +
					"groups:\n  admin:\n    - bob\n  dev:\n    - admin\n" +
					"secrets:\n  - path: README.md\n"
			},
			want: "takes admin from admin",
		},
		{
			name:    "applied by a non-admin",
			applyAs: bob,
			config: func(admin, bob *testIdentity) string {
				return "users:\n" +
					"  - name: admin\n    key:\n      - " + admin.Recipient + "\n" +
					"  - name: bob\n    key:\n      - " + bob.Recipient + "\n" +
					"groups:\n  admin:\n    - admin\n  dev:\n    - bob\n" +
					"secrets:\n  - path: README.md\n    access:\n      - dev\n"
			},
			want: "needs admin rights",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, r := bootstrapRepo(t, admin)
			tellUser(t, r, bob, "dev")
			writeMainConfig(t, dir, tc.config(admin, bob))

			before := entryCount(t, r)

			applyAs := r
			if tc.applyAs != admin {
				require.NoError(t, r.Close())
				applyAs = reloadSesamRepo(t, dir, tc.applyAs)
			}

			_, err := applyConfig(t, applyAs)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, before, entryCount(t, applyAs))
		})
	}
}

// declareBob is a config that adds bob to the repository - the shape of the
// change an attacker would like an admin to apply for them.
func declareBob(admin, bob *testIdentity) string {
	return "users:\n" +
		"  - name: admin\n    key:\n      - " + admin.Recipient + "\n" +
		"  - name: bob\n    key:\n      - " + bob.Recipient + "\n" +
		"groups:\n  admin:\n    - admin\n  dev:\n    - bob\n" +
		"secrets:\n  - path: README.md\n"
}

// TestConfigApplyRefusesCommittedChanges is the "invalid modified config" rule
// from the design document: a declaration that arrived with a commit was not
// written by the person running apply, so it is refused. Someone who pushes a
// config making themselves an admin must not be able to get it applied by
// asking an admin to "just run sesam apply".
func TestConfigApplyRefusesCommittedChanges(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	gitCommitAll(t, dir, "init sesam")

	// The change arrives committed, the way a pushed branch would deliver it.
	writeMainConfig(t, dir, declareBob(admin, bob))
	gitCommitAll(t, dir, "add bob")

	before := entryCount(t, r)

	_, err := applyConfig(t, r)
	require.ErrorContains(t, err, "already committed")
	require.ErrorContains(t, err, "user bob", "the refused step is named")
	require.ErrorContains(t, err, "--force")

	var committedErr *CommittedChangesError
	require.ErrorAs(t, err, &committedErr)
	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(committedErr.Changes))

	require.Equal(t, before, entryCount(t, r))
	_, exists := r.vstate.UserExists("bob")
	require.False(t, exists)
}

// TestConfigApplyForceAppliesCommittedChanges: the rule is a guard rail, not a
// wall - a reviewed declaration can still be applied.
func TestConfigApplyForceAppliesCommittedChanges(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	gitCommitAll(t, dir, "init sesam")
	writeMainConfig(t, dir, declareBob(admin, bob))
	gitCommitAll(t, dir, "add bob")

	var applied []diff.Change
	require.NoError(t, r.Update(func(s *Stage) error {
		changes, err := s.ConfigApply(context.Background(), ConfigApplyOpts{Force: true})
		applied = changes
		return err
	}))

	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(applied))
	_, exists := r.vstate.UserExists("bob")
	require.True(t, exists)
}

// TestConfigApplyAllowsWorkingTreeChanges: the everyday case - the edit is in
// front of the user, uncommitted, so it applies.
func TestConfigApplyAllowsWorkingTreeChanges(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	gitCommitAll(t, dir, "init sesam")

	// Edited, not committed.
	writeMainConfig(t, dir, declareBob(admin, bob))

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(applied))
}

// TestConfigApplyRefusesCommittedAmongLocalChanges: a local edit elsewhere
// must not smuggle a committed change through with it.
func TestConfigApplyRefusesCommittedAmongLocalChanges(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	gitCommitAll(t, dir, "init sesam")
	writeMainConfig(t, dir, declareBob(admin, bob))
	gitCommitAll(t, dir, "add bob")

	// On top of the committed change, an innocent local edit.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "db.env"), []byte("pw=1"), 0o600))
	writeMainConfig(t, dir, declareBob(admin, bob)+"  - path: db.env\n")

	_, err := applyConfig(t, r)
	require.ErrorContains(t, err, "already committed")

	var committedErr *CommittedChangesError
	require.ErrorAs(t, err, &committedErr)
	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(committedErr.Changes),
		"only the committed step is refused, the local one is not listed")
}

// TestConfigApplyWithoutCommits: before the first commit nothing can have
// arrived committed, so the rule stays out of the way.
func TestConfigApplyWithoutCommits(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	writeMainConfig(t, dir, declareBob(admin, bob))

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(applied))
}
