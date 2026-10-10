package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

// TestConfigResetInSync: a config that already describes the audit log is left
// exactly as it is, comments and all.
func TestConfigResetInSync(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	before := readFileString(t, filepath.Join(dir, configFileName))

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.Empty(t, reset.Discarded)
	require.False(t, reset.Rewritten)

	require.Equal(t, before, readFileString(t, filepath.Join(dir, configFileName)))
}

// TestConfigResetDiscardsEdits is the everyday case: hand edits go away, and
// everything the audit log does not know about the file survives. No Force
// needed - a repair in place only discards what was never in the audit log to
// begin with.
func TestConfigResetDiscardsEdits(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// Take the generated config, with its comments, and edit it: a user the
	// log never heard of, and a wider access list for README.md.
	generated := readFileString(t, filepath.Join(dir, configFileName))
	writeMainConfig(t, dir, generated+
		"      - dev\n"+
		"  - path: invented.env\n")

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.False(t, reset.Rewritten)
	require.Equal(t, []core.Operation{
		core.OpSecretAdd,
		core.OpSecretChangeAccess,
	}, opsOf(reset.Discarded))

	after := readFileString(t, filepath.Join(dir, configFileName))
	require.NotContains(t, after, "invented.env")
	require.NotContains(t, after, "- dev")
	require.Contains(t, after, "# Key is the public key of this user")

	// And it converges: resetting again has nothing left to do.
	reset, err = r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.Empty(t, reset.Discarded)
}

// TestConfigResetRepairIgnoresForce pins the line Force actually draws: it
// gates a full rewrite, not a repair in place. Two separately edited repos,
// one reset without Force and one with, must end up identical.
func TestConfigResetRepairIgnoresForce(t *testing.T) {
	admin := writeTestIdentity(t, "admin")

	edit := func(dir string) {
		generated := readFileString(t, filepath.Join(dir, configFileName))
		writeMainConfig(t, dir, generated+
			"      - dev\n"+
			"  - path: invented.env\n")
	}

	dirA, rA := bootstrapRepo(t, admin)
	edit(dirA)
	withoutForce, err := rA.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)

	dirB, rB := bootstrapRepo(t, admin)
	edit(dirB)
	withForce, err := rB.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)

	require.Equal(t, withoutForce.Discarded, withForce.Discarded)
	require.Equal(t,
		readFileString(t, filepath.Join(dirA, configFileName)),
		readFileString(t, filepath.Join(dirB, configFileName)),
	)
}

// TestConfigResetUnappliableConfig covers the state reset exists for: an edit
// that left a config no apply would touch. It must still be repairable, and
// the file's comments should survive that repair.
func TestConfigResetUnappliableConfig(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// No admin group at all - diff.Compute refuses this outright.
	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    # a comment worth keeping\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"groups:\n"+
		"  dev:\n"+
		"    - admin\n"+
		"secrets:\n"+
		"  - path: README.md\n")

	_, err := r.ConfigDiff(ConfigDiffOpts{})
	require.ErrorContains(t, err, "declares no admin user", "precondition: this config is unappliable")

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.False(t, reset.Rewritten, "a readable file is repaired, not replaced")
	require.Equal(t, []core.Operation{core.OpUserChangeGroups}, opsOf(reset.Discarded))

	after := readFileString(t, filepath.Join(dir, configFileName))
	require.Contains(t, after, "# a comment worth keeping")
	require.Contains(t, after, "admin")

	// The repaired file is appliable again.
	_, err = r.ConfigDiff(ConfigDiffOpts{})
	require.NoError(t, err)
}

// TestConfigResetRepairsStrayGroupMemberLeftByAnEdit regresses a typo-sized
// edit forcing a full rewrite: removing a user from users: without also
// removing them from the groups: list they were in makes the file fail
// Config.Validate()'s UnknownGroupMemberError before reset ever gets a chance
// to see that reverting the implied kill - reintroducing the user - resolves
// the very reference Validate() would otherwise complain about.
func TestConfigResetRepairsStrayGroupMemberLeftByAnEdit(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	// Register bob for real, so he exists in the verified state.
	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n    key:\n      - "+admin.Recipient+"\n"+
		"  - name: bob\n    key:\n      - "+bob.Recipient+"\n"+
		"groups:\n  admin:\n    - admin\n  dev:\n    - bob\n"+
		"secrets:\n  - path: README.md\n")
	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(applied))

	// Hand-edit: remove bob from users:, but forget to also remove him from
	// dev's member list - a very ordinary incomplete edit.
	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    # a comment worth keeping\n"+
		"    key:\n      - "+admin.Recipient+"\n"+
		"groups:\n  admin:\n    - admin\n  dev:\n    - bob\n"+
		"secrets:\n  - path: README.md\n")

	// Precondition: the file as it stands does not even load.
	_, err = r.ConfigDiff(ConfigDiffOpts{})
	require.ErrorContains(t, err, `lists unknown user "bob"`)

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.False(t, reset.Rewritten, "a stray reference revert resolves must be repaired, not rewritten")
	require.Equal(t, []core.Operation{core.OpUserKill}, opsOf(reset.Discarded))

	after := readFileString(t, filepath.Join(dir, configFileName))
	require.Contains(t, after, "# a comment worth keeping")
	require.Contains(t, after, "bob")

	// The repaired file loads and is internally consistent again.
	_, err = r.ConfigDiff(ConfigDiffOpts{})
	require.NoError(t, err)
}

// TestConfigResetRepairsAfterGroupsKeyRemoved regresses a missing groups: key
// making repair-in-place hard-fail instead of falling back: UserChangeGroups
// now builds the whole groups: mapping fresh when none exists, mirroring how
// UserTell's addGroupMember already handled the same gap for a brand new
// user.
func TestConfigResetRepairsAfterGroupsKeyRemoved(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// Drop the whole groups: block - an extreme edit, but one repair must
	// survive rather than crash on.
	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    # a comment worth keeping\n"+
		"    key:\n      - "+admin.Recipient+"\n"+
		"secrets:\n  - path: README.md\n")

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.False(t, reset.Rewritten, "a missing groups: key should be repaired in place, not force a full rewrite")
	require.Equal(t, []core.Operation{core.OpUserChangeGroups}, opsOf(reset.Discarded))

	after := readFileString(t, filepath.Join(dir, configFileName))
	require.Contains(t, after, "# a comment worth keeping")
	require.Contains(t, after, "groups:")

	_, err = r.ConfigDiff(ConfigDiffOpts{})
	require.NoError(t, err)
}

// TestConfigResetFallsBackOnDanglingAlias covers the other named failure mode
// for the repair path: an alias-valued group member. A *reference to a user
// still in users: repairs (or simply survives) fine - the real failure case
// is killing the user an alias elsewhere points to, which leaves that alias
// dangling. There is no way to repair that in place (the anchor it needs is
// simply gone); unlike a missing groups: key, this is not something
// LoadForRepair's relaxed Validate() can help with either, since the document
// fails to parse at all, before any Config exists to repair. Already handled
// correctly before this change too - resetConfig's very first fallback (a
// failed Load) already covered it - this just pins the behavior now that
// Load has become LoadForRepair.
func TestConfigResetFallsBackOnDanglingAlias(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n    key:\n      - "+admin.Recipient+"\n"+
		"  - name: &bobname bob\n    key:\n      - "+bob.Recipient+"\n"+
		"groups:\n  admin:\n    - admin\n  dev:\n    - *bobname\n"+
		"secrets:\n  - path: README.md\n")
	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpUserTell}, opsOf(applied))

	// Remove bob - anchor and all - leaving dev's *bobname alias dangling.
	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n    key:\n      - "+admin.Recipient+"\n"+
		"groups:\n  admin:\n    - admin\n  dev:\n    - *bobname\n"+
		"secrets:\n  - path: README.md\n")

	reset, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err, "a dangling alias must fall back to a rewrite, not fail the reset")
	require.True(t, reset.Rewritten, "nothing can repair a dangling alias in place")

	_, err = r.ConfigDiff(ConfigDiffOpts{})
	require.NoError(t, err, "the rewritten file must be valid and appliable")
}

// TestConfigResetRewritesUnreadable covers the other half of recovery: a file
// that cannot be read at all is replaced by one derived from the audit log.
func TestConfigResetRewritesUnreadable(t *testing.T) {
	tests := []struct {
		name string
		set  func(t *testing.T, dir string)
	}{
		{
			name: "not yaml at all",
			set: func(t *testing.T, dir string) {
				writeMainConfig(t, dir, "{{{ this is not yaml\n")
			},
		},
		{
			name: "missing",
			set: func(t *testing.T, dir string) {
				require.NoError(t, os.Remove(filepath.Join(dir, configFileName)))
			},
		},
		{
			name: "group lists an unknown user",
			set: func(t *testing.T, dir string) {
				writeMainConfig(t, dir, "users: []\ngroups:\n  admin:\n    - ghost\nsecrets: []\n")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			admin := writeTestIdentity(t, "admin")
			bob := writeTestIdentity(t, "bob")
			dir, r := bootstrapRepo(t, admin)
			tellUser(t, r, bob, "dev")

			tc.set(t, dir)

			reset, err := r.ConfigReset(ConfigResetOpts{Force: true})
			require.NoError(t, err)
			require.True(t, reset.Rewritten)
			require.NotEmpty(t, reset.Reason)

			// The rewritten file describes the audit log exactly.
			diff, err := r.ConfigDiff(ConfigDiffOpts{})
			require.NoError(t, err)
			require.True(t, diff.IsEmpty(), diff.String())

			after := readFileString(t, filepath.Join(dir, configFileName))
			require.Contains(t, after, "admin")
			require.Contains(t, after, "bob")
			require.Contains(t, after, admin.Recipient)
			require.Contains(t, after, "README.md")
		})
	}
}

// TestConfigResetRewritesUnreadableWithNoSecrets covers rebuildConfig's other
// edge: a verified state with no secrets at all must still get a `secrets:`
// key, since SecretAdd is never called to create one. Without it the
// rewritten file cannot be loaded again by anything, reset included.
func TestConfigResetRewritesUnreadableWithNoSecrets(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// Drop the only secret bootstrapRepo declares, so the verified state (and
	// therefore the rebuilt config) has none.
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.SecretRemove([]string{"README.md"})
	}))

	writeMainConfig(t, dir, "{{{ this is not yaml\n")

	reset, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)
	require.True(t, reset.Rewritten)

	after := readFileString(t, filepath.Join(dir, configFileName))
	require.Contains(t, after, "secrets:")

	// The rewritten file must still be loadable - this is what a missing
	// secrets: key would break, for reset itself and every other command.
	_, err = r.ConfigDiff(ConfigDiffOpts{})
	require.NoError(t, err)
}

// TestConfigResetReportsOrphans: a rewrite flattens the include tree into the
// main file, so a sub-config that used to be included is left unreferenced.
// Reset does not delete the user's file, but it has to say so - nothing reads
// it any more.
func TestConfigResetReportsOrphans(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "svc"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "svc", "token"), []byte("tok"), 0o600))
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.SecretAdd([]string{"svc/token"}, []string{"admin"}, false, true)
	}))

	sub := filepath.Join(dir, "svc", configFileName)
	require.FileExists(t, sub)

	// Destroy the main file so reset has to rewrite rather than repair.
	writeMainConfig(t, dir, "not a config\n")

	reset, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)
	require.True(t, reset.Rewritten)
	require.Equal(t, []string{filepath.Join("svc", configFileName)}, reset.Orphaned)

	// Left on disk, but no longer part of the config.
	require.FileExists(t, sub)

	after := readFileString(t, filepath.Join(dir, configFileName))
	require.Contains(t, after, "svc/token", "the secret itself is kept, in the main file")
	require.NotContains(t, after, "include")
}

// TestConfigResetKeepsAuditLog: reset only ever writes the config.
func TestConfigResetKeepsAuditLog(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	before := entryCount(t, r)
	writeMainConfig(t, dir, "users: []\ngroups: {}\nsecrets: []\n")

	_, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)

	require.Equal(t, before, entryCount(t, r))
	_, exists := r.vstate.SecretExists("README.md")
	require.True(t, exists)
}

// TestConfigResetAfterApplyRoundTrip: reset and apply are inverses of each
// other, so a reset config applies as a no-op.
func TestConfigResetAfterApplyRoundTrip(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)
	tellUser(t, r, bob, "dev")

	writeMainConfig(t, dir, "users: []\ngroups: {}\nsecrets: []\n")
	_, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Empty(t, applied)

	require.NoError(t, r.Update(func(s *Stage) error {
		_, err := s.ConfigApply(context.Background(), ConfigApplyOpts{})
		return err
	}))
}

// TestConfigResetDeletesEmptiedSubConfig: reverting a declared secret empties
// its sub-file, and the config mutators delete such a file from disk outright
// - a repair in place does this unprompted, like the rest of the discard, but
// it must still say so. Deleting a file with no trace at all is not
// acceptable just because a rewrite was not involved (unlike Orphaned, this
// one already happened by the time it is reported).
func TestConfigResetDeletesEmptiedSubConfig(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// A hand-written sub-config with one secret the audit log never saw.
	subDir := filepath.Join(dir, "svc")
	require.NoError(t, os.MkdirAll(subDir, 0o700))
	sub := filepath.Join(subDir, configFileName)
	require.NoError(t, os.WriteFile(sub, []byte(
		"secrets:\n  - path: token\n    access:\n      - admin\n",
	), 0o644))

	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"secrets:\n"+
		"  - path: README.md\n"+
		"  - include: svc/sesam.yml\n")

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpSecretAdd}, opsOf(reset.Discarded))
	require.Equal(t, []string{filepath.Join("svc", configFileName)}, reset.Deleted)

	// Gone, along with its include.
	require.NoFileExists(t, sub)
	require.NotContains(t, readFileString(t, filepath.Join(dir, configFileName)), "include")
}

// TestConfigResetPreviewThenForceRewrite covers the recovery path end to end:
// without Force, a broken config is reported as needing a full rewrite
// without one being written; Force is what actually replaces it, and the
// result then converges with the audit log.
func TestConfigResetPreviewThenForceRewrite(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	const broken = "{{{ not yaml\n"
	writeMainConfig(t, dir, broken)

	preview, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err, "a normal run reports the rewrite rather than failing")
	require.True(t, preview.Rewritten)
	require.NotEmpty(t, preview.Reason)
	require.Equal(t, broken, readFileString(t, filepath.Join(dir, configFileName)))

	forced, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)
	require.True(t, forced.Rewritten)
	require.NotEqual(t, broken, readFileString(t, filepath.Join(dir, configFileName)))

	diff, err := r.ConfigDiff(ConfigDiffOpts{})
	require.NoError(t, err)
	require.True(t, diff.IsEmpty(), diff.String())
}

// TestConfigResetNeverErrorsWithoutForce: whether the fix would be a repair in
// place or a full rewrite, a normal run never fails just because Force was
// not given - it applies the repair directly, or reports the rewrite it would
// need without writing it.
func TestConfigResetNeverErrorsWithoutForce(t *testing.T) {
	t.Run("repairable", func(t *testing.T) {
		admin := writeTestIdentity(t, "admin")
		dir, r := bootstrapRepo(t, admin)

		generated := readFileString(t, filepath.Join(dir, configFileName))
		writeMainConfig(t, dir, generated+"  - path: invented.env\n")
		edited := readFileString(t, filepath.Join(dir, configFileName))

		reset, err := r.ConfigReset(ConfigResetOpts{})
		require.NoError(t, err)
		require.False(t, reset.Rewritten)
		require.NotEmpty(t, reset.Discarded)
		require.NotEqual(t, edited, readFileString(t, filepath.Join(dir, configFileName)))
	})

	t.Run("unreadable", func(t *testing.T) {
		admin := writeTestIdentity(t, "admin")
		dir, r := bootstrapRepo(t, admin)

		const broken = "{{{ not yaml\n"
		writeMainConfig(t, dir, broken)

		reset, err := r.ConfigReset(ConfigResetOpts{})
		require.NoError(t, err)
		require.True(t, reset.Rewritten)
		require.Equal(t, broken, readFileString(t, filepath.Join(dir, configFileName)))
	})
}

// TestConfigPathsSkipsNestedGitAndSesamDirs regresses configPaths comparing
// whole relative walk paths to the bare ".git"/".sesam" constants: a nested
// one (a submodule, or a sesam repo checked out under this one) sits at some
// deeper relative path and was never skipped, so a coincidentally-named file
// inside it could be picked up as one of ours.
func TestConfigPathsSkipsNestedGitAndSesamDirs(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// A legitimate sub-config, which must still be found.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "svc"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "svc", configFileName), []byte("secrets: []\n"), 0o644,
	))

	// A nested .git (e.g. a submodule) with something that looks like a config
	// file inside it - must never be treated as one of ours.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "svc", ".git", "hooks"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "svc", ".git", "hooks", configFileName), []byte("bogus"), 0o644,
	))

	// A nested .sesam (a sesam repo checked out under this one) likewise.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "nested", ".sesam"), 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(dir, "nested", ".sesam", configFileName), []byte("bogus"), 0o644,
	))

	paths, err := r.configPaths()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{configFileName, filepath.Join("svc", configFileName)}, paths)
}
