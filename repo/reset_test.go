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
// everything the audit log does not know about the file survives.
func TestConfigResetDiscardsEdits(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// Take the generated config, with its comments, and edit it: a user the
	// log never heard of, and a wider access list for README.md.
	generated := readFileString(t, filepath.Join(dir, configFileName))
	writeMainConfig(t, dir, generated+
		"      - dev\n"+
		"  - path: invented.env\n")

	reset, err := r.ConfigReset(ConfigResetOpts{Force: true})
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
	reset, err = r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)
	require.Empty(t, reset.Discarded)
}

// TestConfigResetPreviewMatchesForce covers the pairing the whole preview
// mechanism exists for: without Force, ConfigReset reports exactly what a
// forced run would do and writes nothing - checked by running the forced
// reset afterwards and requiring the same answer.
func TestConfigResetPreviewMatchesForce(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	generated := readFileString(t, filepath.Join(dir, configFileName))
	writeMainConfig(t, dir, generated+
		"      - dev\n"+
		"  - path: invented.env\n")
	edited := readFileString(t, filepath.Join(dir, configFileName))

	preview, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.Equal(t, []core.Operation{
		core.OpSecretAdd,
		core.OpSecretChangeAccess,
	}, opsOf(preview.Discarded))

	// Nothing moved.
	require.Equal(t, edited, readFileString(t, filepath.Join(dir, configFileName)))

	// And the forced run agrees with the preview.
	forced, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)
	require.Equal(t, preview.Discarded, forced.Discarded)
	require.NotEqual(t, edited, readFileString(t, filepath.Join(dir, configFileName)))
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

	reset, err := r.ConfigReset(ConfigResetOpts{Force: true})
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

// TestConfigResetPreviewKeepsSubConfigs guards the reason the preview works on
// a copy: reverting a declared secret empties its sub-file, and the config
// mutators delete such a file from disk. Both runs must say so - deleting a
// file with no trace at all is not acceptable just because a rewrite was not
// involved (unlike Orphaned, this one already happened by the time it is
// reported).
func TestConfigResetPreviewKeepsSubConfigs(t *testing.T) {
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

	preview, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpSecretAdd}, opsOf(preview.Discarded))
	require.Equal(t, []string{filepath.Join("svc", configFileName)}, preview.Deleted,
		"a preview must also report what a forced run would delete")

	// The sub-config is still there, with its content and its include.
	require.FileExists(t, sub)
	require.Contains(t, readFileString(t, sub), "token")
	require.Contains(t, readFileString(t, filepath.Join(dir, configFileName)), "include")

	// The forced reset does remove it, which is what the preview rehearsed -
	// and it must say so too.
	forced, err := r.ConfigReset(ConfigResetOpts{Force: true})
	require.NoError(t, err)
	require.NoFileExists(t, sub)
	require.Equal(t, []string{filepath.Join("svc", configFileName)}, forced.Deleted)
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
// place or a full rewrite, a normal run only ever reports it - it never fails
// just because Force was not given, and it never touches the file either.
func TestConfigResetNeverErrorsWithoutForce(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	generated := readFileString(t, filepath.Join(dir, configFileName))
	writeMainConfig(t, dir, generated+"  - path: invented.env\n")
	edited := readFileString(t, filepath.Join(dir, configFileName))

	reset, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.False(t, reset.Rewritten)
	require.NotEmpty(t, reset.Discarded)
	require.Equal(t, edited, readFileString(t, filepath.Join(dir, configFileName)))
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
