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

			reset, err := r.ConfigReset(ConfigResetOpts{})
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

	reset, err := r.ConfigReset(ConfigResetOpts{})
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
	_, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)

	applied, err := applyConfig(t, r)
	require.NoError(t, err)
	require.Empty(t, applied)

	require.NoError(t, r.Update(func(s *Stage) error {
		_, err := s.ConfigApply(context.Background(), ConfigApplyOpts{})
		return err
	}))
}

// TestConfigResetDryRun reports exactly what a real reset would do and writes
// nothing - checked by running the real reset afterwards and requiring the
// same answer.
func TestConfigResetDryRun(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	generated := readFileString(t, filepath.Join(dir, configFileName))
	writeMainConfig(t, dir, generated+
		"      - dev\n"+
		"  - path: invented.env\n")
	edited := readFileString(t, filepath.Join(dir, configFileName))

	dry, err := r.ConfigReset(ConfigResetOpts{DryRun: true})
	require.NoError(t, err)
	require.True(t, dry.DryRun)
	require.Equal(t, []core.Operation{
		core.OpSecretAdd,
		core.OpSecretChangeAccess,
	}, opsOf(dry.Discarded))

	// Nothing moved.
	require.Equal(t, edited, readFileString(t, filepath.Join(dir, configFileName)))

	// And the real run agrees with the rehearsal.
	real, err := r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.Equal(t, dry.Discarded, real.Discarded)
	require.NotEqual(t, edited, readFileString(t, filepath.Join(dir, configFileName)))
}

// TestConfigResetDryRunKeepsSubConfigs guards the reason a dry run works on a
// copy: reverting a declared secret empties its sub-file, and the config
// mutators delete such a file from disk.
func TestConfigResetDryRunKeepsSubConfigs(t *testing.T) {
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

	dry, err := r.ConfigReset(ConfigResetOpts{DryRun: true})
	require.NoError(t, err)
	require.Equal(t, []core.Operation{core.OpSecretAdd}, opsOf(dry.Discarded))

	// The sub-config is still there, with its content and its include.
	require.FileExists(t, sub)
	require.Contains(t, readFileString(t, sub), "token")
	require.Contains(t, readFileString(t, filepath.Join(dir, configFileName)), "include")

	// The real reset does remove it, which is what the dry run rehearsed.
	_, err = r.ConfigReset(ConfigResetOpts{})
	require.NoError(t, err)
	require.NoFileExists(t, sub)
}

// TestConfigResetDryRunRewrite covers the recovery path: a broken config is
// reported as unusable without a replacement being written.
func TestConfigResetDryRunRewrite(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	const broken = "{{{ not yaml\n"
	writeMainConfig(t, dir, broken)

	dry, err := r.ConfigReset(ConfigResetOpts{DryRun: true})
	require.NoError(t, err)
	require.True(t, dry.Rewritten)
	require.NotEmpty(t, dry.Reason)

	require.Equal(t, broken, readFileString(t, filepath.Join(dir, configFileName)))
}
