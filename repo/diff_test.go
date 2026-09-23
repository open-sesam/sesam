package repo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/diff"
)

// writeMainConfig replaces the repository's sesam.yml with body.
func writeMainConfig(t *testing.T, dir, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, configFileName), []byte(body), 0o644))
}

// readDiffFile reads one file out of a written diff dir.
func readDiffFile(t *testing.T, diffDir, tree, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(diffDir, tree, path))
	require.NoError(t, err)
	return string(data)
}

// TestConfigDiffInSync checks that the config sesam writes itself never drifts
// from the audit log it wrote alongside it - and that a diff dir is not even
// created when there is nothing to show.
func TestConfigDiffInSync(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	changes, err := r.ConfigDiff(ConfigDiffOpts{WriteDiffDir: true})
	require.NoError(t, err)
	require.True(t, changes.IsEmpty())
	require.Empty(t, changes.DiffDir)
}

// TestConfigDiffHandEdited checks the path a user actually takes: edit
// sesam.yml, ask what it would change. The audit log must stay untouched.
func TestConfigDiffHandEdited(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"  - name: bob\n"+
		"    key:\n"+
		"      - github:bob\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"  dev:\n"+
		"    - bob\n"+
		"secrets:\n"+
		"  - path: db.env\n"+
		"    access:\n"+
		"      - dev\n")

	changes, err := r.ConfigDiff(ConfigDiffOpts{WriteDiffDir: true})
	require.NoError(t, err)

	ops := make([]core.Operation, 0, len(changes.Changes))
	for _, c := range changes.Changes {
		ops = append(ops, c.Op)
	}
	require.Equal(t, []core.Operation{
		core.OpUserTell,     // bob
		core.OpSecretAdd,    // db.env
		core.OpSecretRemove, // README.md, which the declaration dropped
	}, ops)

	// The declared side is the file as written, the verified side the same
	// file with those changes backed out.
	t.Cleanup(func() { _ = os.RemoveAll(changes.DiffDir) })

	declared := readDiffFile(t, changes.DiffDir, DeclaredTreeDir, configFileName)
	require.Contains(t, declared, "bob")
	require.Contains(t, declared, "db.env")
	require.NotContains(t, declared, "README.md")

	verified := readDiffFile(t, changes.DiffDir, VerifiedTreeDir, configFileName)
	require.NotContains(t, verified, "bob")
	require.NotContains(t, verified, "db.env")
	require.Contains(t, verified, "README.md")
	require.Contains(t, verified, admin.Recipient)

	// Reporting only: the audit log still has neither bob nor db.env.
	_, exists := r.vstate.UserExists("bob")
	require.False(t, exists)
	_, exists = r.vstate.SecretExists("db.env")
	require.False(t, exists)
}

// TestConfigDiffKeepsComments is the reason both sides are rendered by the same
// writer: a diff that reprints the whole file would bury the one line that
// actually changed.
func TestConfigDiffKeepsComments(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// The minimal realistic edit: take the config `sesam init` generated, with
	// all its comments, and widen README.md's access list by one group.
	generated := readFileString(t, filepath.Join(dir, configFileName))
	writeMainConfig(t, dir, generated+"      - dev\n")

	changes, err := r.ConfigDiff(ConfigDiffOpts{WriteDiffDir: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(changes.DiffDir) })

	require.Equal(t, []core.Operation{core.OpSecretChangeAccess}, opsOf(changes.Changes))

	declared := readDiffFile(t, changes.DiffDir, DeclaredTreeDir, configFileName)
	verified := readDiffFile(t, changes.DiffDir, VerifiedTreeDir, configFileName)

	// Both sides still carry the generated file's comments, so a differ has
	// only the access list to report.
	const comment = "# Key is the public key of this user"
	require.Contains(t, declared, comment)
	require.Contains(t, verified, comment)
	require.Contains(t, declared, "- dev")
	require.NotContains(t, verified, "- dev")
}

// TestConfigDiffLeavesLiveTreeAlone guards the reason the diff works on copies:
// backing out a declared secret can empty a sub-file, and the config mutators
// delete such a file from disk. That must happen to the copy only.
func TestConfigDiffLeavesLiveTreeAlone(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	// A hand-written sub-config declaring one secret the audit log knows
	// nothing about.
	subDir := filepath.Join(dir, "svc")
	require.NoError(t, os.MkdirAll(subDir, 0o700))
	subPath := filepath.Join(subDir, configFileName)
	require.NoError(t, os.WriteFile(subPath, []byte(
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

	changes, err := r.ConfigDiff(ConfigDiffOpts{WriteDiffDir: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(changes.DiffDir) })

	require.Equal(t, []core.Operation{core.OpSecretAdd}, opsOf(changes.Changes))

	// The live sub-config is still there, untouched.
	require.FileExists(t, subPath)
	require.Contains(t, readFileString(t, subPath), "token")

	// In the copies, the declared side keeps it and the verified side has it
	// pruned - including the include that pointed at it.
	require.Contains(t, readDiffFile(t, changes.DiffDir, DeclaredTreeDir, "svc/sesam.yml"), "token")
	require.NoFileExists(t, filepath.Join(changes.DiffDir, VerifiedTreeDir, "svc", configFileName))
	require.NotContains(t, readDiffFile(t, changes.DiffDir, VerifiedTreeDir, configFileName), "include")
}

// TestConfigDiffRejectsUnappliable checks that a declaration the audit log
// could never accept is an error rather than a change list.
func TestConfigDiffRejectsUnappliable(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	writeMainConfig(t, dir, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+admin.Recipient+"\n"+
		"groups:\n"+
		"  dev:\n"+
		"    - admin\n"+
		"secrets: []\n")

	_, err := r.ConfigDiff(ConfigDiffOpts{WriteDiffDir: true})
	require.ErrorContains(t, err, "declares no admin user")
}

func opsOf(changes []diff.Change) []core.Operation {
	ops := make([]core.Operation, 0, len(changes))
	for _, c := range changes {
		ops = append(ops, c.Op)
	}

	return ops
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}
