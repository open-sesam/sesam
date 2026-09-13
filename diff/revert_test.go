package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
)

// loadTestConfig writes body as a sesam.yml in a fresh temp dir and loads it.
func loadTestConfig(t *testing.T, body string) *config.Config {
	t.Helper()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "sesam.yml"), []byte(body), 0o644))

	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	cfg, err := config.Load(root, "sesam.yml")
	require.NoError(t, err)

	return cfg
}

// TestRevertDescribesVerifiedState is the property that makes the reverted
// config trustworthy as a diff side: back the declared changes out and what is
// left must describe the verified state exactly - i.e. diffing it against the
// same state finds nothing left to do.
//
// The scenario deliberately triggers every change kind at once, including a
// key swap, which only survives because the reverse walk puts the recorded key
// back before dropping the declared one (a config may not lose its last key).
func TestRevertDescribesVerifiedState(t *testing.T) {
	adminKey := newRecipient(t, core.KeySourceManual)
	bobKey := newRecipient(t, "github:bob")
	carolKey := newRecipient(t, core.KeySourceManual)
	newKey := newRecipient(t, core.KeySourceManual)

	vstate := &core.VerifiedState{
		Users: []core.VerifiedUser{
			{Name: "admin", Groups: []string{"admin"}, Recps: core.Recipients{adminKey}},
			{Name: "bob", Groups: []string{"dev"}, Recps: core.Recipients{bobKey}},
			{Name: "carol", Groups: []string{"dev", "ops"}, Recps: core.Recipients{carolKey}},
		},
		Secrets: []core.VerifiedSecret{
			{RevealedPath: "README.md", AccessGroups: []string{"admin"}},
			{RevealedPath: "db.env", AccessGroups: []string{"admin", "dev"}},
		},
	}

	cfg := loadTestConfig(t, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - "+newKey.String()+"\n"+
		"  - name: carol\n"+
		"    key:\n"+
		"      - "+carolKey.String()+"\n"+
		"  - name: dave\n"+
		"    key:\n"+
		"      - github:dave\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"  ops:\n"+
		"    - carol\n"+
		"    - dave\n"+
		"secrets:\n"+
		"  - path: db.env\n"+
		"    access:\n"+
		"      - ops\n"+
		"  - path: new.env\n")

	declared, err := cfg.State()
	require.NoError(t, err)

	changes, err := Compute(vstate, declared)
	require.NoError(t, err)
	require.Equal(t, []core.Operation{
		core.OpUserTell,           // dave
		core.OpUserAddRecipients,  // admin's new key
		core.OpUserChangeGroups,   // carol: dev, ops -> ops
		core.OpSecretAdd,          // new.env
		core.OpSecretChangeAccess, // db.env: dev -> ops
		core.OpSecretRemove,       // README.md
		core.OpUserRmRecipients,   // admin's recorded key
		core.OpUserKill,           // bob
	}, ops(changes), changes.String())

	require.NoError(t, Revert(cfg, vstate, changes))

	// The reverted config must still be a config sesam would accept...
	require.NoError(t, cfg.Validate())

	// ...and must now describe the verified state: nothing left to apply.
	reverted, err := cfg.State()
	require.NoError(t, err)

	again, err := Compute(vstate, reverted)
	require.NoError(t, err)
	require.True(t, again.IsEmpty(), "reverted config still differs:\n%s", again.String())
}

func TestRevertChange(t *testing.T) {
	bobKey := newRecipient(t, "github:bob")

	vstate := &core.VerifiedState{
		Users: []core.VerifiedUser{
			{Name: "admin", Groups: []string{"admin"}, Recps: core.Recipients{newRecipient(t, "github:admin")}},
			{Name: "bob", Groups: []string{"dev"}, Recps: core.Recipients{bobKey}},
		},
		Secrets: []core.VerifiedSecret{
			{RevealedPath: "db.env", AccessGroups: []string{"admin", "dev"}},
		},
	}

	const declared = "users:\n" +
		"  - name: admin\n" +
		"    key:\n" +
		"      - github:admin\n" +
		"groups:\n" +
		"  admin:\n" +
		"    - admin\n" +
		"secrets:\n" +
		"  - path: db.env\n"

	tests := []struct {
		name        string
		change      Change
		contains    []string
		notContains []string
	}{
		{
			name:        "tell is undone by dropping the user",
			change:      Change{Op: core.OpUserTell, User: "admin", Groups: []string{"admin"}},
			notContains: []string{"admin"},
		},
		{
			name:   "kill is undone by declaring the recorded user",
			change: Change{Op: core.OpUserKill, User: "bob"},
			// The key comes back as the spec it was resolved from, not as the
			// material the audit log stores.
			contains:    []string{"name: bob", "github:bob", "dev"},
			notContains: []string{bobKey.String()},
		},
		{
			name:        "group change is undone by restoring the old groups",
			change:      Change{Op: core.OpUserChangeGroups, User: "admin", Groups: []string{"admin"}, Old: []string{"ops"}},
			contains:    []string{"ops"},
			notContains: []string{"admin:"},
		},
		{
			name:     "access change is undone by restoring the old access",
			change:   Change{Op: core.OpSecretChangeAccess, Path: "db.env", Groups: nil, Old: []string{"dev"}},
			contains: []string{"access", "- dev"},
		},
		{
			name:        "secret add is undone by dropping the secret",
			change:      Change{Op: core.OpSecretAdd, Path: "db.env"},
			notContains: []string{"db.env"},
		},
		{
			name:     "secret removal is undone by declaring it as recorded",
			change:   Change{Op: core.OpSecretRemove, Path: "db.env"},
			contains: []string{"db.env"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadTestConfig(t, declared)
			require.NoError(t, Revert(cfg, vstate, &Diff{Changes: []Change{tc.change}}))

			rendered := cfg.MainFile.RootNode.String()
			for _, want := range tc.contains {
				require.Contains(t, rendered, want, rendered)
			}
			for _, unwanted := range tc.notContains {
				require.NotContains(t, rendered, unwanted, rendered)
			}
		})
	}
}

// TestRevertUnknownVerifiedEntry checks that a change naming something the
// verified state does not hold is an error, not a silently skipped revert -
// the rendered config would otherwise misrepresent the audit log.
func TestRevertUnknownVerifiedEntry(t *testing.T) {
	vstate := &core.VerifiedState{Users: []core.VerifiedUser{
		{Name: "admin", Groups: []string{"admin"}, Recps: core.Recipients{newRecipient(t, "github:admin")}},
	}}

	cfg := loadTestConfig(t, "users:\n"+
		"  - name: admin\n"+
		"    key:\n"+
		"      - github:admin\n"+
		"groups:\n"+
		"  admin:\n"+
		"    - admin\n"+
		"secrets: []\n")

	err := Revert(cfg, vstate, &Diff{Changes: []Change{{Op: core.OpUserKill, User: "ghost"}}})
	require.ErrorContains(t, err, `user "ghost" is not in the verified state`)

	err = Revert(cfg, vstate, &Diff{Changes: []Change{{Op: core.OpSecretRemove, Path: "ghost.env"}}})
	require.ErrorContains(t, err, `secret "ghost.env" is not in the verified state`)
}
