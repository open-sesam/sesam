package repo

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- Init / Load lifecycle -------------------------------------------------

func TestInit_Negative(t *testing.T) {
	admin := writeTestIdentity(t, "admin")

	cases := []struct {
		name    string
		user    string
		dirFn   func(t *testing.T) string
		wantErr string
	}{
		{
			name:    "invalid user name",
			user:    "not a valid name",
			dirFn:   freshGitRepo,
			wantErr: "invalid initial user",
		},
		{
			name: "already initialized",
			user: "admin",
			dirFn: func(t *testing.T) string {
				return bootstrappedDir(t, admin)
			},
			wantErr: "already has sesam",
		},
		{
			name: "not a git repo",
			user: "admin",
			dirFn: func(t *testing.T) string {
				return t.TempDir() // no `git init`
			},
			wantErr: "no git repository",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.dirFn(t)
			_, err := Init(
				context.Background(),
				dir,
				[]string{admin.Path},
				RepoInitOpts{InitialUserName: tc.user},
			)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestLoad_Negative(t *testing.T) {
	admin := writeTestIdentity(t, "admin")

	cases := []struct {
		name    string
		dirFn   func(t *testing.T) string
		idPaths []string
		wantErr string
	}{
		{
			name:    "no .sesam dir",
			dirFn:   freshGitRepo,
			idPaths: []string{admin.Path},
			// Config is lazy-loaded now, so the missing repo first surfaces
			// when the audit log can't be opened.
			wantErr: "failed to load audit log",
		},
		{
			name: "no identity supplied",
			dirFn: func(t *testing.T) string {
				return bootstrappedDir(t, admin)
			},
			idPaths: nil,
			wantErr: "at least one --identity",
		},
		{
			name:    "non-existent dir",
			dirFn:   func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			idPaths: []string{admin.Path},
			wantErr: "failed to access repo path",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.dirFn(t), tc.idPaths, RepoOpts{})
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestRepo_SesamDir(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	got, err := filepath.EvalSymlinks(r.SesamDir())
	require.NoError(t, err)
	want, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestRepo_Close_Idempotent(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	require.NoError(t, r.Close(), "first close")
	require.NoError(t, r.Close(), "second close is a no-op")
}

// --- Listing ---------------------------------------------------------------

func TestRepo_ListUsersAndSecrets_AfterInit(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	users, err := r.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "admin", users[0].Name)
	require.Contains(t, users[0].Groups, "admin")

	secrets, err := r.ListSecrets(nil)
	require.NoError(t, err)
	require.Len(t, secrets, 1, "init seeds the README.md secret")
	require.Equal(t, "README.md", secrets[0].RevealedPath)
}

// --- Whoami ----------------------------------------------------------------

func TestRepo_Whoami(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	got, err := r.Whoami()
	require.NoError(t, err)
	require.Equal(t, "admin", got)
}

func TestRepo_Whoami_UnknownIdentity(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	stranger := writeTestIdentity(t, "stranger")

	dir := bootstrappedDir(t, admin)
	r, err := Load(dir, []string{stranger.Path}, RepoOpts{})
	require.Error(t, err, "Load should refuse an identity that cannot decrypt the audit log")
	require.Contains(t, err.Error(), "failed to load audit log")
	require.Nil(t, r)
}

// --- Secret CRUD -----------------------------------------------------------

func TestRepo_SecretAdd_RejectsBadInputs(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	cases := []struct {
		name    string
		paths   []string
		groups  []string
		wantErr string
	}{
		{
			name:    "no paths",
			paths:   nil,
			groups:  []string{"admin"},
			wantErr: "missing secret path",
		},
		// Note: empty groups is intentionally NOT a bad input - it means
		// "admin only" (see TestSecretAddEmptyGroups).
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := r.Update(func(s *Stage) error { return s.AddSecret(tc.paths, tc.groups, false) })
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestRepo_SecretAddRemove_RoundTrip(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	plaintext := filepath.Join(dir, "secrets", "api.token")
	require.NoError(t, os.MkdirAll(filepath.Dir(plaintext), 0o700))
	require.NoError(t, os.WriteFile(plaintext, []byte("hunter2\n"), 0o600))

	require.NoError(t, r.Update(func(s *Stage) error { return s.AddSecret([]string{"secrets/api.token"}, []string{"admin"}, false) }))

	secrets, err := r.ListSecrets(nil)
	require.NoError(t, err)
	require.Len(t, secrets, 2, "README.md (from init) + the newly added secret")

	var paths []string
	for _, s := range secrets {
		paths = append(paths, s.RevealedPath)
	}
	require.Contains(t, paths, "secrets/api.token")

	require.NoError(t, r.Update(func(s *Stage) error { return s.RemoveSecret([]string{"secrets/api.token"}) }))
	secrets, err = r.ListSecrets(nil)
	require.NoError(t, err)
	require.Len(t, secrets, 1, "only README.md remains")
	require.Equal(t, "README.md", secrets[0].RevealedPath)
}

func TestRepo_SecretRemove_RejectsEmpty(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	err := r.Update(func(s *Stage) error { return s.RemoveSecret(nil) })
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing secret path")
}

// --- User management ------------------------------------------------------

func TestRepo_UserTell_AddsUserAndReSeals(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")

	_, r := bootstrapRepo(t, admin)

	err := r.Update(func(s *Stage) error { return s.Tell(context.Background(), bob.Name, []string{bob.Recipient}, []string{"developers"}) })
	require.NoError(t, err)

	users, err := r.ListUsers()
	require.NoError(t, err)
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.Name)
	}
	require.ElementsMatch(t, []string{"admin", "bob"}, names)
}

func TestRepo_UserKill_RemovesUser(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")

	_, r := bootstrapRepo(t, admin)
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.Tell(context.Background(), bob.Name, []string{bob.Recipient}, []string{"developers"})
	}))

	require.NoError(t, r.Update(func(s *Stage) error { return s.Kill(bob.Name) }))

	users, err := r.ListUsers()
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, "admin", users[0].Name)
}

// --- ShowUser --------------------------------------------------------------

func TestRepo_ShowUser(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	cases := []struct {
		name   string
		target string
		wantOk bool
		check  func(t *testing.T, payload string)
	}{
		{
			name:   "existing user",
			target: "admin",
			wantOk: true,
			check: func(t *testing.T, payload string) {
				var got map[string]any
				require.NoError(t, json.Unmarshal([]byte(payload), &got))
				require.Equal(t, "admin", got["name"])
			},
		},
		{
			name:   "unknown user",
			target: "nobody",
			wantOk: false,
			check:  func(t *testing.T, payload string) { require.Empty(t, payload) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			ok, err := r.ShowUser(tc.target, &buf)
			require.NoError(t, err)
			require.Equal(t, tc.wantOk, ok)
			tc.check(t, buf.String())
		})
	}
}

// --- Verify ----------------------------------------------------------------

func TestRepo_Verify_IntegrityOK(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	report, err := r.Verify(context.Background(), VerifyOptions{Integrity: true})
	require.NoError(t, err)
	// A clean repo produces no integrity errors, so the report is dropped to
	// nil (omitted from JSON). OK() still reports success.
	require.Nil(t, report.Integrity, "empty integrity report is omitted")
	require.True(t, report.OK())
}

func TestRepo_Verify_NoChecksMeansOK(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	_, r := bootstrapRepo(t, admin)

	report, err := r.Verify(context.Background(), VerifyOptions{})
	require.NoError(t, err)
	require.Nil(t, report.Integrity, "no checks requested → no Integrity report")
	require.True(t, report.OK())
}

func TestVerifyReport_OK(t *testing.T) {
	cases := []struct {
		name string
		rep  *VerifyReport
		want bool
	}{
		{"nil report is OK", nil, true},
		{"empty report is OK", &VerifyReport{}, true},
		// We can't easily construct a failing IntegrityReport from outside
		// core, but we can at least cover the nil/empty arms here.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.rep.OK())
		})
	}
}

// --- Seal / Reveal / DeleteRevealed ---------------------------------------

func TestRepo_SealReveal_RoundTrip(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	revealed := filepath.Join(dir, "README.md")
	original, err := os.ReadFile(revealed)
	require.NoError(t, err)

	require.NoError(t, os.Remove(revealed))
	require.False(t, fileExists(t, revealed), "plaintext removed before reveal")

	require.NoError(t, r.RevealAll())
	got, err := os.ReadFile(revealed)
	require.NoError(t, err)
	require.Equal(t, original, got, "RevealAll restores the original plaintext")

	require.NoError(t, r.Update(func(s *Stage) error { return s.SealAll() }), "SealAll on an already-sealed tree is a no-op")
}

// --- Clean (method dispatch) ----------------------------------------------

func TestRepo_Clean_SoftRemovesOnlyTrackedRevealed(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	revealed := filepath.Join(dir, "README.md")
	require.True(t, fileExists(t, revealed))

	leaked := filepath.Join(dir, "leaked.txt")
	require.NoError(t, os.WriteFile(leaked, []byte("noise"), 0o600))

	require.NoError(t, r.Clean(context.Background(), CleanOpts{Aggressive: false}))
	require.False(t, fileExists(t, revealed), "known revealed plaintext is removed")
	require.True(t, fileExists(t, leaked), "untracked unknown file survives soft clean")
}

func TestRepo_Clean_AggressiveAlsoWipesUnknownUntracked(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	leaked := filepath.Join(dir, "leaked.txt")
	require.NoError(t, os.WriteFile(leaked, []byte("noise"), 0o600))

	require.NoError(t, r.Clean(context.Background(), CleanOpts{Aggressive: true}))
	require.False(t, fileExists(t, leaked), "aggressive walks the worktree index")
}

// --- LoadIdentities / ResolveSesamDir (cheap helpers) ----------------------

func TestLoadIdentities_RequiresAtLeastOnePath(t *testing.T) {
	_, err := LoadIdentities(nil, RepoOpts{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one --identity")
}

func TestLoadIdentities_RoundTrip(t *testing.T) {
	admin := writeTestIdentity(t, "admin")

	ids, err := LoadIdentities([]string{admin.Path}, RepoOpts{})
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.Equal(t, []string{admin.Recipient}, ids.RecipientStrings())
}

func TestResolveSesamDir(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, _ := bootstrapRepo(t, admin)

	subdir := filepath.Join(dir, "deep", "nested")
	require.NoError(t, os.MkdirAll(subdir, 0o700))

	cases := []struct {
		name string
		in   string
	}{
		{"worktree root", dir},
		{"nested subdir walks upward", subdir},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveSesamDir(tc.in)
			require.NoError(t, err)
			gotResolved, err := filepath.EvalSymlinks(got)
			require.NoError(t, err)
			wantResolved, err := filepath.EvalSymlinks(dir)
			require.NoError(t, err)
			require.Equal(t, wantResolved, gotResolved)
		})
	}
}

// --- RepoOpts helpers ------------------------------------------------------

func TestRepoOpts_LockTimeoutDefault(t *testing.T) {
	require.Equal(t, defaultLockTimeout, RepoOpts{}.lockTimeout())
	require.Equal(t, defaultLockTimeout, RepoOpts{LockTimeout: 0}.lockTimeout())
	require.Equal(t, defaultLockTimeout, RepoOpts{LockTimeout: -1}.lockTimeout())

	const custom = 7 * 1_000_000_000 // 7s as time.Duration
	require.EqualValues(t, custom, RepoOpts{LockTimeout: custom}.lockTimeout())
}

func TestRepoOpts_PluginUI(t *testing.T) {
	require.NotNil(t, RepoOpts{}.pluginUI(), "non-interactive default")
	require.NotNil(t, RepoOpts{Interactive: true}.pluginUI(), "interactive variant")
}

// --- Status ----------------------------------------------------------------

// writeRepoFile writes content to dir/rel, creating parent dirs as needed.
func writeRepoFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
	require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
}

// statusStates runs Status and collapses the report into a path->state map so
// tests can assert on the specific secrets they created (ignoring the
// bootstrap README.md and any other entries).
func statusStates(t *testing.T, r *Repo, opts StatusOpts) map[string]SecretState {
	t.Helper()
	st, err := r.Status(opts)
	require.NoError(t, err)

	out := make(map[string]SecretState, len(st.Files))
	for _, f := range st.Files {
		out[f.RevealedPath] = f.State
	}
	return out
}

func TestRepoStatusStates(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	add := func(rel, content string) {
		t.Helper()
		writeRepoFile(t, dir, rel, content)
		require.NoError(t, r.Update(func(s *Stage) error { return s.AddSecret([]string{rel}, []string{"admin"}, false) }))
	}

	add("secrets/same", "identical")
	add("secrets/diff", "original")
	add("secrets/unrevealed", "gone-soon")
	add("secrets/unsealed", "seal-removed")

	// Add only records the audit entry; seal writes the ciphertext objects.
	require.NoError(t, r.Update(func(s *Stage) error { return s.SealAll() }))
	require.NoError(t, r.Close())

	// Reload so the runtime user (whoami) is resolved - Status needs it to
	// evaluate access, and Init alone does not populate it.
	r = reloadSesamRepo(t, dir, admin)

	// diff: change the revealed plaintext without re-sealing.
	writeRepoFile(t, dir, "secrets/diff", "changed!")
	// unrevealed: drop the revealed plaintext (sealed object stays).
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/unrevealed")))
	// unsealed: drop the sealed object (revealed plaintext stays).
	require.NoError(t, os.Remove(filepath.Join(dir, r.secret.SealedPath("secrets/unsealed"))))
	// unmanaged: an untracked file sesam does not know about.
	writeRepoFile(t, dir, "loose.txt", "junk")

	t.Run("each state is classified", func(t *testing.T) {
		m := statusStates(t, r, StatusOpts{})
		require.Equal(t, SecretStateInSync, m["secrets/same"])
		require.Equal(t, SecretStateNotInSync, m["secrets/diff"])
		require.Equal(t, SecretStateNoRevealedPath, m["secrets/unrevealed"])
		require.Equal(t, SecretStateNoSealedPath, m["secrets/unsealed"])
		require.Equal(t, SecretStateUnmanaged, m["loose.txt"])

		// The repo lock is a sibling of .sesam at the worktree root but is
		// sesam-internal infra, not an unmanaged worktree file.
		_, hasLock := m[".sesam.lock"]
		require.False(t, hasLock, "the repo lock must not be reported as unmanaged")
	})

	t.Run("ignore-unmanaged drops loose files but keeps secrets", func(t *testing.T) {
		m := statusStates(t, r, StatusOpts{IgnoreUnmanaged: true})
		_, ok := m["loose.txt"]
		require.False(t, ok, "unmanaged file must not appear")
		require.Equal(t, SecretStateInSync, m["secrets/same"])
	})
}

// A user without access to a secret must see it reported as no-access, and
// Status must not try to decrypt it (the user is not a recipient).
func TestRepoStatusUserHasNoAccess(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)

	// A secret in a group bob will never belong to.
	writeRepoFile(t, dir, "secrets/ops", "ops-only")
	require.NoError(t, r.Update(func(s *Stage) error { return s.AddSecret([]string{"secrets/ops"}, []string{"ops"}, false) }))

	// Tell bob, but only into "dev" - he has no access to the "ops" secret.
	require.NoError(t, r.Update(func(s *Stage) error { return s.Tell(context.Background(), "bob", []string{bob.Recipient}, []string{"dev"}) }))
	require.NoError(t, r.Close())

	rb := reloadSesamRepo(t, dir, bob)
	m := statusStates(t, rb, StatusOpts{})
	require.Equal(t, SecretStateUserHasNoAccess, m["secrets/ops"])
}

// With WriteDiffDirs the diff dir must hold the decrypted *sealed* content
// under sealed/ and the working-tree plaintext under revealed/, mirroring the
// secret's revealed path, so `git diff --no-index sealed revealed` works.
func TestRepoStatusDiffDir(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)

	writeRepoFile(t, dir, "secrets/diff", "v1-sealed")
	require.NoError(t, r.Update(func(s *Stage) error { return s.AddSecret([]string{"secrets/diff"}, []string{"admin"}, false) }))
	require.NoError(t, r.Update(func(s *Stage) error { return s.SealAll() }))
	require.NoError(t, r.Close())

	// Reload so whoami is resolved (Init does not set it).
	r = reloadSesamRepo(t, dir, admin)

	// Modify the working copy so sealed and revealed differ.
	writeRepoFile(t, dir, "secrets/diff", "v2-working")

	st, err := r.Status(StatusOpts{WriteDiffDirs: true})
	require.NoError(t, err)
	require.NotEmpty(t, st.DiffDir)
	t.Cleanup(func() { _ = os.RemoveAll(st.DiffDir) })

	sealed, err := os.ReadFile(filepath.Join(st.DiffDir, "sealed", "secrets/diff"))
	require.NoError(t, err)
	require.Equal(t, "v1-sealed", string(sealed), "sealed/ holds the decrypted sealed content")

	revealed, err := os.ReadFile(filepath.Join(st.DiffDir, "revealed", "secrets/diff"))
	require.NoError(t, err)
	require.Equal(t, "v2-working", string(revealed), "revealed/ holds the working-tree plaintext")
}
