package repo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

// testIdentity bundles the identity-file path with the recipient string so
// tests can talk to both repo.Init (path-based) and core helpers that prefer
// the recipient form.
type testIdentity struct {
	Name      string
	Path      string // path to the age identity file
	Recipient string // age recipient (public key)
}

// writeTestIdentity generates an x25519 age identity, writes it to a fresh
// file in t.TempDir, and returns the bundle. The file lives outside the
// sesam worktree so that worktree cleanup never targets it.
func writeTestIdentity(t *testing.T, name string) *testIdentity {
	t.Helper()

	id, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, name+".age")
	require.NoError(t, os.WriteFile(path, fmt.Appendf(nil, "%s\n", id), 0o600))

	return &testIdentity{
		Name:      name,
		Path:      path,
		Recipient: id.Recipient().String(),
	}
}

// freshGitRepo creates a temp dir, runs git init, and configures a test
// committer. Returns the worktree root.
func freshGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	gr, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	cfg, err := gr.Config()
	require.NoError(t, err)
	cfg.User.Name = "Sesam Test"
	cfg.User.Email = "test@sesam.dev"
	require.NoError(t, gr.SetConfig(cfg))

	return dir
}

// bootstrapRepo bootstraps a fresh sesam repository under a brand-new git
// worktree, with `admin` as the initial user. Returns the worktree root
// and an open *Repo; the caller MUST defer r.Close().
func bootstrapRepo(t *testing.T, admin *testIdentity) (string, *Repo) {
	t.Helper()

	dir := freshGitRepo(t)
	r, err := Init(
		context.Background(),
		dir,
		admin.Name,
		[]string{admin.Path},
		RepoInitOpts{RepoOpts: RepoOpts{LockTimeout: 5 * time.Second}},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	return dir, r
}

// bootstrappedDir initializes a sesam repository, immediately closes it,
// and returns just the worktree root. Use this when a test exercises a
// fresh Load on the dir — the bootstrap Close releases the on-disk lock so
// the subsequent Load can acquire it.
func bootstrappedDir(t *testing.T, admin *testIdentity) string {
	t.Helper()
	dir, r := bootstrapRepo(t, admin)
	require.NoError(t, r.Close())
	return dir
}

// reloadSesamRepo opens the sesam repo at dir using `who` as the runtime
// identity. The caller MUST defer r.Close().
func reloadSesamRepo(t *testing.T, dir string, who *testIdentity) *Repo {
	t.Helper()

	r, err := Load(dir, []string{who.Path}, RepoOpts{LockTimeout: 5 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.Close() })

	return r
}

// gitCommitAll stages every worktree change and commits with a deterministic
// committer.
func gitCommitAll(t *testing.T, dir, msg string) {
	t.Helper()

	gr, err := git.PlainOpen(dir)
	require.NoError(t, err)

	wt, err := gr.Worktree()
	require.NoError(t, err)

	_, err = wt.Add(".")
	require.NoError(t, err)

	_, err = wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Sesam Test",
			Email: "test@sesam.dev",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)
}

// fileExists is a small helper that asserts whether `path` is a regular
// file, fatally failing on any other stat error.
func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	require.True(t, os.IsNotExist(err), "stat %s: %v", path, err)
	return false
}
