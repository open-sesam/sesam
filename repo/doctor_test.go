package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/require"
)

func findGitConfigCheck(checks []GitConfigCheck, path string) (GitConfigCheck, bool) {
	for _, c := range checks {
		if c.Path == path {
			return c, true
		}
	}
	return GitConfigCheck{}, false
}

// CheckGitConfig must surface the config-based hook commands so `sesam doctor`
// can report on them (they are otherwise filtered out). The entries only exist
// on git >= 2.54, so skip below that.
func TestCheckGitConfigReportsHooks(t *testing.T) {
	v, err := ReadGitVersion(context.Background())
	require.NoError(t, err)
	if v.LessThan(semver.MustParse("2.54.0")) {
		t.Skipf("git %s < 2.54: config-based hooks unavailable", v)
	}

	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin) // installs no git config

	// Reported as present-but-unset: doctor renders this as "not installed".
	checks, err := CheckGitConfig(dir)
	require.NoError(t, err)
	c, ok := findGitConfigCheck(checks, "hook.sesam-precommit.command")
	require.True(t, ok, "hook command entry must be reported, not filtered out")
	require.False(t, c.OK)
	require.Empty(t, c.Actual)

	// After installing, it matches the expected `sesam ... hook pre-commit`.
	require.NoError(t, r.InstallHooks())
	checks, err = CheckGitConfig(dir)
	require.NoError(t, err)
	c, ok = findGitConfigCheck(checks, "hook.sesam-precommit.command")
	require.True(t, ok)
	require.True(t, c.OK, "installed hook must match expected: got %q want %q", c.Actual, c.Expected)
	require.Contains(t, c.Expected, "hook pre-commit")
}

// Two sesam repos in one git repo must not clobber each other's hooks: the
// subsection names are suffixed with the sesam dir, so a second `sesam init`
// installs its own hook alongside the first instead of overwriting it. Requires
// git >= 2.54 (config-based hooks).
func TestInitMultipleSesamReposKeepDistinctHooks(t *testing.T) {
	v, err := ReadGitVersion(context.Background())
	require.NoError(t, err)
	if v.LessThan(semver.MustParse("2.54.0")) {
		t.Skipf("git %s < 2.54: config-based hooks unavailable", v)
	}

	admin := writeTestIdentity(t, "admin")
	dir := freshGitRepo(t)

	initSub := func(sub string) {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, sub), 0o700))
		r, err := Init(context.Background(), filepath.Join(dir, sub), []string{admin.Path}, RepoInitOpts{
			InitialUserName: admin.Name,
			GitConfigOpts:   GitConfigOpts{InstallHooks: true},
			RepoOpts:        RepoOpts{LockTimeout: 5 * time.Second},
		})
		require.NoError(t, err)
		require.NoError(t, r.Close())
	}

	initSub("sub-a")
	initSub("sub-b") // must not overwrite sub-a's hook

	// Each repo still sees its own installed pre-commit hook, pointing at its
	// own sesam dir.
	for _, sub := range []string{"sub-a", "sub-b"} {
		checks, err := CheckGitConfig(filepath.Join(dir, sub))
		require.NoError(t, err)
		c, ok := findGitConfigCheck(checks, "hook.sesam-precommit.command")
		require.True(t, ok)
		require.True(t, c.OK, "%s pre-commit hook must survive the other repo's init", sub)
		require.Contains(t, c.Expected, "--sesam-dir="+sub)
	}
}
