package repo

import (
	"context"
	"testing"

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
