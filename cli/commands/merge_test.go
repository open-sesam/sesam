package commands

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

func TestMergeDecisionLines(t *testing.T) {
	tests := []struct {
		name string
		in   core.ConflictResolutionEntry
		want string
	}{
		{
			name: "reason wins",
			in:   core.ConflictResolutionEntry{Action: core.MergeDropped, Target: "bob", Reason: "kill wins"},
			want: "- kill wins",
		},
		{
			name: "falls back to action and target",
			in:   core.ConflictResolutionEntry{Action: core.MergeFlagged, Target: "dev"},
			want: "- flagged dev",
		},
		{
			name: "falls back to action only",
			in:   core.ConflictResolutionEntry{Action: core.MergeApplied},
			want: "- applied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeDecisionLines([]core.ConflictResolutionEntry{tt.in})
			require.Equal(t, []string{tt.want}, got)
		})
	}
}

func TestMergeDriverSummary(t *testing.T) {
	out := mergeDriverSummary([]core.ConflictResolutionEntry{
		{Action: core.MergeDropped, Reason: "user bob killed on theirs; kill wins"},
	}, mergeKindMerge)

	require.Contains(t, out, "sesam: both sides changed the audit log.")
	require.Contains(t, out, "sesam: a list of automated decisions you might want to review follows:")
	require.Contains(t, out, "sesam: - user bob killed on theirs; kill wins")
	require.Contains(t, out, "finish this merge with `git commit`")
	require.Contains(t, out, "`git merge --abort`")
	// Every line carries the sesam: prefix so it is distinguishable from git's.
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		require.True(t, strings.HasPrefix(line, "sesam:"), "line without prefix: %q", line)
	}
}

// The advice adapts to the operation the driver is running inside, and says
// nothing specific when git gave it nothing to go on.
func TestMergeDriverSummaryPerKind(t *testing.T) {
	tests := []struct {
		kind mergeKind
		want string
	}{
		{mergeKindRebase, "finish this rebase with `git rebase --continue`"},
		{mergeKindCherryPick, "finish this cherry-pick with `git cherry-pick --continue`"},
		{mergeKindNone, "finish the git operation you started"},
		{mergeKindOther, "finish the git operation you started"},
	}

	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			require.Contains(t, mergeDriverSummary(nil, tt.kind), tt.want)
		})
	}
}

func TestMergeDriverSummaryNoDecisions(t *testing.T) {
	out := mergeDriverSummary(nil, mergeKindMerge)
	// The header still explains the semantic merge, but with nothing to review
	// the decision list is omitted entirely.
	require.Contains(t, out, "sesam: both sides changed the audit log.")
	require.NotContains(t, out, "automated decisions you might want to review")
}
