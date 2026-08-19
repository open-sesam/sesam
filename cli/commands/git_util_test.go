package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The kind drives every piece of advice sesam prints during a half-finished
// operation, so a wrong command string sends a user down a dead end.
func TestMergeKind(t *testing.T) {
	tests := []struct {
		kind       mergeKind
		name       string
		inProgress bool
		cont       string
		abort      string
	}{
		{mergeKindNone, "none", false, "", ""},
		{mergeKindMerge, "merge", true, "git commit", "git merge --abort"},
		{mergeKindRebase, "rebase", true, "git rebase --continue", "git rebase --abort"},
		{mergeKindCherryPick, "cherry-pick", true, "git cherry-pick --continue", "git cherry-pick --abort"},
		{mergeKindRevert, "revert", true, "git revert --continue", "git revert --abort"},
		// A conflicted `git stash pop` has nothing to continue or abort.
		{mergeKindOther, "conflicted operation", true, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.name, tt.kind.String())
			require.Equal(t, tt.inProgress, tt.kind.InProgress())
			require.Equal(t, tt.cont, tt.kind.ContinueCmd())
			require.Equal(t, tt.abort, tt.kind.AbortCmd())
		})
	}
}
