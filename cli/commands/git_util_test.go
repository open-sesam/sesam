package commands

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		// A squash has no merge commit, so there is nothing for git to abort.
		{mergeKindSquash, "squash merge", true, "git commit", ""},
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

func TestResolveRefs(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", append([]string{"-c", "user.name=Test", "-c", "user.email=test@test.com"}, args...)...)
		cmd.Dir = dir
		out, err := cmd.Output()
		require.NoError(t, err, "git %v", args)
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("commit", "-q", "--allow-empty", "-m", "first")
	head := git("rev-parse", "HEAD")
	unknown := strings.Repeat("1", len(head))

	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"none set", nil, []string{"", "", ""}},
		{"one set", map[string]string{"REVERT_HEAD": head}, []string{"", head, ""}},
		{"octopus takes the first head", map[string]string{"MERGE_HEAD": head + "\n" + unknown}, []string{"", "", head}},
		{"unknown object is unset", map[string]string{"CHERRY_PICK_HEAD": unknown}, []string{"", "", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, content := range tt.files {
				path := filepath.Join(dir, ".git", name)
				require.NoError(t, os.WriteFile(path, []byte(content+"\n"), 0o600))
				t.Cleanup(func() { require.NoError(t, os.Remove(path)) })
			}

			got, err := resolveRefs(t.Context(), dir, "CHERRY_PICK_HEAD", "REVERT_HEAD", "MERGE_HEAD")
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
