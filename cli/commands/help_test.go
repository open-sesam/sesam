package commands

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPage(t *testing.T) {
	tests := []struct {
		name        string
		pager       string
		interactive bool
		cancel      bool
		want        string
	}{
		{name: "no terminal writes directly", pager: "cat", want: "manual"},
		{name: "no pager writes directly", interactive: true, want: "manual"},
		{name: "pager output is passed through", pager: "cat", interactive: true, want: "manual"},
		{name: "pager that cannot start falls back", pager: "/nonexistent/pager", interactive: true, want: "manual"},
		{name: "pager exiting non-zero does not dump", pager: "false", interactive: true, want: ""},
		{name: "interrupted pager does not dump", pager: "cat", interactive: true, cancel: true, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PAGER", tt.pager)

			ctx, cancel := context.WithCancel(t.Context())
			if tt.cancel {
				cancel()
			} else {
				defer cancel()
			}

			var out strings.Builder
			require.NoError(t, page(ctx, &out, "manual", tt.interactive))
			require.Equal(t, tt.want, out.String())
		})
	}
}

func TestInterrupted(t *testing.T) {
	ctx := t.Context()

	require.False(t, interrupted(ctx, runShell(t, ctx, "exit 3")))
	require.True(t, interrupted(ctx, runShell(t, ctx, "kill -INT $$")))

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.True(t, interrupted(canceled, runShell(t, canceled, "exit 0")))
}

func runShell(t *testing.T, ctx context.Context, script string) error {
	t.Helper()
	return exec.CommandContext(ctx, "sh", "-c", script).Run()
}
