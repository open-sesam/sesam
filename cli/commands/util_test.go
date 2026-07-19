package commands

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
)

func TestResolveGroups(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		required bool
		want     []string
		additive bool
		wantErr  string
	}{
		{name: "group replaces", args: []string{"cmd", "-g", "dev", "-g", "ops"}, want: []string{"dev", "ops"}},
		{name: "group-add is additive", args: []string{"cmd", "-G", "ops"}, want: []string{"ops"}, additive: true},
		{name: "both flags conflict", args: []string{"cmd", "-g", "dev", "-G", "ops"}, wantErr: "mutually exclusive"},
		{name: "required but neither given", args: []string{"cmd"}, required: true, wantErr: "need --group"},
		{name: "optional and neither given", args: []string{"cmd"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var (
				gotGroups   []string
				gotAdditive bool
				gotErr      error
			)
			cmd := &cli.Command{
				Name: "cmd",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{Name: "group", Aliases: []string{"g"}},
					&cli.StringSliceFlag{Name: "group-add", Aliases: []string{"G"}},
				},
				Action: func(_ context.Context, cmd *cli.Command) error {
					gotGroups, gotAdditive, gotErr = resolveGroups(cmd, tc.required)
					return nil
				},
			}
			require.NoError(t, cmd.Run(context.Background(), tc.args))

			if tc.wantErr != "" {
				require.ErrorContains(t, gotErr, tc.wantErr)
				return
			}
			require.NoError(t, gotErr)
			require.Equal(t, tc.additive, gotAdditive)
			require.Equal(t, tc.want, gotGroups)
		})
	}
}

func TestAskpassRequired(t *testing.T) {
	t.Setenv("SESAM_ASKPASS_REQUIRED", "")
	t.Setenv("GIT_ASKPASS_REQUIRED", "")
	t.Setenv("SSH_ASKPASS_REQUIRED", "")
	require.Equal(t, "prefer", askpassRequired())

	t.Setenv("SSH_ASKPASS_REQUIRED", "force")
	require.Equal(t, "force", askpassRequired())

	t.Setenv("GIT_ASKPASS_REQUIRED", "never")
	require.Equal(t, "never", askpassRequired())

	t.Setenv("SESAM_ASKPASS_REQUIRED", "prefer")
	require.Equal(t, "prefer", askpassRequired())
}
