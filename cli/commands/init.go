package commands

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// TODO: Show ascii logo on init

const (
	asciiLogo = `
,adPPYba,   ,adPPYba,  ,adPPYba,  ,adPPYYba,  88,dPYba,,adPYba,
I8[    ""  a8P_____88  I8[    ""  ""     'Y8  88P'   "88"    "8a
 '"Y8ba,   8PP"""""""   '"Y8ba,   ,adPPPPP88  88      88      88
aa    ]8I  "8b,   ,aa  aa    ]8I  88,    ,88  88      88      88
'"YbbdP"'   '"Ybbd8"'  '"YbbdP"'  '"8bbdP"Y8  88      88      88
`
)

// HandleInit bootstraps sesam metadata in a git repository.
func HandleInit(ctx context.Context, cmd *cli.Command) (err error) {
	initialUser := cmd.String("user")
	if initialUser == "" {
		return fmt.Errorf("failed to determine initial user, please pass --user")
	}

	r, err := repo.Init(
		ctx,
		cmd.String("sesam-dir"),
		initialUser,
		cmd.StringSlice("identity"),
		repo.RepoOpts{
			Interactive: true,
			LockTimeout: cmd.Duration("lock-timeout"),
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := r.Close()
		if closeErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("close repo: %w", closeErr)
			return
		}
		slog.Warn("close repo failed", slog.Any("error", closeErr))
	}()

	fmt.Println(asciiLogo)

	return nil
}
