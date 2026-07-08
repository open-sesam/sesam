package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/muesli/termenv"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

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
	output := termenv.NewOutput(os.Stdout)
	opts := repo.RepoInitOpts{
		InitialUserName: cmd.String("user"),
		RepoOpts: repo.RepoOpts{
			Interactive:     true,
			AskpassProgram:  cmd.String("askpass"),
			AskpassRequired: askpassRequired(),
			LockTimeout:     cmd.Duration("lock-timeout"),
		},
		InitStep: func(format string, args ...any) {
			prefix := output.String(" ✓ ").Foreground(output.Color("#008000")).String()
			format = prefix + format + "\n"
			fmt.Printf(format, args...)
		},
	}

	ids := cmd.StringSlice("identity")
	r, err := repo.Init(
		ctx,
		cmd.String("sesam-dir"),
		ids,
		opts,
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

	fmt.Print(output.String(asciiLogo).Foreground(termenv.ANSIBrightGreen))

	out := termenv.NewOutput(os.Stdout)
	export := out.String("export SESAM_ID=\""+ids[0]).Foreground(termenv.ANSIBrightBlue).String() + "\""

	if os.Getenv("SESAM_ID") == "" {
		homeDir := os.Getenv("HOME")
		homeExport := strings.Replace(export, homeDir, "$HOME", 1)
		fmt.Println()
		printInfo("Tip: Put %s in your shell config", homeExport)
	}
	return nil
}
