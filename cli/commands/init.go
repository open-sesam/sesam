package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/chzyer/readline"
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

func boolWithDefault(cmd *cli.Command, name string, def bool) bool {
	if !cmd.IsSet(name) {
		return def
	}

	return cmd.Bool(name)
}

// HandleInit bootstraps sesam in a git repository. In a fresh repo it creates
// the sesam state (repo.Init); in an already-initialized one - typically a
// fresh clone - it only wires up local git integration and
// reveals the caller's secrets (repo.Setup).
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
			prefix := output.String("✓ ").Foreground(output.Color("#008000")).String()
			format = prefix + format + "\n"
			fmt.Printf(format, args...)
		},
		GitConfigOpts: repo.GitConfigOpts{
			InstallHooks: boolWithDefault(cmd, "install-hooks", true),
			InstallMerge: boolWithDefault(cmd, "install-merge", false), // TODO: not yet implemented.
			InstallDiff:  boolWithDefault(cmd, "install-diff", true),
			InstallAlias: boolWithDefault(cmd, "install-alias", true),
		},
	}

	ids := cmd.StringSlice("identity")
	sesamDir := cmd.String("sesam-dir")

	initialized, err := repo.IsInitialized(sesamDir)
	if err != nil {
		return err
	}

	if initialized {
		printInfo("sesam seems to be already initialized - re-running setup…")
		return repo.Setup(sesamDir, ids, opts)
	}

	r, err := repo.Init(ctx, sesamDir, ids, opts)
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

	if len(ids) == 0 {
		return nil
	}

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

func HandleUninstall(ctx context.Context, cmd *cli.Command) error {
	ask := !cmd.Bool("no-ask")
	all := cmd.Bool("all")
	if all && ask {
		confirm, err := readline.Line("‼ Are you sure you want to delete .sesam/, sesam.yml and remove all git config?\n  Make sure you reveal all secrets. [y/N] ")
		if err != nil {
			return err
		}

		confirm = strings.ToLower(confirm)
		if confirm != "y" && confirm != "yes" && confirm != "yarp" {
			slog.Info("aborted!")
			return nil
		}
	}

	if err := repo.Uninstall(cmd.String("sesam-dir"), all); err != nil {
		return err
	}

	if all {
		slog.Info("If you want to remove revealed files now: run `git clean -fdx`")
	}

	return nil
}
