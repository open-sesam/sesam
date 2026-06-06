package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/open-sesam/sesam/cli/commands"
	"github.com/urfave/cli/v3"
)

// Main builds and runs the sesam CLI command tree.
//
// Commands wrapped in commands.WithRepo load a sesam Repo (acquire lock,
// build managers, defer Close) and hand it to the handler; the wrapping
// makes it obvious which commands need an initialized sesam repository.
func Main(args []string) error {
	cli.VersionFlag = &cli.BoolFlag{
		Name:  "version",
		Usage: "Print the version and exit",
	}

	// Print just the banner, not the default "<name> version <v>" line.
	cli.VersionPrinter = func(cmd *cli.Command) {
		fmt.Fprintln(cmd.Root().Writer, cmd.Version)
	}

	app := &cli.Command{
		Name:                   "sesam",
		Usage:                  "Manage encrypted secrets in git repositories",
		Version:                resolveBuildInfo().String(),
		Flags:                  flagsGeneral,
		EnableShellCompletion:  true,
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			{
				Name:   "init",
				Flags:  flagsInit,
				Action: commands.HandleInit,
				Usage:  "Initialize sesam in the current repository",
			},
			{
				Name:   "verify",
				Action: commands.WithRepo(commands.HandleVerify),
				Usage:  "Verify sesam signatures and encryption state",
			},
			{
				Name:   "id",
				Action: commands.WithRepo(commands.HandleID),
				Usage:  "Identify the current user by age identity",
				Commands: []*cli.Command{
					{
						Name:   "clear-cache",
						Usage:  "Clear cached passprhases from the keyring",
						Action: commands.HandleIDClearCache,
					},
				},
			},
			{
				Name:   "seal",
				Flags:  flagsSeal,
				Action: commands.WithRepo(commands.HandleSeal),
				Usage:  "Encrypt and sign changed secrets",
			},
			{
				Name:    "open",
				Aliases: []string{"reveal"},
				Flags:   flagsReveal,
				Action:  commands.WithRepo(commands.HandleOpen),
				Usage:   "Decrypt all secrets available to the current user",
			},
			{
				Name:   "log",
				Hidden: true,
				Flags:  flagsLog,
				Action: commands.WithRepo(commands.HandleLog),
				Usage:  "Show the audit log of secret changes",
			},
			{
				Name:      "add",
				Flags:     flagsAdd,
				ArgsUsage: "<path> [<path>]...",
				Action:    commands.WithRepo(commands.HandleAdd),
				Usage:     "Add a secret file or directory at `PATH`",
			},
			{
				Name:      "rm",
				ArgsUsage: "<path>",
				Action:    commands.WithRepo(commands.HandleRemove),
				Usage:     "Remove a secret file or directory",
			},
			{
				Name:   "apply",
				Hidden: true,
				Action: commands.HandleApply,
				Usage:  "Apply config differences to audit log and metadata",
			},
			{
				Name:   "tell",
				Flags:  flagsTell,
				Action: commands.WithRepo(commands.HandleTell),
				Usage:  "Add a person to a group and re-encrypt affected files",
			},
			{
				Name:   "kill",
				Flags:  flagsKill,
				Action: commands.WithRepo(commands.HandleKill),
				Usage:  "Remove a person from a group",
			},
			{
				Name:   "docgen",
				Hidden: true,
				Action: commands.HandleDocGen,
				Usage:  "Write a markdown command reference to stdout",
			},
			{
				Name:   "show",
				Flags:  flagsShow,
				Action: commands.HandleShow,
				Usage:  "Show objects managed by sesam",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name:      "object",
						UsageText: "<object>",
					},
				},
			},
			{
				Name:    "list",
				Aliases: []string{"ls"},
				Flags:   flagsListSecrets,
				Usage:   "List entities",
				Action: func(_ context.Context, _ *cli.Command) error {
					return fmt.Errorf("missing list target: use `sesam list secrets` or `sesam list users`")
				},
				Commands: []*cli.Command{
					{
						Name:   "secrets",
						Flags:  flagsListSecrets,
						Action: commands.WithRepo(commands.HandleListSecrets),
						Usage:  "List known secrets and metadata",
					}, {
						Name:   "users",
						Flags:  flagsListUsers,
						Action: commands.WithRepo(commands.HandleListUsers),
						Usage:  "List persons, groups, and access",
					},
				},
			},
			{
				Name:   "smudge",
				Hidden: true,
				Action: commands.HandleSmudge,
				Usage:  "Git smudge filter: reveal a secret to its plaintext path (called by git)",
			},
			{
				Name:   "clean",
				Action: commands.HandleClean,
				Usage:  "Remove revealed plaintext and other untracked files from the sesam directory",
				Flags:  flagsClean,
			},
			{
				Name:   "rotate",
				Hidden: true,
				Action: commands.HandleRotate,
				Usage:  "Plan and execute secret rotation",
				Commands: []*cli.Command{
					{
						Name:   "plan",
						Hidden: true,
						Action: commands.HandleRotatePlan,
						Usage:  "Show the rotation and exchange plan",
					}, {
						Name:   "exec",
						Hidden: true,
						Action: commands.HandleRotateExec,
						Usage:  "Execute the planned rotation",
					}, {
						Name:   "todo",
						Hidden: true,
						Action: commands.HandleRotateTodo,
						Usage:  "Show rotation tasks and follow-up status",
					},
				},
			},
		},
	}

	app.Before = func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if cmd.Bool("no-color") {
			// hack to make sure color is always ignored without passing it to everywhere we use termenv.
			_ = os.Setenv("NO_COLOR", "1")
		}

		logLevels := map[int]slog.Level{
			0: slog.LevelWarn,
			1: slog.LevelInfo,
			2: slog.LevelDebug,
		}

		logLevel, ok := logLevels[flagsVerboseCount]
		if !ok {
			logLevel = slog.LevelDebug
		}

		slog.SetDefault(slog.New(newPrettyHandler(os.Stderr, logLevel)))
		return ctx, nil
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	return app.Run(ctx, args)
}
