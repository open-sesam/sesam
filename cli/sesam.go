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
		_, _ = fmt.Fprintln(cmd.Root().Writer, cmd.Version)
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
				Name:   "deinit",
				Action: commands.HandleStub,
				Usage:  "Remove all traces of sesam",
			},
			{
				Name:   "verify",
				Flags:  flagsVerify,
				Action: commands.WithRepo(commands.HandleVerify),
				Usage:  "Verify sesam signatures and encryption state",
			},
			{
				Name:   "id",
				Flags:  flagsID,
				Action: commands.WithRepo(commands.HandleID),
				Usage:  "Identify the current user by age identity",
			},
			{
				Name:  "keyring",
				Usage: "Keyring utils",
				Commands: []*cli.Command{
					{
						Name:   "clear",
						Usage:  "Clear cached passphrases from the keyring",
						Action: commands.HandleKeyringClearCache,
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
				Name:          "open",
				Aliases:       []string{"reveal"},
				Flags:         flagsReveal,
				Action:        commands.WithRepo(commands.HandleOpen),
				ShellComplete: completeSecrets,
				Usage:         "Decrypt all secrets available to the current user",
			},
			{
				Name:   "log",
				Hidden: true,
				Flags:  flagsLog,
				Action: commands.WithRepo(commands.HandleLog),
				Usage:  "Show the audit log of secret changes",
			},
			{
				Name:          "add",
				Flags:         flagsAdd,
				ArgsUsage:     "<path> [<path>]...",
				Action:        commands.WithRepo(commands.HandleAdd),
				ShellComplete: completeFiles,
				Usage:         "Add a secret file or directory at `PATH`",
			},
			{
				Name:          "rm",
				ArgsUsage:     "<path>",
				Action:        commands.WithRepo(commands.HandleRemove),
				ShellComplete: completeSecrets,
				Usage:         "Remove a secret file or directory",
			},
			{
				Name:          "mv",
				Flags:         flagsMove,
				ArgsUsage:     "<oldpath> <newpath>",
				Action:        commands.WithRepo(commands.HandleMove),
				ShellComplete: completeSecrets,
				Usage:         "Move a secret file or directory to a new name",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name:      "oldpath",
						UsageText: "The old revealed path to move from",
					},
					&cli.StringArg{
						Name:      "newpath",
						UsageText: "The new revealed path to move to",
					},
				},
			},
			{
				Name:          "status",
				Action:        commands.WithRepo(commands.HandleStatus),
				Flags:         flagsStatus,
				ShellComplete: completeFlags,
				Usage:         "Show secrets that are not sealed yet",
			},
			{
				Name:   "apply",
				Action: commands.HandleStub,
				Usage:  "alias for `sesam config apply`",
			},
			{
				Name:  "config",
				Usage: "Config management commands",
				Commands: []*cli.Command{
					{
						Name:   "apply",
						Usage:  "Apply config differences to audit log and metadata",
						Action: commands.HandleStub,
					},
					{
						Name:   "diff",
						Usage:  "Show the diff between config and actual state",
						Action: commands.HandleStub,
					},
					{
						Name:   "get",
						Usage:  "Get specific config keys",
						Action: commands.HandleStub,
					},
					{
						Name:   "set",
						Usage:  "Set specific config keys",
						Action: commands.HandleStub,
					},
				},
			},
			{
				Name:   "edit",
				Action: commands.HandleStub,
				Usage:  "Edit an secret and immeediately seal it afterwards",
			},
			{
				Name:   "doctor",
				Action: commands.HandleStub,
				Usage:  "Check sesam installation for possible problems",
			},
			{
				Name:          "tell",
				Flags:         flagsTell,
				Action:        commands.WithRepo(commands.HandleTell),
				ShellComplete: completeFlags,
				Usage:         "Add a person to a group and re-encrypt affected files",
			},
			{
				Name:          "kill",
				Flags:         flagsKill,
				Action:        commands.WithRepo(commands.HandleKill),
				ShellComplete: completeUsers,
				Usage:         "Remove a person from a group",
			},
			{
				Name:   "docgen",
				Hidden: true,
				Action: commands.HandleDocGen,
				Usage:  "Write a markdown command reference to stdout",
			},
			{
				Name:          "show",
				Flags:         flagsShow,
				Action:        commands.HandleShow,
				ShellComplete: completeSecrets,
				Usage:         "Show objects managed by sesam",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name:      "object",
						UsageText: "<object>",
					},
				},
			},

			{
				Name:    "user",
				Aliases: []string{"u"},
				Usage:   "User management commands",
				Commands: []*cli.Command{
					{
						Name:   "list",
						Flags:  flagsListUsers,
						Action: commands.WithRepo(commands.HandleListUsers),
						Usage:  "List persons, groups, and access",
					},
					{
						Name:   "change-groups",
						Flags:  flagsUserChangeGroups,
						Action: commands.WithRepo(commands.HandleUserChangeGroups),
						Usage:  "Change the groups a user is in",
					},
					{
						Name:   "rename",
						Flags:  flagsRenameUser,
						Action: commands.WithRepo(commands.HandleRenameUser),
						Usage:  "Give a user a different name",
						Arguments: []cli.Argument{
							&cli.StringArg{
								Name:      "olduser",
								UsageText: "The old user name",
							},
							&cli.StringArg{
								Name:      "newuser",
								UsageText: "The new user name",
							},
						},
					},
				},
			},
			{
				Name:    "ls",
				Aliases: []string{"list-secrets"},
				Flags:   flagsListSecrets,
				Action:  commands.WithRepo(commands.HandleListSecrets),
				Usage:   "List known secrets and metadata",
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
				Action: commands.HandleStub,
				Usage:  "Plan and execute secret rotation",
				Commands: []*cli.Command{
					{
						Name:   "plan",
						Hidden: true,
						Action: commands.HandleStub,
						Usage:  "Show the rotation and exchange plan",
					}, {
						Name:   "exec",
						Hidden: true,
						Action: commands.HandleStub,
						Usage:  "Execute the planned rotation",
					}, {
						Name:   "todo",
						Hidden: true,
						Action: commands.HandleStub,
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
			-1: slog.LevelWarn,
			+0: slog.LevelInfo,
			+1: slog.LevelDebug,
		}

		logLevel, ok := logLevels[flagsVerboseCount-flagsQuietCount]
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
