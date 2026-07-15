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

// Command categories group subcommands in `sesam --help`. urfave/cli sorts
// categories lexicographically by name with no ordering hook, so each label
// carries a numeric sort-prefix (gaps of ten leave room to insert later).
// installHelpOrdering strips the prefix before display - see help.go.
const catSep = "\x1f" // ASCII unit separator; never appears in a real label

const (
	catRepository = "10" + catSep + "REPOSITORY"
	catSecrets    = "20" + catSep + "SECRETS"
	catAccess     = "30" + catSep + "ACCESS"
	catConfig     = "40" + catSep + "CONFIG"
	catMeta       = "50" + catSep + "META"
)

// Main builds and runs the sesam CLI command tree.
//
// Commands wrapped in commands.WithRepo load a sesam Repo (acquire lock,
// build managers, defer Close) and hand it to the handler; the wrapping
// makes it obvious which commands need an initialized sesam repository.
func Main(args []string) error {
	installHelpOrdering()

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
			// --- Repository: set up, tear down, and keep a repo healthy ---
			{
				Name:     "init",
				Category: catRepository,
				Flags:    flagsInit,
				Action:   commands.HandleInit,
				Usage:    "Initialize sesam in the current repository",
			},
			{
				Name:     "uninstall",
				Category: catRepository,
				Flags:    flagsUninstall,
				Action:   commands.HandleUninstall,
				Usage:    "Removes git integration and optionally all of the sesam repo",
			},
			{
				Name:     "verify",
				Category: catRepository,
				Flags:    flagsVerify,
				Action:   commands.WithRepo(commands.HandleVerify),
				Usage:    "Verify sesam signatures and encryption state",
			},
			{
				Name:     "clean",
				Category: catRepository,
				Action:   commands.HandleClean,
				Usage:    "Remove revealed plaintext and other untracked files from the sesam directory",
				Flags:    flagsClean,
			},
			{
				Name:     "doctor",
				Category: catRepository,
				Action:   commands.HandleDoctor,
				Usage:    "Check sesam installation for possible problems",
			},
			{
				Name:     "merge",
				Hidden:   true,
				Category: catRepository,
				Usage:    "Merge driver (should be called by git)",
				Commands: []*cli.Command{
					{
						Name:   "secret",
						Usage:  "Merge secrets",
						Action: commands.HandleStub,
					},
					{
						Name:   "log",
						Usage:  "Merge audit log",
						Action: commands.HandleStub,
					},
				},
			},
			{
				Name:     "hook",
				Category: catRepository,
				Usage:    "Util to manage git hooks",
				Commands: []*cli.Command{
					{
						Name:   "pre-commit",
						Usage:  "Execute the pre-commit hook - meant to be run by git!",
						Action: commands.HandleHookPreCommit,
					},
					{
						Name:   "post-checkout",
						Usage:  "Execute the post-checkout hook - meant to be run by git!",
						Action: commands.HandleHookPostCheckout,
					},
					{
						Name:   "install",
						Usage:  "Make sure the git hooks are installed",
						Action: commands.HandleHookInstall,
					},
					{
						Name:   "uninstall",
						Usage:  "Uninstall any hooks",
						Action: commands.HandleHookUninstall,
					},
				},
			},

			// --- Secrets: manage which files are secrets and their content ---
			{
				Name:          "add",
				Category:      catSecrets,
				Flags:         flagsAdd,
				ArgsUsage:     "<path> [<path>]...",
				Action:        commands.WithRepo(commands.HandleAdd),
				ShellComplete: completeFiles,
				Usage:         "Add a secret file or directory at `PATH`",
			},
			{
				Name:          "rm",
				Category:      catSecrets,
				ArgsUsage:     "<path>",
				Flags:         flagsRm,
				Action:        commands.WithRepo(commands.HandleRemove),
				ShellComplete: completeSecrets,
				Usage:         "Remove a secret file or directory",
			},
			{
				Name:          "mv",
				Category:      catSecrets,
				Flags:         flagsMove,
				ArgsUsage:     "<oldpath> <newpath>",
				Action:        commands.WithRepo(commands.HandleMove),
				ShellComplete: completeSecrets,
				Usage:         "Move a secret file or directory to a new name",
				Arguments: []cli.Argument{
					&cli.StringArg{
						Name:      "oldpath",
						UsageText: "<OLD_PATH>",
					},
					&cli.StringArg{
						Name:      "newpath",
						UsageText: "<NEW_PATH>",
					},
				},
			},
			{
				Name:     "edit",
				Category: catSecrets,
				Action:   commands.HandleStub,
				Usage:    "Open secret in $EDITOR and immediately seal it afterwards",
			},
			{
				Name:     "seal",
				Category: catSecrets,
				Flags:    flagsSeal,
				Action:   commands.WithRepo(commands.HandleSeal),
				Usage:    "Encrypt and sign changed secrets",
			},
			{
				Name:          "open",
				Category:      catSecrets,
				Aliases:       []string{"reveal"},
				Flags:         flagsReveal,
				Action:        commands.WithRepo(commands.HandleOpen),
				ShellComplete: completeSecrets,
				Usage:         "Decrypt all secrets available to the current user",
			},
			{
				Name:          "status",
				Aliases:       []string{"s"},
				Category:      catSecrets,
				Action:        commands.WithRepo(commands.HandleStatus),
				Flags:         flagsStatus,
				ShellComplete: completeFlags,
				Usage:         "Show overview over repo state (revealed, sealed, unmanaged, ...)",
			},
			{
				Name:          "show",
				Category:      catSecrets,
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
				Name:     "ls",
				Category: catSecrets,
				Aliases:  []string{"list-secrets"},
				Flags:    flagsListSecrets,
				Action:   commands.WithRepo(commands.HandleListSecrets),
				Usage:    "List known secrets and metadata",
				Arguments: []cli.Argument{
					&cli.StringArgs{
						Name:      "dir",
						UsageText: "[<DIR>...]",
						Max:       255, // apparently we have to set max to something here...
					},
				},
			},
			{
				Name:     "rotate",
				Category: catSecrets,
				Action:   commands.HandleStub,
				Usage:    "Plan and execute secret rotation",
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

			// --- Access: who can read which secrets ---
			{
				Name:          "tell",
				Category:      catAccess,
				Flags:         flagsTell,
				Action:        commands.WithRepo(commands.HandleTell),
				ShellComplete: completeFlags,
				Usage:         "Add a person to a group and re-encrypt files",
			},
			{
				Name:          "kill",
				Category:      catAccess,
				Flags:         flagsKill,
				Action:        commands.WithRepo(commands.HandleKill),
				ShellComplete: completeUsers,
				Usage:         "Remove a person from the sesam repo entirely",
			},
			{
				Name:     "user",
				Category: catAccess,
				Aliases:  []string{"u"},
				Usage:    "User management commands",
				Commands: []*cli.Command{
					{
						Name:    "list",
						Aliases: []string{"ls"},
						Flags:   flagsListUsers,
						Action:  commands.WithRepo(commands.HandleListUsers),
						Usage:   "List persons, groups, and access",
					},
					{
						Name:   "change-groups",
						Flags:  flagsUserChangeGroups,
						Action: commands.WithRepo(commands.HandleUserChangeGroups),
						Usage:  "Change the groups a user is in",
					},
					{
						Name:    "add-recipient",
						Aliases: []string{"ar"},
						Flags:   flagsUserAddRecipient,
						Action:  commands.WithRepo(commands.HandleUserAddRecipient),
						Usage:   "Add a recipient to an existing user",
					},
					{
						Name:    "remove-recipient",
						Aliases: []string{"rr"},
						Flags:   flagsUserRemoveRecipient,
						Action:  commands.WithRepo(commands.HandleUserRemoveRecipient),
						Usage:   "Remove a recipient from an existing user (may not be the last one)",
					},
					{
						Name:    "regen-sign-key",
						Aliases: []string{"rsk"},
						Flags:   flagsUserRegenerateSignKey,
						Action:  commands.WithRepo(commands.HandleUserRegenerateSignKey),
						Usage:   "Regenerate the signing key of a specific user",
					},
					{
						Name:   "rename",
						Flags:  flagsRenameUser,
						Action: commands.WithRepo(commands.HandleRenameUser),
						Usage:  "Give a user a different name",
						Arguments: []cli.Argument{
							&cli.StringArg{
								Name:      "olduser",
								UsageText: "<OLD_NAME>",
							},
							&cli.StringArg{
								Name:      "newuser",
								UsageText: "<NEW_NAME>",
							},
						},
					},
				},
			},

			// --- Config: the declarative sesam.yml workflow ---
			{
				Name:     "apply",
				Usage:    "Alias for `sesam config apply`",
				Action:   commands.HandleStub,
				Category: catConfig,
			},
			{
				Name:     "config",
				Category: catConfig,
				Usage:    "Config management commands",
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
					{
						Name:   "reset",
						Usage:  "Set specific config keys",
						Action: commands.HandleStub,
					},
				},
			},
			{
				Name:     "apply",
				Category: catConfig,
				Action:   commands.HandleStub,
				Usage:    "alias for `sesam config apply`",
			},

			// --- Meta: identity, audit, and local caches ---
			{
				Name:     "id",
				Category: catMeta,
				Flags:    flagsID,
				Action:   commands.WithRepo(commands.HandleID),
				Usage:    "Identify the current user by age identity",
			},
			{
				Name:     "keyring",
				Category: catMeta,
				Usage:    "Keyring utils",
				Commands: []*cli.Command{
					{
						Name:   "clear",
						Usage:  "Clear cached passphrases from the keyring",
						Action: commands.HandleKeyringClearCache,
					},
				},
			},
			{
				Name:     "log",
				Category: catMeta,
				Flags:    flagsLog,
				Action:   commands.WithRepo(commands.HandleLog),
				Usage:    "Show the audit log of secret changes",
			},
			{
				Name:   "docgen",
				Hidden: true,
				Usage:  "Generate reference documentation",
				Commands: []*cli.Command{
					{
						Name:   "cli",
						Action: commands.HandleDocGenCLI,
						Usage:  "Write a markdown CLI reference to stdout",
					},
					{
						Name:   "config",
						Action: commands.HandleDocGenConfig,
						Usage:  "Write a markdown config reference to stdout",
					},
				},
			},
		},
	}

	var activeProfile *profileState

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

		p, err := startProfiling(cmd.String("cpuprofile"))
		if err != nil {
			return ctx, err
		}
		activeProfile = p
		return ctx, nil
	}

	// After runs like a deferred cleanup (also on a failed action), so the CPU
	// profile is always flushed and the heap profile captured at exit.
	app.After = func(_ context.Context, cmd *cli.Command) error {
		return activeProfile.stop(cmd.String("memprofile"))
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	defer cancel()

	return app.Run(ctx, args)
}
