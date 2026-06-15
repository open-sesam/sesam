package cli

import (
	"time"

	"github.com/urfave/cli/v3"
)

const flagUser = "user"

var (
	flagsVerboseCount int
	flagsQuietCount   int
)

// Shared flags reused by several commands, defined once and appended to the
// flag sets that need them.

// flagJSON toggles machine-readable JSON output.
var flagJSON = &cli.BoolFlag{
	Name:  "json",
	Usage: "Print output as JSON",
}

// flagNoSeal skips the implicit `sesam seal` that normally follows a mutating
// command - handy when batching several changes into one seal.
var flagNoSeal = &cli.BoolFlag{
	Name:  "no-seal",
	Usage: "Do not run `sesam seal` afterwards - useful when batching",
}

// userFlag builds the --user flag. Required-ness and help text differ per
// command (init guesses from git, kill needs it), so it is parametrized rather
// than a single shared variable.
func userFlag(required bool, usage string) cli.Flag {
	return &cli.StringFlag{
		Name:     flagUser,
		Required: required,
		Usage:    usage,
	}
}

// groupFlag builds the repeatable --group flag. Required-ness varies per command.
func groupFlag(required bool, usage string) cli.Flag {
	return &cli.StringSliceFlag{
		Name:     "group",
		Required: required,
		Usage:    usage,
	}
}

func recipientsFlag(required bool) cli.Flag {
	return &cli.StringSliceFlag{
		Name:     "recipient",
		Required: required,
		Usage:    "Recipient key spec (e.g. github:alice) - can be given several times",
	}
}

// flagsGeneral are shared by most top-level commands.
//
// They describe the operator identity and repository/config roots.
var flagsGeneral = []cli.Flag{
	&cli.StringSliceFlag{
		Name:    "identity",
		Aliases: []string{"i"},
		Usage:   "Path to the age identity (can be given several times)",
		Sources: cli.EnvVars("SESAM_ID", "SESAM_IDENTITY"),
	},
	&cli.StringFlag{
		Name:    "sesam-dir",
		Aliases: []string{"r", "repo"},
		Value:   ".",
		Usage:   "Directory where .sesam lives",
		Sources: cli.EnvVars("SESAM_DIR"),
	},
	&cli.DurationFlag{
		Name:    "lock-timeout",
		Value:   5 * time.Second,
		Usage:   "Repository lock wait timeout (e.g. 5s, 30s, 2m)",
		Sources: cli.EnvVars("SESAM_LOCK_TIMEOUT"),
	},
	&cli.BoolFlag{
		Name:    "no-color",
		Usage:   "Disable color always",
		Sources: cli.EnvVars("NO_COLOR", "SESAM_NO_COLOR"),
	},
	&cli.BoolFlag{
		Name:    "verbose",
		Aliases: []string{"v"},
		Usage:   "Print more log output",
		Config: cli.BoolConfig{
			Count: &flagsVerboseCount,
		},
	},
	&cli.BoolFlag{
		Name:    "quiet",
		Aliases: []string{"q"},
		Usage:   "Print less log output",
		Config: cli.BoolConfig{
			Count: &flagsQuietCount,
		},
	},
	&cli.StringFlag{
		Name:  "verify-mode",
		Usage: "Adjust how strong or weak the disk state is verified ('all', or 'no-disk')",
		Value: "all",
	},
}

// flagsInit are specific to repository bootstrap.
var flagsInit = []cli.Flag{
	userFlag(false, "Initial admin user name (if not given, git config is used to guess)"),
}

// flagsSeal contains optional controls for sealing.
var flagsSeal = []cli.Flag{
	&cli.BoolFlag{
		Name:  "clean",
		Usage: "Delete revealed secret files after successful seal",
	},
}

var flagsClean = []cli.Flag{
	&cli.BoolFlag{
		Name:  "aggressive",
		Usage: "Also delete other untracked files (similar to `git clean -fdx`)",
	},
	&cli.BoolFlag{
		Name:  "dry-run",
		Usage: "Do not actually delete, just print what would be deleted",
	},
}

// flagsReveal contains optional controls for reveal.
var flagsReveal = []cli.Flag{}

// flagsAdd contains controls for adding secrets.
var flagsAdd = []cli.Flag{
	groupFlag(false, "Group assignment for the secret (repeatable) - 'admin' is implicit"),
	flagNoSeal,
}

var flagsMove = []cli.Flag{}

// flagsTell contains controls for adding users.
var flagsTell = []cli.Flag{
	userFlag(false, "User name to add"),
	recipientsFlag(true),
	groupFlag(true, "Group assignment (repeatable)"),
	flagNoSeal,
}

// flagsKill contains controls for removing users.
var flagsKill = []cli.Flag{
	userFlag(true, "User name to remove"),
	flagNoSeal,
}

// flagsListSecrets contains output controls for secret listing.
var flagsListSecrets = []cli.Flag{flagJSON}

// flagsListUsers contains output controls for user listing.
var flagsListUsers = []cli.Flag{flagJSON}

var flagsRenameUser = []cli.Flag{}

var flagsUserChangeGroups = []cli.Flag{
	userFlag(true, "Which user should be changed"),
	groupFlag(true, "Group assignment for the secret (repeatable) - 'admin' is implicit"),
	flagNoSeal,
}

var flagsUserAddRecipient = []cli.Flag{
	userFlag(true, "Which user receives the new recipient"),
	recipientsFlag(true),
	flagNoSeal,
}

var flagsUserRemoveRecipient = []cli.Flag{
	userFlag(true, "Which user looses the specified recipient"),
	recipientsFlag(true),
	flagNoSeal,
}

var flagsShow = []cli.Flag{}

var flagsLog = []cli.Flag{
	&cli.BoolFlag{
		Name:    "full",
		Aliases: []string{"f"},
		Usage:   "Show full timestamps and ids instead of shortened ones",
	},
	flagJSON,
}

var flagsID = []cli.Flag{flagJSON}

var flagsStatus = []cli.Flag{
	&cli.BoolFlag{
		Name:    "diff",
		Aliases: []string{"d"},
		Usage:   "Show the actual diff using git (extra args are passed to git)",
	},
	&cli.BoolFlag{
		Name:    "users",
		Aliases: []string{"u"},
		Usage:   "Show users instead of groups",
	},
	&cli.BoolFlag{
		Name:    "all",
		Aliases: []string{"a"},
		Usage:   "Also show in-sync secrets and unmanaged files (hidden by default)",
	},
	flagJSON,
}

var flagsVerify = []cli.Flag{
	&cli.BoolFlag{
		Name:  "all",
		Usage: "Run all verifications",
	},
	&cli.BoolFlag{
		Name:  "truncate",
		Usage: "Verify the audit log was not truncated over history",
	},
	&cli.BoolFlag{
		Name:  "forge-check",
		Usage: "Verify the forge public keys did not change since adding users",
	},
	&cli.BoolFlag{
		Name:  "key-reuse",
		Usage: "Double-check that no key is re-used between users",
	},
	&cli.BoolFlag{
		Name:  "integrity",
		Usage: "Check file integrity on disk",
	},
	flagJSON,
	// TODO: Probably need a config linter here too at some point.
}
