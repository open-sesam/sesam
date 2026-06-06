package cli

import (
	"time"

	"github.com/urfave/cli/v3"
)

const flagUser = "user"

var flagsVerboseCount int

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
		Name:    "config",
		Aliases: []string{"c"},
		Value:   "sesam.yml",
		Usage:   "Path to the sesam config file",
		Sources: cli.EnvVars("SESAM_CONFIG"),
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
		Sources: cli.EnvVars("NO_COLOR"),
	},
	&cli.BoolFlag{
		Name:    "verbose",
		Aliases: []string{"v"},
		Usage:   "Print more log output",
		Config: cli.BoolConfig{
			Count: &flagsVerboseCount,
		},
	},
}

// flagsInit are specific to repository bootstrap.
var flagsInit = []cli.Flag{
	&cli.StringFlag{
		Name:  flagUser,
		Usage: "Initial admin user name (if not given, git config is used to guess)",
	},
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
	&cli.BoolFlag{
		Name:  "quiet",
		Usage: "Don't print files",
	},
}

// flagsReveal contains optional controls for reveal.
var flagsReveal = []cli.Flag{}

// flagsAdd contains controls for adding secrets.
var flagsAdd = []cli.Flag{
	&cli.StringSliceFlag{
		Name:     "group",
		Required: true,
		Usage:    "Group assignment for the secret (repeatable)",
	},
}

// flagsTell contains controls for adding users.
var flagsTell = []cli.Flag{
	&cli.StringFlag{
		Name:  flagUser,
		Usage: "User name to add",
	},
	&cli.StringSliceFlag{
		Name:     "recipient",
		Required: true,
		Usage:    "Recipient key spec (e.g. github:alice) - can be given several times",
	},
	&cli.StringSliceFlag{
		Name:     "group",
		Required: true,
		Usage:    "Group assignment (repeatable)",
	},
}

// flagsKill contains controls for removing users.
var flagsKill = []cli.Flag{
	&cli.StringFlag{
		Name:     flagUser,
		Required: true,
		Usage:    "User name to remove",
	},
}

// flagsListSecrets contains output controls for secret listing.
var flagsListSecrets = []cli.Flag{
	&cli.BoolFlag{
		Name:  "json",
		Usage: "Print output as JSON",
	},
}

// flagsListUsers contains output controls for user listing.
var flagsListUsers = []cli.Flag{
	&cli.BoolFlag{
		Name:  "json",
		Usage: "Print output as JSON",
	},
}

var flagsShow = []cli.Flag{}

var flagsLog = []cli.Flag{
	&cli.BoolFlag{
		Name:  "json",
		Usage: "Print as JSON",
	},
}
