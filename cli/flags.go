package cli

import (
	"time"

	"github.com/urfave/cli/v3"
)

const flagUser = "user"

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
}

// flagsInit are specific to repository bootstrap.
var flagsInit = []cli.Flag{
	&cli.StringFlag{
		Name:     flagUser,
		Required: true,
		Usage:    "Initial admin user name",
	},
	&cli.BoolFlag{
		Name:  "use-root",
		Usage: "Initialize in the selected directory even when it already contains many files",
	},
}

var flagsModifyAddSecret = []cli.Flag{
	&cli.StringFlag{
		Name:     "path",
		Required: true,
		Usage:    "Path to the secret which should be added",
	},
	&cli.StringFlag{
		Name:  "name",
		Usage: "Name of the secret (filename if empty)",
	},
	&cli.StringSliceFlag{
		Name:  "access",
		Usage: "Group with access to this secret (can be given multiple times) (optional)",
		Value: []string{"admin"},
	},
	&cli.StringFlag{
		Name:  "description",
		Usage: "Description of the secret (optional)",
	},
	&cli.BoolFlag{
		Name: "own-sesam-file",
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
	&cli.BoolFlag{
		Name:  "own-sesam-file",
		Usage: "When the secret lives in a subdirectory, give that directory its own sesam.yml instead of adding it to the main file",
	},
}

var flagsRemove = []cli.Flag{
	&cli.BoolFlag{
		Name:  "purge",
		Usage: "Purge removes all revealed files matching the given path from disk as well",
	},
}

// flagsTell contains controls for adding users.
var flagsTell = []cli.Flag{
	&cli.StringFlag{
		Name:     flagUser,
		Required: true,
		Usage:    "User name to add",
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
