package cli

import "github.com/urfave/cli/v3"

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
}

// flagsInit are specific to repository bootstrap.
var flagsInit = []cli.Flag{
	&cli.StringFlag{
		Name:     "user",
		Required: true,
		Usage:    "Initial admin user name",
	},
	&cli.BoolFlag{
		Name:  "use-root",
		Usage: "Initialize in the selected directory even when it already contains many files",
	},
}

// flagsSeal contains optional controls for sealing.
var flagsSeal = []cli.Flag{
	&cli.BoolFlag{
		Name:  "delete-revealed",
		Usage: "Delete revealed secret files after successful seal",
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
		Name:     "user",
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
		Name:     "user",
		Required: true,
		Usage:    "User name to remove",
	},
}
