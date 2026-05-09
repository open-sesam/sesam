package cli

import (
	"context"

	"github.com/open-sesam/sesam/config"
	"github.com/urfave/cli/v3"
)

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

var flagsModifyAddSecret = []cli.Flag{
	&cli.StringFlag{
		Name:  "type",
		Usage: "Type of secret (ssh_key,password,template,custom)",
		Action: func(_ context.Context, _ *cli.Command, v string) error {
			return config.VerifySecretType(v)
		},
	},
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
		Usage: "Group with access to this secret (can be given multiple times)",
	},
	&cli.StringFlag{
		Name:  "description",
		Usage: "Description of the secret",
	},
}

// flagsSeal contains optional controls for sealing.
var flagsSeal = []cli.Flag{}

// flagsReveal contains optional controls for reveal.
var flagsReveal = []cli.Flag{}

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

var flagsShow = []cli.Flag{}
