package cli

import "github.com/urfave/cli/v3"

// flagsGeneral are shared by most top-level commands.
//
// They describe the operator identity and repository/config roots.
var flagsGeneral = []cli.Flag{
	&cli.StringFlag{
		Name:    "identity",
		Aliases: []string{"i"},
		Usage:   "Path to the age identity",
	},
	&cli.StringFlag{
		Name:    "config",
		Aliases: []string{"c"},
		Value:   "sesam.yml",
		Usage:   "Path to the sesam config file",
	},
	&cli.StringFlag{
		Name:    "repo",
		Aliases: []string{"r"},
		Value:   ".",
		Usage:   "Path to the git repository",
	},
}

// flagsInit are specific to repository bootstrap.
var flagsInit = []cli.Flag{
	&cli.StringFlag{
		Name:     "user",
		Required: true,
		Usage:    "Initial admin user name",
	},
	&cli.StringFlag{
		Name:  "recipient",
		Usage: "Initial admin recipient key (for example github:alice; optional when derivable from --identity)",
	},
	&cli.BoolFlag{
		Name:  "use-root",
		Usage: "Allow init in a non-empty repository path",
	},
}

// flagsSeal contains optional controls for sealing.
var flagsSeal = []cli.Flag{}

// flagsReveal contains optional controls for reveal.
var flagsReveal = []cli.Flag{}
