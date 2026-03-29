package cli

import "github.com/urfave/cli/v3"

var flagsGeneral = []cli.Flag{
	&cli.StringFlag{
		Name:    "identity",
		Aliases: []string{"i"},
		Value:   "~/.config/sesam/key.txt",
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
