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

var flagsInit = []cli.Flag{
	&cli.StringFlag{
		Name:  "user",
		Usage: "Initial admin user name (defaults to current OS user)",
	},
	&cli.StringFlag{
		Name:  "recipient",
		Usage: "Initial admin recipient key (optional when derivable from --identity)",
	},
}

var flagsSeal = []cli.Flag{
	&cli.StringFlag{
		Name:     "secret",
		Required: true,
		Usage:    "Path to the secret file to encrypt (relative to repo)",
	},
	&cli.StringFlag{
		Name:     "recipient",
		Required: true,
		Usage:    "Recipient key, forge id (github:user), or https:// key URL",
	},
	&cli.StringFlag{
		Name:     "user",
		Required: true,
		Usage:    "User name used for the signing key file",
	},
}

var flagsReveal = []cli.Flag{
	&cli.StringFlag{
		Name:     "secret",
		Required: true,
		Usage:    "Path to the secret file to decrypt (relative to repo)",
	},
	&cli.StringFlag{
		Name:     "user",
		Required: true,
		Usage:    "User name used for the signing key file",
	},
}
