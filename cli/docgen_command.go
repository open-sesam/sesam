//go:build docgen

package cli

import (
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/cli/commands"
	"opensesam.org/sesam/cli/docgen"
)

// docgenEnabled reports whether this build carries the doc generator.
const docgenEnabled = true //nolint:unused

func docgenCommands() []*cli.Command {
	return []*cli.Command{
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
				{
					Name:   "man",
					Action: commands.HandleDocGenMan,
					Usage:  "Write the sesam(1) manual to stdout",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:  "format",
							Value: "roff",
							Usage: "Output format: 'roff' for man(1), or 'markdown'",
						},
						&cli.StringFlag{
							Name:  "handbook",
							Value: docgen.DefaultHandbook,
							Usage: "Directory holding the mdbook sources",
						},
					},
				},
			},
		},
	}
}
