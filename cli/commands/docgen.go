package commands

import (
	"context"
	"fmt"

	clidocs "github.com/urfave/cli-docs/v3"
	"github.com/urfave/cli/v3"
)

// HandleDocGen writes a markdown command reference to stdout.
// The command is hidden from --help output; run via: sesam docgen
func HandleDocGen(_ context.Context, cmd *cli.Command) error {
	// urfave/cli auto-injects a "help" subcommand into every command during
	// setup. It is not marked Hidden, so cli-docs renders it for each command.
	// Strip it from the tree before generating the reference.
	root := cmd.Root()
	stripHelpCommands(root)

	md, err := clidocs.ToMarkdown(root)
	// md, err := clidocs.ToTabularMarkdown(cmd.Root(), "./sesam")
	if err != nil {
		return err
	}

	fmt.Println(md)
	return nil
}

// stripHelpCommands recursively removes the auto-injected "help" subcommand
// from cmd and all of its descendants.
func stripHelpCommands(cmd *cli.Command) {
	kept := cmd.Commands[:0]
	for _, sub := range cmd.Commands {
		if sub.Name == "help" {
			continue
		}
		stripHelpCommands(sub)
		kept = append(kept, sub)
	}
	cmd.Commands = kept
}
