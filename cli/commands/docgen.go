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
	md, err := clidocs.ToMarkdown(cmd.Root())
	// md, err := clidocs.ToTabularMarkdown(cmd.Root(), "./sesam")
	if err != nil {
		return err
	}

	fmt.Println(md)
	return nil
}
