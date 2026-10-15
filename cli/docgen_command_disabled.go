//go:build !docgen

package cli

import "github.com/urfave/cli/v3"

const docgenEnabled = false //nolint:unused

// docgenCommands is empty in a release build - see docgen.go.
func docgenCommands() []*cli.Command {
	return nil
}
