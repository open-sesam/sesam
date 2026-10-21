//go:build docgen

package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/cli/docgen"
)

// HandleDocGenCLI writes a markdown CLI command reference to stdout.
func HandleDocGenCLI(_ context.Context, cmd *cli.Command) error {
	md, err := docgen.CLIReference(cmd.Root())
	if err != nil {
		return err
	}

	fmt.Println(md)
	return nil
}

// HandleDocGenConfig renders the config reference from sesam_schema.json to stdout.
func HandleDocGenConfig(_ context.Context, _ *cli.Command) error {
	md, err := docgen.ConfigReference()
	if err != nil {
		return err
	}

	_, err = os.Stdout.WriteString(md)
	return err
}

// HandleDocGenMan writes the sesam manual to stdout, as roff for man(1) or as
// the markdown it is assembled from. Constructs in the handbook that did not
// survive the conversion are reported on stderr.
func HandleDocGenMan(_ context.Context, cmd *cli.Command) error {
	handbook := cmd.String("handbook")
	if _, err := os.Stat(handbook); err != nil {
		return fmt.Errorf("handbook sources at %q: %w (run from the repo root or pass --handbook)", handbook, err)
	}

	ref, err := docgen.CLIReference(cmd.Root())
	if err != nil {
		return err
	}

	opts := docgen.ManualOptions{CLIReference: ref, Handbook: os.DirFS(handbook)}

	var (
		page     []byte
		warnings []docgen.Warning
	)

	switch format := cmd.String("format"); format {
	case "roff":
		page, warnings, err = docgen.Man(opts)
	case "markdown":
		var md string
		md, warnings, err = docgen.Markdown(opts)
		page = []byte(md)
	default:
		return fmt.Errorf("unknown manual format %q", format)
	}
	if err != nil {
		return err
	}

	for _, warning := range warnings {
		fmt.Fprintln(os.Stderr, handbook+"/"+warning.String())
	}

	_, err = os.Stdout.Write(page)
	return err
}
