package docgen

import (
	"fmt"
	"os"
	"strings"

	clidocs "github.com/urfave/cli-docs/v3"
	"github.com/urfave/cli/v3"
)

// CLIReference renders the live command tree as markdown. The env vars a flag
// reads are folded into its usage text: the markdown template cli-docs uses
// drops them otherwise.
func CLIReference(root *cli.Command) (string, error) {
	stripHelpCommands(root, true)
	annotateEnvVars(root)

	return clidocs.ToMarkdown(root)
}

// stripHelpCommands recursively removes the auto-injected "help" subcommand.
// The root keeps its own, which is sesam's and carries --man.
func stripHelpCommands(cmd *cli.Command, isRoot bool) {
	kept := cmd.Commands[:0]
	for _, sub := range cmd.Commands {
		if sub.Name == "help" && !isRoot {
			continue
		}
		stripHelpCommands(sub, false)
		kept = append(kept, sub)
	}
	cmd.Commands = kept
}

// annotateEnvVars appends the environment variables a flag reads to its usage
// text, so they show up in the generated reference and man page.
func annotateEnvVars(cmd *cli.Command) {
	for _, flag := range cmd.Flags {
		doc, ok := flag.(cli.DocGenerationFlag)
		if !ok || len(doc.GetEnvVars()) == 0 {
			continue
		}

		names := make([]string, 0, len(doc.GetEnvVars()))
		for _, name := range doc.GetEnvVars() {
			names = append(names, "$"+name)
		}

		// The brackets are escaped: cli-docs appends "(default: ...)" right
		// after the usage, and "[...](...)" would turn into a markdown link.
		suffix := ` \[` + strings.Join(names, ", ") + `\]`
		if strings.HasSuffix(doc.GetUsage(), suffix) {
			continue
		}

		switch f := flag.(type) {
		case *cli.StringFlag:
			f.Usage += suffix
		case *cli.StringSliceFlag:
			f.Usage += suffix
		case *cli.BoolFlag:
			f.Usage += suffix
		case *cli.DurationFlag:
			f.Usage += suffix
		default:
			fmt.Fprintf(os.Stderr, "docgen: %T has env vars but no usage annotation\n", flag)
		}
	}

	for _, sub := range cmd.Commands {
		annotateEnvVars(sub)
	}
}
