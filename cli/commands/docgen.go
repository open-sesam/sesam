package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
)

// HandleDocGen writes a markdown command reference to stdout.
// The command is hidden from --help output; run via: sesam docgen
func HandleDocGen(_ context.Context, cmd *cli.Command) error {
	return renderCommandRef(os.Stdout, cmd.Root())
}

func renderCommandRef(w io.Writer, root *cli.Command) error {
	_, _ = fmt.Fprintf(w, "# sesam Command Reference\n\n")
	_, _ = fmt.Fprintf(w, "%s\n\n", root.Usage)

	if flags := visibleFlags(root.Flags); len(flags) > 0 {
		_, _ = fmt.Fprintf(w, "## Global Flags\n\n")
		writeFlagTable(w, flags)
		_, _ = fmt.Fprintf(w, "\n")
	}

	_, _ = fmt.Fprintf(w, "## Commands\n\n")

	for _, sub := range root.VisibleCommands() {
		writeCommand(w, sub, []string{root.Name}, 3)
	}

	_, _ = fmt.Fprintf(w, "\n> `*` - required flag\n")
	return nil
}

func writeCommand(w io.Writer, cmd *cli.Command, path []string, depth int) {
	heading := strings.Repeat("#", depth)
	fullName := strings.Join(append(path, cmd.Name), " ")

	_, _ = fmt.Fprintf(w, "%s `%s`\n\n", heading, fullName)

	if cmd.Usage != "" {
		_, _ = fmt.Fprintf(w, "%s\n\n", cmd.Usage)
	}

	if flags := visibleFlags(cmd.Flags); len(flags) > 0 {
		writeFlagTable(w, flags)
		_, _ = fmt.Fprintf(w, "\n")
	}

	for _, sub := range cmd.VisibleCommands() {
		writeCommand(w, sub, append(path, cmd.Name), depth+1)
	}
}

func writeFlagTable(w io.Writer, flags []cli.Flag) {
	_, _ = fmt.Fprintf(w, "| Flag | Default | Env | Description |\n")
	_, _ = fmt.Fprintf(w, "|------|---------|-----|-------------|\n")

	for _, f := range flags {
		names := flagNames(f)
		defVal := ""
		envVars := ""
		usage := ""

		if dg, ok := f.(cli.DocGenerationFlag); ok {
			// GetDefaultText only returns an explicit DefaultText override;
			// fall back to GetValue() for flags with a non-empty default Value.
			defVal = dg.GetDefaultText()
			if defVal == "" {
				v := dg.GetValue()
				// GetValue() wraps strings in quotes; strip them.
				v = strings.Trim(v, `"`)
				// Skip zero-value booleans - false is always the implicit default.
				if v != "false" {
					defVal = v
				}
			}
			usage = dg.GetUsage()
			if evs := dg.GetEnvVars(); len(evs) > 0 {
				quoted := make([]string, len(evs))
				for i, e := range evs {
					quoted[i] = "`" + e + "`"
				}
				envVars = strings.Join(quoted, ", ")
			}
		}

		req := ""
		if rf, ok := f.(cli.RequiredFlag); ok && rf.IsRequired() {
			req = " `*`"
		}

		if defVal != "" {
			defVal = "`" + defVal + "`"
		}

		_, _ = fmt.Fprintf(w, "| %s%s | %s | %s | %s |\n", names, req, defVal, envVars, usage)
	}
}

func flagNames(f cli.Flag) string {
	names := f.Names()
	parts := make([]string, len(names))
	for i, n := range names {
		if len(n) == 1 {
			parts[i] = "`-" + n + "`"
		} else {
			parts[i] = "`--" + n + "`"
		}
	}
	return strings.Join(parts, ", ")
}

// visibleFlags returns only non-hidden flags, excluding the auto-added --help flag.
func visibleFlags(flags []cli.Flag) []cli.Flag {
	var out []cli.Flag
	for _, f := range flags {
		if vf, ok := f.(cli.VisibleFlag); ok && !vf.IsVisible() {
			continue
		}
		if slices.Contains(f.Names(), "help") {
			continue
		}
		out = append(out, f)
	}
	return out
}
