package cli

import (
	"io"
	"strings"
	"text/template"

	"github.com/urfave/cli/v3"
)

// installHelpOrdering makes `sesam --help` render command categories in the
// declared order instead of urfave/cli's hard-coded lexicographic sort.
func installHelpOrdering() {
	const categoryLoopCall = `{{template "visibleCommandCategoryTemplate" .}}`

	// Mirrors urfave's visibleCommandCategoryTemplate, with trimCat wrapping
	// the label so the numeric sort-prefix never reaches the terminal.
	const orderedCategoryLoop = `{{range .VisibleCategories}}{{if .Name}}

   {{trimCat .Name}}:{{range .VisibleCommands}}
     {{join .Names ", "}}{{"\t"}}{{.Usage}}{{end}}{{else}}{{template "visibleCommandTemplate" .}}{{end}}{{end}}`

	cli.RootCommandHelpTemplate = strings.Replace(
		cli.RootCommandHelpTemplate,
		categoryLoopCall,
		orderedCategoryLoop,
		1,
	)

	// The per-command and per-subcommand help topics print the raw category in
	// their CATEGORY section; route those through trimCat too so the numeric
	// sort-prefix (e.g. "20\x1f") never reaches the terminal.
	cli.CommandHelpTemplate = strings.ReplaceAll(cli.CommandHelpTemplate, "{{.Category}}", "{{trimCat .Category}}")
	cli.SubcommandHelpTemplate = strings.ReplaceAll(cli.SubcommandHelpTemplate, "{{.Category}}", "{{trimCat .Category}}")

	cli.HelpPrinter = func(w io.Writer, templ string, data any) {
		cli.HelpPrinterCustom(w, templ, data, template.FuncMap{
			"trimCat": trimCat,
		})
	}
}

// trimCat drops the numeric sort-prefix (e.g. "10\x1f") from a category label,
// leaving the human-readable name. Labels without a separator pass through.
func trimCat(name string) string {
	if _, rest, ok := strings.Cut(name, catSep); ok {
		return rest
	}
	return name
}
