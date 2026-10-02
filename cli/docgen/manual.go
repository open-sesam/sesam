package docgen

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/cpuguy83/go-md2man/v2/md2man"
)

// DefaultHandbook is where the mdbook sources live, relative to the repo root.
const DefaultHandbook = "docs/src"

// Section is one chapter of the sesam manual. Title is the man page section
// heading, File the handbook page under docs/src the body comes from; an empty
// File means the body is taken from the generated CLI reference instead.
type Section struct {
	Title string
	File  string
}

// ManualOptions carries the parts of the manual that are generated from the
// live command tree rather than read from the handbook.
type ManualOptions struct {
	// CLIReference is the markdown command reference, as produced by
	// cli-docs. Its level-one sections are spliced in by title.
	CLIReference string

	// Handbook holds the mdbook pages, i.e. os.DirFS(DefaultHandbook). It is
	// passed in rather than embedded so that docs/ stays a pure mdbook
	// project; the generator only ever runs from the repo.
	Handbook fs.FS
}

// manualSections are the handbook pages that make up the man page, in order.
// The tutorial pages and the FAQ are in; design.md, alternatives.md and
// installation.md are deliberately not - they are either internal or useless
// to a reader who already has the binary in front of them.
var manualSections = []Section{
	{Title: "DESCRIPTION", File: "whatis.md"},
	{Title: "GLOBAL OPTIONS"},
	{Title: "COMMANDS"},
	{Title: "GETTING STARTED", File: "init.md"},
	{Title: "MANAGING SECRETS", File: "secret.md"},
	{Title: "MANAGING USERS", File: "users.md"},
	{Title: "GIT INTEGRATION", File: "git_integration.md"},
	{Title: "VERIFYING", File: "verify.md"},
	{Title: "TEMPLATE SECRETS", File: "template.md"},
	{Title: "KEY ROTATION", File: "rotation.md"},
	{Title: "FREQUENTLY ASKED QUESTIONS", File: "faq.md"},
}

// titleHeading is what md2man turns into the .TH line. It carries no version
// or date on purpose: the page is a committed artifact, and per-build metadata
// would make it churn on every regeneration.
const titleHeading = "# sesam 1 \"\" \"sesam\" \"Sesam Manual\"\n"

const seeAlso = `# SEE ALSO

Handbook: <https://opensesam.org>

Source, issues and discussions: <https://github.com/open-sesam/sesam>
`

// Markdown assembles the complete manual as man-ready markdown. The returned
// warnings point at handbook constructs that did not convert cleanly.
func Markdown(opts ManualOptions) (string, []Warning, error) {
	if opts.Handbook == nil {
		return "", nil, fmt.Errorf("no handbook source given")
	}

	ref, err := splitReference(opts.CLIReference)
	if err != nil {
		return "", nil, err
	}

	known := make(map[string]bool, len(manualSections))
	for _, sec := range manualSections {
		if sec.File != "" {
			known[sec.File] = true
		}
	}

	var (
		out      strings.Builder
		warnings []Warning
	)

	for _, name := range []string{"NAME", "SYNOPSIS"} {
		body, ok := ref[name]
		if !ok {
			return "", nil, fmt.Errorf("cli reference has no %s section", name)
		}
		writeSection(&out, name, body)
	}

	for _, sec := range manualSections {
		if sec.File == "" {
			body, ok := ref[sec.Title]
			if !ok {
				return "", nil, fmt.Errorf("cli reference has no %s section", sec.Title)
			}

			san := &sanitizer{file: "cli_ref.md", known: known}
			writeSection(&out, sec.Title, san.reference(body))
			warnings = append(warnings, san.warnings...)
			continue
		}

		raw, err := fs.ReadFile(opts.Handbook, sec.File)
		if err != nil {
			return "", nil, fmt.Errorf("read handbook page: %w", err)
		}

		san := &sanitizer{file: sec.File, known: known}
		writeSection(&out, sec.Title, san.prose(string(raw)))
		warnings = append(warnings, san.warnings...)
	}

	out.WriteString("\n")
	out.WriteString(seeAlso)

	sort.SliceStable(warnings, func(i, j int) bool {
		if warnings[i].File != warnings[j].File {
			return warnings[i].File < warnings[j].File
		}
		return warnings[i].Line < warnings[j].Line
	})

	return out.String(), warnings, nil
}

// Man renders the manual as roff, ready for man(1). The title heading only
// goes in here: it is the .TH line md2man needs, and reads as noise in the
// markdown the pager fallback shows.
func Man(opts ManualOptions) ([]byte, []Warning, error) {
	md, warnings, err := Markdown(opts)
	if err != nil {
		return nil, nil, err
	}
	return md2man.Render([]byte(titleHeading + md)), warnings, nil
}

func writeSection(out *strings.Builder, title, body string) {
	out.WriteString("\n# " + title + "\n\n")
	out.WriteString(strings.Trim(body, "\n"))
	out.WriteString("\n")
}

// splitReference breaks the generated CLI reference into its level-one
// sections, keyed by heading.
func splitReference(md string) (map[string]string, error) {
	if strings.TrimSpace(md) == "" {
		return nil, fmt.Errorf("cli reference is empty")
	}

	var (
		out     = map[string]string{}
		current string
		body    strings.Builder
		f       fence
	)

	flush := func() {
		if current != "" {
			out[current] = body.String()
		}
		body.Reset()
	}

	for _, text := range strings.Split(md, "\n") {
		if !f.toggle(text) && !f.inside() && headingLevel(text) == 1 {
			flush()
			current = strings.TrimSpace(text[1:])
			continue
		}
		body.WriteString(text)
		body.WriteString("\n")
	}
	flush()

	return out, nil
}
