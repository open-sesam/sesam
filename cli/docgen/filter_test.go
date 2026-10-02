package docgen

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizerProse(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		want     string
		warnings []Warning
	}{
		{
			name: "title heading is dropped and subheadings become subsections",
			src:  "# Page\n\n## Section\n\n### Deeper\n",
			want: "\n### Section\n\n### Deeper\n",
		},
		{
			name: "code fences keep their content verbatim",
			src:  "# Page\n\n```bash\n# not a heading\n[a](./init.md)\n```\n",
			want: "\n```bash\n# not a heading\n[a](./init.md)\n```\n",
		},
		{
			name: "skip region is dropped",
			src:  "# Page\n\nkeep\n\n<!-- man:skip-start -->\ngone\n<!-- man:skip-end -->\n\nkeep too\n",
			want: "\nkeep\n\n\nkeep too\n",
		},
		{
			name: "skip marker drops the whole section up to the next same-level heading",
			src:  "# Page\n\n## Gone\n\n<!-- man:skip -->\n\nbody\n\n### Also gone\n\nmore\n\n## Kept\n\nyes\n",
			want: "\n### Kept\n\nyes\n",
		},
		{
			name: "html block is dropped",
			src:  "# Page\n\n<div class=\"x\">\n  <img src=\"a.png\" />\n</div>\n\ntext\n",
			want: "\n\ntext\n",
			warnings: []Warning{
				{File: "p.md", Line: 3, Kind: WarnHTML, Detail: "dropped <div> block"},
			},
		},
		{
			name: "void tag does not swallow the rest of the page",
			src:  "# Page\n\n<br>\n\nkept\n",
			want: "\n\nkept\n",
			warnings: []Warning{
				{File: "p.md", Line: 3, Kind: WarnHTML, Detail: "dropped <br> block"},
			},
		},
		{
			name: "inline angle brackets in code spans survive",
			src:  "# Page\n\nrun `git merge <branch>` now\n",
			want: "\nrun `git merge <branch>` now\n",
		},
		{
			name: "image is dropped",
			src:  "# Page\n\n![logo](logo.png)\n\ntext\n",
			want: "\n\ntext\n",
			warnings: []Warning{
				{File: "p.md", Line: 3, Kind: WarnImage, Detail: "dropped image"},
			},
		},
		{
			name: "admonition becomes a labelled blockquote",
			src:  "# Page\n\n```admonish warning title=\"Careful\"\nbody\n```\n",
			want: "\n> **Careful**\n>\n> body\n",
		},
		{
			name: "admonition kind maps to a label",
			src:  "# Page\n\n```admonish warn\nbody\n```\n",
			want: "\n> **Warning**\n>\n> body\n",
		},
		{
			name: "internal link keeps only its text",
			src:  "# Page\n\nsee [the guide](./init.md#anchor) for more\n",
			want: "\nsee the guide for more\n",
		},
		{
			name: "external link is left to md2man",
			src:  "# Page\n\nsee [upstream](https://example.org) for more\n",
			want: "\nsee [upstream](https://example.org) for more\n",
		},
		{
			name: "link wrapping across lines is rewritten and reported at its first line",
			src:  "# Page\n\nsee [the\nmissing page](./nope.md) for more\n",
			want: "\nsee the\nmissing page for more\n",
			warnings: []Warning{
				{File: "p.md", Line: 3, Kind: WarnLink, Detail: `"the missing page" points at nope.md, which is not in the manual`},
			},
		},
		{
			name: "wide code block is reported once",
			src:  "# Page\n\n```\n" + pad(90) + "\n" + pad(95) + "\n```\n",
			want: "\n```\n" + pad(90) + "\n" + pad(95) + "\n```\n",
			warnings: []Warning{
				{File: "p.md", Line: 3, Kind: WarnWideCode, Detail: "code block is 95 columns wide, man pages fit 78"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			san := &sanitizer{file: "p.md", known: map[string]bool{"init.md": true}}
			got := san.prose(tt.src)

			require.Equal(t, tt.want, got)
			require.Equal(t, tt.warnings, nilIfEmpty(san.warnings))
		})
	}
}

func TestSanitizerReferenceQualifiesSubcommands(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "top level headings stay sections",
			src:  "# COMMANDS\n\n## init\n",
			want: "# COMMANDS\n\n### init\n",
		},
		{
			name: "subcommands carry their parent command",
			src:  "# COMMANDS\n\n## hook\n\n### pre-commit\n\n## add\n",
			want: "# COMMANDS\n\n### hook\n\n### hook pre-commit\n\n### add\n",
		},
		{
			name: "aliases stay on the command but not in the path",
			src:  "# COMMANDS\n\n## user, u\n\n### list, ls\n",
			want: "# COMMANDS\n\n### user, u\n\n### user list, ls\n",
		},
		{
			name: "a new section resets the path",
			src:  "# COMMANDS\n\n## hook\n\n# OTHER\n\n### deep\n",
			want: "# COMMANDS\n\n### hook\n\n# OTHER\n\n### deep\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			san := &sanitizer{file: "cli_ref.md"}
			require.Equal(t, tt.want, san.reference(tt.src))
		})
	}
}

func TestHeadingLevel(t *testing.T) {
	tests := []struct {
		text string
		want int
	}{
		{"# a", 1},
		{"### a", 3},
		{"####### a", 0},
		{"#not a heading", 0},
		{"#", 0},
		{"text", 0},
	}

	for _, tt := range tests {
		t.Run(tt.text, func(t *testing.T) {
			require.Equal(t, tt.want, headingLevel(tt.text))
		})
	}
}

func pad(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'x'
	}
	return string(out)
}

func nilIfEmpty(warnings []Warning) []Warning {
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}
