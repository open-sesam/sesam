package docgen

import (
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// handbook is the real mdbook source tree, up at the repo root.
func handbook() fs.FS {
	return os.DirFS("../../" + DefaultHandbook)
}

// reference is the minimal shape Markdown expects from the generated CLI docs.
const reference = `# NAME

sesam - manage secrets

# SYNOPSIS

sesam

# GLOBAL OPTIONS

**--identity**: an identity

# COMMANDS

## init

Initialize
`

func TestManualSectionsAreWellFormed(t *testing.T) {
	seen := map[string]bool{}

	for _, section := range manualSections {
		require.NotEmpty(t, section.Title, "every section needs a title")
		require.Equal(t, strings.ToUpper(section.Title), section.Title, "man section titles are uppercase")
		require.False(t, seen[section.Title], "duplicate section %q", section.Title)
		seen[section.Title] = true

		if section.File == "" {
			continue
		}

		_, err := fs.ReadFile(handbook(), section.File)
		require.NoError(t, err, "handbook page %s is referenced but not embedded", section.File)
	}
}

func TestMarkdownAssemblesEverySection(t *testing.T) {
	md, _, err := Markdown(ManualOptions{CLIReference: reference, Handbook: handbook()})
	require.NoError(t, err)

	require.True(t, strings.HasPrefix(md, "\n# NAME\n"), "the roff title heading belongs to Man, not Markdown")

	want := []string{"# NAME", "# SYNOPSIS"}
	for _, section := range manualSections {
		want = append(want, "# "+section.Title)
	}
	want = append(want, "# SEE ALSO")

	offset := 0
	for _, heading := range want {
		idx := strings.Index(md[offset:], "\n"+heading+"\n")
		require.GreaterOrEqual(t, idx, 0, "%s missing or out of order", heading)
		offset += idx + 1
	}
}

func TestMarkdownRejectsIncompleteReference(t *testing.T) {
	tests := []struct {
		name      string
		reference string
	}{
		{name: "empty", reference: ""},
		{name: "no name", reference: "# SYNOPSIS\n\nsesam\n"},
		{name: "no commands", reference: "# NAME\n\nx\n\n# SYNOPSIS\n\ny\n\n# GLOBAL OPTIONS\n\nz\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Markdown(ManualOptions{CLIReference: tt.reference, Handbook: handbook()})
			require.Error(t, err)
		})
	}
}

func TestManRendersRoff(t *testing.T) {
	page, _, err := Man(ManualOptions{CLIReference: reference, Handbook: handbook()})
	require.NoError(t, err)

	// No version or date in the title: the page is committed, so per-build
	// metadata would make it churn on every regeneration.
	require.Contains(t, string(page), `.TH sesam 1 "" "sesam" "Sesam Manual"`)
	require.Contains(t, string(page), ".SH NAME")
	require.Contains(t, string(page), ".SH FREQUENTLY ASKED QUESTIONS")
}

func TestSplitReference(t *testing.T) {
	sections, err := splitReference("# A\n\nfirst\n\n```\n# not a heading\n```\n\n# B\n\nsecond\n")
	require.NoError(t, err)

	require.Equal(t, []string{"A", "B"}, sortedKeys(sections))
	require.Contains(t, sections["A"], "# not a heading")
	require.Contains(t, sections["B"], "second")
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
