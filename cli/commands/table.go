package commands

import (
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"golang.org/x/term"
)

// newTable returns a table writer styled consistently across sesam's
// list-style commands: a rounded border, centered title and plain (not
// upper-cased) headers/footers. When stdout is a terminal the table is
// capped to its width so long cells wrap instead of overflowing.
func newTable(title string, headers ...any) table.Writer {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.SuppressTrailingSpaces()

	t.Style().Title.Align = text.AlignCenter
	t.Style().Format.Header = text.FormatDefault
	t.Style().Format.Footer = text.FormatDefault
	t.Style().Options.SeparateRows = true

	if term.IsTerminal(int(os.Stdout.Fd())) { //nolint:gosec
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 { //nolint:gosec
			t.Style().Size.WidthMax = w
		}
	}

	if title != "" {
		t.SetTitle(title)
	}
	if len(headers) > 0 {
		t.AppendHeader(headers)
	}

	return t
}
