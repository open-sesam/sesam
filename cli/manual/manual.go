// Package manual carries the sesam manual the binary serves offline, via
// `sesam help --man`.
//
// Both files are generated artifacts, committed because go:embed needs them at
// build time - that way a plain `go build` or `go install` has a working
// manual too. The generator that produces them lives in package docgen and is
// not part of a release build. Regenerate with:
//
//	task docgen
package manual

import _ "embed"

// The manual as roff, for man(1), and as markdown, for the plain-pager
// fallback when there is no man(1) or no terminal.
var (
	//go:embed sesam.1
	page []byte

	//go:embed manual.md
	pageMarkdown string
)

// Page returns the manual as a roff man page.
func Page() []byte {
	return page
}

// PageMarkdown returns the same manual as markdown.
func PageMarkdown() string {
	return pageMarkdown
}
