package docgen

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Warning flags a construct in the handbook that does not survive the trip to
// roff. The generator prints them so the page can be reworded or excluded.
type Warning struct {
	File   string
	Line   int
	Kind   string
	Detail string
}

// Warning kinds.
const (
	WarnImage    = "image"
	WarnHTML     = "html"
	WarnWideCode = "wide-code"
	WarnLink     = "link"
)

// Markers that keep handbook content out of the man page. skipMarker placed
// below a heading drops that heading and everything under it up to the next
// heading of the same or a higher level.
const (
	skipMarker = "<!-- man:skip -->"
	skipStart  = "<!-- man:skip-start -->"
	skipEnd    = "<!-- man:skip-end -->"
)

// manWidth is the usable width of a terminal man page. roff reflows prose but
// not code blocks, so anything wider gets wrapped or cut by the reader.
const manWidth = 78

var (
	// Only a tag at the start of a line opens a raw HTML block. Inline markup
	// such as `git merge <branch>` inside backticks must survive untouched.
	htmlOpenRe  = regexp.MustCompile(`^<([a-zA-Z][a-zA-Z0-9]*)(\s[^>]*)?/?>`)
	imageRe     = regexp.MustCompile(`!\[[^\]]*\]\([^)]*\)`)
	linkRe      = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)
	admonishRe  = regexp.MustCompile("^(?:```|~~~)admonish\\s*([a-zA-Z]*)\\s*(?:title=\"([^\"]*)\")?")
	fenceMarker = []string{"```", "~~~"}
)

// voidTags never open an HTML block: they have no closing tag, so looking for
// one would swallow the rest of the page.
var voidTags = map[string]bool{
	"br": true, "hr": true, "img": true, "input": true,
	"link": true, "meta": true, "source": true,
}

// admonishLabels maps mdbook-admonish kinds to the bold label the man page
// uses instead. Unknown kinds fall back to the capitalized kind itself.
var admonishLabels = map[string]string{
	"note":    "Note",
	"info":    "Note",
	"tip":     "Tip",
	"warn":    "Warning",
	"warning": "Warning",
	"danger":  "Danger",
	"caution": "Caution",
	"bug":     "Bug",
	"example": "Example",
}

func (w Warning) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", w.File, w.Line, w.Kind, w.Detail)
}

// line is a source line tagged with its original position, so warnings still
// point into the handbook after earlier passes have dropped lines.
type line struct {
	text string
	num  int
}

// fence tracks fenced code blocks so the passes leave their contents alone.
type fence struct {
	marker string
}

// toggle reports whether text is a fence delimiter, updating the state.
func (f *fence) toggle(text string) bool {
	trimmed := strings.TrimLeft(text, " \t")
	for _, m := range fenceMarker {
		if !strings.HasPrefix(trimmed, m) {
			continue
		}
		if f.marker == "" {
			f.marker = m
			return true
		}
		if f.marker == m {
			f.marker = ""
			return true
		}
	}
	return false
}

func (f *fence) inside() bool {
	return f.marker != ""
}

// sanitizer turns one handbook page into markdown that md2man can render as a
// man page section, collecting warnings about everything it had to mangle.
type sanitizer struct {
	file     string
	known    map[string]bool // handbook pages that are part of the manual
	warnings []Warning
}

// prose converts a handbook page. The page's own title heading is dropped (the
// manual supplies the section title) and every remaining heading becomes a
// subsection, which is as deep as roff goes.
func (s *sanitizer) prose(src string) string {
	lines := s.passes(split(src))
	lines = dropFirstTitle(lines)
	return join(demote(lines, 3))
}

// reference converts the generated CLI reference. Its level-one headings are
// man sections already; everything below becomes a subsection, with nested
// commands spelled out in full first.
func (s *sanitizer) reference(src string) string {
	return join(demote(qualifyCommands(s.passes(split(src))), 3))
}

func (s *sanitizer) passes(lines []line) []line {
	lines = s.dropSkipped(lines)
	lines = s.dropHTML(lines)
	lines = s.convertAdmonitions(lines)
	lines = s.rewriteLinks(lines)
	s.checkCodeWidth(lines)
	return lines
}

func (s *sanitizer) warn(num int, kind, detail string) {
	s.warnings = append(s.warnings, Warning{File: s.file, Line: num, Kind: kind, Detail: detail})
}

// dropSkipped removes the regions and sections marked with man:skip markers.
func (s *sanitizer) dropSkipped(lines []line) []line {
	var (
		out       []line
		f         fence
		inRegion  bool
		skipLevel int
	)

	keep := func(ln line) {
		if !inRegion && skipLevel == 0 {
			out = append(out, ln)
		}
	}

	for i, ln := range lines {
		if f.toggle(ln.text) || f.inside() {
			keep(ln)
			continue
		}

		switch strings.TrimSpace(ln.text) {
		case skipStart:
			inRegion = true
			continue
		case skipEnd:
			inRegion = false
			continue
		}

		if lvl := headingLevel(ln.text); lvl > 0 {
			if skipLevel > 0 && lvl <= skipLevel {
				skipLevel = 0
			}
			if skipLevel == 0 && skipsSection(lines, i) {
				skipLevel = lvl
				continue
			}
		}

		keep(ln)
	}

	return out
}

// dropHTML removes raw HTML blocks and images, which have no roff equivalent.
func (s *sanitizer) dropHTML(lines []line) []line {
	var (
		out  []line
		f    fence
		open string
	)

	for _, ln := range lines {
		if f.toggle(ln.text) || f.inside() {
			out = append(out, ln)
			continue
		}

		trimmed := strings.TrimSpace(ln.text)

		if open != "" {
			if strings.Contains(trimmed, "</"+open+">") {
				open = ""
			}
			continue
		}

		if m := htmlOpenRe.FindStringSubmatch(trimmed); m != nil {
			tag := strings.ToLower(m[1])
			s.warn(ln.num, WarnHTML, fmt.Sprintf("dropped <%s> block", tag))
			if !voidTags[tag] && !strings.HasSuffix(trimmed, "/>") && !strings.Contains(trimmed, "</"+tag+">") {
				open = tag
			}
			continue
		}

		if imageRe.MatchString(ln.text) {
			s.warn(ln.num, WarnImage, "dropped image")
			stripped := strings.TrimRight(imageRe.ReplaceAllString(ln.text, ""), " \t")
			if strings.TrimSpace(stripped) == "" {
				continue
			}
			ln.text = stripped
		}

		out = append(out, ln)
	}

	return out
}

// convertAdmonitions turns mdbook-admonish fences into blockquotes with a bold
// label, which roff renders as an indented block.
func (s *sanitizer) convertAdmonitions(lines []line) []line {
	var (
		out []line
		f   fence
		in  bool
	)

	for _, ln := range lines {
		isFence := f.toggle(ln.text)

		if in {
			if isFence && !f.inside() {
				in = false
				continue
			}
			out = append(out, line{text: quote(ln.text), num: ln.num})
			continue
		}

		if isFence && f.inside() {
			if m := admonishRe.FindStringSubmatch(strings.TrimLeft(ln.text, " \t")); m != nil {
				in = true
				out = append(out, line{text: "> **" + admonishLabel(m[1], m[2]) + "**", num: ln.num})
				out = append(out, line{text: ">", num: ln.num})
				continue
			}
		}

		out = append(out, ln)
	}

	return out
}

// rewriteLinks drops the markup of handbook-internal links, keeping the text.
// External links stay as they are: md2man renders them as "text <url>".
//
// It runs over whole prose blocks rather than single lines, because a link may
// wrap across a line break.
func (s *sanitizer) rewriteLinks(lines []line) []line {
	var (
		out   []line
		f     fence
		block []line
	)

	flush := func() {
		out = append(out, s.rewriteBlock(block)...)
		block = nil
	}

	for _, ln := range lines {
		if f.toggle(ln.text) || f.inside() {
			flush()
			out = append(out, ln)
			continue
		}
		block = append(block, ln)
	}
	flush()

	return out
}

// rewriteBlock rewrites the links in one fence-free block. Replacements never
// touch a newline, so the block keeps its line count and the warnings keep
// pointing at the right source line.
func (s *sanitizer) rewriteBlock(block []line) []line {
	if len(block) == 0 {
		return nil
	}

	text := join(block)
	matches := linkRe.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return block
	}

	var (
		out  strings.Builder
		last int
	)

	for _, m := range matches {
		label, target := text[m[2]:m[3]], text[m[4]:m[5]]
		// Earlier passes drop lines, so the block is not contiguous in the
		// source; the line it started on is the one carrying the number.
		num := block[strings.Count(text[:m[0]], "\n")].num

		out.WriteString(text[last:m[0]])
		out.WriteString(s.linkReplacement(num, text[m[0]:m[1]], label, target))
		last = m[1]
	}
	out.WriteString(text[last:])

	rewritten := split(out.String())
	if len(rewritten) != len(block) {
		return block
	}
	for i := range rewritten {
		rewritten[i].num = block[i].num
	}

	return rewritten
}

func (s *sanitizer) linkReplacement(num int, match, label, target string) string {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return match
	}

	base, _, _ := strings.Cut(target, "#")
	base = strings.TrimPrefix(base, "./")

	switch {
	case base == "":
		return label
	case strings.HasSuffix(base, ".md"):
		if !s.known[base] {
			s.warn(num, WarnLink, fmt.Sprintf("%q points at %s, which is not in the manual", oneLine(label), base))
		}
		return label
	default:
		return match
	}
}

func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// checkCodeWidth reports code blocks too wide for a terminal man page.
func (s *sanitizer) checkCodeWidth(lines []line) {
	var (
		f     fence
		start int
		width int
	)

	for _, ln := range lines {
		if f.toggle(ln.text) {
			if f.inside() {
				start, width = ln.num, 0
				continue
			}
			if width > manWidth {
				s.warn(start, WarnWideCode, fmt.Sprintf("code block is %d columns wide, man pages fit %d", width, manWidth))
			}
			continue
		}
		if f.inside() {
			width = max(width, utf8.RuneCountInString(ln.text))
		}
	}
}

func admonishLabel(kind, title string) string {
	if title != "" {
		return title
	}
	if label, ok := admonishLabels[strings.ToLower(kind)]; ok {
		return label
	}
	if kind == "" {
		return "Note"
	}
	return strings.ToUpper(kind[:1]) + kind[1:]
}

func quote(text string) string {
	if strings.TrimSpace(text) == "" {
		return ">"
	}
	return "> " + text
}

// headingLevel returns the ATX heading level of text, or 0 if it is not one.
func headingLevel(text string) int {
	n := 0
	for n < len(text) && text[n] == '#' {
		n++
	}
	if n == 0 || n > 6 || n >= len(text) || text[n] != ' ' {
		return 0
	}
	return n
}

// skipsSection reports whether the heading at index i is followed by a skip
// marker, ignoring blank lines in between.
func skipsSection(lines []line, i int) bool {
	for _, ln := range lines[i+1:] {
		switch strings.TrimSpace(ln.text) {
		case "":
			continue
		case skipMarker:
			return true
		default:
			return false
		}
	}
	return false
}

// dropFirstTitle removes the page's own level-one heading; the manual supplies
// the section title instead.
func dropFirstTitle(lines []line) []line {
	var f fence
	for i, ln := range lines {
		if f.toggle(ln.text) || f.inside() {
			continue
		}
		if headingLevel(ln.text) == 1 {
			return append(lines[:i:i], lines[i+1:]...)
		}
	}
	return lines
}

// qualifyCommands prefixes a nested command heading with the command path it
// sits under, turning "pre-commit" into "hook pre-commit". roff has no third
// heading level, so without this every subcommand reads as a top-level one.
func qualifyCommands(lines []line) []line {
	var (
		f      fence
		parent = map[int]string{}
		out    = make([]line, 0, len(lines))
	)

	for _, ln := range lines {
		if f.toggle(ln.text) || f.inside() {
			out = append(out, ln)
			continue
		}

		lvl := headingLevel(ln.text)
		if lvl == 1 {
			clear(parent)
		}
		if lvl < 2 {
			out = append(out, ln)
			continue
		}

		name := strings.TrimSpace(ln.text[lvl:])
		if prefix := parent[lvl-1]; prefix != "" {
			name = prefix + " " + name
		}

		// Aliases ("open, reveal") only belong on the command itself, not in
		// the path its subcommands inherit.
		parent[lvl] = firstName(name)
		for deeper := lvl + 1; parent[deeper] != ""; deeper++ {
			delete(parent, deeper)
		}

		ln.text = strings.Repeat("#", lvl) + " " + name
		out = append(out, ln)
	}

	return out
}

// firstName drops the alias list from a command heading.
func firstName(name string) string {
	first, _, _ := strings.Cut(name, ",")
	return first
}

// demote pushes every heading below level one down to the given level. roff
// knows only sections and subsections, so deeper nesting collapses anyway.
func demote(lines []line, to int) []line {
	var f fence
	out := make([]line, 0, len(lines))

	for _, ln := range lines {
		if f.toggle(ln.text) || f.inside() {
			out = append(out, ln)
			continue
		}
		if lvl := headingLevel(ln.text); lvl > 1 {
			ln.text = strings.Repeat("#", to) + ln.text[lvl:]
		}
		out = append(out, ln)
	}

	return out
}

func split(src string) []line {
	raw := strings.Split(src, "\n")
	lines := make([]line, len(raw))
	for i, text := range raw {
		lines[i] = line{text: text, num: i + 1}
	}
	return lines
}

func join(lines []line) string {
	texts := make([]string, len(lines))
	for i, ln := range lines {
		texts[i] = ln.text
	}
	return strings.Join(texts, "\n")
}
