package commands

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/muesli/termenv"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

func HandleLogJSON(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.Log(func(e *core.AuditEntrySigned) error {
		return printJSON(e)
	})
}

// logLine is the rendered glyph + colored description for one audit entry.
type logLine struct {
	glyph string
	color termenv.Color
	desc  string
}

// shortID truncates long ids (audit root hashes, init UUIDs) to a git-style
// prefix, unless full output was requested.
func shortID(s string, full bool) string {
	if full || len(s) <= 8 {
		return s
	}
	return s[:8]
}

func formatLogTime(t time.Time, full bool) string {
	if full {
		return t.Format(time.RFC3339)
	}
	return t.Format("2006 Jan 02 15:04")
}

// groupsOrAdmin renders an access-group list, defaulting to the implicit
// "admin" when no groups are set.
func groupsOrAdmin(groups []string) string {
	if len(groups) == 0 {
		return "admin"
	}
	return strings.Join(groups, ", ")
}

func shortPubKeys(pubs []core.UserPubKey, full bool) string {
	ids := make([]string, 0, len(pubs))
	for _, pub := range pubs {
		ids = append(ids, shortID(pub.Key, full))
	}

	return strings.Join(ids, ", ")
}

// describeLogEntry maps an audit entry to a glyph (the action), a color (the
// object) and a colored one-line description. Glyph encodes the action
// (+ add, - remove, ~ change, → rename, ★ init, ✓ seal); color encodes the
// object (cyan = user, magenta = secret, green = repo/seal).
func describeLogEntry(out *termenv.Output, e *core.AuditEntrySigned, full bool) logLine {
	userColor := termenv.ANSIBrightCyan
	secretColor := termenv.ANSIBrightMagenta
	repoColor := termenv.ANSIBrightGreen
	groupColor := termenv.ANSIBrightYellow
	dim := out.Color("#808080")

	c := func(v any, col termenv.Color) string {
		return out.String(fmt.Sprintf("%v", v)).Foreground(col).String()
	}
	sid := func(s string) string { return c(shortID(s, full), dim) }

	unknown := logLine{glyph: "?", color: dim, desc: "unknown"}

	switch e.Operation {
	case core.OpInit:
		d, ok := e.RawDetail().(*core.DetailInit)
		if !ok {
			return unknown
		}
		return logLine{"★", repoColor, "initialized repo " + sid(d.InitUUID)}

	case core.OpUserTell:
		d, ok := e.RawDetail().(*core.DetailUserTell)
		if !ok {
			return unknown
		}
		return logLine{
			"+", userColor,
			"told " + c(d.User, userColor) + " into " + c(groupsOrAdmin(d.Groups), groupColor),
		}

	case core.OpUserKill:
		d, ok := e.RawDetail().(*core.DetailUserKill)
		if !ok {
			return unknown
		}
		return logLine{"-", userColor, "removed user " + c(d.User, userColor)}

	case core.OpUserRename:
		d, ok := e.RawDetail().(*core.DetailUserRename)
		if !ok {
			return unknown
		}
		return logLine{
			"→", userColor,
			"renamed user " + c(d.OldName, userColor) + " → " + c(d.NewName, userColor),
		}

	case core.OpUserChangeGroups:
		d, ok := e.RawDetail().(*core.DetailUserChangeGroups)
		if !ok {
			return unknown
		}
		return logLine{
			"~", userColor,
			"set groups of " + c(d.User, userColor) + " to " + c(groupsOrAdmin(d.NewGroups), groupColor),
		}

	case core.OpUserAddRecipients:
		d, ok := e.RawDetail().(*core.DetailUserAddRecipients)
		if !ok {
			return unknown
		}
		return logLine{
			"⊕", userColor,
			"add " + pluralize("recipient", len(d.PubKeys)) + " of " + c(d.User, userColor) + " (" + c(shortPubKeys(d.PubKeys, full), groupColor) + ")",
		}

	case core.OpUserRmRecipients:
		d, ok := e.RawDetail().(*core.DetailUserRmRecipients)
		if !ok {
			return unknown
		}
		return logLine{
			"⊖", userColor,
			"removed " + pluralize("recipient", len(d.PubKeys)) + " of " + c(d.User, userColor) + " (" + c(shortPubKeys(d.PubKeys, full), groupColor) + ")",
		}

	case core.OpUserRegenerateSignKey:
		d, ok := e.RawDetail().(*core.DetailUserRegenerateSignKey)
		if !ok {
			return unknown
		}
		return logLine{
			"~", userColor,
			"regenerated signing key of " + c(d.User, userColor),
		}

	case core.OpSecretAdd:
		d, ok := e.RawDetail().(*core.DetailSecretAdd)
		if !ok {
			return unknown
		}
		return logLine{
			"+", secretColor,
			"added " + c(d.RevealedPath, secretColor) + " (" + c(groupsOrAdmin(d.AccessGroups), groupColor) + ")",
		}

	case core.OpSecretRemove:
		d, ok := e.RawDetail().(*core.DetailSecretRemove)
		if !ok {
			return unknown
		}
		return logLine{"-", secretColor, "removed " + c(d.RevealedPath, secretColor)}

	case core.OpSecretMove:
		d, ok := e.RawDetail().(*core.DetailSecretMove)
		if !ok {
			return unknown
		}
		return logLine{
			"→", secretColor,
			"renamed " + c(d.OldRevealedPath, secretColor) + " → " + c(d.NewRevealedPath, secretColor),
		}

	case core.OpSecretChangeAccess:
		d, ok := e.RawDetail().(*core.DetailSecretChangeAccess)
		if !ok {
			return unknown
		}
		return logLine{
			"~", secretColor,
			"changed access of " + c(d.RevealedPath, secretColor) + " to " + c(groupsOrAdmin(d.AccessGroups), groupColor),
		}

	case core.OpSeal:
		d, ok := e.RawDetail().(*core.DetailSeal)
		if !ok {
			return unknown
		}
		return logLine{"✓", repoColor, fmt.Sprintf(
			"sealed %d %s %s",
			d.FilesSealed, pluralize("secret", d.FilesSealed), sid(d.RootHash),
		)}

	default:
		return unknown
	}
}

func HandleLog(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Bool("json") {
		return HandleLogJSON(ctx, cmd, r)
	}

	full := cmd.Bool("full")
	out := termenv.NewOutput(os.Stdout)
	dim := out.Color("#808080")
	timeColor := out.Color("#008000")
	userColor := termenv.ANSIBrightCyan

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SuppressTrailingSpaces()

	// A borderless table aligns the columns while staying ANSI-width aware, so
	// the colored cells line up where hand-padding would not.
	style := table.StyleDefault
	style.Options.DrawBorder = false
	style.Options.SeparateColumns = false
	style.Options.SeparateRows = false
	style.Options.SeparateHeader = false
	style.Box.PaddingLeft = ""
	style.Box.PaddingRight = "  "
	t.SetStyle(style)
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, Align: text.AlignRight}, // sequence id
	})

	if err := r.Log(func(e *core.AuditEntrySigned) error {
		line := describeLogEntry(out, e, full)
		t.AppendRow(table.Row{
			out.String("#" + strconv.FormatUint(e.SeqID, 10)).Foreground(dim).String(),
			out.String(line.glyph).Foreground(line.color).String(),
			out.String(formatLogTime(e.Time, full)).Foreground(timeColor).String(),
			out.String(e.ChangedBy).Foreground(userColor).String(),
			line.desc,
		})
		return nil
	}); err != nil {
		return err
	}

	t.Render()
	return nil
}
