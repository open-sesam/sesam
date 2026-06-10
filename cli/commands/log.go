package commands

import (
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func HandleLogJSON(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.Log(func(e *core.AuditEntrySigned) error {
		return printJSON(e)
	})
}

func HandleLog(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Bool("json") {
		return HandleLogJSON(ctx, cmd, r)
	}

	output := termenv.NewOutput(os.Stdout)

	var (
		timeColor            = output.Color("#008000")
		userColor            = termenv.ANSIBrightCyan
		detailPrimaryColor   = termenv.ANSIBrightMagenta
		detailSecondaryColor = termenv.ANSIBrightYellow

		unknown = "[unknown]"
	)

	colorize := func(v any, col termenv.Color) string {
		s := fmt.Sprintf("%v", v)
		return output.String(s).Foreground(col).String()
	}

	pluralize := func(s string, n int) string {
		if n == 1 {
			return s
		}

		return s + "s"
	}

	fmtOpMap := map[core.Operation]func(e *core.AuditEntrySigned) string{
		core.OpInit: func(e *core.AuditEntrySigned) string {
			id, ok := e.RawDetail().(*core.DetailInit)
			if !ok {
				return unknown
			}

			return fmt.Sprintf(
				"initialized the repository with uuid %s",
				colorize(id.InitUUID, detailPrimaryColor),
			)
		},
		core.OpUserTell: func(e *core.AuditEntrySigned) string {
			dut, ok := e.RawDetail().(*core.DetailUserTell)
			if !ok {
				return unknown
			}

			return fmt.Sprintf(
				"told secrets to a new user %s in %s (%s)",
				colorize(dut.User, detailPrimaryColor),
				pluralize("group", len(dut.Groups)),
				colorize(strings.Join(dut.Groups, ", "), detailSecondaryColor),
			)
		},
		core.OpUserKill: func(e *core.AuditEntrySigned) string {
			duk, ok := e.RawDetail().(*core.DetailUserKill)
			if !ok {
				return unknown
			}

			return fmt.Sprintf(
				"removed user %s",
				colorize(duk.User, detailPrimaryColor),
			)
		},
		core.OpSecretAdd: func(e *core.AuditEntrySigned) string {
			dsc, ok := e.RawDetail().(*core.DetailSecretAdd)
			if !ok {
				return unknown
			}

			return fmt.Sprintf(
				"modified %s accessibly by %s %s",
				colorize(dsc.RevealedPath, detailPrimaryColor),
				pluralize("group", len(dsc.AccessGroups)),
				colorize(strings.Join(dsc.AccessGroups, ", "), detailSecondaryColor),
			)
		},
		core.OpSecretRemove: func(e *core.AuditEntrySigned) string {
			dsr, ok := e.RawDetail().(*core.DetailSecretRemove)
			if !ok {
				return unknown
			}

			return fmt.Sprintf(
				"removed %s",
				colorize(dsr.RevealedPath, detailPrimaryColor),
			)
		},
		core.OpSeal: func(e *core.AuditEntrySigned) string {
			ds, ok := e.RawDetail().(*core.DetailSeal)
			if !ok {
				return unknown
			}

			return fmt.Sprintf(
				"sealed %s %s (%s)",
				colorize(ds.FilesSealed, detailPrimaryColor),
				pluralize("secret", ds.FilesSealed),
				colorize(ds.RootHash, detailSecondaryColor),
			)
		},
	}

	var seqIDFormat string

	return r.Log(func(e *core.AuditEntrySigned) error {
		opFn, ok := fmtOpMap[e.Operation]
		opDesc := "unknown"
		if ok {
			opDesc = opFn(e)
		}

		if seqIDFormat == "" {
			// choose format depending on how much entries we have:
			seqIDFormat = fmt.Sprintf(
				"%%-%dd",
				int(math.Log10(float64(e.SeqID))+1),
			)
		}

		fmt.Printf(
			"#%s [%s] %s %s\n",
			fmt.Sprintf(seqIDFormat, e.SeqID),
			output.String(e.Time.Format(time.RFC3339)).Foreground(timeColor),
			output.String(e.ChangedBy).Foreground(userColor),
			opDesc,
		)
		return nil
	})
}
