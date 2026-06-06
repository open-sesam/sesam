package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func verifyOpts(cmd *cli.Command) repo.VerifyOptions {
	opts := repo.VerifyOptions{}

	var anySpecified bool
	if cmd.Bool("truncate") {
		opts.Truncation = true
		anySpecified = true
	}

	if cmd.Bool("forge-check") {
		opts.ForgeCheck = true
		anySpecified = true
	}

	if cmd.Bool("key-reuse") {
		opts.KeyReuse = true
		anySpecified = true
	}

	if cmd.Bool("integrity") {
		opts.Integrity = true
		anySpecified = true
	}

	if cmd.Bool("all") || !anySpecified {
		opts.Integrity = true
		opts.ForgeCheck = true
		opts.KeyReuse = true
		opts.Truncation = true
	}

	return opts
}

func printReport(opts repo.VerifyOptions, report *repo.VerifyReport) {
	out := termenv.NewOutput(os.Stdout)

	green := func(s string) string {
		return out.String(s).Foreground(out.Color("#008000")).String()
	}

	orange := func(s string) string {
		return out.String(s).Foreground(out.Color("#B08000")).String()
	}

	red := func(s string) string {
		return out.String(s).Foreground(out.Color("#800000")).String()
	}

	if opts.Integrity {
		if report.Integrity != nil {
			slog.Warn(fmt.Sprintf("Integrity: %s", red("error")))
			for _, integErr := range report.Integrity.Errors {
				slog.Warn(fmt.Sprintf("  %s: %s", integErr.RevealedPath, integErr.Message))
			}
		} else {
			slog.Info(fmt.Sprintf("Integrity: %s", green("ok")))
		}
	}

	if opts.Truncation {
		if report.TruncateError != nil {
			slog.Error(fmt.Sprintf(
				"Audit Log History: %s - %s",
				red("truncated"),
				red(report.TruncateError.Error()),
			))
		} else {
			slog.Info(fmt.Sprintf("Audit log history: %s", green("ok")))
		}
	}

	printForgeReportEntries := func(name string, entries []core.ForgeReportEntry) {
		if len(entries) == 0 {
			return
		}

		slog.Warn(fmt.Sprintf("  - %s", name))
		for _, entry := range entries {
			slog.Warn(fmt.Sprintf("    - %s: %s", entry.User, entry.PubKey))
		}
	}

	if opts.ForgeCheck {
		if report.ForgeCheckReport == nil || report.ForgeCheckReport.IsZero() {
			slog.Info(fmt.Sprintf("Forge Check: %s", green("ok")))
		} else {
			added := report.ForgeCheckReport.Added
			deleted := report.ForgeCheckReport.Deleted
			errored := report.ForgeCheckReport.Errored

			slog.Info(fmt.Sprintf(
				"Forge Check: %d added, %d deleted, %d errored",
				len(added),
				len(deleted),
				len(errored),
			))

			printForgeReportEntries("Added", added)
			printForgeReportEntries("Deleted", deleted)

			if len(errored) > 0 {
				slog.Error("  - Errored:")
				for _, forgeErr := range errored {
					slog.Error(
						fmt.Sprintf(
							"    - %s (%s): %s",
							forgeErr.User,
							forgeErr.Source,
							red(forgeErr.Error.Error()),
						),
					)
				}
			}
		}
	}

	if opts.KeyReuse {
		if len(report.SharedPublicKeys) == 0 {
			slog.Info(fmt.Sprintf("Key re-use: %s", green("ok")))
		} else {
			slog.Error(
				fmt.Sprintf(
					"Key re-use: %s",
					red(fmt.Sprintf("%d shared", len(report.SharedPublicKeys))),
				),
			)

			for _, spk := range report.SharedPublicKeys {
				slog.Error(fmt.Sprintf(
					"  - %s share %s",
					orange(strings.Join(spk.Users, ", ")),
					orange(spk.PubKey),
				))
			}
		}
	}
}

// HandleVerify verifies repository audit and crypt state.
func HandleVerify(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	opts := verifyOpts(cmd)
	report, err := r.Verify(ctx, opts)
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		_ = printJSON(report)
	} else {
		printReport(opts, report)
	}

	if !report.OK() {
		return fmt.Errorf("there were issues")
	}

	return nil
}
