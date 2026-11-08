package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/muesli/termenv"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
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

	if cmd.Bool("config") {
		opts.Config = true
		anySpecified = true
	}

	if cmd.Bool("all") || !anySpecified {
		opts.Integrity = true
		opts.ForgeCheck = true
		opts.KeyReuse = true
		opts.Truncation = true
		// Config is deliberately not part of --all: sesam.yml's plain-text
		// merge and the audit log's own semantic merge can legitimately
		// disagree right after an ordinary merge (see VerifyOptions.Config),
		// which would make ordinary verify fail after routine merge activity.
		// Pass --config explicitly to check for it, e.g. before applying a
		// branch you did not author yourself.
	}

	return opts
}

// rewrittenHints explains a rewritten audit log: why it matters, how it
// usually happens and how to get out.
func rewrittenHints(e *core.AuditLogRewrittenError) []string {
	sesam := e.SesamPath
	lines := []string{
		"  Note that sesam's audit log may only grow. Every commit has to keep all entries of its parent's log.",
		"  Dropped or rewritten entries could otherwise undo what was recorded, e.g. bring back a removed user.",
		"  Often this happens due to git commands bringing back an older log, e.g. by one of those cases:",
		"    - git checkout <rev> -- " + sesam + "   (or git restore --source=<rev>)",
		"    - git revert of a commit that changed " + sesam,
		"    - a merge conflict in " + sesam + "/audit/log.jsonl resolved by taking one side (git checkout --theirs)",
	}

	if e.Newer == "" {
		// problematic log is staged, but not committed
		return append(lines,
			"  To fix it, take "+sesam+" from HEAD and redo your change with sesam:",
			"",
			"    git checkout HEAD -- ':/"+sesam+"' && sesam seal",
			"",
			"  If you are amending a commit on purpose to drop its entries, `git commit --no-verify` skips this check.",
		)
	}

	return append(lines,
		"  To fix it, rewrite history so commit "+e.Newer+" no longer drops entries: redo it on top of its parent's log,",
		"  or squash it with the commits around it if the result only grows the log (e.g. `git rebase -i "+e.Newer+"^`).",
		"  Note that the change was already committed, so you will have to force-push if it was published already.",
	)
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

			var rewritten *core.AuditLogRewrittenError
			if errors.As(report.TruncateError, &rewritten) {
				for _, line := range rewrittenHints(rewritten) {
					slog.Warn(line)
				}
			}
		} else {
			slog.Info(fmt.Sprintf("Audit log history: %s", green("ok")))
		}

		if report.TruncateStoppedAt != "" {
			slog.Warn(fmt.Sprintf(
				"Audit log history: only checked down to commit %s - your identity cannot read the logs before",
				report.TruncateStoppedAt,
			))
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

	if opts.Config {
		if len(report.CommittedConfigChanges) == 0 {
			slog.Info(fmt.Sprintf("Config: %s", green("ok")))
		} else {
			slog.Error(fmt.Sprintf(
				"Config: %s",
				red("sesam.yml declares changes that already arrived committed"),
			))
			for _, change := range report.CommittedConfigChanges {
				slog.Error(fmt.Sprintf("  %s", orange(change.String())))
			}
			slog.Error("check where they came from (git log -p -- sesam.yml) before running apply")
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
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		printReport(opts, report)
	}

	if !report.OK() {
		return fmt.Errorf("there were issues")
	}

	return nil
}
