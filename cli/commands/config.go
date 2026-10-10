package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"github.com/goccy/go-yaml"
	"github.com/muesli/termenv"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
	"opensesam.org/sesam/repo/diff"
)

// HandleConfigDiff shows what sesam.yml declares on top of (or short of) what
// the audit log records, by handing two copies of the config tree to `git
// diff`: "verified" as the audit log sees it and "declared" as the user wrote
// it. Rendering is therefore whatever the user's git config asks for.
//
// Exit code follows git diff's own convention: 0 means the two agree, 1 means
// they differ (not a failure - see runGitDiff), 128 means the comparison
// itself could not be made - or, with --validate, that `sesam config apply
// --force` would refuse the declaration.
func HandleConfigDiff(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	json := cmd.Bool("json")

	changes, err := r.ConfigDiff(ctx, repo.ConfigDiffOpts{
		WriteDiffDir: !json,
		Validate:     cmd.Bool("validate"),
	})
	if err != nil {
		return &ExitCodeError{code: 128, print: true, err: err}
	}

	if json {
		return printJSON(changes.Changes)
	}

	// Nothing to show: both trees would be identical, so don't bother git
	if changes.IsEmpty() {
		slog.Debug("sesam.yml and audit log are in sync, nothing to show")
		return nil
	}

	return runGitDiff(
		ctx,
		changes.DiffDir,
		[]string{repo.VerifiedTreeDir + "/", repo.DeclaredTreeDir + "/"},
		cmd.Args().Slice(),
	)
}

// HandleConfigApply records what sesam.yml declares in the audit log. The plan
// and the seal that follows it share one stage, so a failure anywhere leaves
// the repository exactly as it was.
func HandleConfigApply(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	noSeal := cmd.Bool("no-seal")
	opts := repo.ConfigApplyOpts{Force: cmd.Bool("force")}

	before, err := latestSeqID(r)
	if err != nil {
		return err
	}

	var applied []diff.Change
	if err := r.Update(func(s *repo.Stage) error {
		changes, err := s.ConfigApply(ctx, opts)
		if err != nil {
			return err
		}
		applied = changes

		if noSeal || len(applied) == 0 {
			return nil
		}

		_, err = s.Seal(repo.SealOpts{All: cmd.Bool("seal-all")})
		return err
	}); err != nil {
		var committedErr *repo.CommittedChangesError
		if errors.As(err, &committedErr) {
			return printCommittedChanges(committedErr.Changes)
		}
		return err
	}

	if cmd.Bool("json") {
		return printJSON(applied)
	}

	if len(applied) == 0 {
		slog.Debug("sesam.yml and the audit log are in sync, nothing to apply")
		return nil
	}

	return printAppliedEntries(r, before, len(applied))
}

// errStopLog stops Log's iteration early once enough entries were collected -
// the sentinel Log's contract asks for, never returned to a caller of ours.
var errStopLog = errors.New("stop")

// latestSeqID returns the seq_id of the newest audit entry, or 0 for a log
// with no entries yet (init always writes one, so this is theoretical).
func latestSeqID(r *repo.Repo) (uint64, error) {
	var seq uint64
	err := r.Log(func(e *core.AuditEntrySigned) error {
		seq = e.SeqID
		return errStopLog
	})
	if err != nil && !errors.Is(err, errStopLog) {
		return 0, err
	}

	return seq, nil
}

// printAppliedEntries renders the audit entries ConfigApply appended (those
// with seq_id in (before, before+count]) the same way `sesam log` renders any
// other entry
func printAppliedEntries(r *repo.Repo, before uint64, count int) error {
	ceiling := before + uint64(count) //nolint:gosec

	entries := make([]*core.AuditEntrySigned, 0, count)
	err := r.Log(func(e *core.AuditEntrySigned) error {
		if e.SeqID <= before {
			return errStopLog
		}
		if e.SeqID <= ceiling {
			entries = append(entries, e)
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopLog) {
		return err
	}

	// Log iterates newest-first; applied lists steps in the order they ran.
	slices.Reverse(entries)

	out := termenv.NewOutput(os.Stdout)
	for _, e := range entries {
		line := describeLogEntry(out, e, false)
		fmt.Println(out.String(line.glyph).Foreground(line.color).String() + " " + line.desc)
	}

	slog.Info(fmt.Sprintf("applied %d %s", len(entries), pluralize("change", len(entries))))
	return nil
}

// printCommittedChanges reports the committed-but-undeclared steps ConfigApply
// refused to carry out, the same way `sesam verify --config` renders them.
func printCommittedChanges(changes []diff.Change) error {
	slog.Error("sesam.yml declares changes that are already committed, so they did not come from your working tree:")
	for _, change := range changes {
		slog.Error(fmt.Sprintf("  %s", change.String()))
	}
	slog.Error("check where they came from (git log -p -- sesam.yml); pass --force to apply them anyway")

	return &ExitCodeError{code: 1, print: false}
}

// HandleConfigPrint prints sesam.yml with every included file flattened into
// it, as YAML or, with --json, as JSON - for piping into yq or jq.
func HandleConfigPrint(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	doc, err := r.MergedConfig()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(doc)
	}

	out, err := yaml.MarshalWithOptions(doc, yaml.IndentSequence(true))
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	_, err = os.Stdout.Write(out)
	return err
}

// HandleConfigReset rewrites sesam.yml to describe the audit log again,
// discarding whatever the file declared on top of it. A repair that can be
// made in place always happens; only a full rewrite, which also loses
// comments and descriptions, needs --force - without it, that case is only
// reported.
func HandleConfigReset(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	force := cmd.Bool("force")

	reset, err := r.ConfigReset(repo.ConfigResetOpts{Force: force})
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(reset)
	}

	if reset.Rewritten {
		slog.Info(fmt.Sprintf("sesam.yml cannot be repaired in place (%s)", reset.Reason))
		if force {
			slog.Info("wrote it fresh from the audit log - comments and descriptions are gone")
		} else {
			slog.Info("would write it fresh from the audit log - comments and descriptions would be lost")
		}

		for _, orphan := range reset.Orphaned {
			slog.Info(fmt.Sprintf(
				"note: %s is not included by the rewritten sesam.yml and would be ignored",
				displayPath(r.SesamDir(), orphan),
			))
		}

		if force {
			printDeleted(r, reset)
		}
		return forceHint(force)
	}

	if len(reset.Discarded) == 0 {
		slog.Debug("sesam.yml already describes the audit log, nothing to reset")
		return nil
	}

	slog.Info(fmt.Sprintf("discarded %d declared %s", len(reset.Discarded), pluralize("change", len(reset.Discarded))))

	printDeleted(r, reset)
	return nil
}

// printDeleted reports sub-config files the repair-in-place path emptied and
// removed from disk.
func printDeleted(r *repo.Repo, reset *repo.ConfigReset) {
	for _, path := range reset.Deleted {
		slog.Info(fmt.Sprintf("note: %s is now empty and was deleted", displayPath(r.SesamDir(), path)))
	}
}

// forceHint says a rewrite was only reported, not written, so a preview
// cannot be mistaken for the real thing.
func forceHint(force bool) error {
	if !force {
		slog.Info("pass --force to rewrite sesam.yml from the audit log")
	}

	return nil
}
