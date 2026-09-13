package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/muesli/termenv"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/diff"
	"opensesam.org/sesam/repo"
)

// HandleConfigDiff shows what sesam.yml declares on top of (or short of) what
// the audit log records, by handing two copies of the config tree to `git
// diff`: "verified" as the audit log sees it and "declared" as the user wrote
// it. Rendering is therefore whatever the user's git config asks for.
func HandleConfigDiff(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	json := cmd.Bool("json")

	changes, err := r.ConfigDiff(repo.ConfigDiffOpts{WriteDiffDir: !json})
	if err != nil {
		return err
	}

	if json {
		return printJSON(changes.Changes)
	}

	// Nothing to show: both trees would be identical, so don't bother git
	if changes.IsEmpty() {
		fmt.Println("sesam.yml and the audit log are in sync")
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
		return s.Seal(cmd.Bool("seal-all"))
	}); err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(applied)
	}

	if len(applied) == 0 {
		fmt.Println("sesam.yml and the audit log are in sync - nothing to apply")
		return nil
	}

	out := termenv.NewOutput(os.Stdout)
	for _, change := range applied {
		line := describeChange(out, r.SesamDir(), change)
		fmt.Println(out.String(line.glyph).Foreground(line.color).String() + " " + line.desc)
	}

	fmt.Printf("applied %d %s\n", len(applied), pluralize("change", len(applied)))
	return nil
}

// HandleConfigReset rewrites sesam.yml to describe the audit log again,
// discarding whatever the file declared on top of it. --dry-run reports the
// same outcome without writing anything.
func HandleConfigReset(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	dryRun := cmd.Bool("dry-run")

	reset, err := r.ConfigReset(repo.ConfigResetOpts{DryRun: dryRun})
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(reset)
	}

	if reset.Rewritten {
		fmt.Printf("sesam.yml cannot be reused (%s)\n", reset.Reason)
		if dryRun {
			fmt.Println("would write it fresh from the audit log - comments and descriptions would be lost")
		} else {
			fmt.Println("wrote it fresh from the audit log - comments and descriptions are gone")
		}

		for _, orphan := range reset.Orphaned {
			fmt.Printf(
				"note: %s is not included by the rewritten sesam.yml and would be ignored\n",
				displayPath(r.SesamDir(), orphan),
			)
		}

		return dryRunHint(dryRun)
	}

	if len(reset.Discarded) == 0 {
		fmt.Println("sesam.yml already describes the audit log - nothing to reset")
		return nil
	}

	out := termenv.NewOutput(os.Stdout)
	for _, change := range reset.Discarded {
		line := describeChange(out, r.SesamDir(), change)
		fmt.Println(out.String(line.glyph).Foreground(line.color).String() + " " + line.desc)
	}

	verb := "discarded"
	if dryRun {
		verb = "would discard"
	}
	fmt.Printf("%s %d declared %s\n", verb, len(reset.Discarded), pluralize("change", len(reset.Discarded)))

	return dryRunHint(dryRun)
}

// dryRunHint says that nothing was written, so a dry run cannot be mistaken
// for the real thing.
func dryRunHint(dryRun bool) error {
	if dryRun {
		fmt.Println("dry run - sesam.yml was not touched")
	}

	return nil
}

// describeChange renders a change as a glyph and a colored description: the
// colored, cwd-aware counterpart of diff.Change.String, whose wording it
// follows. It names what the change *is* rather than what was done with it, so
// it reads the same whether the change was applied or discarded.
func describeChange(out *termenv.Output, sesamDir string, c diff.Change) logLine {
	userColor := termenv.ANSIBrightCyan
	secretColor := termenv.ANSIBrightMagenta
	groupColor := termenv.ANSIBrightYellow
	dim := out.Color(colorGrey)

	col := func(v any, color termenv.Color) string {
		return out.String(fmt.Sprintf("%v", v)).Foreground(color).String()
	}

	user := func() string { return col(c.User, userColor) }
	secret := func() string { return col(displayPath(sesamDir, c.Path), secretColor) }
	groups := func(g []string) string { return col(groupsOrAdmin(g), groupColor) }
	keys := func() string { return col(shortKeys(c.Keys), dim) }

	switch c.Op {
	case core.OpUserTell:
		return logLine{"+", userColor, "user " + user() + " (groups: " + groups(c.Groups) + ", keys: " + keys() + ")"}
	case core.OpUserKill:
		return logLine{"-", userColor, "user " + user()}
	case core.OpUserChangeGroups:
		return logLine{"~", userColor, "user " + user() + " groups: " + groups(c.Old) + " -> " + groups(c.Groups)}
	case core.OpUserAddRecipients:
		return logLine{"+", userColor, pluralize("key", len(c.Keys)) + " of " + user() + ": " + keys()}
	case core.OpUserRmRecipients:
		return logLine{"-", userColor, pluralize("key", len(c.Keys)) + " of " + user() + ": " + keys()}
	case core.OpSecretAdd:
		return logLine{"+", secretColor, "secret " + secret() + " (access: " + groups(c.Groups) + ")"}
	case core.OpSecretRemove:
		return logLine{"-", secretColor, "secret " + secret()}
	case core.OpSecretChangeAccess:
		return logLine{"~", secretColor, "secret " + secret() + " access: " + groups(c.Old) + " -> " + groups(c.Groups)}
	default:
		// An operation this renderer does not know yet still shows up, just
		// without colors.
		return logLine{"?", dim, c.String()}
	}
}

// shortKeys renders a key list the way the audit log view does. Specs (forge
// ids, URLs) are short enough to survive untouched; an SSH key is shortened
// after its algorithm prefix, since cutting "ssh-ed25519 AAAA..." at a fixed
// width would leave only the algorithm.
func shortKeys(keys []string) string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if algo, material, found := strings.Cut(key, " "); found {
			out = append(out, algo+" "+shortID(material, false))
			continue
		}

		out = append(out, shortID(key, false))
	}

	return strings.Join(out, ", ")
}
