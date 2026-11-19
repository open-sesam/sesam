package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

// HandleRevert undoes a commit the way the audit log allows: by appending the
// inverse of what it recorded. The rest of the commit is reverted by git.
func HandleRevert(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	sesamDir := r.SesamDir()

	if kind := mergeState(ctx, sesamDir); kind.InProgress() {
		return fmt.Errorf("a %s is in progress - finish or abort it first", kind)
	}

	worktreeRoot, prefix, err := worktreePrefix(ctx, sesamDir)
	if err != nil {
		return err
	}

	rev, parent, err := revertTarget(ctx, worktreeRoot, cmd.StringArg("commit"))
	if err != nil {
		return err
	}

	if err := requireSesamClean(ctx, worktreeRoot, prefix); err != nil {
		return err
	}

	states, err := r.SyncStates(ctx, syncOpts(ctx, sesamDir))
	if err != nil {
		return err
	}

	if unsettled := states.Paths(
		repo.SecretStateNotInSync,
		repo.SecretStateStale,
		repo.SecretStateDiverged,
		repo.SecretStateNoSealedPath,
	); len(unsettled) > 0 {
		return fmt.Errorf(
			"these secrets differ from their objects: %s\nseal or reveal them first (see `sesam status`)",
			strings.Join(unsettled, ", "),
		)
	}

	plan, err := planRevert(ctx, cmd, r, rev, parent)
	if err != nil {
		return err
	}

	if cmd.Bool("dry-run") {
		return printRevertPlan(cmd, sesamDir, plan, nil)
	}

	if err := gitRevertNoCommit(ctx, worktreeRoot, prefix, rev); err != nil {
		return err
	}

	res, err := r.ApplyRevert(ctx, plan)
	if err != nil {
		abortGitRevert(ctx, worktreeRoot)
		return fmt.Errorf("revert %s: %w", short(rev), err)
	}

	if plan.IsEmpty() && !hasStagedChanges(ctx, worktreeRoot) {
		// Nothing left for git to commit either, e.g. only a sign key rotation.
		abortGitRevert(ctx, worktreeRoot)
		if err := printRevertPlan(cmd, sesamDir, plan, nil); err != nil {
			return err
		}

		fmt.Fprintln(os.Stderr, "sesam: nothing to revert")
		return nil
	}

	if err := r.GitAddDotSesam(ctx); err != nil {
		return err
	}

	if err := r.GitAddConfig(ctx, nil); err != nil {
		return err
	}

	return printRevertPlan(cmd, sesamDir, plan, res)
}

// revertTarget resolves the commit to revert and its parent, refusing what has
// no single parent or is not part of HEAD's history.
func revertTarget(ctx context.Context, worktreeRoot, arg string) (rev, parent string, err error) {
	if arg == "" {
		return "", "", errors.New("missing commit to revert")
	}

	rev, ok := gitProbe(ctx, worktreeRoot, "rev-parse", "--verify", "-q", arg+"^{commit}")
	if !ok {
		return "", "", fmt.Errorf("%q is not a commit", arg)
	}

	out, err := gitOutput(ctx, worktreeRoot, "rev-list", "--parents", "-n", "1", rev)
	if err != nil {
		return "", "", err
	}

	switch fields := strings.Fields(out); len(fields) {
	case 1:
		return "", "", &repo.RefusedRevertError{Reason: "the commit has no parent"}
	case 2:
		parent = fields[1]
	default:
		return "", "", &repo.RefusedRevertError{Reason: "the commit is a merge; revert the commits it brought in instead"}
	}

	//nolint:gosec // fixed git subcommand; rev is a sha we resolved ourselves.
	c := exec.CommandContext(ctx, "git", "merge-base", "--is-ancestor", rev, "HEAD")
	c.Dir = worktreeRoot
	if err := c.Run(); err != nil {
		return "", "", &repo.RefusedRevertError{Reason: short(rev) + " is not part of HEAD's history"}
	}

	return rev, parent, nil
}

// requireSesamClean refuses uncommitted changes to the vault or its configs:
// the revert restores both from HEAD and would throw them away.
func requireSesamClean(ctx context.Context, worktreeRoot, prefix string) error {
	out, err := gitOutput(ctx, worktreeRoot, append([]string{"status", "--porcelain", "--"}, sesamPathspecs(prefix)...)...)
	if err != nil {
		return err
	}

	if out != "" {
		return fmt.Errorf("uncommitted changes to the vault - commit or discard them first:\n%s", out)
	}

	return nil
}

// sesamPathspecs names what sesam owns in git: the vault and every config.
func sesamPathspecs(prefix string) []string {
	base := filepath.ToSlash(prefix)
	if base == "." {
		base = ""
	} else {
		base += "/"
	}

	return []string{base + core.SesamDir(), ":(glob)" + base + "**/sesam.yml"}
}

// planRevert loads the reverted commit and its parent as repos of their own,
// each verified as a whole, and lets the live repo work out the inverse.
func planRevert(ctx context.Context, cmd *cli.Command, r *repo.Repo, rev, parent string) (*repo.RevertPlan, error) {
	sesamDir := r.SesamDir()
	opts := repo.RepoOpts{
		AskpassProgram:  cmd.String("askpass"),
		AskpassRequired: askpassRequired(),
		VerifyMode:      repo.VerifyModeNoDisk,
		Identities:      r.Identities(),
	}

	load := func(rev, name string) (*repo.Repo, func(), error) {
		dir := filepath.Join(sesamDir, core.SesamTmpDir(), name)
		side, err := loadVerifiedRevision(ctx, sesamDir, rev, dir, cmd.StringSlice("identity"), opts)
		if err != nil {
			_ = os.RemoveAll(dir)
			return nil, nil, fmt.Errorf("%s: %w", short(rev), err)
		}

		return side, func() {
			_ = side.Close()
			_ = os.RemoveAll(dir)
		}, nil
	}

	before, closeBefore, err := load(parent, "revert-before")
	if err != nil {
		return nil, err
	}
	defer closeBefore()

	after, closeAfter, err := load(rev, "revert-after")
	if err != nil {
		return nil, err
	}
	defer closeAfter()

	return r.PlanRevert(ctx, before, after)
}

// gitRevertNoCommit lets git revert everything but sesam's own files, which are
// put back to HEAD for the revert to write its inverse onto.
func gitRevertNoCommit(ctx context.Context, worktreeRoot, prefix, rev string) error {
	// Conflicts outside the vault are left to the user, as with any revert.
	runErr := runGitAsRevert(ctx, worktreeRoot, "revert", "--no-commit", rev)
	if mergeState(ctx, filepath.Join(worktreeRoot, prefix)) != mergeKindRevert {
		return fmt.Errorf("git revert %s: %w", short(rev), runErr)
	}

	args := append([]string{"restore", "--source=HEAD", "--staged", "--worktree", "--"}, sesamPathspecs(prefix)...)
	if err := runGitAsRevert(ctx, worktreeRoot, args...); err != nil {
		abortGitRevert(ctx, worktreeRoot)
		return fmt.Errorf("restore the vault from HEAD: %w", err)
	}

	return nil
}

// runGitAsRevert runs git marked as part of `sesam revert`, so the drivers keep
// our side and the hooks stay out of the repo this process holds locked.
func runGitAsRevert(ctx context.Context, dir string, args ...string) error {
	//nolint:gosec // fixed git subcommands; args are built in this file.
	c := exec.CommandContext(ctx, "git", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), envRevert+"=1")
	c.Stdout = os.Stderr
	c.Stderr = os.Stderr

	return c.Run()
}

func abortGitRevert(ctx context.Context, worktreeRoot string) {
	if err := runGitAsRevert(ctx, worktreeRoot, "revert", "--abort"); err != nil {
		fmt.Fprintln(os.Stderr, "sesam: could not abort the git revert, run `git revert --abort` yourself")
	}
}

// printRevertPlan shows what the revert does (res nil: would do) and how to
// finish it.
func printRevertPlan(cmd *cli.Command, sesamDir string, plan *repo.RevertPlan, res *repo.RevertResult) error {
	if cmd.Bool("json") {
		return printJSON(struct {
			*repo.RevertPlan
			*repo.RevertResult
		}{plan, res})
	}

	for _, step := range plan.Steps {
		if step.Path != "" {
			step.Path = DisplayPath(sesamDir, step.Path)
			if step.To != "" {
				step.To = DisplayPath(sesamDir, step.To)
			}
		}

		fmt.Println(step)
	}

	for _, c := range plan.Content {
		switch {
		case c.Conflicts > 0:
			fmt.Printf("! content of %s (%d %s)\n", DisplayPath(sesamDir, c.Path), c.Conflicts, pluralize("conflict", c.Conflicts))
		default:
			fmt.Printf("~ content of %s\n", DisplayPath(sesamDir, c.Path))
		}
	}

	for _, s := range plan.Skipped {
		fmt.Printf("  skipped %s %s: %s\n", s.Op, s.Target, s.Reason)
	}

	if res == nil {
		return nil
	}

	for _, p := range res.Conflicted {
		// git runs no hook on --continue while nothing is staged, so the seal and
		// the add are on the user.
		p = DisplayPath(sesamDir, p)
		fmt.Fprintf(
			os.Stderr,
			"sesam: resolve the conflict markers in %s, then run `sesam seal %s` and `git add %s`\n",
			p, p, DisplayPath(sesamDir, core.SesamDir()),
		)
	}

	fmt.Fprintln(os.Stderr, "sesam: review the result, then finish with `git revert --continue` (or start over with `git revert --abort`)")
	return nil
}

// hasStagedChanges reports whether the index differs from HEAD.
func hasStagedChanges(ctx context.Context, worktreeRoot string) bool {
	c := exec.CommandContext(ctx, "git", "diff", "--cached", "--quiet")
	c.Dir = worktreeRoot
	return c.Run() != nil
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}

	return rev
}
