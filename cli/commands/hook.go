package commands

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

// silentWithRepo opens the repo like WithRepo but silently no-ops when the
// repository does not exist, so a hook never aborts a git operation in a
// non-sesam repo.
func silentWithRepo(verifyMode repo.VerifyMode, action RepoAction) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) (err error) {
		if os.Getenv(envRevert) == "1" {
			return nil
		}

		// Resolve up front: repo.Load/IsInitialized walk up to the nearest .sesam,
		// while the git helpers below only take Abs() of what they are given. Run
		// from a subdirectory the two would name different trees, and the git
		// pathspec would then match nothing.
		sesamDir, err := repo.ResolveSesamDir(ctx, cmd.String("sesam-dir"))
		if err != nil {
			slog.Warn("sesam hook: failed to resolve sesam dir", slog.Any("err", err))
			// do not abort the git operation!
			return nil
		}

		exists, err := repo.IsInitialized(ctx, sesamDir)
		if err != nil {
			slog.Warn(
				"sesam hook: failed to check if sesam repo exists",
				slog.String("dir", sesamDir),
				slog.Any("err", err),
			)
			// do not abort the git operation!
			return nil
		}

		if !exists {
			// abort silently.
			return nil
		}

		r, err := repo.Load(ctx, sesamDir, cmd.StringSlice("identity"), repo.RepoOpts{
			Interactive:     true,
			LockTimeout:     cmd.Duration("lock-timeout"),
			AskpassProgram:  cmd.String("askpass"),
			AskpassRequired: askpassRequired(),
			VerifyMode:      verifyMode,
			InMerge:         mergeState(ctx, sesamDir).InProgress(),
		})
		if err != nil {
			return err
		}

		defer func() {
			if closeErr := r.Close(); closeErr != nil && err == nil {
				err = fmt.Errorf("close repo: %w", closeErr)
			}
		}()

		return action(ctx, cmd, r)
	}
}

// Run seal (only if needed, depending on audit log and if .sesam exists) and verify. If very fails we should abort the commit.
//
// no-disk verify: an object may have been checked out without its audit log,
// leaving the on-disk root hash stale. Load must tolerate that so the Seal below
// can reconcile the log; the seal-less full verify would otherwise reject the
// load and block the commit without a way to self-heal.
func HandleHookPreCommit(ctx context.Context, cmd *cli.Command) error {
	return silentWithRepo(repo.VerifyModeNoDisk, func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		// If we're in a merge, then we need to straighten a few things before we can really commit.
		sesamDir := r.SesamDir()
		kind := mergeState(ctx, sesamDir)
		merging := kind.InProgress()

		// Refuse to seal markers into the ciphertext - git can't see them, since
		// revealed files are gitignored.
		if merging {
			conflicted, err := r.ConflictedSecrets()
			if err != nil {
				return err
			}
			if len(conflicted) > 0 {
				return fmt.Errorf(
					"unresolved conflicts in this %s:\n%s\nfix them, then run `%s` again",
					kind,
					strings.Join(conflictedSecretHints(conflicted), "\n"),
					cmp.Or(kind.ContinueCmd(), "git commit"),
				)
			}
		}

		states, err := r.SyncStates(ctx, syncOpts(ctx, sesamDir))
		if err != nil {
			return err
		}

		reverting := kind == mergeKindRevert

		if diverged := states.Paths(repo.SecretStateDiverged); len(diverged) > 0 && !reverting {
			return divergedError(diverged, kind)
		}

		if !reverting {
			if err := refreshStale(ctx, r, states, false); err != nil {
				return err
			}
		}

		if err := r.Update(func(s *repo.Stage) error {
			if merging {
				// There might be leftover secrets or signkeys, that are not in the audit-log anymore.
				// (i.e. the decisions made during audit log merge might be different than what secret-merger does)
				if err := s.PruneUnusedAfterMerge(); err != nil {
					return err
				}
			}

			_, err := s.Seal(ctx, repo.SealOpts{States: states, ForceStale: reverting, ForceDiverged: reverting})
			return err
		}); err != nil {
			return err
		}

		// Verify what gets committed: the staged log, after sesam's own changes.
		if err := r.GitAddDotSesam(ctx); err != nil {
			return err
		}

		verifyOpts := repo.VerifyOptions{
			Truncation: true,
			KeyReuse:   true,
			ForgeCheck: false,
			Integrity:  true,
		}

		report, err := r.Verify(ctx, verifyOpts)
		if err != nil {
			return err
		}

		if !report.OK() {
			printReport(verifyOpts, report)
			return fmt.Errorf("verification failed - please fix before committing")
		}

		if merging {
			// Whatever the merge unpacked to verify is not needed past this point.
			if err := r.ClearTmp(); err != nil {
				slog.Warn("could not clear the tmp dir", slog.Any("err", err))
			}

			// sesam.yml took ours via the sesam-ours merge driver, so it still
			// declares whatever side "ours" happened to be, not the merged audit
			// log. Force: a config this hook can't repair in place must still be
			// resolved somehow, and there is no one left to ask.
			cfgReset, err := r.ConfigReset(repo.ConfigResetOpts{Force: true})
			if err != nil {
				return fmt.Errorf("reset config after merge: %w", err)
			}

			if err := r.GitAddConfig(ctx, cfgReset.Deleted); err != nil {
				return fmt.Errorf("stage config after merge reset: %w", err)
			}
		}

		return r.GitAddDotSesam(ctx)
	})(ctx, cmd)
}

// divergedError explains a secret that was edited here while the operation
// replaced its object. Neither side can be picked for the user.
func divergedError(paths []string, kind mergeKind) error {
	where := "in git"
	if kind.InProgress() {
		where = "in this " + kind.String()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%d %s changed both here and %s:\n", len(paths), pluralize("secret", len(paths)), where)
	for _, p := range paths {
		b.WriteString("  " + p + "\n")
	}

	b.WriteString(waysOut)
	if abort := kind.AbortCmd(); abort != "" {
		b.WriteString(", `" + abort + "` starts over")
	}

	return errors.New(b.String())
}

func HandleHookPostCheckout(ctx context.Context, cmd *cli.Command) error {
	// git passes (prev-HEAD, new-HEAD, is-branch-checkout). The flag is "1" for a
	// branch switch (and clone), "0" for a file checkout (git checkout -- path).
	// git does not tell us which files changed, but prev-HEAD says where the
	// objects came from, which is enough to tell stale plaintext from edited.
	prev := cmd.Args().Get(0)
	branchCheckout := cmd.Args().Get(2) != "0"

	// Run clean and open (only if .sesam exists) - is also run on git clone.
	// NOTE: Returning an error here does not stop git checkout, just makes the exit-code go red.
	//       We just print warnings therefore.
	// no-disk verify: a checkout may have changed sealed objects on disk, so the
	// on-disk root hash is expected to differ from the log until we reveal.
	return silentWithRepo(repo.VerifyModeNoDisk, func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		// Mid-merge the revealed files hold merged content that is not sealed yet,
		// so neither branch below may run: both reveal from the objects and would
		// throw the resolution away. `git checkout -b` is allowed with an unmerged
		// index, so this has to gate the branch path too.
		if mergeState(ctx, r.SesamDir()).InProgress() {
			return nil
		}

		sync := syncOpts(ctx, r.SesamDir())
		if branchCheckout && isCommitHash(prev) {
			sync.Before = prev
		}

		states, err := r.SyncStates(ctx, sync)
		if err != nil {
			slog.Warn("failed to compare secrets after checkout", slog.Any("err", err))
			return nil
		}

		// Edited plaintext survives the checkout, whatever the new branch holds;
		// git would refuse to overwrite it were it tracked.
		printKeptEdits(states)

		if branchCheckout {
			// Branch switch/clone: drop plaintext that has no readable secret on
			// the new branch, and any other untracked file under the sesam dir.
			// Current secrets stay - revealed below when stale or missing, kept
			// when edited. Aggressive clean is confined to the sesam dir.
			current := currentSecrets(states)
			_, err := r.Clean(ctx, repo.CleanOpts{
				Aggressive: true,
				CheckFunc:  func(path string) (bool, error) { return !current[path], nil },
			})
			if err != nil {
				slog.Warn("failed to clean up previous revealed secrets", slog.Any("err", err))
			}
			if err := refreshStale(ctx, r, states, true); err != nil {
				slog.Warn("failed to reveal secrets after checkout", slog.Any("err", err))
			}
			return nil
		}

		// File checkout (git checkout -- path): a single sealed object may have
		// been restored without its audit log, leaving the on-disk root hash
		// stale. Take the checked-out object where the plaintext is still the
		// previous version, then seal to record it in the log so the repo is
		// consistent again (a no-op when nothing drifted).
		if err := refreshStale(ctx, r, states, true); err != nil {
			slog.Warn("failed to reveal secrets after checkout", slog.Any("err", err))
		}
		if err := r.Update(func(s *repo.Stage) error {
			_, err := s.Seal(ctx, repo.SealOpts{States: states})
			return err
		}); err != nil {
			slog.Warn("failed to reseal after file checkout", slog.Any("err", err))
		}

		return nil
	})(ctx, cmd)
}

// currentSecrets is the plaintext a branch switch must not clean: every secret
// the user can read on the new branch. Leftovers of secrets they lost access to
// are not in it and go.
func currentSecrets(states repo.SyncStates) map[string]bool {
	current := make(map[string]bool, len(states))
	for _, p := range states.Paths(
		repo.SecretStateInSync,
		repo.SecretStateNotInSync,
		repo.SecretStateStale,
		repo.SecretStateDiverged,
		repo.SecretStateNoSealedPath,
	) {
		current[p] = true
	}

	return current
}

// HandleHookPostMerge refreshes the plaintext of secrets a completed merge changed.
// It's the only way to make sure the revealed text is up-to-date when doing
// things like fast-forward (i.e. git pull).
//
// Revealing is important, because leftover stale revealed files might be
// written back on an explicit seal.
func HandleHookPostMerge(ctx context.Context, cmd *cli.Command) error {
	// git passes 1 for a squash merge, which leaves the changes staged instead of
	// committing them - so HEAD has not moved and ORIG_HEAD tells us nothing.
	squash := cmd.Args().Get(0) == "1"

	return silentWithRepo(repo.VerifyModeNoDisk, func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		sesamDir := r.SesamDir()

		// Only git knows which objects the merge brought in, and where the
		// worktree was before it: ORIG_HEAD, or HEAD itself for a squash.
		listPaths, before := mergedSecretPaths, "ORIG_HEAD"
		if squash {
			listPaths, before = stagedSecretPaths, "HEAD"
		}

		paths, err := listPaths(ctx, sesamDir)
		if err != nil {
			slog.Warn("failed to list merged secrets", slog.Any("err", err))
			return nil
		}
		if len(paths) == 0 {
			return nil
		}

		sync := syncOpts(ctx, sesamDir)
		sync.Paths = paths
		sync.Before = resolveRev(ctx, sesamDir, before)

		states, err := r.SyncStates(ctx, sync)
		if err != nil {
			slog.Warn("failed to compare merged secrets", slog.Any("err", err))
			return nil
		}

		// Plaintext edited before the merge stays, also where the merge replaced
		// the object (conflicted secrets included: their plaintext is the
		// driver's, waiting to be resolved). Only the untouched one is refreshed.
		printKeptEdits(states)

		if err := refreshStale(ctx, r, states, true); err != nil {
			slog.Warn("failed to reveal secrets after merge", slog.Any("err", err))
		}

		return nil
	})(ctx, cmd)
}

// HandleHookPrepareCommitMsg refuses a `git revert` commit whose staged audit
// log drops entries of HEAD's. That is the one hook a plain `git revert` runs:
// it commits without pre-commit and would truncate the log unnoticed. Other
// commits are left to pre-commit, which `--no-verify` may skip on purpose.
func HandleHookPrepareCommitMsg(ctx context.Context, cmd *cli.Command) error {
	msgFile, source := cmd.Args().Get(0), cmd.Args().Get(1)
	if source == "commit" {
		return nil
	}

	rev := revertedCommit(msgFile)
	if rev == "" {
		return nil
	}

	sesamDir, err := repo.ResolveSesamDir(ctx, cmd.String("sesam-dir"))
	if err != nil {
		return nil //nolint:nilerr // a hook must never abort a commit outside sesam
	}

	if changed, err := stagedLogChanged(ctx, sesamDir); err != nil || !changed {
		return nil //nolint:nilerr // e.g. no HEAD yet: nothing to drop entries of
	}

	return silentWithRepo(repo.VerifyModeNoDisk, func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		err := r.VerifyStagedLog(ctx)

		var rewritten *core.AuditLogRewrittenError
		if !errors.As(err, &rewritten) {
			return err
		}

		// git already gave up on the commit and keeps no revert state, so we
		// undo its changes - but only when they are nothing but git's revert.
		undo := "git reset --merge"
		switch {
		case mergeState(ctx, sesamDir) == mergeKindRevert:
			undo = "git revert --abort"
		case undoPlainRevert(ctx, sesamDir, rev):
			fmt.Fprintln(os.Stderr, "sesam: undid what `git revert` changed (`git reset --merge`).")
			undo = ""
		}

		return fmt.Errorf(
			"the staged audit log drops entries that HEAD holds - refusing to commit:\n  %w\n\n%s",
			err, gitRevertRefusal(rev, undo),
		)
	})(ctx, cmd)
}

// revertedCommit reads the commit a `git revert` message names, "" if the
// message is not one.
func revertedCommit(msgFile string) string {
	//nolint:gosec // git hands us the message file of the commit in progress.
	data, err := os.ReadFile(msgFile)
	if err != nil {
		return ""
	}

	m := revertMsgPattern.FindSubmatch(data)
	if m == nil {
		return ""
	}

	return string(m[1])
}

// revertMsgPattern matches the line `git revert` puts into its message.
var revertMsgPattern = regexp.MustCompile(`This reverts commit ([0-9a-f]{7,64})`)

// undoPlainRevert runs `git reset --merge` for a commit that is nothing but
// git's own auto-committing revert of rev, and reports whether it did. Anything
// else - `revert --no-commit` (REVERT_HEAD), a sequence (sequencer dir), edits
// staged on top - is left alone: the reset would throw that work away.
func undoPlainRevert(ctx context.Context, sesamDir, rev string) bool {
	worktreeRoot, _, err := worktreePrefix(ctx, sesamDir)
	if err != nil || mergeState(ctx, sesamDir).InProgress() {
		return false
	}

	if seq, ok := gitProbe(ctx, worktreeRoot, "rev-parse", "--path-format=absolute", "--git-path", "sequencer"); !ok {
		return false
	} else if _, err := os.Stat(seq); !errors.Is(err, os.ErrNotExist) {
		return false
	}

	staged, ok := patchID(ctx, worktreeRoot, "diff", "--cached", "HEAD")
	if !ok {
		return false
	}

	commit, ok := commitInHistory(ctx, worktreeRoot, rev)
	if !ok {
		return false
	}

	reverted, ok := patchID(ctx, worktreeRoot, "diff", commit, commit+"^")
	if !ok || staged != reverted {
		return false
	}

	return runGitAsRevert(ctx, worktreeRoot, "reset", "--merge") == nil
}

// commitInHistory finds the one commit in HEAD's history whose hash starts with
// abbrev. The hash handed back is git's own, so the commit message never ends up
// on a git command line, and a ref that merely looks like a hash cannot match.
func commitInHistory(ctx context.Context, dir, abbrev string) (string, bool) {
	out, err := gitOutputRaw(ctx, dir, "rev-list", "HEAD")
	if err != nil {
		return "", false
	}

	found := ""
	for sha := range strings.FieldsSeq(out) {
		if !strings.HasPrefix(sha, abbrev) {
			continue
		}
		if found != "" {
			return "", false // ambiguous
		}
		found = sha
	}

	return found, found != ""
}

// patchID is the `git patch-id` of a `git diff ...`: equal for the same change,
// wherever it applies.
func patchID(ctx context.Context, dir string, diffArgs ...string) (string, bool) {
	args := append(append([]string{}, diffArgs...), "--binary", "--no-renames", "--no-ext-diff", "--no-textconv")

	//nolint:gosec // fixed git subcommands; the revs are hashes git printed itself.
	diff := exec.CommandContext(ctx, "git", args...)
	diff.Dir = dir

	out, err := diff.Output()
	if err != nil || len(out) == 0 {
		return "", false
	}

	id := exec.CommandContext(ctx, "git", "patch-id", "--stable")
	id.Dir = dir
	id.Stdin = bytes.NewReader(out)

	sum, err := id.Output()
	if err != nil {
		return "", false
	}

	fields := strings.Fields(string(sum))
	if len(fields) == 0 {
		return "", false
	}

	return fields[0], true
}

// stagedLogChanged reports whether the index holds another audit log than HEAD.
func stagedLogChanged(ctx context.Context, sesamDir string) (bool, error) {
	worktreeRoot, prefix, err := worktreePrefix(ctx, sesamDir)
	if err != nil {
		return false, err
	}

	logPath := filepath.ToSlash(filepath.Join(prefix, core.SesamDir(), "audit", "log.jsonl"))
	if _, ok := gitProbe(ctx, worktreeRoot, "rev-parse", "--verify", "HEAD^{commit}"); !ok {
		return false, nil
	}

	//nolint:gosec // fixed git subcommand; the path is derived from the repo layout.
	c := exec.CommandContext(ctx, "git", "diff", "--cached", "--quiet", "HEAD", "--", logPath)
	c.Dir = worktreeRoot

	err = c.Run()
	exitErr := new(exec.ExitError)
	switch {
	case err == nil:
		return false, nil
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
		return true, nil
	default:
		return false, err
	}
}

// HandleHookPreMergeCommit runs when git is about to auto-commit a clean merge.
// If the merge changed sesam state it exits non-zero so git stops WITHOUT
// committing, leaving a fully resolved index. The user then runs `git commit`,
// whose pre-commit reseals + reconciles - so a merge finalizes with no `git add`.
// A merge that never touched sesam auto-commits like any other.
func HandleHookPreMergeCommit(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(ctx, cmd.String("sesam-dir"))
	if err != nil {
		//nolint:nilerr // never block a merge on our own resolution error
		return nil
	}

	exists, err := repo.IsInitialized(ctx, sesamDir)
	if err != nil || !exists {
		//nolint:nilerr // not a sesam repo (or unreadable) => let git auto-commit
		return nil
	}

	changed, err := mergeTouchedSesam(ctx, sesamDir)
	if err != nil {
		slog.Warn("pre-merge-commit: sesam-change check failed; forcing manual finalize", slog.Any("err", err))
		changed = true // fail safe: never auto-commit an unsealed sesam merge
	}
	if !changed {
		return nil
	}

	fmt.Fprintln(os.Stderr, "sesam: merge changed the vault - run `git commit` to finalize (seal + reconcile + verify).")
	return &ExitCodeError{code: 1, print: false}
}

// HandleHookInstall (re)installs the git hooks. It only touches git config, so
// it does not load the repo (no lock, no audit-log verify).
func HandleHookInstall(ctx context.Context, cmd *cli.Command) error {
	return repo.InstallHooks(ctx, cmd.String("sesam-dir"))
}

func HandleHookUninstall(ctx context.Context, cmd *cli.Command) error {
	return repo.UninstallHooks(ctx, cmd.String("sesam-dir"))
}
