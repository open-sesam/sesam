package commands

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// silentWithRepo opens the repo like WithRepo but silently no-ops when the
// repository does not exist, so a hook never aborts a git operation in a
// non-sesam repo.
func silentWithRepo(verifyMode repo.VerifyMode, action RepoAction) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) (err error) {
		// Resolve up front: repo.Load/IsInitialized walk up to the nearest .sesam,
		// while the git helpers below only take Abs() of what they are given. Run
		// from a subdirectory the two would name different trees, and the git
		// pathspec would then match nothing.
		sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
		if err != nil {
			slog.Warn("sesam hook: failed to resolve sesam dir", slog.Any("err", err))
			// do not abort the git operation!
			return nil
		}

		exists, err := repo.IsInitialized(sesamDir)
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

		r, err := repo.Load(sesamDir, cmd.StringSlice("identity"), repo.RepoOpts{
			Interactive: true,
			LockTimeout: cmd.Duration("lock-timeout"),
			VerifyMode:  verifyMode,
			InMerge:     mergeState(sesamDir).InProgress(),
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
		kind := mergeState(sesamDir)
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

		states, err := r.SyncStates(syncOpts(sesamDir))
		if err != nil {
			return err
		}

		if diverged := states.Paths(repo.SecretStateDiverged); len(diverged) > 0 {
			return divergedError(diverged, kind)
		}

		if err := refreshStale(r, states, false); err != nil {
			return err
		}

		if err := r.Update(func(s *repo.Stage) error {
			if merging {
				// There might be leftover secrets or signkeys, that are not in the audit-log anymore.
				// (i.e. the decisions made during audit log merge might be different than what secret-merger does)
				if err := s.PruneUnusedAfterMerge(); err != nil {
					return err
				}
			}

			_, err := s.Seal(repo.SealOpts{States: states})
			return err
		}); err != nil {
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
		}

		return r.GitAddDotSesam()
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
		if mergeState(r.SesamDir()).InProgress() {
			return nil
		}

		sync := syncOpts(r.SesamDir())
		if branchCheckout && isCommitHash(prev) {
			sync.Before = prev
		}

		states, err := r.SyncStates(sync)
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
			if err := refreshStale(r, states, true); err != nil {
				slog.Warn("failed to reveal secrets after checkout", slog.Any("err", err))
			}
			return nil
		}

		// File checkout (git checkout -- path): a single sealed object may have
		// been restored without its audit log, leaving the on-disk root hash
		// stale. Take the checked-out object where the plaintext is still the
		// previous version, then seal to record it in the log so the repo is
		// consistent again (a no-op when nothing drifted).
		if err := refreshStale(r, states, true); err != nil {
			slog.Warn("failed to reveal secrets after checkout", slog.Any("err", err))
		}
		if err := r.Update(func(s *repo.Stage) error {
			_, err := s.Seal(repo.SealOpts{States: states})
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

		paths, err := listPaths(sesamDir)
		if err != nil {
			slog.Warn("failed to list merged secrets", slog.Any("err", err))
			return nil
		}
		if len(paths) == 0 {
			return nil
		}

		sync := syncOpts(sesamDir)
		sync.Paths = paths
		sync.Before = resolveRev(sesamDir, before)

		states, err := r.SyncStates(sync)
		if err != nil {
			slog.Warn("failed to compare merged secrets", slog.Any("err", err))
			return nil
		}

		// Plaintext edited before the merge stays, also where the merge replaced
		// the object (conflicted secrets included: their plaintext is the
		// driver's, waiting to be resolved). Only the untouched one is refreshed.
		printKeptEdits(states)

		if err := refreshStale(r, states, true); err != nil {
			slog.Warn("failed to reveal secrets after merge", slog.Any("err", err))
		}

		return nil
	})(ctx, cmd)
}

// HandleHookPreMergeCommit runs when git is about to auto-commit a clean merge.
// If the merge changed sesam state it exits non-zero so git stops WITHOUT
// committing, leaving a fully resolved index. The user then runs `git commit`,
// whose pre-commit reseals + reconciles - so a merge finalizes with no `git add`.
// A merge that never touched sesam auto-commits like any other.
func HandleHookPreMergeCommit(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		//nolint:nilerr // never block a merge on our own resolution error
		return nil
	}

	exists, err := repo.IsInitialized(sesamDir)
	if err != nil || !exists {
		//nolint:nilerr // not a sesam repo (or unreadable) => let git auto-commit
		return nil
	}

	changed, err := mergeTouchedSesam(sesamDir)
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
func HandleHookInstall(_ context.Context, cmd *cli.Command) error {
	return repo.InstallHooks(cmd.String("sesam-dir"))
}

func HandleHookUninstall(_ context.Context, cmd *cli.Command) error {
	return repo.UninstallHooks(cmd.String("sesam-dir"))
}
