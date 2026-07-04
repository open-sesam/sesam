package commands

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// silentWithRepo opens the repo like WithRepo but silently no-ops when the
// repository does not exist, so a hook never aborts a git operation in a
// non-sesam repo.
func silentWithRepo(verifyMode repo.VerifyMode, action RepoAction) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) (err error) {
		sesamDir := cmd.String("sesam-dir")
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
func HandleHookPreCommit(ctx context.Context, cmd *cli.Command) error {
	return silentWithRepo(repo.VerifyModeDefault, func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		if err := r.Update(func(s *repo.Stage) error {
			return s.Seal(false)
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

		return r.GitAddDotSesam()
	})(ctx, cmd)
}

func HandleHookPostCheckout(ctx context.Context, cmd *cli.Command) error {
	// git passes (prev-HEAD, new-HEAD, is-branch-checkout). The flag is "1" for a
	// branch switch (and clone), "0" for a file checkout (git checkout -- path).
	// git does not tell us which files changed, so we cannot reveal selectively.
	branchCheckout := cmd.Args().Get(2) != "0"

	// Run clean and open (only if .sesam exists) - is also run on git clone.
	// NOTE: Returning an error here does not stop git checkout, just makes the exit-code go red.
	//       We just print warnings therefore.
	// no-disk verify: a checkout may have changed sealed objects on disk, so the
	// on-disk root hash is expected to differ from the log until we reveal.
	return silentWithRepo(repo.VerifyModeNoDisk, func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		// On a branch switch, aggressively drop stale plaintext under .sesam
		// (secrets removed or now inaccessible on the new branch) before
		// revealing the new set. Aggressive clean is confined to the sesam dir.
		// A file checkout must not wipe the worktree, so it only re-reveals
		// (e.g. restoring a checked-out sealed object).
		if branchCheckout {
			if err := r.Clean(ctx, repo.CleanOpts{Aggressive: true}); err != nil {
				slog.Warn("failed to clean up previous revealed secrets", slog.Any("err", err))
			}
		}

		if err := r.RevealAll(); err != nil {
			slog.Warn("failed to reveal secrets after checkout", slog.Any("err", err))
		}

		return nil
	})(ctx, cmd)
}

func HandleHookInstall(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.InstallHooks()
}

func HandleHookUninstall(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.UninstallHooks()
}
