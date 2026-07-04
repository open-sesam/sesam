package commands

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// silentWithRepo opens the repo like WithRepo but skips opening
// if the repository does not exist.
func silentWithRepo(action RepoAction) cli.ActionFunc {
	return func(ctx context.Context, cmd *cli.Command) (err error) {
		sesamDir := cmd.String("sesam-dir")
		exists, err := repo.IsInitialized(sesamDir)
		if err != nil {
			slog.Warn(
				"sesam: pre-commit.hook: failed to check if sesam repo exists",
				slog.String("dir", sesamDir),
				slog.Any("err", err),
			)
			// do not abort the commit!
			return nil
		}

		if !exists {
			// abort silently.
			return nil
		}

		return WithRepo(func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
			return action(ctx, cmd, r)
		})(ctx, cmd)
	}
}

// Run seal (only if needed, depending on audit log and if .sesam exists) and verify. If very fails we should abort the commit.
func HandleHookPreCommit(ctx context.Context, cmd *cli.Command) error {
	return silentWithRepo(func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
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
	// Run clean and open (only if .sesam exists) - is also run on git clone.
	return silentWithRepo(func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		if err := r.RevealAll(); err != nil {
			// what happens when the post-checkout hook fails?
			return err
		}

		return r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
		})
	})(ctx, cmd)
}

func HandleHookInstall(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.InstallHooks()
}

func HandleHookUninstall(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	return r.UninstallHooks()
}
