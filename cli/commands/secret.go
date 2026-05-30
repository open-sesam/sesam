package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	groups := normalizedGroups(cmd.StringSlice("group"))
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), cmd.Duration("lock-timeout"), core.NewInteractivePluginUI(), func(mgr *runtimeManagers) error {
		if err := repo.WithWorkingDir(sesamDir, func() error {
			return mgr.Secret.AddSecret(revealedPath, groups)
		}); err != nil {
			return fmt.Errorf("failed to add secret %q: %w", revealedPath, err)
		}

		return nil
	})
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), cmd.Duration("lock-timeout"), core.NewInteractivePluginUI(), func(mgr *runtimeManagers) error {
		if err := mgr.Secret.RemoveSecret(revealedPath); err != nil {
			return fmt.Errorf("failed to remove secret %q: %w", revealedPath, err)
		}

		return nil
	})
}

// HandleMove renames or relocates a tracked secret path.
func HandleMove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify mv")
}

func normalizedGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		if group == "" {
			continue
		}
		out = append(out, group)
	}

	return out
}
