package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, cmd *cli.Command, r *repo.Repo, configRepo *config.ConfigRepository) error {
	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	groups := normalizedGroups(cmd.StringSlice("group"))
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	if err := configRepo.AddSecrets(revealedPath, cmd.Bool("own-sesam-file"), groups); err != nil {
		return fmt.Errorf("failed to add secret to config: %w", err)
	}

	return r.SecretAdd([]string{revealedPath}, groups)
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, cmd *cli.Command, r *repo.Repo, configRepo *config.ConfigRepository) error {
	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	if err := configRepo.RemoveSecrets(revealedPath, cmd.Bool("purge")); err != nil {
		return fmt.Errorf("failed to remove secret from config: %w", err)
	}

	return r.SecretRemove([]string{revealedPath})
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
