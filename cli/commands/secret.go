package commands

import (
	"context"
	"fmt"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	if !cmd.Args().Present() {
		return fmt.Errorf("need at least one path")
	}

	groups := normalizedGroups(cmd.StringSlice("group"))
	if len(groups) == 0 {
		printInfo("no groups specified, assuming `--group admin` only")
	}

	return r.SecretAdd(cmd.Args().Slice(), groups)
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	revealedPath := cmd.Args().First()
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
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
