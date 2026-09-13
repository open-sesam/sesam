package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
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
		[]string{"verified/", "declared/"},
		cmd.Args().Slice(),
	)
}
