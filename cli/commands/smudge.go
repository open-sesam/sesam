package commands

import (
	"context"
	"os"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleSmudge is the git smudge filter entry point. Git invokes it once per
// `git checkout` (or similar) and drives the pkt-line protocol described in
// `man 5 gitattributes`. The smudge filter never acquires the repo lock —
// git already serializes the worktree.
func HandleSmudge(ctx context.Context, cmd *cli.Command) error {
	return repo.RunSmudgeFilter(
		ctx,
		cmd.String("sesam-dir"),
		cmd.StringSlice("identity"),
		repo.RepoOpts{
			AskpassProgram:  cmd.String("askpass"),
			AskpassRequired: askpassRequired(),
		},
		os.Stdin,
		os.Stdout,
	)
}
