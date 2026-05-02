package commands

import (
	"context"
	"os"
	"time"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleShow decrypts a secret and writes it to stdout.
func HandleShow(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	// TODO: Support later showing audit log, users, forge-ids, ...
	// TODO: Support showing several
	// TODO: This loads the full audit log and all. Bit too much work for a simple diff. identity loadign is enough for reveal.
	objectPath := cmd.Args().First()
	return withRepoLock(sesamDir, 5*time.Second, func() error {
		identityPaths := cmd.StringSlice("identity")
		ids, err := loadIdentities(
			identityPaths,
			"sesam.identity.runtime",
		)
		if err != nil {
			return err
		}

		return core.ShowSecret(ids, objectPath, os.Stdout)
	})
}
