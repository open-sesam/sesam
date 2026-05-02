package commands

import (
	"context"
	"fmt"
	"time"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleTell adds a user/group relation and updates access.
func HandleShow(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	// TODO: Support later showing audit log, users, forge-ids, ...
	objectPath := cmd.Args().First()
	return withRepoLock(sesamDir, 5*time.Second, func() error {
		identityPaths := cmd.StringSlice("identity")
		sm, _, err := buildManagers(sesamDir, identityPaths)
		if err != nil {
			return err
		}

		fmt.Println(objectPath, sm)
		// TODO: call it here.
		return nil
	})
}
