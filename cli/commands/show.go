package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

	// TODO: Options to either force resolution as audit, user, secret, ...
	// TODO: Show secret metadata (access list)
	object := cmd.StringArg("object")
	return withRepoLock(sesamDir, 5*time.Second, func() error {
		switch {
		case filepath.Base(object) == "log.jsonl":
			identityPaths := cmd.StringSlice("identity")
			ids, err := loadIdentities(
				identityPaths,
				"sesam.identity.runtime",
			)
			if err != nil {
				return err
			}

			auditLog, err := core.LoadAuditLog(sesamDir, ids)
			if err != nil {
				return fmt.Errorf("failed to load audit log: %w", err)
			}

			return auditLog.AsJSON(os.Stdout)
		default:
			// assume we should show a secret:
			identityPaths := cmd.StringSlice("identity")
			ids, err := loadIdentities(
				identityPaths,
				"sesam.identity.runtime",
			)
			if err != nil {
				return err
			}

			ok, err := core.ShowSecret(sesamDir, ids, object, os.Stdout)
			if ok {
				return err
			}

			// NOTE: This gets expensive, so do it last:
			_, um, err := buildManagers(sesamDir, identityPaths)
			if err != nil {
				return err
			}

			ok, err = um.ShowUser(object, os.Stdout)
			if ok {
				return err
			}

			return fmt.Errorf("not sure what this is: %s", object)
		}
	})
}
