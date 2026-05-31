package commands

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleShow decrypts an object (audit log, secret, or user) and writes a
// human-readable form to stdout.
//
// Show deliberately does NOT go through WithRepo. It is invoked by git as a
// textconv during `git diff`, once per blob, so loading the audit log and
// building managers for every invocation is unacceptable overhead. The
// dispatch tries the cheap paths first (audit log, then secret) and only
// loads a full Repo for the last-resort user lookup.
func HandleShow(ctx context.Context, cmd *cli.Command) error {
	identityPaths := cmd.StringSlice("identity")
	object := cmd.StringArg("object")

	ids, err := repo.LoadIdentities(identityPaths, repo.RepoOpts{Interactive: true})
	if err != nil {
		return err
	}

	if filepath.Base(object) == "log.jsonl" {
		ok, err := core.ShowAuditLog(ids, object, os.Stdout)
		if ok {
			return err
		}
		return fmt.Errorf("cannot open audit log: %s", object)
	}

	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	ok, err := core.ShowSecret(sesamDir, ids, object, os.Stdout)
	if ok {
		return err
	}

	// Last resort: the object might be a user name. This needs the audit
	// log + managers, so we accept the load cost only on this branch.
	return WithRepo(func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		ok, err = r.ShowUser(object, os.Stdout)
		if ok {
			return err
		}

		return fmt.Errorf("not sure what this is: %s", object)
	})(ctx, cmd)
}
