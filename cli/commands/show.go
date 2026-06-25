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

	ids, err := repo.LoadIdentities(identityPaths, repo.RepoOpts{
		AskpassProgram:  cmd.String("askpass"),
		AskpassRequired: askpassRequired(),
	})
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

	// Absolute paths are an explicit exception: show decrypts any .sesam file
	// directly (like `age -d`), and git's diff textconv also hands us an
	// absolute temp-file path for an extracted blob. Either way it is passed
	// through untouched - ShowSecret opens it directly.
	//
	// A relative argument is translated into a sesam-relative path. toRepoPath
	// only errors when the arg escapes the sesam dir (e.g. `../outside`), so
	// surface that rather than silently reading a bad path and ending up at the
	// misleading user-name fallback. Plain names (no escape) resolve fine and
	// still fall through to the user lookup when they aren't a secret.
	showPath := object
	if !filepath.IsAbs(object) {
		cwd, _ := os.Getwd()
		rel, relErr := toRepoPath(sesamDir, cwd, object)
		if relErr != nil {
			return relErr
		}
		showPath = rel
	}

	root, rootErr := os.OpenRoot(sesamDir)
	if rootErr != nil {
		return rootErr
	}

	ok, showErr := core.ShowSecret(root, ids, showPath, os.Stdout)
	_ = root.Close()
	if ok {
		return showErr
	}

	// Last resort: the object might be a user name. This needs the audit
	// log + managers, so we accept the load cost only on this branch.
	return WithRepo(func(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
		ok, err := r.ShowUser(object, os.Stdout)
		if ok {
			return err
		}

		return fmt.Errorf("not sure what this is: %s", object)
	})(ctx, cmd)
}
