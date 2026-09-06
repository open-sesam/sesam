package commands

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

// HandleSeal encrypts and signs tracked secrets via a staged seal commit.
//
// Conflict markers are warned about, not refused: seal is what you reach for to
// get out of a half-finished merge, so refusing would be the bigger trap.
func HandleSeal(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	conflicted, err := r.ConflictedSecrets()
	if err != nil {
		return err
	}

	if len(conflicted) > 0 {
		fmt.Fprintf(
			os.Stderr,
			"sesam: WARNING: sealing %d %s with unresolved conflicts - the markers are being encrypted as-is:\n%s\n",
			len(conflicted),
			pluralize("secret", len(conflicted)),
			strings.Join(conflictedSecretHints(conflicted), "\n"),
		)
	}

	if err := warnIfSealingOverMerge(cmd, r); err != nil {
		return err
	}

	if err := r.Update(func(s *repo.Stage) error {
		return s.Seal(cmd.Bool("seal-all"))
	}); err != nil {
		return err
	}

	if cmd.Bool("clean") {
		return r.Clean(ctx, repo.CleanOpts{
			Aggressive: false,
		})
	}

	return nil
}

// warnIfSealingOverMerge warns when the audit log ends on a merge and nothing has
// sealed since: the revealed files are then likely still the pre-merge ones, and
// sealing writes them back over what the merge brought in. Silent while the
// operation is still in progress - there, sealing the resolution is the job.
func warnIfSealingOverMerge(cmd *cli.Command, r *repo.Repo) error {
	if mergeState(cmd.String("sesam-dir")).InProgress() {
		return nil
	}

	// Nothing drifted means nothing to write back, so there is nothing to warn
	// about - a `sesam reveal` right before us leaves exactly that state.
	drifted, err := hasDriftedSecret(r)
	if err != nil || !drifted {
		return err
	}

	var tip core.Operation
	if err := r.Log(func(e *core.AuditEntrySigned) error {
		tip = e.Operation
		return errStopLog
	}); err != nil && !errors.Is(err, errStopLog) {
		return err
	}

	if tip != core.OpMerge {
		return nil
	}

	fmt.Fprint(
		os.Stderr,
		"sesam: WARNING: the last audit entry is a merge and nothing was sealed since.\n"+
			"sesam: if you did not resolve these files yourself, run `sesam reveal` first -\n"+
			"sesam: sealing otherwise would write pre-merge plaintext back over the merged objects.\n",
	)

	return nil
}

// errStopLog breaks out of Repo.Log once we have seen the newest entry.
var errStopLog = errors.New("stop log iteration")

// hasDriftedSecret reports whether any secret's plaintext differs from its object.
func hasDriftedSecret(r *repo.Repo) (bool, error) {
	status, err := r.Status(repo.StatusOpts{IgnoreUnmanaged: true})
	if err != nil {
		return false, err
	}

	for _, f := range status.Files {
		if f.State == repo.SecretStateNotInSync {
			return true, nil
		}
	}

	return false, nil
}
