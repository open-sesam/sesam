package commands

import (
	"context"
	"fmt"
	"os"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleSmudge is the git smudge filter entry point. It supports two modes:
//
//   - Long-running filter process (no path argument): git invokes the command
//     once per `git checkout` (or similar) and drives the pkt-line protocol
//     described in `man 5 gitattributes` and gitprotocol-common. Identities
//     are loaded once and reused across every blob, amortising key/passphrase
//     cost. Configured via `filter.sesam-filter.process = sesam smudge`.
//
//   - One-shot smudge (path argument): git invokes the command once per file,
//     piping the encrypted blob through stdin/stdout and passing the object
//     path as `%f`. Configured via `filter.sesam-filter.smudge = sesam
//     smudge %f`. Kept for older git versions and for manual debugging.
//
// In both modes the encrypted blob passes through to stdout unchanged (the
// working-tree .sesam file stays encrypted) and the plaintext is decrypted
// to the embedded RevealedPath as a side effect. The sesamDir is derived
// from the per-request pathname (see clirepo.splitObjectPath) so the
// handler works whether .sesam lives at the worktree root or in a subdir.
// Reveal failures are logged but do not fail the smudge - aborting the git
// checkout would be worse than a stale or missing revealed file.
func HandleSmudge(ctx context.Context, cmd *cli.Command) error {
	identityPaths := cmd.StringSlice("identity")
	if len(identityPaths) == 0 {
		return fmt.Errorf("need at least one identity")
	}

	ids, err := loadIdentitiesKeyringOnly(identityPaths, keyringFingerprint)
	if err != nil {
		return err
	}

	if cmd.Args().Len() > 0 {
		// Fallback for git<2.11: Long-running processes were not supported.
		// Instead we are called per-file. This is slower and has the drawback
		// that we do not cleanup revealed files that are not in the current index.
		path := cmd.Args().Get(0)
		return clirepo.RunOneShotSmudge(ids, path, os.Stdin, os.Stdout)
	}

	handler := &clirepo.FilterProcessHandler{
		Identities:    ids,
		IdentityPaths: identityPaths,
	}

	return handler.Run(ctx, os.Stdin, os.Stdout)
}
