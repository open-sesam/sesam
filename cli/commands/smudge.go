package commands

import (
	"context"
	"fmt"
	"os"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleSmudge is the git smudge filter entry point. Git invokes it
// once per `git checkout` (or similar) and drives the pkt-line protocol
// described in `man 5 gitattributes` and gitprotocol-common. Identities
// are loaded once and reused across every blob, amortising key /
// passphrase cost. Configured via `filter.sesam-filter.process = sesam
// smudge` - sesam requires git >= 2.11 (Dec 2016) for this protocol.
//
// The encrypted blob passes through to stdout unchanged (the
// working-tree .sesam file stays encrypted) and the plaintext is
// decrypted to the embedded RevealedPath as a side effect. The
// sesamDir is derived from the per-request pathname (see
// clirepo.splitObjectPath) so the handler works whether .sesam lives
// at the worktree root or in a subdir. Reveal failures are logged but
// do not fail the smudge - aborting the git checkout would be worse
// than a stale or missing revealed file.
func HandleSmudge(ctx context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	identityPaths := cmd.StringSlice("identity")
	if len(identityPaths) == 0 {
		return fmt.Errorf("need at least one identity")
	}

	ids, err := loadIdentitiesKeyringOnly(identityPaths, keyringFingerprint)
	if err != nil {
		return err
	}

	// Load the audit view up-front. A filter session that can't verify
	// the audit log must fail-fast: silently degrading to "decrypt without
	// auth check" would defeat the sealer-authorization check on every
	// blob in the session.
	kr, authorize, err := clirepo.LoadAuditView(sesamDir, ids)
	if err != nil {
		return fmt.Errorf("load audit view for smudge filter: %w", err)
	}

	handler := &clirepo.FilterProcessHandler{
		SesamDir:      sesamDir,
		Identities:    ids,
		IdentityPaths: identityPaths,
		Keyring:       kr,
		Authorize:     authorize,
	}

	return handler.Run(ctx, os.Stdin, os.Stdout)
}
