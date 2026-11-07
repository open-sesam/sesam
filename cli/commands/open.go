package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleOpen reveals what is missing or stale and keeps plaintext edited here,
// naming it. Named paths and --force-diverged take the object over such edits;
// --all overwrites everything.
func HandleOpen(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Bool("all") {
		return r.RevealAll(ctx)
	}

	paths, err := toRepoPaths(r.SesamDir(), cmd.Args().Slice())
	if err != nil {
		return err
	}

	states, err := r.SyncStates(ctx, syncOpts(ctx, r.SesamDir()))
	if err != nil {
		return err
	}

	if err := checkRevealable(states, paths); err != nil {
		return err
	}

	if cmd.Bool("force-diverged") {
		paths = append(paths, states.Paths(repo.SecretStateDiverged)...)
	}

	// Only edited plaintext is lost; the rest is a plain refresh.
	discarded := repo.SyncStates{}
	for _, p := range paths {
		if st := states[p]; st == repo.SecretStateNotInSync || st == repo.SecretStateDiverged {
			discarded[p] = st
		}
	}

	if err := r.RevealPaths(ctx, paths); err != nil {
		return err
	}

	for _, p := range paths {
		states[p] = repo.SecretStateInSync
	}

	if err := refreshStale(ctx, r, states, true); err != nil {
		return err
	}

	printDiscardedEdits(discarded)
	printKeptEdits(states)
	return nil
}

// checkRevealable refuses named paths a reveal could not write, instead of
// leaving them alone without a word.
func checkRevealable(states repo.SyncStates, paths []string) error {
	for _, p := range paths {
		state, ok := states[p]
		switch {
		case !ok:
			return fmt.Errorf("%s: not a tracked secret", p)
		case state == repo.SecretStateUserHasNoAccess:
			return fmt.Errorf("%s: you have no access to this secret", p)
		case state == repo.SecretStateNoSealedPath:
			return fmt.Errorf("%s: never sealed, there is nothing to reveal", p)
		}
	}

	return nil
}

// printDiscardedEdits names the edited plaintext a reveal overwrote: it was
// gitignored and unsealed, so this is the only trace of it.
func printDiscardedEdits(discarded repo.SyncStates) {
	paths := discarded.Paths(repo.SecretStateNotInSync, repo.SecretStateDiverged)
	if len(paths) == 0 {
		return
	}

	printNote(
		fmt.Sprintf("discarded your unsealed edits in %d %s:", len(paths), pluralize("secret", len(paths))),
		paths,
		"They were overwritten with the sealed version.",
	)
}

// refreshStale reveals the plaintext whose object moved away from it (and,
// with missing, the plaintext that is not there at all), then records those
// paths as in sync so a Seal handed the same states only checks recipients.
func refreshStale(ctx context.Context, r *repo.Repo, states repo.SyncStates, missing bool) error {
	want := []repo.SecretState{repo.SecretStateStale}
	if missing {
		want = append(want, repo.SecretStateNoRevealedPath)
	}

	paths := states.Paths(want...)
	if err := r.RevealPaths(ctx, paths); err != nil {
		return err
	}

	for _, p := range paths {
		states[p] = repo.SecretStateInSync
	}

	return nil
}

// printKeptEdits names the secrets a reveal did not touch because their
// plaintext was edited here.
func printKeptEdits(states repo.SyncStates) {
	modified := states.Paths(repo.SecretStateNotInSync)
	diverged := states.Paths(repo.SecretStateDiverged)
	kept := len(modified) + len(diverged)
	if kept == 0 {
		return
	}

	lines := modified
	for _, p := range diverged {
		lines = append(lines, p+" (its object changed in git as well)")
	}

	printNote(
		fmt.Sprintf("kept %d edited %s (not revealed):", kept, pluralize("secret", kept)),
		lines,
		"`sesam seal` keeps your version (`--force-diverged` for diverged ones), `sesam reveal <path>` takes the object (`--force-diverged` for all diverged ones).",
	)
}
