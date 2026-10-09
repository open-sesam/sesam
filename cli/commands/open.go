package commands

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleOpen reveals what is missing or stale and keeps plaintext edited here,
// naming it. --all overwrites everything.
func HandleOpen(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	if cmd.Bool("all") {
		return r.RevealAll()
	}

	states, err := r.SyncStates(syncOpts(r.SesamDir()))
	if err != nil {
		return err
	}

	if err := refreshStale(r, states, true); err != nil {
		return err
	}

	printKeptEdits(states)
	return nil
}

// refreshStale reveals the plaintext whose object moved away from it (and,
// with missing, the plaintext that is not there at all), then records those
// paths as in sync so a Seal handed the same states only checks recipients.
func refreshStale(r *repo.Repo, states repo.SyncStates, missing bool) error {
	want := []repo.SecretState{repo.SecretStateStale}
	if missing {
		want = append(want, repo.SecretStateNoRevealedPath)
	}

	paths := states.Paths(want...)
	if err := r.RevealPaths(paths); err != nil {
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
		"`sesam seal` keeps your version, `sesam reveal --all` takes the objects.",
	)
}
