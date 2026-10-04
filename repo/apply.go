package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"

	"opensesam.org/sesam/core"
	sesamConf "opensesam.org/sesam/repo/config"
	"opensesam.org/sesam/repo/diff"
)

// ConfigApplyOpts controls how an apply behaves.
type ConfigApplyOpts struct {
	// Force applies steps that arrived already committed, which
	// CommittedChangesError otherwise refuses. Reserve it for a declaration
	// whose origin you have checked.
	Force bool
}

// CommittedChangesError reports steps the working tree did not ask for: they
// are already in the committed configuration, so they reached this repository
// with a commit rather than with the edit in front of the user.
//
// Refusing them is what keeps a pushed sesam.yml from being applied by an
// admin who was only asked to "run sesam apply" - see the invalid modified
// config attack in docs/src/design.md.
//
// Error() is a short, library-friendly summary. Changes carries the full list
// for a caller - the cli - that wants to render it in detail instead.
type CommittedChangesError struct {
	Changes []diff.Change
}

func (e *CommittedChangesError) Error() string {
	return fmt.Sprintf(
		"sesam.yml declares %d change(s) that are already committed; pass --force to apply them anyway",
		len(e.Changes),
	)
}

// ConfigApply records what sesam.yml declares in the audit log, one entry per
// step of the diff.
//
// It runs inside a stage, so the whole plan is a transaction: every entry, key
// and object it writes lands in the fork of .sesam, and a failure anywhere
// leaves the live repository untouched. The caller commits (or rolls back) the
// stage - typically via Repo.Update, which also gives the plan and the seal
// that follows it a single atomic swap.
//
// sesam.yml itself is never written: the declaration is already the target
// state, so the file keeps the user's comments, anchors and descriptions
// exactly as they were.
//
// The returned changes are the ones that were carried out, in the order they
// were applied. Nothing to do yields no changes and no error.
func (s *Stage) ConfigApply(ctx context.Context, opts ConfigApplyOpts) ([]diff.Change, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isClosed() {
		return nil, ErrClosed
	}

	// Read sesam.yml once and reuse the declaration for the self-check below:
	// re-reading it there would compare against whatever the file says by the
	// time the last step finishes, not the declaration that was actually
	// planned against and applied
	cfg, err := sesamConf.Load(s.root, configFileName)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	declared, err := cfg.State()
	if err != nil {
		return nil, fmt.Errorf("declared state: %w", err)
	}

	plan, err := diff.Compute(s.vstate, declared)
	if err != nil {
		return nil, err
	}

	if plan.IsEmpty() {
		// plan.Changes, not nil: diff.Delta already guarantees a non-nil empty
		// slice here, so an apply with nothing to do matches diff's own
		// "nothing changed" output ([], not null) under --json.
		return plan.Changes, nil
	}

	if err := s.applyPreflight(plan.Changes, opts); err != nil {
		return nil, err
	}

	for _, change := range plan.Changes {
		if err := s.applyChange(ctx, change); err != nil {
			return nil, fmt.Errorf("failed to apply %q: %w", change, err)
		}
	}

	// The plan is only correct if it actually closed the gap. Re-diffing
	// against the same declaration catches anything the steps did not express.
	rest, err := diff.Compute(s.vstate, declared)
	if err != nil {
		return nil, fmt.Errorf("re-checking the applied state: %w", err)
	}

	if !rest.IsEmpty() {
		slog.Warn("applied state differs from sesam.yml - this is a bug, nothing was changed", slog.Any("diff", rest))
	}

	return plan.Changes, nil
}

// applyPreflight rejects plans that would fail part-way through, so the user
// gets one clear reason instead of an error from the middle of the log.
func (s *Stage) applyPreflight(changes []diff.Change, opts ConfigApplyOpts) error {
	me, exists := s.vstate.UserExists(s.whoami)
	if !exists {
		return fmt.Errorf("user %s is not part of this repository", s.whoami)
	}

	if !me.IsAdmin() {
		return fmt.Errorf(
			"applying the config needs admin rights, but %s is only in %v",
			s.whoami, me.Groups,
		)
	}

	// Every step after the first is signed as an admin and verified against the
	// state the previous ones built, so an apply that strips its own author of
	// admin rights invalidates everything that follows it.
	for _, change := range changes {
		if change.User != s.whoami {
			continue
		}

		switch change.Op {
		case core.OpUserKill:
			return fmt.Errorf(
				"sesam.yml drops %s, who is applying it - have another admin apply this",
				s.whoami,
			)
		case core.OpUserChangeGroups:
			if !slices.Contains(change.Groups, "admin") {
				return fmt.Errorf(
					"sesam.yml takes admin from %s, who is applying it - have another admin apply this",
					s.whoami,
				)
			}
		}
	}

	return s.requireLocalChanges(changes, opts)
}

// requireLocalChanges enforces the rule that an apply may only carry out what
// the working tree asks for: a step the committed configuration already
// declares did not originate with the user running the command.
func (s *Stage) requireLocalChanges(changes []diff.Change, opts ConfigApplyOpts) error {
	if opts.Force {
		slog.Warn("applying with --force: changes that arrived committed are not refused")
		return nil
	}

	committed, err := s.committedConfigChanges()
	if err != nil {
		return err
	}

	var alreadyCommitted []diff.Change
	for _, change := range changes {
		if slices.ContainsFunc(committed, change.Conflicts) {
			alreadyCommitted = append(alreadyCommitted, change)
		}
	}

	if len(alreadyCommitted) > 0 {
		return &CommittedChangesError{Changes: alreadyCommitted}
	}

	return nil
}

// applyChange carries out a single step against the audit log.
//
// It deliberately bypasses the Stage mutators: those keep sesam.yml in sync
// with the log, which is backwards here. The declaration is the input, so
// writing it back would re-marshal the user's file and, for a user or secret
// the config already declares, be refused outright.
func (s *Stage) applyChange(ctx context.Context, change diff.Change) error {
	switch change.Op {
	case core.OpUserTell:
		return s.user.UserTell(ctx, change.User, change.Keys, change.Groups)

	case core.OpUserKill:
		return s.user.UserKill(change.User)

	case core.OpUserChangeGroups:
		_, err := s.user.UserChangeGroups(change.User, change.Groups, false)
		return err

	case core.OpUserAddRecipients:
		return s.user.UserAddRecipient(ctx, change.User, change.Keys)

	case core.OpUserRmRecipients:
		return s.user.UserRmRecipient(ctx, change.User, change.Keys)

	case core.OpSecretAdd:
		// sesam.yml declared this secret before its plaintext existed on disk
		if err := s.touchIfMissing(change.Path); err != nil {
			return err
		}
		_, err := s.secret.SecretAdd(change.Path, change.Groups, false)
		return err

	case core.OpSecretRemove:
		return s.secret.SecretRemove(change.Path)

	case core.OpSecretChangeAccess:
		return s.secret.SecretChangeGroups(change.Path, change.Groups)

	default:
		return fmt.Errorf("unexpected core.Operation: %#v", change.Op)
	}
}

// touchIfMissing creates an empty file at path (and its parent directories)
// if nothing is there yet
func (s *Stage) touchIfMissing(path string) error {
	_, err := s.root.Stat(path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	if dir := filepath.Dir(path); dir != "." {
		if err := s.root.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create directory for %s: %w", path, err)
		}
	}

	f, err := s.root.Create(path)
	if err != nil {
		return fmt.Errorf("touch %s: %w", path, err)
	}

	return f.Close()
}
