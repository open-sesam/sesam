package repo

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
	sesamConf "opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/diff"
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
type CommittedChangesError struct {
	Changes []diff.Change
}

func (e *CommittedChangesError) Error() string {
	lines := make([]string, 0, len(e.Changes)+2)
	lines = append(lines,
		"sesam.yml declares changes that are already committed, "+
			"so they did not come from your working tree:")

	for _, change := range e.Changes {
		lines = append(lines, "  "+change.String())
	}

	lines = append(lines,
		"check where they came from (git log -p -- sesam.yml); "+
			"pass --force to apply them anyway")

	return strings.Join(lines, "\n")
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

	plan, err := s.configDiff(ConfigDiffOpts{})
	if err != nil {
		return nil, err
	}

	if plan.IsEmpty() {
		return nil, nil
	}

	if err := s.applyPreflight(plan.Changes, opts); err != nil {
		return nil, err
	}

	for _, change := range plan.Changes {
		if err := s.applyChange(ctx, change); err != nil {
			return nil, fmt.Errorf("failed to apply %q: %w", change, err)
		}
	}

	// The plan is only correct if it actually closed the gap. Re-diffing the
	// state we just built catches anything the steps did not express - and
	// because we are still inside the stage, a mismatch rolls the whole thing
	// back instead of leaving the repository half applied.
	rest, err := s.configDiff(ConfigDiffOpts{})
	if err != nil {
		return nil, fmt.Errorf("re-reading the applied state: %w", err)
	}

	if !rest.IsEmpty() {
		return nil, fmt.Errorf(
			"applied state still differs from sesam.yml - this is a bug, nothing was changed:\n%s",
			rest,
		)
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

	committed, err := s.committedChanges()
	if err != nil {
		return err
	}

	var alreadyCommitted []diff.Change
	for _, change := range changes {
		if slices.ContainsFunc(committed, change.Equal) {
			alreadyCommitted = append(alreadyCommitted, change)
		}
	}

	if len(alreadyCommitted) > 0 {
		return &CommittedChangesError{Changes: alreadyCommitted}
	}

	return nil
}

// committedChanges returns the steps the configuration committed at HEAD would
// apply on its own, which is how a step is recognised as not coming from the
// working tree.
//
// Nothing relevant committed - no HEAD, no config in it, or a committed config
// that cannot be read and so cannot be the vector - yields no steps.
func (s *Stage) committedChanges() ([]diff.Change, error) {
	head, err := s.gitRepo.Head()
	if err != nil {
		// No commits yet: everything on disk is uncommitted by definition.
		slog.Debug("no git HEAD, treating the whole config as local", slog.Any("err", err))
		return nil, nil
	}

	commit, err := s.gitRepo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("read HEAD commit %s: %w", head.Hash(), err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("read tree of %s: %w", head.Hash(), err)
	}

	prefix, err := core.SesamGitPrefix(s.gitRepo, s.sesamDir)
	if err != nil {
		return nil, err
	}

	paths, err := s.configPaths()
	if err != nil {
		return nil, err
	}

	dir, cleanup, err := writeCommittedConfigs(tree, prefix, paths)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()

	cfg, err := sesamConf.Load(root, configFileName)
	if err != nil {
		// The committed config is absent or unreadable, so no step can be
		// attributed to it.
		slog.Debug("no usable config at HEAD", slog.Any("err", err))
		return nil, nil
	}

	declared, err := cfg.State()
	if err != nil {
		slog.Debug("config at HEAD does not describe a state", slog.Any("err", err))
		return nil, nil
	}

	// Delta, not Compute: what the committed config asks for is interesting
	// even when it could not be applied as it stands.
	return diff.Delta(s.vstate, declared).Changes, nil
}

// writeCommittedConfigs materializes the given config paths as they are in
// tree into a temp directory, so the committed configuration can be read with
// the ordinary config loader. Paths missing from the commit are skipped.
func writeCommittedConfigs(
	tree *object.Tree,
	prefix string,
	paths []string,
) (dir string, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp("", "sesam-committed-config-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to make temp dir: %w", err)
	}

	removeTmp := func() { _ = os.RemoveAll(tmpDir) }
	defer func() {
		if err != nil {
			removeTmp()
		}
	}()

	for _, rel := range paths {
		file, err := tree.File(path.Join(prefix, filepath.ToSlash(rel)))
		if err != nil {
			// Not committed (yet): nothing to compare against.
			continue
		}

		contents, err := file.Contents()
		if err != nil {
			return "", nil, fmt.Errorf("read committed %s: %w", rel, err)
		}

		dst := filepath.Join(tmpDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", nil, fmt.Errorf("make dir for %s: %w", dst, err)
		}

		if err := os.WriteFile(dst, []byte(contents), 0o600); err != nil {
			return "", nil, fmt.Errorf("write %s: %w", dst, err)
		}
	}

	return tmpDir, removeTmp, nil
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
