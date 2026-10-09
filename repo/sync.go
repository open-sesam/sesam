package repo

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"golang.org/x/sync/errgroup"
	"opensesam.org/sesam/core"
)

type SyncOpts struct {
	// Paths limits the pass to these revealed paths; nil means every secret.
	Paths []string

	// Before is the commit (hex) whose objects the worktree held when the git
	// operation now in progress started: HEAD during a stopped merge, ORIG_HEAD
	// during a rebase, the previous HEAD in post-checkout. An object that
	// operation replaced, whose plaintext matches no version we know, is
	// SecretStateDiverged instead of SecretStateNotInSync. Empty outside hooks.
	Before string

	// Candidates are further commits (hex) whose object version the plaintext
	// may still be the decryption of, e.g. ORIG_HEAD after a hookless pull.
	// They only ever turn "modified" into "stale"; unknown ones are skipped.
	// Ignored when Before is set: inside an operation the only version a
	// plaintext can legitimately lag behind is the one the operation started from.
	Candidates []string
}

// SyncStates is one pass over the secrets: the state each one is in.
type SyncStates map[string]SecretState

// syncFacts is what classify needs to know about one secret.
type syncFacts struct {
	access    bool
	plaintext bool
	object    bool

	// matchesObject: the plaintext is the decryption of the worktree object.
	matchesObject bool
	// recipientsChanged: the object was sealed for a different recipient set
	// than the secret has now. Only looked at when matchesObject.
	recipientsChanged bool
	// matchesOlder: ... of some earlier version of it that git holds.
	matchesOlder bool
	// objectMoved: the worktree object differs from the one at SyncOpts.Before.
	objectMoved bool
	// unmerged: git still lists the object as conflicted, so a plaintext that
	// matches nothing is a resolution in progress, not a lost edit.
	unmerged bool
}

// objectHistory is what git knows about the objects, opened once per pass and
// only when some plaintext did not match its worktree object.
type objectHistory struct {
	prefix string

	// older are the trees to look for earlier object versions in: Before alone
	// when it is known, else HEAD and the candidates. Resolvable ones only.
	older []*object.Tree

	// before is the tree at SyncOpts.Before; nil when none was given.
	before *object.Tree

	// unmerged holds the worktree-relative paths git lists as conflicted.
	unmerged map[string]bool
}

// Paths returns, sorted, the secrets in any of the given states.
func (s SyncStates) Paths(states ...SecretState) []string {
	var paths []string
	for p, st := range s {
		for _, want := range states {
			if st == want {
				paths = append(paths, p)
				break
			}
		}
	}

	sort.Strings(paths)
	return paths
}

// SyncStates says, per secret, which side moved since plaintext and object were
// last written together. The plaintext is matched against the object versions
// git knows: the worktree's, HEAD's, then opts.Before and opts.Candidates.
// Matching the worktree object is in sync; matching an older version is stale;
// matching none is modified - or diverged, when opts.Before shows the object
// moved as well. Nothing is stored between passes: git holds the object's
// history and every object's footer holds a keyed hash of its plaintext.
func (v *View) SyncStates(opts SyncOpts) (SyncStates, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	return v.syncStates(opts)
}

// syncStates is SyncStates without the lock, for callers already holding it.
func (v *View) syncStates(opts SyncOpts) (SyncStates, error) {
	secrets := v.vstate.Secrets
	if opts.Paths != nil {
		want := make(map[string]bool, len(opts.Paths))
		for _, p := range opts.Paths {
			want[p] = true
		}

		secrets = nil
		for _, s := range v.vstate.Secrets {
			if want[s.RevealedPath] {
				secrets = append(secrets, s)
			}
		}
	}

	facts := make([]syncFacts, len(secrets))
	hashes := make([]plumbing.Hash, len(secrets))

	g := new(errgroup.Group)
	g.SetLimit(4 * runtime.GOMAXPROCS(0))
	for i, s := range secrets {
		g.Go(func() error {
			var err error
			facts[i], hashes[i], err = v.probeWorktree(s)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	// Git's history, sequentially and only for what did not match: usually
	// nothing, after a pull or merge the handful of objects it replaced.
	var hist *objectHistory
	states := make(SyncStates, len(secrets))
	for i, s := range secrets {
		f := facts[i]
		if f.access && f.plaintext && f.object && !f.matchesObject {
			if hist == nil {
				var err error
				if hist, err = v.openObjectHistory(opts); err != nil {
					return nil, err
				}
			}

			if err := v.consultHistory(hist, s.RevealedPath, hashes[i], &f); err != nil {
				return nil, err
			}
		}

		states[s.RevealedPath] = classify(f)
	}

	return states, nil
}

// classify is the whole decision table; the rest of this file gathers facts.
func classify(f syncFacts) SecretState {
	switch {
	case !f.access:
		return SecretStateUserHasNoAccess
	case !f.plaintext:
		return SecretStateNoRevealedPath
	case !f.object:
		return SecretStateNoSealedPath
	case f.matchesObject && f.recipientsChanged:
		return SecretStateRecipientsChanged
	case f.matchesObject:
		return SecretStateInSync
	case f.unmerged:
		// A resolution in progress, whatever it happens to equal.
		return SecretStateNotInSync
	case f.matchesOlder:
		return SecretStateStale
	case f.objectMoved:
		return SecretStateDiverged
	default:
		return SecretStateNotInSync
	}
}

// probeWorktree gathers what plaintext and worktree object say on their own,
// plus the object's git blob hash for the history lookup.
func (v *View) probeWorktree(s core.VerifiedSecret) (syncFacts, plumbing.Hash, error) {
	f := syncFacts{access: v.vstate.UserHasAccess(v.whoami, s.AccessGroups)}
	if !f.access {
		return f, plumbing.ZeroHash, nil
	}

	if _, err := v.root.Stat(s.RevealedPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return f, plumbing.ZeroHash, nil
		}

		return f, plumbing.ZeroHash, fmt.Errorf("stat %s: %w", s.RevealedPath, err)
	}
	f.plaintext = true

	data, err := v.root.ReadFile(v.secret.SealedPath(s.RevealedPath))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return f, plumbing.ZeroHash, nil
		}

		return f, plumbing.ZeroHash, fmt.Errorf("read object of %s: %w", s.RevealedPath, err)
	}
	f.object = true

	match, err := v.secret.MatchObject(s.RevealedPath, bytes.NewReader(data))
	if err != nil {
		return f, plumbing.ZeroHash, fmt.Errorf("compare %s with its object: %w", s.RevealedPath, err)
	}

	f.matchesObject = match.Content
	f.recipientsChanged = !match.Recipients
	return f, plumbing.ComputeHash(plumbing.BlobObject, data), nil
}

// consultHistory fills in what only git can tell about a plaintext that does
// not match its worktree object: is it an earlier version, and did the
// operation in progress replace the object.
func (v *View) consultHistory(h *objectHistory, revealedPath string, worktree plumbing.Hash, f *syncFacts) error {
	treePath := path.Join(h.prefix, filepath.ToSlash(core.ObjectPath(revealedPath)))
	f.unmerged = h.unmerged[treePath]

	seen := map[plumbing.Hash]bool{worktree: true}
	for _, tree := range h.older {
		file, err := tree.File(treePath)
		if errors.Is(err, object.ErrFileNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("look up %s in history: %w", treePath, err)
		}

		if seen[file.Hash] {
			continue
		}
		seen[file.Hash] = true

		rd, err := file.Reader()
		if err != nil {
			return fmt.Errorf("read %s from history: %w", treePath, err)
		}

		blob, err := io.ReadAll(rd)
		_ = rd.Close()
		if err != nil {
			return fmt.Errorf("read %s from history: %w", treePath, err)
		}

		match, err := v.secret.MatchObject(revealedPath, bytes.NewReader(blob))
		if err != nil {
			return fmt.Errorf("compare %s with an earlier object: %w", revealedPath, err)
		}

		if match.Content {
			f.matchesOlder = true
			break
		}
	}

	if h.before != nil {
		file, err := h.before.File(treePath)
		switch {
		case errors.Is(err, object.ErrFileNotFound):
			f.objectMoved = true // the operation added it
		case err != nil:
			return fmt.Errorf("look up %s before the operation: %w", treePath, err)
		default:
			f.objectMoved = file.Hash != worktree
		}
	}

	return nil
}

// openObjectHistory resolves the trees and index state one pass needs.
func (v *View) openObjectHistory(opts SyncOpts) (*objectHistory, error) {
	prefix, err := core.SesamGitPrefix(v.gitRepo, v.sesamDir)
	if err != nil {
		return nil, err
	}

	h := &objectHistory{prefix: prefix, unmerged: map[string]bool{}}
	seen := map[plumbing.Hash]bool{}

	// add resolves a commit's tree once and appends it to older. Unresolvable
	// candidates are skipped, they are hints; Before is a fact the caller
	// asserted and has to resolve.
	add := func(rev string, required bool) error {
		hash := plumbing.NewHash(rev)
		if seen[hash] {
			return nil
		}
		seen[hash] = true

		commit, err := v.gitRepo.CommitObject(hash)
		if err != nil {
			if required {
				return fmt.Errorf("resolve commit %s: %w", rev, err)
			}

			slog.Debug("sync: skipping unresolvable candidate", slog.String("rev", rev), slog.Any("err", err))
			return nil
		}

		tree, err := commit.Tree()
		if err != nil {
			return fmt.Errorf("tree of %s: %w", rev, err)
		}

		h.older = append(h.older, tree)
		return nil
	}

	if opts.Before != "" {
		if err := add(opts.Before, true); err != nil {
			return nil, err
		}

		h.before = h.older[0]
		return h.finish(v)
	}

	head, err := v.gitRepo.Head()
	switch {
	case errors.Is(err, plumbing.ErrReferenceNotFound):
		// no commit yet: nothing older to compare with
	case err != nil:
		return nil, fmt.Errorf("resolve HEAD: %w", err)
	default:
		if err := add(head.Hash().String(), true); err != nil {
			return nil, err
		}
	}

	for _, rev := range opts.Candidates {
		if err := add(rev, false); err != nil {
			return nil, err
		}
	}

	return h.finish(v)
}

// finish reads which paths git still lists as conflicted.
func (h *objectHistory) finish(v *View) (*objectHistory, error) {
	idx, err := v.gitRepo.Storer.Index()
	if err != nil {
		return nil, fmt.Errorf("read git index: %w", err)
	}

	for _, e := range idx.Entries {
		if e.Stage != 0 {
			h.unmerged[e.Name] = true
		}
	}

	return h, nil
}
