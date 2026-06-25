package repo

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-sesam/sesam/core"
)

// forkSuffix is the sibling directory that holds the staged copy of .sesam.
// It lives next to .sesam (a child of sesamDir, not of .sesam) so it never
// participates in flock identity and is ignored by the generated .gitignore.
const forkSuffix = ".sesam-tmp"

// ErrStageFinalized is returned when Commit/Rollback is called on a stage that
// was already committed or rolled back.
var ErrStageFinalized = errors.New("stage already finalized")

// Stage is a read-write transaction over a forked copy of .sesam.
//
// Repo.Stage() hardlinks the live .sesam into .sesam-tmp (byte-copying the
// append-mutated audit log), then binds a fork-bound View (sesam-internal base
// ".sesam-tmp", in-memory state cloned from the live view). Mutators write into
// the fork; the embedded View's reads reflect the staged state ("see your own
// writes"). Commit makes the fork live with a single atomic directory swap;
// Rollback discards it.
type Stage struct {
	*View

	repo *Repo
	done bool
}

// Stage opens a read-write transaction. It errors if a stage is already open
// or the repo is closed. The caller must finish it with Commit or Rollback.
func (r *Repo) Stage() (*Stage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}
	if r.stage != nil {
		// stage exists already; return again.
		return r.stage, nil
	}

	// Drop any fork left behind by a crashed previous run before re-forking.
	if err := r.root.RemoveAll(forkSuffix); err != nil {
		return nil, fmt.Errorf("clear stale fork: %w", err)
	}

	if err := r.materializeFork(); err != nil {
		_ = r.root.RemoveAll(forkSuffix)
		return nil, fmt.Errorf("materialize fork: %w", err)
	}

	s, err := r.buildStage()
	if err != nil {
		_ = r.root.RemoveAll(forkSuffix)
		return nil, err
	}

	r.stage = s
	return s, nil
}

// Update runs fn inside a stage, committing on success and rolling back on any
// error or panic. It is the convenience entry point RW CLI commands use.
func (r *Repo) Update(fn func(*Stage) error) error {
	s, err := r.Stage()
	if err != nil {
		return err
	}
	defer func() { _ = s.Rollback() }() // no-op once committed

	if err := fn(s); err != nil {
		return err
	}

	return s.Commit()
}

// buildStage binds a fork-bound View to .sesam-tmp using the memory-based
// clone: the live audit log, keyring and verified state are cloned in memory
// (no replay), the audit log gets a fresh fd on the byte-copied fork log, and
// every sesam-internal path is pointed at the fork via SetBase. The signer is
// immutable and reused from the live secret manager.
func (r *Repo) buildStage() (*Stage, error) {
	// Fork operations write renameio temps into the fork's own tmp dir so a
	// crash leaves nothing stray in the live tree. materializeFork mirrors it,
	// but ensure it exists defensively (renameio fails hard on a missing dir).
	if err := r.root.MkdirAll(filepath.Join(forkSuffix, "tmp"), 0o700); err != nil {
		return nil, fmt.Errorf("create fork tmp dir: %w", err)
	}

	audit, err := r.auditLog.Fork(r.root, forkSuffix)
	if err != nil {
		return nil, fmt.Errorf("fork audit log: %w", err)
	}

	keyring := r.keyring.Clone()
	vstate := r.vstate.Clone(audit, keyring)
	signer := r.secret.Signer

	secret, err := core.BuildSecretManager(
		r.sesamDir,
		r.root,
		r.identities,
		signer,
		keyring,
		audit,
		vstate,
	)
	if err != nil {
		_ = audit.Close()
		return nil, fmt.Errorf("build fork secret manager: %w", err)
	}
	secret.SetBase(forkSuffix)

	user, err := core.BuildUserManager(
		r.root,
		signer,
		audit,
		vstate,
		secret,
	)
	if err != nil {
		_ = audit.Close()
		return nil, fmt.Errorf("build fork user manager: %w", err)
	}
	user.SetBase(forkSuffix)

	// config stays nil: it is lazy-loaded (View.cfg) the first time a config
	// mutator runs, giving the fork its own independent in-memory copy. Staged
	// edits never touch the live config and are written only on Commit, so a
	// Rollback (or a stage that never touches config) leaves sesam.yml untouched.
	fork := &View{
		mu:            r.mu, // shared with the Repo
		sesamDir:      r.sesamDir,
		root:          r.root,
		opts:          r.opts,
		pluginUI:      r.pluginUI,
		gitRepo:       r.gitRepo,
		whoami:        r.whoami,
		identityPaths: r.identityPaths,
		identities:    r.identities,
		auditLog:      audit,
		keyring:       keyring,
		vstate:        vstate,
		secret:        secret,
		user:          user,
	}

	return &Stage{View: fork, repo: r}, nil
}

// materializeFork builds .sesam-tmp as a hardlink mirror of .sesam. The
// append-mutated audit log is byte-copied (a hardlink would let staged appends
// touch the live inode, defeating Rollback); everything else is hard-linked
// (cheap, and rewrites go through renameio which replaces inodes rather than
// mutating shared ones).
func (r *Repo) materializeFork() error {
	auditLogRel := filepath.Join(sesamSuffix, "audit", "log.jsonl")

	return fs.WalkDir(r.root.FS(), sesamSuffix, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel := filepath.FromSlash(p)
		dst := forkSuffix + strings.TrimPrefix(rel, sesamSuffix)

		if d.IsDir() {
			return r.root.MkdirAll(dst, 0o700)
		}

		// The audit log gets a forced byte copy (a hardlink would let staged
		// appends touch the live inode and survive a Rollback); everything else
		// hardlinks (cheap), copying only on filesystems that refuse.
		return core.CopyFile(r.root, rel, dst, rel != auditLogRel)
	})
}

// Commit makes the fork live with one atomic directory swap, then promotes the
// fork View onto the Repo so subsequent reads see committed state.
func (s *Stage) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done {
		return ErrStageFinalized
	}

	// Durability before the swap: fsync the fork's directory tree so the
	// hardlink entries and the copied audit log are on disk for sure.
	// See man(2) fsync - not 100% sure it's necessary anymore, but better safe than sorry.
	if err := fsyncTree(s.repo.root, forkSuffix); err != nil {
		return fmt.Errorf("fsync fork: %w", err)
	}

	live := filepath.Join(s.repo.sesamDir, sesamSuffix)
	fork := filepath.Join(s.repo.sesamDir, forkSuffix)
	if err := atomicSwapDirs(live, fork); err != nil {
		return fmt.Errorf("swap fork into place: %w", err)
	}
	s.done = true // past the point of no return

	// Make the swap itself durable.
	_ = fsyncDir(s.repo.root, ".")

	// Promote: the fork's managers already hold the committed in-memory state
	// and their fds follow the swapped-in inodes. Re-base them to the live tree
	// and make the fork View the Repo's live View. No reopen, no replay.
	_ = s.repo.closeState()

	s.auditLog.SetBase("")
	s.secret.SetBase("")
	s.user.SetBase("")

	s.repo.View = s.View
	s.repo.stage = nil

	// Persist the staged config to the live sesam.yml file(s), but only if a
	// config mutator actually loaded it (s.config != nil) — a config-free stage
	// (e.g. a plain seal) neither loads nor rewrites sesam.yml. Done after the
	// swap because the audit log is the authoritative state and sesam.yml is
	// only the desired-state mirror: if this fails the operation is already
	// committed, so a stale config is a warning, not a rollback.
	if s.config != nil {
		if err := s.config.Save(); err != nil {
			slog.Warn(
				"committed, but failed to persist sesam.yml",
				slog.String("err", err.Error()),
			)
		}
	}

	// Reap the old tree (now sitting at .sesam-tmp). Non-fatal: a leftover fork
	// is reaped on the next Stage()/Load.
	if err := s.repo.root.RemoveAll(forkSuffix); err != nil {
		return fmt.Errorf("reap old tree: %w", err)
	}
	return nil
}

// Rollback discards the fork. Idempotent and safe to defer.
func (s *Stage) Rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.done {
		return nil
	}
	s.done = true

	_ = s.closeState()
	s.repo.stage = nil

	// Repo's live state was never touched, so nothing to restore.
	return s.repo.root.RemoveAll(forkSuffix)
}

// UserTell adds a new user with access to `groups`, encrypting their secrets to
// `recipients`.
func (s *Stage) UserTell(ctx context.Context, user string, recipients, groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserTell(ctx, user, recipients, groups); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}
	// Config edits stay in memory until Commit (see buildStage).
	cfg, err := s.cfg()
	if err != nil {
		return err
	}
	return cfg.UserTell(user, recipients, groups)
}

// UserKill removes a user from the set of authenticated users.
func (s *Stage) UserKill(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserKill(user); err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}
	cfg, err := s.cfg()
	if err != nil {
		return err
	}
	return cfg.UserKill(user)
}

// SealAll re-encrypts all revealed content into the staged sealed storage.
func (s *Stage) SealAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.secret.SealAll(); err != nil {
		return fmt.Errorf("failed to seal secrets: %w", err)
	}
	return nil
}

// SecretAdd starts tracking the secret(s) at each path. Paths are sesam-relative.
func (s *Stage) SecretAdd(revealedPaths, groups []string, nested bool) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	var files []string
	for _, p := range revealedPaths {
		expanded, err := s.expandSecretFiles(p)
		if err != nil {
			return fmt.Errorf("failed to expand %q: %w", p, err)
		}
		files = append(files, expanded...)
	}

	for _, rel := range files {
		if err := core.IsForbiddenPath(rel); err != nil {
			return err
		}
		if err := cfg.SecretAdd(rel, nested, groups); err != nil {
			return fmt.Errorf("failed to add secret %q to config: %w", rel, err)
		}
		if err := s.secret.SecretAdd(rel, groups); err != nil {
			return fmt.Errorf("failed to add secret %q: %w", rel, err)
		}
	}

	return nil
}

// SecretRemove stops tracking the secret(s) at each path.
func (s *Stage) SecretRemove(revealedPaths []string) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	for _, p := range revealedPaths {
		targets := s.secretsUnder(p)
		if len(targets) == 0 {
			return fmt.Errorf("no secrets found for %q", p)
		}
		for _, secret := range targets {
			rel := secret.RevealedPath
			if err := cfg.SecretRemove(rel); err != nil {
				return fmt.Errorf("failed to remove secret %q from config: %w", rel, err)
			}
			if err := s.secret.SecretRemove(rel); err != nil {
				return fmt.Errorf("failed to remove secret %q: %w", rel, err)
			}
		}
	}

	return nil
}

// SecretMove relocates the secret(s) at oldRevealedPath to newRevealedPath. A
// single secret is renamed directly; a directory moves every secret beneath it,
// preserving each one's path relative to the source root.
func (s *Stage) SecretMove(oldRevealedPath, newRevealedPath string, nested bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	oldBase := filepath.Clean(oldRevealedPath)
	newBase := filepath.Clean(newRevealedPath)

	targets := s.secretsUnder(oldBase)
	if len(targets) == 0 {
		return fmt.Errorf("no secrets found for %q", oldRevealedPath)
	}

	for _, secret := range targets {
		oldRel := filepath.Clean(secret.RevealedPath)
		sub, err := filepath.Rel(oldBase, oldRel)
		if err != nil {
			return err
		}

		newRel := newBase
		if sub != "." {
			newRel = filepath.Join(newBase, sub)
		}

		if err := s.secret.SecretMove(oldRel, newRel); err != nil {
			return fmt.Errorf("failed to move secret %q: %w", oldRel, err)
		}

		if err := cfg.SecretMove(oldRel, newRel, nested); err != nil {
			return fmt.Errorf("failed to move secret %q in config: %w", oldRel, err)
		}
	}

	return nil
}

// UserRename renames a user
func (s *Stage) UserRename(oldName, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserRename(oldName, newName); err != nil {
		return err
	}

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	return cfg.UserRename(oldName, newName)
}

// UserChangeGroups sets the group membership of a user.
func (s *Stage) UserChangeGroups(user string, groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserChangeGroups(user, groups); err != nil {
		return err
	}

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	return cfg.UserChangeGroups(user, groups)
}

// UserAddRecipient grants additional public keys to a user.
func (s *Stage) UserAddRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserAddRecipient(ctx, user, pubKeySpecs); err != nil {
		return err
	}

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	return cfg.UserAddRecipient(user, pubKeySpecs)
}

// UserRmRecipient removes public keys from a user.
func (s *Stage) UserRmRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserRmRecipient(ctx, user, pubKeySpecs); err != nil {
		return err
	}

	cfg, err := s.cfg()
	if err != nil {
		return err
	}

	return cfg.UserRmRecipient(user, pubKeySpecs)
}

// UserRegenerateSignKey issues a fresh signing key for a user.
func (s *Stage) UserRegenerateSignKey(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.user.UserRegenerateSignKey(user)
}

// fsyncTree fsyncs every directory under dir (inclusive) within root, so newly
// created directory entries (hardlinks, copies) are durable before the swap.
func fsyncTree(root *os.Root, dir string) error {
	return fs.WalkDir(root.FS(), dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return fsyncDir(root, filepath.FromSlash(p))
		}
		return nil
	})
}

func fsyncDir(root *os.Root, dir string) error {
	fd, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()
	return fd.Sync()
}
