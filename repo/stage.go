package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	sesamConf "github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/core"
)

// forkSuffix is the sibling directory that holds the staged copy of .sesam.
// It lives next to .sesam (a child of sesamDir, not of .sesam) so it never
// participates in flock identity and is ignored by the generated .gitignore.
const forkSuffix = ".sesam-tmp"

// ErrStageOpen is returned by Stage when a stage is already in flight. Only one
// stage may exist at a time: it owns the single .sesam-tmp fork directory.
var ErrStageOpen = errors.New("a stage is already open")

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
//
// Config: the staged View carries its own in-memory copy of sesam.yml (a fresh
// load); mutators edit that copy and it is written to disk only on Commit, so
// Rollback never touches the live config. sesam.yml lives in the worktree root,
// outside .sesam, so it cannot ride the swap itself — it is saved right after
// the swap (the audit log is authoritative; config is its desired-state
// mirror), leaving only a narrow crash window where config trails the log.
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
		return nil, ErrStageOpen
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

	secret, err := core.BuildSecretManager(r.sesamDir, r.root, r.identities, signer, keyring, audit, vstate)
	if err != nil {
		_ = audit.Close()
		return nil, fmt.Errorf("build fork secret manager: %w", err)
	}
	secret.SetBase(forkSuffix)

	user, err := core.BuildUserManager(r.root, signer, audit, vstate, secret)
	if err != nil {
		_ = audit.Close()
		return nil, fmt.Errorf("build fork user manager: %w", err)
	}
	user.SetBase(forkSuffix)

	// Independent in-memory config: a fresh load of the live sesam.yml. Staged
	// edits mutate this copy only and are not written to disk until Commit, so
	// a Rollback leaves the live config files untouched.
	cfg, err := sesamConf.Load(r.root, "sesam.yml")
	if err != nil {
		_ = audit.Close()
		return nil, fmt.Errorf("load fork config: %w", err)
	}

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
		config:        cfg,
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

		if rel == auditLogRel {
			// Forced byte copy: a hardlink would let staged appends touch the
			// live log inode and survive a Rollback.
			return copyInRoot(r.root, rel, dst)
		}

		// Everything else: hardlink (cheap), copy on filesystems that refuse.
		return core.CopyFile(r.root, rel, dst)
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
	// hardlink entries and the copied audit log are on disk. Object/signkey
	// writes already went through renameio (file+dir fsync) and audit appends
	// through O_SYNC; this covers the rest.
	if err := fsyncTree(s.repo.root, forkSuffix); err != nil {
		return fmt.Errorf("fsync fork: %w", err)
	}

	// The single linearization point. Absolute paths: renameat2 needs them.
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

	// Persist the staged config to the live sesam.yml file(s). Done after the
	// swap because the audit log is the authoritative state and sesam.yml is
	// only the desired-state mirror: if this fails the operation is already
	// committed, so a stale config is a warning, not a rollback. (sesam.yml
	// lives in the worktree root, outside .sesam, so it cannot ride the swap.)
	if err := s.config.Save(); err != nil {
		slog.Warn(
			"committed, but failed to persist sesam.yml (audit log is authoritative)",
			slog.String("err", err.Error()),
		)
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

// ── staged mutators ────────────────────────────────────────────────────────

// Tell adds a new user with access to `groups`, encrypting their secrets to
// `recipients`.
func (s *Stage) Tell(ctx context.Context, user string, recipients, groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserTell(ctx, user, recipients, groups); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}
	// Config edits stay in memory until Commit (see buildStage).
	return s.config.UserTell(user, recipients, groups)
}

// Kill removes a user from the set of authenticated users.
func (s *Stage) Kill(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.user.UserKill(user); err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}
	return s.config.UserKill(user)
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

// AddSecret starts tracking the secret(s) at each path. Paths are sesam-relative.
func (s *Stage) AddSecret(revealedPaths, groups []string, nested bool) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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
		if err := s.config.SecretAdd(rel, nested, groups); err != nil {
			return fmt.Errorf("failed to add secret %q to config: %w", rel, err)
		}
		if err := s.secret.SecretAdd(rel, groups); err != nil {
			return fmt.Errorf("failed to add secret %q: %w", rel, err)
		}
	}

	return nil
}

// RemoveSecret stops tracking the secret(s) at each path.
func (s *Stage) RemoveSecret(revealedPaths []string) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range revealedPaths {
		targets := s.secretsUnder(p)
		if len(targets) == 0 {
			return fmt.Errorf("no secrets found for %q", p)
		}
		for _, secret := range targets {
			rel := secret.RevealedPath
			if err := s.config.SecretRemove(rel); err != nil {
				return fmt.Errorf("failed to remove secret %q from config: %w", rel, err)
			}
			if err := s.secret.SecretRemove(rel); err != nil {
				return fmt.Errorf("failed to remove secret %q: %w", rel, err)
			}
		}
	}

	return nil
}

// MoveSecret relocates the secret(s) at oldRevealedPath to newRevealedPath. A
// single secret is renamed directly; a directory moves every secret beneath it,
// preserving each one's path relative to the source root.
func (s *Stage) MoveSecret(oldRevealedPath, newRevealedPath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

		// TODO: preserve nested layout on move (derive from the source's owning
		// file); for now the moved secret lands in the main file.
		if err := s.config.SecretMove(oldRel, newRel, false); err != nil {
			return fmt.Errorf("failed to move secret %q in config: %w", oldRel, err)
		}
	}

	return nil
}

// RenameUser renames a user. TODO: config integration.
func (s *Stage) RenameUser(oldName, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.user.UserRename(oldName, newName)
}

// ChangeGroups sets the group membership of a user. TODO: config integration.
func (s *Stage) ChangeGroups(user string, groups []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.user.UserChangeGroups(user, groups)
}

// AddRecipient grants additional public keys to a user. TODO: config integration.
func (s *Stage) AddRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.user.UserAddRecipient(ctx, user, pubKeySpecs)
}

// RmRecipient removes public keys from a user. TODO: config integration.
func (s *Stage) RmRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.user.UserRmRecipient(ctx, user, pubKeySpecs)
}

// RegenerateSignKey issues a fresh signing key for a user.
func (s *Stage) RegenerateSignKey(user string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.user.UserRegenerateSignKey(user)
}

// ── fork I/O helpers ─────────────────────────────────────────────────────────

// copyInRoot copies the file at src to dst within root, creating dst's parent
// and fsyncing the result.
func copyInRoot(root *os.Root, src, dst string) error {
	if err := root.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}

	in, err := root.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := root.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
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
