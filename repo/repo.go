// Package repo provides the high-level sesam repository API.
//
// A Repo is a handle to a sesam repository on disk. Load (or Init) acquires
// the on-disk `.sesam/lock`, opens the audit log, and builds the secret /
// user managers — all of which stay open for the lifetime of the Repo and
// are released by Close. Methods reuse the same managers across calls and
// are safe to invoke concurrently from multiple goroutines (an internal
// mutex serializes operations, since the underlying managers are not
// goroutine-safe).
package repo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/gofrs/flock"
	"github.com/open-sesam/sesam/core"
)

const defaultLockTimeout = 30 * time.Second

// keyringFingerprint is the OS-keyring entry name used to cache the runtime
// passphrase of encrypted age identities.
const keyringFingerprint = "sesam.identity.runtime"

var ErrClosed = errors.New("sesam repo is closed")

// Repo is a handle to a sesam repo. See package-level docs for lifetime
// semantics.
type Repo struct {
	sesamDir string
	opts     RepoOpts

	pluginUI *core.PluginUI
	gitRepo  *git.Repository
	lock     *flock.Flock

	identityPaths []string
	identities    core.Identities

	auditLog *core.AuditLog
	keyring  core.Keyring
	vstate   *core.VerifiedState
	secret   *core.SecretManager
	user     *core.UserManager

	mu sync.Mutex
}

// RepoOpts controls runtime behavior shared across all Repo operations.
type RepoOpts struct {
	// Interactive should be true when we can talk to the user via the terminal.
	// TODO: later we should check things like ssh-askpass to allow password
	// decryption without running in the foreground. Then we might need to split
	// up options here too (one for interactive terminal and one for interactive UI)
	Interactive bool

	// LockTimeout bounds how long acquiring the on-disk repo lock waits.
	// Zero means use the default.
	LockTimeout time.Duration
}

func (opts RepoOpts) lockTimeout() time.Duration {
	if opts.LockTimeout <= 0 {
		return defaultLockTimeout
	}
	return opts.LockTimeout
}

func (opts RepoOpts) pluginUI() *core.PluginUI {
	if opts.Interactive {
		return core.NewInteractivePluginUI()
	}
	return core.NewNonInteractivePluginUI()
}

// LoadIdentities reads the user's age identity files.
func LoadIdentities(identityPaths []string, opts RepoOpts) (core.Identities, error) {
	idLoader := loadIdentities
	if !opts.Interactive {
		idLoader = loadIdentitiesKeyringOnly
	}

	return idLoader(identityPaths, keyringFingerprint, opts.pluginUI())
}

// ResolveSesamDir resolves the sesam repository root. It walks up from
// sesamPath until it finds a directory containing `.sesam/`, or returns
// the absolute path of sesamPath unchanged if none is found (the latter
// is used during `sesam init` before `.sesam/` exists).
func ResolveSesamDir(sesamPath string) (string, error) {
	return resolveSesamDir(sesamPath)
}

// Init initializes a new sesam repository at sesamDir.
//
// initialUserName becomes the first admin user; ids are paths to the admin's
// age identity files. The sesam config is written to <sesamDir>/sesam.yml.
// On success the returned Repo holds the on-disk lock and has the secret /
// user managers ready for use; the caller must Close it.
func Init(ctx context.Context, sesamDir, initialUserName string, ids []string, opts RepoOpts) (*Repo, error) {
	if err := core.ValidUserName(initialUserName); err != nil {
		return nil, fmt.Errorf("invalid initial user %q: %w", initialUserName, err)
	}

	resolvedDir, gitRepo, err := resolveSesamDirAndGit(sesamDir)
	if err != nil {
		return nil, err
	}

	if err := isInitialized(resolvedDir); err != nil {
		return nil, err
	}

	r := newRepo(resolvedDir, gitRepo, ids, opts)
	success := false
	defer func() {
		if !success {
			_ = r.Close()

			// cleanup half created state:
			_ = os.RemoveAll(sesamDir)
			_ = os.RemoveAll("sesam.yml")
		}
	}()

	identities, err := loadIdentities(ids, "sesam.id."+initialUserName, r.pluginUI)
	if err != nil {
		return nil, err
	}
	r.identities = identities

	if err := ensureSesamDirs(resolvedDir); err != nil {
		return nil, err
	}

	if err := r.acquireLock(); err != nil {
		return nil, err
	}

	configPath := filepath.Join(resolvedDir, "sesam.yml")
	if err := createInitialConfig(configPath, initialUserName, identities.RecipientStrings()); err != nil {
		return nil, err
	}

	signer, auditLog, err := core.InitAdminUser(ctx, resolvedDir, initialUserName, identities.RecipientStrings(), r.pluginUI)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize admin user: %w", err)
	}
	r.auditLog = auditLog

	r.keyring = core.EmptyKeyring()
	vstate, err := core.Verify(auditLog, r.keyring, r.pluginUI)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}
	r.vstate = vstate

	r.secret, err = core.BuildSecretManager(resolvedDir, identities, signer, r.keyring, auditLog, vstate)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	r.user, err = core.BuildUserManager(resolvedDir, signer, auditLog, vstate, r.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	if err := ensureDefaultGitIgnore(resolvedDir); err != nil {
		return nil, err
	}
	if err := ensureDefaultGitAttributes(resolvedDir); err != nil {
		return nil, err
	}
	if err := ensureGitConfig(gitRepo, resolvedDir); err != nil {
		return nil, err
	}
	if err := ensureSesamReadme(resolvedDir); err != nil {
		return nil, err
	}

	if err := withWorkingDir(resolvedDir, func() error {
		return r.secret.AddSecret("README.md", []string{"admin"})
	}); err != nil {
		return nil, fmt.Errorf("failed to bootstrap readme secret: %w", err)
	}

	if err := ensureTmpKeepFile(resolvedDir); err != nil {
		return nil, err
	}

	if err := r.secret.SealAll(); err != nil {
		return nil, err
	}

	if err := stageInitFiles(gitRepo, resolvedDir, configPath); err != nil {
		return nil, err
	}

	success = true
	return r, nil
}

// Load loads an existing sesam repository at sesamDir. The on-disk repo
// lock is held until Close.
func Load(sesamDir string, ids []string, opts RepoOpts) (*Repo, error) {
	resolvedDir, gitRepo, err := resolveSesamDirAndGit(sesamDir)
	if err != nil {
		return nil, err
	}

	r := newRepo(resolvedDir, gitRepo, ids, opts)
	success := false
	defer func() {
		if !success {
			_ = r.Close()
		}
	}()

	if err := r.acquireLock(); err != nil {
		return nil, err
	}

	identities, err := LoadIdentities(ids, opts)
	if err != nil {
		return nil, err
	}
	r.identities = identities

	r.keyring = core.EmptyKeyring()

	auditLog, err := core.LoadAuditLog(resolvedDir, identities)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit log: %w", err)
	}
	r.auditLog = auditLog

	vstate, err := core.Verify(auditLog, r.keyring, r.pluginUI)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}
	r.vstate = vstate

	whoami, signIdentity, err := identityToUser(identities, r.keyring.ListUsers())
	if err != nil {
		return nil, fmt.Errorf("failed to map identity to user: %w", err)
	}

	signer, err := core.LoadSignKey(resolvedDir, whoami, signIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key for %s: %w", whoami, err)
	}

	r.secret, err = core.BuildSecretManager(resolvedDir, identities, signer, r.keyring, auditLog, vstate)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	r.user, err = core.BuildUserManager(resolvedDir, signer, auditLog, vstate, r.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	success = true
	return r, nil
}

func newRepo(sesamDir string, gitRepo *git.Repository, ids []string, opts RepoOpts) *Repo {
	return &Repo{
		sesamDir:      sesamDir,
		opts:          opts,
		gitRepo:       gitRepo,
		pluginUI:      opts.pluginUI(),
		identityPaths: ids,
	}
}

// SesamDir returns the resolved absolute path of the sesam repository.
func (r *Repo) SesamDir() string {
	return r.sesamDir
}

func (r *Repo) isClosed() bool {
	return r.auditLog == nil
}

// Close releases the on-disk lock and closes the audit log. Safe to call
// multiple times. The first non-nil error is returned.
func (r *Repo) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	if r.auditLog != nil {
		if err := r.auditLog.Close(); err != nil {
			firstErr = fmt.Errorf("close audit log: %w", err)
		}
		r.auditLog = nil
	}
	if r.vstate != nil {
		if err := r.vstate.Close(); err != nil {
			firstErr = fmt.Errorf("close vstate: %w", err)
		}
		r.vstate = nil
	}
	if r.lock != nil {
		if err := r.lock.Unlock(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("unlock repository: %w", err)
		}
		r.lock = nil
	}
	return firstErr
}

// TODO: We might need to enrich the user type with config-derived info like
// descriptions. Something for later.

// ListUsers returns a list of all users currently in the audit log.
func (r *Repo) ListUsers() ([]core.VerifiedUser, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	return append([]core.VerifiedUser(nil), r.vstate.Users...), nil
}

// ListSecrets returns a list of secrets currently managed by sesam.
func (r *Repo) ListSecrets() ([]core.VerifiedSecret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	return append([]core.VerifiedSecret(nil), r.vstate.Secrets...), nil
}

// RevealAll will reveal all secrets.
func (r *Repo) RevealAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	if err := r.secret.RevealAll(); err != nil {
		return fmt.Errorf("failed to reveal secrets: %w", err)
	}
	return nil
}

// SealAll takes all revealed content and encrypts it to the sealed storage.
func (r *Repo) SealAll() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	if err := r.secret.SealAll(); err != nil {
		return fmt.Errorf("failed to seal secrets: %w", err)
	}
	return nil
}

type CleanOpts struct {
	Aggressive bool

	// CheckFunc is called for every path that should be cleaned.
	// Return true to allow, false to disallow.
	// Return errors immediately stops cleaning.
	//
	// NOTE: This is holding a mutex. Calling other repo API will deadlock.
	CheckFunc func(path string) (bool, error)
}

// Clean removes stale plaintext from the worktree.
//
// In the default (non-aggressive) mode, Clean only deletes the revealed
// plaintexts that sesam itself produced (the paths recorded in the audit
// log). This is what `sesam seal --clean` does after sealing.
//
// With opts.Aggressive set, Clean delegates to CleanAggressive and removes
// every untracked file in the worktree — including stale scratch state
// inside `.sesam/` — roughly `git clean -fdx`.
//
// opts.CheckFunc, when non-nil, is called for every path Clean wants to
// delete: return (true, nil) to allow, (false, nil) to skip, or a non-nil
// error to abort.
func (r *Repo) Clean(ctx context.Context, opts CleanOpts) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	if opts.Aggressive {
		return CleanAggressive(
			ctx,
			r.sesamDir,
			r.identityPaths,
			opts,
		)
	}

	if err := deleteRevealedSecrets(
		r.sesamDir,
		r.secret.State.Secrets,
		opts.CheckFunc,
	); err != nil {
		return fmt.Errorf("failed to delete revealed secrets: %w", err)
	}

	_, err := recursiveRmEmptyDirs(r.sesamDir, map[string]bool{
		sesamSuffix: true,
		gitSuffix:   true,
	}, opts.CheckFunc)

	return err
}

// ShowUser writes a JSON description of the named user to `out`. The bool
// return is true iff a user with that name was found (mirrors the underlying
// core.UserManager.ShowUser contract). Use this for the user-info fallback
// in `sesam show`; audit-log and secret display do NOT need a Repo and
// should go through core.ShowAuditLog / core.ShowSecret directly, since
// loading a Repo is prohibitively expensive on the git-diff textconv path.
func (r *Repo) ShowUser(name string, out io.Writer) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return false, ErrClosed
	}

	return r.user.ShowUser(name, out)
}

// UserTell adds the new user to the list of valid users. They will be in
// `groups` and the files they may access are encrypted with `recipients`.
// All secrets are immediately re-sealed.
func (r *Repo) UserTell(ctx context.Context, user string, recipients, groups []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	if err := r.user.TellUser(ctx, user, recipients, groups); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}
	return nil
}

// UserKill removes `user` from the list of authenticated users.
// All secrets are immediately re-sealed.
func (r *Repo) UserKill(user string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	if err := r.user.KillUsers(user); err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}
	return nil
}

// SecretAdd adds the secret at each path to the secrets known by sesam.
// A path can be a directory, in which case the operation is recursive.
// All secrets are immediately re-sealed.
func (r *Repo) SecretAdd(revealedPaths, groups []string) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass at least one group")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	return withWorkingDir(r.sesamDir, func() error {
		for _, revealedPath := range revealedPaths {
			if err := r.secret.AddSecret(revealedPath, groups); err != nil {
				return fmt.Errorf("failed to add secret %q: %w", revealedPath, err)
			}
		}
		return nil
	})
}

// SecretRemove removes managed secrets at the given paths.
// All secrets are immediately re-sealed.
func (r *Repo) SecretRemove(revealedPaths []string) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, revealedPath := range revealedPaths {
		if err := r.secret.RemoveSecret(revealedPath); err != nil {
			return fmt.Errorf("failed to remove secret %q: %w", revealedPath, err)
		}
	}
	return nil
}

// VerifyOptions selects which verification checks Verify should run.
type VerifyOptions struct {
	// Truncation checks if the audit log was truncated over the git history.
	Truncation bool

	// KeyReuse checks if different users re-use the same public keys.
	// This should be forbidden by logic in sesam while adding for a single
	// user, but someone could play dirty tricks (or we have a bug...)
	KeyReuse bool

	// ForgeCheck will check if the public keys on forge-side changed.
	ForgeCheck bool

	// Integrity checks the integrity of all files and whether they match the
	// current seal's root hash.
	Integrity bool
}

// VerifyReport carries the per-check outcome from Verify.
type VerifyReport struct {
	// Integrity is the report from the integrity check. nil if Integrity was
	// not requested.
	Integrity *core.IntegrityReport

	// TODO: Truncation, KeyReuse, ForgeCheck reports
}

// OK reports whether every requested check passed.
func (rep *VerifyReport) OK() bool {
	if rep == nil {
		return true
	}
	if rep.Integrity != nil && !rep.Integrity.OK() {
		return false
	}
	return true
}

// Verify will check the repository's state depending on the verification
// strategies set in opts. Some verifications are hard errors (i.e. when the
// audit log cannot be decrypted or is inconsistent) and are returned as
// `err`. All other consistency checks have their results placed in the
// returned report.
func (r *Repo) Verify(opts VerifyOptions) (*VerifyReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	report := &VerifyReport{}

	if opts.Integrity {
		report.Integrity = core.VerifyIntegrity(r.sesamDir, r.vstate, r.keyring)
	}

	// TODO: Truncation, KeyReuse, ForgeCheck.
	_ = opts.Truncation
	_ = opts.KeyReuse
	_ = opts.ForgeCheck

	return report, nil
}

// Whoami returns the name of the current user, determined by checking which
// identity matches a user in the audit-log keyring.
func (r *Repo) Whoami() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return "", ErrClosed
	}

	whoami, _, err := identityToUser(r.identities, r.keyring.ListUsers())
	if err != nil {
		return "", fmt.Errorf("failed to identify current user: %w", err)
	}
	return whoami, nil
}
