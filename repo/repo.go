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
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/gofrs/flock"
	"github.com/google/renameio/v2"
	sesamConf "github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/core"
)

const defaultLockTimeout = 30 * time.Second

var ErrClosed = errors.New("sesam repo is closed")

// Repo is a handle to a sesam repo. See package-level docs for lifetime
// semantics.
type Repo struct {
	sesamDir string
	root     *os.Root
	opts     RepoOpts

	pluginUI *core.PluginUI
	gitRepo  *git.Repository
	lock     *flock.Flock

	whoami string

	identityPaths []string
	identities    core.Identities

	auditLog *core.AuditLog
	keyring  core.Keyring
	vstate   *core.VerifiedState
	secret   *core.SecretManager
	user     *core.UserManager

	config *sesamConf.Config
	mu     sync.Mutex
}

type VerifyMode string

const (
	// VerifyModeAll runs the default check (chain verify + root hash verify)
	VerifyModeAll = "all"

	// VerifyModeNoDisk will skip the root hash check
	VerifyModeNoDisk = "no-disk"

	VerifyModeDefault = VerifyModeAll
)

func ToVerifyMode(s string) (VerifyMode, error) {
	switch s {
	case VerifyModeAll:
	case VerifyModeNoDisk:
	default:
		return VerifyMode(""), fmt.Errorf("invalid verify mode: %s", s)
	}

	return VerifyMode(s), nil
}

// RepoOpts controls runtime behavior shared across all Repo operations.
type RepoOpts struct {
	// Interactive should be true when we can talk to the user via the terminal.
	Interactive bool

	// LockTimeout bounds how long acquiring the on-disk repo lock waits.
	// Zero means use the default.
	LockTimeout time.Duration

	// VerifyMode defines how the on-disk state is verified
	VerifyMode VerifyMode
}

type RepoInitOpts struct {
	RepoOpts

	// InitialUserName is the name of the first admin user.
	// If empty, we try to guess it from the git config.
	InitialUserName string

	// InitStep receives logs whenever something interesting happens
	InitStep func(fmt string, args ...any)
}

func (rio *RepoInitOpts) PrintStep(fmt string, args ...any) {
	if rio.InitStep == nil {
		return
	}

	rio.InitStep(fmt, args...)
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

	return idLoader(identityPaths, opts.pluginUI())
}

func guessInitUserNameFromGitConfig(repo *git.Repository) (string, error) {
	// This checks:
	// - repo .git/config
	// - ~/.gitconfig
	// - /etc/gitconfig
	cfg, err := repo.ConfigScoped(config.SystemScope)
	if err != nil {
		return "", fmt.Errorf("failed to read git config: %w", err)
	}

	if cfg.User.Email != "" {
		return strings.ToLower(cfg.User.Email), nil
	}

	if cfg.User.Name != "" {
		n := cfg.User.Name
		n = strings.ReplaceAll(n, " ", "_")
		n = strings.ReplaceAll(n, "/", "_")
		n = strings.ToLower(n)
		return n, nil
	}

	return "", fmt.Errorf("user.email is not set in git-config - please pass --user")
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
// ids are paths to the admin's age identity files. The sesam config is written
// to <sesamDir>/sesam.yml. On success the returned Repo holds the on-disk lock
// and has the secret / user managers ready for use; the caller must Close it.
//
// The initial user's name is derived from git config (if possible) or taken from the options if given explicitly.
func Init(ctx context.Context, sesamDir string, idPaths []string, opts RepoInitOpts) (*Repo, error) {
	resolvedDir, gitRepo, err := resolveSesamDirAndGit(sesamDir)
	if err != nil {
		return nil, err
	}

	if err := isInitialized(resolvedDir); err != nil {
		return nil, err
	}

	if opts.InitialUserName == "" {
		opts.InitialUserName, err = guessInitUserNameFromGitConfig(gitRepo)
		if err != nil {
			return nil, err
		}

		opts.PrintStep(
			"Guessed initial user's name from git-config as `%s` (use --user to override)",
			opts.InitialUserName,
		)
	}

	if err := core.ValidUserName(opts.InitialUserName); err != nil {
		return nil, fmt.Errorf("invalid initial user %q: %w", opts.InitialUserName, err)
	}

	root, err := os.OpenRoot(resolvedDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open repo root %q: %w", resolvedDir, err)
	}

	r := newRepo(resolvedDir, root, nil, gitRepo, idPaths, opts.RepoOpts)
	r.whoami = opts.InitialUserName
	success := false
	defer func() {
		if !success {
			_ = r.Close()

			// cleanup half created state:
			_ = os.RemoveAll(filepath.Join(resolvedDir, ".sesam"))
			_ = os.RemoveAll(filepath.Join(resolvedDir, "sesam.yml"))
		}
	}()

	identities, err := loadIdentities(idPaths, r.pluginUI)
	if err != nil {
		return nil, err
	}
	r.identities = identities

	opts.PrintStep("Will use identities at %q…", strings.Join(idPaths, ", "))

	opts.PrintStep("Creating repo at »%s«…", filepath.Join(resolvedDir, ".sesam"))
	if err := ensureSesamDirs(resolvedDir); err != nil {
		return nil, err
	}

	if err := r.acquireLock(); err != nil {
		return nil, err
	}

	opts.PrintStep("Creating initial sesam.yml")
	configPath := filepath.Join(resolvedDir, "sesam.yml")
	if err := createInitialConfig(
		configPath,
		opts.InitialUserName,
		identities.RecipientStrings(),
	); err != nil {
		return nil, err
	}

	configRepo, err := sesamConf.Load(root, "sesam.yml")
	if err != nil {
		return nil, err
	}
	r.config = configRepo

	opts.PrintStep("Creating initial user »%s«…", opts.InitialUserName)
	signer, auditLog, err := core.InitAdminUser(
		ctx,
		root,
		opts.InitialUserName,
		identities.RecipientStrings(),
		r.pluginUI,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize admin user: %w", err)
	}
	r.auditLog = auditLog

	r.keyring = core.EmptyKeyring()

	verifyFn := core.Verify
	if opts.VerifyMode == VerifyModeNoDisk {
		verifyFn = core.VerifyChain
	}

	vstate, err := verifyFn(auditLog, r.keyring, r.pluginUI)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}
	r.vstate = vstate

	r.secret, err = core.BuildSecretManager(resolvedDir, root, identities, signer, r.keyring, auditLog, vstate)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	r.user, err = core.BuildUserManager(root, signer, auditLog, vstate, r.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	opts.PrintStep("Adjusting .gitgnore to ignore all revealed files…")
	if err := ensureDefaultGitIgnore(resolvedDir); err != nil {
		return nil, err
	}

	opts.PrintStep("Telling git when to call sesam…")
	if err := ensureDefaultGitAttributes(resolvedDir); err != nil {
		return nil, err
	}

	opts.PrintStep("Adjusting git config…")
	if err := ensureGitConfig(gitRepo, resolvedDir, opts); err != nil {
		return nil, err
	}

	opts.PrintStep("Creating initial README.md as first secret…")
	if err := ensureSesamReadme(resolvedDir); err != nil {
		return nil, err
	}

	if err := r.secret.SecretAdd("README.md", []string{"admin"}); err != nil {
		return nil, fmt.Errorf("failed to bootstrap readme secret: %w", err)
	}

	opts.PrintStep("Making sure the rains come down in Africa…")
	if err := r.secret.SealAll(); err != nil {
		return nil, err
	}

	opts.PrintStep("Staging all files…")
	if err := stageInitFiles(gitRepo, resolvedDir, configPath); err != nil {
		return nil, err
	}

	opts.PrintStep("Welcome to…")
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

	root, err := os.OpenRoot(resolvedDir)
	if err != nil {
		return nil, fmt.Errorf("failed to open repo root %q: %w", resolvedDir, err)
	}

	configRepo, err := sesamConf.Load(root, "sesam.yml")
	if err != nil {
		_ = root.Close()
		return nil, err
	}

	r := newRepo(resolvedDir, root, configRepo, gitRepo, ids, opts)
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

	auditLog, err := core.LoadAuditLog(root, identities)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit log: %w", err)
	}
	r.auditLog = auditLog

	verifyFn := core.Verify
	if opts.VerifyMode == VerifyModeNoDisk {
		verifyFn = core.VerifyChain
	}

	vstate, err := verifyFn(auditLog, r.keyring, r.pluginUI)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}
	r.vstate = vstate

	whoami, signIdentity, err := identityToUser(identities, r.keyring.ListUsers())
	if err != nil {
		return nil, fmt.Errorf("failed to map identity to user: %w", err)
	}
	r.whoami = whoami

	signer, err := core.LoadSignKey(root, whoami, signIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key for %s: %w", whoami, err)
	}

	r.secret, err = core.BuildSecretManager(resolvedDir, root, identities, signer, r.keyring, auditLog, vstate)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	r.user, err = core.BuildUserManager(root, signer, auditLog, vstate, r.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	success = true
	return r, nil
}

func newRepo(sesamDir string, root *os.Root, configRepo *sesamConf.Config, gitRepo *git.Repository, ids []string, opts RepoOpts) *Repo {
	// sesamDir is already absolute - resolveSesamDirAndGit normalizes it, the
	// single place that resolves it against the cwd.
	return &Repo{
		sesamDir:      sesamDir,
		root:          root,
		opts:          opts,
		gitRepo:       gitRepo,
		pluginUI:      opts.pluginUI(),
		identityPaths: ids,
		config:        configRepo,
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
	if r.root != nil {
		if err := r.root.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close repo root: %w", err)
		}
		r.root = nil
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

type SecretInfo struct {
	core.VerifiedSecret
	sesamConf.Config
}

// ListSecrets returns a list of secrets currently managed by sesam.
func (r *Repo) ListSecrets(paths []string) ([]SecretInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	var out []SecretInfo
	if len(paths) == 0 {
		for _, secret := range r.vstate.Secrets {
			out = append(out, SecretInfo{
				VerifiedSecret: secret,
			})
		}

		return out, nil
	}

	// filter a bit:
	for _, path := range paths {
		for _, secret := range r.secretsUnder(path) {
			out = append(out, SecretInfo{
				VerifiedSecret: secret,
				// TODO: Associate it with config here. We could add a layer in front
				// of the config that would turn the config state into go structs once
				// at load and then only modifies the loaded state. The actual AST
				// modifications are passed through the underying implementation.
			})
		}
	}

	return out, nil
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

	if err := r.user.UserTell(ctx, user, recipients, groups); err != nil {
		return fmt.Errorf("failed to add user: %w", err)
	}

	if err := r.config.UserTell(user, recipients, groups); err != nil {
		return fmt.Errorf("failed to add user %q to config: %w", user, err)
	}
	return r.config.Save()
}

// UserKill removes `user` from the list of authenticated users.
// All secrets are immediately re-sealed.
func (r *Repo) UserKill(user string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	if err := r.user.UserKill(user); err != nil {
		return fmt.Errorf("failed to remove user: %w", err)
	}

	if err := r.config.UserKill(user); err != nil {
		return fmt.Errorf("failed to remove user %q from config: %w", user, err)
	}
	return r.config.Save()
}

// SecretAdd adds the secret(s) at each path to the secrets known by sesam. A
// path can be a single file, several files, or a directory (added recursively).
// When nested is set, subdirectories get their own sesam.yml included from the
// main file; otherwise everything is flattened into the main file.
//
// Paths are sesam-relative (the cli layer resolves the caller's cwd before
// handing them down). Re-adding files will change their groups accordingly.
func (r *Repo) SecretAdd(revealedPaths, groups []string, nested bool) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	var files []string
	for _, p := range revealedPaths {
		expanded, err := r.expandSecretFiles(p)
		if err != nil {
			return fmt.Errorf("failed to expand %q: %w", p, err)
		}
		files = append(files, expanded...)
	}

	for _, rel := range files {
		if err := core.IsForbiddenPath(rel); err != nil {
			return err
		}

		// Config and the secret manager each self-decide add vs. change.
		if err := r.config.SecretAdd(rel, nested, groups); err != nil {
			return fmt.Errorf("failed to add secret %q to config: %w", rel, err)
		}

		if err := r.secret.SecretAdd(rel, groups); err != nil {
			return fmt.Errorf("failed to add secret %q: %w", rel, err)
		}
	}

	return r.config.Save()
}

// expandSecretFiles resolves a sesam-relative path into the concrete regular
// files it represents. A regular file yields itself; a directory is walked
// recursively. Only the .git and .sesam metadata directories are skipped —
// other dotfiles (e.g. .env) are valid secrets, matching core.IsForbiddenPath.
// Non-regular entries (symlinks, sockets, devices, …) and sesam.yml are
// ignored. Returned paths are sesam-relative and cleaned.
func (r *Repo) expandSecretFiles(rel string) ([]string, error) {
	rel = filepath.Clean(rel)
	info, err := r.root.Stat(rel)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{rel}, nil
	}

	var files []string
	err = fs.WalkDir(r.root.FS(), filepath.ToSlash(rel), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if name := d.Name(); name == gitSuffix || name == sesamSuffix {
				return fs.SkipDir
			}
			return nil
		}

		// Only regular files can become secrets; skip symlinks, sockets,
		// devices, fifos and the config files themselves.
		if !d.Type().IsRegular() || d.Name() == "sesam.yml" {
			return nil
		}

		files = append(files, filepath.Clean(filepath.FromSlash(p)))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

// secretsUnder returns every managed secret located at the sesam-relative path
// rel or beneath it, enumerated from the verified state rather than the
// filesystem. This makes remove/move work even when the plaintext is not
// currently revealed on disk. The result is sorted by revealed path.
func (r *Repo) secretsUnder(rel string) []core.VerifiedSecret {
	target := filepath.Clean(rel)

	var out []core.VerifiedSecret
	for _, s := range r.vstate.Secrets {
		secretRel := filepath.Clean(s.RevealedPath)
		if secretRel == target || isUnder(target, secretRel) {
			out = append(out, s)
		}
	}

	slices.SortFunc(out, func(a, b core.VerifiedSecret) int {
		return strings.Compare(a.RevealedPath, b.RevealedPath)
	})

	return out
}

// isUnder reports whether path lives at or beneath dir.
func isUnder(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}

	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// SecretRemove stops tracking the secret(s) at each path. A path can be a
// single file, several files, or a directory (removed recursively). The config
// entries are dropped and the encrypted objects deleted; the plaintext files
// are left on disk for the user to delete.
func (r *Repo) SecretRemove(revealedPaths []string) error {
	if len(revealedPaths) == 0 {
		return fmt.Errorf("missing secret path: pass at least one path")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	for _, p := range revealedPaths {
		targets := r.secretsUnder(p)
		if len(targets) == 0 {
			return fmt.Errorf("no secrets found for %q", p)
		}

		for _, secret := range targets {
			rel := secret.RevealedPath

			// TODO: We should not assume that config actually had this secret configured.
			//       During normal workflow this might be not in there. So not hard error at least.
			if err := r.config.SecretRemove(rel); err != nil {
				return fmt.Errorf("failed to remove secret %q from config: %w", rel, err)
			}

			if err := r.secret.SecretRemove(rel); err != nil {
				return fmt.Errorf("failed to remove secret %q: %w", rel, err)
			}
		}
	}

	return r.config.Save()
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
	Success          bool                   `json:"success"`
	Integrity        *core.IntegrityReport  `json:"integrity,omitempty"`
	TruncateError    error                  `json:"truncate_error,omitempty"`
	ForgeCheckReport *core.ForgeReport      `json:"forge_report,omitempty"`
	SharedPublicKeys []core.SharedPublicKey `json:"shared_public_keys,omitempty"`
}

// OK reports whether every requested check passed.
func (rep *VerifyReport) OK() bool {
	if rep == nil {
		return true
	}

	if rep.Integrity != nil && !rep.Integrity.OK() {
		return false
	}

	if rep.TruncateError != nil {
		return false
	}

	if len(rep.SharedPublicKeys) > 0 {
		return false
	}

	// NOTE: ForgeCheckReport may exist, they're more informal.
	return true
}

// Verify will check the repository's state depending on the verification
// strategies set in opts. Some verifications are hard errors (i.e. when the
// audit log cannot be decrypted or is inconsistent) and are returned as
// `err`. All other consistency checks have their results placed in the
// returned report.
func (r *Repo) Verify(ctx context.Context, opts VerifyOptions) (*VerifyReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	report := &VerifyReport{}

	if opts.Integrity {
		report.Integrity = core.VerifyIntegrity(r.root, r.vstate, r.keyring)
		if report.Integrity.IsZero() {
			report.Integrity = nil
		}
	}

	if opts.ForgeCheck {
		report.ForgeCheckReport = core.VerifyForgeIds(ctx, r.vstate, r.keyring, r.opts.pluginUI())
		if report.ForgeCheckReport.IsZero() {
			report.ForgeCheckReport = nil
		}
	}

	if opts.Truncation {
		report.TruncateError = core.VerifyHistory(r.sesamDir, r.gitRepo, r.identities, r.opts.pluginUI())
	}

	if opts.KeyReuse {
		report.SharedPublicKeys = core.VerifyKeyReuse(r.keyring)
	}

	report.Success = report.OK()
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

	return r.whoami, nil
}

func (r *Repo) Log(fn func(e *core.AuditEntrySigned) error) error {
	ents := r.auditLog.Entries
	for idx := len(ents) - 1; idx >= 0; idx-- {
		if err := fn(&ents[idx]); err != nil {
			return err
		}
	}

	return nil
}

// SecretMove relocates the secret(s) at oldRevealedPath to newRevealedPath. A
// single secret is renamed directly; a directory moves every secret beneath it,
// preserving each one's path relative to the source root. Both the audit log
// (secret manager) and the config files are kept in sync.
func (r *Repo) SecretMove(oldRevealedPath, newRevealedPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	oldBase := filepath.Clean(oldRevealedPath)
	newBase := filepath.Clean(newRevealedPath)

	targets := r.secretsUnder(oldBase)
	if len(targets) == 0 {
		return fmt.Errorf("no secrets found for %q", oldRevealedPath)
	}

	for _, secret := range targets {
		oldRel := filepath.Clean(secret.RevealedPath)
		// Map each secret under the source onto the destination, preserving its
		// path relative to the source root (the source itself maps directly).
		sub, err := filepath.Rel(oldBase, oldRel)
		if err != nil {
			return err
		}

		newRel := newBase
		if sub != "." {
			newRel = filepath.Join(newBase, sub)
		}

		if err := r.secret.SecretMove(oldRel, newRel); err != nil {
			return fmt.Errorf("failed to move secret %q: %w", oldRel, err)
		}

		// TODO: preserve nested layout on move (derive from the source's owning
		// file); for now the moved secret lands in the main file.
		//
		// TODO: We should not assume that config actually had this secret configured.
		//       During normal workflow this might be not in there. So not hard error at least.
		if err := r.config.SecretMove(oldRel, newRel, false); err != nil {
			return fmt.Errorf("failed to move secret %q in config: %w", oldRel, err)
		}
	}

	return r.config.Save()
}

func (r *Repo) UserRename(oldName, newName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	// TODO: Needs config integration.
	return r.user.UserRename(oldName, newName)
}

func (r *Repo) UserChangeGroups(user string, groups []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	// TODO: Needs config integration.
	return r.user.UserChangeGroups(user, groups)
}

func (r *Repo) UserAddRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	// TODO: Needs config integration.
	return r.user.UserAddRecipient(ctx, user, pubKeySpecs)
}

func (r *Repo) UserRmRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	// TODO: Needs config integration.
	return r.user.UserRmRecipient(ctx, user, pubKeySpecs)
}

func (r *Repo) UserRegenerateSignKey(user string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return ErrClosed
	}

	return r.user.UserRegenerateSignKey(user)
}

type SecretState int

const (
	SecretStateNone = SecretState(iota)
	SecretStateNoSealedPath
	SecretStateNoRevealedPath
	SecretStateUserHasNoAccess
	SecretStateInSync
	SecretStateNotInSync
	SecretStateUnmanaged
)

func (s SecretState) String() string {
	var desc string
	switch s {
	case SecretStateNoSealedPath:
		desc = "unsealed"
	case SecretStateNoRevealedPath:
		desc = "unrevealed"
	case SecretStateUserHasNoAccess:
		desc = "no_access"
	case SecretStateInSync:
		desc = "in_sync"
	case SecretStateNotInSync:
		desc = "out_of_sync"
	case SecretStateUnmanaged:
		desc = "unmanaged"
	default:
		desc = "undefined"
	}

	return desc
}

func (s SecretState) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", s.String())), nil
}

// StatusForFile describes wether the sealed file differs from the revealed file.
//
// Cases:
//
//  1. Seal exists, Revealed does not exist => Not yet revealed, because cleaned.
//  2. Seal exists, Revealed does not exist => Not revealed, because user has no access.
//  3. Seal exists not, Reveaed exists      => Not yet sealed.
//  4. Both exist and user has access to it => Either equal or not.
type StatusForFile struct {
	RevealedPath string      `json:"revealed_path"`
	State        SecretState `json:"state"`

	// AccessGroups are the groups granted access to this secret. Empty for
	// unmanaged files (SecretStateNoSesamSecret).
	AccessGroups []string `json:"access_groups,omitempty"`

	// AccessUsers are the users having access to this file.
	AccessUsers []string `json:"access_users,omitempty"`
}

// Status describes how the revealed state compares to the sealed state
type Status struct {
	// Files are the reports for each known secret
	Files []StatusForFile `json:"files"`

	// DiffDir is only set when WriteDiffDirs is true.
	DiffDir string `json:"-"`
}

// StatusOpts can be given to Status()
type StatusOpts struct {
	// WriteDiffDirs will return a tmp directory that has a sealed/ and revealed/ sub-directory.
	// It contains the whole repo in a way that can be easily passed to `git diff`.
	// You are supposed to delete this directory after use.
	WriteDiffDirs bool

	// IgnoreUnmanaged will ignore files not managed by sesam.
	IgnoreUnmanaged bool
}

func (r *Repo) cleanablePaths() ([]string, error) {
	paths := []string{}
	err := cleanup(r.gitRepo, r.sesamDir, func(path string) (bool, error) {
		paths = append(paths, path)
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return paths, nil
}

// Status computes a comparison between the revealed and sealed state in the repo.
func (r *Repo) Status(opts StatusOpts) (*Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	var status Status

	secretMap := make(map[string]*core.VerifiedSecret)
	for idx := range r.vstate.Secrets {
		secretMap[r.vstate.Secrets[idx].RevealedPath] = &r.vstate.Secrets[idx]
	}

	if !opts.IgnoreUnmanaged {
		allPaths, err := r.cleanablePaths()
		if err != nil {
			return nil, fmt.Errorf("failed to list all paths: %w", err)
		}

		for _, path := range allPaths {
			if _, ok := secretMap[path]; !ok {
				secretMap[path] = nil
			}
		}
	}

	for revealedPath, secret := range secretMap {
		// Unmanaged files have no associated secret (and no access groups).
		if secret == nil {
			status.Files = append(status.Files, StatusForFile{
				RevealedPath: revealedPath,
				State:        SecretStateUnmanaged,
			})
			continue
		}

		add := func(state SecretState) {
			sff := StatusForFile{
				RevealedPath: revealedPath,
				State:        state,
				AccessGroups: slices.Clone(secret.AccessGroups),
				AccessUsers:  r.vstate.UserForGroups(secret.AccessGroups),
			}

			sort.Strings(sff.AccessGroups)
			sort.Strings(sff.AccessUsers)
			status.Files = append(status.Files, sff)
		}

		if !r.vstate.UserHasAccess(r.whoami, secret.AccessGroups) {
			add(SecretStateUserHasNoAccess)
			continue
		}

		if _, err := r.root.Stat(revealedPath); err != nil {
			add(SecretStateNoRevealedPath)
			continue
		}

		sealedPath := r.secret.SealedPath(revealedPath)
		if _, err := r.root.Stat(sealedPath); err != nil {
			add(SecretStateNoSealedPath)
			continue
		}

		same, err := r.secret.EqualPlaintext(revealedPath, r.identities)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to compare %s and %s: %w",
				revealedPath,
				sealedPath,
				err,
			)
		}

		if same {
			add(SecretStateInSync)
		} else {
			add(SecretStateNotInSync)
		}
	}

	sort.Slice(status.Files, func(i, j int) bool {
		return status.Files[i].RevealedPath < status.Files[j].RevealedPath
	})

	if opts.WriteDiffDirs {
		tmpDir, err := r.statusToDiffDir(&status)
		if err != nil {
			return nil, err
		}

		status.DiffDir = tmpDir
	}

	return &status, nil
}

func (r *Repo) statusToDiffDir(status *Status) (diffDir string, err error) {
	// The diff tree is consumed by an external `git diff` process, so it is
	// built with absolute paths outside the root.
	rootTmpDir := filepath.Join(r.sesamDir, core.SesamTmpDir())
	tmpDir, err := os.MkdirTemp(rootTmpDir, "status-diff-")
	if err != nil {
		return "", fmt.Errorf("failed to make temp dir for diff: %w", err)
	}

	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	sealTmpDir := filepath.Join(tmpDir, "sealed")
	plainTmpDir := filepath.Join(tmpDir, "revealed")

	for _, file := range status.Files {
		sealTmpPath := filepath.Join(sealTmpDir, file.RevealedPath)
		if err := os.MkdirAll(filepath.Dir(sealTmpPath), 0o700); err != nil {
			return "", fmt.Errorf("failed to make sub temp dir for diff: %w", err)
		}

		switch file.State {
		case SecretStateNoSealedPath, SecretStateUserHasNoAccess, SecretStateNone:
			// can't decrypt path - put a dummy file there.
			desc, _ := file.State.MarshalJSON()
			if err := renameio.WriteFile(sealTmpPath, desc, 0o600); err != nil {
				return "", fmt.Errorf("failed write sealed state file: %w", err)
			}
		case SecretStateInSync:
			// no need to write same files.
		default:
			//nolint:gosec
			sealFd, err := os.OpenFile(sealTmpPath, os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0o600)
			if err != nil {
				return "", fmt.Errorf("failed to open sealed file: %w", err)
			}

			if _, err := core.ShowSecret(r.root, r.identities, file.RevealedPath, sealFd); err != nil {
				_ = sealFd.Close()
				return "", err
			}

			if err := sealFd.Close(); err != nil {
				return "", fmt.Errorf("failed to close seal file: %w", err)
			}
		}

		plainTmpPath := filepath.Join(plainTmpDir, file.RevealedPath)
		if err := os.MkdirAll(filepath.Dir(plainTmpPath), 0o700); err != nil {
			return "", fmt.Errorf("failed to make sub temp dir for diff: %w", err)
		}

		switch file.State {
		case SecretStateNoRevealedPath, SecretStateNone, SecretStateUserHasNoAccess:
			// can't link revealed path, write dummy file.
			desc := fmt.Sprintf("-- sesam: %s --", file.State.String())
			if err := renameio.WriteFile(plainTmpPath, []byte(desc), 0o600); err != nil {
				return "", fmt.Errorf("failed write revealed state file: %w", err)
			}
		case SecretStateInSync:
			// no need to write same files.
		default:
			if err := os.Link(filepath.Join(r.sesamDir, file.RevealedPath), plainTmpPath); err != nil {
				return "", fmt.Errorf("failed to link revealed file: %w", err)
			}
		}
	}

	return tmpDir, nil
}
