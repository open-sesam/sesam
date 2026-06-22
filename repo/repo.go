// Package repo provides the high-level sesam repository API.
//
// A Repo is a handle to a sesam repository on disk. Load (or Init) acquires
// the on-disk `.sesam.lock`, opens the audit log, and builds the secret / user
// managers — all of which stay open for the lifetime of the Repo and are
// released by Close. Read operations live on the embedded View; state-changing
// operations live on a Stage opened via Stage()/Update(), which commits with a
// single atomic swap of the whole `.sesam` directory (see stage.go).
//
// Methods reuse the same managers across calls and serialize on a shared mutex
// (the underlying managers are not goroutine-safe).
package repo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/gofrs/flock"
	sesamConf "github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/core"
)

const defaultLockTimeout = 30 * time.Second

var ErrClosed = errors.New("sesam repo is closed")

// Repo is a handle to a sesam repo. See package-level docs for lifetime
// semantics. It embeds the live View, so committed-state reads (ListUsers,
// Status, Verify, …) are callable directly on the Repo.
type Repo struct {
	*View

	lock *flock.Flock

	// stage is the single in-flight read-write transaction, if any. Guards
	// against two concurrent forks of .sesam (see stage.go).
	stage *Stage
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

	// AskpassProgram overrides SESAM_ASKPASS when set.
	AskpassProgram string

	// AskpassRequired controls whether askpass is used: prefer, force, or never.
	// Empty means prefer.
	AskpassRequired string

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

func (opts RepoOpts) askpassRequired() string {
	switch opts.AskpassRequired {
	case "never", "force", "prefer":
		return opts.AskpassRequired
	default:
		return "prefer"
	}
}

func (opts RepoOpts) passphraseProvider(keyFingerprint string) core.PassphraseProvider {
	var fallback core.PassphraseProvider
	if opts.Interactive && opts.askpassRequired() != "force" {
		fallback = &core.StdinPassphraseProvider{}
	}
	if opts.askpassRequired() != "never" {
		fallback = &core.AskpassProvider{Program: opts.AskpassProgram, Fallback: fallback}
	}
	return &core.KeyringPassphraseProvider{
		KeyFingerprint: keyFingerprint,
		Fallback:       fallback,
	}
}

// LoadIdentities reads the user's age identity files.
func LoadIdentities(identityPaths []string, opts RepoOpts) (core.Identities, error) {
	return loadIdentitiesWith(identityPaths, opts.passphraseProvider, opts.pluginUI())
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

	// Recovery: a crashed stage may have left a .sesam-tmp fork behind. The
	// live .sesam is always authoritative (the commit swap is atomic), so the
	// fork is always safe to reap.
	if err := root.RemoveAll(forkSuffix); err != nil {
		return nil, fmt.Errorf("reap stale stage fork: %w", err)
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
		View: &View{
			mu:            &sync.Mutex{},
			sesamDir:      sesamDir,
			root:          root,
			opts:          opts,
			gitRepo:       gitRepo,
			pluginUI:      opts.pluginUI(),
			identityPaths: ids,
			config:        configRepo,
		},
	}
}

// SesamDir returns the resolved absolute path of the sesam repository.
func (r *Repo) SesamDir() string {
	return r.sesamDir
}

// Close releases the on-disk lock and closes the audit log. Safe to call
// multiple times. The first non-nil error is returned.
func (r *Repo) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	firstErr := r.closeState()

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

type SecretInfo struct {
	core.VerifiedSecret
	sesamConf.Config
}

// isUnder reports whether path lives at or beneath dir.
func isUnder(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}

	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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

type CleanOpts struct {
	Aggressive bool

	// CheckFunc is called for every path that should be cleaned.
	// Return true to allow, false to disallow.
	// Return errors immediately stops cleaning.
	//
	// NOTE: This is holding a mutex. Calling other repo API will deadlock.
	CheckFunc func(path string) (bool, error)
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
