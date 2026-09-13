package repo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"filippo.io/age"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sahib/renameio/v2"
	sesamConf "opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
)

// View is a consistent, read-only window onto a sesam state. It is embedded in
// both Repo (the live, committed state) and Stage (a fork-bound, staged state),
// so the read API is shared and a Stage's reads transparently reflect its own
// uncommitted writes.
//
// A View never creates its own resources directly: Repo.Load/Init build the
// live one and Stage forks one. The mutex is shared by pointer with the owning
// Repo so live reads and a stage's reads/commit serialize against each other.
type View struct {
	// mu is shared (by pointer) with the owning Repo and any open Stage so all
	// operations serialize on one lock (the managers are not goroutine-safe).
	mu *sync.Mutex

	// sesamDir is the absolute path the root is anchored at; kept for git
	// interop, the directory swap and worktree-side paths.
	sesamDir string

	// root confines all sesam file I/O to the repository.
	root *os.Root

	opts     RepoOpts
	pluginUI *core.PluginUI
	gitRepo  *git.Repository

	whoami string

	identityPaths []string
	identities    core.Identities

	auditLog *core.AuditLog
	keyring  core.Keyring
	vstate   *core.VerifiedState
	secret   *core.SecretManager
	user     *core.UserManager

	config *sesamConf.Config
}

func (v *View) isClosed() bool {
	return v.auditLog == nil
}

// cfg returns the repo config, loading sesam.yml on first use and caching it.
// Caller must hold v.mu (matching expandSecretFiles/secretsUnder). This is the
// canonical config access point for staged writes today and read paths (apply,
// the config commands) later.
func (v *View) cfg() (*sesamConf.Config, error) {
	if v.config == nil {
		c, err := sesamConf.Load(v.root, "sesam.yml")
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		v.config = c
	}
	return v.config, nil
}

// closeState closes the audit log and verified state. The root and lock are
// shared/owned by the Repo and are not touched here.
func (v *View) closeState() error {
	return v.closeStateQuiet(true)
}

func (v *View) closeStateQuiet(warnPendingSeal bool) error {
	var errs []error
	if v.auditLog != nil {
		if err := v.auditLog.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close audit log: %w", err))
		}
		v.auditLog = nil
	}
	if v.vstate != nil {
		// A pending seal means unsealed changes sit on disk; nudge the user to
		// seal before committing. Suppressed mid-merge, where the seal is
		// intentionally deferred to the finalize pre-commit.
		if srs := v.vstate.SealRequiredSeqID; warnPendingSeal && srs > 0 && !v.opts.InMerge {
			slog.Warn(
				"a seal is pending - please run `sesam seal` before committing!",
				slog.Uint64("seq_id", srs),
			)
		}
		v.vstate = nil
	}
	return errors.Join(errs...)
}

type UserInfo struct {
	core.VerifiedUser
	Config sesamConf.User `json:"config"`
}

// ListUsers returns the users currently in the audit log.
func (v *View) ListUsers() ([]UserInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	cfg, err := v.cfg()
	if err != nil {
		return nil, err
	}

	cfgUsers, err := cfg.Users()
	if err != nil {
		return nil, err
	}

	combinedInfo := func(vu core.VerifiedUser) UserInfo {
		idx := slices.IndexFunc(cfgUsers, func(s sesamConf.User) bool {
			return s.Name == vu.Name
		})

		info := UserInfo{
			VerifiedUser: vu,
		}

		if idx >= 0 {
			info.Config = cfgUsers[idx]
		}

		return info
	}

	out := make([]UserInfo, 0, len(v.vstate.Users))
	for idx := range v.vstate.Users {
		out = append(out, combinedInfo(v.vstate.Users[idx]))
	}

	return out, nil
}

// ListSecrets returns the secrets currently managed by sesam.
func (v *View) ListSecrets(paths []string) ([]SecretInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	cfg, err := v.cfg()
	if err != nil {
		return nil, err
	}

	cfgSecrets, err := cfg.Secrets()
	if err != nil {
		return nil, err
	}

	// NOTE: This is probably slow for large N, but ok for the start.
	combinedInfo := func(vs core.VerifiedSecret) SecretInfo {
		idx := slices.IndexFunc(cfgSecrets, func(s sesamConf.Secret) bool {
			return s.Path == vs.RevealedPath
		})

		info := SecretInfo{
			VerifiedSecret: vs,
		}

		if idx >= 0 {
			info.Config = cfgSecrets[idx]
		}

		return info
	}

	out := make([]SecretInfo, 0, len(v.vstate.Secrets))
	if len(paths) == 0 {
		for _, secret := range v.vstate.Secrets {
			out = append(out, combinedInfo(secret))
		}
		return out, nil
	}

	for _, path := range paths {
		for _, secret := range v.secretsUnder(path) {
			out = append(out, combinedInfo(secret))
		}
	}

	return out, nil
}

// Reveal reveals all secrets to the worktree.
// If `all` is false we will check the hmac of each file
// before starting to decrypt as an optimization.
func (v *View) Reveal(all bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return ErrClosed
	}

	if err := v.secret.Reveal(all); err != nil {
		return fmt.Errorf("failed to reveal secrets: %w", err)
	}
	return nil
}

// RevealPaths reveals only the named secrets to the worktree.
func (v *View) RevealPaths(paths []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return ErrClosed
	}

	if err := v.secret.RevealPaths(paths); err != nil {
		return fmt.Errorf("failed to reveal secrets: %w", err)
	}
	return nil
}

// VerifiedState is the state the audit log replayed to. Callers must treat it as
// read-only; it is the same value the view keeps working with.
func (v *View) VerifiedState() (*core.VerifiedState, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	return v.vstate, nil
}

// ClearTmp empties the repo's scratch space.
func (v *View) ClearTmp() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return ErrClosed
	}

	return ClearTmp(v.root)
}

// Clean removes stale plaintext from the worktree. See CleanOpts for modes.
func (v *View) Clean(ctx context.Context, opts CleanOpts) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return ErrClosed
	}

	if opts.Aggressive {
		return CleanAggressive(ctx, v.sesamDir, v.identityPaths, opts)
	}

	if err := deleteRevealedSecrets(v.root, v.secret.State.Secrets, opts.CheckFunc); err != nil {
		return fmt.Errorf("failed to delete revealed secrets: %w", err)
	}

	_, err := core.PruneEmptyDirs(v.root, ".", map[string]bool{
		sesamSuffix: true,
		gitSuffix:   true,
	}, opts.CheckFunc)

	return err
}

// ShowUser writes a JSON description of the named user to out. The bool is true
// iff a user with that name exists.
func (v *View) ShowUser(name string, out io.Writer) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return false, ErrClosed
	}

	return v.user.ShowUser(name, out)
}

// Verify checks the repository's state per the strategies set in opts. Hard
// errors (undecryptable/inconsistent log) come back as err; all other check
// results are placed in the report.
func (v *View) Verify(ctx context.Context, opts VerifyOptions) (*VerifyReport, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	report := &VerifyReport{}

	if opts.Integrity {
		report.Integrity = core.VerifyIntegrity(v.root, v.vstate, v.keyring)
		if report.Integrity.IsZero() {
			report.Integrity = nil
		}
	}

	if opts.ForgeCheck {
		report.ForgeCheckReport = core.VerifyForgeIds(ctx, v.root, v.vstate, v.keyring, v.opts.pluginUI())
		if report.ForgeCheckReport.IsZero() {
			report.ForgeCheckReport = nil
		}
	}

	if opts.Truncation {
		report.TruncateError = core.VerifyHistory(v.sesamDir, v.gitRepo, v.identities, v.opts.pluginUI())
	}

	if opts.KeyReuse {
		report.SharedPublicKeys = core.VerifyKeyReuse(v.keyring)
	}

	report.Success = report.OK()
	return report, nil
}

// Whoami returns the current user, determined by matching an identity against
// the audit-log keyring.
func (v *View) Whoami() (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return "", ErrClosed
	}

	return v.whoami, nil
}

// Log iterates the audit entries newest-first, invoking fn for each.
func (v *View) Log(fn func(e *core.AuditEntrySigned) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return ErrClosed
	}

	ents := v.auditLog.Entries
	for idx := len(ents) - 1; idx >= 0; idx-- {
		if err := fn(&ents[idx]); err != nil {
			return err
		}
	}

	return nil
}

// ConflictedSecrets returns the secrets a merge left unresolved - text (in-file
// conflict markers) and binary (.ours/.theirs side files) alike, each tagged via
// ConflictedSecret.Binary. git cannot catch either (revealed files are gitignored,
// the object is ciphertext), so the finalize must stop until they are resolved.
func (v *View) ConflictedSecrets() ([]core.ConflictedSecret, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	return core.ConflictedSecrets(v.root, v.vstate.Secrets)
}

// MergedSecretSplit sorts the secrets a merge staged by what has to happen to
// their revealed file before the finalize seals.
type MergedSecretSplit struct {
	// Stale plaintext: still the pre-merge content, so it has to be replaced or
	// the seal would write it back over what the merge brought in.
	Stale []string

	// Edited by the user after the merge stopped. Revealing would discard that
	// silently, so their version is kept and sealed instead.
	Edited []string
}

// SplitMergedSecrets decides, for each secret a merge staged, whether its
// revealed file may be refreshed from the object. It compares the plaintext
// against two objects: the one the merge staged, and the one at HEAD
//
//   - equal to the staged object: already the merge result, nothing to do
//   - equal to HEAD's object: never touched, now stale => reveal
//   - equal to neither: the user wrote it themselves => keep
//
// A path that cannot be read is reported stale. RevealPaths skips whatever
// it has no access to.
func (v *View) SplitMergedSecrets(paths []string) (*MergedSecretSplit, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	prefix, err := core.SesamGitPrefix(v.gitRepo, v.sesamDir)
	if err != nil {
		return nil, err
	}

	headTree, err := v.headTree()
	if err != nil {
		return nil, err
	}

	ageIds := v.identities.AgeIdentities()

	split := &MergedSecretSplit{}
	for _, revealedPath := range paths {
		objectPath := core.ObjectPath(revealedPath)

		revealed, err := fs.ReadFile(v.root.FS(), revealedPath)
		if err != nil {
			// No plaintext to lose; the reveal writes it out.
			split.Stale = append(split.Stale, revealedPath)
			continue
		}

		staged, err := decryptRootObject(v.root, objectPath, ageIds)
		if err != nil {
			slog.Debug(
				"merge finalize: cannot read the staged object",
				slog.String("path", revealedPath), slog.Any("err", err),
			)
			split.Stale = append(split.Stale, revealedPath)
			continue
		}

		if bytes.Equal(revealed, staged) {
			continue // already holds the merge result
		}

		head, err := decryptTreeObject(headTree, path.Join(prefix, filepath.ToSlash(objectPath)), ageIds)
		switch {
		case errors.Is(err, object.ErrFileNotFound):
			// The merge added this secret, so the plaintext beside it predates it
			// and is nobody's but the user's. Keep it.
			split.Edited = append(split.Edited, revealedPath)
		case err != nil:
			slog.Debug(
				"merge finalize: cannot read the pre-merge object",
				slog.String("path", revealedPath), slog.Any("err", err),
			)
			split.Stale = append(split.Stale, revealedPath)
		case bytes.Equal(revealed, head):
			split.Stale = append(split.Stale, revealedPath)
		default:
			split.Edited = append(split.Edited, revealedPath)
		}
	}

	return split, nil
}

// headTree is the tree of the commit the worktree is on. During a merge that is
// still the pre-merge state: the merge commit is only written after the finalize.
func (v *View) headTree() (*object.Tree, error) {
	head, err := v.gitRepo.Head()
	if err != nil {
		return nil, fmt.Errorf("resolve HEAD: %w", err)
	}

	commit, err := v.gitRepo.CommitObject(head.Hash())
	if err != nil {
		return nil, fmt.Errorf("read HEAD commit %s: %w", head.Hash(), err)
	}

	return commit.Tree()
}

// decryptRootObject decrypts a sealed object from the worktree.
func decryptRootObject(root *os.Root, objectPath string, ageIds []age.Identity) ([]byte, error) {
	fd, err := root.Open(objectPath)
	if err != nil {
		return nil, err
	}

	defer func() { _ = fd.Close() }()

	return decryptObjectBytes(fd, ageIds)
}

// decryptTreeObject decrypts a sealed object out of a git tree. The blob has to
// be buffered: reading the footer seeks, and go-git hands out a plain reader.
func decryptTreeObject(tree *object.Tree, treePath string, ageIds []age.Identity) ([]byte, error) {
	file, err := tree.File(treePath)
	if err != nil {
		return nil, err
	}

	rd, err := file.Reader()
	if err != nil {
		return nil, err
	}

	defer func() { _ = rd.Close() }()

	blob, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}

	return decryptObjectBytes(bytes.NewReader(blob), ageIds)
}

// decryptObjectBytes decrypts a sealed object into memory. The signature is not
// checked: the plaintext is only ever compared against another one, never
// written anywhere.
func decryptObjectBytes(rd io.ReadSeeker, ageIds []age.Identity) ([]byte, error) {
	var buf bytes.Buffer
	if _, _, _, err := core.RevealStream(rd, &buf, ageIds); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// noGitIntegrationWarningFile is the opt-out sentinel: if present under the
// sesam dir, the "git integration not installed" nudge is suppressed.
const noGitIntegrationWarningFile = ".sesam/no-git-integration-warning"

// GitIntegrationInstalled reports whether `sesam init` has wired this checkout's
// git integration at least once - i.e. any sesam-managed git-config entry is
// present. A fresh clone that never ran init has none; that is the case the
// load-time nudge targets (the integration lives in .git/config, which is not
// cloned).
func (v *View) GitIntegrationInstalled() (bool, error) {
	checks, err := CheckGitConfig(v.sesamDir)
	if err != nil {
		return false, err
	}

	for _, c := range checks {
		if c.Actual != "" {
			return true, nil
		}
	}

	return false, nil
}

// GitIntegrationNudgeSuppressed reports whether the user opted out of the
// missing-integration nudge via the noGitIntegrationWarningFile sentinel.
func (v *View) GitIntegrationNudgeSuppressed() bool {
	_, err := v.root.Stat(noGitIntegrationWarningFile)
	return err == nil
}

// GitAddDotSesam is equivalent to `git add .sesam`
func (v *View) GitAddDotSesam() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return ErrClosed
	}

	wt, err := v.gitRepo.Worktree()
	if err != nil {
		return err
	}

	// go-git addresses index paths relative to the worktree root, and .sesam may
	// sit in a subdirectory (nested layout), so relativize against it. Adding the
	// directory pulls in its untracked objects too.
	prefix, err := core.SesamGitPrefix(v.gitRepo, v.sesamDir)
	if err != nil {
		return err
	}

	return wt.AddWithOptions(&git.AddOptions{
		All:  false, // true would add all files and ignore the path.
		Path: path.Join(prefix, sesamSuffix),
	})
}

// Status computes a comparison between the revealed and sealed state.
func (v *View) Status(opts StatusOpts) (*Status, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	var status Status

	secretMap := make(map[string]*core.VerifiedSecret)
	for idx := range v.vstate.Secrets {
		secretMap[v.vstate.Secrets[idx].RevealedPath] = &v.vstate.Secrets[idx]
	}

	// Unresolved merge conflicts (text markers or binary .ours/.theirs) - git can't
	// see them, so flag the parent secret here (shown even without --all). The
	// binary set also hides the side files from the unmanaged listing below.
	conflictedSecrets, err := core.ConflictedSecrets(v.root, v.vstate.Secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to scan for merge conflicts: %w", err)
	}
	conflicted := make(map[string]bool, len(conflictedSecrets))
	binaryConflicts := make(map[string]bool)
	for _, c := range conflictedSecrets {
		conflicted[c.Path] = true
		if c.Binary {
			binaryConflicts[c.Path] = true
		}
	}

	if !opts.IgnoreUnmanaged {
		allPaths, err := v.cleanablePaths()
		if err != nil {
			return nil, fmt.Errorf("failed to list all paths: %w", err)
		}

		for _, path := range allPaths {
			if _, ok := secretMap[path]; ok {
				continue
			}
			// Hide the .ours/.theirs of a binary conflict; they belong to their
			// parent secret, which is reported as conflicted below.
			base, ok := strings.CutSuffix(path, ".ours")
			if !ok {
				base, ok = strings.CutSuffix(path, ".theirs")
			}
			if ok && binaryConflicts[base] {
				continue
			}
			secretMap[path] = nil
		}
	}

	for revealedPath, secret := range secretMap {
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
				AccessUsers:  v.vstate.UserForGroups(secret.AccessGroups),
			}

			sort.Strings(sff.AccessGroups)
			sort.Strings(sff.AccessUsers)
			status.Files = append(status.Files, sff)
		}

		if !v.vstate.UserHasAccess(v.whoami, secret.AccessGroups) {
			add(SecretStateUserHasNoAccess)
			continue
		}

		if _, err := v.root.Stat(revealedPath); err != nil {
			add(SecretStateNoRevealedPath)
			continue
		}

		if conflicted[revealedPath] {
			add(SecretStateConflicted)
			continue
		}

		sealedPath := v.secret.SealedPath(revealedPath)
		if _, err := v.root.Stat(sealedPath); err != nil {
			add(SecretStateNoSealedPath)
			continue
		}

		needsSeal, _, err := v.secret.NeedsSeal(revealedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to compare %s and %s: %w", revealedPath, sealedPath, err)
		}

		if needsSeal {
			add(SecretStateNotInSync)
		} else {
			add(SecretStateInSync)
		}
	}

	sort.Slice(status.Files, func(i, j int) bool {
		return status.Files[i].RevealedPath < status.Files[j].RevealedPath
	})

	if opts.WriteDiffDirs {
		tmpDir, err := v.statusToDiffDir(&status)
		if err != nil {
			return nil, err
		}
		status.DiffDir = tmpDir
	}

	return &status, nil
}

// expandSecretFiles resolves a sesam-relative path into the concrete regular
// files it represents. Directories are walked recursively, skipping the .git
// and .sesam metadata trees and sesam.yml. Returned paths are sesam-relative.
// Unlocked helper: callers hold v.mu.
func (v *View) expandSecretFiles(rel string) ([]string, error) {
	rel = filepath.Clean(rel)
	info, err := v.root.Stat(rel)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return []string{rel}, nil
	}

	var files []string
	err = fs.WalkDir(v.root.FS(), filepath.ToSlash(rel), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if name := d.Name(); name == gitSuffix || name == sesamSuffix {
				return fs.SkipDir
			}
			return nil
		}

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

// secretsUnder returns every managed secret at or beneath the sesam-relative
// path rel, enumerated from verified state.
func (v *View) secretsUnder(rel string) []core.VerifiedSecret {
	target := filepath.Clean(rel)

	var out []core.VerifiedSecret
	for _, s := range v.vstate.Secrets {
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

func (v *View) cleanablePaths() ([]string, error) {
	paths := []string{}
	err := cleanup(v.root, v.gitRepo, func(path string) (bool, error) {
		paths = append(paths, path)
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	return paths, nil
}

func (v *View) statusToDiffDir(status *Status) (diffDir string, err error) {
	// The diff tree is consumed by an external `git diff` process, so it is
	// built with absolute paths outside the root.
	rootTmpDir := filepath.Join(v.sesamDir, core.SesamTmpDir())
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

			if _, err := core.ShowSecret(v.root, v.identities, file.RevealedPath, sealFd); err != nil {
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
			desc := fmt.Sprintf("-- sesam: %s --", file.State.String())
			if err := renameio.WriteFile(plainTmpPath, []byte(desc), 0o600); err != nil {
				return "", fmt.Errorf("failed write revealed state file: %w", err)
			}
		case SecretStateInSync:
			// no need to write same files.
		default:
			if err := os.Link(filepath.Join(v.sesamDir, file.RevealedPath), plainTmpPath); err != nil {
				return "", fmt.Errorf("failed to link revealed file: %w", err)
			}
		}
	}

	return tmpDir, nil
}
