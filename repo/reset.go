package repo

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	sesamConf "opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/diff"
)

// ConfigResetOpts controls how a reset behaves.
type ConfigResetOpts struct {
	// DryRun reports what a reset would do and leaves every file as it is.
	// The work still happens - on a throwaway copy of the config tree - so
	// what comes back is the real outcome, not a prediction of one.
	DryRun bool
}

// ConfigReset reports what resetting sesam.yml did, or would do for a dry run.
type ConfigReset struct {
	// Discarded are the changes the config declared on top of the audit log,
	// i.e. the hand edits that were thrown away. Empty when the two agreed.
	Discarded []diff.Change `json:"discarded"`

	// Rewritten is set when sesam.yml could not be reused and was written from
	// scratch, losing its comments and descriptions. Reason says why.
	Rewritten bool   `json:"rewritten"`
	Reason    string `json:"reason,omitempty"`

	// Orphaned are config files still on disk that the rewritten sesam.yml no
	// longer includes. They are left alone - deleting a user's file is not
	// reset's call - but nothing reads them any more, so they are reported.
	Orphaned []string `json:"orphaned,omitempty"`

	// DryRun echoes the option back, so a caller handed only this result knows
	// whether any of it reached disk.
	DryRun bool `json:"dry_run,omitempty"`
}

// ConfigReset rewrites sesam.yml to describe the verified state, discarding
// whatever the file declared on top of it. The audit log is the source and is
// never touched - this is the opposite direction of `sesam config apply`.
//
// Wherever possible the existing file is edited rather than replaced, so only
// the lines that disagree with the audit log change and comments, descriptions,
// anchors and the include structure survive. A file that cannot be read at all
// is written fresh from the audit log instead, which is the case reset exists
// for: recovering from an edit that broke the config.
func (r *Repo) ConfigReset(opts ConfigResetOpts) (*ConfigReset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	// A dry run rehearses on a copy: the same code runs, Save still validates
	// what it would write, and the live tree is out of reach of the config
	// mutators - which do delete a sub-file their last secret left empty.
	root := r.root
	if opts.DryRun {
		scratch, cleanup, err := r.scratchConfigTree()
		if err != nil {
			return nil, err
		}
		defer cleanup()

		root = scratch
	}

	out := &ConfigReset{DryRun: opts.DryRun}

	cfg, err := r.resetConfig(root, out)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		// Already in sync, so there is nothing to write.
		return out, nil
	}

	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	if out.Rewritten {
		// A rewrite flattens everything into the main file, so any sub-config
		// that used to be included is now unreferenced.
		orphans, err := r.orphanedConfigs(cfg)
		if err != nil {
			return nil, err
		}
		out.Orphaned = orphans
	}

	if !opts.DryRun {
		// The cached view would still hold the pre-reset file.
		r.config = nil
	}

	slog.Debug(
		"config reset",
		slog.Int("discarded", len(out.Discarded)),
		slog.Bool("rewritten", out.Rewritten),
		slog.Bool("dry_run", opts.DryRun),
	)

	return out, nil
}

// resetConfig returns the config to write, filling in what had to be done to
// get there. A nil config means the declaration already matched the audit log.
func (r *Repo) resetConfig(root *os.Root, out *ConfigReset) (*sesamConf.Config, error) {
	cfg, err := sesamConf.Load(root, configFileName)
	if err != nil {
		// Unreadable, invalid or simply gone - there is nothing to edit, so
		// build the file from the audit log.
		out.Rewritten = true
		out.Reason = err.Error()

		return r.rebuildConfig(root)
	}

	declared, err := cfg.State()
	if err != nil {
		// The file parses but does not describe a state (a path escaping the
		// repo, a name declared twice), so it cannot be edited either.
		out.Rewritten = true
		out.Reason = err.Error()

		return r.rebuildConfig(root)
	}

	// Delta, not Compute: a config that lost its last admin is not appliable,
	// and is exactly the one that needs resetting.
	changes := diff.Delta(r.vstate, declared)
	out.Discarded = changes.Changes

	if changes.IsEmpty() {
		return nil, nil
	}

	if err := diff.Revert(cfg, r.vstate, changes); err != nil {
		return nil, fmt.Errorf("rewrite config from audit log: %w", err)
	}

	return cfg, nil
}

// rebuildConfig builds a complete config from the verified state alone, used
// when the file on disk cannot serve as a starting point. Users come first so
// the groups they belong to exist before any secret refers to them; both are
// written in a stable order.
func (r *Repo) rebuildConfig(root *os.Root) (*sesamConf.Config, error) {
	cfg, err := sesamConf.Create(root, configFileName)
	if err != nil {
		return nil, fmt.Errorf("create config: %w", err)
	}

	users := slices.Clone(r.vstate.Users)
	slices.SortFunc(users, func(a, b core.VerifiedUser) int {
		return strings.Compare(a.Name, b.Name)
	})

	for _, user := range users {
		if err := cfg.UserTell(user.Name, user.Recps.Specs(), user.Groups); err != nil {
			return nil, fmt.Errorf("declare user %q: %w", user.Name, err)
		}
	}

	secrets := slices.Clone(r.vstate.Secrets)
	slices.SortFunc(secrets, func(a, b core.VerifiedSecret) int {
		return strings.Compare(a.RevealedPath, b.RevealedPath)
	})

	for _, secret := range secrets {
		if err := cfg.SecretAdd(secret.RevealedPath, false, secret.DeclaredGroups()); err != nil {
			return nil, fmt.Errorf("declare secret %q: %w", secret.RevealedPath, err)
		}
	}

	return cfg, nil
}

// scratchConfigTree copies every config file in the repository into a
// throwaway directory and returns a root for it. The returned func removes the
// copy again.
func (r *Repo) scratchConfigTree() (root *os.Root, cleanup func(), err error) {
	tmpDir, err := os.MkdirTemp(filepath.Join(r.sesamDir, core.SesamTmpDir()), "config-reset-")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to make temp dir for dry run: %w", err)
	}

	// A local, not the named return: that one is reassigned by the return
	// statement below, and the closure would end up calling itself.
	removeTmp := func() { _ = os.RemoveAll(tmpDir) }
	defer func() {
		if err != nil {
			removeTmp()
		}
	}()

	paths, err := r.configPaths()
	if err != nil {
		return nil, nil, err
	}

	for _, path := range paths {
		data, err := r.root.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}

		dst := filepath.Join(tmpDir, path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, nil, fmt.Errorf("make dir for %s: %w", dst, err)
		}

		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, nil, fmt.Errorf("write %s: %w", dst, err)
		}
	}

	scratch, err := os.OpenRoot(tmpDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", tmpDir, err)
	}

	return scratch, func() {
		_ = scratch.Close()
		removeTmp()
	}, nil
}

// configPaths lists every config file in the repository, wherever it sits in
// the include tree - and including ones no file includes at all.
func (v *View) configPaths() ([]string, error) {
	var paths []string

	err := fs.WalkDir(v.root.FS(), ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel := filepath.FromSlash(p)
		if entry.IsDir() {
			switch rel {
			case sesamSuffix, gitSuffix, forkSuffix:
				return fs.SkipDir
			}
			return nil
		}

		if filepath.Base(rel) == configFileName {
			paths = append(paths, rel)
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan for config files: %w", err)
	}

	return paths, nil
}

// orphanedConfigs lists config files under the repository that cfg does not
// reference. A config nobody includes is silently ignored, which is worth
// saying out loud after a rewrite flattened the include tree away.
func (r *Repo) orphanedConfigs(cfg *sesamConf.Config) ([]string, error) {
	paths, err := r.configPaths()
	if err != nil {
		return nil, err
	}

	var orphans []string
	for _, path := range paths {
		if _, referenced := cfg.SourceFiles[path]; !referenced {
			orphans = append(orphans, path)
		}
	}

	return orphans, nil
}
