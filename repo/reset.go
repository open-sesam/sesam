package repo

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"opensesam.org/sesam/core"
	sesamConf "opensesam.org/sesam/repo/config"
	"opensesam.org/sesam/repo/diff"
)

// ConfigResetOpts controls how a reset behaves.
type ConfigResetOpts struct {
	// Force allows rewriting sesam.yml from scratch when it cannot be
	// repaired in place, discarding its comments and descriptions.
	Force bool
}

// ConfigReset reports what resetting sesam.yml did, or would do without
// Force.
type ConfigReset struct {
	// Discarded are the changes the config declared on top of the audit log,
	// i.e. the hand edits that were thrown away. Empty when the two agreed.
	Discarded []diff.Change `json:"discarded"`

	// Rewritten is set when sesam.yml could not be reused and was written from scratch
	// losing its comments and descriptions. Reason says why.
	Rewritten bool   `json:"rewritten"`
	Reason    string `json:"reason,omitempty"`

	// Orphaned are config files still on disk that the rewritten sesam.yml no
	// longer includes. Not deleted but reported.
	Orphaned []string `json:"orphaned,omitempty"`

	// Deleted are sub-config files the repair-in-place path removed from disk
	Deleted []string `json:"deleted,omitempty"`
}

// ConfigReset rewrites sesam.yml to describe the verified state, discarding
// whatever the file declared on top of it. The audit log is the source and is
// never touched - this is the opposite direction of `sesam config apply`.
func (r *Repo) ConfigReset(opts ConfigResetOpts) (*ConfigReset, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.isClosed() {
		return nil, ErrClosed
	}

	out := &ConfigReset{}
	cfg, err := r.resetConfig(r.root, out)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		// Already in sync, so there is nothing to write.
		return out, nil
	}

	if out.Rewritten {
		// A rewrite flattens everything into the main file, so any sub-config
		// that used to be included is now unreferenced - true whether or not
		// Force lets the rewrite actually reach disk.
		orphans, err := r.orphanedConfigs(cfg)
		if err != nil {
			return nil, err
		}
		out.Orphaned = orphans

		if !opts.Force {
			// rebuildConfig only ever builds cfg in memory, so nothing has
			// reached disk yet - safe to stop here and just report it.
			return out, nil
		}
	}

	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	// A revert (the repair-in-place path) can prune a declared secret out of
	// a sub-config and leave it empty; the config mutators delete such a file
	// outright rather than leaving it orphaned. That must not happen without
	// a trace either.
	out.Deleted = cfg.Deleted()

	// The cached view would still hold the pre-reset file.
	r.config = nil

	slog.Debug(
		"config reset",
		slog.Int("discarded", len(out.Discarded)),
		slog.Bool("rewritten", out.Rewritten),
		slog.Int("orphaned", len(out.Orphaned)),
		slog.Int("deleted", len(out.Deleted)),
		slog.Bool("force", opts.Force),
	)

	return out, nil
}

// resetConfig returns the config to write, filling in what had to be done to
// get there. A nil config means the declaration already matched the audit log.
func (r *Repo) resetConfig(root *os.Root, out *ConfigReset) (*sesamConf.Config, error) {
	cfg, err := sesamConf.LoadForRepair(root, configFileName)
	if err != nil {
		// Unreadable, invalid structure, or simply gone - there is nothing to
		// edit, so the file can only be built fresh from the audit log.
		return r.rewriteConfig(root, out, err)
	}

	declared, err := cfg.State()
	if err != nil {
		// The file parses but does not describe a state (a path escaping the
		// repo, a name declared twice), so it cannot be edited either.
		return r.rewriteConfig(root, out, err)
	}

	changes := diff.Delta(r.vstate, declared)
	out.Discarded = changes.Changes

	if !changes.IsEmpty() {
		if err := diff.Revert(cfg, r.vstate, changes); err != nil {
			// A mutator choked on the file's own shape (e.g. a missing
			// groups: key no fallback handles, or an alias-valued member none
			// of them resolve) - fall back rather than fail the whole reset.
			return r.rewriteConfig(root, out, err)
		}
	}

	// LoadForRepair skipped Validate()'s referential checks on the premise
	// that reverting the diff above might fix exactly what they'd complain
	// about. Confirm that actually happened (or that there was nothing to fix
	// in the first place)
	if err := cfg.Validate(); err != nil {
		return r.rewriteConfig(root, out, err)
	}

	if changes.IsEmpty() {
		return nil, nil //nolint:nilnil // nil config means config fits audit log (no error and nothing to reset)
	}

	return cfg, nil
}

// rewriteConfig records why the file has to be replaced and builds the
// replacement. Whether that replacement reaches disk is entirely down to
// which root the caller resolved: rewriteConfig itself never refuses, since
// ConfigReset already routed a non-Force call to a throwaway copy.
func (r *Repo) rewriteConfig(root *os.Root, out *ConfigReset, cause error) (*sesamConf.Config, error) {
	out.Rewritten = true
	out.Reason = cause.Error()

	return r.rebuildConfig(root)
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
	slices.SortFunc(secrets, func(a, b core.SecretAccess) int {
		return strings.Compare(a.RevealedPath, b.RevealedPath)
	})

	for _, secret := range secrets {
		if err := cfg.SecretAdd(secret.RevealedPath, false, secret.DeclaredGroups()); err != nil {
			return nil, fmt.Errorf("declare secret %q: %w", secret.RevealedPath, err)
		}
	}

	// SecretAdd never runs when there are no secrets, so the key would
	// otherwise be missing entirely
	if err := cfg.EnsureSecretsKey(); err != nil {
		return nil, fmt.Errorf("ensure secrets key: %w", err)
	}

	return cfg, nil
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
			switch entry.Name() {
			case sesamSuffix, gitSuffix, forkSuffix:
				return fs.SkipDir
			}
			return nil
		}

		if entry.Name() == configFileName {
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
