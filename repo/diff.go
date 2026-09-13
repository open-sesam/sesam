package repo

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	sesamConf "opensesam.org/sesam/config"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/diff"
)

// Names of the two config trees written into a diff dir. They double as the
// labels `git diff` prints, so they read as the two states being compared, and
// are exported because the caller has to name them when invoking the differ.
const (
	VerifiedTreeDir = "verified"
	DeclaredTreeDir = "declared"
)

// ConfigDiffOpts controls what ConfigDiff produces besides the change list.
type ConfigDiffOpts struct {
	// WriteDiffDir materializes the two config trees to compare (see
	// ConfigDiff.DiffDir). Skipped when the states already agree.
	WriteDiffDir bool
}

// ConfigDiff is the difference between sesam.yml and the audit log
type ConfigDiff struct {
	// Changes are the steps that would bring the audit log in line with
	// sesam.yml - what `sesam config apply` would carry out.
	Changes []diff.Change `json:"changes"`

	// DiffDir holds a "verified" and a "declared" copy of the config tree,
	// ready to be handed to `git diff`. Empty unless WriteDiffDir was set and
	// there is something to show. The caller owns the directory and must
	// remove it.
	DiffDir string `json:"diff_dir,omitempty"`
}

// IsEmpty reports whether sesam.yml and the audit log agree.
func (cd *ConfigDiff) IsEmpty() bool {
	return len(cd.Changes) == 0
}

// String renders the difference as one plain line per change.
func (cd *ConfigDiff) String() string {
	return (&diff.Diff{Changes: cd.Changes}).String()
}

// ConfigDiff compares the state declared in sesam.yml against the verified
// state replayed from the audit log.
func (v *View) ConfigDiff(opts ConfigDiffOpts) (*ConfigDiff, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.isClosed() {
		return nil, ErrClosed
	}

	return v.configDiff(opts)
}

// configDiff is the lock-free body of ConfigDiff, also used by apply, which
// holds the lock across the whole transaction.
func (v *View) configDiff(opts ConfigDiffOpts) (*ConfigDiff, error) {
	// Read sesam.yml fresh rather than through the cached view: the whole
	// point of the diff is to answer what the file says *now*, and the user
	// may well have edited it since this repo was opened.
	cfg, err := sesamConf.Load(v.root, configFileName)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	declared, err := cfg.State()
	if err != nil {
		return nil, fmt.Errorf("declared state: %w", err)
	}

	changes, err := diff.Compute(v.vstate, declared)
	if err != nil {
		return nil, err
	}

	out := &ConfigDiff{Changes: changes.Changes}
	if !opts.WriteDiffDir || changes.IsEmpty() {
		return out, nil
	}

	dir, err := v.writeConfigDiffDir(cfg, changes)
	if err != nil {
		return nil, err
	}
	out.DiffDir = dir

	return out, nil
}

// writeConfigDiffDir materializes the two sides of the diff as two copies of
// the whole config tree (the main file plus every included one): "declared" as
// the user wrote it, and "verified" with the declared changes backed out.
func (v *View) writeConfigDiffDir(cfg *sesamConf.Config, changes *diff.Diff) (dir string, err error) {
	// The tree is consumed by an external `git diff` process, so it is built
	// with absolute paths outside the root.
	tmpDir, err := os.MkdirTemp(filepath.Join(v.sesamDir, core.SesamTmpDir()), "config-diff-")
	if err != nil {
		return "", fmt.Errorf("failed to make temp dir for diff: %w", err)
	}

	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	// Sorted, so the copy order does not depend on map iteration.
	paths := slices.Sorted(maps.Keys(cfg.SourceFiles))

	declaredCfg, declaredClose, err := v.copyConfigTree(tmpDir, DeclaredTreeDir, paths)
	if err != nil {
		return "", err
	}
	defer declaredClose()

	verifiedCfg, verifiedClose, err := v.copyConfigTree(tmpDir, VerifiedTreeDir, paths)
	if err != nil {
		return "", err
	}
	defer verifiedClose()

	if err := declaredCfg.Save(); err != nil {
		return "", fmt.Errorf("render declared config: %w", err)
	}

	if err := diff.Revert(verifiedCfg, v.vstate, changes); err != nil {
		return "", err
	}

	if err := verifiedCfg.Save(); err != nil {
		return "", fmt.Errorf("render verified config: %w", err)
	}

	return tmpDir, nil
}

// copyConfigTree copies the given config files into <tmpDir>/<name> and loads
// the copy, so every later edit and render stays inside the throwaway tree.
// The returned func closes the copy's root.
func (v *View) copyConfigTree(
	tmpDir, name string,
	paths []string,
) (cfg *sesamConf.Config, closeRoot func(), err error) {
	treeDir := filepath.Join(tmpDir, name)

	for _, path := range paths {
		data, err := v.root.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, err)
		}

		dst := filepath.Join(treeDir, path)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, nil, fmt.Errorf("make dir for %s: %w", dst, err)
		}

		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return nil, nil, fmt.Errorf("write %s: %w", dst, err)
		}
	}

	root, err := os.OpenRoot(treeDir)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", treeDir, err)
	}

	cfg, err = sesamConf.Load(root, configFileName)
	if err != nil {
		_ = root.Close()
		return nil, nil, fmt.Errorf("load %s config copy: %w", name, err)
	}

	return cfg, func() { _ = root.Close() }, nil
}
