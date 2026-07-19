package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The cli layer is the only place that knows about the current working
// directory. User-supplied paths are translated into sesam-relative paths
// before they reach the repo API, and sesam-relative paths coming back are
// rendered relative to the cwd for display — mirroring how git behaves from a
// subdirectory.

// escapesRoot reports whether a sesam-relative path points outside the repo.
func escapesRoot(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// toRepoPath converts a user-supplied path into one relative to sesamDir.
//
//   - An absolute path is relativized against sesamDir directly.
//   - When the cwd is inside the sesam subtree, a relative path is resolved
//     against the cwd (so `add ./local` from sub/ becomes sub/local).
//   - When the cwd is outside the subtree (the user passed --sesam-dir from
//     above the repo), the path is treated as already sesam-relative.
func toRepoPath(sesamDir, cwd, arg string) (string, error) {
	if filepath.IsAbs(arg) {
		rel, err := filepath.Rel(sesamDir, filepath.Clean(arg))
		if err != nil || escapesRoot(rel) {
			return "", fmt.Errorf("path %q is outside the sesam dir %q", arg, sesamDir)
		}
		return rel, nil
	}

	cwdRel, err := filepath.Rel(sesamDir, cwd)
	if err != nil || escapesRoot(cwdRel) {
		// cwd is outside the subtree (or unrelatable): the path is already
		// sesam-relative.
		return filepath.Clean(arg), nil //nolint:nilerr // outside-subtree fallback, not an error
	}

	rel := filepath.Clean(filepath.Join(cwdRel, arg))
	if escapesRoot(rel) {
		return "", fmt.Errorf("path %q escapes the sesam dir %q", arg, sesamDir)
	}
	return rel, nil
}

// toRepoPaths translates a batch of user-supplied paths (see toRepoPath).
func toRepoPaths(sesamDir string, args []string) ([]string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	out := make([]string, 0, len(args))
	for _, a := range args {
		rel, err := toRepoPath(sesamDir, cwd, a)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

// displayPath renders a sesam-relative path for output. When the cwd is inside
// the sesam subtree the path is shown relative to the cwd (like git); when the
// cwd is outside it, the sesam-relative path is returned unchanged.
func displayPath(sesamDir, rel string) string {
	cwd, err := os.Getwd()
	if err != nil {
		return rel
	}
	return displayPathFrom(sesamDir, cwd, rel)
}

// displayPathFrom is displayPath with the cwd passed in, so the cwd-relative
// rendering can be tested without changing the process directory.
func displayPathFrom(sesamDir, cwd, rel string) string {
	cwdRel, err := filepath.Rel(sesamDir, cwd)
	if err != nil || escapesRoot(cwdRel) {
		return rel
	}

	shown, err := filepath.Rel(cwd, filepath.Join(sesamDir, rel))
	if err != nil {
		return rel
	}
	return shown
}

func dashify(s string) string {
	if len(s) == 0 {
		return "—"
	}

	return s
}
