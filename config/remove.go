package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml/ast"
)

// RemoveSecrets removes the secret(s) at path — a single file or a directory —
// from the configuration.
//
// For a single file the matching secret entry is removed from whichever
// sesam.yml holds it (the main file or a subdirectory file). For a directory
// every secret whose file lives in that directory or any subdirectory is
// removed. Any subdirectory sesam.yml left empty by the removal is deleted
// from disk and its include entry dropped from the parent file, cascading
// upward; the main file is never deleted.
//
// Only the config entries are removed; the referenced plaintext files are left
// on disk for the user to delete themselves.
//
// It returns the absolute on-disk paths of the secrets that were removed so the
// caller can mirror the change into the secret manager.
func (c *ConfigRepository) RemoveSecrets(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	target := filepath.Clean(path)

	entries, err := c.secretEntries()
	if err != nil {
		return nil, err
	}

	var removed []secretEntry
	for _, e := range entries {
		if matchesTarget(revealedPath(e), target, info.IsDir()) {
			removed = append(removed, e)
		}
	}

	if len(removed) == 0 {
		return nil, fmt.Errorf("no secrets found for %q", path)
	}

	removedPaths := make([]string, 0, len(removed))
	for _, e := range removed {
		removedPaths = append(removedPaths, revealedPath(e))
	}

	// Cut each removed secret's node from its source file's AST. Save only
	// re-renders the AST, so deleting the node is what makes the removal stick.
	for _, e := range removed {
		if err := removeNode(e.source, e.node); err != nil {
			return nil, err
		}
	}

	// Delete any subdirectory file emptied by the removal (and the include
	// that points at it), cascading upward.
	if err := c.pruneEmptySources(); err != nil {
		return nil, err
	}

	return removedPaths, nil
}

// revealedPath is the on-disk location of a secret's plaintext file: its Path
// is recorded relative to the directory of the sesam.yml that owns it.
func revealedPath(e secretEntry) string {
	return filepath.Join(filepath.Dir(e.source.Path), e.secret.Path)
}

// matchesTarget reports whether revealed (a secret's plaintext path) should be
// removed for the given target. A file target matches exactly; a directory
// target matches anything beneath it.
func matchesTarget(revealed, target string, targetIsDir bool) bool {
	revealed = filepath.Clean(revealed)
	if !targetIsDir {
		return revealed == target
	}

	rel, err := filepath.Rel(target, revealed)
	if err != nil {
		return false
	}

	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// removeNode cuts a single mapping node from a source file's secrets sequence,
// carrying its head comment out with it.
func removeNode(src *FileSource, node *ast.MappingNode) error {
	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return fmt.Errorf("%s: %w", src.Path, err)
	}

	idx := slices.IndexFunc(seq.Values, func(v ast.Node) bool {
		return v == ast.Node(node)
	})
	removeSeqValue(seq, idx)

	return nil
}

// pruneEmptySources deletes every subdirectory file left without any secrets
// or includes, dropping the include that points at it from its parent. It
// repeats until no further file empties out, so a chain of nested includes
// collapses in one call. The main file is never deleted.
func (c *ConfigRepository) pruneEmptySources() error {
	for {
		var emptied []string
		for path, src := range c.SourceFiles {
			if src == c.MainFile {
				continue
			}

			if isEmptySource(src) {
				emptied = append(emptied, path)
			}
		}

		if len(emptied) == 0 {
			return nil
		}

		for _, path := range emptied {
			if err := c.deleteSource(path); err != nil {
				return err
			}
		}
	}
}

// isEmptySource reports whether src no longer carries any secret or include
// entry and can therefore be deleted.
func isEmptySource(src *FileSource) bool {
	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return false
	}

	return len(seq.Values) == 0
}

// deleteSource removes the include pointing at path from any parent file,
// drops the file from the repository and deletes it from disk.
func (c *ConfigRepository) deleteSource(path string) error {
	c.removeIncludeTo(path)
	delete(c.SourceFiles, path)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// removeIncludeTo cuts any include entry resolving to target from every loaded
// file, carrying its comment out with it.
func (c *ConfigRepository) removeIncludeTo(target string) {
	target = filepath.Clean(target)

	for _, src := range c.SourceFiles {
		dir := filepath.Dir(src.Path)

		seq, err := secretsNode(src.RootNode)
		if err != nil {
			continue
		}

		for i := 0; i < len(seq.Values); {
			m, ok := seq.Values[i].(*ast.MappingNode)
			if ok {
				if inc, isInc := includePath(m); isInc && filepath.Clean(filepath.Join(dir, inc)) == target {
					removeSeqValue(seq, i)
					continue // a value shifted into slot i; re-check it
				}
			}
			i++
		}
	}
}
