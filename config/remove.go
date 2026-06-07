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
// The plaintext files referenced by the removed secrets are deleted from disk
// only when purge is true; otherwise just the config entries are removed.
func (c *ConfigRepository) RemoveSecrets(path string, purge bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	target := filepath.Clean(path)

	var kept, removed []Secret
	for _, s := range c.MainFile.Config.Secrets {
		if matchesTarget(c.revealedPath(s), target, info.IsDir()) {
			removed = append(removed, s)
		} else {
			kept = append(kept, s)
		}
	}

	if len(removed) == 0 {
		return fmt.Errorf("no secrets found for %q", path)
	}

	// Drop each removed secret's entry from its source file's AST. Save only
	// re-encodes the AST, so deleting the node is what makes the removal stick.
	for _, s := range removed {
		if s.node == nil {
			continue
		}

		if err := removeNode(s.Source, s.node); err != nil {
			return err
		}
	}

	c.MainFile.Config.Secrets = kept

	// Delete any subdirectory file emptied by the removal (and the include
	// that points at it), cascading upward.
	if err := c.pruneEmptySources(); err != nil {
		return err
	}

	if purge {
		for _, s := range removed {
			if err := os.Remove(c.revealedPath(s)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}

	return nil
}

// revealedPath is the on-disk location of a secret's plaintext file: its Path
// is recorded relative to the directory of the sesam.yml that owns it.
func (c *ConfigRepository) revealedPath(s Secret) string {
	return filepath.Join(filepath.Dir(s.Source.Path), s.Path)
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

// removeNode deletes a single mapping node from a source file's secrets
// sequence.
func removeNode(src *FileSource, node *ast.MappingNode) error {
	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return fmt.Errorf("%s: %w", src.Path, err)
	}

	seq.Values = slices.DeleteFunc(seq.Values, func(v ast.Node) bool {
		return v == ast.Node(node)
	})

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
	if len(src.NewIncludes) > 0 {
		return false
	}

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

// removeIncludeTo drops any include entry resolving to target from every
// loaded file (AST entries and queued includes alike).
func (c *ConfigRepository) removeIncludeTo(target string) {
	target = filepath.Clean(target)

	for _, src := range c.SourceFiles {
		dir := filepath.Dir(src.Path)

		if seq, err := secretsNode(src.RootNode); err == nil {
			seq.Values = slices.DeleteFunc(seq.Values, func(v ast.Node) bool {
				m, ok := v.(*ast.MappingNode)
				if !ok {
					return false
				}

				inc, ok := includePath(m)
				return ok && filepath.Clean(filepath.Join(dir, inc)) == target
			})
		}

		src.NewIncludes = slices.DeleteFunc(src.NewIncludes, func(inc string) bool {
			return filepath.Clean(filepath.Join(dir, inc)) == target
		})
	}
}
