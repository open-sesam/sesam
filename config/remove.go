package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/goccy/go-yaml/ast"
)

// SecretRemove removes a single secret from the configuration.
//
// The matching secret entry is cut from whichever sesam.yml holds it (the main
// file or a subdirectory file). Any subdirectory sesam.yml left empty by the
// removal is deleted from disk and its include entry dropped from the parent
// file, cascading upward; the main file is never deleted.
//
// Only the config entry is removed; the referenced plaintext file is left on
// disk for the user to delete themselves. Directory expansion is the caller's
// job — SecretRemove only ever touches a single secret.
func (c *Config) SecretRemove(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve secret path %q: %w", path, err)
	}
	target := filepath.Clean(abs)

	entries, err := c.secretEntries()
	if err != nil {
		return err
	}

	var found *secretEntry
	for i := range entries {
		if filepath.Clean(revealedPath(entries[i])) == target {
			found = &entries[i]
			break
		}
	}

	if found == nil {
		return fmt.Errorf("no secret found for %q", path)
	}

	// Cut the secret's node from its source file's AST. Save only re-renders
	// the AST, so deleting the node is what makes the removal stick.
	if err := removeNode(found.source, found.node); err != nil {
		return err
	}

	// Delete any subdirectory file emptied by the removal (and the include
	// that points at it), cascading upward.
	return c.pruneEmptySources()
}

// revealedPath is the on-disk location of a secret's plaintext file: its Path
// is recorded relative to the directory of the sesam.yml that owns it.
func revealedPath(e secretEntry) string {
	return filepath.Join(filepath.Dir(e.source.Path), e.secret.Path)
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
func (c *Config) pruneEmptySources() error {
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
func (c *Config) deleteSource(path string) error {
	c.removeIncludeTo(path)
	delete(c.SourceFiles, path)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// removeIncludeTo cuts any include entry resolving to target from every loaded
// file, carrying its comment out with it.
func (c *Config) removeIncludeTo(target string) {
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
