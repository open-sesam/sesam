package config

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"

	"github.com/goccy/go-yaml/ast"
)

// SecretRemove removes a single secret from the configuration.
//
// The matching secret entry is cut from whichever sesam.yml holds it (the main
// file or a subdirectory file). Any subdirectory sesam.yml left empty by the
// removal is deleted from disk; the main file is never deleted.
func (c *Config) SecretRemove(path string) error {
	target := filepath.Clean(path)

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

	// Delete any subdirectory file emptied by the removal.
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

// Prune deletes every sub-config left without any secrets, for callers that
// build a config through Create rather than the mutators (which prune on
// their own).
func (c *Config) Prune() error {
	return c.pruneEmptySources()
}

// pruneEmptySources deletes every subdirectory file left without any secrets.
// The main file is never deleted.
func (c *Config) pruneEmptySources() error {
	for _, src := range c.sources() {
		if src == c.MainFile || !isEmptySource(src) {
			continue
		}

		if err := c.deleteSource(src.Path); err != nil {
			return err
		}
	}

	return nil
}

// isEmptySource reports whether src no longer carries any secret and can
// therefore be deleted. A file never given an item in memory counts as empty:
// whatever it held on disk has to go.
func isEmptySource(src *FileSource) bool {
	if src.RootNode == nil {
		return true
	}

	seq, err := secretsNode(src.RootNode)
	if err != nil {
		return false
	}

	return len(seq.Values) == 0
}

// deleteSource drops the file at path from the repository and deletes it from
// disk.
func (c *Config) deleteSource(path string) error {
	delete(c.SourceFiles, path)

	if err := c.root.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	c.deleted = append(c.deleted, path)

	return nil
}
