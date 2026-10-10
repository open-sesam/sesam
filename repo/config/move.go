package config

import (
	"fmt"
	"path/filepath"
)

// SecretMove relocates a single tracked secret from oldPath to newPath,
// preserving its access groups and any other metadata. nested controls the
// layout of the secret at its destination, exactly as in SecretAdd.
//
// The old entry is cut from its owning file (emptied subdirectory files are
// pruned) and a fresh entry is placed for the new location. Directory
// expansion is the caller's job — SecretMove only ever touches one secret.
func (c *Config) SecretMove(oldPath, newPath string, nested bool) error {
	oldRel := filepath.Clean(oldPath)
	newRel := filepath.Clean(newPath)

	entries, err := c.secretEntries()
	if err != nil {
		return err
	}

	var found *secretEntry
	for i := range entries {
		if filepath.Clean(revealedPath(entries[i])) == oldRel {
			found = &entries[i]
			break
		}
	}

	if found == nil {
		return fmt.Errorf("no secret found for %q", oldPath)
	}

	// Preserve the secret's metadata; placeSecret recomputes Path for the
	// destination relative to its owning file.
	sec := found.secret
	sec.Path = ""

	if err := removeNode(found.source, found.node); err != nil {
		return err
	}

	if err := c.placeSecret(newRel, nested, sec); err != nil {
		return err
	}

	return c.pruneEmptySources()
}
