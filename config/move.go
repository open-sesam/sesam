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
	oldAbs, err := filepath.Abs(oldPath)
	if err != nil {
		return fmt.Errorf("failed to resolve secret path %q: %w", oldPath, err)
	}
	newAbs, err := filepath.Abs(newPath)
	if err != nil {
		return fmt.Errorf("failed to resolve secret path %q: %w", newPath, err)
	}
	oldAbs = filepath.Clean(oldAbs)
	newAbs = filepath.Clean(newAbs)

	entries, err := c.secretEntries()
	if err != nil {
		return err
	}

	var found *secretEntry
	for i := range entries {
		if filepath.Clean(revealedPath(entries[i])) == oldAbs {
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

	if err := c.placeSecret(newAbs, nested, sec); err != nil {
		return err
	}

	return c.pruneEmptySources()
}
