package config

import (
	"fmt"
	"path/filepath"

	"github.com/goccy/go-yaml/ast"
)

// SecretChangeGroups replaces the access groups of an already-tracked secret.
// It errors if no secret for path is declared in any loaded file.
func (c *Config) SecretChangeGroups(path string, access []string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("failed to resolve secret path %q: %w", path, err)
	}

	return c.changeSecretGroups(filepath.Clean(abs), access)
}

// changeSecretGroups finds the secret whose revealed path equals abs (already
// cleaned & absolute) and rewrites its access list in place.
func (c *Config) changeSecretGroups(abs string, access []string) error {
	entries, err := c.secretEntries()
	if err != nil {
		return err
	}

	for _, e := range entries {
		if filepath.Clean(revealedPath(e)) == abs {
			return setSecretAccess(e.node, access)
		}
	}

	return fmt.Errorf("no secret found for %q", abs)
}

// setSecretAccess replaces (or adds, when absent) the access: list of a single
// secret mapping node. Replacing in place via MappingValueNode.Replace keeps
// the node's other keys and attached comments intact and re-aligns the new
// sequence's indentation to the existing value's column.
func setSecretAccess(node *ast.MappingNode, access []string) error {
	if mv := findMappingValue(node, "access"); mv != nil {
		newSeq, err := marshalSeq(access)
		if err != nil {
			return fmt.Errorf("failed to build access list: %w", err)
		}

		return mv.Replace(newSeq)
	}

	// Secret had no access: key yet — add the whole key/value pair.
	m, err := marshalMapping(map[string][]string{"access": access})
	if err != nil {
		return fmt.Errorf("failed to build access list: %w", err)
	}

	node.Merge(m)
	return nil
}
