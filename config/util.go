package config

import "path/filepath"

// sameDir reports whether a and b refer to the same directory.
func sameDir(a, b string) bool {
	rel, err := filepath.Rel(a, b)
	return err == nil && rel == "."
}
