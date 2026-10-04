package util

import (
	"slices"

	"opensesam.org/sesam/core"
)

// WithAdmin adds the implicit "admin" group, so an access list can be compared
// against one the audit log recorded, where it is always spelled out.
func WithAdmin(groups []string) []string {
	if slices.Contains(groups, "admin") {
		return SortedSet(groups)
	}

	return SortedSet(append(slices.Clone(groups), "admin"))
}

// SortedSet returns s sorted with duplicates removed. The result is never nil,
// so an absent set and an empty one render the same - unlike core.Deduplicate,
// which this wraps.
func SortedSet(s []string) []string {
	if out := core.Deduplicate(s); out != nil {
		return out
	}

	return []string{}
}
