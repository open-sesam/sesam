package util

import "slices"

// WithoutAdmin drops the implicit "admin" group, which every secret carries
// whether or not the config spells it out.
func WithoutAdmin(groups []string) []string {
	return slices.DeleteFunc(slices.Clone(groups), func(g string) bool {
		return g == "admin"
	})
}

// SortedSet returns s sorted with duplicates removed. The result is never nil,
// so an absent set and an empty one render the same.
func SortedSet(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}

	return slices.Compact(slices.Sorted(slices.Values(s)))
}
