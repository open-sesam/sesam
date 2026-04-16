package core

import (
	"cmp"
	"io"
	"log/slog"
	"slices"
)

// Deduplicate returns a sorted copy of s with duplicates removed.
func deduplicate[T cmp.Ordered](s []T) []T {
	c := slices.Clone(s)
	slices.Sort(c)
	return slices.Compact(c)
}

func closeLogged(fd io.Closer) {
	if err := fd.Close(); err != nil {
		slog.Warn(
			"failed to close descriptor",
			slog.Any("err", err),
			slog.Any("fd", fd),
		)
	}
}
