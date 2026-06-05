package cli

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
)

// pseudoVersion matches the timestamp-and-revision tail the Go toolchain puts
// into Main.Version for untagged builds (e.g. 0.0.0-20260605162431-50d585884077).
var pseudoVersion = regexp.MustCompile(`[0-9]{14}-[0-9a-f]{12}`)

// describeAhead matches the "N commits past the tag" suffix that `git describe`
// appends, e.g. the "-5-gae27c29" in "v0.1.2-5-gae27c29".
var describeAhead = regexp.MustCompile(`-(\d+)-g[0-9a-f]+$`)

// bareHash matches a plain abbreviated commit hash, i.e. the
// `git describe --always` fallback emitted when no tag is reachable.
var bareHash = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// Build metadata. These are injected at release time via the linker, e.g.
// See Taskfile.yml.
//
// When left empty (a plain `go build`), they fall back to the VCS stamps the
// Go toolchain embeds automatically via runtime/debug.
var (
	version = ""
)

// buildInfo is the resolved, display-ready build metadata.
type buildInfo struct {
	Version   string // without a leading "v"
	Commit    string // short git revision
	Date      string // YYYY-MM-DD
	Year      string // copyright year, derived from Date
	IsDirty   bool   // build with non-empty git diff?
	GoVersion string // build with what go version?
}

// isReleaseVersion reports whether v looks like a real release tag rather than
// "(devel)", an empty string, or a module pseudo-version.
func isReleaseVersion(v string) bool {
	if v == "" || v == "(devel)" {
		return false
	}

	return !pseudoVersion.MatchString(v)
}

// normalizeVersion turns a raw version source (a linker-injected `git describe`
// string, or runtime/debug's Main.Version) into the displayed version:
//
//	v0.1.2             -> 0.1.2         (built exactly on a tag)
//	v0.1.2-5-gae27c29  -> 0.1.2-dev+5   (5 commits past the last tag)
//	ae27c29            -> ""            (no tag reachable; caller falls back)
//	""                 -> ""
//
// A trailing "-dirty" is dropped; dirtiness is surfaced separately in the
// banner via buildInfo.IsDirty.
func normalizeVersion(raw string) string {
	raw = strings.TrimSuffix(raw, "-dirty")
	if raw == "" {
		return ""
	}

	if m := describeAhead.FindStringSubmatch(raw); m != nil {
		base := strings.TrimPrefix(raw[:len(raw)-len(m[0])], "v")
		return base + "-dev+" + m[1]
	}

	if bareHash.MatchString(raw) {
		// `--always` fell back to a bare hash: no tag exists yet.
		return ""
	}

	return strings.TrimPrefix(raw, "v")
}

// resolveBuildInfo merges the linker-injected values with the VCS information
// embedded by the Go toolchain, filling in sane defaults for anything missing.
func resolveBuildInfo() buildInfo {
	v, c, d := normalizeVersion(version), "", ""
	var goVersion string
	var isDirty bool

	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion

		// Only trust Main.Version when it is a real release tag: a plain
		// `go build` reports "(devel)" or a pseudo-version, neither of which
		// is a tag we want to show.
		if v == "" && isReleaseVersion(bi.Main.Version) {
			v = normalizeVersion(bi.Main.Version)
		}

		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				d = s.Value
			case "vcs.modified":
				isDirty = s.Value == "true"
			}
		}
	}

	// We have no real tag yet, so fall back to 0.0.0.
	if v == "" {
		v = "0.0.0"
	}

	if c == "" {
		c = "unknown"
	} else if len(c) > 9 {
		c = c[:9]
	}

	if d == "" {
		d = "unknown"
	} else if len(d) >= 10 {
		// Trim an RFC3339 timestamp (vcs.time) down to the date.
		d = d[:10]
	}

	year := "unknown"
	if len(d) >= 4 && d != "unknown" {
		year = d[:4]
	}

	return buildInfo{
		Version:   v,
		Commit:    c,
		Date:      d,
		Year:      year,
		GoVersion: goVersion,
		IsDirty:   isDirty,
	}
}

const copyrightStart = "2026"

func (b buildInfo) copyrightYears() string {
	if b.Year == "" || b.Year == "unknown" || b.Year <= copyrightStart {
		return copyrightStart
	}

	return copyrightStart + "-" + b.Year
}

// String renders the version banner, e.g.
func (b buildInfo) String() string {
	dirtySuffix := ""
	if b.IsDirty {
		dirtySuffix = "-dirty"
	}

	return fmt.Sprintf(
		"%s [%s%s] (%s, %s) © %s Chris Pahl and contributors",
		b.Version,
		b.Commit,
		dirtySuffix,
		b.Date,
		b.GoVersion,
		b.copyrightYears(),
	)
}
