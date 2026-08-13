package core

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

// conflictMarkerMin is the minimum run length of a git conflict marker. git's
// default marker size is 7; a custom size (git's %L) is always >= 7, so requiring
// at least 7 never misses a real marker.
const conflictMarkerMin = 7

// hasConflictMarkers reports whether r contains an unresolved git conflict: both
// a start line ("<<<<<<< …") and an end line (">>>>>>> …"). Requiring the pair
// (rather than a lone "=======") keeps false positives off files that
// legitimately contain separator lines.
func hasConflictMarkers(r io.Reader) (bool, error) {
	var sawStart, sawEnd bool

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		switch {
		case isMarkerLine(line, '<'):
			sawStart = true
		case isMarkerLine(line, '>'):
			sawEnd = true
		}

		if sawStart && sawEnd {
			return true, nil
		}
	}

	return false, sc.Err()
}

// isMarkerLine reports whether line begins with >= conflictMarkerMin copies of c
// followed by a space or end of line - i.e. "<<<<<<< label" or ">>>>>>>".
func isMarkerLine(line []byte, c byte) bool {
	n := 0
	for n < len(line) && line[n] == c {
		n++
	}

	if n < conflictMarkerMin {
		return false
	}

	return n == len(line) || line[n] == ' '
}

// ConflictedSecrets returns the revealed paths whose plaintext still carries git
// conflict markers left by the secret merge driver. Sealing such a file would
// encrypt the markers into the object - and revealed files are gitignored, so git
// itself never flags them - so the merge finalize must refuse until they are
// resolved.
func ConflictedSecrets(root *os.Root, secrets []VerifiedSecret) ([]string, error) {
	var conflicted []string
	for _, s := range secrets {
		fd, err := root.Open(s.RevealedPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Not revealed on disk - nothing to seal, nothing to check.
				continue
			}
			return nil, fmt.Errorf("open revealed %s: %w", s.RevealedPath, err)
		}

		has, err := hasConflictMarkers(fd)
		_ = fd.Close()
		if err != nil {
			return nil, fmt.Errorf("scan revealed %s: %w", s.RevealedPath, err)
		}

		if has {
			conflicted = append(conflicted, s.RevealedPath)
		}
	}

	return conflicted, nil
}
