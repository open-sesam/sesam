package commands

import (
	"fmt"
	"strings"

	"opensesam.org/sesam/core"
)

// mergeDecisionLines renders each noteworthy merge decision as a "- ..." bullet.
// Shared by the merge driver (live, during git merge) and `sesam log` (history)
// so both explain a semantic merge the same way.
func mergeDecisionLines(resolutions []core.ConflictResolutionEntry) []string {
	lines := make([]string, 0, len(resolutions))
	for i := range resolutions {
		lines = append(lines, "- "+mergeDecisionText(&resolutions[i]))
	}

	return lines
}

// mergeDecisionText is the one-line explanation for a single decision. The
// resolver already phrases Reason as a full sentence; fall back to the raw
// action/target only if it is somehow missing.
func mergeDecisionText(r *core.ConflictResolutionEntry) string {
	if r.Reason != "" {
		return r.Reason
	}
	if r.Target != "" {
		return fmt.Sprintf("%s %s", r.Action, r.Target)
	}

	return string(r.Action)
}

func mergeDriverSummary(resolutions []core.ConflictResolutionEntry) string {
	lines := mergeDecisionLines(resolutions)

	var b strings.Builder
	b.WriteString("sesam: both sides of the merge changed the audit log.\n")
	b.WriteString("sesam: the audit log was therefore semantically merged.\n")
	b.WriteString("sesam:\n")
	if len(lines) > 0 {
		b.WriteString("sesam: a list of automated decisions you might want to review follows:\n")
		for _, line := range lines {
			b.WriteString("sesam: " + line + "\n")
		}
	}

	b.WriteString("sesam:\n")
	b.WriteString("sesam: NOTE: git will tell you the merge failed below.\n")
	b.WriteString("sesam:       this is only to give you a chance to review the repo state before continuing to create a merge commit.\n")
	b.WriteString("sesam:\n")
	b.WriteString("sesam: please continue to resolve any conflicts mentioned above (if any) and then run `git commit`\n")
	b.WriteString("sesam: in case you don't have the git integration installed run `sesam hook pre-commit` directly.\n")

	return b.String()
}
