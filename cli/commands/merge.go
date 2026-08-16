package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

type ExitCodeError struct {
	err   error
	code  int
	print bool
}

func (e *ExitCodeError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d (no error)", e.code)
	}

	return fmt.Sprintf("exit %d: %s", e.code, e.err)
}

func (e *ExitCodeError) Print() bool {
	return e.print
}

func (e *ExitCodeError) Code() int {
	return e.code
}

func HandleMergeSecret(ctx context.Context, cmd *cli.Command) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	// %P is worktree-root-relative; git runs the driver from the worktree root,
	// so join it onto cwd to get an absolute path toRepoPath can rebase.
	pathArg := cmd.StringArg("path")
	if !filepath.IsAbs(pathArg) {
		pathArg = filepath.Join(cwd, pathArg)
	}

	revealedPath, err := toRepoPath(sesamDir, cwd, pathArg)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(revealedPath, ".sesam/objects/") {
		return fmt.Errorf("%%P needs to be a sesam object - gitattributes wrongly configured?")
	}

	// figure the revealed path from the object path:
	revealedPath = strings.TrimPrefix(revealedPath, ".sesam/objects/")
	revealedPath = strings.TrimSuffix(revealedPath, ".sesam")

	identityPaths := cmd.StringSlice("identity")
	ids, err := repo.LoadIdentities(identityPaths, repo.RepoOpts{
		AskpassProgram:  cmd.String("askpass"),
		AskpassRequired: askpassRequired(),
	})
	if err != nil {
		return err
	}

	root, rootErr := os.OpenRoot(sesamDir)
	if rootErr != nil {
		return rootErr
	}

	defer func() { _ = root.Close() }()

	originPath := cmd.StringArg("origin")
	ourPath := cmd.StringArg("our-path")
	theirPath := cmd.StringArg("their-path")
	conflictMarkerSize := cmd.IntArg("conflict-marker-size")

	conflicts, binary, err := repo.MergeSecret(
		ctx,
		root,
		ids,
		revealedPath,
		ourPath,
		theirPath,
		originPath,
		conflictMarkerSize,
	)
	if err != nil {
		return &ExitCodeError{
			err:   err,
			code:  129,
			print: true,
		}
	}

	slog.Debug(
		"merged successfully",
		slog.Int("conflicts", conflicts),
		slog.Bool("binary", binary),
		slog.String("path", revealedPath),
	)

	if binary {
		fmt.Fprintf(os.Stderr, "sesam: binary secret %s changed on both sides - cannot auto-merge; wrote %s.ours and %s.theirs.\n", revealedPath, revealedPath, revealedPath)
		fmt.Fprintf(os.Stderr, "sesam: copy the one you want over %s (and delete the .ours/.theirs), then commit.\n", revealedPath)
		return &ExitCodeError{err: nil, print: false, code: 1}
	}

	if conflicts > 0 {
		fmt.Fprintf(os.Stderr,
			"sesam: automatically merging revealed file %s; %d %s - please fix manually.\n",
			revealedPath, conflicts, pluralize("conflict", conflicts),
		)
		return &ExitCodeError{
			err:   nil,
			print: false,
			code:  (conflicts % 127) + 1,
		}
	}

	fmt.Fprintf(os.Stderr, "sesam: automatically merging revealed file %s; no conflicts\n", revealedPath)
	return nil
}

func HandleMergeAuditLog(ctx context.Context, cmd *cli.Command) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	// %P is worktree-root-relative; git runs the driver from the worktree root,
	// so join it onto cwd to get an absolute path toRepoPath can rebase.
	pathArg := cmd.StringArg("path")
	if !filepath.IsAbs(pathArg) {
		pathArg = filepath.Join(cwd, pathArg)
	}

	auditLogPath, err := toRepoPath(sesamDir, cwd, pathArg)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(auditLogPath, ".sesam/audit/log.jsonl") {
		return fmt.Errorf("%%P needs to be the audit log path but is %s %v - gitattributes wrongly configured?", pathArg, os.Args)
	}

	identityPaths := cmd.StringSlice("identity")
	ids, err := repo.LoadIdentities(identityPaths, repo.RepoOpts{
		AskpassProgram:  cmd.String("askpass"),
		AskpassRequired: askpassRequired(),
	})
	if err != nil {
		return err
	}

	root, rootErr := os.OpenRoot(sesamDir)
	if rootErr != nil {
		return rootErr
	}

	defer func() { _ = root.Close() }()

	originPath := cmd.StringArg("origin")
	ourPath := cmd.StringArg("our-path")
	theirPath := cmd.StringArg("their-path")
	conflictMarkerSize := cmd.IntArg("conflict-marker-size")

	cr, err := repo.MergeAuditLog(
		ctx,
		root,
		ids,
		ourPath,
		theirPath,
		originPath,
		conflictMarkerSize,
	)
	if err != nil {
		return &ExitCodeError{
			err:   err,
			code:  128,
			print: true,
		}
	}

	// Exit 0: the merged log is written to %A, so git treats this path as
	// resolved (no `git add` needed).
	//
	// Even though we exit without error here (which git would normally take as "continue with merge commit")
	// we rely on the pre-merge-commit hook to fail. This allows the user to handle conflicts he/she would have
	// resolved differently.
	fmt.Fprint(os.Stderr, mergeDriverSummary(cr.Resolutions))

	return nil
}

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
	b.WriteString("sesam: if you're unsure what any of this means, you can also abort the merge with `git merge --abort` and then `sesam reveal --all`\n")
	return b.String()
}
