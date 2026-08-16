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
	// # find out full revealed path from git tracked path
	// revealed = map_tracked_to_revealed(%P)
	// require_key() else {
	//     # side effect: only admins may merge:
	//     stderr("cannot decrypt %P: no key")
	//     # user should git merge --abort and ask an admin.
	//     exit 1
	// }
	// o,a,b   = decrypt(%O), decrypt(%A), decrypt(%B)
	// merged, clean = three_way_text_merge(o, a, b)
	// # If there are conflicts, tell the user - print something here.
	// write(revealed, clean ? merged : merged_with_markers) # %A left as ours ciphertext (valid blob); real seal deferred to pre-commit
	// exit clean ? 0 : 1

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

	conflicts, err := repo.MergeSecret(
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
		slog.String("path", revealedPath),
	)

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
	// # replay theirs onto ours, admin re-signs.
	// # Try our very best to produce a coherent audit log - prio is
	// # a working audit log and not staying true to the last bit of correctness here:
	// # If something needs the user attention (e.g. user deleted on branch A, added on branch B)
	// # then we take a pre-decision for them and let them know so they can change it if necessary.
	// write(%A, rebase_ops(%O, %A, %B))
	// stderr("merge needs finalize -> fix any markers in revealed paths, then git commit")
	// # prevent the auto-commit from git - we don't want them
	// # Side effect: That would always print something like:
	// #
	// # Auto-merging .sesam/audit.log
	// # CONFLICT (content): Merge conflict in .sesam/audit.log
	// # Auto-merging .sesam/secrets/db
	// # Auto-merging .sesam/secrets/api-key
	// # CONFLICT (content): Merge conflict in .sesam/secrets/api-key
	// # Automatic merge failed; fix conflicts and then commit the result.
	// #
	// #
	// # => UX is a bit funny here, if we always create conflicts.
	// # => But we could say "go over all conflicting paths outside of audit log"
	// #    and make sure there are no conflicts, then run git commit"
	// #    The git commit will trigger the pre-commit below.
	// #
	// # Crux: If we allow the clean merge with exit 0, then we can't really hook in the seal.
	// # We could of course scream loudly "RUN SESAM SEAL AND COMMIT AGAIN", but not ideal either.
	// exit 1

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
