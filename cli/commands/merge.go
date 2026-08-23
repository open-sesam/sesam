package commands

import (
	"context"
	"encoding/json"
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
	drv, err := openMergeDriver(cmd)
	if err != nil {
		return err
	}

	defer drv.close()

	revealedPath, ok := core.RevealedPath(drv.path)
	if !ok {
		return fmt.Errorf("%%P needs to be a sesam object - gitattributes wrongly configured?")
	}

	res, err := repo.MergeSecret(
		ctx,
		drv.root,
		drv.ids,
		revealedPath,
		drv.ourPath,
		drv.theirPath,
		drv.originPath,
		drv.conflictMarkerSize,
		theirStateFunc(ctx, cmd, drv),
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
		slog.Int("conflicts", res.Conflicts),
		slog.Bool("binary", res.Binary),
		slog.String("seal", res.Seal.String()),
		slog.String("path", revealedPath),
	)

	if res.Binary {
		fmt.Fprintf(os.Stderr, "sesam: binary secret %s changed on both sides - cannot auto-merge; wrote %s.ours and %s.theirs.\n", revealedPath, revealedPath, revealedPath)
		fmt.Fprintf(os.Stderr, "sesam: copy the one you want over %s (and delete the .ours/.theirs), then commit.\n", revealedPath)
		return &ExitCodeError{err: nil, print: false, code: 1}
	}

	if res.Conflicts > 0 {
		fmt.Fprintf(
			os.Stderr,
			"sesam: automatically merging revealed file %s; %d %s - please fix manually.\n",
			revealedPath, res.Conflicts, pluralize("conflict", res.Conflicts),
		)
		return &ExitCodeError{
			err:   nil,
			print: false,
			code:  (res.Conflicts % 127) + 1,
		}
	}

	switch res.Seal {
	case repo.MergeSealDone:
		fmt.Fprintf(os.Stderr, "sesam: automatically merging revealed file %s; no conflicts, resealed\n", revealedPath)
	case repo.MergeSealDeferred:
		fmt.Fprintf(
			os.Stderr,
			"sesam: automatically merging revealed file %s; no conflicts, but access to it changed on both sides\n"+
				"sesam: it will be sealed with the merged recipients when you commit\n",
			revealedPath,
		)
	default:
		// %A is still ours, so someone has to seal before committing. A plain merge
		// has the finalize hook for that, a rebase or cherry-pick has nothing.
		fmt.Fprintf(
			os.Stderr,
			"sesam: automatically merging revealed file %s; no conflicts, but it could not be resealed\n"+
				"sesam: run `sesam seal` before finishing, or the merged content will not be committed\n",
			revealedPath,
		)
	}

	return nil
}

func HandleMergeAuditLog(ctx context.Context, cmd *cli.Command) error {
	drv, err := openMergeDriver(cmd)
	if err != nil {
		return err
	}

	defer drv.close()

	if !strings.HasSuffix(drv.path, core.SesamDir()+"/audit/log.jsonl") {
		return fmt.Errorf("%%P needs to be the audit log path but is %s - gitattributes wrongly configured?", drv.path)
	}

	cr, err := repo.MergeAuditLog(
		ctx,
		drv.root,
		drv.ids,
		drv.ourPath,
		drv.theirPath,
		drv.originPath,
		drv.conflictMarkerSize,
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
	fmt.Fprint(os.Stderr, mergeDriverSummary(cr.Resolutions, mergeState(drv.sesamDir)))

	return nil
}

// withoutConflicted drops the secrets a merge left unresolved from paths.
func withoutConflicted(paths []string, conflicted []core.ConflictedSecret) []string {
	skip := make(map[string]bool, len(conflicted))
	for _, c := range conflicted {
		skip[c.Path] = true
	}

	kept := make([]string, 0, len(paths))
	for _, p := range paths {
		if !skip[p] {
			kept = append(kept, p)
		}
	}

	return kept
}

// mergeDriver is everything git hands a merge driver, resolved once: both of
// ours take the same %O/%A/%B/%L arguments and need the same repo handles.
type mergeDriver struct {
	sesamDir string
	root     *os.Root
	ids      core.Identities

	identityPaths []string

	// path is %P, the merged file, as a sesam-relative path.
	path string

	originPath, ourPath, theirPath string
	conflictMarkerSize             int
}

func openMergeDriver(cmd *cli.Command) (*mergeDriver, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return nil, err
	}

	// %P is worktree-root-relative and git runs the driver from the worktree
	// root, so join it onto cwd to get something toRepoPath can rebase.
	pathArg := cmd.StringArg("path")
	if !filepath.IsAbs(pathArg) {
		pathArg = filepath.Join(cwd, pathArg)
	}

	path, err := toRepoPath(sesamDir, cwd, pathArg)
	if err != nil {
		return nil, err
	}

	identityPaths := cmd.StringSlice("identity")
	ids, err := repo.LoadIdentities(identityPaths, repo.RepoOpts{
		AskpassProgram:  cmd.String("askpass"),
		AskpassRequired: askpassRequired(),
	})
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(sesamDir)
	if err != nil {
		return nil, err
	}

	return &mergeDriver{
		sesamDir:           sesamDir,
		root:               root,
		ids:                ids,
		identityPaths:      identityPaths,
		path:               path,
		originPath:         cmd.StringArg("origin"),
		ourPath:            cmd.StringArg("our-path"),
		theirPath:          cmd.StringArg("their-path"),
		conflictMarkerSize: cmd.IntArg("conflict-marker-size"),
	}, nil
}

func (d *mergeDriver) close() {
	_ = d.root.Close()
}

// conflictedSecretHints renders a fix-it line per unresolved secret, shared by
// the finalize (which refuses) and `sesam seal` (which only warns).
func conflictedSecretHints(conflicted []core.ConflictedSecret) []string {
	lines := make([]string, 0, len(conflicted))
	for _, c := range conflicted {
		if c.Binary {
			lines = append(lines, "  "+c.Path+" (binary): copy its .ours or .theirs over it, then delete the side files")
		} else {
			lines = append(lines, "  "+c.Path+": resolve the conflict markers in the revealed file")
		}
	}

	return lines
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

// mergeDriverSummary explains what the log driver decided and how to finish.
// The advice stays vague on MergeKindNone rather than guessing "merge".
func mergeDriverSummary(resolutions []core.ConflictResolutionEntry, kind mergeKind) string {
	lines := mergeDecisionLines(resolutions)

	var b strings.Builder
	b.WriteString("sesam: both sides changed the audit log.\n")
	b.WriteString("sesam: the audit log was therefore semantically merged.\n")
	b.WriteString("sesam:\n")
	if len(lines) > 0 {
		b.WriteString("sesam: a list of automated decisions you might want to review follows:\n")
		for _, line := range lines {
			b.WriteString("sesam: " + line + "\n")
		}
	}

	b.WriteString("sesam:\n")
	b.WriteString("sesam: NOTE: git may tell you the operation failed below.\n")
	b.WriteString("sesam:       this is only to give you a chance to review the repo state before continuing.\n")
	b.WriteString("sesam:\n")
	b.WriteString("sesam: resolve any conflicts mentioned above (if any), then check with `sesam status`.\n")

	if cont := kind.ContinueCmd(); cont != "" {
		b.WriteString("sesam: finish this " + kind.String() + " with `" + cont + "`.\n")
	} else {
		b.WriteString("sesam: then finish the git operation you started (`git commit`, `git rebase --continue`, ...).\n")
	}

	b.WriteString("sesam: in case you don't have the git integration installed run `sesam hook pre-commit` directly.\n")

	if abort := kind.AbortCmd(); abort != "" {
		b.WriteString("sesam: if you're unsure what any of this means, you can also start over with `" + abort + "` and then `sesam reveal --all`\n")
	}

	return b.String()
}

// theirsVStatePath is where the incoming branch's verified state is parked for
// the driver runs that follow.
var theirsVStatePath = filepath.Join(core.SesamTmpDir(), "theirs-vstate.json")

// theirsCheckoutPath is where the incoming .sesam is unpacked to be verified.
var theirsCheckoutPath = filepath.Join(core.SesamTmpDir(), "theirs")

// theirStateFunc yields the state of the branch being merged in, verifying that
// branch the first time anything asks. git runs a driver per conflicting path,
// so the work happens once and the rest read the file it left behind.
func theirStateFunc(ctx context.Context, cmd *cli.Command, drv *mergeDriver) repo.TheirStateFunc {
	return func() (*core.VerifiedState, error) {
		state, err := readTheirState(drv.sesamDir)
		if err == nil {
			return state, nil
		}

		if !os.IsNotExist(err) {
			return nil, err
		}

		if err := ensureTheirsVerified(ctx, drv.sesamDir, drv.theirPath, drv.identityPaths, repo.RepoOpts{
			AskpassProgram:  cmd.String("askpass"),
			AskpassRequired: askpassRequired(),

			// The disk checks are left to the explicit Verify: at load time a
			// mismatch aborts with "try --verify-mode no-disk", which hides the
			// actual finding behind advice to pass a flag.
			VerifyMode: repo.VerifyModeNoDisk,

			// We unlocked these already; loading them again could prompt twice.
			Identities: drv.ids,
		}); err != nil {
			return nil, err
		}

		return readTheirState(drv.sesamDir)
	}
}

func readTheirState(sesamDir string) (*core.VerifiedState, error) {
	//nolint:gosec // path is the sesam dir plus a fixed name.
	fd, err := os.Open(filepath.Join(sesamDir, theirsVStatePath))
	if err != nil {
		return nil, err
	}

	defer func() { _ = fd.Close() }()

	var state core.VerifiedState
	if err := json.NewDecoder(fd).Decode(&state); err != nil {
		return nil, fmt.Errorf("read %s: %w", theirsVStatePath, err)
	}

	return &state, nil
}

// ensureTheirsVerified makes sure the branch being merged in was verified as a
// whole before we take anything from it. It is the equivalent of checking that
// branch out and running `sesam verify` on it: unpack its .sesam, load it as a
// repo of its own, verify, and leave the resulting state behind for the drivers.
//
// git runs a driver per conflicting path, so this happens once and the rest of
// the invocations read the file.
func ensureTheirsVerified(ctx context.Context, sesamDir, theirPath string, identityPaths []string, opts repo.RepoOpts) error {
	rev, err := mergeSource(sesamDir, theirPath)
	if err != nil {
		return err
	}

	checkoutDir := filepath.Join(sesamDir, theirsCheckoutPath)
	if err := extractSesamDir(ctx, sesamDir, rev, checkoutDir); err != nil {
		return fmt.Errorf("unpack %s: %w", rev, err)
	}

	theirs, err := repo.Load(checkoutDir, identityPaths, opts)
	if err != nil {
		return fmt.Errorf("load %s: %w", rev, err)
	}

	defer func() { _ = theirs.Close() }()

	// Truncation and forge checks need the history and the network; neither says
	// anything about whether the objects we are about to merge are sound.
	report, err := theirs.Verify(ctx, repo.VerifyOptions{Integrity: true, KeyReuse: true})
	if err != nil {
		return fmt.Errorf("verify %s: %w", rev, err)
	}

	if !report.OK() {
		printReport(repo.VerifyOptions{Integrity: true, KeyReuse: true}, report)
		return fmt.Errorf("the branch being merged in does not verify - refusing to merge it")
	}

	state, err := theirs.VerifiedState()
	if err != nil {
		return err
	}

	return writeJSONFile(filepath.Join(sesamDir, theirsVStatePath), state)
}
