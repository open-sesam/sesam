package commands

import (
	"context"
	"encoding/hex"
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

	// %A is still ours in both unsealed cases, so the object has to be sealed
	// before the operation is finished. Only an operation that ends in `git
	// commit` runs the pre-commit hook that would do it for them.
	kind := mergeState(drv.sesamDir)
	unsealed := res.Seal != repo.MergeSealDone && !kind.RunsPreCommit()

	switch res.Seal {
	case repo.MergeSealDone:
		fmt.Fprintf(os.Stderr, "sesam: automatically merging revealed file %s; no conflicts, resealed\n", revealedPath)
	case repo.MergeSealDeferred:
		fmt.Fprintf(
			os.Stderr,
			"sesam: automatically merging revealed file %s; no conflicts, but access to it changed on both sides\n"+
				"sesam: %s\n",
			revealedPath, sealAdvice(kind, "it will be sealed with the merged recipients when you commit"),
		)
	default:
		fmt.Fprintf(
			os.Stderr,
			"sesam: automatically merging revealed file %s; no conflicts, but it could not be resealed\n"+
				"sesam: %s\n",
			revealedPath, sealAdvice(kind, "run `sesam seal` before finishing, or the merged content will not be committed"),
		)
	}

	// Nothing downstream will seal this one. Report it as a conflict rather than
	// exiting 0: git would otherwise take %A - the pre-merge object - as the
	// result and the merged content would be silently dropped.
	if unsealed {
		return &ExitCodeError{err: nil, print: false, code: 1}
	}

	return nil
}

// sealAdvice tells the user how the pending seal gets done. `whenHooked` applies
// when the finalize hook will run; otherwise the object is left conflicted and
// the seal has to be run by hand before the operation can continue.
func sealAdvice(kind mergeKind, whenHooked string) string {
	if kind.RunsPreCommit() {
		return whenHooked
	}

	advice := "run `sesam seal`, then `git add` the object"
	if cont := kind.ContinueCmd(); cont != "" {
		advice += " and `" + cont + "` (it runs no hook that could seal for you)"
	}

	return advice
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
// theirsVStatePath names the state by the revision it was verified for, so a
// file left behind by an aborted merge is simply never looked up again.
func theirsVStatePath(rev string) string {
	return filepath.Join(core.SesamTmpDir(), "theirs-vstate-"+rev+".json")
}

// theirsCheckoutPath is where the incoming .sesam is unpacked to be verified.
var theirsCheckoutPath = filepath.Join(core.SesamTmpDir(), "theirs")

// theirStateFunc yields the state of the branch being merged in, verifying that
// branch the first time anything asks. git runs a driver per conflicting path,
// so the work happens once and the rest read the file it left behind.
func theirStateFunc(ctx context.Context, cmd *cli.Command, drv *mergeDriver) repo.TheirStateFunc {
	return func() (*core.VerifiedState, error) {
		rev, err := mergeSource(drv.sesamDir, drv.theirPath)
		if err != nil {
			return nil, err
		}

		// The revision becomes a file name below, so insist it is an object id.
		if _, err := hex.DecodeString(rev); rev == "" || err != nil {
			return nil, fmt.Errorf("%q is not a commit id", rev)
		}

		if state, err := readTheirState(drv.sesamDir, rev); err == nil {
			return state, nil
		}

		if err := ensureTheirsVerified(ctx, drv.sesamDir, rev, drv.identityPaths, repo.RepoOpts{
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

		return readTheirState(drv.sesamDir, rev)
	}
}

// readTheirState returns the state verified for `rev`, if there is one.
func readTheirState(sesamDir, rev string) (*core.VerifiedState, error) {
	//nolint:gosec // sesam dir plus a name built from a revision we resolved.
	fd, err := os.Open(filepath.Join(sesamDir, theirsVStatePath(rev)))
	if err != nil {
		return nil, err
	}

	defer func() { _ = fd.Close() }()

	var state core.VerifiedState
	if err := json.NewDecoder(fd).Decode(&state); err != nil {
		return nil, fmt.Errorf("read %s: %w", theirsVStatePath(rev), err)
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
func ensureTheirsVerified(ctx context.Context, sesamDir, rev string, identityPaths []string, opts repo.RepoOpts) error {
	checkoutDir := filepath.Join(sesamDir, theirsCheckoutPath)
	if err := extractSesamDir(ctx, sesamDir, rev, checkoutDir); err != nil {
		return fmt.Errorf("unpack %s: %w", rev, err)
	}

	// we need to double check that that the incoming audit log is actually from the same root as ours.
	// otherwise some attacker could craft an audit log that is not based on ours.
	// usually, this would be noticed in the audit log merge driver, but it's here as double bolt.
	if err := requireSameInitAnchor(sesamDir, checkoutDir); err != nil {
		return err
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

	return writeJSONFile(filepath.Join(sesamDir, theirsVStatePath(rev)), state)
}

// requireSameInitAnchor refuses a vault that does not belong to this repository.
// The anchor is the hash of the init entry, which pins the repo id and the first
// admin's signing key, so one comparison covers the whole chain below it.
func requireSameInitAnchor(sesamDir, checkoutDir string) error {
	ours, err := readInitAnchor(sesamDir)
	if err != nil {
		return err
	}

	theirs, err := readInitAnchor(checkoutDir)
	if err != nil {
		return err
	}

	if ours != theirs {
		return fmt.Errorf(
			"the branch being merged in belongs to a different repository (init %s != %s) - refusing to merge it",
			theirs, ours,
		)
	}

	return nil
}

func readInitAnchor(dir string) (string, error) {
	//nolint:gosec // dir is ours; the file name is fixed.
	data, err := os.ReadFile(filepath.Join(dir, core.AuditInitPath()))
	if err != nil {
		return "", fmt.Errorf("read init anchor: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}
