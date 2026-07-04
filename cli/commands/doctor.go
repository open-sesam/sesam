package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

type DoctorDiagnoseType int

const (
	DiagnoseHealthy = DoctorDiagnoseType(iota)
	DiagnoseWarning
	DiagnoseIssue
	DiagnoseFailed
	// DiagnoseInfo is neither pass nor fail: a neutral note (e.g. a stubbed
	// check or "nothing to do here"). It does not block sub-checks and is not
	// counted as a problem in the summary.
	DiagnoseInfo
)

type DoctorDiagnosis struct {
	Type DoctorDiagnoseType
	Desc string
	// Fix, when set, is a short remediation hint printed under the check.
	Fix string
}

type DoctorCheck interface {
	Name() string
	Run() DoctorDiagnosis
	SubChecks() []DoctorCheck
}

// doctorCategory groups related checks under a heading in the report.
type doctorCategory struct {
	title  string
	checks []DoctorCheck
}

type doctorEnv struct {
	sesamDir      string
	identityPaths []string
	lockTimeout   time.Duration
	version       string // full version banner, as shown to the user
	versionShort  string // bare semver, e.g. "0.1.2" - for the update check
}

type genericCheck struct {
	name      string
	run       func() DoctorDiagnosis
	subChecks []DoctorCheck
}

func (g *genericCheck) Name() string { return g.name }

func (g *genericCheck) Run() DoctorDiagnosis { return g.run() }

func (g *genericCheck) SubChecks() []DoctorCheck { return g.subChecks }

// Diagnosis constructors keep the check bodies terse.

func docHealthy(desc string) DoctorDiagnosis {
	return DoctorDiagnosis{Type: DiagnoseHealthy, Desc: desc}
}

func docInfo(desc string) DoctorDiagnosis {
	return DoctorDiagnosis{Type: DiagnoseInfo, Desc: desc}
}

func docFailed(desc string) DoctorDiagnosis {
	return DoctorDiagnosis{Type: DiagnoseFailed, Desc: desc}
}

func docWarn(desc, fix string) DoctorDiagnosis {
	return DoctorDiagnosis{Type: DiagnoseWarning, Desc: desc, Fix: fix}
}

func docIssue(desc, fix string) DoctorDiagnosis {
	return DoctorDiagnosis{Type: DiagnoseIssue, Desc: desc, Fix: fix}
}

// --- check tree -------------------------------------------------------------

func buildCategories(ctx context.Context, env doctorEnv) []doctorCategory {
	return []doctorCategory{
		{"System", []DoctorCheck{osCheck()}},
		{"Installation", []DoctorCheck{sesamInPathCheck(), versionCheck(ctx, env)}},
		{"Identity", []DoctorCheck{identityCheck(env)}},
		{"Environment", []DoctorCheck{askpassCheck(), editorCheck(), completionCheck()}},
		{"Git", []DoctorCheck{gitRepoCheck(), gitCheck(ctx, env)}},
		{"Repository", []DoctorCheck{sesamDirCheck(env)}},
	}
}

func osCheck() DoctorCheck {
	return &genericCheck{name: "operating-system", run: func() DoctorDiagnosis {
		switch runtime.GOOS {
		case "linux":
			return docHealthy(fmt.Sprintf("%s/%s (supported)", runtime.GOOS, runtime.GOARCH))
		case "darwin":
			return docWarn("macOS is not tested yet, but should mostly work", "please report any macOS issues you run into")
		case "windows":
			return docIssue(
				"Windows is unsupported and likely to misbehave (symlinks, file modes, paths)",
				"run sesam under WSL2 or on a Linux/macOS host",
			)
		default:
			return docWarn(fmt.Sprintf("%s is untested", runtime.GOOS), "")
		}
	}}
}

func sesamInPathCheck() DoctorCheck {
	return &genericCheck{
		name: "sesam-in-path",
		run: func() DoctorDiagnosis {
			path, err := exec.LookPath("sesam")
			if err != nil && !errors.Is(err, exec.ErrDot) {
				// NOTE: LookPath() does not like relative paths.
				// git does not care however, so that's not a blocker for us.
				return docIssue(
					"not found in PATH - git filters and hooks call `sesam` by name",
					"install the sesam binary into a directory on your $PATH",
				)
			}
			return docHealthy(path)
		},
		subChecks: []DoctorCheck{runningBinaryCheck()},
	}
}

func runningBinaryCheck() DoctorCheck {
	return &genericCheck{name: "running-binary", run: func() DoctorDiagnosis {
		inPath, err := exec.LookPath("sesam")
		if err != nil && !errors.Is(err, exec.ErrDot) {
			return docFailed("sesam not in PATH")
		}

		absInPath, err := filepath.Abs(inPath)
		if err != nil {
			return docFailed("sesam PATH cannot be made absolute")
		}

		self, err := os.Executable()
		if err != nil {
			return docWarn("could not determine the running binary's path", "")
		}

		a := resolveSymlinks(absInPath)
		b := resolveSymlinks(self)
		if a == b {
			return docHealthy("the sesam in PATH is the binary you are running")
		}
		return docWarn(
			fmt.Sprintf("the sesam in PATH (%s) differs from the running binary (%s)", a, b),
			"git uses the PATH copy - make sure it is the version you expect",
		)
	}}
}

func versionCheck(ctx context.Context, env doctorEnv) DoctorCheck {
	return &genericCheck{
		name:      "version",
		run:       func() DoctorDiagnosis { return docHealthy(env.version) },
		subChecks: []DoctorCheck{latestVersionCheck(ctx, env)},
	}
}

// githubReleasesURL is the GitHub API endpoint for the newest published release.
// It 404s until the first release is tagged, which latestVersionCheck treats as
// "nothing to compare against yet" rather than an error.
const githubReleasesURL = "https://api.github.com/repos/open-sesam/sesam/releases/latest"

// errNoReleases marks the expected "repo has no releases yet" 404.
var errNoReleases = errors.New("no published releases")

func latestVersionCheck(ctx context.Context, env doctorEnv) DoctorCheck {
	return &genericCheck{name: "latest-version", run: func() DoctorDiagnosis {
		latest, err := fetchLatestReleaseTag(ctx)
		if err != nil {
			if errors.Is(err, errNoReleases) {
				return docInfo("no published releases to compare against yet")
			}
			// Best-effort: a blocked or down network must never turn doctor
			// red, so an update-check failure is informational only.
			return docInfo(fmt.Sprintf("could not check for updates: %v", err))
		}

		current, errCur := semver.NewVersion(env.versionShort)
		newest, errNew := semver.NewVersion(latest)
		if errCur != nil || errNew != nil {
			return docInfo(fmt.Sprintf("latest release is %s (running %s)", latest, env.versionShort))
		}

		switch current.Compare(newest) {
		case -1:
			return docWarn(
				fmt.Sprintf("a newer release is available: %s (you have %s)", latest, env.versionShort),
				"upgrade to the latest sesam release",
			)
		case 1:
			return docInfo(fmt.Sprintf("running %s, ahead of the latest release %s", env.versionShort, latest))
		default:
			return docHealthy(fmt.Sprintf("up to date (%s)", latest))
		}
	}}
}

func fetchLatestReleaseTag(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubReleasesURL, nil)
	if err != nil {
		return "", err
	}

	// what a weird mime type, but github wants it
	// https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api?apiVersion=2026-03-10#media-types
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sesam-doctor")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", errNoReleases
	default:
		return "", fmt.Errorf("github returned %s", resp.Status)
	}

	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", err
	}
	if payload.TagName == "" {
		return "", errors.New("release response had no tag_name")
	}
	return payload.TagName, nil
}

func identityCheck(env doctorEnv) DoctorCheck {
	paths := env.identityPaths
	return &genericCheck{
		name: "identity-configured",
		run: func() DoctorDiagnosis {
			if len(paths) == 0 {
				return docIssue(
					"no identity configured",
					"pass --identity or set $SESAM_ID / $SESAM_IDENTITY to your private key file (ssh or age)",
				)
			}
			return docHealthy(fmt.Sprintf(
				"%d identity file%s: %s",
				len(paths), pluralize("", len(paths)), strings.Join(paths, ", "),
			))
		},
		subChecks: []DoctorCheck{
			identityReadableCheck(paths),
			identityTypeCheck(paths),
			identityPermsCheck(paths),
			identityPluginCheck(paths),
			identityUserCheck(env),
		},
	}
}

// identityTypeCheck reports each identity's type (age x25519, ssh, age-plugin, …)
// purely for debugging - it never decrypts or contacts a plugin. Always info.
func identityTypeCheck(paths []string) DoctorCheck {
	return &genericCheck{name: "identity-type", run: func() DoctorDiagnosis {
		var types []string
		for _, p := range paths {
			data, err := os.ReadFile(expandHome(p))
			if err != nil {
				continue // identity-readable already reports access problems
			}
			types = append(types, core.IdentityType(string(data)))
		}
		if len(types) == 0 {
			return docInfo("no identity files to inspect")
		}
		return docInfo(strings.Join(types, ", "))
	}}
}

func identityReadableCheck(paths []string) DoctorCheck {
	return &genericCheck{name: "identity-readable", run: func() DoctorDiagnosis {
		var bad []string
		for _, p := range paths {
			f, err := os.Open(expandHome(p))
			if err != nil {
				bad = append(bad, fmt.Sprintf("%s (%v)", p, err))
				continue
			}
			_ = f.Close()
		}
		if len(bad) > 0 {
			return docIssue("cannot read "+strings.Join(bad, "; "), "check the path and the file's permissions")
		}
		return docHealthy("all identity files are readable")
	}}
}

func identityPermsCheck(paths []string) DoctorCheck {
	return &genericCheck{name: "identity-permissions", run: func() DoctorDiagnosis {
		var loose []string
		for _, p := range paths {
			fi, err := os.Stat(expandHome(p))
			if err != nil {
				continue // identity-readable already reports access errors
			}
			if perm := fi.Mode().Perm(); perm&0o077 != 0 {
				loose = append(loose, fmt.Sprintf("%s (%#o)", p, perm))
			}
		}
		if len(loose) > 0 {
			return docWarn(
				"identity readable by group/other: "+strings.Join(loose, "; "),
				"chmod 600 the identity file(s)",
			)
		}
		return docHealthy("not group/other-readable (0600 or stricter)")
	}}
}

func identityPluginCheck(paths []string) DoctorCheck {
	return &genericCheck{name: "identity-plugin", run: func() DoctorDiagnosis {
		var missing, found []string
		usesPlugin := false
		for _, p := range paths {
			bin, ok := pluginBinaryForIdentityFile(expandHome(p))
			if !ok {
				continue
			}
			usesPlugin = true
			if _, err := exec.LookPath(bin); err != nil && !errors.Is(err, exec.ErrDot) {
				missing = append(missing, bin)
			} else {
				found = append(found, bin)
			}
		}
		switch {
		case !usesPlugin:
			return docInfo("no age-plugin identities in use")
		case len(missing) > 0:
			return docIssue(
				"missing age plugin binaries: "+strings.Join(missing, ", "),
				"install the plugin(s) and make sure they are on $PATH",
			)
		default:
			return docHealthy("plugin(s) installed: " + strings.Join(found, ", "))
		}
	}}
}

func identityUserCheck(env doctorEnv) DoctorCheck {
	return &genericCheck{name: "identity-resolves-to-user", run: func() DoctorDiagnosis {
		initialized, err := repo.IsInitialized(env.sesamDir)
		if err != nil {
			return docInfo(fmt.Sprintf("no sesam repo to check against (%v)", err))
		}
		if !initialized {
			return docInfo("no sesam repo here yet - cannot map identity to a user")
		}

		r, err := repo.Load(env.sesamDir, env.identityPaths, repo.RepoOpts{
			Interactive: true,
			LockTimeout: env.lockTimeout,
			VerifyMode:  repo.VerifyModeDefault,
		})
		if err != nil {
			return docIssue(
				fmt.Sprintf("identity does not map to a user (%v)", err),
				"ask an admin to `sesam tell` your recipient, then `sesam open`",
			)
		}
		defer func() { _ = r.Close() }()

		who, err := r.Whoami()
		if err != nil {
			return docIssue(fmt.Sprintf("could not determine the current user: %v", err), "")
		}
		return docHealthy(fmt.Sprintf("recognised as user »%s«", who))
	}}
}

func askpassCheck() DoctorCheck {
	return &genericCheck{name: "askpass", run: func() DoctorDiagnosis {
		var set []string
		for _, v := range []string{"SESAM_ASKPASS", "GIT_ASKPASS", "SSH_ASKPASS"} {
			if p := os.Getenv(v); p != "" {
				set = append(set, fmt.Sprintf("%s=%s", v, p))
			}
		}
		if len(set) == 0 {
			return docWarn(
				"no askpass helper set (SESAM_ASKPASS, GIT_ASKPASS, SSH_ASKPASS)",
				"set one to supply passphrases non-interactively; otherwise prompts fall back to the terminal",
			)
		}
		return docHealthy("configured via " + strings.Join(set, ", "))
	}}
}

func editorCheck() DoctorCheck {
	return &genericCheck{name: "editor", run: func() DoctorDiagnosis {
		if e := os.Getenv("EDITOR"); e != "" {
			return docHealthy("EDITOR=" + e)
		}
		if e := os.Getenv("VISUAL"); e != "" {
			return docHealthy("$VISUAL=" + e)
		}
		return docWarn(
			"neither EDITOR nor VISUAL is set",
			"export EDITOR=<your editor> so `sesam edit` knows what to launch",
		)
	}}
}

func completionCheck() DoctorCheck {
	return &genericCheck{name: "shell-completion", run: func() DoctorDiagnosis {
		// Whether completion is wired up lives in the interactive shell's
		// in-memory state (its complete/compdef tables and functions), which is
		// never exported to a child process - so doctor genuinely cannot tell.
		// The only environment signal is the login shell; the rest is a pointer
		// to the docs, not a verdict.
		switch shell := filepath.Base(os.Getenv("SHELL")); shell {
		case "bash", "zsh", "fish":
			return docInfo(
				fmt.Sprintf(
					"%s detected - to enable completion: source <(sesam completion %s)",
					shell,
					shell,
				),
			)
		default:
			return docInfo("shell not detected from $SHELL - see docs/ to enable shell completion")
		}
	}}
}

func gitRepoCheck() DoctorCheck {
	return &genericCheck{name: "git-repository", run: func() DoctorDiagnosis {
		cwd, err := os.Getwd()
		if err != nil {
			return docFailed(fmt.Sprintf("could not determine the working directory: %v", err))
		}
		root, err := repo.GitWorktreeRoot(cwd)
		if err != nil {
			return docIssue("not inside a git repository", "run `git init` or cd into your repository")
		}

		rel, err := filepath.Rel(resolveSymlinks(cwd), resolveSymlinks(root))
		if err != nil {
			rel = root
		}
		if rel == "." {
			return docHealthy("at the repository root")
		}
		return docHealthy(fmt.Sprintf("root at %s", rel))
	}}
}

func gitCheck(ctx context.Context, env doctorEnv) DoctorCheck {
	return &genericCheck{
		name: "git-binary",
		run: func() DoctorDiagnosis {
			path, err := exec.LookPath("git")
			if err != nil {
				return docIssue("git not found in PATH", "install git (>= 2.54 for upcoming hook support)")
			}
			return docHealthy(path)
		},
		subChecks: []DoctorCheck{
			gitVersionCheck(ctx),
			gitConfigCheck(env),
			gitHooksCheck(),
		},
	}
}

// see: https://github.blog/open-source/git/highlights-from-git-2-54/#h-config-based-hooks
var minGitVersion = semver.MustParse("2.54.0")

func gitVersionCheck(ctx context.Context) DoctorCheck {
	return &genericCheck{name: "git-version", run: func() DoctorDiagnosis {
		v, err := repo.ReadGitVersion(ctx)
		if err != nil {
			return docFailed(fmt.Sprintf("could not read git version: %v", err))
		}
		if v.LessThan(minGitVersion) {
			return docWarn(
				fmt.Sprintf("git %s (< %s)", v, minGitVersion),
				fmt.Sprintf("upgrade git to %s+ for git-config-based hook support", minGitVersion),
			)
		}
		return docHealthy(fmt.Sprintf("%s (>= %s)", v, minGitVersion))
	}}
}

// gitConfigCheck reads the managed git config once and exposes each entry as a
// sub-check. The parent only reports whether the config was readable at all, so
// per-entry problems still surface below it rather than being hidden.
func gitConfigCheck(env doctorEnv) DoctorCheck {
	var (
		once    sync.Once
		checks  []repo.GitConfigCheck
		loadErr error
	)
	load := func() {
		once.Do(func() { checks, loadErr = repo.CheckGitConfig(env.sesamDir) })
	}

	entry := func(path string) DoctorCheck {
		return &genericCheck{name: path, run: func() DoctorDiagnosis {
			load()
			if loadErr != nil {
				return docFailed("git config unreadable")
			}
			for _, c := range checks {
				if c.Path != path {
					continue
				}
				switch {
				case c.OK:
					return docHealthy("set as expected")
				case c.Actual == "":
					return docIssue("not set", "run `sesam init` to (re)install sesam's git integration")
				default:
					return docIssue(
						fmt.Sprintf("unexpected value %q (want %q)", c.Actual, c.Expected),
						"run `sesam init` to (re)install sesam's git integration",
					)
				}
			}
			return docFailed("not checked")
		}}
	}

	return &genericCheck{
		name: "git-config",
		run: func() DoctorDiagnosis {
			load()
			if loadErr != nil {
				return docIssue(
					fmt.Sprintf("could not read git config: %v", loadErr),
					"run `sesam init` inside the repository",
				)
			}
			return docHealthy("sesam git drivers (each checked below)")
		},
		subChecks: []DoctorCheck{
			entry("merge.sesam-merge.name"),
			entry("merge.sesam-merge.driver"),
			entry("diff.sesam-diff.textconv"),
			entry("alias.sesam"),
		},
	}
}

func gitHooksCheck() DoctorCheck {
	// TODO: @adel need to be implenmented when git hooks come in.
	stub := func(name string) DoctorCheck {
		return &genericCheck{name: name, run: func() DoctorDiagnosis {
			return docInfo("planned, not implemented yet")
		}}
	}
	return &genericCheck{
		name: "git-hooks",
		run:  func() DoctorDiagnosis { return docInfo("hook installation not implemented yet") },
		subChecks: []DoctorCheck{
			stub("pre-commit (seal+verify)"),
			stub("post-commit (open)"),
		},
	}
}

func sesamDirCheck(env doctorEnv) DoctorCheck {
	return &genericCheck{
		name: "sesam-directory",
		run: func() DoctorDiagnosis {
			resolved, err := repo.ResolveSesamDir(env.sesamDir)
			if err != nil {
				return docIssue(
					fmt.Sprintf("could not resolve sesam dir: %v", err),
					"pass --sesam-dir or run inside the repository",
				)
			}
			fi, err := os.Stat(filepath.Join(resolved, ".sesam"))
			if err != nil {
				if os.IsNotExist(err) {
					return docIssue("no .sesam directory found", "run `sesam init` to create a sesam repository")
				}
				return docFailed(fmt.Sprintf("stat .sesam: %v", err))
			}
			if !fi.IsDir() {
				return docIssue(".sesam exists but is not a directory", "remove it and run `sesam init`")
			}
			return docHealthy(filepath.Join(resolved, ".sesam"))
		},
		subChecks: []DoctorCheck{
			sesamDirPermsCheck(env),
			gitignoreCheck(env),
			gitattributesCheck(env),
		},
	}
}

func sesamDirPermsCheck(env doctorEnv) DoctorCheck {
	return &genericCheck{name: "sesam-directory-permissions", run: func() DoctorDiagnosis {
		if runtime.GOOS == "windows" {
			return docInfo("permission check skipped on Windows")
		}
		resolved, err := repo.ResolveSesamDir(env.sesamDir)
		if err != nil {
			return docFailed(err.Error())
		}
		fi, err := os.Stat(filepath.Join(resolved, ".sesam"))
		if err != nil {
			return docFailed(err.Error())
		}
		if perm := fi.Mode().Perm(); perm != 0o700 {
			return docWarn(fmt.Sprintf(".sesam is %#o, expected 0700", perm), "chmod 700 .sesam")
		}
		return docHealthy("0700")
	}}
}

func gitignoreCheck(env doctorEnv) DoctorCheck {
	return &genericCheck{name: "gitignore", run: func() DoctorDiagnosis {
		res, err := repo.CheckGitIgnore(env.sesamDir)
		return managedFileDiagnosis(res, err, ".gitignore")
	}}
}

func gitattributesCheck(env doctorEnv) DoctorCheck {
	return &genericCheck{name: "gitattributes", run: func() DoctorDiagnosis {
		res, err := repo.CheckGitAttributes(env.sesamDir)
		return managedFileDiagnosis(res, err, ".gitattributes")
	}}
}

func managedFileDiagnosis(res repo.ManagedFileCheck, err error, name string) DoctorDiagnosis {
	if err != nil {
		return docFailed(fmt.Sprintf("could not check %s: %v", name, err))
	}
	if !res.Exists {
		return docIssue(name+" is missing", "run `sesam init` to (re)create it")
	}
	if len(res.Missing) > 0 {
		return docIssue(
			fmt.Sprintf("missing %d expected line%s: %s",
				len(res.Missing), pluralize("", len(res.Missing)), strings.Join(res.Missing, " | ")),
			"run `sesam init` to append the missing lines",
		)
	}
	return docHealthy("all expected patterns present")
}

// --- runner & rendering -----------------------------------------------------

type doctorSummary struct {
	healthy, warning, issue, failed, info, skipped int
}

func (s *doctorSummary) add(t DoctorDiagnoseType) {
	switch t {
	case DiagnoseHealthy:
		s.healthy++
	case DiagnoseWarning:
		s.warning++
	case DiagnoseIssue:
		s.issue++
	case DiagnoseFailed:
		s.failed++
	case DiagnoseInfo:
		s.info++
	}
}

func (s *doctorSummary) problems() int { return s.issue + s.failed }

// Severity aliases over the shared palette (see colors.go), used by the
// per-check lines and the summary tally.
const (
	colorHealthy = colorGreen
	colorWarning = colorYellow
	colorIssue   = colorRed
	colorInfo    = colorBlue
	colorSkipped = colorGrey
)

func iconAndColor(t DoctorDiagnoseType) (icon, color string) {
	switch t {
	case DiagnoseHealthy:
		return "✓", colorHealthy
	case DiagnoseWarning:
		return "⚠", colorWarning
	case DiagnoseInfo:
		return "ℹ", colorInfo
	default: // Issue / Failed
		return "✗", colorIssue
	}
}

func runCheckRecursive(check DoctorCheck, depth int, skipped bool, out *termenv.Output, sum *doctorSummary) {
	indent := strings.Repeat("  ", depth)

	if skipped {
		sum.skipped++
		fmt.Printf(
			"%s- %s %s: %s\n",
			indent,
			out.String("·").Foreground(out.Color(colorSkipped)),
			check.Name(),
			out.String("skipped (blocked by a failing check above)").Foreground(out.Color(colorSkipped)),
		)
		for _, sub := range check.SubChecks() {
			runCheckRecursive(sub, depth+1, true, out, sum)
		}
		return
	}

	diag := check.Run()
	sum.add(diag.Type)

	icon, color := iconAndColor(diag.Type)
	fmt.Printf(
		"%s- %s %s: %s\n",
		indent,
		out.String(icon).Foreground(out.Color(color)),
		check.Name(),
		out.String(diag.Desc).Foreground(out.Color(color)),
	)
	if diag.Fix != "" {
		fmt.Printf("%s  ↳ fix: %s\n", indent, diag.Fix)
	}

	// Issues/failures block dependent sub-checks; show them as skipped so the
	// summary stays honest about what was not actually run.
	childSkipped := diag.Type != DiagnoseHealthy && diag.Type != DiagnoseWarning && diag.Type != DiagnoseInfo
	for _, sub := range check.SubChecks() {
		runCheckRecursive(sub, depth+1, childSkipped, out, sum)
	}
}

func printSummary(out *termenv.Output, sum *doctorSummary) {
	fmt.Printf("## Summary\n\n")

	color := func(text, hex string) string {
		return out.String(text).Foreground(out.Color(hex)).String()
	}

	parts := []string{
		color(fmt.Sprintf("%d ok", sum.healthy), colorHealthy),
		color(fmt.Sprintf("%d warning%s", sum.warning, pluralize("", sum.warning)), colorWarning),
		color(fmt.Sprintf("%d issue%s", sum.problems(), pluralize("", sum.problems())), colorIssue),
	}
	if sum.info > 0 {
		parts = append(parts, color(fmt.Sprintf("%d info", sum.info), colorInfo))
	}
	if sum.skipped > 0 {
		parts = append(parts, color(fmt.Sprintf("%d skipped", sum.skipped), colorSkipped))
	}
	fmt.Println(strings.Join(parts, " · "))
	fmt.Println()

	switch {
	case sum.problems() > 0:
		fmt.Println(color(
			"Some checks failed. Fix the issues above and re-run `sesam doctor` - "+
				"a failing check can hide the ones nested under it.", colorIssue,
		))
	case sum.warning > 0:
		fmt.Println(color("Some warnings worth a look, but nothing blocking.", colorWarning))
	default:
		fmt.Println(color("Everything looks healthy.", colorHealthy))
	}
}

func RunDoctor(ctx context.Context, env doctorEnv) error {
	out := termenv.NewOutput(os.Stdout)

	fmt.Println("# sesam doctor")
	fmt.Println()
	fmt.Printf("Version: %s\n", env.version)
	fmt.Println()

	blueTip := out.String("Tip:").Foreground(out.Color(colorBlue))
	fmt.Printf("%s include this output when filing a bug report,\n", blueTip)
	fmt.Println("     just double check that anything sensitive is readacted.")
	fmt.Println()
	fmt.Printf("%s `sesam doctor` finds only issues related to installation issues.\n", blueTip)
	fmt.Println("     If you want integrity check then run `sesam verify`.")
	fmt.Println()

	var sum doctorSummary
	for _, cat := range buildCategories(ctx, env) {
		fmt.Printf("## %s\n\n", cat.title)
		for _, check := range cat.checks {
			runCheckRecursive(check, 0, false, out, &sum)
		}
		fmt.Println()
	}

	printSummary(out, &sum)

	if sum.problems() > 0 {
		// Exit non-zero so CI / scripts can gate on a clean install. The
		// message is empty: the summary above already explains what failed.
		return cli.Exit("", 1)
	}
	return nil
}

func HandleDoctor(ctx context.Context, cmd *cli.Command) error {
	version := cmd.Root().Version
	return RunDoctor(ctx, doctorEnv{
		sesamDir:      cmd.String("sesam-dir"),
		identityPaths: cmd.StringSlice("identity"),
		lockTimeout:   cmd.Duration("lock-timeout"),
		version:       version,
		versionShort:  firstField(version),
	})
}

// firstField returns the first whitespace-separated token of s, i.e. the bare
// version number at the head of the build banner.
func firstField(s string) string {
	if fields := strings.Fields(s); len(fields) > 0 {
		return fields[0]
	}
	return s
}

// --- small helpers ----------------------------------------------------------

func resolveSymlinks(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// expandHome resolves a leading "~" via repo.ExpandHomeDir, falling back to the
// raw path on error - good enough for the best-effort identity checks, which
// surface an unreadable path anyway.
func expandHome(path string) string {
	if expanded, err := repo.ExpandHomeDir(path); err == nil {
		return expanded
	}
	return path
}

// pluginBinaryForIdentityFile reads an identity file and, if its payload is an
// age plugin identity, returns the plugin binary name git/age would invoke.
func pluginBinaryForIdentityFile(path string) (string, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // user-supplied identity path
	if err != nil {
		return "", false
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return pluginBinaryForIdentity(line)
	}
	return "", false
}

// pluginBinaryForIdentity maps an `AGE-PLUGIN-<NAME>-1…` identity string to the
// `age-plugin-<name>` binary git/age would invoke.
func pluginBinaryForIdentity(line string) (string, bool) {
	if name, ok := core.PluginName(line); ok {
		return "age-plugin-" + name, true
	}
	return "", false
}
