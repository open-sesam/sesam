package commands

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/muesli/termenv"
	"github.com/urfave/cli/v3"
)

type DoctorDiagnoseType int

const (
	DiagnoseHealthy = DoctorDiagnoseType(iota)
	DiagnoseWarning
	DiagnoseIssue
	DiagnoseFailed
)

type DoctorDiagnosis struct {
	Type DoctorDiagnoseType
	Desc string
}

type DoctorCheck interface {
	Name() string
	Run() DoctorDiagnosis
	SubChecks() []DoctorCheck
}

type genericCheck struct {
	name      string
	run       func() DoctorDiagnosis
	subChecks []DoctorCheck
}

func (g *genericCheck) Name() string {
	return g.name
}

func (g *genericCheck) Run() DoctorDiagnosis {
	return g.run()
}

func (g *genericCheck) SubChecks() []DoctorCheck {
	return g.subChecks
}

// TODO: Factor out reading of git version as util.
var gitVersionCheck = &genericCheck{
	name: "git-version",
	run: func() DoctorDiagnosis {
		cmd := exec.Command("git", "--version")
		rawVersionFull, err := cmd.Output()
		if err != nil {
			return DoctorDiagnosis{
				Type: DiagnoseFailed,
				Desc: fmt.Sprintf("failed to read version: %v", err),
			}
		}

		lastSpace := bytes.LastIndexByte(rawVersionFull, ' ')
		if lastSpace < 0 {
			return DoctorDiagnosis{
				Type: DiagnoseFailed,
				Desc: fmt.Sprintf("malformed version: %s", rawVersionFull),
			}
		}

		rawVersion := rawVersionFull[lastSpace+1:]
		rawVersion = bytes.TrimSpace(rawVersion)
		parts := strings.SplitN(string(rawVersion), ".", 3)
		if len(parts) != 3 {
			return DoctorDiagnosis{
				Type: DiagnoseFailed,
				Desc: fmt.Sprintf("malformed version: %s", rawVersionFull),
			}
		}

		v1, err1 := strconv.Atoi(parts[0])
		v2, err2 := strconv.Atoi(parts[1])
		v3, err3 := strconv.Atoi(parts[2])

		if err1 != nil || err2 != nil || err3 != nil {
			return DoctorDiagnosis{
				Type: DiagnoseFailed,
				Desc: fmt.Sprintf("malformed version: %s", rawVersionFull),
			}
		}

		gitVersion := v1*1e6 + v2*1e3 + v3
		if gitVersion < 2_054_000 {
			return DoctorDiagnosis{
				Type: DiagnoseWarning,
				Desc: fmt.Sprintf("git < 2.54 - git config hooks will not be supported"),
			}
		}

		return DoctorDiagnosis{
			Type: DiagnoseHealthy,
			Desc: fmt.Sprintf("found %s (>= 2.54)", rawVersion),
		}
	},
}

var sesamInPathCheck = &genericCheck{
	name: "sesam-in-path",
	run: func() DoctorDiagnosis {
		sesamPath, err := exec.LookPath("sesam")
		if err != nil {
			return DoctorDiagnosis{
				Type: DiagnoseIssue,
				Desc: "failed to find sesam in PATH - needed by git integration",
			}
		}

		return DoctorDiagnosis{
			Type: DiagnoseHealthy,
			Desc: fmt.Sprintf("found at %s", sesamPath),
		}
	},
}

var gitBinaryCheck = &genericCheck{
	name: "git-binary-present",
	run: func() DoctorDiagnosis {
		gitPath, err := exec.LookPath("git")
		if err != nil {
			return DoctorDiagnosis{
				Type: DiagnoseIssue,
				Desc: "not found",
			}
		}

		return DoctorDiagnosis{
			Type: DiagnoseHealthy,
			Desc: fmt.Sprintf("found at %s", gitPath),
		}
	},
	subChecks: []DoctorCheck{
		gitVersionCheck,
		sesamInPathCheck,
	},
}

var rootChecks = []DoctorCheck{
	gitBinaryCheck,
}

func runCheckRecursive(ctx context.Context, check DoctorCheck, depth int, out *termenv.Output) {
	diag := check.Run()

	var runSub bool
	var icon, color string

	switch diag.Type {
	case DiagnoseIssue, DiagnoseFailed:
		icon, color = "x", "#FF5555"
	case DiagnoseWarning:
		runSub = true
		icon, color = "⚠", "#FFD000"
	case DiagnoseHealthy:
		runSub = true
		icon, color = "✓", "#00FF00"
	}

	fmt.Printf(
		"%s %s: %s\n",
		out.String(icon).Foreground(out.Color(color)),
		check.Name(),
		out.String(diag.Desc).Foreground(out.Color(color)),
	)

	if runSub {
		for _, sub := range check.SubChecks() {
			runCheckRecursive(ctx, sub, depth+1, out)
		}
	}
}

func RunDoctor(ctx context.Context) error {
	out := termenv.NewOutput(os.Stdout)

	for _, rootCheck := range rootChecks {
		runCheckRecursive(ctx, rootCheck, 0, out)
	}

	return nil
}

//    OS (linux fine, macos should be warned as "not tested yet, but should work", windows as issue)
//        What's GOOS in WSL?
//    is there a .sesam-dir?
//        Is it 0700?
//    sesam in PATH and thus reachable.
//        should be also the binary we're running.
//    SESAM_IDENTITY not set (or SESAM_ID)
//        additional check: can we access the identity?
//        can we resolve to a user? i.e. are we in the config?
//        if identity is a plugin, check if the age-plugin is installed.
//        identity file permissions (should be 0600),
//    askpass env vars being setup and
//    EDITOR or VISUAL being set (for sesam edit)
//    git is in PATH:
//        git version >= 2.54 (needed for git hooks)
//        git config setup correctly?
//            merge.sesam-merge.name + merge.sesam-merge.driver = sesam audit merge …
//            diff.sesam-diff.textconv = sesam show
//            alias.sesam
//            Hooks installed
//                pre-commit
//                post-commit
//    bash completion
//    gitignore ignoring all sealed files?
//    gitattributes correctly set up?
//    Are we on the last sesam version? (+ print version always)
//    Run verify additionally?
//
//=> Mention that bug report should contain a run of sesam doctor.
//=> Add --redacted option to not print identity?
//=> Group output in categories or in issue-type?
//=> Print ways to fix it, if possible.
//=> Ideally output is github markdown compatible.
//=> Print summary (including checks not being run) at the end. Say to re-run sesam doctor when there were issues, as they might block other checks.

func HandleDoctor(ctx context.Context, cmd *cli.Command) error {
	RunDoctor(ctx)
	return nil
}
