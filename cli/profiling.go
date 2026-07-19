package cli

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
)

// profileState holds the resources opened by --cpuprofile so the After hook can
// stop the profile and close the file. A sesam process runs exactly one command,
// so a single package-level instance is enough.
type profileState struct {
	cpuFile *os.File
}

// startProfiling begins CPU profiling into cpuPath when it is non-empty. Profiles
// are written to files, never to stdout, so this is safe for the git-driver
// commands. The returned state may be nil (no CPU profile requested).
func startProfiling(cpuPath string) (*profileState, error) {
	if cpuPath == "" {
		return &profileState{}, nil
	}

	//nolint:gosec
	f, err := os.Create(cpuPath)
	if err != nil {
		return nil, fmt.Errorf("create cpu profile %q: %w", cpuPath, err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("start cpu profile: %w", err)
	}
	return &profileState{cpuFile: f}, nil
}

// stop ends any CPU profile started by startProfiling and, when memPath is set,
// writes a heap profile after a GC. Safe to call on a nil receiver.
func (p *profileState) stop(memPath string) error {
	if p != nil && p.cpuFile != nil {
		pprof.StopCPUProfile()
		if err := p.cpuFile.Close(); err != nil {
			return fmt.Errorf("close cpu profile: %w", err)
		}
	}

	if memPath != "" {
		//nolint:gosec
		f, err := os.Create(memPath)
		if err != nil {
			return fmt.Errorf("create mem profile %q: %w", memPath, err)
		}
		defer func() { _ = f.Close() }()

		runtime.GC() // materialize up-to-date allocation stats
		if err := pprof.WriteHeapProfile(f); err != nil {
			return fmt.Errorf("write heap profile: %w", err)
		}
	}

	return nil
}
