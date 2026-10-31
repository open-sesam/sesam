package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
)

type runChildState struct {
	PID  int
	PPID int
}

const runTestSecret = "a\x00\xffb\n"

func TestRunProcess(t *testing.T) {
	dir := t.TempDir()
	identity, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	key := filepath.Join(t.TempDir(), "identity.age")
	require.NoError(t, os.WriteFile(key, []byte(identity.String()), 0o600))
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TMPDIR=" + t.TempDir(),
		"SESAM_ID=" + key,
		"SESAM_DIR=" + dir,
	}
	if coverage := os.Getenv("GOCOVERDIR"); coverage != "" {
		env = append(env, "GOCOVERDIR="+coverage)
	}
	command := func(name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(t.Context(), name, args...)
		cmd.Dir = dir
		cmd.Env = env
		return cmd
	}
	for _, args := range [][]string{
		{"git", "init"},
		{"git", "config", "user.name", "Sesam Test"},
		{"git", "config", "user.email", "test@sesam.dev"},
		{"sesam", "init", "--user", "admin"},
	} {
		output, err := command(args[0], args[1:]...).CombinedOutput()
		require.NoError(t, err, "%s", output)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "raw.txt"), []byte(runTestSecret), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "vars.env"), []byte("BINARY='a\xffb'\nEMPTY=\n"), 0o600))
	output, err := command("sesam", "add", "raw.txt", "vars.env").CombinedOutput()
	require.NoError(t, err, "%s", output)
	require.NoError(t, os.Remove(filepath.Join(dir, "raw.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "vars.env")))

	for _, tc := range []struct {
		name   string
		script string
		code   int
	}{
		{name: "exit status", script: "exit 23", code: 23},
		{name: "signal exit status", script: "kill -KILL $$", code: 137},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := command("sesam", "run", "--secret", "RAW=raw.txt", "--", "sh", "-c", tc.script).Run()
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			status := exitErr.Sys().(syscall.WaitStatus)
			require.True(t, status.Exited(), "sesam should exit normally, not by signal")
			require.Equal(t, tc.code, status.ExitStatus())
		})
	}

	executable, err := os.Executable()
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		signals []syscall.Signal
		group   bool
	}{
		{name: "forward SIGTERM", signals: []syscall.Signal{syscall.SIGTERM}},
		{name: "forward SIGHUP", signals: []syscall.Signal{syscall.SIGHUP}},
		{name: "do not forward SIGINT", signals: []syscall.Signal{syscall.SIGINT, syscall.SIGTERM}},
		{name: "do not forward SIGQUIT", signals: []syscall.Signal{syscall.SIGQUIT, syscall.SIGTERM}},
		{name: "process group SIGINT", signals: []syscall.Signal{syscall.SIGINT}, group: true},
		{name: "parent SIGKILL", signals: []syscall.Signal{syscall.SIGKILL}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sesam", "run", "--secret", "RAW=raw.txt", "--env-file", "vars.env", "--", executable, "-test.run=^TestRunChild$")
			cmd.Dir = dir
			cmd.Env = append(append([]string(nil), env...), "SESAM_RUN_TEST_CHILD=1")
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			cmd.Stderr = os.Stderr
			reader, writer, err := os.Pipe()
			require.NoError(t, err)
			defer reader.Close()
			defer writer.Close()
			require.NoError(t, reader.SetReadDeadline(time.Now().Add(15*time.Second)))
			cmd.Stdout = writer
			require.NoError(t, cmd.Start())
			t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
			require.NoError(t, writer.Close())
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			decoder := json.NewDecoder(reader)
			var state runChildState
			require.NoError(t, decoder.Decode(&state))
			require.Positive(t, state.PID)
			require.Equal(t, cmd.Process.Pid, state.PPID, "command must be a direct child of sesam")
			target := cmd.Process.Pid
			if tc.group {
				target = -target
			}
			for i, sig := range tc.signals {
				require.NoError(t, syscall.Kill(target, sig))
				if i < len(tc.signals)-1 {
					select {
					case err := <-done:
						t.Fatalf("sesam exited after a signal it should not forward: %v", err)
					case <-time.After(100 * time.Millisecond):
					}
				}
			}
			var waitErr error
			select {
			case waitErr = <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var exitErr *exec.ExitError
			require.ErrorAs(t, waitErr, &exitErr)
			status := exitErr.Sys().(syscall.WaitStatus)
			sig := tc.signals[len(tc.signals)-1]
			if sig == syscall.SIGKILL {
				require.True(t, status.Signaled())
				require.Equal(t, syscall.SIGKILL, status.Signal())
				var orphan runChildState
				require.NoError(t, decoder.Decode(&orphan))
				require.Equal(t, state.PID, orphan.PID)
				require.Positive(t, orphan.PPID)
				require.NotEqual(t, state.PPID, orphan.PPID)
				return
			}
			require.True(t, status.Exited())
			require.Equal(t, 128+int(sig), status.ExitStatus())
			_, err = io.Copy(io.Discard, reader)
			require.NoError(t, err, "child should close its output when it exits")
			require.ErrorIs(t, syscall.Kill(state.PID, 0), syscall.ESRCH, "child must be reaped")
		})
	}
}

// TestRunChild runs only as the subprocess of TestRunProcess.
func TestRunChild(t *testing.T) {
	if os.Getenv("SESAM_RUN_TEST_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	path := os.Getenv("RAW")
	require.Equal(t, "/dev/fd/3", path)
	file := os.NewFile(3, "run-secret")
	require.NotNil(t, file)
	defer file.Close()
	info, err := file.Stat()
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o400), info.Mode().Perm())
	require.Zero(t, info.Sys().(*syscall.Stat_t).Nlink)
	_, err = file.Write([]byte("overwrite"))
	require.Error(t, err, "inherited secret must not be writable")
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, runTestSecret, string(content))
	require.Equal(t, "a\xffb", os.Getenv("BINARY"))
	empty, exists := os.LookupEnv("EMPTY")
	require.True(t, exists)
	require.Empty(t, empty)
	_, exists = os.LookupEnv("SESAM_SECRET_RAW_TXT")
	require.False(t, exists)

	parent := os.Getppid()
	encoder := json.NewEncoder(os.Stdout)
	require.NoError(t, encoder.Encode(runChildState{PID: os.Getpid(), PPID: parent}))
	for os.Getppid() == parent {
		time.Sleep(10 * time.Millisecond)
	}
	content, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, runTestSecret, string(content), "secret descriptor must remain readable after parent death")
	require.NoError(t, encoder.Encode(runChildState{PID: os.Getpid(), PPID: os.Getppid()}))
	time.Sleep(time.Hour)
}
