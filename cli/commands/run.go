package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// ExitError carries how a command started by sesam run terminated so that the
// binary can reproduce that status for its own caller. Exactly one of Code and
// Signal is set.
type ExitError struct {
	Code   int
	Signal syscall.Signal
}

func (e *ExitError) Error() string {
	if e.Signal != 0 {
		return fmt.Sprintf("command terminated by signal %d (%s)", e.Signal, e.Signal)
	}
	return fmt.Sprintf("command exited with status %d", e.Code)
}

// Terminate uses the shell convention of 128+signal for signaled commands.
func (e *ExitError) Terminate() {
	if e.Signal == 0 {
		os.Exit(e.Code)
	}
	os.Exit(128 + int(e.Signal))
}

// HandleRun verifies selected secrets, prepares a child environment, closes the
// repository, and runs the requested command as a child process.
func HandleRun(ctx context.Context, cmd *cli.Command) (err error) {
	signals := runSignals()
	defer signal.Stop(signals)

	secretArgs := cmd.StringSlice("secret")
	envFileArgs := cmd.StringSlice("env-file")
	if len(secretArgs)+len(envFileArgs) == 0 {
		return fmt.Errorf("at least one --secret or --env-file is required")
	}

	arguments := cmd.Args().Slice()
	if len(arguments) == 0 || arguments[0] == "" {
		return fmt.Errorf("a command is required after --")
	}
	secrets := make([]repo.RunSecret, 0, len(secretArgs))
	paths := make([]string, 0, len(secretArgs))
	for _, arg := range secretArgs {
		name, path, ok := strings.Cut(arg, "=")
		if !ok || name == "" || path == "" {
			return fmt.Errorf("--secret %q must be VARIABLE=path", arg)
		}
		secrets = append(secrets, repo.RunSecret{Name: name})
		paths = append(paths, path)
	}
	inheritedEnv := os.Environ()
	target, err := exec.LookPath(arguments[0])
	if err != nil {
		return fmt.Errorf("find command %q using inherited PATH: %w", arguments[0], err)
	}

	r, err := repo.Load(
		cmd.String("sesam-dir"),
		cmd.StringSlice("identity"),
		repo.RepoOpts{
			Interactive:     true,
			AskpassProgram:  cmd.String("askpass"),
			AskpassRequired: askpassRequired(),
			LockTimeout:     cmd.Duration("lock-timeout"),
			VerifyMode:      repo.VerifyModeAll,
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := r.Close()
		if closeErr == nil {
			return
		}
		if err == nil {
			err = fmt.Errorf("close repo: %w", closeErr)
			return
		}
		slog.Warn("close repo failed", slog.Any("error", closeErr))
	}()

	paths, err = toRepoPaths(r.SesamDir(), paths)
	if err != nil {
		return err
	}
	for i, path := range paths {
		secrets[i].Path = path
	}
	envFiles, err := toRepoPaths(r.SesamDir(), envFileArgs)
	if err != nil {
		return err
	}

	prepared, err := r.PrepareRun(repo.RunOptions{
		Secrets:  secrets,
		EnvFiles: envFiles,
	})
	if err != nil {
		return err
	}
	filePaths := make([]string, len(prepared.Files))
	for i := range filePaths {
		filePaths[i] = fmt.Sprintf("/dev/fd/%d", 3+i)
	}
	environment, err := prepared.Environment(inheritedEnv, arguments, filePaths)
	if err != nil {
		return err
	}
	// The lock must be gone before the command starts: it may run for hours and
	// may itself call sesam against the same repository.
	if err := r.Close(); err != nil {
		return fmt.Errorf("close repo before running command: %w", err)
	}

	files := make([]*os.File, 0, len(prepared.Files))
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	for _, secret := range prepared.Files {
		file, err := runSecretFile(secret.Content)
		if err != nil {
			return fmt.Errorf("prepare file secret %q: %w", secret.Name, err)
		}
		files = append(files, file)
	}

	return runSupervised(ctx, runRequest{Path: target, Args: arguments, Env: environment, Files: len(files)}, files, signals)
}

// runSecretFile unlinks an empty file before writing any plaintext. Only the
// read-only descriptor is inherited; the kernel owns the file's lifetime.
func runSecretFile(content []byte) (_ *os.File, err error) {
	writer, err := os.CreateTemp("", "sesam-run-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = writer.Close() }()
	reader, err := os.Open(writer.Name())
	if err != nil {
		_ = os.Remove(writer.Name())
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = reader.Close()
		}
	}()
	if err := os.Remove(writer.Name()); err != nil {
		return nil, err
	}
	if err := writer.Chmod(0o400); err != nil {
		return nil, err
	}
	if _, err := writer.Write(content); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return reader, nil
}

// commandStatus translates the result of waiting into an ExitError describing
// how the command terminated, or into a plain error if waiting itself failed.
func commandStatus(name string, waitErr error) error {
	if waitErr == nil {
		return nil
	}

	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		return fmt.Errorf("wait for command %q: %w", name, waitErr)
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return &ExitError{Signal: status.Signal()}
	}
	return &ExitError{Code: exitErr.ExitCode()}
}
