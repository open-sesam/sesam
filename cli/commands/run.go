package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"
	"golang.org/x/sys/unix"
	"opensesam.org/sesam/repo"
)

// HandleRun verifies selected secrets, prepares a child environment, closes
// the repository, and replaces sesam with the requested command.
func HandleRun(_ context.Context, cmd *cli.Command) (err error) {
	secretArgs := cmd.StringSlice("secret")
	envFileArgs := cmd.StringSlice("env-file")
	all := cmd.Bool("all")
	if all && len(secretArgs) > 0 {
		return fmt.Errorf("--all and --secret cannot be used together")
	}
	if !all && len(secretArgs)+len(envFileArgs) == 0 {
		return fmt.Errorf("at least one --secret, --env-file, or --all is required")
	}

	arguments := cmd.Args().Slice()
	if len(arguments) == 0 || arguments[0] == "" {
		return fmt.Errorf("a command is required after --")
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

	secrets, err := toRepoPaths(r.SesamDir(), secretArgs)
	if err != nil {
		return err
	}
	envFiles, err := toRepoPaths(r.SesamDir(), envFileArgs)
	if err != nil {
		return err
	}

	environment, err := r.PrepareRunEnvironment(repo.RunOptions{
		All:         all,
		Secrets:     secrets,
		EnvFiles:    envFiles,
		Environment: inheritedEnv,
		Arguments:   arguments,
	})
	if err != nil {
		return err
	}
	if err := r.Close(); err != nil {
		return fmt.Errorf("close repo before exec: %w", err)
	}

	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	if err := unix.Exec(target, arguments, environment); err != nil {
		return fmt.Errorf("exec command %q: %w", arguments[0], err)
	}
	return nil
}
