package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleRun verifies selected secrets, closes the repository, and runs the
// requested command with them.
func HandleRun(ctx context.Context, cmd *cli.Command) (err error) {
	secretArgs := cmd.StringSlice("secret")
	envFileArgs := cmd.StringSlice("env-file")
	if !cmd.Bool("all") && len(secretArgs)+len(envFileArgs) == 0 {
		return fmt.Errorf("at least one --secret, --env-file, or --all is required")
	}

	arguments := cmd.Args().Slice()
	if len(arguments) == 0 || arguments[0] == "" {
		return fmt.Errorf("a command is required after --")
	}
	secrets := make([]repo.RunSecret, 0, len(secretArgs))
	paths := make([]string, 0, len(secretArgs))
	for _, arg := range secretArgs {
		name, path, ok := strings.Cut(arg, "=")
		if !ok {
			name, path = "", arg
		}
		if path == "" || ok && name == "" {
			return fmt.Errorf("--secret %q must be path or VARIABLE=path", arg)
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
		All:         cmd.Bool("all"),
		Secrets:     secrets,
		EnvFiles:    envFiles,
		EnvPatterns: cmd.StringSlice("env-pattern"),
	})
	if err != nil {
		return err
	}
	// The lock must be gone before the command starts: it may run for hours and
	// may itself call sesam against the same repository.
	if err := r.Close(); err != nil {
		return fmt.Errorf("close repo before running command: %w", err)
	}
	return prepared.Run(ctx, repo.RunCommand{Path: target, Args: arguments, Env: inheritedEnv})
}
