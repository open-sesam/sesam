package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-sesam/sesam/cli/repo"
	"github.com/urfave/cli/v3"
)

// HandleAdd adds a secret path to sesam metadata.
func HandleAdd(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	revealedPath := strings.TrimSpace(cmd.Args().First())
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	groups := normalizedGroups(cmd.StringSlice("group"))
	if len(groups) == 0 {
		return fmt.Errorf("missing group: pass --group at least once")
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		mgr, _, err := buildManagers(sesamDir, cmd.StringSlice("identity"))
		if err != nil {
			return err
		}
		defer func() {
			_ = mgr.AuditLog.Close()
		}()

		if err := repo.WithWorkingDir(sesamDir, func() error {
			return mgr.AddSecret(revealedPath, groups)
		}); err != nil {
			return fmt.Errorf("failed to add secret %q: %w", revealedPath, err)
		}

		return nil
	})
}

// HandleRemove removes a secret path from sesam metadata.
func HandleRemove(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	revealedPath := strings.TrimSpace(cmd.Args().First())
	if revealedPath == "" {
		return fmt.Errorf("missing secret path: pass a path argument")
	}

	return withRepoLock(sesamDir, 5*time.Second, func() error {
		mgr, _, err := buildManagers(sesamDir, cmd.StringSlice("identity"))
		if err != nil {
			return err
		}
		defer func() {
			_ = mgr.AuditLog.Close()
		}()

		if err := mgr.RemoveSecret(revealedPath); err != nil {
			return fmt.Errorf("failed to remove secret %q: %w", revealedPath, err)
		}

		return nil
	})
}

// HandleMove renames or relocates a tracked secret path.
func HandleMove(_ context.Context, _ *cli.Command) error {
	return handleStub("modify mv")
}

// HandleList prints tracked secret metadata.
func HandleList(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	auditLog, _, vstate, err := loadVerifiedState(sesamDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLog.Close()
	}()

	if len(vstate.Secrets) == 0 {
		fmt.Println("no secrets")
		return nil
	}

	secrets := make([]string, 0, len(vstate.Secrets))
	for _, secret := range vstate.Secrets {
		groups := append([]string(nil), secret.AccessGroups...)
		sort.Strings(groups)
		secrets = append(secrets, fmt.Sprintf("%s\tgroups=%s", secret.RevealedPath, commaJoined(groups)))
	}

	sort.Strings(secrets)
	for _, line := range secrets {
		fmt.Println(line)
	}

	return nil
}

func normalizedGroups(groups []string) []string {
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		out = append(out, group)
	}

	return out
}
