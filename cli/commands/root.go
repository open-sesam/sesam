package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleVerify verifies repository audit and crypt state.
func HandleVerify(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), func(mgr *runtimeManagers) error {
		report := core.VerifyIntegrity(
			sesamDir,
			mgr.Secret.State,
			mgr.Secret.Keyring,
		)
		if !report.OK() {
			return fmt.Errorf("integrity check failed: %s", report.String())
		}

		fmt.Println("verify ok")
		return nil
	})
}

// HandleID identifies the current user from configured identities.
func HandleID(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), func(mgr *runtimeManagers) error {
		whoami, _, err := identityToUser(
			mgr.Secret.Identities,
			mgr.Secret.Keyring.ListUsers(),
		)
		if err != nil {
			return fmt.Errorf("failed to identify current user: %w", err)
		}

		fmt.Println(whoami)
		return nil
	})
}

// HandleServer starts the optional sesam API server.
func HandleServer(_ context.Context, _ *cli.Command) error {
	return handleStub("server")
}

// HandleLog prints audit-log history.
func HandleLog(_ context.Context, _ *cli.Command) error {
	return handleStub("log")
}

// HandleUndo reverts secret state to a prior revision.
func HandleUndo(_ context.Context, _ *cli.Command) error {
	return handleStub("undo")
}

// HandleListUsers lists users, groups, and access bindings.
func HandleListUsers(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	return withManagers(sesamDir, cmd.StringSlice("identity"), func(mgr *runtimeManagers) error {
		vstate := mgr.Secret.State
		users := append([]core.VerifiedUser(nil), vstate.Users...)
		sort.Slice(users, func(i, j int) bool {
			return users[i].Name < users[j].Name
		})

		for _, user := range users {
			groups := append([]string(nil), user.Groups...)
			sort.Strings(groups)
			fmt.Printf("%s\tgroups=%s\n", user.Name, commaJoined(groups))
		}

		return nil
	})
}

// HandleApply applies config changes to audit and metadata state.
func HandleApply(_ context.Context, _ *cli.Command) error {
	return handleStub("apply")
}

func commaJoined(values []string) string {
	if len(values) == 0 {
		return ""
	}

	var out strings.Builder
	out.WriteString(values[0])
	for _, v := range values[1:] {
		out.WriteString(",")
		out.WriteString(v)
	}

	return out.String()
}
