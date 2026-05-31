package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleListSecrets prints tracked secret metadata.
func HandleListSecrets(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	auditLog, _, vstate, err := loadVerifiedState(sesamDir, cmd.StringSlice("identity"), core.NewInteractivePluginUI())
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLog.Close()
	}()

	if cmd.Bool("json") {
		secrets := append([]core.VerifiedSecret(nil), vstate.Secrets...)
		sort.Slice(secrets, func(i, j int) bool {
			return secrets[i].RevealedPath < secrets[j].RevealedPath
		})

		for i := range secrets {
			secrets[i].AccessGroups = sortedGroups(secrets[i].AccessGroups)
		}

		return printJSON(secrets)
	}

	if len(vstate.Secrets) == 0 {
		fmt.Println("no secrets")
		return nil
	}

	secrets := make([]string, 0, len(vstate.Secrets))
	for _, secret := range vstate.Secrets {
		groups := sortedGroups(secret.AccessGroups)
		secrets = append(secrets, fmt.Sprintf("%s\t%s", secret.RevealedPath, commaJoined(groups)))
	}

	sort.Strings(secrets)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PATH\tGROUPS")
	for _, line := range secrets {
		_, _ = fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush list output: %w", err)
	}

	return nil
}

// HandleListUsers lists users, groups, and access bindings.
func HandleListUsers(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := repo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	auditLog, _, vstate, err := loadVerifiedState(sesamDir, cmd.StringSlice("identity"), core.NewInteractivePluginUI())
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLog.Close()
	}()

	if cmd.Bool("json") {
		users := append([]core.VerifiedUser(nil), vstate.Users...)
		sort.Slice(users, func(i, j int) bool {
			return users[i].Name < users[j].Name
		})

		for i := range users {
			users[i].Groups = sortedGroups(users[i].Groups)
		}

		return printJSON(users)
	}

	if len(vstate.Users) == 0 {
		fmt.Println("no users")
		return nil
	}

	users := append([]core.VerifiedUser(nil), vstate.Users...)
	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "USER\tGROUPS")
	for _, user := range users {
		groups := sortedGroups(user.Groups)
		_, _ = fmt.Fprintf(tw, "%s\t%s\n", user.Name, commaJoined(groups))
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush user list output: %w", err)
	}

	return nil
}

func sortedGroups(groups []string) []string {
	out := append([]string(nil), groups...)
	sort.Strings(out)
	return out
}
