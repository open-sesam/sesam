package commands

import (
	"context"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleListSecrets prints tracked secret metadata.
func HandleListSecrets(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	secrets, err := r.ListSecrets()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		sort.Slice(secrets, func(i, j int) bool {
			return secrets[i].RevealedPath < secrets[j].RevealedPath
		})

		for i := range secrets {
			secrets[i].AccessGroups = sortedGroups(secrets[i].AccessGroups)
		}

		return printJSON(secrets)
	}

	if len(secrets) == 0 {
		fmt.Println("no secrets")
		return nil
	}

	lines := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		groups := sortedGroups(secret.AccessGroups)
		lines = append(lines, fmt.Sprintf("%s\t%s", secret.RevealedPath, commaJoined(groups)))
	}

	sort.Strings(lines)
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "PATH\tGROUPS")
	for _, line := range lines {
		_, _ = fmt.Fprintln(tw, line)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("failed to flush list output: %w", err)
	}

	return nil
}

// HandleListUsers lists users, groups, and access bindings.
func HandleListUsers(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	users, err := r.ListUsers()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		sort.Slice(users, func(i, j int) bool {
			return users[i].Name < users[j].Name
		})

		for i := range users {
			users[i].Groups = sortedGroups(users[i].Groups)
		}

		return printJSON(users)
	}

	if len(users) == 0 {
		fmt.Println("no users")
		return nil
	}

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
