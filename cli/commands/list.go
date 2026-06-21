package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleListSecrets prints tracked secret metadata.
func HandleListSecrets(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	secrets, err := r.ListSecrets(cmd.StringArgs("dir"))
	if err != nil {
		return err
	}

	sort.Slice(secrets, func(i, j int) bool {
		return secrets[i].RevealedPath < secrets[j].RevealedPath
	})
	for i := range secrets {
		secrets[i].AccessGroups = sortedGroups(secrets[i].AccessGroups)
	}

	if cmd.Bool("json") {
		return printJSON(secrets)
	}

	if len(secrets) == 0 {
		fmt.Println("no secrets")
		return nil
	}

	// TODO: Pull in config description in here.
	t := newTable("Secrets", "Path", "Access Groups")
	for _, secret := range secrets {
		t.AppendRow([]any{
			secret.RevealedPath,
			commaJoined(secret.AccessGroups),
		})
	}
	t.AppendFooter([]any{"", fmt.Sprintf("%d secrets", len(secrets))})
	t.Render()

	return nil
}

// HandleListUsers lists users, groups, and access bindings.
func HandleListUsers(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	users, err := r.ListUsers()
	if err != nil {
		return err
	}

	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})
	for i := range users {
		users[i].Groups = sortedGroups(users[i].Groups)
	}

	if cmd.Bool("json") {
		return printJSON(users)
	}

	if len(users) == 0 {
		fmt.Println("no users")
		return nil
	}

	t := newTable("Users", "User", "Admin", "Groups", "Recipients", "Signing Keys")
	for _, user := range users {
		t.AppendRow([]any{
			user.Name,
			adminMark(user.IsAdmin()),
			commaJoined(user.Groups),
			multiline(elideKeys(recipientKeys(user.Recps))),
			multiline(elideKeys([]string{user.SignPubKey})),
		})
	}
	t.AppendFooter([]any{"", "", "", "", fmt.Sprintf("%d users", len(users))})
	t.Render()

	return nil
}

func sortedGroups(groups []string) []string {
	out := append([]string(nil), groups...)
	sort.Strings(out)
	return out
}

// recipientKeys returns the public key strings for a user's recipients.
func recipientKeys(recps core.Recipients) []string {
	keys := make([]string, 0, len(recps))
	for _, recp := range recps {
		keys = append(keys, recp.String())
	}
	return keys
}

// keyDisplayLen is how many leading characters of a public key we show.
// Keys share a fixed prefix (age1… / a version tag), so this needs to be
// long enough to reach the bytes that actually differ between keys.
const keyDisplayLen = 50

// elideKeys truncates each key to a short, still-distinguishable prefix so
// the table stays narrow. Full keys are available via `list --json`.
func elideKeys(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		if len(key) > keyDisplayLen {
			key = key[:keyDisplayLen] + "…"
		}
		out = append(out, key)
	}
	return out
}

// multiline stacks values one per line so a single cell can hold several
// keys while keeping each row aligned. Empty input renders as a dash.
func multiline(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, "\n")
}

func adminMark(isAdmin bool) string {
	if isAdmin {
		return "✓"
	}
	return ""
}
