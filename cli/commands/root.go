package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleID identifies the current user from configured identities.
func HandleID(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	whoami, err := r.Whoami()
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		users, err := r.ListUsers()
		if err != nil {
			return err
		}

		for _, user := range users {
			if user.Name == whoami {
				_ = printJSON(user)
				return nil
			}
		}

		return fmt.Errorf("%s not in user list?", whoami)
	}

	fmt.Println(whoami)
	return nil
}

func HandleKeyringClearCache(_ context.Context, _ *cli.Command) error {
	return core.DeleteAllCachedPassphrases()
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
