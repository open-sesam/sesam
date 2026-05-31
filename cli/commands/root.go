package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleVerify verifies repository audit and crypt state.
func HandleVerify(_ context.Context, _ *cli.Command, r *repo.Repo) error {
	report, err := r.Verify(repo.VerifyOptions{Integrity: true})
	if err != nil {
		return err
	}

	if report.Integrity != nil && !report.Integrity.OK() {
		return fmt.Errorf("integrity check failed: %s", report.Integrity.String())
	}

	fmt.Println("verify ok")
	return nil
}

// HandleID identifies the current user from configured identities.
func HandleID(_ context.Context, _ *cli.Command, r *repo.Repo) error {
	whoami, err := r.Whoami()
	if err != nil {
		return err
	}

	fmt.Println(whoami)
	return nil
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
