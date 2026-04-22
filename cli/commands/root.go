package commands

import (
	"context"

	"github.com/urfave/cli/v3"
)

// HandleVerify verifies repository audit and crypt state.
func HandleVerify(_ context.Context, _ *cli.Command) error {
	return handleStub("verify")
}

// HandleID identifies the current user from configured identities.
func HandleID(_ context.Context, _ *cli.Command) error {
	return handleStub("id")
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

// HandleList lists users, groups, and access bindings.
func HandleList(_ context.Context, _ *cli.Command) error {
	return handleStub("list")
}

// HandleApply applies config changes to audit and metadata state.
func HandleApply(_ context.Context, _ *cli.Command) error {
	return handleStub("apply")
}
