package cli

import (
	"context"

	"github.com/open-sesam/sesam/cli/commands"
	"github.com/urfave/cli/v3"
)

// Main builds and runs the sesam CLI command tree.
//
// The command surface is intentionally broad, but only a subset is fully
// implemented right now. Unimplemented commands return explicit errors so the
// caller can detect feature gaps in scripts and tests.
func Main(args []string) error {
	app := &cli.Command{
		Name:  "sesam",
		Usage: "Manage encrypted secrets in git repositories",
		Flags: flagsGeneral,
		Commands: []*cli.Command{
			{
				Name:   "init",
				Flags:  flagsInit,
				Action: commands.HandleInit,
				Usage:  "Initialize sesam in the current repository",
			}, {
				Name:   "verify",
				Action: commands.HandleVerify,
				Usage:  "Verify sesam signatures and encryption state",
			}, {
				Name:   "id",
				Action: commands.HandleID,
				Usage:  "Identify the current user by age identity",
			}, {
				Name:   "seal",
				Flags:  flagsSeal,
				Action: commands.HandleSeal,
				Usage:  "Encrypt and sign changed secrets",
			}, {
				Name:   "reveal",
				Flags:  flagsReveal,
				Action: commands.HandleReveal,
				Usage:  "Decrypt all secrets available to the current user",
			}, {
				Name:   "server",
				Action: commands.HandleServer,
				Usage:  "Run the secret serving API",
			}, {
				Name:   "log",
				Action: commands.HandleLog,
				Usage:  "Show the audit log of secret changes",
			}, {
				Name:   "undo",
				Action: commands.HandleUndo,
				Usage:  "Restore secrets from an earlier revision",
			}, {
				Name:   "modify",
				Action: commands.HandleModify,
				Usage:  "Modify tracked secrets and metadata",
				Commands: []*cli.Command{
					{
						Name:   "add",
						Action: commands.HandleModifyAdd,
						Usage:  "Add a secret file or directory",
					}, {
						Name:   "rm",
						Action: commands.HandleModifyRemove,
						Usage:  "Remove a secret file or directory",
					}, {
						Name:   "mv",
						Action: commands.HandleModifyMove,
						Usage:  "Move a secret to a different path",
					}, {
						Name:   "ls",
						Action: commands.HandleModifyList,
						Usage:  "List known secrets and metadata",
					},
				},
			}, {
				Name:   "tell",
				Action: commands.HandleTell,
				Usage:  "Add a person to a group and re-encrypt affected files",
			}, {
				Name:   "kill",
				Action: commands.HandleKill,
				Usage:  "Remove a person from a group",
			}, {
				Name:   "list",
				Action: commands.HandleList,
				Usage:  "List persons, groups, and access",
			}, {
				Name:   "rotate",
				Action: commands.HandleRotate,
				Usage:  "Plan and execute secret rotation",
				Commands: []*cli.Command{
					{
						Name:   "plan",
						Action: commands.HandleRotatePlan,
						Usage:  "Show the rotation and exchange plan",
					}, {
						Name:   "exec",
						Action: commands.HandleRotateExec,
						Usage:  "Execute the planned rotation",
					}, {
						Name:   "todo",
						Action: commands.HandleRotateTodo,
						Usage:  "Show rotation tasks and follow-up status",
					},
				},
			},
		},
	}

	return app.Run(context.Background(), args)
}
