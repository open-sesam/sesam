package commands

import (
	"context"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/repo"
)

// HandleOpen decrypts and verifies tracked secrets via Repo.RevealAll.
func HandleOpen(_ context.Context, _ *cli.Command, r *repo.Repo) error {
	return r.RevealAll()
}
