package commands

import (
	"context"

	"opensesam.org/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleOpen decrypts and verifies tracked secrets via Repo.RevealAll.
func HandleOpen(_ context.Context, _ *cli.Command, r *repo.Repo) error {
	return r.RevealAll()
}
