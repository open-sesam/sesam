package commands

import (
	"context"

	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleReveal decrypts and verifies tracked secrets via Repo.RevealAll.
func HandleReveal(_ context.Context, _ *cli.Command, r *repo.Repo) error {
	return r.RevealAll()
}
