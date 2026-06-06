package commands

import (
	"context"

	"github.com/open-sesam/sesam/config"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

// HandleOpen decrypts and verifies tracked secrets via Repo.RevealAll.
func HandleOpen(_ context.Context, _ *cli.Command, r *repo.Repo, configRepo *config.ConfigRepository) error {
	return r.RevealAll()
}
