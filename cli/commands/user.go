package commands

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/open-sesam/sesam/core"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func guessUserNameFromForgeID(recps []string) (string, error) {
	for _, recp := range recps {
		for _, prefix := range core.SupportedForges {
			if strings.HasPrefix(recp, prefix+":") {
				_, user, _ := strings.Cut(recp, ":")
				slog.Info(fmt.Sprintf("guessed '--user %s' from %s\n", user, recp))
				return user, nil
			}
		}
	}

	return "", fmt.Errorf("failed to guess user name - please pass --user")
}

// HandleTell adds a user/group relation and updates access.
func HandleTell(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	recipients := cmd.StringSlice("recipient")
	groups, additive, err := resolveGroups(cmd, false)
	if err != nil {
		return err
	}
	user := cmd.String("user")
	if user == "" {
		var err error
		user, err = guessUserNameFromForgeID(recipients)
		if err != nil {
			return err
		}
	}

	noSeal := cmd.Bool("no-seal")

	// tell + reseal commit atomically as a single .sesam swap.
	return r.Update(func(s *repo.Stage) error {
		if err := s.UserTell(ctx, user, recipients, groups, additive); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.Seal(cmd.Bool("seal-all"))
	})
}

func HandleKill(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	noSeal := cmd.Bool("no-seal")

	// kill + reseal commit atomically as a single .sesam swap.
	return r.Update(func(s *repo.Stage) error {
		if err := s.UserKill(user); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.Seal(cmd.Bool("seal-all"))
	})
}

func HandleUserChangeGroups(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	groups, additive, err := resolveGroups(cmd, true)
	if err != nil {
		return err
	}
	noSeal := cmd.Bool("no-seal")

	return r.Update(func(s *repo.Stage) error {
		if err := s.UserChangeGroups(user, groups, additive); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.Seal(cmd.Bool("seal-all"))
	})
}

func HandleRenameUser(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	oldName := cmd.StringArg("olduser")
	newName := cmd.StringArg("newuser")
	if oldName == "" || newName == "" {
		return fmt.Errorf("need <olduser> and <newuser>")
	}

	return r.Update(func(s *repo.Stage) error {
		return s.UserRename(oldName, newName)
	})
}

func HandleUserAddRecipient(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	recipients := cmd.StringSlice("recipient")
	noSeal := cmd.Bool("no-seal")

	return r.Update(func(s *repo.Stage) error {
		if err := s.UserAddRecipient(ctx, user, recipients); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.Seal(cmd.Bool("seal-all"))
	})
}

func HandleUserRemoveRecipient(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	recipients := cmd.StringSlice("recipient")
	noSeal := cmd.Bool("no-seal")

	return r.Update(func(s *repo.Stage) error {
		if err := s.UserRmRecipient(ctx, user, recipients); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.Seal(cmd.Bool("seal-all"))
	})
}

func HandleUserRegenerateSignKey(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	return r.Update(func(s *repo.Stage) error {
		return s.UserRegenerateSignKey(user)
	})
}
