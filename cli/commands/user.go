package commands

import (
	"context"
	"fmt"
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
				fmt.Printf("guessed '--user %s' from %s\n", user, recp)
				return user, nil
			}
		}
	}

	return "", fmt.Errorf("failed to guess user name - please pass --user")
}

// HandleTell adds a user/group relation and updates access.
func HandleTell(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	recipients := cmd.StringSlice("recipient")
	groups := cmd.StringSlice("group")
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
		if err := s.UserTell(ctx, user, recipients, groups); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.SealAll()
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
		return s.SealAll()
	})
}

func HandleUserChangeGroups(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	groups := cmd.StringSlice("group")
	noSeal := cmd.Bool("no-seal")

	return r.Update(func(s *repo.Stage) error {
		if err := s.UserChangeGroups(user, groups); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return s.SealAll()
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
		return s.SealAll()
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
		return s.SealAll()
	})
}

func HandleUserRegenerateSignKey(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	return r.Update(func(s *repo.Stage) error {
		return s.UserRegenerateSignKey(user)
	})
}
