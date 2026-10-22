package commands

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

func guessUserNameFromForgeID(recps []string) (string, error) {
	for _, recp := range recps {
		for _, prefix := range core.SupportedForges {
			if strings.HasPrefix(recp, prefix+":") {
				_, user, _ := strings.Cut(recp, ":")
				slog.Info(fmt.Sprintf("guessed '--user %s' from %s", user, recp))
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

	// The "at least one group" rule is enforced where the resulting membership
	// is known: Stage.UserTell dispatches recipient-only/no-op updates for
	// existing users, and core rejects a brand-new user with no groups.
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
		return sealStage(cmd, r, s)
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
		return sealStage(cmd, r, s)
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
		return sealStage(cmd, r, s)
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
		return sealStage(cmd, r, s)
	})
}

func HandleUserRemoveRecipient(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	recipients := cmd.StringSlice("recipient")
	noSeal := cmd.Bool("no-seal")

	if cmd.Bool("all-except") {
		users, err := r.ListUsers()
		if err != nil {
			return err
		}

		if len(recipients) == 0 {
			return fmt.Errorf("--all-except needs at least one recipient not to delete")
		}

		// Specs like github:bob or file:// only match stored keys once resolved.
		root, err := os.OpenRoot(r.SesamDir())
		if err != nil {
			return err
		}
		defer func() { _ = root.Close() }()

		keep, err := core.ParseAndResolveRecipients(ctx, root, recipients, nil)
		if err != nil {
			return err
		}

		recipientsToDelete := []string{}
		for _, u := range users {
			if u.Name == user {
				// kick away all but the one mentioned:
				for _, recp := range u.Recps {
					if !slices.ContainsFunc(keep, func(k *core.Recipient) bool { return k.Equal(recp) }) {
						recipientsToDelete = append(recipientsToDelete, recp.String())
					}
				}

				recipients = recipientsToDelete
				break
			}
		}
	}

	if cmd.Bool("all-except") && len(recipients) == 0 {
		slog.Info("nothing to remove: the user only has the keys you kept", slog.String("user", user))
		return nil
	}

	return r.Update(func(s *repo.Stage) error {
		if err := s.UserRmRecipient(ctx, user, recipients); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return sealStage(cmd, r, s)
	})
}

func HandleUserRegenerateSignKey(_ context.Context, cmd *cli.Command, r *repo.Repo) error {
	user := cmd.String("user")
	noSeal := cmd.Bool("no-seal")

	return r.Update(func(s *repo.Stage) error {
		if err := s.UserRegenerateSignKey(user); err != nil {
			return err
		}
		if noSeal {
			return nil
		}
		return sealStage(cmd, r, s)
	})
}
