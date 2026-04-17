package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type UserManager struct {
	repoDir  string
	signer   Signer
	log      *AuditLog
	state    *VerifiedState
	signUser *VerifiedUser
}

func BuildUserManager(
	repoDir string,
	signer Signer,
	log *AuditLog,
	state *VerifiedState,
) (*UserManager, error) {
	vu, exists := state.UserExists(signer.UserName())
	if !exists {
		// How did we get here? Well, better double check than crash.
		return nil, errors.New("signing user does not exist - bug?")
	}

	return &UserManager{
		repoDir:  repoDir,
		signer:   signer,
		log:      log,
		state:    state,
		signUser: vu,
	}, nil
}

func (um *UserManager) TellUser(
	ctx context.Context,
	user, pubKeySpec string,
	groups []string,
) error {
	if err := validUserName(user); err != nil {
		return fmt.Errorf("invalid user name: %w", err)
	}

	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for telling users")
	}

	if _, exists := um.state.UserExists(user); exists {
		return fmt.Errorf("re-adding user not yet supported")
	}

	// core.ResolveRecipient and core.ParseRecipient only has to be done once per user add.
	// init means adding an initial user, so assume we get the public key here via the config or something.
	rawPubKey, err := ResolveRecipient(
		ctx,
		um.repoDir,
		pubKeySpec,
		CacheModeReadWrite,
	)
	if err != nil {
		return fmt.Errorf("failed to resolve recipient %s: %w", pubKeySpec, err)
	}

	recp, err := ParseRecipient(rawPubKey)
	if err != nil {
		return fmt.Errorf("failed to parse recipient %s: %w", rawPubKey, err)
	}

	newUserSigner, err := GenerateSignKey(
		um.repoDir,
		user,
		recp.Recipient,
	)
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}

	newUserSignKeyStr := MulticodeEncode(
		newUserSigner.PublicKey(),
		MhEd25519Pub,
	)
	return um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserTell{
			User:        user,
			Groups:      groups,
			PubKeys:     []string{recp.String()},
			SignPubKeys: []string{newUserSignKeyStr},
		}),
	)
}

func (um *UserManager) KillUsers(user string) error {
	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for killing users")
	}

	if err := um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserKill{
			User: user,
		}),
	); err != nil {
		return err
	}

	signKeyPath := filepath.Join(um.repoDir, ".sesam", "signkey", user+".age")
	if err := os.RemoveAll(signKeyPath); err != nil {
		return err
	}

	return nil
}
