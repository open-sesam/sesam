package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type UserManager struct {
	sesamDir string
	signer   Signer
	log      *AuditLog
	state    *VerifiedState
	signUser *VerifiedUser
}

func BuildUserManager(
	sesamDir string,
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
		sesamDir: sesamDir,
		signer:   signer,
		log:      log,
		state:    state,
		signUser: vu,
	}, nil
}

func (um *UserManager) TellUser(
	ctx context.Context,
	user string, pubKeySpecs []string,
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

	recps, err := ParseAndResolveRecipients(ctx, pubKeySpecs)
	if err != nil {
		return err
	}

	// audit key needs to be accessible by all recipients, including the new user.
	// FeedEntry hasn't run yet so the new user isn't in the keyring; add explicitly.
	allRecps := append(AllRecipients(um.state.keyring), recps...)
	if err := um.log.WriteAuditKey(allRecps); err != nil {
		return err
	}

	newUserSigner, err := GenerateSignKey(
		um.sesamDir,
		user,
		recps.AgeRecipients(),
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
			PubKeys:     recps.UserPubKeys(),
			SignPubKeys: []string{newUserSignKeyStr},
		}),
	)
}

func (um *UserManager) ShowUser(user string, dst io.Writer) (bool, error) {
	u, ok := um.state.UserExists(user)
	if ok {
		// convert u to json
		enc := json.NewEncoder(dst)
		enc.SetIndent("", "  ")
		return true, enc.Encode(u)
	}

	return false, nil
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

	signKeyPath := filepath.Join(um.sesamDir, ".sesam", "signkeys", user+".age")
	if err := os.RemoveAll(signKeyPath); err != nil {
		return err
	}

	// audit log needs to be re-encrypted with a fresh key to keep out the deleted user.
	allRecps := AllRecipients(um.state.keyring)
	if err := um.log.RotateKey(um.signer, allRecps); err != nil {
		return err
	}

	return nil
}

// InitAdminUser has to be called on init to create the initial user.
func InitAdminUser(
	ctx context.Context,
	sesamDir, user string, pubKeySpecs []string,
) (Signer, *AuditLog, error) {
	recps, err := ParseAndResolveRecipients(ctx, pubKeySpecs)
	if err != nil {
		return nil, nil, err
	}

	signer, err := GenerateSignKey(
		sesamDir,
		user,
		recps.AgeRecipients(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate signing key: %w", err)
	}

	signKeyStr := MulticodeEncode(signer.PublicKey(), MhEd25519Pub)
	auditLog, err := InitAuditLog(sesamDir, signer, recps, DetailUserTell{
		User:        signer.UserName(),
		Groups:      []string{"admin"},
		PubKeys:     recps.UserPubKeys(),
		SignPubKeys: []string{signKeyStr},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init audit log: %w", err)
	}

	return signer, auditLog, nil
}
