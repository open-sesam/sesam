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
	secMgr   *SecretManager
}

// BuildUserManager wires a UserManager.
func BuildUserManager(
	sesamDir string,
	signer Signer,
	log *AuditLog,
	state *VerifiedState,
	secMgr *SecretManager,
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
		secMgr:   secMgr,
	}, nil
}

func (um *UserManager) UserTell(
	ctx context.Context,
	user string, pubKeySpecs []string,
	groups []string,
) error {
	if err := ValidUserName(user); err != nil {
		return fmt.Errorf("invalid user name: %w", err)
	}

	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for telling users")
	}

	if _, exists := um.state.UserExists(user); exists {
		return fmt.Errorf("re-adding user not yet supported")
	}

	recps, err := ParseAndResolveRecipients(ctx, pubKeySpecs, um.state.pluginUI)
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
	if err := um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserTell{
			User:       user,
			Groups:     groups,
			PubKeys:    recps.UserPubKeys(),
			SignPubKey: newUserSignKeyStr,
		}),
	); err != nil {
		return err
	}

	return nil
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

func (um *UserManager) UserKill(user string) error {
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

func (um *UserManager) UserRename(oldName, newName string) error {
	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for renaming users")
	}

	if err := um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserRename{
			OldName: oldName,
			NewName: newName,
		}),
	); err != nil {
		return err
	}

	// TODO: Also not exactly atomic as an operation...
	return os.Rename(
		um.signKeyPath(oldName),
		um.signKeyPath(newName),
	)
}

func (um *UserManager) signKeyPath(user string) string {
	return filepath.Join(um.sesamDir, ".sesam", "signkeys", user+".age")
}

func (um *UserManager) UserChangeGroups(user string, groups []string) error {
	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for changing a user groups")
	}

	return um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserChangeGroups{
			User:      user,
			NewGroups: groups,
		}),
	)
}

func (um *UserManager) UserAddRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for adding recipients an user")
	}

	recps, err := ParseAndResolveRecipients(ctx, pubKeySpecs, um.state.pluginUI)
	if err != nil {
		return err
	}

	if err := um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserAddRecipients{
			User:    user,
			PubKeys: recps.UserPubKeys(),
		}),
	); err != nil {
		return err
	}

	// make sure new recipients can also decrypt the log.
	allRecps := AllRecipients(um.state.keyring)
	if err := um.log.WriteAuditKey(allRecps); err != nil {
		return err
	}

	signRecps := um.state.keyring.Recipients([]string{user})
	if len(signRecps) == 0 {
		return fmt.Errorf("found no recipients for user: %s", user)
	}

	return um.UserRegenerateSignKey(user)
}

func (um *UserManager) UserRmRecipient(ctx context.Context, user string, pubKeySpecs []string) error {
	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for removing recipients from a user")
	}

	toDeleteRecps, err := ParseAndResolveRecipients(ctx, pubKeySpecs, um.state.pluginUI)
	if err != nil {
		return err
	}

	if err := um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserRmRecipients{
			User:    user,
			PubKeys: toDeleteRecps.UserPubKeys(),
		}),
	); err != nil {
		return err
	}

	allRecps := AllRecipients(um.state.keyring)
	if err := um.log.RotateKey(um.signer, allRecps); err != nil {
		return err
	}

	// recipient changed, so the recipients for the private sign key changed.
	// as admin user we might not have access to it, so we have to give the user
	// a new signing key. It's cheap, so not a problem really.
	return um.UserRegenerateSignKey(user)
}

func (um *UserManager) UserRegenerateSignKey(user string) error {
	if !um.signUser.IsAdmin() {
		return fmt.Errorf("need to be admin for regnerating signing keys")
	}

	// Validate up front: GenerateSignKey writes a key file, so bail before any
	// disk I/O if the user is unknown (otherwise the empty recipient list fails
	// later with a confusing "no recipients" error).
	if _, exists := um.state.UserExists(user); !exists {
		return fmt.Errorf("user %s does not exist", user)
	}

	newRecps := um.state.keyring.Recipients([]string{user})
	signer, err := GenerateSignKey(
		um.sesamDir,
		user,
		newRecps.AgeRecipients(),
	)
	if err != nil {
		return fmt.Errorf("failed to generate signing key: %w", err)
	}

	signKeyStr := MulticodeEncode(signer.PublicKey(), MhEd25519Pub)

	if err := um.state.FeedEntry(
		um.signer,
		newAuditEntry(um.signer.UserName(), &DetailUserRegenerateSignKey{
			User:          user,
			NewSignPubKey: signKeyStr,
		}),
	); err != nil {
		return err
	}

	return nil
}

// InitAdminUser has to be called on init to create the initial user.
// pluginUI is used when any of pubKeySpecs is a plugin recipient; pass nil
// to default to a non-interactive UI.
func InitAdminUser(
	ctx context.Context,
	sesamDir, user string, pubKeySpecs []string,
	pluginUI *PluginUI,
) (Signer, *AuditLog, error) {
	recps, err := ParseAndResolveRecipients(ctx, pubKeySpecs, pluginUI)
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
		User:       signer.UserName(),
		Groups:     []string{"admin"},
		PubKeys:    recps.UserPubKeys(),
		SignPubKey: signKeyStr,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to init audit log: %w", err)
	}

	return signer, auditLog, nil
}
