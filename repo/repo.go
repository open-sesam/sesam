package repo

import (
	"context"
	"io"

	"github.com/open-sesam/sesam/core"
)

// Repo is a handle to a sesam repo.
// It contains all high-level operation one can use.
type Repo struct{}

type LoadOptions struct {
	// Interactive should be true when we can talk through the user via the terminal.
	// TODO: later we should check things like ssh-askpass to allow password decryption
	// without running in the foreground.
	Interactive bool
}

// Init initializes a new sesam repository at ${sesamDir}/.sesam.
// The `intialUserName` will be used to create the first admin user using the identities that were given.
func Init(sesamDir string, intialUserName string, ids []string, opts LoadOptions) (*Repo, error) {
	return nil, nil
}

// Load loads an existing sesam repository at `sesamDir`.
func Load(sesamDir string, ids []string, opts LoadOptions) (*Repo, error) {
	return nil, nil
}

// Close will clean up all open resources.
func (r *Repo) Close() error {
	return nil
}

// Clean will delete all revealed files.
// If `aggressive` is true it will also delete files in the sesam repo that are not tracked by git.
// `checkFn` is called (if given) on each path that this function wants to delete.
// You can return (false, nil) to prohibit deleting it, (true, nil) to allow it.
// Any error returned by `checkFn` will cause Clean to stop.
func (r *Repo) Clean(ctx context.Context, aggressive bool, checkFn func(path string) (bool, error)) error {
	return nil
}

// TODO: Me might need to enricht the user type with config derived stuff like descriptions. Something for later.

// ListUsers returns a list of all users currently in the audit log.
func (r *Repo) ListUsers() ([]*core.VerifiedUser, error) {
	return nil, nil
}

// ListSecrets return a list of secrets currently managed by sesam.
func (r *Repo) ListSecrets() ([]*core.VerifiedSecret, error) {
	return nil, nil
}

// RevealAll will reveal all secrets
func (r *Repo) RevealAll() error {
	return nil
}

// SealAll takes all revealed content and encrypts it to the sealed storage.
func (r *Repo) SealAll() error {
	return nil
}

// Show will try to guess what `object` is and write a human readable presentation of it to `out`.
// This is simmilar to `git show` and will produce output that can be easily diffed.
func (r *Repo) Show(object string, out io.Writer) error {
	// TODO: For audit and secrets we can do not the full load...
	return nil
}

// UserTell adds the new user to the list of valid users. It will be in `groups`
// and the files he may access are encrypted with `recipients`.
// All secrets are immediately re-sealed.
func (r *Repo) UserTell(user string, recipients []string, groups []string) error {
	return nil
}

// UserKill removes `user` from the list of authenticated users.
// All secrets are immediately re-sealed.
func (r *Repo) UserKill(user string) error {
	return nil
}

// SecretAdd adds the secret at `revealedPath` to the secrets known by sesam.
// `revealedPath` can be a directory as well, then the operation is recursive.
// All secrets are immediately re-sealed. Pass multiple secrets if you want batching.
func (r *Repo) SecretAdd(revealedPaths []string) error {
	return nil
}

// SecretRemove removes the managed secret at `revealedPath`.
// All secrets are immediately re-sealed. Pass multiple secrets if you want batching.
func (r *Repo) SecretRemove(revealedPaths []string) error {
	return nil
}

type VerifyOptions struct {
	// Truncation checks if the audit log was truncated over the git history.
	Truncation bool

	// KeyReuse checks if different users re-use the same public keys.
	// This should be forbidden by logic in sesam while adding for a single user,
	// but someone could play dirty tricks (or we have a bug...)
	KeyReuse bool

	// ForgeCheck will check if the public keys on forge-side changed.
	ForgeCheck bool

	// Integrity checks the integrity of all files
	// and if they match the current seal's root hash.
	Integrity bool
}

type VerifyReport struct {
	// TODO: Fill out all the different types of verifications that we have.
	//       Requires merging a couple PRs still. Can be left empty for now.
}

// Verify will check the repositoryies state depending on what verification strategies are set.
// Some verfications are hard errors (i.e. when audit log could be decrypted or is inconsistent),
// which are returned as actual `err`.
//
// All other consistency checks will put their results in the returned report.
func (r *Repo) Verify(opts VerifyOptions) (*VerifyReport, error) {
	return &VerifyReport{}, nil
}

// Whoami returns the name of the current user determined by checking what identities were supplied.
func (r *Repo) Whoami() string {
	return ""
}
