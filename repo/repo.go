package repo

import (
	"context"
	"io"

	"github.com/open-sesam/sesam/core"
)

type Repo struct{}

// TODO: Also git dir? if interactive or not?
func Load(sesamDir string) (*Repo, error) {
	return nil, nil
}

func (r *Repo) Close() error {
	return nil
}

// TODO: Option for aggressive clean
func (r *Repo) Clean(ctx context.Context) error {
	return nil
}

// TODO: Me might need to enricht the user type with config derived stuff like descriptions.
func (r *Repo) ListUsers() ([]*core.VerifiedUser, error) {
	return nil, nil
}

func (r *Repo) ListSecrets() ([]*core.VerifiedSecret, error) {
	return nil, nil
}

func (r *Repo) RevealAll() error {
	return nil
}

func (r *Repo) SealAll() error {
	return nil
}

func (r *Repo) Show(object string, out io.Writer) error {
	// TODO: For audit and secrets we can take a shortcut here... but should we?
	return nil
}

func (r *Repo) UserTell(user string, recipients []string, groups []string) error {
	return nil
}

func (r *Repo) UserKill(user string) error {
	return nil
}

func (r *Repo) SecretAdd(revealedPath string) error {
	return nil
}

func (r *Repo) SecretRemove(revealedPath string) error {
	return nil
}

type VerifyReport struct {
	// TODO: Fill out all the different types of verifications that we have.
}

func (r *Repo) Verify() (*VerifyReport, error) {
	return &VerifyReport{}, nil
}
