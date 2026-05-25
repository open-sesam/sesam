package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-sesam/sesam/core"
)

func deleteRevealedSecrets(sesamDir string, secrets []core.VerifiedSecret) error {
	for _, secret := range secrets {
		revealedPath := filepath.Join(sesamDir, secret.RevealedPath)
		if err := os.Remove(revealedPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to delete %s: %w", secret.RevealedPath, err)
		}
	}

	return nil
}
