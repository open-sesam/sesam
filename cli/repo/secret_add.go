package repo

import (
	"os"

	"github.com/open-sesam/sesam/config"
)

// TODO: adding the secret to the secrets manager is still missing. For this, I probably need
// to adjust the "AddSecretDir" function to also return all newly added secrets as a secret struct

// AddSecret adds a single secret to the main sesam.yml or a directory + sub directories.
func AddSecret(configPath, path, name, secretType, description string, access []string) error {
	configRepo := config.NewConfigRepository()
	if err := configRepo.Load(configPath); err != nil {
		return err
	}

	if err := configRepo.Resolve(); err != nil {
		return err
	}

	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		if err := configRepo.AddSecretDir(path); err != nil {
			return err
		}
	} else {
		secret := config.Secret{
			SecretType:  config.SecretType(secretType),
			Name:        name,
			Path:        path,
			Access:      access,
			Description: description,
		}

		if err := configRepo.AddSecret(secret); err != nil {
			return err
		}
	}

	if err := configRepo.Save(); err != nil {
		return err
	}

	return nil
}
