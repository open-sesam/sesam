package commands

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/open-sesam/sesam/core"
)

func withManagers(sesamDir string, identityPaths []string, lockTimeout time.Duration, pluginUI *core.PluginUI, fn func(*runtimeManagers) error) error {
	return withRepoLock(sesamDir, lockTimeout, func() (err error) {
		mgr, err := buildManagers(sesamDir, identityPaths, pluginUI)
		if err != nil {
			return err
		}
		defer func() {
			closeErr := mgr.Close()
			if closeErr == nil {
				return
			}

			if err != nil {
				err = fmt.Errorf("failed to close managers: %w", closeErr)
				return
			}

			slog.Warn("encrypt: failed to close managers", slog.Any("error", closeErr))
		}()

		return fn(mgr)
	})
}

type runtimeManagers struct {
	Secret *core.SecretManager
	User   *core.UserManager

	auditLog *core.AuditLog
}

func (mgr *runtimeManagers) Close() error {
	if mgr == nil || mgr.auditLog == nil {
		return nil
	}

	err := mgr.auditLog.Close()
	if err != nil {
		return fmt.Errorf("failed to close audit log: %w", err)
	}

	return nil
}

// buildManagers initializes runtime state for non-init operations.
func buildManagers(sesamDir string, identityPath []string, pluginUI *core.PluginUI) (*runtimeManagers, error) {
	identities, err := loadIdentities(
		identityPath,
		"sesam.identity.runtime",
		pluginUI,
	)
	if err != nil {
		return nil, err
	}

	keyring := core.EmptyKeyring()

	auditLog, err := core.LoadAuditLog(sesamDir, identities)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit log: %w", err)
	}

	verifyStart := time.Now()
	vstate, err := core.Verify(auditLog, keyring, pluginUI)
	if err != nil {
		return nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	slog.Info("audit log verified", slog.Duration("duration", time.Since(verifyStart)))

	whoami, signIdentity, err := identityToUser(identities, keyring.ListUsers())
	if err != nil {
		return nil, fmt.Errorf("failed to map identity to user: %w", err)
	}

	slog.Info("resolved signer identity", slog.String("user", whoami))

	signer, err := core.LoadSignKey(sesamDir, whoami, signIdentity)
	if err != nil {
		return nil, fmt.Errorf("failed to load sign key for %s: %w", whoami, err)
	}

	secMgr, err := core.BuildSecretManager(
		sesamDir,
		identities,
		signer,
		keyring,
		auditLog,
		vstate,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build secret manager: %w", err)
	}

	usrMgr, err := core.BuildUserManager(
		sesamDir,
		signer,
		auditLog,
		vstate,
		secMgr,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build user manager: %w", err)
	}

	return &runtimeManagers{
		Secret:   secMgr,
		User:     usrMgr,
		auditLog: auditLog,
	}, nil
}
