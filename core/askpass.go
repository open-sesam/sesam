package core

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ErrAskpassUnavailable is returned when askpass is required but no usable
// askpass command is configured.
var ErrAskpassUnavailable = errors.New("askpass unavailable")

// AskpassProvider reads passphrases from SESAM_ASKPASS, GIT_ASKPASS, or
// SSH_ASKPASS before delegating to an optional fallback provider.
type AskpassProvider struct {
	Fallback PassphraseProvider
}

type askpassEnv struct {
	Command  string
	Required string
}

var askpassEnvs = []askpassEnv{
	{Command: "SESAM_ASKPASS", Required: "SESAM_ASKPASS_REQUIRED"},
	{Command: "GIT_ASKPASS", Required: "GIT_ASKPASS_REQUIRED"},
	{Command: "SSH_ASKPASS", Required: "SSH_ASKPASS_REQUIRED"},
}

func (app *AskpassProvider) ReadPassphrase(prompt string) ([]byte, error) {
	var (
		askpassRequired bool
		lastErr         error
	)

	for _, env := range askpassEnvs {
		mode, err := askpassMode(os.Getenv(env.Required))
		if err != nil {
			return nil, err
		}
		if mode == "never" {
			continue
		}
		if mode == "force" {
			askpassRequired = true
		}

		command := strings.TrimSpace(os.Getenv(env.Command))
		if command == "" {
			continue
		}

		passphrase, err := runAskpass(command, prompt)
		if err == nil {
			return passphrase, nil
		}
		lastErr = fmt.Errorf("%s failed: %w", env.Command, err)
		if mode == "force" {
			return nil, lastErr
		}
	}

	if askpassRequired {
		return nil, fmt.Errorf("%w: no askpass command configured", ErrAskpassUnavailable)
	}
	if app != nil && app.Fallback != nil {
		return app.Fallback.ReadPassphrase(prompt)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrAskpassUnavailable
}

func askpassMode(raw string) (string, error) {
	switch mode := strings.ToLower(strings.TrimSpace(raw)); mode {
	case "", "prefer":
		return "prefer", nil
	case "never", "force":
		return mode, nil
	default:
		return "", fmt.Errorf("invalid askpass required mode %q", raw)
	}
}

func runAskpass(command, prompt string) ([]byte, error) {
	out, err := exec.Command(command, prompt).Output()
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(out, "\r\n"), nil
}
