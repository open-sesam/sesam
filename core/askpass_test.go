package core

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func clearAskpassEnv(t *testing.T) {
	t.Helper()
	for _, env := range askpassEnvs {
		t.Setenv(env.Command, "")
		t.Setenv(env.Required, "")
	}
}

func writeAskpassScript(t *testing.T, name, output string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, name+".cmd")
		err := os.WriteFile(path, []byte("@echo off\r\necho "+output+"\r\n"), 0o700)
		require.NoError(t, err)
		return path
	}

	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '"+output+"\\n'\n"), 0o700)
	require.NoError(t, err)
	return path
}

func TestAskpassProviderUsesConfiguredCommand(t *testing.T) {
	clearAskpassEnv(t)
	t.Setenv("SESAM_ASKPASS", writeAskpassScript(t, "sesam-askpass", "from-sesam"))

	got, err := (&AskpassProvider{}).ReadPassphrase("Passphrase: ")
	require.NoError(t, err)
	require.Equal(t, []byte("from-sesam"), got)
}

func TestAskpassProviderEnvOrder(t *testing.T) {
	clearAskpassEnv(t)
	t.Setenv("SESAM_ASKPASS", writeAskpassScript(t, "sesam-askpass", "from-sesam"))
	t.Setenv("GIT_ASKPASS", writeAskpassScript(t, "git-askpass", "from-git"))
	t.Setenv("SSH_ASKPASS", writeAskpassScript(t, "ssh-askpass", "from-ssh"))

	got, err := (&AskpassProvider{}).ReadPassphrase("Passphrase: ")
	require.NoError(t, err)
	require.Equal(t, []byte("from-sesam"), got)
}

func TestAskpassProviderNeverFallsBack(t *testing.T) {
	clearAskpassEnv(t)
	t.Setenv("SESAM_ASKPASS", writeAskpassScript(t, "sesam-askpass", "from-sesam"))
	t.Setenv("SESAM_ASKPASS_REQUIRED", "never")

	fallback := &mockPassphraseProvider{passphrase: []byte("from-fallback")}
	got, err := (&AskpassProvider{Fallback: fallback}).ReadPassphrase("Passphrase: ")
	require.NoError(t, err)
	require.Equal(t, []byte("from-fallback"), got)
	require.True(t, fallback.called)
}

func TestAskpassProviderForceRequiresCommand(t *testing.T) {
	clearAskpassEnv(t)
	t.Setenv("SESAM_ASKPASS_REQUIRED", "force")

	fallback := &mockPassphraseProvider{passphrase: []byte("from-fallback")}
	_, err := (&AskpassProvider{Fallback: fallback}).ReadPassphrase("Passphrase: ")
	require.ErrorIs(t, err, ErrAskpassUnavailable)
	require.False(t, fallback.called)
}

func TestAskpassProviderInvalidRequiredMode(t *testing.T) {
	clearAskpassEnv(t)
	t.Setenv("SESAM_ASKPASS_REQUIRED", "sometimes")

	_, err := (&AskpassProvider{}).ReadPassphrase("Passphrase: ")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid askpass required mode")
}
