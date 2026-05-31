package core

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPluginUINonInteractiveReturnsErrNoTTY(t *testing.T) {
	ui := NewNonInteractivePluginUI()
	cui := ui.ClientUI()

	err := cui.DisplayMessage("yubikey", "touch your key")
	require.ErrorIs(t, err, ErrNoTTY)

	_, err = cui.RequestValue("yubikey", "PIN?", true)
	require.ErrorIs(t, err, ErrNoTTY)

	_, err = cui.RequestValue("yubikey", "PIN?", false)
	require.ErrorIs(t, err, ErrNoTTY)

	_, err = cui.Confirm("yubikey", "ok?", "y", "n")
	require.ErrorIs(t, err, ErrNoTTY)

	// WaitTimer is fire-and-forget; just confirm it doesn't panic.
	cui.WaitTimer("yubikey")
}

func TestPluginUIInteractivePrompts(t *testing.T) {
	stderr := &bytes.Buffer{}
	ui := &PluginUI{
		interactive: true,
		stdin:       strings.NewReader("hello\n"),
		stderr:      stderr,
	}

	val, err := ui.ClientUI().RequestValue("yubikey", "what?", false)
	require.NoError(t, err)
	require.Equal(t, "hello", val)
	require.Contains(t, stderr.String(), "what?")
	require.Contains(t, stderr.String(), "yubikey")
}

func TestPluginUIInteractiveConfirmYes(t *testing.T) {
	stderr := &bytes.Buffer{}
	ui := &PluginUI{
		interactive: true,
		stdin:       strings.NewReader("yes\n"),
		stderr:      stderr,
	}

	ok, err := ui.ClientUI().Confirm("yubikey", "proceed?", "yes", "no")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPluginUIInteractiveConfirmNo(t *testing.T) {
	stderr := &bytes.Buffer{}
	ui := &PluginUI{
		interactive: true,
		stdin:       strings.NewReader("no\n"),
		stderr:      stderr,
	}

	ok, err := ui.ClientUI().Confirm("yubikey", "proceed?", "yes", "no")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestErrNoTTYIsStable(t *testing.T) {
	// Callers wrap/compare ErrNoTTY with errors.Is - keep this contract.
	require.True(t, errors.Is(ErrNoTTY, ErrNoTTY))
}
