package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAskpassRequired(t *testing.T) {
	t.Setenv("SESAM_ASKPASS_REQUIRED", "")
	t.Setenv("GIT_ASKPASS_REQUIRED", "")
	t.Setenv("SSH_ASKPASS_REQUIRED", "")
	require.Equal(t, "prefer", askpassRequired())

	t.Setenv("SSH_ASKPASS_REQUIRED", "force")
	require.Equal(t, "force", askpassRequired())

	t.Setenv("GIT_ASKPASS_REQUIRED", "never")
	require.Equal(t, "never", askpassRequired())

	t.Setenv("SESAM_ASKPASS_REQUIRED", "prefer")
	require.Equal(t, "prefer", askpassRequired())
}
