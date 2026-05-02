package core

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func integritySetup(t *testing.T) (*SecretManager, *VerifiedState) {
	t.Helper()
	mgr := testSecretManager(t)
	secret := testSecret(t, mgr, "secrets/db", "password123")
	sig, err := secret.Seal("testuser")
	require.NoError(t, err)

	state := &VerifiedState{
		Secrets: []VerifiedSecret{
			{RevealedPath: "secrets/db", AccessGroups: []string{"admin"}},
		},
		LastSealRootHash: buildRootHash([]*secretSignature{sig}),
	}

	return mgr, state
}

func TestIntegrityAllGood(t *testing.T) {
	mgr, state := integritySetup(t)
	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.True(t, report.OK(), "expected no errors, got: %s", report.String())
}

func TestIntegrityMissingFile(t *testing.T) {
	mgr, state := integritySetup(t)
	os.Remove(mgr.cryptPath("secrets/db"))

	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.False(t, report.OK(), "should detect missing .sesam file")
}

func TestIntegrityCorruptedAgeFile(t *testing.T) {
	mgr, state := integritySetup(t)
	require.NoError(t, os.WriteFile(mgr.cryptPath("secrets/db"), []byte("corrupted"), 0o600))

	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.False(t, report.OK(), "should detect hash mismatch")
}

func TestIntegrityExtraFile(t *testing.T) {
	mgr, state := integritySetup(t)

	// Seal an extra secret that is not registered in state.
	extra := testSecret(t, mgr, "secrets/extra", "extra-content")
	_, err := extra.Seal("testuser")
	require.NoError(t, err)

	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.False(t, report.OK(), "should detect extra .sesam file not in state")
}

func TestIntegrityRootHashMismatch(t *testing.T) {
	mgr, state := integritySetup(t)
	state.LastSealRootHash = "wrong-hash"

	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.False(t, report.OK(), "should detect root hash mismatch")
}

func TestIntegrityNoSeal(t *testing.T) {
	mgr, state := integritySetup(t)
	state.LastSealRootHash = ""

	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.True(t, report.OK(), "should pass when no seal, got: %s", report.String())
}

func TestIntegrityMultipleSecrets(t *testing.T) {
	mgr := testSecretManager(t)

	var sigs []*secretSignature
	var secrets []VerifiedSecret
	for _, p := range []string{"secrets/a", "secrets/b", "secrets/c"} {
		s := testSecret(t, mgr, p, "content-"+p)
		sig, err := s.Seal("testuser")
		require.NoError(t, err)
		sigs = append(sigs, sig)
		secrets = append(secrets, VerifiedSecret{RevealedPath: p, AccessGroups: []string{"admin"}})
	}

	state := &VerifiedState{
		Secrets:          secrets,
		LastSealRootHash: buildRootHash(sigs),
	}

	report := VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.True(t, report.OK(), "all good with 3 secrets: %s", report.String())

	// Now corrupt one.
	require.NoError(t, os.WriteFile(mgr.cryptPath("secrets/b"), []byte("bad"), 0o600))
	report = VerifyIntegrity(mgr.SesamDir, state, mgr.Keyring)
	require.False(t, report.OK(), "should detect corruption in one of multiple secrets")
}

func TestIntegrityReportString(t *testing.T) {
	t.Run("no issues", func(t *testing.T) {
		r := &IntegrityReport{}
		require.Equal(t, "no issues", r.String())
		require.True(t, r.OK())
	})

	t.Run("with issues", func(t *testing.T) {
		r := &IntegrityReport{}
		r.add("secrets/x", "test error")
		require.False(t, r.OK())
		require.Contains(t, r.String(), "secrets/x")
		require.Contains(t, r.String(), "test error")
	})
}

func TestIntegrityErrorString(t *testing.T) {
	t.Run("with path", func(t *testing.T) {
		e := IntegrityError{RevealedPath: "secrets/x", Message: "bad"}
		require.Equal(t, "secrets/x: bad", e.Error())
	})

	t.Run("without path", func(t *testing.T) {
		e := IntegrityError{Message: "global error"}
		require.Equal(t, "global error", e.Error())
	})
}
