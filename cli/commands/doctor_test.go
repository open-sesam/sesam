package commands

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
	"opensesam.org/sesam/repo"
)

func testUser(t *testing.T, name string, recipients ...string) repo.UserInfo {
	t.Helper()
	recps := make(core.Recipients, 0, len(recipients))
	for _, s := range recipients {
		r, err := core.ParseRecipient(s, core.NewNonInteractivePluginUI())
		require.NoError(t, err)
		recps = append(recps, r)
	}
	return repo.UserInfo{VerifiedUser: core.VerifiedUser{
		Membership: core.Membership{Name: name},
		Recps:      recps,
	}}
}

func TestPluginUsers(t *testing.T) {
	native, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	yubi := plugin.EncodeRecipient("yubikey", []byte{1, 2, 3})
	yubi2 := plugin.EncodeRecipient("yubikey", []byte{4, 5, 6})
	kms := plugin.EncodeRecipient("kms", []byte{7, 8, 9})

	got := pluginUsers([]repo.UserInfo{
		testUser(t, "carol", yubi, yubi2), // two keys, one plugin: listed once
		testUser(t, "alice", native.Recipient().String(), yubi),
		testUser(t, "ci", kms),
		testUser(t, "bob", native.Recipient().String()),
	})
	require.Equal(t, map[string][]string{
		"age-plugin-yubikey": {"alice", "carol"},
		"age-plugin-kms":     {"ci"},
	}, got)
}

func TestRecipientPluginsCheck(t *testing.T) {
	bin := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bin, "age-plugin-yubikey"), []byte("#!/bin/sh\n"), 0o700))
	t.Setenv("PATH", bin)

	for _, tc := range []struct {
		name     string
		facts    doctorRepoFacts
		wantType DoctorDiagnoseType
		wantDesc string
	}{
		{"repo not loaded", doctorRepoFacts{}, DiagnoseInfo, "no repo users"},
		{"no plugin recipients", doctorRepoFacts{loaded: true}, DiagnoseHealthy, "no recipient needs"},
		{
			"plugin installed",
			doctorRepoFacts{loaded: true, pluginUsers: map[string][]string{"age-plugin-yubikey": {"alice"}}},
			DiagnoseHealthy, "age-plugin-yubikey",
		},
		{
			"plugin missing",
			doctorRepoFacts{loaded: true, pluginUsers: map[string][]string{
				"age-plugin-yubikey": {"alice"},
				"age-plugin-kms":     {"ci", "deploy"},
			}},
			DiagnoseWarning, "age-plugin-kms (for ci, deploy)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			diag := recipientPluginsCheck(&tc.facts).Run()
			require.Equal(t, tc.wantType, diag.Type)
			require.Contains(t, diag.Desc, tc.wantDesc)
		})
	}
}
