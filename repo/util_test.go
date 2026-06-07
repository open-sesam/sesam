package repo

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"filippo.io/age"
	"github.com/open-sesam/sesam/core"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestExpandHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"tilde alone resolves to home", "~", home},
		{"tilde-slash prefix gets joined", "~/.config", filepath.Join(home, ".config")},
		{"absolute path is unchanged", "/etc/passwd", "/etc/passwd"},
		{"relative path is unchanged", "rel/path", "rel/path"},
		// `~user` form is intentionally NOT supported — only `~` and `~/...`.
		{"tilde-name is left alone", "~root/.bashrc", "~root/.bashrc"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := expandHomeDir(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestIdentityToUser(t *testing.T) {
	// Build two real x25519 identities so we have actual recipients to feed
	// into the keyring map.
	ageA, err := age.GenerateX25519Identity()
	require.NoError(t, err)
	ageB, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	parse := func(t *testing.T, ageID *age.X25519Identity) *core.Identity {
		t.Helper()
		id, err := core.ParseIdentity(ageID.String(), nil, core.NewNonInteractivePluginUI(), "")
		require.NoError(t, err)
		return id
	}
	parseRecp := func(t *testing.T, ageID *age.X25519Identity) *core.Recipient {
		t.Helper()
		recp, err := core.ParseRecipient(ageID.Recipient().String(), core.NewNonInteractivePluginUI())
		require.NoError(t, err)
		return recp
	}

	idA := parse(t, ageA)
	idB := parse(t, ageB)
	recpA := parseRecp(t, ageA)
	recpB := parseRecp(t, ageB)

	users := map[string]core.Recipients{
		"alice": {recpA},
		"bob":   {recpB},
	}

	cases := []struct {
		name     string
		loaded   core.Identities
		wantUser string
		wantErr  string
	}{
		{
			name:     "single matching identity",
			loaded:   core.Identities{idA},
			wantUser: "alice",
		},
		{
			name:     "multiple loaded, first match wins",
			loaded:   core.Identities{idB, idA},
			wantUser: "bob",
		},
		{
			name:    "no match",
			loaded:  core.Identities{},
			wantErr: "no loaded identity matches",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, picked, err := identityToUser(tc.loaded, users)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				require.Nil(t, picked)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantUser, user)
			require.NotNil(t, picked, "returned identity must be one of the loaded ones")
		})
	}
}

func TestLoadIdentities_FailureModes(t *testing.T) {
	good := writeTestIdentity(t, "good")

	cases := []struct {
		name    string
		paths   []string
		wantErr string
	}{
		{
			name:    "blank path entry",
			paths:   []string{""},
			wantErr: "missing identity path",
		},
		{
			name:    "non-existent file",
			paths:   []string{filepath.Join(t.TempDir(), "missing.age")},
			wantErr: "failed to read identity",
		},
		{
			name:    "happy path",
			paths:   []string{good.Path},
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids, err := loadIdentities(tc.paths, "sesam.test", core.NewNonInteractivePluginUI())
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				require.Nil(t, ids)
				return
			}
			require.NoError(t, err)
			require.Len(t, ids, 1)
		})
	}
}

func TestLoadIdentitiesKeyringOnlyUsesAskpass(t *testing.T) {
	for _, env := range []string{
		"SESAM_ASKPASS", "SESAM_ASKPASS_REQUIRED",
		"GIT_ASKPASS", "GIT_ASKPASS_REQUIRED",
		"SSH_ASKPASS", "SSH_ASKPASS_REQUIRED",
	} {
		t.Setenv(env, "")
	}

	passphrase := "from-askpass"
	t.Setenv("SESAM_ASKPASS", writeRepoAskpassScript(t, passphrase))

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	require.NoError(t, err)

	identityPath := filepath.Join(t.TempDir(), "encrypted-identity")
	require.NoError(t, os.WriteFile(identityPath, pem.EncodeToMemory(pemBlock), 0o600))

	ids, err := loadIdentitiesKeyringOnly(
		[]string{identityPath},
		"sesam.test."+t.Name(),
		core.NewNonInteractivePluginUI(),
	)
	require.NoError(t, err)
	require.Len(t, ids, 1)
}

func writeRepoAskpassScript(t *testing.T, output string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "askpass.cmd")
		err := os.WriteFile(path, []byte("@echo off\r\necho "+output+"\r\n"), 0o700)
		require.NoError(t, err)
		return path
	}

	path := filepath.Join(dir, "askpass")
	err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '"+output+"\\n'\n"), 0o700)
	require.NoError(t, err)
	return path
}

func TestSplitObjectPath(t *testing.T) {
	cases := []struct {
		name     string
		pathname string
		wantOk   bool
		wantDir  string
		wantPath string
	}{
		{
			name:     "worktree root",
			pathname: ".sesam/objects/secrets/token.sesam",
			wantOk:   true,
			wantDir:  ".",
			wantPath: "secrets/token",
		},
		{
			name:     "nested sesam dir",
			pathname: "subdir/.sesam/objects/secrets/token.sesam",
			wantOk:   true,
			wantDir:  "subdir",
			wantPath: "secrets/token",
		},
		{
			name:     "deep revealed path",
			pathname: ".sesam/objects/a/b/c/d.sesam",
			wantOk:   true,
			wantDir:  ".",
			wantPath: "a/b/c/d",
		},
		{
			name:     "missing .sesam suffix",
			pathname: ".sesam/objects/token",
			wantOk:   false,
		},
		{
			name:     "no objects segment",
			pathname: "outside/path.txt",
			wantOk:   false,
		},
		{
			name:     "completely unrelated",
			pathname: "",
			wantOk:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotDir, gotPath, ok := splitObjectPath(tc.pathname)
			require.Equal(t, tc.wantOk, ok)
			if !tc.wantOk {
				return
			}
			require.Equal(t, tc.wantDir, gotDir)
			require.Equal(t, tc.wantPath, gotPath)
		})
	}
}

func TestIsInitialized(t *testing.T) {
	cases := []struct {
		name    string
		setupFn func(t *testing.T, dir string)
		wantErr string
	}{
		{
			name:    "empty dir is not initialized",
			setupFn: func(t *testing.T, dir string) {},
		},
		{
			name: "existing sesam.yml blocks",
			setupFn: func(t *testing.T, dir string) {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "sesam.yml"), nil, 0o600))
			},
			wantErr: "already has sesam config",
		},
		{
			name: "existing .sesam dir blocks",
			setupFn: func(t *testing.T, dir string) {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, ".sesam"), 0o700))
			},
			wantErr: "already has sesam directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setupFn(t, dir)

			err := isInitialized(dir)
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
