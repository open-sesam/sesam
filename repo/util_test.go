package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/stretchr/testify/require"
	"opensesam.org/sesam/core"
)

type repoMockPassphraseProvider struct {
	passphrase []byte
	prompt     string
}

func (m *repoMockPassphraseProvider) ReadPassphrase(prompt string) ([]byte, error) {
	m.prompt = prompt
	return m.passphrase, nil
}

func (m *repoMockPassphraseProvider) PassphraseVerified([]byte, bool) {}

func encryptRepoIdentityForTest(t *testing.T, plaintext string, passphrase []byte) string {
	t.Helper()

	recipient, err := age.NewScryptRecipient(string(passphrase))
	require.NoError(t, err)
	// Tests only: drop age's ~1s default scrypt work factor (logN=18) so the
	// fixture encrypts and decrypts near-instantly. Real identities keep it.
	recipient.SetWorkFactor(10)

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	require.NoError(t, err)
	_, err = w.Write([]byte(plaintext))
	require.NoError(t, err)
	require.NoError(t, w.Close())

	return buf.String()
}

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
			got, err := ExpandHomeDir(tc.in)
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
		{
			name:    "same identity twice is deduplicated",
			paths:   []string{good.Path, good.Path},
			wantErr: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ids, err := loadIdentities(tc.paths, core.NewNonInteractivePluginUI())
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

func TestLoadIdentitiesWithEncryptedAgeIdentity(t *testing.T) {
	ageID, err := age.GenerateX25519Identity()
	require.NoError(t, err)

	passphrase := []byte("test-passphrase-123")
	key := encryptRepoIdentityForTest(t, ageID.String()+"\n", passphrase)
	path := filepath.Join(t.TempDir(), "encrypted.age")
	require.NoError(t, os.WriteFile(path, []byte(key), 0o600))

	provider := &repoMockPassphraseProvider{passphrase: passphrase}
	ids, err := loadIdentitiesWith(
		[]string{path},
		func(keyFingerprint string) core.PassphraseProvider {
			require.Equal(t, core.KeyFingerprint([]byte(key)), keyFingerprint)
			return provider
		},
		core.NewNonInteractivePluginUI(),
	)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.Equal(t, []string{ageID.Recipient().String()}, ids.RecipientStrings())
	require.Contains(t, provider.prompt, "sesam")
	require.Contains(t, provider.prompt, filepath.Base(path))
	require.Contains(t, provider.prompt, core.KeyFingerprint([]byte(key)))
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
