package commands

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeClipboard records what was written so the clear logic can be exercised
// without a display server or a subprocess.
type fakeClipboard struct {
	content  []byte
	writes   int
	readErr  error
	writeErr error
}

func (f *fakeClipboard) Write(_ context.Context, content []byte) error {
	if f.writeErr != nil {
		return f.writeErr
	}
	f.content = content
	f.writes++
	return nil
}

func (f *fakeClipboard) Read(_ context.Context) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.content, nil
}

func TestHashClipboardRoundtrip(t *testing.T) {
	tests := []struct {
		name    string
		hashed  string
		checked string
		want    bool
	}{
		{name: "match", hashed: "hunter2", checked: "hunter2", want: true},
		{name: "mismatch", hashed: "hunter2", checked: "hunter3", want: false},
		{name: "empty against value", hashed: "", checked: "hunter2", want: false},
		{name: "empty against empty", hashed: "", checked: "", want: true},
		{name: "prefix is not a match", hashed: "hunter2", checked: "hunter", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := hashClipboard([]byte(tc.hashed))
			require.NoError(t, err)

			got, err := matchClipboard([]byte(tc.checked), digest)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestHashClipboardIsSalted(t *testing.T) {
	first, err := hashClipboard([]byte("hunter2"))
	require.NoError(t, err)
	second, err := hashClipboard([]byte("hunter2"))
	require.NoError(t, err)

	require.NotEqual(t, first, second, "equal secrets must not produce equal digests")
}

func TestMatchClipboardMalformedDigest(t *testing.T) {
	tests := []struct {
		name   string
		digest string
	}{
		{name: "empty", digest: ""},
		{name: "too few fields", digest: "argon2id$1$65536$4$c2FsdA"},
		{name: "unknown scheme", digest: "bcrypt$1$65536$4$c2FsdA$a2V5"},
		{name: "bad time", digest: "argon2id$x$65536$4$c2FsdA$a2V5"},
		{name: "bad salt", digest: "argon2id$1$65536$4$!!!$a2V5"},
		{name: "empty key", digest: "argon2id$1$65536$4$c2FsdA$"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := matchClipboard([]byte("hunter2"), tc.digest)
			require.Error(t, err)
			require.False(t, ok)
		})
	}
}

func TestClearClipboard(t *testing.T) {
	secret := []byte("hunter2")

	t.Run("clears its own content", func(t *testing.T) {
		cb := &fakeClipboard{content: secret}
		matches := func(cur []byte) bool { return string(cur) == string(secret) }

		require.NoError(t, clearClipboard(t.Context(), cb, matches))
		require.Empty(t, cb.content)
	})

	t.Run("leaves foreign content alone", func(t *testing.T) {
		cb := &fakeClipboard{content: []byte("something the user copied")}
		matches := func(cur []byte) bool { return string(cur) == string(secret) }

		require.NoError(t, clearClipboard(t.Context(), cb, matches))
		require.Equal(t, "something the user copied", string(cb.content))
		require.Zero(t, cb.writes)
	})

	// The copy path strips the trailing newline of a secret file, so the
	// value read back must be normalized the same way before comparing.
	t.Run("ignores a trailing newline", func(t *testing.T) {
		cb := &fakeClipboard{content: []byte("hunter2\n")}
		matches := func(cur []byte) bool { return string(cur) == string(secret) }

		require.NoError(t, clearClipboard(t.Context(), cb, matches))
		require.Empty(t, cb.content)
	})
}

func TestCommandClipboardRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clipboard")
	cb := commandClipboard{
		copyCmd:  "cat > " + path,
		pasteCmd: "cat " + path,
	}

	require.NoError(t, cb.Write(t.Context(), []byte("hunter2")))
	got, err := cb.Read(t.Context())
	require.NoError(t, err)
	require.Equal(t, "hunter2", string(got))

	require.NoError(t, cb.Write(t.Context(), nil))
	got, err = cb.Read(t.Context())
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestNewClipboardBackend(t *testing.T) {
	tests := []struct {
		name     string
		copyCmd  string
		pasteCmd string
		wantErr  bool
		wantKind any
	}{
		{name: "both set", copyCmd: "true", pasteCmd: "true", wantKind: commandClipboard{}},
		{name: "only copy set", copyCmd: "true", wantErr: true},
		{name: "only paste set", pasteCmd: "true", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envClipboardCopyCmd, tc.copyCmd)
			t.Setenv(envClipboardPasteCmd, tc.pasteCmd)

			cb, err := newClipboardBackend()
			if tc.wantErr {
				require.Error(t, err)
				require.Nil(t, cb)
				return
			}

			require.NoError(t, err)
			require.IsType(t, tc.wantKind, cb)
		})
	}
}

func TestUnclipStatePath(t *testing.T) {
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	path, err := unclipStatePath()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(runtimeDir, "sesam", "unclip.json"), path)

	// Only the copying side may create the directory; the unclip child has
	// to cope with it being gone.
	require.NoDirExists(t, filepath.Dir(path))
}

func TestCopyToClipboardRefusesEmpty(t *testing.T) {
	t.Setenv(envClipboardCopyCmd, "cat >/dev/null")
	t.Setenv(envClipboardPasteCmd, "true")

	require.Error(t, copyToClipboard(t.Context(), nil, false, 0))
	require.Error(t, copyToClipboard(t.Context(), []byte("\n\n"), false, 0))
}
