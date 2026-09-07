package repo

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRunSecretName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "postgres/backup/password.txt", want: "SESAM_SECRET_POSTGRES_BACKUP_PASSWORD_TXT"},
		{path: "a-Z_9.foo-bar", want: "SESAM_SECRET_A_Z_9_FOO_BAR"},
		{path: "café", want: "SESAM_SECRET_CAF__"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			require.Equal(t, tc.want, runSecretName(tc.path))
		})
	}
}

func TestParseDotenvValid(t *testing.T) {
	document := []byte(" \t# comment\r\nexport FOO = unquoted\r\nEMPTY=   \nSINGLE=' literal \\ # $HOME '\r\nDOUBLE=\"literal ' value\"\nSHELL=$(touch);`id`$HOME=a\n_NO9=ok")

	got, err := parseDotenv(document)
	require.NoError(t, err)
	require.Equal(t, []runEntry{
		{name: "FOO", value: []byte("unquoted")},
		{name: "EMPTY", value: []byte{}},
		{name: "SINGLE", value: []byte(" literal \\ # $HOME ")},
		{name: "DOUBLE", value: []byte("literal ' value")},
		{name: "SHELL", value: []byte("$(touch);`id`$HOME=a")},
		{name: "_NO9", value: []byte("ok")},
	}, got)
}

func TestParseDotenvInvalid(t *testing.T) {
	tests := []struct {
		name     string
		document string
		wantErr  string
	}{
		{name: "bare carriage return", document: "A=x\rB=y", wantErr: "carriage return"},
		{name: "missing assignment", document: "FOO", wantErr: "expected '='"},
		{name: "bad name start", document: "9FOO=x", wantErr: "invalid variable name"},
		{name: "bad name byte", document: "FOO.BAR=x", wantErr: "expected '='"},
		{name: "unquoted space", document: "FOO=two words", wantErr: "invalid byte"},
		{name: "unquoted trailing space", document: "FOO=value ", wantErr: "invalid byte"},
		{name: "unquoted tab", document: "FOO=two\twords", wantErr: "invalid byte"},
		{name: "unquoted quote", document: "FOO=a'b", wantErr: "invalid byte"},
		{name: "unquoted backslash", document: "FOO=a\\b", wantErr: "invalid byte"},
		{name: "inline comment", document: "FOO=value # comment", wantErr: "invalid byte"},
		{name: "unterminated quote", document: "FOO='value", wantErr: "unterminated"},
		{name: "quoted trailer", document: "FOO='value'junk", wantErr: "unexpected bytes"},
		{name: "quoted newline", document: "FOO='first\nsecond'", wantErr: "unterminated"},
		{name: "duplicate", document: "FOO=one\nFOO=two", wantErr: "duplicate variable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDotenv([]byte(tc.document))
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestPrepareRunEnvironmentRejectsSelectorDuplicates(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []string
		envFiles []string
		wantErr  string
	}{
		{name: "duplicate secret", secrets: []string{"a", "a"}, wantErr: "duplicate secret selector"},
		{name: "duplicate env file", envFiles: []string{"a", "a"}, wantErr: "duplicate env file selector"},
		{name: "same path in both modes", secrets: []string{"a"}, envFiles: []string{"a"}, wantErr: "both secret and env file"},
		{name: "noncanonical", secrets: []string{"./a"}, wantErr: "not a canonical"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareRunEnvironment(RunOptions{
				Secrets: tc.secrets, EnvFiles: tc.envFiles, Arguments: []string{"probe"},
			}, func(string) ([]byte, error) {
				return []byte("value"), nil
			})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestPrepareRunEnvironmentRejectsCollisions(t *testing.T) {
	tests := []struct {
		name       string
		opts       RunOptions
		plaintexts map[string]string
		wantErr    string
	}{
		{
			name:       "generated raw names",
			opts:       RunOptions{Secrets: []string{"a-b", "a_b"}},
			plaintexts: map[string]string{"a-b": "one", "a_b": "two"},
			wantErr:    "SESAM_SECRET_A_B",
		},
		{
			name:       "dotenv within document",
			opts:       RunOptions{EnvFiles: []string{"one.env"}},
			plaintexts: map[string]string{"one.env": "DUP=one\nDUP=two\n"},
			wantErr:    "duplicate variable",
		},
		{
			name:       "dotenv across documents",
			opts:       RunOptions{EnvFiles: []string{"one.env", "two.env"}},
			plaintexts: map[string]string{"one.env": "DUP=one", "two.env": "DUP=two"},
			wantErr:    "collides",
		},
		{
			name:       "raw and dotenv",
			opts:       RunOptions{Secrets: []string{"a-b"}, EnvFiles: []string{"one.env"}},
			plaintexts: map[string]string{"a-b": "one", "one.env": "SESAM_SECRET_A_B=two"},
			wantErr:    "collides",
		},
		{
			name:       "raw and inherited",
			opts:       RunOptions{Secrets: []string{"a-b"}, Environment: []string{"SESAM_SECRET_A_B=parent"}},
			plaintexts: map[string]string{"a-b": "one"},
			wantErr:    "inherited environment",
		},
		{
			name:       "dotenv and inherited",
			opts:       RunOptions{EnvFiles: []string{"one.env"}, Environment: []string{"DUP=parent"}},
			plaintexts: map[string]string{"one.env": "DUP=child"},
			wantErr:    "inherited environment",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Arguments = []string{"probe"}
			_, err := prepareRunEnvironment(tc.opts, func(path string) ([]byte, error) {
				return []byte(tc.plaintexts[path]), nil
			})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestPrepareRunEnvironmentRejectsNULAndLimits(t *testing.T) {
	manyVariables := strings.Builder{}
	for i := 0; i <= runMaxInjectedVars; i++ {
		fmt.Fprintf(&manyVariables, "K%03d=x\n", i)
	}

	tests := []struct {
		name    string
		opts    RunOptions
		reveal  runRevealFunc
		wantErr string
	}{
		{
			name:    "raw NUL",
			opts:    RunOptions{Secrets: []string{"a"}},
			reveal:  func(string) ([]byte, error) { return []byte{'a', 0, 'b'}, nil },
			wantErr: "contains NUL",
		},
		{
			name:    "dotenv NUL",
			opts:    RunOptions{EnvFiles: []string{"a"}},
			reveal:  func(string) ([]byte, error) { return []byte("A='a\x00b'"), nil },
			wantErr: "contains NUL",
		},
		{
			name: "one selector",
			opts: RunOptions{Secrets: []string{"a"}},
			reveal: func(string) ([]byte, error) {
				return bytes.Repeat([]byte{'x'}, runMaxSelectorPlaintext+1), nil
			},
			wantErr: "selector a exceeds",
		},
		{
			name: "total selector plaintext",
			opts: RunOptions{Secrets: []string{"a", "b"}},
			reveal: func(string) ([]byte, error) {
				return bytes.Repeat([]byte{'x'}, runMaxTotalPlaintext/2+1), nil
			},
			wantErr: "total decrypted selector plaintext",
		},
		{
			name: "encoded injected entries",
			opts: RunOptions{Secrets: []string{"a"}},
			reveal: func(string) ([]byte, error) {
				return bytes.Repeat([]byte{'x'}, runMaxValueSize), nil
			},
			wantErr: "encoded injected environment",
		},
		{
			name:    "variable count",
			opts:    RunOptions{EnvFiles: []string{"a"}},
			reveal:  func(string) ([]byte, error) { return []byte(manyVariables.String()), nil },
			wantErr: "exceeds 256 variables",
		},
		{
			name: "process budget",
			opts: RunOptions{
				Secrets:     []string{"a"},
				Environment: []string{"BIG=" + string(bytes.Repeat([]byte{'x'}, runMaxProcessSize))},
			},
			reveal:  func(string) ([]byte, error) { return []byte("x"), nil },
			wantErr: "exceeding 98304-byte budget",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.Arguments = []string{"probe"}
			_, err := prepareRunEnvironment(tc.opts, tc.reveal)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestPrepareRunEnvironmentIsDeterministic(t *testing.T) {
	opts := RunOptions{
		Secrets:     []string{"raw/a", "raw/b"},
		EnvFiles:    []string{"vars.env"},
		Environment: []string{"BASE=kept"},
		Arguments:   []string{"probe", "arg"},
	}
	reveal := func(path string) ([]byte, error) {
		values := map[string]string{
			"raw/a":    "one\n",
			"raw/b":    "two",
			"vars.env": "ZED=last\nALPHA=first",
		}
		return []byte(values[path]), nil
	}

	first, err := prepareRunEnvironment(opts, reveal)
	require.NoError(t, err)
	second, err := prepareRunEnvironment(opts, reveal)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, []string{
		"BASE=kept",
		"SESAM_SECRET_RAW_A=one\n",
		"SESAM_SECRET_RAW_B=two",
		"ZED=last",
		"ALPHA=first",
	}, first)
}

func TestPrepareRunEnvironmentRequiresSelectorAndCommand(t *testing.T) {
	_, err := prepareRunEnvironment(RunOptions{Arguments: []string{"probe"}}, nil)
	require.ErrorContains(t, err, "at least one")

	_, err = prepareRunEnvironment(RunOptions{Secrets: []string{"a"}}, nil)
	require.ErrorContains(t, err, "command is required")
}

func TestRepoPrepareRunEnvironmentReadsEncryptedObjects(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)
	writeRepoFile(t, dir, "raw.txt", "raw-value\n")
	writeRepoFile(t, dir, "vars.env", "TOKEN='dotenv value'\nEMPTY=")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd([]string{"raw.txt", "vars.env"}, []string{"admin"}, false, false); err != nil {
			return err
		}
		return s.Seal(true)
	}))
	require.NoError(t, os.Remove(filepath.Join(dir, "raw.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "vars.env")))

	env, err := r.PrepareRunEnvironment(RunOptions{
		Secrets:     []string{"raw.txt"},
		EnvFiles:    []string{"vars.env"},
		Environment: []string{"BASE=kept"},
		Arguments:   []string{"probe"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"BASE=kept",
		"SESAM_SECRET_RAW_TXT=raw-value\n",
		"TOKEN=dotenv value",
		"EMPTY=",
	}, env)
	require.NoFileExists(t, filepath.Join(dir, "raw.txt"))
	require.NoFileExists(t, filepath.Join(dir, "vars.env"))
}

func TestRepoPrepareRunEnvironmentAllUsesCurrentUserAccess(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)
	writeRepoFile(t, dir, "secrets/raw.txt", "raw-value\n")
	writeRepoFile(t, dir, "secrets/vars.env", "TOKEN='dotenv value'")
	writeRepoFile(t, dir, "secrets/ops.txt", "ops-value")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd([]string{"secrets/raw.txt", "secrets/vars.env"}, []string{"dev"}, false, false); err != nil {
			return err
		}
		if err := s.SecretAdd([]string{"secrets/ops.txt"}, []string{"ops"}, false, false); err != nil {
			return err
		}
		if err := s.UserTell(context.Background(), bob.Name, []string{bob.Recipient}, []string{"dev"}, false); err != nil {
			return err
		}
		return s.Seal(true)
	}))
	require.NoError(t, r.Close())
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/raw.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/vars.env")))
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/ops.txt")))

	r = reloadSesamRepo(t, dir, bob)
	env, err := r.PrepareRunEnvironment(RunOptions{
		All:         true,
		EnvFiles:    []string{"secrets/vars.env"},
		Environment: []string{"BASE=kept"},
		Arguments:   []string{"probe"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{
		"BASE=kept",
		"SESAM_SECRET_SECRETS_RAW_TXT=raw-value\n",
		"TOKEN=dotenv value",
	}, env)
}
