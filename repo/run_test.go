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

func TestPrepareRunRejectsInvalidSelectors(t *testing.T) {
	tests := []struct {
		name     string
		secrets  []RunSecret
		envFiles []string
		wantErr  string
	}{
		{name: "duplicate secret", secrets: []RunSecret{{Name: "A", Path: "a"}, {Name: "B", Path: "a"}}, wantErr: "duplicate secret selector"},
		{name: "duplicate env file", envFiles: []string{"a", "a"}, wantErr: "duplicate env file selector"},
		{name: "same path in both modes", secrets: []RunSecret{{Name: "A", Path: "a"}}, envFiles: []string{"a"}, wantErr: "both secret and env file"},
		{name: "noncanonical", secrets: []RunSecret{{Name: "A", Path: "./a"}}, wantErr: "not a canonical"},
		{name: "empty name", secrets: []RunSecret{{Path: "a"}}, wantErr: "invalid secret variable name"},
		{name: "name starts with digit", secrets: []RunSecret{{Name: "9A", Path: "a"}}, wantErr: "invalid secret variable name"},
		{name: "name contains punctuation", secrets: []RunSecret{{Name: "A-B", Path: "a"}}, wantErr: "invalid secret variable name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareRun(RunOptions{
				Secrets: tc.secrets, EnvFiles: tc.envFiles,
			}, func(string) ([]byte, error) {
				return []byte("value"), nil
			})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestRunPreparationEnvironmentRejectsCollisions(t *testing.T) {
	tests := []struct {
		name       string
		opts       RunOptions
		inherited  []string
		plaintexts map[string]string
		wantErr    string
	}{
		{
			name:       "duplicate explicit names",
			opts:       RunOptions{Secrets: []RunSecret{{Name: "FILE", Path: "a-b"}, {Name: "FILE", Path: "a_b"}}},
			plaintexts: map[string]string{"a-b": "one", "a_b": "two"},
			wantErr:    "FILE",
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
			name:       "file and dotenv",
			opts:       RunOptions{Secrets: []RunSecret{{Name: "FILE", Path: "a-b"}}, EnvFiles: []string{"one.env"}},
			plaintexts: map[string]string{"a-b": "one", "one.env": "FILE=two"},
			wantErr:    "collides",
		},
		{
			name:       "file and inherited",
			opts:       RunOptions{Secrets: []RunSecret{{Name: "FILE", Path: "a-b"}}},
			inherited:  []string{"FILE=parent"},
			plaintexts: map[string]string{"a-b": "one"},
			wantErr:    "inherited environment",
		},
		{
			name:       "dotenv and inherited",
			opts:       RunOptions{EnvFiles: []string{"one.env"}},
			inherited:  []string{"DUP=parent"},
			plaintexts: map[string]string{"one.env": "DUP=child"},
			wantErr:    "inherited environment",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := prepareRun(tc.opts, func(path string) ([]byte, error) {
				return []byte(tc.plaintexts[path]), nil
			})
			if err == nil {
				paths := make([]string, len(prepared.Files))
				for i := range paths {
					paths[i] = fmt.Sprintf("/dev/fd/%d", 3+i)
				}
				_, err = prepared.Environment(tc.inherited, []string{"probe"}, paths)
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestPrepareRunRejectsNULAndLimits(t *testing.T) {
	manyVariables := strings.Builder{}
	for i := 0; i <= runMaxInjectedVars; i++ {
		fmt.Fprintf(&manyVariables, "K%03d=x\n", i)
	}

	tests := []struct {
		name      string
		opts      RunOptions
		inherited []string
		reveal    runRevealFunc
		wantErr   string
	}{
		{
			name:    "dotenv NUL",
			opts:    RunOptions{EnvFiles: []string{"a"}},
			reveal:  func(string) ([]byte, error) { return []byte("A='a\x00b'"), nil },
			wantErr: "contains NUL",
		},
		{
			name: "one selector",
			opts: RunOptions{Secrets: []RunSecret{{Name: "A", Path: "a"}}},
			reveal: func(string) ([]byte, error) {
				return bytes.Repeat([]byte{'x'}, runMaxSelectorPlaintext+1), nil
			},
			wantErr: "selector a exceeds",
		},
		{
			name: "total selector plaintext",
			opts: RunOptions{Secrets: []RunSecret{{Name: "A", Path: "a"}, {Name: "B", Path: "b"}}},
			reveal: func(string) ([]byte, error) {
				return bytes.Repeat([]byte{'x'}, runMaxTotalPlaintext/2+1), nil
			},
			wantErr: "total decrypted selector plaintext",
		},
		{
			name: "encoded injected entries",
			opts: RunOptions{Secrets: []RunSecret{{Name: strings.Repeat("A", runMaxInjectedSize), Path: "a"}}},
			reveal: func(string) ([]byte, error) {
				return []byte("x"), nil
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
			name:      "process budget",
			opts:      RunOptions{Secrets: []RunSecret{{Name: "A", Path: "a"}}},
			inherited: []string{"BIG=" + strings.Repeat("x", runMaxProcessSize)},
			reveal:    func(string) ([]byte, error) { return []byte("x"), nil },
			wantErr:   "exceeding 98304-byte budget",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := prepareRun(tc.opts, tc.reveal)
			if err == nil {
				paths := make([]string, len(prepared.Files))
				for i := range paths {
					paths[i] = fmt.Sprintf("/dev/fd/%d", 3+i)
				}
				_, err = prepared.Environment(tc.inherited, []string{"probe"}, paths)
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestRunPreparationEnvironment(t *testing.T) {
	opts := RunOptions{
		Secrets:  []RunSecret{{Name: "CERT", Path: "raw/a"}, {Name: "KEY", Path: "raw/b"}},
		EnvFiles: []string{"vars.env"},
	}
	reveal := func(path string) ([]byte, error) {
		values := map[string]string{
			"raw/a":    "one\x00\n",
			"raw/b":    "two",
			"vars.env": "ZED=last\nALPHA=first",
		}
		return []byte(values[path]), nil
	}

	prepared, err := prepareRun(opts, reveal)
	require.NoError(t, err)
	require.Equal(t, []RunFile{
		{Name: "CERT", Content: []byte("one\x00\n")},
		{Name: "KEY", Content: []byte("two")},
	}, prepared.Files)
	inherited := []string{"BASE=kept"}
	first, err := prepared.Environment(inherited, []string{"probe", "arg"}, []string{"/dev/fd/3", "/dev/fd/4"})
	require.NoError(t, err)
	second, err := prepared.Environment(inherited, []string{"probe", "arg"}, []string{"/dev/fd/3", "/dev/fd/4"})
	require.NoError(t, err)
	require.Equal(t, []string{"BASE=kept"}, inherited)
	require.Equal(t, first, second)
	require.Equal(t, []string{
		"BASE=kept",
		"CERT=/dev/fd/3",
		"KEY=/dev/fd/4",
		"ZED=last",
		"ALPHA=first",
	}, first)
}

func TestPrepareRunRequiresSelectorAndCommand(t *testing.T) {
	_, err := prepareRun(RunOptions{}, nil)
	require.ErrorContains(t, err, "at least one")

	prepared := &RunPreparation{Files: []RunFile{{Name: "FILE"}}}
	_, err = prepared.Environment(nil, nil, []string{"/dev/fd/3"})
	require.ErrorContains(t, err, "command is required")
	_, err = prepared.Environment(nil, []string{"probe"}, nil)
	require.ErrorContains(t, err, "expected 1 secret file paths")
}

func TestRepoPrepareRunReadsEncryptedObjects(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)
	writeRepoFile(t, dir, "raw.txt", "raw-value\n")
	writeRepoFile(t, dir, "vars.env", "TOKEN='dotenv value'\nEMPTY=")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd([]string{"raw.txt", "vars.env"}, []string{"admin"}, false, false); err != nil {
			return err
		}
		_, err := s.Seal(SealOpts{All: true})
		return err
	}))
	require.NoError(t, os.Remove(filepath.Join(dir, "raw.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "vars.env")))

	prepared, err := r.PrepareRun(RunOptions{
		Secrets:  []RunSecret{{Name: "RAW", Path: "raw.txt"}},
		EnvFiles: []string{"vars.env"},
	})
	require.NoError(t, err)
	require.Equal(t, []RunFile{{Name: "RAW", Content: []byte("raw-value\n")}}, prepared.Files)
	env, err := prepared.Environment([]string{"BASE=kept"}, []string{"probe"}, []string{"/dev/fd/3"})
	require.NoError(t, err)
	require.Equal(t, []string{
		"BASE=kept",
		"RAW=/dev/fd/3",
		"TOKEN=dotenv value",
		"EMPTY=",
	}, env)
	require.NoFileExists(t, filepath.Join(dir, "raw.txt"))
	require.NoFileExists(t, filepath.Join(dir, "vars.env"))
}

func TestRepoPrepareRunChecksCurrentUserAccess(t *testing.T) {
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
		_, err := s.Seal(SealOpts{All: true})
		return err
	}))
	require.NoError(t, r.Close())
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/raw.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/vars.env")))
	require.NoError(t, os.Remove(filepath.Join(dir, "secrets/ops.txt")))

	r = reloadSesamRepo(t, dir, bob)
	prepared, err := r.PrepareRun(RunOptions{
		Secrets:  []RunSecret{{Name: "RAW", Path: "secrets/raw.txt"}},
		EnvFiles: []string{"secrets/vars.env"},
	})
	require.NoError(t, err)
	env, err := prepared.Environment([]string{"BASE=kept"}, []string{"probe"}, []string{"/dev/fd/3"})
	require.NoError(t, err)
	require.Equal(t, []string{
		"BASE=kept",
		"RAW=/dev/fd/3",
		"TOKEN=dotenv value",
	}, env)
	_, err = r.PrepareRun(RunOptions{Secrets: []RunSecret{{Name: "OPS", Path: "secrets/ops.txt"}}})
	require.Error(t, err)
}
