package repo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func revealBytes(fn func(string) ([]byte, error)) runRevealFunc {
	return func(path string, dst io.Writer) error {
		value, err := fn(path)
		if err != nil {
			return err
		}
		_, err = dst.Write(value)
		return err
	}
}

type testRunFile struct {
	Name    string
	Content []byte
}

func runFiles(t *testing.T, prepared *RunPreparation) []testRunFile {
	t.Helper()
	t.Cleanup(func() { require.NoError(t, prepared.Close()) })
	files := make([]testRunFile, len(prepared.Files))
	for i, file := range prepared.Files {
		position, err := file.file.Seek(0, io.SeekCurrent)
		require.NoError(t, err)
		_, err = file.file.Seek(0, io.SeekStart)
		require.NoError(t, err)
		files[i].Name = file.Name
		files[i].Content, err = io.ReadAll(file.file)
		require.NoError(t, err)
		_, err = file.file.Seek(position, io.SeekStart)
		require.NoError(t, err)
	}
	return files
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
		{name: "malformed duplicate", document: "FOO=one\nFOO=two words", wantErr: "invalid byte"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseDotenv([]byte(tc.document))
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestParseDotenvDuplicateVariables(t *testing.T) {
	for _, tc := range []struct {
		name     string
		document string
		want     string
		warnings int
	}{
		{name: "last assignment wins", document: "FOO=first-secret\nBAR=kept\nFOO=second-secret\nexport FOO='last-secret'", want: "last-secret", warnings: 2},
		{name: "empty overrides nonempty", document: "FOO=first-secret\nBAR=kept\nFOO=", want: "", warnings: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings := captureWarnings(t)
			entries, err := parseDotenv([]byte(tc.document))
			require.NoError(t, err)
			require.Equal(t, []runEntry{
				{name: "FOO", value: []byte(tc.want)},
				{name: "BAR", value: []byte("kept")},
			}, entries)
			prepared := RunPreparation{entries: entries}
			env, err := prepared.Environment(nil, nil)
			require.NoError(t, err)
			require.Equal(t, []string{"FOO=" + tc.want, "BAR=kept"}, env)
			logged := warnings.String()
			require.Equal(t, tc.warnings, strings.Count(logged, "duplicate dotenv variable"))
			require.Contains(t, logged, "level=WARN")
			require.Contains(t, logged, "name=FOO")
			require.Contains(t, logged, "line=3")
			for _, value := range []string{"first-secret", "second-secret", "last-secret"} {
				require.NotContains(t, logged, value, "warnings must not include secret values")
			}
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
		{name: "name starts with digit", secrets: []RunSecret{{Name: "9A", Path: "a"}}, wantErr: "invalid secret variable name"},
		{name: "name contains punctuation", secrets: []RunSecret{{Name: "A-B", Path: "a"}}, wantErr: "invalid secret variable name"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := prepareRun(RunOptions{
				Secrets: tc.secrets, EnvFiles: tc.envFiles,
			}, revealBytes(func(string) ([]byte, error) {
				t.Fatal("invalid selectors must fail before reading secrets")
				return nil, nil
			}))
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestRunSecretName(t *testing.T) {
	for _, tc := range []struct{ path, name string }{
		{"postgres/backup/password.txt", "SESAM_POSTGRES_BACKUP_PASSWORD_TXT"},
		{"9dir/my-secret_v2.txt", "SESAM_9DIR_MY_SECRET_V2_TXT"},
		{"UPPER/é.txt", "SESAM_UPPER___TXT"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			require.Equal(t, tc.name, runSecretName(tc.path))
		})
	}
}

func TestPrepareRunAutomaticSelection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		secret   RunSecret
		patterns []string
		content  string
		wantFile string
	}{
		{name: "generated name", secret: RunSecret{Path: "postgres/backup/password.txt"}, content: "binary\x00value", wantFile: "SESAM_POSTGRES_BACKUP_PASSWORD_TXT"},
		{name: "dotenv suffix", secret: RunSecret{Path: "deploy/production.env"}, content: "TOKEN=value"},
		{name: "dot env basename", secret: RunSecret{Path: ".env"}, content: "TOKEN=value"},
		{name: "custom regex", secret: RunSecret{Path: "deploy/.env.production"}, patterns: []string{`(^|/)\.env\.`}, content: "TOKEN=value"},
		{name: "explicit mapping forces file", secret: RunSecret{Name: "CONFIG", Path: "production.env"}, content: "not dotenv", wantFile: "CONFIG"},
		{name: "regex explicit mapping forces file", secret: RunSecret{Name: "CONFIG", Path: "production.vars"}, patterns: []string{`\.vars$`}, content: "not dotenv", wantFile: "CONFIG"},
		{name: "unmatched regex", secret: RunSecret{Path: "vars.txt"}, patterns: []string{`\.vars$`}, content: "not dotenv", wantFile: "SESAM_VARS_TXT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := prepareRun(RunOptions{Secrets: []RunSecret{tc.secret}, EnvPatterns: tc.patterns}, revealBytes(func(path string) ([]byte, error) {
				require.Equal(t, tc.secret.Path, path)
				return []byte(tc.content), nil
			}))
			require.NoError(t, err)
			if tc.wantFile != "" {
				require.Equal(t, []testRunFile{{Name: tc.wantFile, Content: []byte(tc.content)}}, runFiles(t, prepared))
				require.Empty(t, prepared.entries)
			} else {
				require.Empty(t, prepared.Files)
				require.Equal(t, []runEntry{{name: "TOKEN", value: []byte("value"), source: tc.secret.Path}}, prepared.entries)
			}
		})
	}
}

func TestPrepareRunRejectsInvalidPatternBeforeReading(t *testing.T) {
	_, err := prepareRun(RunOptions{Secrets: []RunSecret{{Path: "a"}}, EnvPatterns: []string{"["}}, revealBytes(func(string) ([]byte, error) {
		t.Fatal("invalid pattern must fail before reading secrets")
		return nil, nil
	}))
	require.ErrorContains(t, err, "invalid env pattern")
}

func TestPrepareRunPreservesSelectionOrderAndOptions(t *testing.T) {
	opts := RunOptions{
		Secrets: []RunSecret{
			{Path: "first.env"},
			{Path: "raw-file.txt"},
			{Name: "FORCED", Path: "also.env"},
			{Path: "last.env"},
		},
		EnvFiles: []string{"extra.vars"},
	}
	original := append([]RunSecret(nil), opts.Secrets...)
	var readPaths []string
	prepared, err := prepareRun(opts, revealBytes(func(path string) ([]byte, error) {
		readPaths = append(readPaths, path)
		values := map[string]string{
			"first.env":    "FIRST=one",
			"raw-file.txt": "raw",
			"also.env":     "not dotenv",
			"last.env":     "LAST=two",
			"extra.vars":   "EXTRA=three",
		}
		return []byte(values[path]), nil
	}))
	require.NoError(t, err)
	require.Equal(t, original, opts.Secrets)
	require.Equal(t, []string{"first.env", "raw-file.txt", "also.env", "last.env", "extra.vars"}, readPaths)
	require.Equal(t, []testRunFile{
		{Name: "SESAM_RAW_FILE_TXT", Content: []byte("raw")},
		{Name: "FORCED", Content: []byte("not dotenv")},
	}, runFiles(t, prepared))
	require.Equal(t, []runEntry{
		{name: "FIRST", value: []byte("one"), source: "first.env"},
		{name: "LAST", value: []byte("two"), source: "last.env"},
		{name: "EXTRA", value: []byte("three"), source: "extra.vars"},
	}, prepared.entries)
}

func TestPrepareRunOverlappingEnvFiles(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     RunOptions
		previous string
		last     string
		want     string
	}{
		{name: "explicit files", opts: RunOptions{EnvFiles: []string{"one.env", "two.env"}}, previous: "one.env", last: "two.env", want: "second-secret"},
		{name: "automatic detection", opts: RunOptions{Secrets: []RunSecret{{Path: "one.env"}, {Path: "two.env"}}}, previous: "one.env", last: "two.env", want: "second-secret"},
		{name: "explicit after automatic", opts: RunOptions{Secrets: []RunSecret{{Path: "one.env"}}, EnvFiles: []string{"two.env"}}, previous: "one.env", last: "two.env", want: "second-secret"},
		{name: "reversed order", opts: RunOptions{EnvFiles: []string{"two.env", "one.env"}}, previous: "two.env", last: "one.env", want: "first-secret"},
		{name: "empty override", opts: RunOptions{EnvFiles: []string{"one.env", "empty.env"}}, previous: "one.env", last: "empty.env", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warnings := captureWarnings(t)
			prepared, err := prepareRun(tc.opts, revealBytes(func(path string) ([]byte, error) {
				values := map[string]string{
					"one.env":   "DUP=first-secret\nFIRST=kept",
					"two.env":   "DUP=second-secret\nSECOND=kept",
					"empty.env": "DUP=\nSECOND=kept",
				}
				return []byte(values[path]), nil
			}))
			require.NoError(t, err)
			inherited := []string{"BASE=kept"}
			env, err := prepared.Environment(inherited, nil)
			require.NoError(t, err)
			require.ElementsMatch(t, []string{"BASE=kept", "DUP=" + tc.want, "FIRST=kept", "SECOND=kept"}, env)
			require.Equal(t, []string{"BASE=kept"}, inherited)
			again, err := prepared.Environment(inherited, nil)
			require.NoError(t, err)
			require.Equal(t, env, again)
			logged := warnings.String()
			require.Contains(t, logged, "level=WARN")
			require.Contains(t, logged, "name=DUP")
			require.Contains(t, logged, "previous_file="+tc.previous)
			require.Contains(t, logged, "file="+tc.last)
			require.NotContains(t, logged, "first-secret")
			require.NotContains(t, logged, "second-secret")
		})
	}
}

func TestPrepareRunOverlapsCountUniqueVariables(t *testing.T) {
	captureWarnings(t)
	const variables = 300
	var document strings.Builder
	for i := 0; i < variables; i++ {
		fmt.Fprintf(&document, "K%03d=value\n", i)
	}
	prepared, err := prepareRun(RunOptions{EnvFiles: []string{"one.env", "two.env"}}, revealBytes(func(string) ([]byte, error) {
		return []byte(document.String()), nil
	}))
	require.NoError(t, err)
	env, err := prepared.Environment(nil, nil)
	require.NoError(t, err)
	require.Len(t, env, variables)
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
			name:       "generated names collide",
			opts:       RunOptions{Secrets: []RunSecret{{Path: "a-b"}, {Path: "a_b"}}},
			plaintexts: map[string]string{"a-b": "one", "a_b": "two"},
			wantErr:    "SESAM_A_B",
		},
		{
			name:       "generated and inherited",
			opts:       RunOptions{Secrets: []RunSecret{{Path: "a"}}},
			inherited:  []string{"SESAM_A=parent"},
			plaintexts: map[string]string{"a": "one"},
			wantErr:    "inherited environment",
		},
		{
			name:       "file and dotenv",
			opts:       RunOptions{Secrets: []RunSecret{{Name: "FILE", Path: "a-b"}}, EnvFiles: []string{"one.env"}},
			plaintexts: map[string]string{"a-b": "one", "one.env": "FILE=two"},
			wantErr:    `from env file "one.env" collides with file secret "FILE"`,
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
			wantErr:    `from env file "one.env" collides with inherited environment`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prepared, err := prepareRun(tc.opts, revealBytes(func(path string) ([]byte, error) {
				return []byte(tc.plaintexts[path]), nil
			}))
			if err == nil {
				paths := make([]string, len(prepared.Files))
				for i := range paths {
					paths[i] = fmt.Sprintf("/dev/fd/%d", 3+i)
				}
				_, err = prepared.Environment(tc.inherited, paths)
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestRunPreparationEnvironmentHasNoPolicyLimits(t *testing.T) {
	const variables = 300
	entries := make([]runEntry, variables+1)
	for i := 0; i < variables; i++ {
		entries[i] = runEntry{name: fmt.Sprintf("K%03d", i), value: []byte("x"), source: "many.env"}
	}
	entries[variables] = runEntry{name: "LARGE", value: bytes.Repeat([]byte{'x'}, 128*1024), source: "large.env"}
	prepared := RunPreparation{entries: entries}
	env, err := prepared.Environment(nil, nil)
	require.NoError(t, err)
	require.Len(t, env, variables+1)
	require.Len(t, env[len(env)-1], len("LARGE=")+128*1024)
}

func TestRunPreparationEnvironment(t *testing.T) {
	opts := RunOptions{
		Secrets:  []RunSecret{{Name: "CERT", Path: "raw/a"}, {Name: "KEY", Path: "raw/b"}},
		EnvFiles: []string{"vars.env"},
	}
	reveal := revealBytes(func(path string) ([]byte, error) {
		values := map[string]string{
			"raw/a":    "one\x00\n",
			"raw/b":    "two",
			"vars.env": "ZED=last\nALPHA=first",
		}
		return []byte(values[path]), nil
	})

	prepared, err := prepareRun(opts, reveal)
	require.NoError(t, err)
	require.Equal(t, []testRunFile{
		{Name: "CERT", Content: []byte("one\x00\n")},
		{Name: "KEY", Content: []byte("two")},
	}, runFiles(t, prepared))
	inherited := []string{"BASE=kept"}
	first, err := prepared.Environment(inherited, []string{"/dev/fd/3", "/dev/fd/4"})
	require.NoError(t, err)
	second, err := prepared.Environment(inherited, []string{"/dev/fd/3", "/dev/fd/4"})
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

func TestPrepareRunRequiresSelectorAndFilePaths(t *testing.T) {
	_, err := prepareRun(RunOptions{}, nil)
	require.ErrorContains(t, err, "at least one")

	prepared := &RunPreparation{Files: []RunFile{{Name: "FILE"}}}
	_, err = prepared.Environment(nil, nil)
	require.ErrorContains(t, err, "expected 1 secret file paths")
}

func TestRepoPrepareRunReadsEncryptedObjects(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)
	writeRepoFile(t, dir, "raw.txt", "raw-value\n")
	writeRepoFile(t, dir, "vars.env", "TOKEN='dotenv value'\nEMPTY=")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd(t.Context(), []string{"raw.txt", "vars.env"}, []string{"admin"}, false, false); err != nil {
			return err
		}
		_, err := s.Seal(t.Context(), SealOpts{All: true})
		return err
	}))
	require.NoError(t, os.Remove(filepath.Join(dir, "raw.txt")))
	require.NoError(t, os.Remove(filepath.Join(dir, "vars.env")))

	prepared, err := r.PrepareRun(RunOptions{
		Secrets:  []RunSecret{{Name: "RAW", Path: "raw.txt"}},
		EnvFiles: []string{"vars.env"},
	})
	require.NoError(t, err)
	require.Equal(t, []testRunFile{{Name: "RAW", Content: []byte("raw-value\n")}}, runFiles(t, prepared))
	env, err := prepared.Environment([]string{"BASE=kept"}, []string{"/dev/fd/3"})
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

func TestRepoPrepareRunStreamsLargeFiles(t *testing.T) {
	for _, size := range []int{0, 2 * 1024 * 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			admin := writeTestIdentity(t, "admin")
			dir, r := bootstrapRepo(t, admin)
			content := strings.Repeat("x", size)
			writeRepoFile(t, dir, "raw.txt", content)
			require.NoError(t, r.Update(func(s *Stage) error {
				if err := s.SecretAdd(t.Context(), []string{"raw.txt"}, []string{"admin"}, false, false); err != nil {
					return err
				}
				_, err := s.Seal(t.Context(), SealOpts{All: true})
				return err
			}))
			require.NoError(t, os.Remove(filepath.Join(dir, "raw.txt")))
			prepared, err := r.PrepareRun(RunOptions{Secrets: []RunSecret{{Name: "RAW", Path: "raw.txt"}}})
			require.NoError(t, err)
			require.Equal(t, []testRunFile{{Name: "RAW", Content: []byte(content)}}, runFiles(t, prepared))
			require.NoFileExists(t, filepath.Join(dir, "raw.txt"))
		})
	}
}

func TestRepoPrepareRunChecksCurrentUserAccess(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)
	writeRepoFile(t, dir, "secrets/raw.txt", "raw-value\n")
	writeRepoFile(t, dir, "secrets/vars.env", "TOKEN='dotenv value'")
	writeRepoFile(t, dir, "secrets/ops.txt", "ops-value")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd(t.Context(), []string{"secrets/raw.txt", "secrets/vars.env"}, []string{"dev"}, false, false); err != nil {
			return err
		}
		if err := s.SecretAdd(t.Context(), []string{"secrets/ops.txt"}, []string{"ops"}, false, false); err != nil {
			return err
		}
		if err := s.UserTell(context.Background(), bob.Name, []string{bob.Recipient}, []string{"dev"}, false); err != nil {
			return err
		}
		_, err := s.Seal(t.Context(), SealOpts{All: true})
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
	firstPrepared := prepared
	t.Cleanup(func() { require.NoError(t, firstPrepared.Close()) })
	env, err := prepared.Environment([]string{"BASE=kept"}, []string{"/dev/fd/3"})
	require.NoError(t, err)
	require.Equal(t, []string{
		"BASE=kept",
		"RAW=/dev/fd/3",
		"TOKEN=dotenv value",
	}, env)
	_, err = r.PrepareRun(RunOptions{Secrets: []RunSecret{{Name: "OPS", Path: "secrets/ops.txt"}}})
	require.Error(t, err)

	prepared, err = r.PrepareRun(RunOptions{All: true})
	require.NoError(t, err)
	require.Equal(t, []testRunFile{{Name: "SESAM_SECRETS_RAW_TXT", Content: []byte("raw-value\n")}}, runFiles(t, prepared))
	env, err = prepared.Environment(nil, []string{"/dev/fd/3"})
	require.NoError(t, err)
	require.Equal(t, []string{"SESAM_SECRETS_RAW_TXT=/dev/fd/3", "TOKEN=dotenv value"}, env)
}

func TestRepoPrepareRunAllExplicitOverrides(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	dir, r := bootstrapRepo(t, admin)
	writeRepoFile(t, dir, "vars.env", "not dotenv")
	writeRepoFile(t, dir, "z.txt", "last")
	writeRepoFile(t, dir, "a.txt", "first")
	require.NoError(t, r.Update(func(s *Stage) error {
		if err := s.SecretAdd(t.Context(), []string{"vars.env", "z.txt", "a.txt"}, []string{"admin"}, false, false); err != nil {
			return err
		}
		_, err := s.Seal(t.Context(), SealOpts{All: true})
		return err
	}))
	prepared, err := r.PrepareRun(RunOptions{
		All: true, Secrets: []RunSecret{{Name: "CONFIG", Path: "vars.env"}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, prepared.Close()) })
	var names []string
	for _, file := range prepared.Files {
		names = append(names, file.Name)
	}
	require.Equal(t, []string{"CONFIG", "SESAM_README_MD", "SESAM_A_TXT", "SESAM_Z_TXT"}, names)
}

func TestRepoPrepareRunAllWithoutAccess(t *testing.T) {
	admin := writeTestIdentity(t, "admin")
	bob := writeTestIdentity(t, "bob")
	dir, r := bootstrapRepo(t, admin)
	require.NoError(t, r.Update(func(s *Stage) error {
		return s.UserTell(context.Background(), bob.Name, []string{bob.Recipient}, []string{"dev"}, false)
	}))
	require.NoError(t, r.Close())
	r = reloadSesamRepo(t, dir, bob)
	_, err := r.PrepareRun(RunOptions{All: true})
	require.ErrorContains(t, err, "no accessible secrets selected")
}
