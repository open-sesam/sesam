package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/rogpeppe/go-internal/testscript"
)

const askpassTestPassphrase = "askpass-test-passphrase"

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"sesam": func() {
			if err := Main(os.Args); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
		"age-plugin-sesamtest": RunMockPlugin,
	})
}

func TestWorkflows(t *testing.T) {
	// Scripts are grouped into per-topic subdirectories under testdata/scripts;
	// each subdirectory runs as its own subtest (testscript reads a Dir
	// non-recursively) so `-run TestWorkflows/<category>` targets one group.
	setup := func(e *testscript.Env) error {
		// All auxiliary files (identities, TMPDIR) live outside the git
		// worktree ($WORK) so that sesam's worktree cleanup never touches
		// them. git uses TMPDIR for textconv temp files; if TMPDIR were
		// inside $WORK, Cleanup would delete those files mid-diff.
		idDir := e.WorkDir + ".ids"
		if err := os.MkdirAll(idDir, 0o700); err != nil {
			return err
		}
		tmpDir := e.WorkDir + ".tmp"
		if err := os.MkdirAll(tmpDir, 0o700); err != nil {
			return err
		}
		e.Setenv("TMPDIR", tmpDir)

		writeIdentity := func(name string) (*age.X25519Identity, string, error) {
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return nil, "", fmt.Errorf("generate age identity: %w", err)
			}

			keyPath := filepath.Join(idDir, name+".age")
			f, err := os.Create(keyPath)
			if err != nil {
				return nil, "", err
			}
			fmt.Fprintf(f, "%s\n", id)
			if err := f.Close(); err != nil {
				return nil, "", err
			}
			e.Setenv(name+"_KEY", keyPath)
			e.Setenv(name+"_PUBKEY", id.Recipient().String())
			return id, keyPath, nil
		}

		_, adminKeyPath, err := writeIdentity("ADMIN")
		if err != nil {
			return err
		}
		if _, _, err := writeIdentity("BOB"); err != nil {
			return err
		}
		// A second non-admin identity, used as an extra recipient/device
		// key in the add/remove-recipient and regen workflows.
		if _, _, err := writeIdentity("CAROL"); err != nil {
			return err
		}

		adminKey, err := os.ReadFile(adminKeyPath)
		if err != nil {
			return err
		}
		adminEncryptedKeyPath := filepath.Join(idDir, "ADMIN.encrypted.age")
		if err := writeEncryptedIdentity(adminEncryptedKeyPath, adminKey, askpassTestPassphrase); err != nil {
			return err
		}
		e.Setenv("ADMIN_ENCRYPTED_KEY", adminEncryptedKeyPath)

		askpassPath := filepath.Join(idDir, "askpass")
		askpassScript := fmt.Sprintf("#!/bin/sh\nprintf %%s %q\n", askpassTestPassphrase)
		if err := os.WriteFile(askpassPath, []byte(askpassScript), 0o700); err != nil {
			return err
		}
		e.Setenv("ASKPASS_HELPER", askpassPath)

		recordAskpassPath := filepath.Join(idDir, "record-askpass")
		recordAskpassScript := fmt.Sprintf("#!/bin/sh\nprintf %%s \"$1\" >\"$ASKPASS_PROMPT\"\nprintf %%s %q\n", askpassTestPassphrase)
		if err := os.WriteFile(recordAskpassPath, []byte(recordAskpassScript), 0o700); err != nil {
			return err
		}
		e.Setenv("ASKPASS_RECORD_HELPER", recordAskpassPath)

		// Plugin identity for the mock age-plugin-sesamtest binary
		// registered via TestMain. Used by plugin_workflow.txt to
		// exercise the full age plugin protocol against a fake plugin
		// instead of a real YubiKey.
		pluginKeyPath := filepath.Join(idDir, "PLUGIN.age")
		if err := os.WriteFile(pluginKeyPath, []byte(MockPluginIdentityFile()), 0o600); err != nil {
			return err
		}
		e.Setenv("PLUGIN_KEY", pluginKeyPath)
		e.Setenv("PLUGIN_PUBKEY", MockPluginRecipient())

		// SESAM_ID points to admin's key so all commands run as admin by default.
		e.Setenv("SESAM_ID", filepath.Join(idDir, "ADMIN.age"))
		return nil
	}

	const root = "testdata/scripts"
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}

	ran := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		ran = true
		category := entry.Name()
		t.Run(category, func(t *testing.T) {
			testscript.Run(t, testscript.Params{
				Dir:   filepath.Join(root, category),
				Setup: setup,
				Cmds: map[string]func(ts *testscript.TestScript, neg bool, args []string){
					"sesam-repo": sesamRepoCmd,
				},
			})
		})
	}
	if !ran {
		t.Fatalf("no testscript categories found under %s", root)
	}
}

func writeEncryptedIdentity(path string, plaintext []byte, passphrase string) error {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return err
	}
	recipient.SetWorkFactor(10)

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)
	writer, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return err
	}
	if _, err := io.Copy(writer, bytes.NewReader(plaintext)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := armorWriter.Close(); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0o600)
}

// sesamRepoCmd sets up the git+sesam repo nearly every script opens with:
//
//	sesam-repo [user]        (user defaults to "admin")
//
// Anything the script wants to survive sesam's aggressive clean has to live
// outside the worktree, so the fixture files named after it are moved to
// $TMPDIR and can be copied back in as $TMPDIR/<name>.
func sesamRepoCmd(ts *testscript.TestScript, neg bool, args []string) {
	if neg {
		ts.Fatalf("sesam-repo does not support negation")
	}

	user := "admin"
	fixtures := args
	if len(args) > 0 && !strings.Contains(args[0], ".") {
		user, fixtures = args[0], args[1:]
	}

	for _, name := range fixtures {
		ts.Check(os.Rename(ts.MkAbs(name), filepath.Join(ts.Getenv("TMPDIR"), name)))
	}

	ts.Check(ts.Exec("git", "init"))
	ts.Check(ts.Exec("git", "config", "user.email", "test@sesam.dev"))
	ts.Check(ts.Exec("git", "config", "user.name", "Sesam Test"))
	ts.Check(ts.Exec("sesam", "init", "--user", user, "--install-merge"))
	ts.Check(ts.Exec("git", "add", "-A"))
	ts.Check(ts.Exec("git", "commit", "-m", "init sesam"))
}
