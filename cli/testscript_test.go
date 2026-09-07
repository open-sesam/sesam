package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
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
		"runprobe":             runProbe,
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

func runProbe() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "runprobe: missing operation")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "args":
		for idx, arg := range os.Args[2:] {
			fmt.Printf("%d=%q\n", idx, arg)
		}
	case "env":
		for _, name := range os.Args[2:] {
			value, exists := os.LookupEnv(name)
			fmt.Printf("%s=%q exists=%t\n", name, value, exists)
		}
	case "exit":
		code, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(code)
	case "mark":
		if err := os.WriteFile(os.Args[2], []byte("started"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	case "reenter":
		command := exec.Command("sesam", "id")
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	case "signal":
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		os.Exit(97)
	case "status":
		command := exec.Command(os.Args[2], os.Args[3:]...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		err := command.Run()
		if err == nil {
			fmt.Println("exit=0 signal=0")
			return
		}
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok {
			fmt.Fprintln(os.Stderr, "runprobe: unavailable wait status")
			os.Exit(2)
		}
		exitStatus := -1
		if status.Exited() {
			exitStatus = status.ExitStatus()
		}
		signalStatus := 0
		if status.Signaled() {
			signalStatus = int(status.Signal())
		}
		fmt.Printf("exit=%d signal=%d\n", exitStatus, signalStatus)
	case "write-size":
		size, err := strconv.Atoi(os.Args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := os.WriteFile(os.Args[2], bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "runprobe: unknown operation %q\n", os.Args[1])
		os.Exit(2)
	}
}
