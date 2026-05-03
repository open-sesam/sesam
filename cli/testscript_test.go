package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"sesam": func() {
			if err := Main(os.Args); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		},
	})
}

func TestWorkflows(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/scripts",
		Setup: func(e *testscript.Env) error {
			writeIdentity := func(name string) (*age.X25519Identity, error) {
				id, err := age.GenerateX25519Identity()
				if err != nil {
					return nil, fmt.Errorf("generate age identity: %w", err)
				}
				keyPath := filepath.Join(e.WorkDir, name+".age")
				f, err := os.Create(keyPath)
				if err != nil {
					return nil, err
				}
				fmt.Fprintf(f, "%s\n", id)
				f.Close()
				e.Setenv(name+"_KEY", keyPath)
				e.Setenv(name+"_PUBKEY", id.Recipient().String())
				return id, nil
			}

			if _, err := writeIdentity("ADMIN"); err != nil {
				return err
			}
			if _, err := writeIdentity("BOB"); err != nil {
				return err
			}

			// SESAM_ID points to admin's key so all commands run as admin by default.
			e.Setenv("SESAM_ID", filepath.Join(e.WorkDir, "ADMIN.age"))
			return nil
		},
	})
}
