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
			id, err := age.GenerateX25519Identity()
			if err != nil {
				return fmt.Errorf("generate age identity: %w", err)
			}

			keyPath := filepath.Join(e.WorkDir, "identity.age")
			f, err := os.Create(keyPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(f, "%s\n", id)
			f.Close()

			e.Setenv("SESAM_ID", keyPath)
			return nil
		},
	})
}
