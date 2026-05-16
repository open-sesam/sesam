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

			writeIdentity := func(name string) (*age.X25519Identity, error) {
				id, err := age.GenerateX25519Identity()
				if err != nil {
					return nil, fmt.Errorf("generate age identity: %w", err)
				}

				keyPath := filepath.Join(idDir, name+".age")
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
			e.Setenv("SESAM_ID", filepath.Join(idDir, "ADMIN.age"))
			return nil
		},
	})
}
