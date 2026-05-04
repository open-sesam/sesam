package commands

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleSmudge is the git smudge filter entry point. Git calls it for each
// .sesam object file that needs to be checked out. It passes the encrypted blob
// through to stdout unchanged (the working-tree .sesam file stays encrypted),
// and as a side effect decrypts the blob to the embedded RevealedPath.
//
// Errors during reveal are logged as warnings and do not fail the smudge - a
// failed smudge would abort the git checkout entirely, which is worse than a
// stale or missing revealed file.
func HandleSmudge(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	// Stream stdin to stdout and simultaneously write to a temp file so we can
	// seek back over it for decryption without buffering the blob in memory.
	tmpDir := filepath.Join(sesamDir, ".sesam", "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return fmt.Errorf("creating tmp dir: %w", err)
	}

	smudgeTmp, err := os.CreateTemp(tmpDir, "smudge-*")
	if err != nil {
		return fmt.Errorf("creating smudge tmp: %w", err)
	}
	defer func() {
		_ = smudgeTmp.Close()
		_ = os.Remove(smudgeTmp.Name())
	}()

	if _, err := io.Copy(io.MultiWriter(os.Stdout, smudgeTmp), os.Stdin); err != nil {
		return fmt.Errorf("streaming stdin: %w", err)
	}

	identityPaths := cmd.StringSlice("identity")
	if len(identityPaths) == 0 {
		slog.Debug("smudge: no identity configured, skipping reveal")
		return nil
	}

	// if it's an encrypted identity, let's hope user already gave his passkey here.
	// TODO: make that a const
	ids, err := loadIdentities(identityPaths, keyringFingerprint)
	if err != nil {
		slog.Warn("smudge: failed to load identities", slog.String("err", err.Error()))
		return nil
	}

	if _, err := smudgeTmp.Seek(0, io.SeekStart); err != nil {
		slog.Warn("smudge: failed to seek tmp file", slog.String("err", err.Error()))
		return nil
	}

	// %f is the repo-relative path of the encrypted object, e.g.
	// ".sesam/objects/secrets/token.sesam". Strip the prefix and suffix to get
	// the revealed path ("secrets/token") without reading the footer.
	objectPath := cmd.Args().Get(0)
	const objectsPrefix = ".sesam/objects/"
	if !strings.HasPrefix(objectPath, objectsPrefix) || !strings.HasSuffix(objectPath, ".sesam") {
		slog.Warn("smudge: unexpected object path, skipping reveal", slog.String("path", objectPath))
		return nil
	}
	revealedPath := strings.TrimSuffix(strings.TrimPrefix(objectPath, objectsPrefix), ".sesam")

	revealed, err := core.RevealBlob(sesamDir, ids, smudgeTmp, revealedPath)
	if err != nil {
		slog.Warn("smudge: could not reveal", slog.String("path", objectPath), slog.String("err", err.Error()))
	} else if !revealed {
		slog.Debug("smudge: not a recipient, skipping reveal", slog.String("path", objectPath))
	}

	return nil
}
