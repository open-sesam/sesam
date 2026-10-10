package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"
	"opensesam.org/sesam/cli/manual"
)

// HandleHelp implements `sesam help [command]`.
//
// Without an argument it opens the manual the binary carries, which is the
// same page the release archives ship as sesam.1. With one it prints that
// command's help. The command overview stays at `sesam --help`.
func HandleHelp(ctx context.Context, cmd *cli.Command) error {
	if arg := cmd.Args().First(); arg != "" {
		return cli.ShowCommandHelp(ctx, cmd.Root(), arg)
	}

	return showManual(ctx)
}

// showManual hands the embedded man page to man(1), falling back to markdown
// through the pager and finally to plain stdout when there is no man or no
// terminal.
func showManual(ctx context.Context) error {
	interactive := term.IsTerminal(int(os.Stdout.Fd()))

	// A man that refuses the file (or is not there at all) falls through to the
	// markdown below rather than leaving the user without the manual.
	if manPath, err := exec.LookPath("man"); err == nil && interactive {
		if err := runMan(ctx, manPath, manual.Page()); err == nil {
			return nil
		}
	}

	return page(ctx, manual.PageMarkdown(), interactive)
}

// runMan hands the rendered page to man(1). It goes through a file because man
// formats by file name and will not read roff from stdin.
func runMan(ctx context.Context, manPath string, roff []byte) error {
	dir, err := os.MkdirTemp("", "sesam-man-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "sesam.1")
	if err := os.WriteFile(path, roff, 0o600); err != nil {
		return fmt.Errorf("write man page: %w", err)
	}

	// manPath comes from LookPath and the file is one we just wrote.
	cmd := exec.CommandContext(ctx, manPath, path) //nolint:gosec
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	return cmd.Run()
}

// page writes text through $PAGER, or straight to stdout when there is none.
func page(ctx context.Context, text string, interactive bool) error {
	fields := strings.Fields(os.Getenv("PAGER"))
	if !interactive || len(fields) == 0 {
		_, err := io.WriteString(os.Stdout, text)
		return err
	}

	// $PAGER is the user's own setting, same as git and man treat it.
	cmd := exec.CommandContext(ctx, fields[0], fields[1:]...) //nolint:gosec
	cmd.Stdin = strings.NewReader(text)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		_, err := io.WriteString(os.Stdout, text)
		return err
	}

	return nil
}
