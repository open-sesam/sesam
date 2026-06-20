package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/urfave/cli/v3"
)

// Shell completion for the sesam CLI.
//
// urfave/cli drives completion by re-invoking the binary with the hidden
// "--generate-shell-completion" flag; whatever the matched command's
// ShellComplete func prints (one candidate per line) becomes the suggestion
// list. The generated zsh/bash scripts fall back to their own file completion
// when the binary prints nothing.
//
// The default (DefaultCompleteWithFlags) only prints flags while the current
// word starts with "-", and otherwise prints the list of subcommands. For our
// leaf commands that means a bare <TAB> prints only the auto-added "help"
// command, which is useless. The completers below replace that with file paths
// or known secret/user names while still delegating flag completion to the
// library.

// rawPrevArg returns the shell word the user is currently completing: the token
// just before the completion flag that the shell scripts always append. It is
// taken from os.Args rather than cmd.Args() because the latter only holds
// parsed positionals — a half-typed flag like "--g" or a flag awaiting its
// value ("--user <TAB>") is swallowed by the flag parser and never appears
// there, yet those are exactly the cases we need to detect.
func rawPrevArg() string {
	if n := len(os.Args); n >= 2 {
		return os.Args[n-2]
	}
	return ""
}

// emit prints one completion candidate per line to the command's writer.
func emit(w io.Writer, names ...string) {
	for _, name := range names {
		_, _ = fmt.Fprintln(w, name)
	}
}

// completeFlags prints flag suggestions matching the partially typed "-flag",
// covering both the command's own flags and the inherited global flags (which
// urfave/cli accepts on every subcommand). It mirrors the library's matching
// rules — short flags are hidden once the user has typed "--", and zsh/fish get
// a trailing ":usage" — but DefaultCompleteWithFlags only ever sees cmd.Flags,
// which is why we reimplement it here to fold in cmd.Root().Flags.
func completeFlags(_ context.Context, cmd *cli.Command) {
	last := rawPrevArg()
	cur := strings.TrimLeft(last, "-")
	shell := os.Getenv("SHELL")
	withUsage := strings.HasSuffix(shell, "zsh") || strings.HasSuffix(shell, "fish")
	w := cmd.Root().Writer

	seen := map[string]bool{}
	consider := func(flags []cli.Flag) {
		for _, f := range flags {
			if vf, ok := f.(cli.VisibleFlag); ok && !vf.IsVisible() {
				continue
			}
			name := strings.TrimSpace(f.Names()[0])
			if seen[name] || !strings.HasPrefix(name, cur) || name == cur {
				continue
			}
			// Cap at 2 to decide between a single "-" (short) or "--" (long)
			// prefix, matching the library's printFlagSuggestions.
			dashes := utf8.RuneCountInString(name)
			if dashes > 2 {
				dashes = 2
			}
			if strings.HasPrefix(last, "--") && dashes == 1 {
				continue // don't offer short flags once "--" was typed
			}
			seen[name] = true
			out := strings.Repeat("-", dashes) + name
			if df, ok := f.(cli.DocGenerationFlag); ok && withUsage {
				if u := df.GetUsage(); u != "" {
					out += ":" + u
				}
			}
			emit(w, out)
		}
	}

	consider(cmd.Flags)
	if root := cmd.Root(); root != cmd {
		consider(root.Flags)
	}
}

// completeFiles completes the positional argument as a path on disk. It prints
// nothing for the argument itself so the shell script runs its own file
// completion (zsh: `_files`); flag completion is delegated to the library. Use
// it for commands that take a brand-new path, e.g. `sesam add`.
func completeFiles(ctx context.Context, cmd *cli.Command) {
	if strings.HasPrefix(rawPrevArg(), "-") {
		completeFlags(ctx, cmd)
	}
}

// completeSecrets completes the positional argument with the revealed paths of
// secrets that already exist on disk. Candidates are globbed straight from
// .sesam/objects, so no decryption (and no passphrase prompt) is needed. Use it
// for commands that operate on existing secrets, e.g. `sesam rm`/`open`/`show`.
func completeSecrets(ctx context.Context, cmd *cli.Command) {
	if strings.HasPrefix(rawPrevArg(), "-") {
		completeFlags(ctx, cmd)
		return
	}

	root := filepath.Join(cmd.String("sesam-dir"), ".sesam", "objects")
	w := cmd.Root().Writer
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".sesam") {
			//nolint:nilerr
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			//nolint:nilerr
			return nil
		}
		emit(w, strings.TrimSuffix(rel, ".sesam"))
		return nil
	})
}

// completeUsers completes the value of --user with the names of users that have
// a signing key on disk (.sesam/signkeys/<user>.age) — again no decryption
// needed. Otherwise it delegates to flag completion. Use it for `sesam kill`.
func completeUsers(ctx context.Context, cmd *cli.Command) {
	prev := rawPrevArg()
	if prev == "--"+flagUser || prev == "-"+flagUser {
		root := filepath.Join(cmd.String("sesam-dir"), ".sesam", "signkeys")
		w := cmd.Root().Writer
		entries, _ := os.ReadDir(root)
		for _, e := range entries {
			if name, ok := strings.CutSuffix(e.Name(), ".age"); ok {
				emit(w, name)
			}
		}
		return
	}
	if strings.HasPrefix(prev, "-") {
		completeFlags(ctx, cmd)
	}
}
