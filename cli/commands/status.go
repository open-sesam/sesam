package commands

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/muesli/termenv"
	"github.com/open-sesam/sesam/repo"
	"github.com/urfave/cli/v3"
)

func printDirectoryDiff(ctx context.Context, status *repo.Status, extraGitArgs []string) error {
	defer func() {
		if err := os.RemoveAll(status.DiffDir); err != nil {
			slog.Error("failed to remove diff dir", slog.Any("err", err))
		}
	}()

	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("failed to find git in PATH - required for this command")
	}

	// We have to call git directly here, as the user might have configured git tooling of his liking.
	// go-git offers no comparable diff viewing capabilities (just basic uncolored diffs)
	args := []string{
		"diff",
		"--no-index",
		"--color=auto",
	}

	targetDirs := []string{
		"--",
		"sealed/",
		"revealed/",
	}

	//nolint:gocritic
	allArgs := append(
		args,
		append(
			extraGitArgs,
			targetDirs...,
		)...,
	)

	// gosec complains about extra args coming from the command line.
	//nolint:gosec
	cmd := exec.CommandContext(
		ctx,
		"git",
		allArgs...,
	)
	cmd.Dir = status.DiffDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 {
				// if there's a diff it will exit with 1
				return nil
			}
		}

		return err
	}

	return nil
}

const colorDim = colorGrey

// glyphFor maps a secret state to a git-style single-character marker and its
// color. The character carries the meaning so it stays useful without color.
// Glyphs are single-width on purpose so the tree's leading column stays aligned.
func glyphFor(state repo.SecretState) (glyph, color string) {
	switch state {
	case repo.SecretStateNotInSync:
		return "M", colorYellow // modified - needs seal
	case repo.SecretStateNoSealedPath:
		return "A", colorGreen // added - never sealed
	case repo.SecretStateNoRevealedPath:
		return "∅", "#00AAFF" // sealed, not revealed here
	case repo.SecretStateUserHasNoAccess:
		return "x", colorRed // not a recipient
	case repo.SecretStateInSync:
		return "✓", colorDim // in sync
	case repo.SecretStateUnmanaged:
		return "?", colorDim // unmanaged
	default:
		return "?", colorDim
	}
}

// footerOrder fixes the order states appear in the summary line.
var footerOrder = []repo.SecretState{
	repo.SecretStateNotInSync,
	repo.SecretStateNoSealedPath,
	repo.SecretStateNoRevealedPath,
	repo.SecretStateUserHasNoAccess,
	repo.SecretStateInSync,
	repo.SecretStateUnmanaged,
}

// statusNode is a single node in the path tree built from revealed paths.
type statusNode struct {
	children map[string]*statusNode
	leaf     *repo.StatusForFile
}

func newStatusNode() *statusNode {
	return &statusNode{children: map[string]*statusNode{}}
}

func (n *statusNode) insert(file repo.StatusForFile) {
	cur := n

	parts := strings.Split(file.RevealedPath, "/")
	for i, part := range parts {
		child, ok := cur.children[part]
		if !ok {
			child = newStatusNode()
			cur.children[part] = child
		}
		cur = child
		if i == len(parts)-1 {
			f := file
			cur.leaf = &f
		}
	}
}

// emit walks the tree depth-first, appending directory and leaf lines to the
// list writer. Empty branches never exist because only visible files were
// inserted.
func (n *statusNode) emit(out *termenv.Output, l list.Writer, showUsers bool) {
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		child := n.children[name]
		if child.leaf != nil && len(child.children) == 0 {
			l.AppendItem(renderLeaf(out, name, *child.leaf, showUsers))
			continue
		}

		l.AppendItem(out.String(name + "/").Foreground(out.Color("#888888")).String())
		l.Indent()
		child.emit(out, l, showUsers)
		l.UnIndent()
	}
}

// renderLeaf renders "<glyph> <name> (groups)" for a single secret.
func renderLeaf(out *termenv.Output, name string, file repo.StatusForFile, showUsers bool) string {
	glyph, color := glyphFor(file.State)
	line := out.String(glyph).Foreground(out.Color(color)).String() + " " + name

	elems := file.AccessGroups
	if showUsers {
		elems = file.AccessUsers
	}

	if len(elems) > 0 {
		line += " " + out.String(
			"("+strings.Join(elems, ", ")+")",
		).Foreground(out.Color(colorDim)).String()
	}

	return line
}

// printStatusTree renders the status as a tree rooted at ".". In-sync secrets
// and unmanaged files are hidden unless `all` is set; the footer counts every
// state regardless of what is shown.
func printStatusTree(sesamDir string, status *repo.Status, all, showUsers bool) {
	out := termenv.NewOutput(os.Stdout)

	counts := make(map[repo.SecretState]int, len(footerOrder))
	root := newStatusNode()
	visible := 0
	for _, file := range status.Files {
		counts[file.State]++
		if !all && (file.State == repo.SecretStateInSync ||
			file.State == repo.SecretStateUnmanaged) {
			continue
		}
		// Render paths relative to the cwd, like git from a subdirectory.
		file.RevealedPath = displayPath(sesamDir, file.RevealedPath)
		root.insert(file)
		visible++
	}

	if visible == 0 {
		fmt.Println(out.String("✓ nothing to show - everything in sync").
			Foreground(out.Color(colorGreen)).String())
	} else {
		l := list.NewWriter()
		// Tweak the connected style so the manually printed "." root reads like
		// unix `tree`: the first top-level item is a branch (not a tree-start
		// corner) and a lone item is the last branch.
		style := list.StyleConnectedRounded
		style.CharItemTop = style.CharItemFirst
		style.CharItemSingle = style.CharItemBottom
		l.SetStyle(style)
		root.emit(out, l, showUsers)

		fmt.Println(out.String(".").Foreground(out.Color("#888888")).String())
		fmt.Println(l.Render())
	}

	// Summary: count every state, using the state's own name as the label.
	parts := make([]string, 0, len(footerOrder))
	for _, state := range footerOrder {
		n := counts[state]
		if n == 0 {
			continue
		}
		_, color := glyphFor(state)
		label := strings.ReplaceAll(state.String(), "_", " ")
		parts = append(parts, out.String(fmt.Sprintf("%d %s", n, label)).
			Foreground(out.Color(color)).String())
	}
	if len(parts) > 0 {
		fmt.Println("  " + strings.Join(parts, " · "))
	}
}

func HandleStatus(ctx context.Context, cmd *cli.Command, r *repo.Repo) error {
	diff := cmd.Bool("diff")
	status, err := r.Status(repo.StatusOpts{
		WriteDiffDirs: diff,
		// The diff dir is for managed secrets only; the tree needs unmanaged
		// files so the footer can count them (they are hidden unless --all).
		IgnoreUnmanaged: diff,
	})
	if err != nil {
		return err
	}

	if cmd.Bool("json") {
		return printJSON(status)
	}

	if diff {
		return printDirectoryDiff(ctx, status, cmd.Args().Slice())
	}

	printStatusTree(r.SesamDir(), status, cmd.Bool("all"), cmd.Bool("users"))
	return nil
}
