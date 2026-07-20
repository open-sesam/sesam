package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEscapesRoot(t *testing.T) {
	tests := []struct {
		rel  string
		want bool
	}{
		{"", false},
		{".", false},
		{"foo", false},
		{"foo/bar", false},
		{"..foo", false},
		{"foo/..", false},
		{"..", true},
		{"../foo", true},
		{"../../etc", true},
	}

	for _, tc := range tests {
		t.Run(tc.rel, func(t *testing.T) {
			require.Equal(t, tc.want, escapesRoot(tc.rel))
		})
	}
}

// TestToRepoPath covers the input side of the three cwd behaviors: an absolute
// argument is relativized against the sesam dir, a relative one is resolved
// against the cwd when inside the subtree (so `add ./local` from sub/ becomes
// sub/local), and is taken as already sesam-relative when the cwd is outside.
func TestToRepoPath(t *testing.T) {
	const sesamDir = "/repo"

	tests := []struct {
		name     string
		sesamDir string
		cwd      string
		arg      string
		want     string
		wantErr  bool
	}{
		{name: "abs inside", cwd: "/repo", arg: "/repo/sub/local", want: "sub/local"},
		{name: "abs equals root", cwd: "/repo", arg: "/repo", want: "."},
		{name: "abs outside", cwd: "/repo", arg: "/etc/passwd", wantErr: true},
		{name: "rel at root", cwd: "/repo", arg: "local", want: "local"},
		{name: "rel dot-slash in subdir", cwd: "/repo/sub", arg: "./local", want: "sub/local"},
		{name: "rel in subdir", cwd: "/repo/sub", arg: "local", want: "sub/local"},
		{name: "rel dotdot stays inside", cwd: "/repo/sub", arg: "../top", want: "top"},
		{name: "rel dotdot escapes", cwd: "/repo/sub", arg: "../../etc", wantErr: true},
		{name: "cwd outside treats arg as repo-relative", cwd: "/outside", arg: "sub/local", want: "sub/local"},
		{name: "cwd outside single segment", cwd: "/outside", arg: "local", want: "local"},
		// When the cwd is an ancestor of sesamDir (e.g. add/mv from the worktree
		// root with a nested --sesam-dir) the arg is taken as already
		// sesam-relative — it must NOT be reinterpreted against the cwd, which
		// would retarget it to the wrong object.
		{name: "cwd ancestor keeps arg sesam-relative", cwd: "/", arg: "repo/.sesam/objects/x.sesam", want: "repo/.sesam/objects/x.sesam"},
		{name: "cwd ancestor nested sesam-dir", cwd: "/repo", sesamDir: "/repo/secrets", arg: "secrets/db.env", want: "secrets/db.env"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := sesamDir
			if tc.sesamDir != "" {
				dir = tc.sesamDir
			}
			got, err := toRepoPath(dir, tc.cwd, tc.arg)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestToShowPath covers the show-only reinterpretation: git invokes show as a
// textconv from the worktree root (an ancestor of sesamDir) with a worktree-
// relative path, which must resolve back to a sesam-relative one. All other
// cases delegate to toRepoPath.
func TestToShowPath(t *testing.T) {
	const sesamDir = "/repo"

	tests := []struct {
		name     string
		sesamDir string
		cwd      string
		arg      string
		want     string
		wantErr  bool
	}{
		// git textconv from the worktree root: worktree-relative arg resolves back in.
		{name: "cwd ancestor, worktree-relative arg", cwd: "/", arg: "repo/.sesam/objects/x.sesam", want: ".sesam/objects/x.sesam"},
		{name: "cwd ancestor nested sesam-dir", cwd: "/repo", sesamDir: "/repo/secrets", arg: "secrets/db.env", want: "db.env"},
		// cwd outside and arg does not resolve back: treated as sesam-relative.
		{name: "cwd outside unrelated arg", cwd: "/outside", arg: "sub/local", want: "sub/local"},
		// inside the subtree and absolute args behave exactly like toRepoPath.
		{name: "rel in subdir", cwd: "/repo/sub", arg: "local", want: "sub/local"},
		{name: "abs inside", cwd: "/repo", arg: "/repo/sub/local", want: "sub/local"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := sesamDir
			if tc.sesamDir != "" {
				dir = tc.sesamDir
			}
			got, err := toShowPath(dir, tc.cwd, tc.arg)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestDisplayPathFrom covers the output side: a sesam-relative path is rendered
// relative to the cwd when inside the subtree (like git from a subdirectory),
// and unchanged when the cwd is outside.
func TestDisplayPathFrom(t *testing.T) {
	const sesamDir = "/repo"

	tests := []struct {
		name string
		cwd  string
		rel  string
		want string
	}{
		{name: "at root", cwd: "/repo", rel: "sub/local", want: "sub/local"},
		{name: "in subdir hides prefix", cwd: "/repo/sub", rel: "sub/local", want: "local"},
		{name: "in subdir other subtree", cwd: "/repo/sub", rel: "other/x", want: "../other/x"},
		{name: "in subdir file at root", cwd: "/repo/sub", rel: "README.md", want: "../README.md"},
		{name: "cwd outside unchanged", cwd: "/outside", rel: "sub/local", want: "sub/local"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, displayPathFrom(sesamDir, tc.cwd, tc.rel))
		})
	}
}
