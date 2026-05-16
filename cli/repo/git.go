package repo

import (
	"fmt"

	"github.com/go-git/go-git/v5"
)

// OpenGitRepo opens the git repository that contains sesamRoot. DetectDotGit
// walks up parent directories, so this works whether .sesam lives at the
// worktree root or in a subdir.
func OpenGitRepo(sesamRoot string) (*git.Repository, error) {
	repo, err := git.PlainOpenWithOptions(sesamRoot, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, fmt.Errorf("open git repo at %s: %w", sesamRoot, err)
	}
	return repo, nil
}
