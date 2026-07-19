#!/usr/bin/env bash
#
# Tag, build, sign and publish a release locally (never from CI, so the signing
# key stays on this machine). Creates a signed, changelog-annotated tag, verifies
# it against the committed maintainers list, then execs GoReleaser to build,
# sign and publish the artifacts and multi-arch images.
#
# Usage:
#   scripts/release.sh <vX.Y.Z>
set -euo pipefail

tag="${1:-}"
case "$tag" in
v[0-9]*) ;;
*)
  echo "usage: scripts/release.sh vX.Y.Z" >&2
  exit 1
  ;;
esac

# Preflight: the GHCR push needs write:packages on the gh token. docker login
# succeeds without it, so otherwise the missing scope only surfaces after a
# full multi-arch build.
gh auth status 2>&1 | grep -q 'write:packages' ||
  {
    echo "gh token lacks write:packages — run: gh auth refresh -h github.com -s write:packages,read:packages" >&2
    exit 1
  }

# Release only from a clean tree that lives on main (goreleaser refuses a dirty
# tree anyway). Re-enable both for real releases:
# [ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "working tree is dirty" >&2; exit 1; }
git merge-base --is-ancestor "$tag^{commit}" main || {
  echo "$tag is not reachable from main" >&2
  exit 1
}

# Create the signed, changelog-annotated tag unless it already exists, so a
# failed publish can be retried. --cleanup=verbatim keeps the '#' markdown
# headers git would otherwise strip as comments.
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "Tag $tag already exists; reusing it."
else
  # Tag message = changelog for this version + a contributor tally. git-cliff
  # ignores .mailmap, so the tally comes from git shortlog, which honors it.
  prev="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD 2>/dev/null || true)"
  {
    git-cliff --unreleased --tag "$tag" --strip header
    echo
    echo "#### Contributors"
    echo
    git shortlog -sn --no-merges "${prev:+$prev..}HEAD" |
      sed -E 's/^[[:space:]]*([0-9]+)[[:space:]]+(.*)$/- \2 (\1)/'
  } | git tag -s --cleanup=verbatim "$tag" -F -
fi

# Verify against the committed maintainers list rather than the user's global
# git config: the author's tag key stays separate from the release-artifact
# key, and no per-machine setup is required.
git -c gpg.ssh.allowedSignersFile=allowed_signers.txt verify-tag "$tag"

git --no-pager show --no-patch "$tag"
printf 'Publish %s to GHCR + GitHub? [y/N] ' "$tag"
read -r reply </dev/tty
case "$reply" in [yY]*) ;; *)
  echo "aborted." >&2
  exit 1
  ;;
esac

# Push the tag first so the GitHub release attaches to it (idempotent).
git push origin "$tag"

# Multi-arch images need QEMU emulation and a buildx builder.
docker run --privileged --rm tonistiigi/binfmt --install all
docker buildx use sesam-release 2>/dev/null || docker buildx create --name sesam-release --use

# Credentials live only on this machine; nothing is stored in CI.
export GITHUB_TOKEN="$(gh auth token)"
gh auth token | docker login ghcr.io -u "$(gh api user --jq .login)" --password-stdin

# Reuse the signed tag's message as the release body.
notes="$(mktemp)"
trap 'rm -f "$notes"' EXIT
git tag -l --format='%(contents)' "$tag" >"$notes"
goreleaser release --clean --release-notes "$notes"
