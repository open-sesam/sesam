#!/usr/bin/env bash
#
# Build the book of every vX.Y.Z tag into <docs-dir>/<tag>/, write
# <docs-dir>/versions.json and inject the version picker into every page,
# including the "main" book that must already sit at <docs-dir>.
set -euo pipefail

out="$(realpath "${1:?usage: build-docs-versions.sh <docs-dir>}")"
picker="$(realpath docs/theme/version-picker.js)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

tags=$(git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true)
built=()
for tag in $tags; do
  wt="$tmp/$tag"
  # --no-checkout + reset skips post-checkout, which would reveal secrets into
  # the temp worktree (core.hooksPath does not cover config-based hooks).
  git worktree add --no-checkout --detach --quiet "$wt" "$tag"
  git -C "$wt" reset --hard --quiet
  # Uses the committed *_ref.md of that tag; old tags are immutable, so a
  # broken build is skipped instead of failing the whole deploy.
  if (cd "$wt/docs" && MDBOOK_OUTPUT__HTML__SITE_URL="/docs/$tag/" mdbook build -d "$out/$tag"); then
    built+=("$tag")
  else
    echo "warning: skipping docs for $tag (build failed)" >&2
    rm -rf "${out:?}/$tag"
  fi
  git worktree remove --force "$wt"
done

printf '%s\n' main "${built[@]}" | jq -R . | jq -s . >"$out/versions.json"
cp "$picker" "$out/version-picker.js"

# Injected after the build so tags released before the picker existed get it too.
find "$out" -name '*.html' -print0 |
  xargs -0 sed -i 's|</body>|<script src="/docs/version-picker.js"></script></body>|'
