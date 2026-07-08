#!/usr/bin/env bash
#
# Generate Go vanity-import ("go-import") pages for every package in this module.
#
# `go get opensesam.org/sesam/core` resolves the path by fetching
#   https://opensesam.org/sesam/core?go-get=1
# and reading a <meta name="go-import"> tag (see https://go.dev/ref/mod). GitHub
# Pages is static, so every importable path needs a real HTML file. This writes
# one index.html per package, plus the module root (go re-fetches the repo-root
# prefix to verify it), under <output-dir> mirroring the published URL layout.
#
# Usage:
#   scripts/gen-vanity-imports.sh <output-dir>
# Env:
#   MODULE  vanity module path (default: `go list -m`; override to preview
#           before the go.mod rename, e.g. MODULE=opensesam.org/sesam)
#   REPO    VCS repository root (default: https://github.com/open-sesam/sesam)
set -euo pipefail

out="${1:?usage: gen-vanity-imports.sh <output-dir>}"
real="$(go list -m)"
module="${MODULE:-$real}"
repo="${REPO:-https://github.com/open-sesam/sesam}"

rm -rf "${out}"

# Every package import path rewritten to the vanity prefix, plus the module root
# itself (needed for go's prefix-verification fetch). Sorted + de-duplicated.
paths="$(go list ./... | while IFS= read -r p; do printf '%s\n' "${module}${p#"$real"}"; done)"
paths="$(printf '%s\n%s\n' "$module" "$paths" | sort -u)"

n=0
while IFS= read -r pkg; do
  [ -n "$pkg" ] || continue
  dir="$out/${pkg#*/}" # drop the host component → URL path under the site root
  mkdir -p "$dir"
  cat >"$dir/index.html" <<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="go-import" content="${module} git ${repo}">
<meta name="go-source" content="${module} ${repo} ${repo}/tree/main{/dir} ${repo}/tree/main{/dir}/{file}#L{line}">
<meta http-equiv="refresh" content="0; url=https://pkg.go.dev/${pkg}">
</head>
<body>Redirecting to <a href="https://pkg.go.dev/${pkg}">pkg.go.dev/${pkg}</a>.</body>
</html>
HTML
  n=$((n + 1))
done <<<"$paths"

mv "$out/open-sesam/sesam" "$out/sesam"
rmdir "$out/open-sesam"
echo "generated $n go-import page(s) under '$out' (module: $module, repo: $repo)"
