#!/usr/bin/env bash
#
# Generate Go vanity-import ("go-import") pages for every package in this module.
# See here for the documentation: https://go.dev/ref/mod#vcs-find
set -euo pipefail

out="${1:?usage: gen-vanity-imports.sh <output-dir>}"
module="opensesam.org/sesam"
repo="https://github.com/open-sesam/sesam"

go list ./... | while IFS= read -r p; do
  pkg="$(printf "%s\n" ${p#opensesam.org/})"
  dir="$out/$pkg"
  echo $dir

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

done
