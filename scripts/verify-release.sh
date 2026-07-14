#!/usr/bin/env bash
#
# Verify a downloaded sesam release archive: authenticity (SSH signature over
# the release checksums) and integrity (the archive's hash matches the signed
# checksums). Everything except the archive is fetched from a trusted channel —
# the checksums + signature from the GitHub release, the signing key from the
# repo at the release tag — so a tampered archive can neither vouch for itself
# nor swap out the key it is checked against.
#
# Usage:
#   scripts/verify-release.sh <path-to-sesam_X.Y.Z_os_arch.tar.gz|.zip>
#
# Needs: curl, ssh-keygen, and sha256sum (Linux) or shasum (macOS).
set -euo pipefail

REPO="open-sesam/sesam"
IDENTITY="release@sesam"  # principal in allowed_signers.txt
NAMESPACE="sesam-release" # ssh signature namespace used at signing time

artifact="${1:?usage: scripts/verify-release.sh <path-to-archive>}"
[ -f "$artifact" ] || {
  echo "no such file: $artifact" >&2
  exit 1
}
base="$(basename "$artifact")"

# The archive name encodes the release: sesam_<version>_<os>_<arch>.<ext>.
# The version carries no leading 'v'; the git tag does.
if [[ ! "$base" =~ ^sesam_([0-9][^_]*)_([a-z0-9]+)_([a-z0-9]+)\.(tar\.gz|zip)$ ]]; then
  echo "unrecognized archive name: $base" >&2
  exit 1
fi
tag="v${BASH_REMATCH[1]}"

work="$(mktemp -d)"
# trap 'rm -rf "$work"' EXIT
fetch() { curl -fsSL "$1" -o "$2" || {
  echo "failed to fetch $1" >&2
  exit 1
}; }

# Checksums + signature are release-specific, so fetch them from the release
# tag (an immutable ref). The signing key comes from the repo's trust ref —
# 'main' by default, so a botched or rotated allowed_signers can be corrected
# and a compromised key revoked for every past release (the repo is the trust
# root either way). Override for reproducible verification or to test a branch:
#   SESAM_TRUST_REF=<ref> scripts/verify-release.sh <archive>
trust_ref="${SESAM_TRUST_REF:-main}"
dl="https://github.com/$REPO/releases/download/$tag"
raw="https://raw.githubusercontent.com/$REPO/$trust_ref"
fetch "$dl/checksums.txt" "$work/checksums.txt"
fetch "$dl/checksums.txt.sig" "$work/checksums.txt.sig"
fetch "$raw/allowed_signers.txt" "$work/allowed_signers.txt"

# 1. Authenticity: the checksums file is signed by the trusted release key.
ssh-keygen -Y verify -f "$work/allowed_signers.txt" -I "$IDENTITY" \
  -n "$NAMESPACE" -s "$work/checksums.txt.sig" <"$work/checksums.txt" >/dev/null ||
  {
    echo "✗ signature verification FAILED" >&2
    exit 1
  }
echo "✓ checksums.txt signed by $IDENTITY"

# 2. Integrity: the archive's hash matches the (now trusted) checksums entry.
want="$(awk -v f="$base" '$2 == f {print $1}' "$work/checksums.txt")"
[ -n "$want" ] || {
  echo "✗ $base not listed in checksums.txt" >&2
  exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$artifact" | awk '{print $1}')"
else
  got="$(shasum -a 256 "$artifact" | awk '{print $1}')"
fi
[ "$want" = "$got" ] || {
  echo "✗ checksum MISMATCH for $base" >&2
  exit 1
}
echo "✓ $base matches the signed checksum"
echo "OK: $base is an authentic $tag release artifact"
