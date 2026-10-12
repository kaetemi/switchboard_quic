#!/bin/sh
# Polyverse Switchboard
# Microservice Network Architecture
# Copyright (C) 2018-2026  Jan BOON (Kaetemi)
# Authors:
#   Jan Boon <jan.boon@kaetemi.be>
#   Claude Opus 5.5 <noreply@anthropic.com>
#
# Downloads the prebuilt shim of a release into native/sbq/prebuilt/, where
# hook/build.dart uses it instead of a cargo build: the release's SHA256SUMS,
# then each library it lists (<os>_<arch>/<file>, published as the asset
# <os>_<arch>-<file>), checked against it before anything is put in place.
#
# Usage: tool/fetch_prebuilt.sh <tag> [<os>_<arch>...]
#   tool/fetch_prebuilt.sh v0.1.0                  # every platform
#   tool/fetch_prebuilt.sh v0.1.0 linux_x64        # one
# REPO overrides the repository (kaetemi/switchboard_quic); RELEASE_URL the
# whole download location (https://github.com/$REPO/releases/download/<tag>).
# Needs curl or wget, and sha256sum or shasum. Exits non-zero, with nothing
# replaced, when a download fails, a checksum does not match or a platform is
# not in the release.
set -eu
cd "$(dirname "$0")/.."
if [ $# -lt 1 ]; then
  echo "usage: tool/fetch_prebuilt.sh <tag> [<os>_<arch>...]" >&2
  exit 2
fi
tag=$1
shift
url=${RELEASE_URL:-https://github.com/${REPO:-kaetemi/switchboard_quic}/releases/download/$tag}
dest=native/sbq/prebuilt

if command -v curl > /dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget > /dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  echo "fetch_prebuilt: needs curl or wget" >&2
  exit 1
fi
if command -v sha256sum > /dev/null 2>&1; then
  check() { sha256sum -c "$1"; }
elif command -v shasum > /dev/null 2>&1; then
  check() { shasum -a 256 -c "$1"; }
else
  echo "fetch_prebuilt: needs sha256sum or shasum" >&2
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/sbq_prebuilt.XXXXXX")
trap 'rm -rf "$work"' EXIT
fetch "$url/SHA256SUMS" "$work/SHA256SUMS"

# Lines of SHA256SUMS: "<sha256>  <os>_<arch>/<file>".
: > "$work/wanted"
while read -r sum path; do
  case "$path" in
    */*) ;;
    *) continue ;;
  esac
  platform=${path%%/*}
  if [ $# -gt 0 ]; then
    case " $* " in
      *" $platform "*) ;;
      *) continue ;;
    esac
  fi
  mkdir -p "$work/$platform"
  echo "fetch_prebuilt: $platform-${path#*/}"
  fetch "$url/$platform-${path#*/}" "$work/$path"
  printf '%s  %s\n' "$sum" "$path" >> "$work/wanted"
done < "$work/SHA256SUMS"

for platform in "$@"; do
  if ! grep -q " $platform/" "$work/wanted"; then
    echo "fetch_prebuilt: $tag has no library for $platform" >&2
    exit 1
  fi
done
if [ ! -s "$work/wanted" ]; then
  echo "fetch_prebuilt: $tag lists no library" >&2
  exit 1
fi
(cd "$work" && check wanted)

while read -r sum path; do
  mkdir -p "$dest/${path%%/*}"
  cp "$work/$path" "$dest/$path.tmp"
  mv "$dest/$path.tmp" "$dest/$path"
  echo "fetch_prebuilt: $dest/$path"
done < "$work/wanted"
# The build hook's cached result may name a cargo build: clear this package's.
# A package that depends on this one keeps its own (`rm -rf
# .dart_tool/hooks_runner` there).
rm -rf .dart_tool/hooks_runner/switchboard_quic
