#!/bin/sh
# Polyverse Switchboard
# Microservice Network Architecture
# Copyright (C) 2018-2026  Jan BOON (Kaetemi)
# Authors:
#   Jan Boon <jan.boon@kaetemi.be>
#   Claude Opus 5.5 <noreply@anthropic.com>
#   GPT-6 Astra <noreply@openai.com>
#
# Downloads the prebuilt shim of a release into native/sbq/prebuilt/, where
# hook/build.dart uses it instead of a cargo build: the release's SHA256SUMS,
# then each library it lists (<os>_<arch>/<file>, published as the asset
# <os>_<arch>-<file>), checked against it before anything is put in place.
#
# Usage: tool/fetch_prebuilt.sh <tag> [<os>_<arch>...]
#   tool/fetch_prebuilt.sh v0.1.0                  # every platform
#   tool/fetch_prebuilt.sh v0.1.0 linux_x64        # one
# Platforms: linux_x64, linux_arm64, macos_arm64, macos_x64, windows_x64.
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
case "$tag" in
  ''|*[!A-Za-z0-9._+/-]*) echo "fetch_prebuilt: invalid tag: $tag" >&2; exit 2 ;;
esac
# Slashes are legal in tags, but must not become URL path components.
url_tag=$(printf '%s' "$tag" | sed 's|/|%2F|g')
for platform in "$@"; do
  case "$platform" in
    linux_x64|linux_arm64|macos_arm64|macos_x64|windows_x64) ;;
    *) echo "fetch_prebuilt: unknown platform: $platform" >&2; exit 2 ;;
  esac
done
url=${RELEASE_URL:-https://github.com/${REPO:-kaetemi/switchboard_quic}/releases/download/$url_tag}
dest=native/sbq/prebuilt

if command -v curl > /dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 -o "$2" -- "$1"; }
elif command -v wget > /dev/null 2>&1; then
  fetch() { wget -q -T 30 -t 3 -O "$2" -- "$1"; }
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
install_tmp=""
cleanup() {
  [ -z "$install_tmp" ] || rm -f "$install_tmp"
  rm -rf "$work"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
fetch "$url/SHA256SUMS" "$work/SHA256SUMS"

# Validate the complete manifest before using any of its paths. Only the
# release layout is allowed, including when a caller requests just one file.
: > "$work/manifest"
while read -r sum path || [ -n "$sum" ]; do
  case "$sum" in
    ''|*[!0-9a-fA-F]*) echo "fetch_prebuilt: invalid SHA256SUMS hash" >&2; exit 1 ;;
  esac
  [ "${#sum}" -eq 64 ] || { echo "fetch_prebuilt: invalid SHA256SUMS hash" >&2; exit 1; }
  case "$path" in
    linux_x64/libsbq.so|linux_arm64/libsbq.so|macos_arm64/libsbq.dylib|macos_x64/libsbq.dylib|windows_x64/sbq.dll) ;;
    *) echo "fetch_prebuilt: invalid SHA256SUMS path: $path" >&2; exit 1 ;;
  esac
  if grep -Fq "  $path" "$work/manifest"; then
    echo "fetch_prebuilt: duplicate SHA256SUMS path: $path" >&2
    exit 1
  fi
  printf '%s  %s\n' "$sum" "$path" >> "$work/manifest"
done < "$work/SHA256SUMS"

for platform in "$@"; do
  if ! grep -Fq "  $platform/" "$work/manifest"; then
    echo "fetch_prebuilt: $tag has no library for $platform" >&2
    exit 1
  fi
done
: > "$work/wanted"
while read -r sum path; do
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
done < "$work/manifest"

if [ ! -s "$work/wanted" ]; then
  echo "fetch_prebuilt: $tag lists no library" >&2
  exit 1
fi
(cd "$work" && check wanted)

# Clear before installing, so an interrupted install cannot leave a stale
# cargo selection cached after it has replaced a library.
rm -rf .dart_tool/hooks_runner/switchboard_quic
while read -r sum path; do
  mkdir -p "$dest/${path%%/*}"
  install_tmp=$(mktemp "$dest/$path.XXXXXX")
  cp "$work/$path" "$install_tmp"
  chmod 644 "$install_tmp"
  mv -f "$install_tmp" "$dest/$path"
  install_tmp=""
  echo "fetch_prebuilt: $dest/$path"
done < "$work/wanted"
# The build hook's cached result may name a cargo build: clear this package's.
# A package that depends on this one keeps its own (`rm -rf
# .dart_tool/hooks_runner` there).
rm -rf .dart_tool/hooks_runner/switchboard_quic
