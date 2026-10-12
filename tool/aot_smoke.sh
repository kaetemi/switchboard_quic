#!/bin/sh
# Polyverse Switchboard
# Microservice Network Architecture
# Copyright (C) 2018-2026  Jan BOON (Kaetemi)
# Authors:
#   Jan Boon <jan.boon@kaetemi.be>
#   Claude Opus 5.5 <noreply@anthropic.com>
#
# Builds tool/native_smoke.dart ahead of time, twice, and runs both:
# 1. `dart build cli`, the AOT build that runs hook/build.dart and bundles the
#    shim (bundle/bin/native_smoke with bundle/lib/libsbq.so, libsbq.dylib on
#    macOS, sbq.dll on Windows);
# 2. `dart compile exe`, which runs no build hooks (and refuses entry points
#    under bin/ of a package that has one): the provider then loads the shim
#    from next to the executable (or from $SBQ_LIBRARY) into the process.
# Linux, macOS, and Windows under Git Bash (MSYS2), where the executables are
# .exe files. TMPDIR is where the builds go.
set -e
cd "$(dirname "$0")/.."
out="${TMPDIR:-/tmp}/switchboard_quic_aot_smoke"
exe=""
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN*) exe=".exe" ;;
esac
rm -rf "$out"
dart build cli -t tool/native_smoke.dart -o "$out/build"
"$out/build/bundle/bin/native_smoke$exe"
mkdir -p "$out/exe"
dart compile exe tool/native_smoke.dart -o "$out/exe/native_smoke$exe"
cp "$out/build/bundle/lib/"*sbq* "$out/exe/"
"$out/exe/native_smoke$exe"
