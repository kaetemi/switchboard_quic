#!/bin/sh
# Builds tool/native_smoke.dart ahead of time, twice, and runs both:
# 1. `dart build cli`, the AOT build that runs hook/build.dart and bundles the
#    shim (bundle/bin/native_smoke with bundle/lib/libsbq.so);
# 2. `dart compile exe`, which runs no build hooks (and refuses entry points
#    under bin/ of a package that has one): the provider then loads the shim
#    from next to the executable (or from $SBQ_LIBRARY) into the process.
set -e
cd "$(dirname "$0")/.."
out="${TMPDIR:-/tmp}/switchboard_quic_aot_smoke"
rm -rf "$out"
dart build cli -t tool/native_smoke.dart -o "$out/build"
"$out/build/bundle/bin/native_smoke"
mkdir -p "$out/exe"
dart compile exe tool/native_smoke.dart -o "$out/exe/native_smoke"
cp "$out/build/bundle/lib/"*sbq* "$out/exe/"
"$out/exe/native_smoke"
