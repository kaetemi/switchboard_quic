#!/bin/sh
# Polyverse Switchboard
# Microservice Network Architecture
# Copyright (C) 2018-2026  Jan BOON (Kaetemi)
# Authors:
#   Jan Boon <jan.boon@kaetemi.be>
#   Claude Opus 5.5 <noreply@anthropic.com>
#
# The browser tests of the web provider: starts tool/web_server.dart (native
# WebTransport listeners on 127.0.0.1 with a fresh self-signed certificate,
# and a Switchboard node behind one), writes its description to
# test/web_server.json (the test runner serves the package directory, and the
# tests fetch it next to their page), runs `dart test -P web` (headless
# Chrome, dart2js: test/web_provider_test.dart, test/web_binding_test.dart),
# then stops the server and removes the description. Exits non-zero on any
# failure, and 0 with a SKIPPED line when Chromium is absent (CHROME overrides
# where it is looked for).
#
# Usage: tool/web_smoke.sh [log] [dart test arguments...]
# TMPDIR is where the run's files go (the test runner's, the browser
# profile); Chromium's own singleton socket goes to CHROME_TMPDIR (/tmp by
# default: a Unix socket path is limited to about 100 bytes), through a
# wrapper that removes it when Chromium exits. The tests run under a memory
# cap (systemd-run, where a user manager is available).
set -u
cd "$(dirname "$0")/.."
log=${1:-/dev/null}
[ $# -gt 0 ] && shift
CHROME=${CHROME:-$HOME/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome}
if [ ! -x "$CHROME" ]; then
  echo "web smoke: SKIPPED: no Chromium at $CHROME (set CHROME)" | tee -a "$log"
  exit 0
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/web_smoke.XXXXXX")
info=test/web_server.json
cleanup() {
  [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null && wait "$server_pid" 2>/dev/null
  rm -f "$info"
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Chromium with a short TMPDIR, its singleton socket's directory removed when
# it exits (the test runner removes the profile right after).
cat > "$work/chrome" <<WRAPPER
#!/bin/sh
profile=""
for a in "\$@"; do
  case "\$a" in --user-data-dir=*) profile=\${a#--user-data-dir=} ;; esac
done
TMPDIR="${CHROME_TMPDIR:-/tmp}" "$CHROME" "\$@" &
pid=\$!
trap 'kill -TERM \$pid 2>/dev/null' TERM INT HUP
wait \$pid
status=\$?
while kill -0 \$pid 2>/dev/null; do
  wait \$pid
  status=\$?
done
socket=\$(readlink "\$profile/SingletonSocket" 2>/dev/null || true)
case "\$socket" in
  */org.chromium.Chromium.*/SingletonSocket) rm -rf "\$(dirname "\$socket")" ;;
esac
exit \$status
WRAPPER
chmod +x "$work/chrome"

dart run tool/web_server.dart > "$work/server.out" 2> "$work/server.err" &
server_pid=$!
ready=""
for _ in $(seq 1 600); do
  ready=$(sed -n 's/^READY //p' "$work/server.out")
  [ -n "$ready" ] && break
  if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [ -z "$ready" ]; then
  echo "web smoke: FAILED: the server did not start" | tee -a "$log"
  cat "$work/server.out" "$work/server.err" | tee -a "$log"
  exit 1
fi
printf '%s\n' "$ready" > "$info"
echo "web smoke: server $ready" | tee -a "$log"

cap=""
if command -v systemd-run > /dev/null 2>&1 &&
  systemd-run --user --scope -q true > /dev/null 2>&1; then
  cap="systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0"
fi
CHROME_EXECUTABLE="$work/chrome" $cap dart test -j 2 -P web "$@" 2>&1 | tee -a "$log" | tee "$work/test.out"
tests=$(sed -n 's/.*+\([0-9]*\).*/\1/p' "$work/test.out" | tail -n 1)
verdict=$(tail -n 1 "$work/test.out")
if ! kill -0 "$server_pid" 2>/dev/null; then
  echo "web smoke: FAILED: the server died" | tee -a "$log"
  cat "$work/server.err" | tee -a "$log"
  exit 1
fi
kill "$server_pid" 2>/dev/null
wait "$server_pid"
server=$?
server_pid=""
cat "$work/server.err" | tee -a "$log"
case "$verdict" in
  *"All tests passed!"*) ;;
  *)
    echo "web smoke: FAILED (${tests:-0} passed before: $verdict)" | tee -a "$log"
    exit 1
    ;;
esac
if grep -q 'no server' "$work/test.out"; then
  echo "web smoke: FAILED: the tests did not find the server" | tee -a "$log"
  exit 1
fi
if grep -q '\[E\]' "$work/test.out"; then
  echo "web smoke: FAILED: an [E] line" | tee -a "$log"
  exit 1
fi
if [ "$server" -ne 0 ]; then
  echo "web smoke: FAILED: the server exited with $server" | tee -a "$log"
  exit 1
fi
echo "web smoke: OK ($tests tests)" | tee -a "$log"
