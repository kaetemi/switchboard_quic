#!/bin/sh
# Polyverse Switchboard
# Microservice Network Architecture
# Copyright (C) 2018-2026  Jan BOON (Kaetemi)
# Authors:
#   Jan Boon <jan.boon@kaetemi.be>
#   Claude Opus 5.5 <noreply@anthropic.com>
#
# WebTransport between headless Chromium and the native provider: starts
# tool/browser_server.dart (a WebTransport listener on https://127.0.0.1:port/sb
# with a fresh self-signed certificate, and the page), then headless Chromium,
# and drives it with tool/browser_probe.mjs over the DevTools protocol:
# `new WebTransport(url, {serverCertificateHashes, protocols: ['switchboard']})`,
# the protocol selected, a stream echoed, a stream aborted with 42, a request
# to another path refused, a close with 7 and a reason. Both sides check what
# they saw; the script exits non-zero on any mismatch, and 0 with a SKIPPED line
# when Chromium or node is absent (CHROME and NODE override where they are
# looked for). The Dart suite does not depend on it.
#
# Usage: tool/browser_smoke.sh [log]
# TMPDIR is where the profile goes; Chromium's own singleton socket goes to
# CHROME_TMPDIR (/tmp by default: a Unix socket path is limited to about 100
# bytes), which Chromium removes when it exits.
set -u
cd "$(dirname "$0")/.."
log=${1:-/dev/null}
CHROME=${CHROME:-$HOME/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome}
NODE=${NODE:-$(command -v node || true)}
if [ ! -x "$CHROME" ]; then
  echo "browser smoke: SKIPPED: no Chromium at $CHROME (set CHROME)" | tee -a "$log"
  exit 0
fi
if [ -z "$NODE" ] || [ ! -x "$NODE" ]; then
  echo "browser smoke: SKIPPED: no node (set NODE)" | tee -a "$log"
  exit 0
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/browser_smoke.XXXXXX")
stop_chrome() {
  [ -z "${chrome_pid:-}" ] && return
  # Browser.close from the probe: give it time to exit by itself.
  for _ in $(seq 1 50); do
    kill -0 "$chrome_pid" 2>/dev/null || break
    sleep 0.1
  done
  kill "$chrome_pid" 2>/dev/null && wait "$chrome_pid" 2>/dev/null
  chrome_pid=""
  # Its singleton socket's directory, if it did not remove it.
  socket=$(readlink "$work/profile/SingletonSocket" 2>/dev/null || true)
  case "$socket" in
    */org.chromium.Chromium.*/SingletonSocket) rm -rf "$(dirname "$socket")" ;;
  esac
}
cleanup() {
  stop_chrome
  [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT

dart run tool/browser_server.dart > "$work/server.out" 2> "$work/server.err" &
server_pid=$!
ready=""
for _ in $(seq 1 600); do
  ready=$(sed -n 's/^READY //p' "$work/server.out")
  [ -n "$ready" ] && break
  if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
  sleep 0.1
done
if [ -z "$ready" ]; then
  echo "browser smoke: FAILED: the server did not start" | tee -a "$log"
  cat "$work/server.out" "$work/server.err" | tee -a "$log"
  exit 1
fi
field() {
  "$NODE" -e "console.log(JSON.parse(process.argv[1])[process.argv[2]])" "$ready" "$1"
}
wt=$(field webtransport)
page=$(field page)
hash=$(field certificateSha256)
echo "browser smoke: server $ready" | tee -a "$log"

TMPDIR=${CHROME_TMPDIR:-/tmp} "$CHROME" --headless=new --no-sandbox --remote-debugging-port=0 \
  --user-data-dir="$work/profile" --no-first-run --no-default-browser-check \
  about:blank > "$work/chrome.log" 2>&1 &
chrome_pid=$!
port=""
for _ in $(seq 1 100); do
  [ -f "$work/profile/DevToolsActivePort" ] && port=$(head -n 1 "$work/profile/DevToolsActivePort")
  [ -n "$port" ] && break
  sleep 0.1
done
if [ -z "$port" ]; then
  echo "browser smoke: FAILED: Chromium did not start" | tee -a "$log"
  cat "$work/chrome.log" | tee -a "$log"
  exit 1
fi

timeout 60 "$NODE" tool/browser_probe.mjs "$port" "$page" "$hash" "$wt" > "$work/probe.out" 2>&1
probe=$?
wait "$server_pid"
server=$?
server_pid=""
stop_chrome
cat "$work/probe.out" | tee -a "$log"
grep -v '^READY ' "$work/server.out" | tee -a "$log"
cat "$work/server.err" | tee -a "$log"
if [ "$probe" -ne 0 ] || [ "$server" -ne 0 ]; then
  echo "browser smoke: FAILED (probe $probe, server $server)" | tee -a "$log"
  exit 1
fi
echo "browser smoke: OK" | tee -a "$log"
