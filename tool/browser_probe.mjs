/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// The browser side of tool/browser_smoke.sh: drives headless Chromium over
// the DevTools protocol (node's own fetch and WebSocket), opens the page the
// server serves, and runs the W3C WebTransport API in it against the
// server: `new WebTransport(url, {serverCertificateHashes, protocols:
// ['switchboard']})`, a bidirectional stream echoed, a second one aborted
// with streamErrorCode 42, a session to another path (refused), and
// `close({closeCode: 7, reason})`. Prints `PROBE {json}` and exits non-zero
// when the browser's side differs from what is expected.
//
// Usage: node browser_probe.mjs <devtools port> <page url> <certificate
// sha-256 hex> <webtransport url>

const [, , port, pageUrl, certHex, wtUrl] = process.argv;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let version;
for (let i = 0; i < 100 && !version; i++) {
  try {
    version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  } catch {
    await sleep(100);
  }
}
if (!version) {
  console.log('PROBE {"error": "no DevTools endpoint"}');
  process.exit(2);
}
const target = await (
  await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(pageUrl)}`, {
    method: 'PUT',
  })
).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener('open', r));
let id = 0;
const pending = new Map();
ws.addEventListener('message', (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) {
    pending.get(m.id)(m);
    pending.delete(m.id);
  }
});
const call = (method, params = {}) =>
  new Promise((r) => {
    const i = ++id;
    pending.set(i, r);
    ws.send(JSON.stringify({ id: i, method, params }));
  });
// The page loads.
for (let i = 0; i < 50; i++) {
  const r = await call('Runtime.evaluate', {
    expression: 'document.readyState + " " + location.href',
    returnByValue: true,
  });
  if (`${r.result?.result?.value}`.startsWith('complete http')) break;
  await sleep(100);
}

const expression = `(async () => {
  const out = { browser: navigator.userAgent, secureContext: window.isSecureContext };
  const hash = new Uint8Array('${certHex}'.match(/../g).map((h) => parseInt(h, 16)));
  const options = {
    serverCertificateHashes: [{ algorithm: 'sha-256', value: hash }],
    protocols: ['switchboard'],
  };
  const enc = new TextEncoder(), dec = new TextDecoder();
  const timeout = (p, ms, what) => Promise.race([
    p, new Promise((_, no) => setTimeout(() => no(new Error(what + ' timed out')), ms)),
  ]);
  try {
    const wt = new WebTransport('${wtUrl}', options);
    await timeout(wt.ready, 8000, 'ready');
    out.ready = true;
    out.protocol = wt.protocol;
    out.exportKeyingMaterial = typeof wt.exportKeyingMaterial;
    if (typeof wt.exportKeyingMaterial === 'function') {
      try {
        const k = await wt.exportKeyingMaterial(enc.encode('switchboard-ident'));
        out.exporter = Array.from(new Uint8Array(k)).map((x) => x.toString(16).padStart(2, '0')).join('');
      } catch (e) { out.exporter = 'error: ' + e; }
    }
    // A stream echoed.
    const s = await wt.createBidirectionalStream();
    const w = s.writable.getWriter();
    await w.write(enc.encode('hello switchboard'));
    await w.close();
    const rd = s.readable.getReader();
    let got = '';
    for (;;) { const { value, done } = await rd.read(); if (done) break; got += dec.decode(value); }
    out.echo = got;
    // A stream aborted with 42.
    const s2 = await wt.createBidirectionalStream();
    const w2 = s2.writable.getWriter();
    await w2.write(enc.encode('to be aborted'));
    await w2.abort(new WebTransportError({ message: 'aborted by the probe', streamErrorCode: 42 }));
    s2.readable.cancel().catch(() => {});
    await new Promise((r) => setTimeout(r, 300));
    // Another path: refused.
    try {
      const other = new WebTransport('${wtUrl}'.replace(/\\/sb$/, '/elsewhere'), options);
      other.closed.catch(() => {});
      await timeout(other.ready, 8000, 'ready elsewhere');
      out.otherPath = 'connected';
      other.close();
    } catch (e) {
      out.otherPath = 'refused: ' + e.name + (e.source ? ' (' + e.source + ')' : '');
    }
    wt.close({ closeCode: 7, reason: 'browser done' });
    out.closed = await timeout(wt.closed, 5000, 'closed');
  } catch (e) {
    out.error = e.name + ': ' + e.message + (e.source ? ' source=' + e.source : '');
  }
  return JSON.stringify(out);
})()`;
const r = await call('Runtime.evaluate', {
  expression,
  awaitPromise: true,
  returnByValue: true,
});
await call('Browser.close').catch(() => {});
let out;
try {
  out = JSON.parse(r.result?.result?.value);
} catch {
  out = { error: 'no result: ' + JSON.stringify(r) };
}
const failures = [];
if (!out.secureContext) failures.push('not a secure context');
if (!out.ready) failures.push('the session was not established');
if (out.protocol !== 'switchboard') failures.push(`wt.protocol is ${JSON.stringify(out.protocol)}`);
if (out.echo !== 'hello switchboard') failures.push('the echo');
if (!`${out.otherPath}`.startsWith('refused')) failures.push('the request to another path');
if (out.closed?.closeCode !== 7) failures.push('the close');
if (out.error) failures.push(out.error);
out.failures = failures;
console.log('PROBE ' + JSON.stringify(out));
process.exit(failures.length ? 1 : 0);
