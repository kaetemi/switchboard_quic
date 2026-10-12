<!--
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
-->

# Polyverse Switchboard QUIC and WebTransport binding

The binding of [Polyverse Switchboard](https://github.com/kaetemi/switchboard) to transports with native streams, as specified by the wiki page "Polyverse Switchboard QUIC and WebTransport Binding": every channel is a bidirectional stream, records replace mux frames, a control stream carries the control messages, QUIC flow control replaces credit, and the `IDENT` proof binds the TLS exporter.

The binding is written once against a stream provider interface (`lib/src/provider/quic_provider.dart`), for two providers: the native provider over [quinn](https://github.com/quinn-rs/quinn) through FFI (a Rust shim in `native/`), and the web provider over the browser's WebTransport API.

Status: the binding layer is complete for both kinds of session; the native provider speaks raw QUIC (`quic://host:port`) and WebTransport over HTTP/3 (`https://host:port/path`, the HTTP/3 layer in its shim), as a client and as a listener, tested against web-transport-quinn and headless Chromium; the web provider runs the binding over the browser's own WebTransport API, tested in headless Chrome 149 against the native provider's listeners and a Switchboard node behind them.

| Library | What | Platforms |
| --- | --- | --- |
| `package:switchboard_quic/switchboard_quic.dart` | `QuicSwitchboardBinding` and `QuicSwitchboardListener` for `Switchboard` nodes, and everything of `core.dart` | VM (`dart:io`, as the node) |
| `package:switchboard_quic/core.dart` | The provider contract, `QuicBindingConnection` and `QuicChannel`, the wire format | VM and web |
| `package:switchboard_quic/switchboard_quic_native.dart` | `NativeQuicProvider`, the provider contract | VM (`dart:ffi`) |
| `package:switchboard_quic/switchboard_quic_web.dart` | `WebQuicProvider`, and everything of `core.dart` | Browsers (`dart:js_interop`, `package:web`) |

## The binding layer

`lib/src/binding/` is the reference implementation of the binding page, written once against the provider contract:

* `QuicBindingConnection` (a `BindingConnection`) and `QuicChannel` (a `MuxChannel`) carry the connection and channel contracts of the core package over a `QuicSession`, so that a `Switchboard` node, Talk, the proxy and everything above them run unchanged. A channel is one bidirectional stream: the opener's direction starts with an OPEN record (`u48` channel id, then the open payload), subframes are DATA records (`u32` header, length in bits 0 to 29, command in bits 30 and 31), and each side ends its direction with a CLOSE record and FIN, or a reset carrying the status. The initiator's first stream, whose OPEN record names channel 0, is the control stream: `HELLO` first in each direction (record limit, channels, `EXPORTER`), then `PING`, `PONG`, `GOAWAY`, `NONCE` and `IDENT`.
* `QuicSwitchboardBinding` gives a node its `quic://host:port` endpoints (raw QUIC, ALPN `switchboard`) and its `https://host:port/path` endpoints (WebTransport sessions offering the protocol `switchboard`), dialled through its connector; a connector that cannot dial a scheme fails with `unsupportedScheme` (the node's `UNIMPLEMENTED`, and its next endpoint). Between nodes the WebTransport listener's certificate is self-signed like a raw QUIC one: such a binding passes `webTransportCertificateVerified: false` (or a pin), and identity comes from exporter-bound `IDENT`s over the session's exporter (label `switchboard-ident`). A dial is bounded by the node's connect timeout, which is also the handshake deadline it asks the provider for; a session the provider yields after the dial gave up is closed with `CANCELLED`, since a connect cannot be cancelled. The QUIC idle timeout (30 s) and the stack's keep-alive (`keepAlive`, by default a third of the idle timeout) are the binding's; the control `PING` stays the node's `MuxOptions.keepAliveInterval`, the application's probe (binding page, "Keep-alive"). `QuicSwitchboardListener` adopts a `QuicListener`'s sessions into a node (`Switchboard.adopt`) and declares its endpoint (`Switchboard.addListeningEndpoint`).
* `QuicIdentityRules` are the identification rules of the page's "Certificates" section. Node certificates are self-signed, so where identity is in use the binding authenticates a connection with exporter-bound `IDENT`s in each direction: by default a dialling node with a credential identifies first and uses the connection only once the listener's exporter-bound `IDENT` naming it has verified, closes the connection with `UNAUTHENTICATED` when a `HELLO` lacks `EXPORTER`, and presents a bearer credential only to an authenticated end; a listener refuses nonce-bound `IDENT`s and identifies in turn, naming the peer, only to a peer whose exporter-bound `IDENT` verified. A pin (`certificateHashes`) or a verified certificate authenticates the listener and lifts the dialling side's rules; a listener that serves only browsers passes `QuicIdentityRules.none`.
* The wire format (records, `HELLO`, error codes, the exporter labels and the WebTransport code mapping) is public, for providers and tests.
* `connectQuicBinding(connector, endpoint, ...)` is the dial of `QuicSwitchboardBinding` on its own: it connects through a provider, starts a `QuicBindingConnection` as the initiator with the identification rules the certificate's verification calls for, and fails with the statuses a node's dial does. It is what a browser frontend gives `ReconnectingClient.connections` (see "The web provider").
* `package:switchboard_quic/core.dart` compiles for the web: the provider contract, `QuicBindingConnection`, `QuicChannel`, `connectQuicBinding` and the wire format, for a browser frontend over the web provider. `package:switchboard_quic/switchboard_quic.dart` adds `QuicSwitchboardBinding` and `QuicSwitchboardListener`, which need `dart:io` as the node does.

```dart
final binding = QuicSwitchboardBinding(connector);          // a provider's QuicConnector
final node = Switchboard(bindings: [binding], credential: credential, holderKey: key);
final talk = await node.openTalkAt(Uri.parse('quic://hub.example:4433'), address);

final listener = await QuicSwitchboardListener.start(
  server,                                                   // a Switchboard node
  quicListener,                                             // a provider's QuicListener
  policy: ChannelPolicies.scoped(),
);
```

The provider's own configuration of a listener (its certificate, its windows, its timeouts) is the provider's; give it the node's `MuxOptions.initialWindow` as the stream receive window and a connection window of `MuxOptions.receiveHighWaterMarkBytes`, as `QuicSwitchboardBinding` does for the sessions it dials. Its timeouts follow the binding's rule: a stack keep-alive shorter than the idle timeout, so that a quiet connection is not closed between two of its `PING`s, and a handshake deadline, so that a client that goes silent halfway through its handshake does not hold its state. `QuicServerConfig`'s defaults (idle timeout 30 s, keep-alive 10 s, handshake 10 s) do both; the tests and `tool/native_smoke.dart` keep to the rule, and turn the keep-alive off only where a test is about the idle timeout itself.

## The native provider

`package:switchboard_quic/switchboard_quic_native.dart` (Dart VM only) exports `NativeQuicProvider`: raw QUIC (`quic://host:port`, ALPN `switchboard`) and WebTransport over HTTP/3 (`https://host:port/path`), over quinn, through the Rust shim in `native/sbq` (see `native/README.md`), which carries the HTTP/3 layer. quinn's stream priorities are strict between levels and round robin within one, so the provider puts the priority classes 1 (ordinary) and 0 (bulk) on one level and class 2 (control) above it (`NativeQuicStream.quinnPriority`).

Two nodes over it, as `test/native_integration_test.dart` runs them:

```dart
final provider = NativeQuicProvider();                     // one per isolate
final cert = NativeQuicProvider.generateSelfSigned('node.example');

// The listening node: a self-signed certificate (ECDSA P-256, 14 days, so
// that browsers can pin it too) and the node's windows; the timeouts are
// the defaults (idle 30 s, keep-alive 10 s, handshake 10 s).
final quic = await provider.listen('0.0.0.0', 4433, QuicServerConfig(
  alpn: const [switchboardAlpn],
  certificateDer: cert.certificateDer,
  privateKeyDer: cert.privateKeyDer,
  maxStreamsBidi: 129,                                     // 128 channels and the control stream
  streamReceiveWindow: server.muxOptions.initialWindow,
  connectionReceiveWindow: server.muxOptions.receiveHighWaterMarkBytes,
), advertisedHost: 'node.example');
final listener = await QuicSwitchboardListener.start(server, quic,
    policy: ChannelPolicies.scoped());

// A dialling node: no certificate verification (identity comes from the
// exporter-bound IDENTs), or a pin with certificateHashes: [cert.sha256].
final client = Switchboard(
  bindings: [QuicSwitchboardBinding(provider)],
  credential: credential, holderKey: key, verifier: verifier,
);
final talk = await client.openTalkAt(Uri.parse('quic://node.example:4433'), address);
```

The provider alone (`connect`, `listen`, `listenWebTransport`, sessions and streams) is what `tool/native_smoke.dart` and `test/native_provider_test.dart` exercise. Raw QUIC has no draining signal and grants the peer no unidirectional streams, so `draining` never completes and `incomingUnidirectionalStreams` stays empty; a reset is observed even while nobody reads (`resetReceived`).

### WebTransport

`connect` dials an `https://host:port/path` endpoint (port 443 by default) as a WebTransport session: a QUIC connection with the ALPN `h3` (the provider's own), HTTP/3 over it, and an extended CONNECT offering `QuicClientConfig.alpn` as its protocols (`WT-Available-Protocols`; `switchboard` for Switchboard). The session is established by the server's 2xx; another status fails the connect with `QuicExceptionKind.refused` and the status in its message. `connectWebTransport` does the same with an `Origin` header of the caller's choice. Certificates are verified as for raw QUIC: the platform roots, a pin (`serverCertificateHashes`), or not at all. The session's exporter applies WebTransport's per-session derivation (`EXPORTER-WebTransport` with the session ID) to the application's label and context; stream and close codes are WebTransport application codes (0 to 2^32 - 1), and a reset or `STOP_SENDING` the peer sent outside that range arrives without a code (null); `draining` completes on the peer's `WT_DRAIN_SESSION` or an HTTP/3 `GOAWAY` (`NativeQuicSession.drain` sends one); the peer's unidirectional streams are delivered for the binding to refuse.

```dart
// A listener for WebTransport on https://node.example:4433/sb (UDP).
final wt = await provider.listenWebTransport('0.0.0.0', 4433, QuicServerConfig(
  alpn: const [switchboardAlpn],                           // not used: the listener serves h3
  certificateDer: cert.certificateDer,
  privateKeyDer: cert.privateKeyDer,
  maxStreamsBidi: 129,                                     // plus one for the CONNECT stream
  streamReceiveWindow: server.muxOptions.initialWindow,
  connectionReceiveWindow: server.muxOptions.receiveHighWaterMarkBytes,
), path: '/sb', allowedOrigins: ['https://app.example'], advertisedHost: 'node.example');
await QuicSwitchboardListener.start(server, wt, policy: ChannelPolicies.scoped());

// A node dialling it: the certificate is self-signed, identity comes from IDENT.
final client = Switchboard(bindings: [
  QuicSwitchboardBinding(provider, webTransportCertificateVerified: false),
], credential: credential, holderKey: key, verifier: verifier);
final talk = await client.openTalkAt(Uri.parse('https://node.example:4433/sb'), address);
```

A listener answers each request itself: another path than its own 404 (the query aside), an `Origin` outside `allowedOrigins` 403 (a request without `Origin` is not a browser's and passes; null allows any origin; the origins match as strings, so give the browser's serialized origin, scheme, host and port, without a trailing slash), protocols offered of which it serves none 400, and after `close` 503 on the connections still open; otherwise it selects the first protocol the client offered that it serves, or none when the client offered none, and the session arrives on `sessions` (with its request: `requestPath`, `requestAuthority`, `requestOrigin`, `requestProtocols`, `requestDraft`). The `:authority` is not checked (it is `requestAuthority`): a node is reached under other names and ports than the ones it advertises (a DNS name or an address, a port forwarded by NAT or a load balancer; `advertisedHost` names the endpoint only), and what protects a session is its certificate, its `Origin` and identification. The `answered` counts are the listener's own answers; the shim answers a request not answered within the configuration's `handshakeTimeout` (10 s when it is zero), and every request after `close`, with 503 itself, and an offer of a protocol outside 1 to 255 printable ASCII bytes with 400. Dialling, the provider refuses an endpoint with userinfo, sends its query, and drops its fragment; the handshake deadline bounds the QUIC handshake and again the HTTP/3 exchange (10 s when it is zero). A WebTransport `close` completes once the peer's stack acknowledged the close (`WT_CLOSE_SESSION` and FIN), or after three round trips (0.2 to 2 s) without that, so that the provider can be shut down after it without cutting the close short. `listenWebTransport` and `listen` take two UDP ports: the transport parameters of HTTP/3 (unidirectional streams, the datagram parameter) differ from raw QUIC's, and quinn fixes them per listener before it knows the ALPN of a connection (the shim can serve both ALPNs on one port, with HTTP/3's parameters for both; the provider does not offer it).

Versions: Chrome 149 speaks WebTransport draft-02 (`SETTINGS_ENABLE_WEBTRANSPORT`, the `sec-webtransport-http3-draft02` request header), web-transport-quinn 0.13.2 the draft-07 signalling (`SETTINGS_WEBTRANSPORT_MAX_SESSIONS`); both send `WT-Available-Protocols`. The shim speaks both, as client and server, and answers in the version the client signalled; see `native/README.md`. Neither enables the session flow control of the later drafts, so a client uses one session per connection (the provider's client always does).

### Browsers and certificates

A browser reaches a WebTransport listener with the W3C API: `new WebTransport('https://node.example:4433/sb', {protocols: ['switchboard']})`, `wt.protocol` then being `'switchboard'`. With a certificate from a public authority, nothing else is needed. With a self-signed one (development, a LAN, a device), the page passes its hash: `serverCertificateHashes: [{algorithm: 'sha-256', value: hash}]`, where the browser accepts only an X.509v3 certificate with an ECDSA P-256 key whose validity is current and at most 14 days long. `NativeQuicProvider.generateSelfSigned(subject)` makes exactly that (ECDSA P-256, valid from five minutes ago for 14 days; `validityDays` beyond 14 makes one browsers refuse for a hash), and `NativeCertificate.sha256` is the hash to give the page; rotate as the binding page's "Certificates" says. The listener's `allowedOrigins` names the pages allowed (the browser sends its page's origin). Chrome 149 has no `exportKeyingMaterial`, so its `IDENT` proofs are nonce-bound, which is safe for it since it verified the certificate; a listener that serves browsers therefore passes `QuicIdentityRules.none` to `QuicSwitchboardListener.start` (whose default refuses nonce-bound proofs, for nodes). The web provider (see "The web provider") is the binding's side of it in the browser.

`tool/browser_smoke.sh` runs it end to end: `tool/browser_server.dart` (a listener with a fresh certificate, and the page) and headless Chromium driven over the DevTools protocol by `tool/browser_probe.mjs` (the protocol selected, an echo, a stream aborted with 42, another path refused, a close with 7 and a reason). It needs Chromium (`CHROME`, by default Playwright's under `~/.cache/ms-playwright`) and node, and skips without them; the Dart suite does not depend on it. `SBQ_TRACE=1` makes the shim write what peers send (SETTINGS, requests, responses) to stderr.

### Building the shim

The package's build hook (`hook/build.dart`) supplies the shim to `dart run`, `dart test` and `dart build cli`: a prebuilt library from `native/sbq/prebuilt/<os>_<arch>/` when there is one, else `cargo build --release` for the host when `cargo` is on `PATH` (about a minute the first time), else a clear failure. So either place a prebuilt library there or install a Rust toolchain (<https://rustup.rs>; ring needs a C compiler). By hand:

```sh
cd native/sbq
cargo build --release            # target/release/libsbq.so (+ libsbq.a)
cargo test                       # ABI self test
cargo clippy --all-targets       # kept warning-free
```

Compile programs ahead of time with `dart build cli`, which bundles the library (ship the bundle directory); a `dart compile exe` binary finds the library next to the executable, in `../lib`, or through `SBQ_LIBRARY`. The Dart layer refuses a library of another ABI version (`SBQ_ABI_VERSION`, now 4: WebTransport sessions), so a prebuilt library must come from the same version of the package. After an ABI change, regenerate `native/sbq/include/sbq.h` (cbindgen) and `lib/src/native/sbq_bindings.g.dart` (`dart run ffigen --config ffigen.yaml`) and bump `SBQ_ABI_VERSION`; `native/README.md` has the details, the ABI and the platforms.

## The web provider

`package:switchboard_quic/switchboard_quic_web.dart` (browsers only) exports `WebQuicProvider`, a `QuicConnector` over the browser's W3C WebTransport API, and everything of `core.dart`, so that a frontend reaches a Switchboard node over WebTransport with one import. A browser cannot listen: the provider dials `https://host:port/path` only (`quic://` and every other scheme fail with `unsupportedScheme`, as does a browser without the API, so that a node's next endpoint is tried). The usual frontend keeps one connection up with core's `ReconnectingClient`, whose `connections` constructor takes the binding's dial:

```dart
import 'package:switchboard/core.dart';
import 'package:switchboard_quic/switchboard_quic_web.dart';

final client = ReconnectingClient.connections(
  (options) => connectQuicBinding(
    const WebQuicProvider(),
    Uri.parse('https://node.example:4433/sb'),
    options: options,                          // the client's MuxOptions
    certificateHashes: [hash],                 // only for a self-signed certificate
  ),
);
final talk = await client.openTalk(ChannelAddress(type: Name('profile')));
final reply = await talk.request('GET', Uint8List(0));
```

* **Certificates.** With a certificate from a public authority, nothing more is needed. With a self-signed one (development, a LAN, a device), the page passes its SHA-256 (`certificateHashes`, the W3C `serverCertificateHashes`): an ECDSA P-256 certificate valid for at most 14 days, as `NativeQuicProvider.generateSelfSigned` makes; the hashes come from the application that starts the client, never from the endpoint (see "Browsers and certificates"). The browser always verifies the certificate, so `connectQuicBinding` applies `QuicIdentityRules.initiator(certificateVerified: true)`: the TLS handshake authenticated the node, and nothing more is required.
* **Identity.** A browser without `exportKeyingMaterial` (Chrome 149) computes no exporter: its `HELLO` lacks `EXPORTER`, and its `IDENT` proofs are nonce-bound, which is safe for it since it verified the certificate; the node's listener passes `QuicIdentityRules.none`. A browser that has `exportKeyingMaterial` sets `EXPORTER` and binds its proofs like any node (the provider asks for the label `switchboard-ident`, and takes the result only when it is 32 bytes). Frontends keep presenting their credentials in channel payloads, as over `wss`.
* **What the provider does with the API.** `connect` opens `new WebTransport(url, {protocols: ['switchboard'], serverCertificateHashes, allowPooling: false, requireUnreliable: false})` and waits for `ready`, bounded by the configuration's handshake deadline (then `unreachable`); the browser decides the windows, stream limits, idle timeout and keep-alive. `protocol` is `wt.protocol`; `draining` is `wt.draining` where the browser has it; the session's end is `wt.closed` (its close info as an application close, by the peer unless it is this side's own; a rejection as a loss). `openStream` is `createBidirectionalStream`, and the server's streams come from `incomingBidirectionalStreams` and `incomingUnidirectionalStreams`, read only while someone listens. A stream holds the default reader of its readable and the writer of its writable: `read(max)` takes at most one browser chunk, returns at most `max` bytes and keeps the rest for the next read, and what was not read stays in the browser's stream, whose flow control is the browser's; a write copies the bytes and hands them to the writer once its `ready` allows, completing when the browser took them; `finish` is `writer.close()`, `reset(code)` `writer.abort(new WebTransportError({streamErrorCode}))`, `stop(code)` `reader.cancel(...)` with one; `resetReceived` and `stopped` come from the reader's and the writer's `closed` (a `WebTransportError` of source `stream` and its `streamErrorCode`), so that a paused reader still sees a reset. Every promise has a handler; readers and writers release their locks once their direction has ended, and a stream the provider drops is stopped and reset first. Priority classes become `sendOrder`s where the browser has them (2: 1; 1 and 0: 0, so that neither starves the other), in two send groups where it has `createSendGroup` (2 and 1 in one, 0 in the other); `WebQuicSession.stats()` reads `getStats` where it exists; `WebQuicSession.capabilities` tells which of these the browser has.
* **Chrome 149**, as the tests find it: `wt.protocol` is there; `draining`, `exportKeyingMaterial`, `getStats`, `createSendGroup` and the streams' `sendOrder` are not (the binding's control stream shares the browser's own scheduling, and `draining` stays pending: the binding's `GOAWAY` on the control stream does that work). Its `WebTransportError` takes `{message, streamErrorCode}` (not the specification's `(message, options)`, which the provider tries first) and carries an octet, so stream error codes above 255 are argument errors here (`WebQuicProvider.maxStreamErrorCode`; the binding sends status codes, 0 to 255, and received codes are not bounded); session close codes are 32-bit, and a reason is cut to 1024 bytes of UTF-8 by the provider (Chrome would send a longer one). A refused request (another path, an origin the server refuses), an unreachable server and a rejected certificate all reject `ready` with "Opening handshake failed.", so all of them fail the connect with `handshakeFailed`. `createBidirectionalStream` rejects while the server grants no stream instead of waiting, whatever `waitUntilAvailable` says, so the provider asks again (from 5 to 200 ms apart) until it gets one or the session ends. `wt.close()` resolves `closed` at once; the browser's network stack sends the close on its own. The streams report the end of the session (`WebTransportError` of source `session`) before `closed` settles, and the provider reads that as the session ending; what the page had not read of them by then is gone, so a node's `GOAWAY` written just before its close reaches the browser as the close (code 0, `GOING_AWAY`). Chrome reports a server's close only after it has answered it, and reads a connection close that arrives before that report as a lost connection ("Connection lost."), which is why the native listener leaves that close to the browser (see `native/README.md`). A reset sent right after a stream's first write can overtake the stream's header at a native listener, which then cannot tell the stream's session (no `RESET_STREAM_AT`, see `native/README.md`): the server never sees that stream.

The browser tests run in headless Chrome against a server of the native provider:

```sh
TMPDIR=/some/scratch tool/web_smoke.sh [log] [dart test arguments]
```

`tool/web_smoke.sh` starts `tool/web_server.dart` (WebTransport listeners on 127.0.0.1 with a fresh certificate: sessions that behave as each test asks and record what the server saw, one that grants two streams, a Switchboard node with Talk services behind `QuicSwitchboardListener` and `QuicIdentityRules.none`, and a UDP port that never answers), writes its description to `test/web_server.json`, which the page fetches next to itself (the test runner serves the package directory), and runs `dart test -P web` under a memory cap, with Chrome for Testing as `CHROME_EXECUTABLE` (through a wrapper that gives Chromium a short `TMPDIR` for its singleton socket); it skips without Chromium (`CHROME` overrides where it is looked for), and the tests skip without the server. `test/web_provider_test.dart` checks the provider against the contract (the protocol, echo, `read(max)`, FIN, resets and `STOP_SENDING` both ways with their codes, closes both ways with their codes and reasons, draining, refusals, the handshake deadline, the exporter, the server's streams, the stream limit, backpressure, two sessions at once, a quiet session outliving the server's handshake deadline), and `test/web_binding_test.dart` the binding over it (`HELLO`, Talk through the node, a nonce-bound `IDENT` accepted, the node's `GOAWAY`, a close from the browser) and `ReconnectingClient.connections` (a request, the node closing the connection and the reconnect, the node's `GOAWAY`); both check that the page saw no unhandled promise rejection. They are compiled with dart2js; `tool/web_smoke.sh log -c dart2wasm` runs them compiled with dart2wasm.

## Tests

Run every suite under a memory cap:

```sh
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 dart test -j 2           # VM
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 dart test -j 2 -P node   # Node.js
(cd native/sbq && cargo test && cargo clippy --all-targets)
TMPDIR=/some/scratch tool/aot_smoke.sh                                                   # AOT
tool/browser_smoke.sh                                                                    # Chromium
TMPDIR=/some/scratch tool/web_smoke.sh                                                   # the web provider in Chrome
```

* Against `test/fake_provider.dart`, an in-memory provider whose stream directions are delivered independently, each in order, with configurable delays (so that streams overtake one another and the control stream), stream and connection flow control, a stream limit, resets and `STOP_SENDING` with codes, FIN, and an exporter equal at both ends of a session and different per session (or none, as in a browser without `exportKeyingMaterial`): `test/vectors_test.dart` checks every byte vector of the binding page; `test/binding_test.dart` the connection and channel contracts; `test/switchboard_test.dart` and `test/review_switchboard_test.dart` two nodes end to end, dial timeouts with a held connect and the stack keep-alive a dial asks for, a man in the middle and the proxy between the frame mux and the binding. `-P node` runs the first two compiled to JavaScript.
* Against the native provider over UDP on the loopback, every case over raw QUIC and over WebTransport: `test/native_provider_test.dart` the provider contract (the handshake deadline against a socket that never answers among it), and the requests, refusals, drain and codes of WebTransport; `test/native_integration_test.dart` Switchboard nodes over the binding over quinn (exporter-bound mutual identification with the exporter equal at both ends, refusal of an unidentified dialler, a pin, Talk, 8 MiB bulk payloads, `whenWritable` pacing, 64 parallel channels, GOAWAY both ways, the idle timeout, the stack keep-alive holding a quiet connection, the proxy toward a frame mux backend), which prints its throughput lines.
* `tool/aot_smoke.sh` compiles `tool/native_smoke.dart` (the provider, then the binding over it, over raw QUIC and over WebTransport) with `dart build cli` and with `dart compile exe` and runs both.
* `tool/browser_smoke.sh` runs headless Chromium against a WebTransport listener of the native provider (see "Browsers and certificates").
* `tool/web_smoke.sh` runs the web provider and the binding over it in headless Chrome (`dart test -P web`) against the native provider's listeners and a Switchboard node (see "The web provider").
