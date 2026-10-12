# Polyverse Switchboard QUIC and WebTransport binding

The binding of [Polyverse Switchboard](https://github.com/kaetemi/switchboard) to transports with native streams, as specified by the wiki page "Polyverse Switchboard QUIC and WebTransport Binding": every channel is a bidirectional stream, records replace mux frames, a control stream carries the control messages, QUIC flow control replaces credit, and the `IDENT` proof binds the TLS exporter.

The binding is written once against a stream provider interface (`lib/src/provider/quic_provider.dart`), for two providers: the native provider over [quinn](https://github.com/quinn-rs/quinn) through FFI (a Rust shim in `native/`), and the web provider over the browser's WebTransport API.

Status: the binding layer is complete for both kinds of session; the native provider speaks raw QUIC (`quic://host:port`) and WebTransport over HTTP/3 (`https://host:port/path`, the HTTP/3 layer in its shim), as a client and as a listener, tested against web-transport-quinn and headless Chromium. Not there yet: the web provider (the browser's own WebTransport API under the binding).

| Library | What | Platforms |
| --- | --- | --- |
| `package:switchboard_quic/switchboard_quic.dart` | `QuicSwitchboardBinding` and `QuicSwitchboardListener` for `Switchboard` nodes, and everything of `core.dart` | VM (`dart:io`, as the node) |
| `package:switchboard_quic/core.dart` | The provider contract, `QuicBindingConnection` and `QuicChannel`, the wire format | VM and web |
| `package:switchboard_quic/switchboard_quic_native.dart` | `NativeQuicProvider`, the provider contract | VM (`dart:ffi`) |

## The binding layer

`lib/src/binding/` is the reference implementation of the binding page, written once against the provider contract:

* `QuicBindingConnection` (a `BindingConnection`) and `QuicChannel` (a `MuxChannel`) carry the connection and channel contracts of the core package over a `QuicSession`, so that a `Switchboard` node, Talk, the proxy and everything above them run unchanged. A channel is one bidirectional stream: the opener's direction starts with an OPEN record (`u48` channel id, then the open payload), subframes are DATA records (`u32` header, length in bits 0 to 29, command in bits 30 and 31), and each side ends its direction with a CLOSE record and FIN, or a reset carrying the status. The initiator's first stream, whose OPEN record names channel 0, is the control stream: `HELLO` first in each direction (record limit, channels, `EXPORTER`), then `PING`, `PONG`, `GOAWAY`, `NONCE` and `IDENT`.
* `QuicSwitchboardBinding` gives a node its `quic://host:port` endpoints (raw QUIC, ALPN `switchboard`) and its `https://host:port/path` endpoints (WebTransport sessions offering the protocol `switchboard`), dialled through its connector; a connector that cannot dial a scheme fails with `unsupportedScheme` (the node's `UNIMPLEMENTED`, and its next endpoint). Between nodes the WebTransport listener's certificate is self-signed like a raw QUIC one: such a binding passes `webTransportCertificateVerified: false` (or a pin), and identity comes from exporter-bound `IDENT`s over the session's exporter (label `switchboard-ident`). A dial is bounded by the node's connect timeout, which is also the handshake deadline it asks the provider for; a session the provider yields after the dial gave up is closed with `CANCELLED`, since a connect cannot be cancelled. The QUIC idle timeout (30 s) and the stack's keep-alive (`keepAlive`, by default a third of the idle timeout) are the binding's; the control `PING` stays the node's `MuxOptions.keepAliveInterval`, the application's probe (binding page, "Keep-alive"). `QuicSwitchboardListener` adopts a `QuicListener`'s sessions into a node (`Switchboard.adopt`) and declares its endpoint (`Switchboard.addListeningEndpoint`).
* `QuicIdentityRules` are the identification rules of the page's "Certificates" section. Node certificates are self-signed, so where identity is in use the binding authenticates a connection with exporter-bound `IDENT`s in each direction: by default a dialling node with a credential identifies first and uses the connection only once the listener's exporter-bound `IDENT` naming it has verified, closes the connection with `UNAUTHENTICATED` when a `HELLO` lacks `EXPORTER`, and presents a bearer credential only to an authenticated end; a listener refuses nonce-bound `IDENT`s and identifies in turn, naming the peer, only to a peer whose exporter-bound `IDENT` verified. A pin (`certificateHashes`) or a verified certificate authenticates the listener and lifts the dialling side's rules; a listener that serves only browsers passes `QuicIdentityRules.none`.
* The wire format (records, `HELLO`, error codes, the exporter labels and the WebTransport code mapping) is public, for providers and tests.
* `package:switchboard_quic/core.dart` compiles for the web: the provider contract, `QuicBindingConnection`, `QuicChannel` and the wire format, for a browser frontend over the web provider. `package:switchboard_quic/switchboard_quic.dart` adds `QuicSwitchboardBinding` and `QuicSwitchboardListener`, which need `dart:io` as the node does.

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

A listener answers each request itself: another path than its own 404, an `Origin` outside `allowedOrigins` 403 (a request without `Origin` is not a browser's and passes; null allows any origin), protocols offered of which it serves none 400, and after `close` 503 on the connections still open; otherwise it selects the first protocol the client offered that it serves, or none when the client offered none, and the session arrives on `sessions` (with its request: `requestPath`, `requestOrigin`, `requestProtocols`, `requestDraft`). A request not answered within the configuration's `handshakeTimeout` is refused 503 by the shim. `listenWebTransport` and `listen` take two UDP ports: the transport parameters of HTTP/3 (unidirectional streams, the datagram parameter) differ from raw QUIC's, and quinn fixes them per listener before it knows the ALPN of a connection (the shim can serve both ALPNs on one port, with HTTP/3's parameters for both; the provider does not offer it).

Versions: Chrome 149 speaks WebTransport draft-02 (`SETTINGS_ENABLE_WEBTRANSPORT`, the `sec-webtransport-http3-draft02` request header), web-transport-quinn 0.13.2 the draft-07 signalling (`SETTINGS_WEBTRANSPORT_MAX_SESSIONS`); both send `WT-Available-Protocols`. The shim speaks both, as client and server, and answers in the version the client signalled; see `native/README.md`. Neither enables the session flow control of the later drafts, so a client uses one session per connection (the provider's client always does).

### Browsers and certificates

A browser reaches a WebTransport listener with the W3C API: `new WebTransport('https://node.example:4433/sb', {protocols: ['switchboard']})`, `wt.protocol` then being `'switchboard'`. With a certificate from a public authority, nothing else is needed. With a self-signed one (development, a LAN, a device), the page passes its hash: `serverCertificateHashes: [{algorithm: 'sha-256', value: hash}]`, where the browser accepts only an X.509v3 certificate with an ECDSA P-256 key whose validity is current and at most 14 days long. `NativeQuicProvider.generateSelfSigned(subject)` makes exactly that (ECDSA P-256, valid from five minutes ago for 14 days; `validityDays` beyond 14 makes one browsers refuse for a hash), and `NativeCertificate.sha256` is the hash to give the page; rotate as the binding page's "Certificates" says. The listener's `allowedOrigins` names the pages allowed (the browser sends its page's origin). Chrome 149 has no `exportKeyingMaterial`, so its `IDENT` proofs are nonce-bound, which is safe for it since it verified the certificate; a listener that serves browsers therefore passes `QuicIdentityRules.none` to `QuicSwitchboardListener.start` (whose default refuses nonce-bound proofs, for nodes).

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

## Tests

Run every suite under a memory cap:

```sh
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 dart test -j 2           # VM
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 dart test -j 2 -P node   # Node.js
(cd native/sbq && cargo test && cargo clippy --all-targets)
TMPDIR=/some/scratch tool/aot_smoke.sh                                                   # AOT
tool/browser_smoke.sh                                                                    # Chromium
```

* Against `test/fake_provider.dart`, an in-memory provider whose stream directions are delivered independently, each in order, with configurable delays (so that streams overtake one another and the control stream), stream and connection flow control, a stream limit, resets and `STOP_SENDING` with codes, FIN, and an exporter equal at both ends of a session and different per session (or none, as in a browser without `exportKeyingMaterial`): `test/vectors_test.dart` checks every byte vector of the binding page; `test/binding_test.dart` the connection and channel contracts; `test/switchboard_test.dart` and `test/review_switchboard_test.dart` two nodes end to end, dial timeouts with a held connect and the stack keep-alive a dial asks for, a man in the middle and the proxy between the frame mux and the binding. `-P node` runs the first two compiled to JavaScript.
* Against the native provider over UDP on the loopback, every case over raw QUIC and over WebTransport: `test/native_provider_test.dart` the provider contract (the handshake deadline against a socket that never answers among it), and the requests, refusals, drain and codes of WebTransport; `test/native_integration_test.dart` Switchboard nodes over the binding over quinn (exporter-bound mutual identification with the exporter equal at both ends, refusal of an unidentified dialler, a pin, Talk, 8 MiB bulk payloads, `whenWritable` pacing, 64 parallel channels, GOAWAY both ways, the idle timeout, the stack keep-alive holding a quiet connection, the proxy toward a frame mux backend), which prints its throughput lines.
* `tool/aot_smoke.sh` compiles `tool/native_smoke.dart` (the provider, then the binding over it, over raw QUIC and over WebTransport) with `dart build cli` and with `dart compile exe` and runs both.
* `tool/browser_smoke.sh` runs headless Chromium against a WebTransport listener of the native provider (see "Browsers and certificates").
