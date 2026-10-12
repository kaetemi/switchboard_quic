# Polyverse Switchboard QUIC and WebTransport binding

The binding of [Polyverse Switchboard](https://github.com/kaetemi/switchboard) to transports with native streams, as specified by the wiki page "Polyverse Switchboard QUIC and WebTransport Binding": every channel is a bidirectional stream, records replace mux frames, a control stream carries the control messages, QUIC flow control replaces credit, and the `IDENT` proof binds the TLS exporter.

The binding is written once against a stream provider interface (`lib/src/provider/quic_provider.dart`), for two providers: the native provider over [quinn](https://github.com/quinn-rs/quinn) through FFI (a Rust shim in `native/`), and the web provider over the browser's WebTransport API.

Status: the binding layer is complete for both kinds of session; the native provider speaks raw QUIC (`quic://host:port`). Not there yet: WebTransport in the native provider (its HTTP/3 session layer) and the web provider, so `https://` endpoints fail with `UNIMPLEMENTED` and a node moves to a record's next endpoint.

| Library | What | Platforms |
| --- | --- | --- |
| `package:switchboard_quic/switchboard_quic.dart` | `QuicSwitchboardBinding` and `QuicSwitchboardListener` for `Switchboard` nodes, and everything of `core.dart` | VM (`dart:io`, as the node) |
| `package:switchboard_quic/core.dart` | The provider contract, `QuicBindingConnection` and `QuicChannel`, the wire format | VM and web |
| `package:switchboard_quic/switchboard_quic_native.dart` | `NativeQuicProvider`, the provider contract | VM (`dart:ffi`) |

## The binding layer

`lib/src/binding/` is the reference implementation of the binding page, written once against the provider contract:

* `QuicBindingConnection` (a `BindingConnection`) and `QuicChannel` (a `MuxChannel`) carry the connection and channel contracts of the core package over a `QuicSession`, so that a `Switchboard` node, Talk, the proxy and everything above them run unchanged. A channel is one bidirectional stream: the opener's direction starts with an OPEN record (`u48` channel id, then the open payload), subframes are DATA records (`u32` header, length in bits 0 to 29, command in bits 30 and 31), and each side ends its direction with a CLOSE record and FIN, or a reset carrying the status. The initiator's first stream, whose OPEN record names channel 0, is the control stream: `HELLO` first in each direction (record limit, channels, `EXPORTER`), then `PING`, `PONG`, `GOAWAY`, `NONCE` and `IDENT`.
* `QuicSwitchboardBinding` gives a node its `quic://host:port` endpoints (raw QUIC, ALPN `switchboard`), and passes `https://host:port/path` endpoints (WebTransport) to its connector, which fails with `unsupportedScheme` (the node's `UNIMPLEMENTED`, and its next endpoint) until it has a WebTransport layer. `QuicSwitchboardListener` adopts a `QuicListener`'s sessions into a node (`Switchboard.adopt`) and declares its endpoint (`Switchboard.addListeningEndpoint`).
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

The provider's own configuration of a listener (its certificate, its windows) is the provider's; give it the node's `MuxOptions.initialWindow` as the stream receive window and a connection window of `MuxOptions.receiveHighWaterMarkBytes`, as `QuicSwitchboardBinding` does for the sessions it dials.

## The native provider

`package:switchboard_quic/switchboard_quic_native.dart` (Dart VM only) exports `NativeQuicProvider`: raw QUIC (`quic://host:port`, ALPN `switchboard`) over quinn, through the Rust shim in `native/sbq` (see `native/README.md`). quinn's stream priorities are strict between levels and round robin within one, so the provider puts the priority classes 1 (ordinary) and 0 (bulk) on one level and class 2 (control) above it (`NativeQuicStream.quinnPriority`).

Two nodes over it, as `test/native_integration_test.dart` runs them:

```dart
final provider = NativeQuicProvider();                     // one per isolate
final cert = NativeQuicProvider.generateSelfSigned('node.example');

// The listening node: a self-signed certificate (ECDSA P-256, 14 days, so
// that browsers can pin it too) and the node's windows.
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

The provider alone (`connect`, `listen`, sessions and streams) is what `tool/native_smoke.dart` and `test/native_provider_test.dart` exercise. Raw QUIC has no draining signal and grants the peer no unidirectional streams, so `draining` never completes and `incomingUnidirectionalStreams` stays empty; a reset is observed even while nobody reads (`resetReceived`). WebTransport (`https://`) is not implemented by the native provider yet: the HTTP/3 session layer will sit between the shim's streams and the provider interface.

### Building the shim

The package's build hook (`hook/build.dart`) supplies the shim to `dart run`, `dart test` and `dart build cli`: a prebuilt library from `native/sbq/prebuilt/<os>_<arch>/` when there is one, else `cargo build --release` for the host when `cargo` is on `PATH` (about a minute the first time), else a clear failure. So either place a prebuilt library there or install a Rust toolchain (<https://rustup.rs>; ring needs a C compiler). By hand:

```sh
cd native/sbq
cargo build --release            # target/release/libsbq.so (+ libsbq.a)
cargo test                       # ABI self test
cargo clippy --all-targets       # kept warning-free
```

Compile programs ahead of time with `dart build cli`, which bundles the library (ship the bundle directory); a `dart compile exe` binary finds the library next to the executable, in `../lib`, or through `SBQ_LIBRARY`. After an ABI change, regenerate `native/sbq/include/sbq.h` (cbindgen) and `lib/src/native/sbq_bindings.g.dart` (`dart run ffigen --config ffigen.yaml`) and bump `SBQ_ABI_VERSION`; `native/README.md` has the details, the ABI and the platforms.

## Tests

Run every suite under a memory cap:

```sh
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 dart test -j 2           # VM
systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 dart test -j 2 -P node   # Node.js
(cd native/sbq && cargo test && cargo clippy --all-targets)
TMPDIR=/some/scratch tool/aot_smoke.sh                                                   # AOT
```

* Against `test/fake_provider.dart`, an in-memory provider whose stream directions are delivered independently, each in order, with configurable delays (so that streams overtake one another and the control stream), stream and connection flow control, a stream limit, resets and `STOP_SENDING` with codes, FIN, and an exporter equal at both ends of a session and different per session (or none, as in a browser without `exportKeyingMaterial`): `test/vectors_test.dart` checks every byte vector of the binding page; `test/binding_test.dart` the connection and channel contracts; `test/switchboard_test.dart` and `test/review_switchboard_test.dart` two nodes end to end, a man in the middle and the proxy between the frame mux and the binding. `-P node` runs the first two compiled to JavaScript.
* Against the native provider over UDP on the loopback: `test/native_provider_test.dart` the provider contract; `test/native_integration_test.dart` Switchboard nodes over the binding over quinn (exporter-bound mutual identification with the exporter equal at both ends, refusal of an unidentified dialler, a pin, Talk, 8 MiB bulk payloads, `whenWritable` pacing, 64 parallel channels, GOAWAY both ways, the idle timeout, the proxy toward a frame mux backend), which prints its throughput lines.
* `tool/aot_smoke.sh` compiles `tool/native_smoke.dart` (the provider, then the binding over it) with `dart build cli` and with `dart compile exe` and runs both.
