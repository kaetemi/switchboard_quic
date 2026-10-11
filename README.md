# Polyverse Switchboard QUIC and WebTransport binding

The binding of [Polyverse Switchboard](https://github.com/kaetemi/switchboard) to transports with native streams, as specified by the wiki page "Polyverse Switchboard QUIC and WebTransport Binding": every channel is a bidirectional stream, records replace mux frames, a control stream carries the control messages, QUIC flow control replaces credit, and the `IDENT` proof binds the TLS exporter.

Two stream providers behind one interface (`lib/src/provider/quic_provider.dart`): the native provider over [quinn](https://github.com/quinn-rs/quinn) through FFI (a Rust shim in `native/`), and the web provider over the browser's WebTransport API.

Work in progress.

## The native provider

`package:switchboard_quic/switchboard_quic_native.dart` (Dart VM only) exports `NativeQuicProvider`: raw QUIC (`quic://host:port`, ALPN `switchboard`) over quinn, through the Rust shim in `native/sbq` (see `native/README.md`).

```dart
final provider = NativeQuicProvider();
final cert = NativeQuicProvider.generateSelfSigned('node.example');
final listener = await provider.listen('0.0.0.0', 4433, QuicServerConfig(
  alpn: const [quicAlpn],
  certificateDer: cert.certificateDer,
  privateKeyDer: cert.privateKeyDer,
));
final session = await provider.connect(Uri.parse('quic://node.example:4433'),
    QuicClientConfig(alpn: const [quicAlpn], verifyCertificate: false));
```

The package's build hook supplies the shim: a prebuilt library from `native/sbq/prebuilt/<os>_<arch>/` when there is one, else `cargo build --release` for the host, so `dart run`, `dart test` and `dart build cli` need either a prebuilt library or a Rust toolchain. Compile programs ahead of time with `dart build cli`, which bundles the library; a `dart compile exe` binary finds it next to the executable or through `SBQ_LIBRARY`. WebTransport (`https://`) is not implemented by the native provider yet: the HTTP/3 session layer will sit between the shim's streams and the provider interface.
