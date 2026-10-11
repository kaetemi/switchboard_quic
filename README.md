# Polyverse Switchboard QUIC and WebTransport binding

The binding of [Polyverse Switchboard](https://github.com/kaetemi/switchboard) to transports with native streams, as specified by the wiki page "Polyverse Switchboard QUIC and WebTransport Binding": every channel is a bidirectional stream, records replace mux frames, a control stream carries the control messages, QUIC flow control replaces credit, and the `IDENT` proof binds the TLS exporter.

Two stream providers behind one interface (`lib/src/provider/quic_provider.dart`): the native provider over [quinn](https://github.com/quinn-rs/quinn) through FFI (a Rust shim in `native/`), and the web provider over the browser's WebTransport API.

Work in progress.
