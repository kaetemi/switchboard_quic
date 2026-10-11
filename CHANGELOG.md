## 0.1.0-dev.1

* Package created: the provider interface the binding is written against.
* The native stream provider (`switchboard_quic_native.dart`): raw QUIC over quinn through a Rust shim with a flat C ABI (`native/sbq`), loaded through a build hook (prebuilt library or `cargo build`). quinn's priorities are strict only, so the provider puts the priority classes 1 (ordinary) and 0 (bulk) on one quinn level, where their streams interleave, and class 2 (control) strictly above; error codes beyond QUIC's 2^62 - 1 are argument errors.
* Provider contract: `connectionReceiveWindow` in both configurations; the exporter's label and context go to the TLS exporter unchanged on raw QUIC; `stop` ends the read direction locally; `stopped` after a local reset; pending operations fail with `sessionEnded` when the session ends.
