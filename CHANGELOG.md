## 0.1.0-dev.1

* Package created: the provider interface the binding is written against.
* The native stream provider (`switchboard_quic_native.dart`): raw QUIC over quinn through a Rust shim with a flat C ABI (`native/sbq`), loaded through a build hook (prebuilt library or `cargo build`). quinn's priorities are strict only, so the provider puts the priority classes 1 (ordinary) and 0 (bulk) on one quinn level, where their streams interleave, and class 2 (control) strictly above; error codes beyond QUIC's 2^62 - 1 are argument errors.
* Provider contract: `connectionReceiveWindow` in both configurations; the exporter's label and context go to the TLS exporter unchanged on raw QUIC; `stop` ends the read direction locally; `stopped` after a local reset; pending operations fail with `sessionEnded` when the session ends.
* The binding layer (`lib/src/binding/`), the reference implementation of
  the wiki page "Polyverse Switchboard QUIC and WebTransport Binding" over
  the provider contract: `QuicBindingConnection` and `QuicChannel` carry
  the core package's connection and channel contracts on native streams
  (records, the OPEN and CLOSE records, resets and `STOP_SENDING` with
  the status as the error code, the close handshake and its confirmation
  timeout, the control stream with `HELLO`, `PING`, `PONG`, `GOAWAY`,
  `NONCE` and `IDENT`, the proof bound to the TLS exporter, keep-alive,
  the application close and its mapping to `GOAWAY`, the resource limits
  of the page); `QuicIdentityRules` with the specification's defaults for
  initiators and listeners; `QuicSwitchboardBinding` (`quic` and `https`
  endpoints) and `QuicSwitchboardListener` for `Switchboard` nodes; the
  wire codecs, the exporter labels and the WebTransport error code
  mapping.
* Provider contract (on top of the native provider's amendments): reset
  and stop codes may be absent (`int?`, a WebTransport reset without an
  application code), and the priority classes 1 and 0 never starve each
  other (a stack with strict priorities only puts them on one level).
* `package:switchboard_quic/core.dart`: what compiles for the web.
* Tests: an in-memory provider with independent stream delivery, the test
  vectors of the page, the connection and channel contracts, and two nodes
  end to end.
* Provider contract (review of the binding): `QuicSession.draining` (read
  as a `GOAWAY` with `GOING_AWAY`), `incomingUnidirectionalStreams` of
  `QuicReceiveStream`s (the binding stops them with `UNSUPPORTED`),
  `QuicStream.resetReceived` (a reset observed while no read is pending,
  so that a reader the application paused still sees an abort), and a
  `STOP_SENDING` without a code distinguished from acknowledgement.
* The native provider implements them: the shim's
  `sbq_stream_poll_reset` (ABI 2) tells a reset without reading and arms
  the READABLE event otherwise, which the provider calls whenever no read
  is pending; raw QUIC has no draining signal (`draining` never
  completes), and the shim grants no unidirectional streams, so none is
  ever delivered.
* The binding over the native provider, end to end
  (`test/native_integration_test.dart`): Switchboard nodes over UDP on
  the loopback with exporter-bound mutual identification (the exporter
  equal at both ends, 32 bytes, `QuicBindingConnection.exporterForTesting`),
  an unidentified dialler refused, a pin right and wrong, Talk, 8 MiB bulk
  payloads, `whenWritable` pacing, 64 parallel channels recycling stream
  credit, GOAWAY with code and reason both ways, a paused reader seeing a
  reset, the idle timeout as `CONNECTION_LOST`, the proxy toward a frame
  mux backend, and throughput lines. `tool/native_smoke.dart` runs the
  binding over the provider too, in JIT and AOT.
* Fix: a `STOP_SENDING` arriving after the peer's CLOSE record (the peer
  gave up waiting for this side's close in turn) ends the channel at once
  instead of at this side's own confirmation timeout. The fake provider
  gives a stopped direction no more stream credit, as a QUIC stack.
* The node-level tests are marked `@TestOn('vm')`.
* Handshake deadline: `handshakeTimeout` in `QuicClientConfig` and
  `QuicServerConfig` (10 s by default; zero leaves the handshake to the
  idle timeout, quinn's only bound, as before). The shim enforces it
  (ABI 3: a trailing `handshake_ms` of `sbq_client_config` and
  `sbq_server_config`): a connect that runs out of time ends as a
  handshake the idle timeout ended (`unreachable`), and a listener
  abandons an incoming handshake not complete in time, so neither a dial
  to a black hole nor a client that goes silent halfway through its
  handshake is held forever when there is no idle timeout.
* Provider contract: `QuicConnector.connect` cannot be cancelled; a
  caller that stops waiting closes the session it still yields.
  `QuicSwitchboardBinding.dial` bounds the connect by the node's connect
  timeout (`BindingDialSettings.timeout`), fails with `UNAVAILABLE` on
  expiry and closes a session that lands later with `CANCELLED`, also for
  direct callers; the same timeout is the handshake deadline it asks for.
* `QuicSwitchboardBinding.keepAlive`: the QUIC stack's keep-alive is the
  binding's own, a third of `idleTimeout` by default (none without an
  idle timeout, `Duration.zero` disables it), and no longer follows
  `MuxOptions.keepAliveInterval`, the control `PING`, the application's
  probe: a control interval above the idle timeout no longer lets a
  quiet connection idle out, and turning the control `PING` on or off
  leaves the stack's keep-alive as it is.
* `QuicChannel.sendWindow` documented as the core contract has it for a
  binding over a stack's flow control: an estimate (room for one largest
  subframe while writable), not a count.
* Fix: `sbq_stream_open` on a connection whose handshake never completed
  returns `SBQ_ERR_CONNECTION` after its CLOSED event, as the event's
  documentation says, instead of `SBQ_ERR_STATE`, which stays the answer
  during the handshake.
* Negative durations are argument errors: the native provider throws
  `ArgumentError` for a negative `idleTimeout`, `keepAlive` or
  `handshakeTimeout` in either configuration instead of passing it to
  the shim as a huge unsigned value (a negative handshake deadline used
  to mean none), and rounds a positive one up to whole milliseconds, so
  that it never becomes none; `QuicSwitchboardBinding` throws for a
  negative `idleTimeout` or `keepAlive` when constructed. The provider
  contract says so of its configurations, and the fake provider checks
  it too.
