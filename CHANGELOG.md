<!--
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Fable 5.1 <noreply@anthropic.com>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
-->

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
* WebTransport over HTTP/3 in the native provider. The shim (ABI 4) has
  an HTTP/3 layer of its own (no HTTP/3 or WebTransport crate): SETTINGS,
  the control and QPACK streams, a QPACK of static references and
  literals with Huffman decoding that refuses the dynamic table, extended
  CONNECT, the WebTransport stream headers, capsules, the mapping of
  application codes into the HTTP/3 space and the per-session exporter.
  It speaks the draft-02 signalling of Chrome 149 and the draft-07
  signalling of web-transport-quinn 0.13.2, both with the
  `WT-Available-Protocols` / `WT-Protocol` negotiation, as client and
  server, and bounds everything a peer sends. A session is a handle the
  stream and connection calls take; `sbq_connect_wt` dials one, a
  listener whose ALPN offers `h3` posts `WT_REQUEST` for the embedder to
  accept or reject (503 when not answered in time), and `sbq_wt_drain`
  sends `WT_DRAIN_SESSION`.
* `NativeQuicProvider` dials `https://host:port/path` as a WebTransport
  session (`connectWebTransport` with an `Origin`), offering
  `QuicClientConfig.alpn` as the protocols, and `listenWebTransport`
  serves one path: 404 for another, 403 for an origin not allowed, 400
  for protocols of which none is served, 503 after `close`; its sessions
  carry their request (`requestPath`, `requestOrigin`,
  `requestProtocols`, `requestDraft`). Over WebTransport, stream and
  close codes are WebTransport codes (up to 2^32 - 1), a reset or
  `STOP_SENDING` outside that range has no code, `draining` completes on
  `WT_DRAIN_SESSION` or `GOAWAY` (`NativeQuicSession.drain` sends one),
  and the peer's unidirectional streams are delivered for refusal.
* Provider contract: `QuicExceptionKind.refused` (a WebTransport
  response other than 2xx); the connector, protocol, reset and
  configuration documentation say what WebTransport changes; a
  `STOP_SENDING` without a code fails `stopped` in the native provider
  (it completed it with null, which the contract reserves for an
  acknowledgement).
* The binding, over WebTransport: a reset or `STOP_SENDING` without a
  code on the control stream (the peer's `WT_SESSION_GONE`, which may
  overtake its close) waits up to two seconds for the session's end
  before it counts as a protocol error.
* Tests: the native provider and integration suites run their cases over
  raw QUIC and over WebTransport, with cases of their own for each (a
  node-to-node connection over `https://127.0.0.1:port/sb` with
  exporter-bound identification both ways among them); the shim's tests
  cover the codecs against the RFC examples and the binding page's
  vectors, sessions through the ABI, and a misbehaving client on raw
  quinn streams. `tool/native_smoke.dart` (JIT and AOT) runs a
  WebTransport session and the binding over it; `tool/browser_smoke.sh`
  runs headless Chromium against a listener of the native provider.
* The HTTP/3 layer after review: stricter validation of framing,
  SETTINGS, QPACK prefixes, Huffman padding, Structured Fields
  parameters, field names and values, CONNECT trailers and capsules;
  outstanding request handles bounded with the sessions of a
  connection; the streams of sessions that are gone told from those of
  sessions still to come without a history; every stream the layer gives
  up stopped or reset explicitly, a cancelled task's included, and a FIN
  once sent never reset. Fixed: a stream header cut short by a small
  window stalled the stream; protocol names of 128 to 255 bytes; a
  draft-02 server without `ENABLE_CONNECT_PROTOCOL`; a CONNECT after an
  HTTP/3 `GOAWAY`. `sbq_listen` takes an address literal (the provider
  resolves a listen name asynchronously).
* A local WebTransport close completes (`CLOSED` in the shim, `close()`
  and `done` in the provider) once the peer's stack acknowledged it, or
  after a bounded wait (three round trips, 0.2 to 2 s), so that a
  provider disposed of right after does not cut the close short; the
  provider contract says so. A WebTransport listener routes by path
  only: the `:authority` a client used is not checked (it is
  `requestAuthority`). The HTTP/3 exchanges keep a 10 s deadline when
  the handshake deadline is zero, as the contract now says.
* The web provider (`package:switchboard_quic/switchboard_quic_web.dart`):
  `WebQuicProvider`, a `QuicConnector` of `https://` WebTransport sessions
  through the browser's W3C API (`dart:js_interop` and `package:web`, with
  extensions for what `package:web` 1.1.1 lacks: `protocol`, `draining`,
  `exportKeyingMaterial`, `getStats`, `createSendGroup`, the `protocols`
  option, the streams' `sendOrder` and `sendGroup`, and both forms of the
  `WebTransportError` constructor, each feature-tested at run time). Reads
  pull through a default reader and keep the rest of a chunk; writes copy
  and wait for the writer's `ready`; resets and `STOP_SENDING` carry
  `WebTransportError` codes, and the reader's and writer's `closed` tell the
  peer's; the session's end comes from `closed`; priority classes become
  send orders and groups where the browser has them; streams the browser
  refuses for want of credit are asked for again. The library exports
  `core.dart` too.
* `connectQuicBinding`, in `core.dart`: the dial of `QuicSwitchboardBinding`
  on its own (connect through a provider, bounded, with the identification
  rules the certificate's verification calls for, and start the binding),
  for `ReconnectingClient.connections` in a browser;
  `QuicSwitchboardBinding.dial` uses it, and `switchboardAlpn` moved with
  it.
* Provider contract (what the web provider teaches, provider-neutral): a
  provider whose stack refuses a stream for want of credit waits itself; a
  provider may leave the peer's streams in the stack while nobody listens;
  a reset or stop code the stack cannot carry is an `ArgumentError`, never
  another code; `stopped` follows the stack's report of a closed direction
  where acknowledgement is not observable; a close is complete once a stack
  that delivers it on its own took it; configuration the stack decides is
  ignored (a browser always verifies certificates); the exporter is null
  where the stack cannot export the length asked; `remote` may be the
  endpoint's host and port; over WebTransport without `RESET_STREAM_AT`, a
  reset that overtakes a stream's header can leave the peer without the
  stream.
* Fix (the shim's HTTP/3 layer): the type of a peer's unidirectional stream
  no longer has a deadline. Chrome's stack sends the type of a QPACK stream
  with its first instruction, and the stream it opens next opens that one,
  typeless; the shim stopped it at the handshake deadline, which Chrome
  answers by closing the connection, so every Chrome session to a native
  listener ended after 10 s. A typeless stream holds one of the 16
  unidirectional streams the peer is granted (no ABI change).
* Fix (the shim's HTTP/3 layer): once its last WebTransport session has
  closed, a server leaves the QUIC connection's close to the client for
  the close wait (three round trips, 0.2 to 2 s) instead of closing it as
  soon as both sides closed the CONNECT stream. Chrome reports a session
  closed only after it sent its FIN in answer to the close, and a
  connection close that arrives before that report fails the session: a
  node's close of a browser's session, its `GOAWAY` when idle included,
  reached the page as "Connection lost." (the binding's
  `CONNECTION_LOST`) instead of its code whenever the connection close
  overtook that report, which load made frequent. Chrome closes the
  connection itself once it reported the close; a client of the shim
  still closes it at once (no ABI change).
* Tests: `test/web_provider_test.dart` and `test/web_binding_test.dart` in
  headless Chrome (`dart test -P web`, run by `tool/web_smoke.sh` with
  `tool/web_server.dart`, native WebTransport listeners and a Switchboard
  node, as the server): the provider against the contract, the binding
  over it, and `ReconnectingClient.connections`; shim tests of a typeless
  unidirectional stream outliving the deadline and of a server leaving the
  connection's close to the client. A browser test resets a stream only
  once the server has it: a reset that overtakes the stream's header loses
  it at a quinn server (no `RESET_STREAM_AT`), which then cannot tell the
  stream's session.
* Platforms beyond Linux x86-64. The shim builds for Windows x86-64
  (MinGW here; MSVC in CI and releases) and Linux aarch64, and checks
  clean (`cargo check`, clippy) for macOS arm64 and x86-64, iOS and
  Android; its tests pass on aarch64 under qemu-user, and on Windows
  under wine with quinn-udp patched for wine's sockets outside the tree,
  where the Windows Dart SDK also passes the VM suite and the AOT smoke.
  `native/README.md`, "Platforms", says what ran where and what did not.
* Fix (the shim): a listener's UDP socket on an IPv6 address is
  dual-stack where the platform allows it (`IPV6_V6ONLY` off before the
  bind, as quinn makes its client sockets). On Windows, whose IPv6
  sockets are IPv6-only by default, a listener on `::` took no IPv4
  client; Linux and macOS default to dual-stack (on Linux unless
  `bindv6only` is set, which the listener now overrides). No ABI change.
* The build hook finds cargo in `%USERPROFILE%\.cargo\bin` too, and in a
  quoted Windows `PATH` entry with semicolons or spaces in it
  (`$CARGO_HOME/bin` only when the hooks runner passes that variable,
  which Dart 3.13 does not); builds with `--locked` and takes the library
  that build reports (a configured `build.target` cannot leave it an old
  one), with an explicit `--target` when rustc's host is of another
  architecture than the Dart VM (an x64 Dart SDK under Rosetta 2 or
  Windows' emulation); refuses a library whose header names another
  architecture or format than the target's, or that it cannot read
  (Dart 3.13 bundles such a library, and loading it fails with a
  misleading message): ELF by class and byte order, Mach-O in either
  byte order, a universal one only with the target's slice, PE through
  `e_lfanew`, also beyond the first page (six VM tests); declares
  the library it uses as a dependency, so that a cached result does not
  outlive a `cargo clean`; and says that it builds nothing for iOS and
  Android. The `dart compile exe` fallback loads the library with
  Apple's `RTLD_GLOBAL` on iOS too.
* CI (`.github/workflows/ci.yml`): the shim and the Dart package on
  Linux x64 and arm64, macOS arm64 and x64, and Windows x64, and the
  Node.js suite on Linux x64, against the core commit recorded in
  `tool/core_commit.txt` (`01ccd03`). Releases
  (`.github/workflows/release.yml`, on a tag `v*`, or by hand for an
  existing one): the shim tested and built on those five platforms from
  the tag's commit with read-only access, then attached by one job with
  write access, as `<os>_<arch>-<file>` with a `SHA256SUMS` of the
  `<os>_<arch>/<file>` layout the hook reads, to a draft that is
  published once exactly those six assets are there; runs for one tag
  wait for each other, and a rerun leaves a published release as it is,
  after checking it against its own `SHA256SUMS`. Neither workflow has
  run on GitHub yet. `tool/fetch_prebuilt.sh` downloads a release's
  libraries, checks its `SHA256SUMS` (known paths, hashes, no
  duplicates) and the libraries against it, and replaces each under
  `native/sbq/prebuilt/` atomically; `native/sbq/.pubignore` lets them
  into a published package.
* Portability of the tools and tests: `tool/aot_smoke.sh` runs the
  `.exe` files under Git Bash on Windows (not run there yet);
  `.gitattributes` keeps LF in Windows checkouts;
  `tool/web_server.dart` watches SIGTERM only where it can be
  watched; a native provider test no longer binds 127.0.0.2 (Linux routes
  all of 127.0.0.0/8 to the loopback, macOS does not); the native smoke
  waits up to 5 s for both `HELLO`s before it checks that they carry
  `EXPORTER` (a channel's records may overtake the control stream, as a
  run under wine showed). In the shim's tests, the dual-stack test skips
  only where the system cannot bind a dual-stack socket, which it probes
  itself, so that a failing listener is a failure; and
  `refusals_carry_their_status` gives its listener 2 s instead of 300 ms
  (it timed out under qemu), still below the client's 5 s.
