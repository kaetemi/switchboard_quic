## 0.1.0-dev.1

* Package created: the provider interface the binding is written against.
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
* Provider contract: reset and stop codes may be absent (`int?`, a
  WebTransport reset without an application code), a connection receive
  window in both configurations, and the documented semantics of priority
  classes (1 and 0 never starving each other), of the exporter on raw QUIC
  and WebTransport, of reads after `stop`, and of pending reads and writes
  when the session ends.
* Tests: an in-memory provider with independent stream delivery, the test
  vectors of the page, the connection and channel contracts, and two nodes
  end to end.
