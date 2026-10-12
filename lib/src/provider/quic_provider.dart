/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Fable 5.1 <noreply@anthropic.com>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

/// The stream provider contract of the QUIC and WebTransport binding.
///
/// The binding (records, channels, the control stream, `HELLO`, identity;
/// wiki page "Polyverse Switchboard QUIC and WebTransport Binding") is written
/// once against these interfaces. Two providers implement them: the native
/// one over quinn through FFI (`quic://` raw QUIC and `https://`
/// WebTransport over its own HTTP/3 layer) and the web one over the
/// browser's WebTransport API (`https://` only; a browser cannot listen).
/// Nothing here knows about Switchboard; it is the smallest QUIC surface the
/// binding needs, in the vocabulary of RFC 9000 and the W3C WebTransport API.
///
/// Reads are pull-based so that unread data stays in the stack and holds back
/// the peer's credit: the binding reads the next record only once the
/// previous one has been taken by the layer above.
///
/// When a session ends, everything pending on it and on its streams fails
/// with a [QuicException] of kind [QuicExceptionKind.sessionEnded] (reads,
/// writes, [QuicStream.finish], [QuicSession.openStream],
/// [QuicStream.stopped]); [QuicSession.done] tells how it ended.
library;

import 'dart:async';
import 'dart:typed_data';

/// Opens sessions to endpoints. The native provider dials `quic://host:port`
/// and `https://host:port/path` (WebTransport); the web provider dials
/// `https://` only.
abstract interface class QuicConnector {
  /// Connects to [endpoint] with [config]. Fails with a [QuicException]
  /// (`unreachable`, `handshakeFailed`, `unsupportedScheme`, `refused`,
  /// ...); a handshake that runs past [QuicClientConfig.handshakeTimeout]
  /// fails with `unreachable`. A WebTransport session is established by the
  /// server's 2xx response: another response fails with `refused` where the
  /// stack tells (the native provider puts the HTTP status in the message;
  /// a browser reports a refusal like any other failure).
  ///
  /// The attempt cannot be cancelled. A caller that stops waiting (a
  /// timeout of its own) closes the session the future still yields, and
  /// ignores its failure, as for [QuicSession.openStream].
  Future<QuicSession> connect(Uri endpoint, QuicClientConfig config);
}

/// Accepts sessions on one local endpoint (native provider only).
abstract interface class QuicListener {
  /// The endpoint peers dial, as the node advertises it.
  Uri get endpoint;

  /// Accepted sessions, after their handshake completed.
  Stream<QuicSession> get sessions;

  /// Stops accepting; open sessions are left to their owners.
  Future<void> close();
}

/// One QUIC connection or WebTransport session: bidirectional streams in
/// both directions, an application close, and the TLS exporter when the
/// stack exposes it.
abstract interface class QuicSession {
  /// Whether this side initiated the session.
  bool get isInitiator;

  /// The negotiated ALPN (`switchboard` for raw QUIC) or the WebTransport
  /// protocol the server selected (`WT-Protocol`); null when unknown, or
  /// when the server selected none.
  String? get protocol;

  /// The peer's address for logs (the endpoint's host and port where the
  /// stack does not tell the address it reached).
  String get remote;

  /// Opens a bidirectional stream. Waits for stream credit (a provider whose
  /// stack refuses a stream for want of credit instead of waiting waits
  /// itself, asking again); fails with [QuicException] once the session has
  /// ended. Nothing is visible to the peer until the first write. Waiting
  /// calls are served in order. A caller that stops waiting (a timeout)
  /// resets the stream the call still yields, since an opened stream holds
  /// a unit of the peer's stream limit.
  Future<QuicStream> openStream();

  /// Streams the peer opened, in the order the stack delivers them (no
  /// order is guaranteed between streams). A provider may take them from
  /// the stack only while this stream is listened to and not paused,
  /// leaving the others in the stack, where they hold the peer's stream
  /// credit; one that accepts eagerly holds what is not yet listened to
  /// in its delivery instead.
  Stream<QuicStream> get incomingStreams;

  /// Peer-created unidirectional streams, for applications to accept or
  /// refuse by stopping them. Never includes HTTP/3's own control streams.
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams;

  /// Completes when the peer or underlying HTTP/3 connection starts
  /// draining this session. Never fails; remains pending on raw QUIC and
  /// when no draining signal arrived before [done].
  Future<void> get draining;

  /// How many streams opened by the peer this side accepts at once (the
  /// `MAX_STREAMS` grant); null where the stack decides (browsers).
  int? get maxIncomingStreams;

  /// The session's keying material exporter; null when the stack has none
  /// (a browser without `exportKeyingMaterial`), or cannot export [length]
  /// bytes.
  ///
  /// On a raw QUIC connection it is the TLS exporter of RFC 8446 section 7.5
  /// with [label] and [context] as given (Switchboard: the RFC 9266
  /// `tls-exporter`, label `EXPORTER-Channel-Binding`, empty context, 32
  /// bytes). Over WebTransport [label] and [context] are the application's
  /// and the provider applies the draft's per-session derivation
  /// (`EXPORTER-WebTransport` with the session ID; Switchboard: label
  /// `switchboard-ident`, empty context). The caller picks the label by the
  /// kind of session, which it knows from the endpoint it dialled or the
  /// listener that accepted it.
  Future<Uint8List?> exportKeyingMaterial(
    String label,
    Uint8List context,
    int length,
  );

  /// The server certificate's SHA-256 over its DER encoding, for pinning
  /// (initiator side); null when the provider does not expose it.
  Uint8List? get peerCertificateHash;

  /// Closes the session with an application [code] (0 to 255 here) and a
  /// [reason] (at most 1024 bytes of UTF-8; longer reasons are cut at a
  /// character boundary). Idempotent; completes once the session has ended
  /// (as [done]). Data still in flight is discarded, and what is pending on
  /// the session fails at once. Over WebTransport, where the close is data
  /// on the CONNECT stream that disposing of the stack would discard, the
  /// session has ended once the peer's stack acknowledged the close, or a
  /// bounded wait for that passed (the native provider: three round trips,
  /// within 0.2 to 2 s, the wait a peer that is gone costs); the provider can
  /// then be disposed of without cutting the close short. Where the stack
  /// delivers the close itself whatever the application does next (a
  /// browser's network stack), the session has ended once the stack took the
  /// close.
  Future<void> close(int code, String reason);

  /// Completes when the session has ended, with how.
  Future<QuicSessionEnd> get done;
}

/// The receive direction of a peer-created unidirectional stream.
abstract interface class QuicReceiveStream {
  /// Stops this direction with the application's error code, discarding
  /// unread bytes. Idempotent, including after the session ended.
  void stop(int code);
}

/// One bidirectional stream.
abstract interface class QuicStream {
  /// Reads the next chunk, at least one and at most [max] bytes; null at the
  /// peer's FIN (and on every read after it). Fails with [QuicStreamReset]
  /// when the peer reset its direction (the code is the status), and again
  /// on every read after it. Only one read may be pending at a time.
  Future<Uint8List?> read(int max);

  /// Completes on the peer's RESET_STREAM, even while no [read] is
  /// pending, with its application code (null when none was delivered: a
  /// WebTransport reset with an HTTP/3 code outside the WebTransport range).
  /// A paused reader must still be able to observe an abort. FIN does not
  /// complete this future: unread bytes may contain an application close.
  /// Fails with `sessionEnded` when the session ends first.
  Future<int?> get resetReceived;

  /// Writes [bytes]; completes once the stack has accepted them (they are
  /// copied; the buffer must not change until then, and may be reused
  /// after). Writes are queued in order. Waits for stream and connection
  /// credit, so a peer that does not read stalls the writer. Fails with
  /// [QuicStreamStopped] once the peer sent `STOP_SENDING` (its code), and
  /// with a [StateError] after [finish] or [reset].
  Future<void> write(Uint8List bytes);

  /// Ends this side's direction (FIN) after everything written; completes
  /// once the stack took the FIN ([stopped] tells when it was acknowledged).
  /// Idempotent. Fails with [QuicStreamStopped] if the peer stopped the
  /// direction first.
  Future<void> finish();

  /// Aborts this side's direction with [code] (`RESET_STREAM`), also after
  /// [finish]; data not yet delivered is discarded, and writes still queued
  /// fail with a [StateError]. A no-op once the direction has ended. A code
  /// is a QUIC application code on raw QUIC (0 to 2^62 - 1) and a
  /// WebTransport application code (0 to 2^32 - 1) over WebTransport; one
  /// outside the range is an [ArgumentError], and so is one the stack
  /// cannot carry (an API may carry fewer codes than the protocol): a
  /// provider never sends another code instead. Over WebTransport without
  /// `RESET_STREAM_AT`, a reset that overtakes the stream's header can leave
  /// the peer unable to tell the stream's session: it never sees the stream.
  void reset(int code);

  /// Asks the peer to stop sending with [code] (`STOP_SENDING`). This
  /// side's read direction ends at once: the stack discards what still
  /// arrives, and a pending [read] and every later one fail with a
  /// [QuicStreamReset] carrying [code] (the peer's confirming reset is not
  /// observable through the stacks). A no-op once the direction has ended.
  /// Codes as for [reset].
  void stop(int code);

  /// Sender-local priority class. The binding uses 2 for the control
  /// stream, 1 for ordinary channels and 0 for bulk ones. 2 goes first,
  /// strictly. 1 and 0 share what is left so that neither starves the
  /// other (binding page, "Flow control and scheduling"): a stack whose
  /// priorities are strict only (quinn) puts 1 and 0 on one level, below
  /// 2, where it interleaves them; one with weights or send groups (the
  /// W3C API's `sendGroup`) favours 1 without starving 0. A stack without
  /// priorities ignores it.
  set priority(int value);

  /// Completes when the peer's `STOP_SENDING` arrived (with its code) or
  /// when every byte of this side's direction was acknowledged after
  /// [finish] (null; where the stack does not tell acknowledgement, once it
  /// reports the direction closed after the FIN). A STOP_SENDING without an
  /// application code fails with [QuicStreamStopped] whose code is null,
  /// distinguishing it from acknowledgement. With null at once when this
  /// side [reset] its direction. A provider answers a `STOP_SENDING` itself
  /// by resetting its direction with the same code (RFC 9000 section 3.5).
  Future<int?> get stopped;
}

/// Client configuration. Its durations are zero (none) or positive: a
/// provider rejects a negative one with an [ArgumentError]. A provider whose
/// stack decides some of these itself (a browser: the windows, the stream
/// limit, the idle timeout and the keep-alive) ignores them.
class QuicClientConfig {
  const QuicClientConfig({
    required this.alpn,
    this.serverCertificateHashes = const [],
    this.verifyCertificate = true,
    this.maxStreamsBidi = 128,
    this.streamReceiveWindow = 1 << 20,
    this.connectionReceiveWindow = 16 << 20,
    this.idleTimeout = const Duration(seconds: 30),
    this.keepAlive = const Duration(seconds: 10),
    this.handshakeTimeout = const Duration(seconds: 10),
  });

  /// ALPN tokens to offer, in order (`switchboard` for raw QUIC); for
  /// WebTransport, the protocol values to offer in `WT-Available-Protocols`
  /// instead (printable ASCII; the provider offers the ALPN `h3` itself).
  final List<String> alpn;

  /// SHA-256 hashes of acceptable server certificates (DER). Empty with
  /// [verifyCertificate] true: the platform roots; empty with it false:
  /// any certificate (the identity then comes from `IDENT`), where the
  /// stack allows it (a browser verifies whatever this says).
  final List<Uint8List> serverCertificateHashes;
  final bool verifyCertificate;

  /// Streams the peer may have open at once (`MAX_STREAMS`).
  final int maxStreamsBidi;

  /// Receive window of each stream, in bytes (`MAX_STREAM_DATA`).
  final int streamReceiveWindow;

  /// Receive window of the connection, in bytes (`MAX_DATA`), the backstop
  /// of every stream together; the binding page recommends 16 MiB.
  final int connectionReceiveWindow;

  /// Zero for none (the stack's and the peer's limits apply).
  final Duration idleTimeout;

  /// The interval of the stack's own keep-alive (QUIC `PING` frames), which
  /// keeps a quiet connection from reaching [idleTimeout]; shorter than it
  /// (a third, say). Zero for none.
  final Duration keepAlive;

  /// How long the handshake may take before [QuicConnector.connect] fails
  /// with `unreachable` (a provider that tries several addresses of a name
  /// may give each attempt its own). Zero for no deadline of its own:
  /// [idleTimeout] alone bounds it then, and nothing does when that is zero
  /// too. Over WebTransport it bounds the QUIC handshake and again the
  /// HTTP/3 exchange that establishes the session (the server's SETTINGS and
  /// its response); with zero, a provider may still bound that exchange
  /// (the native provider: 10 seconds), which no idle timeout would end
  /// while the server's stack answers.
  final Duration handshakeTimeout;
}

/// Server configuration (native provider). Its durations are zero (none)
/// or positive, as in [QuicClientConfig].
class QuicServerConfig {
  const QuicServerConfig({
    required this.alpn,
    required this.certificateDer,
    required this.privateKeyDer,
    this.maxStreamsBidi = 128,
    this.streamReceiveWindow = 1 << 20,
    this.connectionReceiveWindow = 16 << 20,
    this.idleTimeout = const Duration(seconds: 30),
    this.keepAlive = const Duration(seconds: 10),
    this.handshakeTimeout = const Duration(seconds: 10),
  });

  /// The ALPN tokens served. A WebTransport listener serves `h3` whatever
  /// this says (the native provider's `listenWebTransport`).
  final List<String> alpn;

  /// The certificate, DER; the native provider also takes the DER
  /// certificates of its chain appended to it.
  final Uint8List certificateDer;

  /// The private key, DER (PKCS#8, SEC1 or PKCS#1).
  final Uint8List privateKeyDer;

  /// As in [QuicClientConfig].
  final int maxStreamsBidi;
  final int streamReceiveWindow;
  final int connectionReceiveWindow;
  final Duration idleTimeout;
  final Duration keepAlive;

  /// How long the handshake of an incoming session may take: one that is
  /// not complete by then is abandoned and never delivered on
  /// [QuicListener.sessions]. Zero for no deadline of its own: [idleTimeout]
  /// alone bounds it then, and with that zero too a client that goes silent
  /// halfway through its handshake holds its state until the listener
  /// closes. A WebTransport listener also bounds a request's HTTP/3
  /// exchange and its wait for an answer with it; with zero, a provider may
  /// still bound those (the native provider: 10 seconds).
  final Duration handshakeTimeout;
}

/// How a session ended.
class QuicSessionEnd {
  const QuicSessionEnd.closed(this.code, this.reason, {required this.byPeer})
    : lost = false;
  const QuicSessionEnd.lost(this.reason)
    : code = null,
      lost = true,
      byPeer = false;

  /// The application code of the close, null when the transport was lost.
  final int? code;
  final String reason;
  final bool byPeer;
  final bool lost;
}

/// A provider failure.
class QuicException implements Exception {
  const QuicException(this.kind, this.message);
  final QuicExceptionKind kind;
  final String message;
  @override
  String toString() => 'QuicException(${kind.name}): $message';
}

enum QuicExceptionKind {
  unsupportedScheme,
  unreachable,
  handshakeFailed,
  certificateRejected,

  /// The server answered a WebTransport request with a status other than
  /// 2xx.
  refused,
  sessionEnded,
  streamLimit,
  internal,
}

/// The peer reset its direction of a stream.
class QuicStreamReset implements Exception {
  const QuicStreamReset(this.code);

  /// The application error code; null when the stack delivered none (a
  /// WebTransport reset outside the application range, such as those of a
  /// terminating session), which the binding reads as `UNKNOWN`.
  final int? code;
  @override
  String toString() => 'QuicStreamReset($code)';
}

/// The peer asked this side to stop sending.
class QuicStreamStopped implements Exception {
  const QuicStreamStopped(this.code);

  /// The application error code; null when the stack delivered none, as
  /// for [QuicStreamReset.code].
  final int? code;
  @override
  String toString() => 'QuicStreamStopped($code)';
}
