/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Fable 5.1 <noreply@anthropic.com>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The stream provider contract of the QUIC and WebTransport binding.
///
/// The binding (records, channels, the control stream, `HELLO`, identity;
/// wiki page "Polyverse Switchboard QUIC and WebTransport Binding") is written
/// once against these interfaces. Two providers implement them: the native
/// one over quinn through FFI (`quic://` raw QUIC, and WebTransport once the
/// HTTP/3 layer exists) and the web one over the browser's WebTransport API.
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
/// (and later `https://host:port/path` for WebTransport); the web provider
/// dials `https://` only.
abstract interface class QuicConnector {
  /// Connects to [endpoint] with [config]. Fails with a [QuicException]
  /// (`unreachable`, `handshakeFailed`, `unsupportedScheme`, ...).
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
  /// protocol value; null when unknown.
  String? get protocol;

  /// The peer's address for logs.
  String get remote;

  /// Opens a bidirectional stream. Waits for stream credit; fails with
  /// [QuicException] once the session has ended. Nothing is visible to the
  /// peer until the first write. Waiting calls are served in order. A caller
  /// that stops waiting (a timeout) resets the stream the call still yields,
  /// since an opened stream holds a unit of the peer's stream limit.
  Future<QuicStream> openStream();

  /// Streams the peer opened, in the order the stack delivers them (no
  /// order is guaranteed between streams).
  Stream<QuicStream> get incomingStreams;

  /// How many streams opened by the peer this side accepts at once (the
  /// `MAX_STREAMS` grant); null where the stack decides (browsers).
  int? get maxIncomingStreams;

  /// The session's keying material exporter; null when the stack has none
  /// (a browser without `exportKeyingMaterial`).
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
  /// (as [done]). Data still in flight is discarded.
  Future<void> close(int code, String reason);

  /// Completes when the session has ended, with how.
  Future<QuicSessionEnd> get done;
}

/// One bidirectional stream.
abstract interface class QuicStream {
  /// Reads the next chunk, at least one and at most [max] bytes; null at the
  /// peer's FIN (and on every read after it). Fails with [QuicStreamReset]
  /// when the peer reset its direction (the code is the status), and again
  /// on every read after it. Only one read may be pending at a time.
  Future<Uint8List?> read(int max);

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
  /// fail with a [StateError]. A no-op once the direction has ended.
  void reset(int code);

  /// Asks the peer to stop sending with [code] (`STOP_SENDING`). This
  /// side's read direction ends at once: the stack discards what still
  /// arrives, and a pending [read] and every later one fail with a
  /// [QuicStreamReset] carrying [code] (the peer's confirming reset is not
  /// observable through the stacks). A no-op once the direction has ended.
  void stop(int code);

  /// Sender-local priority: higher first, strict between levels. The
  /// binding uses 2 for the control stream, 1 ordinary, 0 bulk.
  set priority(int value);

  /// Completes when the peer's `STOP_SENDING` arrived (with its code) or
  /// when every byte of this side's direction was acknowledged after
  /// [finish] (null); with null at once when this side [reset] its
  /// direction. A provider answers a `STOP_SENDING` itself by resetting its
  /// direction with the same code (RFC 9000 section 3.5).
  Future<int?> get stopped;
}

/// Client configuration.
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
  });

  /// ALPN tokens to offer, in order (`switchboard` for raw QUIC); for
  /// WebTransport, the protocol values to offer instead.
  final List<String> alpn;

  /// SHA-256 hashes of acceptable server certificates (DER). Empty with
  /// [verifyCertificate] true: the platform roots; empty with it false:
  /// any certificate (the identity then comes from `IDENT`).
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

  /// Zero for none.
  final Duration keepAlive;
}

/// Server configuration (native provider).
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
  });

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
  sessionEnded,
  streamLimit,
  internal,
}

/// The peer reset its direction of a stream.
class QuicStreamReset implements Exception {
  const QuicStreamReset(this.code);
  final int code;
  @override
  String toString() => 'QuicStreamReset($code)';
}

/// The peer asked this side to stop sending.
class QuicStreamStopped implements Exception {
  const QuicStreamStopped(this.code);
  final int code;
  @override
  String toString() => 'QuicStreamStopped($code)';
}
