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
  /// peer until the first write.
  Future<QuicStream> openStream();

  /// Streams the peer opened, in the order the stack delivers them (no
  /// order is guaranteed between streams).
  Stream<QuicStream> get incomingStreams;

  /// How many streams opened by the peer this side accepts at once (the
  /// `MAX_STREAMS` grant); null where the stack decides (browsers).
  int? get maxIncomingStreams;

  /// RFC 8446 section 7.5 keying material; null when the stack has no
  /// exporter (a browser without `exportKeyingMaterial`). On a raw QUIC
  /// connection [label] and [context] go to the TLS exporter unchanged (the
  /// binding asks for RFC 9266's `EXPORTER-Channel-Binding`, empty context).
  /// Over WebTransport the provider applies the per-session exporter of the
  /// draft itself (label `EXPORTER-WebTransport`, the session ID and the
  /// application's label and context in the TLS context), so [label] and
  /// [context] are the application's (`switchboard-ident`, empty).
  Future<Uint8List?> exportKeyingMaterial(
    String label,
    Uint8List context,
    int length,
  );

  /// The server certificate's SHA-256 over its DER encoding, for pinning
  /// (initiator side); null when the provider does not expose it.
  Uint8List? get peerCertificateHash;

  /// Closes the session with an application [code] (0 to 255 here) and a
  /// [reason] (at most 1024 bytes of UTF-8). Idempotent.
  Future<void> close(int code, String reason);

  /// Completes when the session has ended, with how.
  Future<QuicSessionEnd> get done;
}

/// One bidirectional stream.
abstract interface class QuicStream {
  /// Reads the next chunk, at most [max] bytes; null at the peer's FIN.
  /// Fails with [QuicStreamReset] when the peer reset its direction (the
  /// code is the status), and with [QuicException] once the session has
  /// ended. Only one read may be pending at a time. The binding does not
  /// read again after [stop].
  Future<Uint8List?> read(int max);

  /// Writes [bytes]; completes once the stack has accepted them (they are
  /// copied, the buffer may be reused). Waits for stream and connection
  /// credit, so a peer that does not read stalls the writer. Fails with
  /// [QuicStreamStopped] once the peer sent `STOP_SENDING` (its code), and
  /// with [QuicException] once the session has ended. The binding has at
  /// most one write pending per stream.
  Future<void> write(Uint8List bytes);

  /// Ends this side's direction (FIN) after everything written.
  Future<void> finish();

  /// Aborts this side's direction with [code] (`RESET_STREAM`); data not yet
  /// delivered is discarded.
  void reset(int code);

  /// Asks the peer to stop sending with [code] (`STOP_SENDING`); what was
  /// not read yet may be discarded, and the peer's direction ends with a
  /// reset. A read pending meanwhile may complete, or fail with the reset
  /// or a [QuicException]; the binding reads no more.
  void stop(int code);

  /// Sender-local priority class. The binding uses 2 for the control
  /// stream, 1 for ordinary channels and 0 for bulk ones. 2 goes first,
  /// strictly. 1 and 0 share what is left so that neither starves the
  /// other: a stack whose priorities are strict only (quinn) puts 1 and 0
  /// on one level, below 2, where it interleaves them; one with weights or
  /// send groups (the W3C API's `sendGroup`) favours 1 without starving 0.
  set priority(int value);

  /// Completes when the peer's `STOP_SENDING` arrived (with its code) or
  /// when every byte of this side's direction was acknowledged after
  /// [finish] (null).
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
    this.receiveWindow = 16 << 20,
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
  final int maxStreamsBidi;
  final int streamReceiveWindow;

  /// The connection receive window (`MAX_DATA`) shared by every stream:
  /// the backstop for the stream windows together.
  final int receiveWindow;
  final Duration idleTimeout;
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
    this.receiveWindow = 16 << 20,
    this.idleTimeout = const Duration(seconds: 30),
    this.keepAlive = const Duration(seconds: 10),
  });

  final List<String> alpn;
  final Uint8List certificateDer;
  final Uint8List privateKeyDer;
  final int maxStreamsBidi;
  final int streamReceiveWindow;

  /// As [QuicClientConfig.receiveWindow].
  final int receiveWindow;
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

  /// The application error code; null when the stack delivered none (a
  /// WebTransport reset outside the application range, such as those of a
  /// terminating session).
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
