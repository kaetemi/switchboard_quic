/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The web stream provider: the browser's own WebTransport API (W3C) under
/// the binding, so that a browser frontend reaches a Switchboard node over
/// WebTransport. A browser cannot listen: [WebQuicProvider] is a
/// [QuicConnector] of `https://` sessions only.
///
/// What the browser decides, the provider cannot: the QUIC windows, the
/// stream limits, the idle timeout and keep-alive (the configuration's are
/// ignored), and whether a certificate is verified (always: by the platform
/// roots, or by `serverCertificateHashes`). What a browser may lack
/// (`protocol`, `draining`, `exportKeyingMaterial`, `getStats`, send
/// orders and groups) is feature-tested at run time; Chrome 149 has
/// `protocol` only.
///
/// Reads are pull-based through a default reader of each stream's
/// readable: a read takes one chunk of the browser's at most, returns at
/// most the bytes asked for and keeps the rest of the chunk for the next
/// read; what was not read stays in the browser's stream, whose flow
/// control is the browser's. Writes go through the writable's writer, one
/// at a time as its `ready` allows, and complete once the browser took the
/// chunk (a copy of the caller's bytes).
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:web/web.dart' as web;

import '../provider/quic_provider.dart';
import 'web_interop.dart';

/// The largest WebTransport application error code (a `u32`): session
/// close codes; stream codes are bounded by the browser too
/// ([WebQuicProvider.maxStreamErrorCode]).
const int _maxWebTransportCode = 0xFFFFFFFF;

/// The largest close reason, in bytes of UTF-8.
const int _maxReasonBytes = 1024;

void _checkCloseCode(int code) {
  if (code < 0 || code > _maxWebTransportCode) {
    throw ArgumentError.value(code, 'code', 'must be 0 to 2^32 - 1');
  }
}

void _checkStreamCode(int code) {
  _checkCloseCode(code);
  final max = StreamErrors.maxCode;
  if (code > max) {
    throw ArgumentError.value(
      code,
      'code',
      'this browser carries stream error codes of 0 to $max only',
    );
  }
}

/// WebTransport sessions through the browser's W3C API.
///
/// `connect` opens `new WebTransport(endpoint, {protocols, serverCertificateHashes,
/// allowPooling: false, requireUnreliable: false})`: [QuicClientConfig.alpn]
/// are the protocols offered (`switchboard` for Switchboard), and
/// [QuicClientConfig.serverCertificateHashes] the SHA-256 hashes of
/// acceptable certificates (a self-signed ECDSA P-256 certificate valid for
/// at most 14 days; empty: the platform roots). The browser verifies the
/// certificate whatever [QuicClientConfig.verifyCertificate] says. The
/// session is established once `ready` resolves; the browser tells a
/// refused request (another path, an origin the server refuses), an
/// unreachable server and a rejected certificate apart to no one ("Opening
/// handshake failed."), so all of them fail the connect with
/// [QuicExceptionKind.handshakeFailed] and the browser's message;
/// [QuicClientConfig.handshakeTimeout] bounds the wait (then
/// [QuicExceptionKind.unreachable]). The other durations, the windows and
/// the stream limit of the configuration are the browser's to decide, but
/// a negative duration is still an [ArgumentError].
final class WebQuicProvider implements QuicConnector {
  const WebQuicProvider();

  /// Whether this browser has the WebTransport API (a secure context of a
  /// browser that implements it).
  static bool get isSupported {
    final constructor = webTransportClass;
    return constructor != null && constructor.isA<JSFunction>();
  }

  /// The largest stream error code ([QuicStream.reset], [QuicStream.stop])
  /// this browser can send: 2^32 - 1 by the specification, 255 in Chrome
  /// 149, whose `WebTransportError.streamErrorCode` is an octet. A larger
  /// code is an [ArgumentError] rather than another code on the wire. The
  /// binding sends status codes, 0 to 255. Codes received are not bounded.
  static int get maxStreamErrorCode => StreamErrors.maxCode;

  /// The `sendOrder` of a stream of the priority class [priorityClass]
  /// (see [QuicStream.priority]), where the browser has send orders:
  /// higher goes sooner, strictly, among the streams of one send group. A
  /// class above 1 is `class - 1`, so the control stream (2) is 1; the
  /// classes 1 (ordinary) and 0 (bulk) are both 0, so that neither starves
  /// the other where they share a group; a negative class is itself.
  static int sendOrderOf(int priorityClass) =>
      priorityClass > 0 ? priorityClass - 1 : priorityClass;

  /// Connects to the `https://host:port/path` [endpoint] (port 443 by
  /// default; its fragment dropped). Fails with
  /// [QuicExceptionKind.unsupportedScheme] for any other scheme, and where
  /// the browser has no WebTransport API.
  @override
  Future<QuicSession> connect(Uri endpoint, QuicClientConfig config) async {
    if (endpoint.scheme.toLowerCase() != 'https') {
      throw QuicException(
        QuicExceptionKind.unsupportedScheme,
        'the web provider dials https:// only, not ${endpoint.scheme}://',
      );
    }
    if (endpoint.host.isEmpty) {
      throw QuicException(
        QuicExceptionKind.unreachable,
        'an https:// endpoint needs a host: $endpoint',
      );
    }
    if (endpoint.userInfo.isNotEmpty) {
      throw ArgumentError.value(
        endpoint,
        'endpoint',
        'userinfo is not allowed',
      );
    }
    for (final (name, d) in [
      ('idleTimeout', config.idleTimeout),
      ('keepAlive', config.keepAlive),
      ('handshakeTimeout', config.handshakeTimeout),
    ]) {
      if (d.isNegative) {
        throw ArgumentError.value(d, name, 'must not be negative');
      }
    }
    for (final hash in config.serverCertificateHashes) {
      if (hash.length != 32) {
        throw ArgumentError('a certificate hash is 32 bytes (SHA-256)');
      }
    }
    if (!isSupported) {
      throw const QuicException(
        QuicExceptionKind.unsupportedScheme,
        'this browser has no WebTransport API (or the page is not a secure '
        'context)',
      );
    }
    final options = web.WebTransportOptions(
      allowPooling: false,
      requireUnreliable: false,
    );
    if (config.alpn.isNotEmpty) {
      options.protocols = [for (final p in config.alpn) p.toJS].toJS;
    }
    if (config.serverCertificateHashes.isNotEmpty) {
      options.serverCertificateHashes = [
        for (final hash in config.serverCertificateHashes)
          web.WebTransportHash(
            algorithm: 'sha-256',
            value: Uint8List.fromList(hash).toJS,
          ),
      ].toJS;
    }
    final url = endpoint.removeFragment().toString();
    final web.WebTransport transport;
    try {
      transport = web.WebTransport(url, options);
    } on Object catch (e) {
      // A SyntaxError: the URL or the protocols.
      throw ArgumentError(
        'the browser refused the endpoint or the options: $e',
      );
    }
    return WebQuicSession._(
      transport,
      endpoint,
    )._connect(config.handshakeTimeout);
  }
}

/// Statistics of a [WebQuicSession], where the browser has `getStats`
/// (W3C `WebTransportConnectionStats`); a field the browser does not report
/// is null.
final class WebQuicStats {
  const WebQuicStats({
    this.bytesSent,
    this.packetsSent,
    this.packetsLost,
    this.bytesReceived,
    this.packetsReceived,
    this.smoothedRtt,
    this.rttVariation,
    this.minRtt,
    this.estimatedSendRate,
  });

  final int? bytesSent;
  final int? packetsSent;
  final int? packetsLost;
  final int? bytesReceived;
  final int? packetsReceived;
  final Duration? smoothedRtt;
  final Duration? rttVariation;
  final Duration? minRtt;

  /// Bits per second.
  final int? estimatedSendRate;
}

extension type _Stats._(JSObject _) implements JSObject {
  external JSAny? get bytesSent;
  external JSAny? get packetsSent;
  external JSAny? get packetsLost;
  external JSAny? get bytesReceived;
  external JSAny? get packetsReceived;
  external JSAny? get smoothedRtt;
  external JSAny? get rttVariation;
  external JSAny? get minRtt;
  external JSAny? get estimatedSendRate;
}

/// What `closed` resolves with (W3C `WebTransportCloseInfo`), read
/// defensively.
extension type _CloseInfo._(JSObject _) implements JSObject {
  external JSAny? get closeCode;
  external JSAny? get reason;
}

double? _number(JSAny? value) => value != null && value.isA<JSNumber>()
    ? (value as JSNumber).toDartDouble
    : null;

int? _integer(JSAny? value) => _number(value)?.toInt();

/// A `DOMHighResTimeStamp` duration in milliseconds.
Duration? _millis(JSAny? value) {
  final ms = _number(value);
  return ms == null ? null : Duration(microseconds: (ms * 1000).round());
}

/// One WebTransport session of the browser.
final class WebQuicSession implements QuicSession {
  WebQuicSession._(this._transport, Uri endpoint)
    : remote = _authority(endpoint) {
    jsFuture(_transport.closed).then(_onClosed, onError: _onClosedError);
  }

  static String _authority(Uri endpoint) {
    final host = endpoint.host.contains(':')
        ? '[${endpoint.host}]'
        : endpoint.host;
    return '$host:${endpoint.port}';
  }

  final web.WebTransport _transport;
  Completer<QuicSession>? _connecting;
  Timer? _handshakeTimer;
  String? _protocol;
  final _done = Completer<QuicSessionEnd>();
  final _draining = Completer<void>();
  QuicSessionEnd? _end;
  QuicException? _endError;
  bool _closeSent = false;
  int _closeCode = 0;
  String _closeReason = '';
  Timer? _goneTimer;

  // Streams.
  final _streams = <WebQuicStream>{};
  final _receiveStreams = <WebQuicReceiveStream>{};
  final _opens = Queue<Completer<QuicStream>>();
  bool _opening = false;
  late final _incoming = StreamController<QuicStream>(
    onListen: _pumpIncoming,
    onResume: _pumpIncoming,
  );
  late final _unidirectional = StreamController<QuicReceiveStream>(
    onListen: _pumpUnidirectional,
    onResume: _pumpUnidirectional,
  );
  web.ReadableStreamDefaultReader? _incomingReader;
  web.ReadableStreamDefaultReader? _unidirectionalReader;
  bool _incomingPumping = false;
  bool _unidirectionalPumping = false;

  // Send groups, where the browser has them.
  JSObject? _ordinaryGroup;
  JSObject? _bulkGroup;

  /// Always the initiator: a browser cannot listen.
  @override
  bool get isInitiator => true;

  /// The protocol the server selected (`wt.protocol`); null where the
  /// browser does not say, or the server selected none.
  @override
  String? get protocol => _protocol;

  /// The endpoint's host and port: the browser does not tell the address
  /// it reached.
  @override
  final String remote;

  /// The browser does not expose the certificate.
  @override
  Uint8List? get peerCertificateHash => null;

  /// The browser decides.
  @override
  int? get maxIncomingStreams => null;

  @override
  Future<QuicSessionEnd> get done => _done.future;

  /// Completes on `wt.draining` where the browser has it (the server's
  /// `WT_DRAIN_SESSION` or an HTTP/3 `GOAWAY`); never in Chrome 149, which
  /// has no such promise.
  @override
  Future<void> get draining => _draining.future;

  @override
  Stream<QuicStream> get incomingStreams => _incoming.stream;

  /// The server's unidirectional streams, from the session's
  /// `incomingUnidirectionalStreams`, for the application to stop. Done
  /// when the session ends.
  @override
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams =>
      _unidirectional.stream;

  /// Which optional members of the W3C API this browser's session has, by
  /// name: `protocol`, `draining`, `exportKeyingMaterial`, `getStats` and
  /// `createSendGroup` (Chrome 149: `protocol` only). For diagnostics; the
  /// provider tests each where it uses it.
  Map<String, bool> get capabilities => {
    'protocol': _transport.protocolProperty?.isA<JSString>() ?? false,
    'draining': _transport.drainingProperty?.isA<JSPromise>() ?? false,
    'exportKeyingMaterial': _hasFunction(
      _transport.exportKeyingMaterialProperty,
    ),
    'getStats': _hasFunction(_transport.getStatsProperty),
    'createSendGroup': hasSendGroups,
  };

  /// Whether the browser has send groups (`createSendGroup`): the binding's
  /// classes 2 and 1 then share one group (2 at a higher `sendOrder`) and
  /// class 0 has another, which the browser serves side by side.
  bool get hasSendGroups => _hasFunction(_transport.createSendGroupProperty);

  /// The session's statistics where the browser has `getStats` (W3C); null
  /// where it has not (Chrome 149) or once the session has ended.
  Future<WebQuicStats?> stats() async {
    if (_end != null || !_hasFunction(_transport.getStatsProperty)) {
      return null;
    }
    final JSAny? value;
    try {
      value = await jsFuture(_transport.getStats());
    } on JsError {
      return null;
    }
    if (value == null || !value.isA<JSObject>()) return null;
    final s = value as _Stats;
    return WebQuicStats(
      bytesSent: _integer(s.bytesSent),
      packetsSent: _integer(s.packetsSent),
      packetsLost: _integer(s.packetsLost),
      bytesReceived: _integer(s.bytesReceived),
      packetsReceived: _integer(s.packetsReceived),
      smoothedRtt: _millis(s.smoothedRtt),
      rttVariation: _millis(s.rttVariation),
      minRtt: _millis(s.minRtt),
      estimatedSendRate: _integer(s.estimatedSendRate),
    );
  }

  static bool _hasFunction(JSAny? member) =>
      member != null && member.isA<JSFunction>();

  /// `createBidirectionalStream`. The browser rejects it while the server
  /// grants no stream (Chrome 149 does not wait, whatever
  /// `waitUntilAvailable` says), so the provider waits itself: it asks
  /// again, the first waiting call first, at growing intervals (5 to
  /// 200 ms) until the browser gives a stream or the session ends.
  @override
  Future<QuicStream> openStream() {
    final error = _endError;
    if (error != null) return Future.error(error);
    final completer = Completer<QuicStream>();
    _opens.add(completer);
    unawaited(_openNext());
    return completer.future;
  }

  Future<void> _openNext() async {
    if (_opening) return;
    _opening = true;
    var backoff = const Duration(milliseconds: 5);
    while (_opens.isNotEmpty && _end == null) {
      final JSAny? value;
      try {
        value = await jsFuture(
          _transport.createBidirectionalStream(
            SendStreamOptions(waitUntilAvailable: true)
                as web.WebTransportSendStreamOptions,
          ),
        );
      } on JsError {
        if (_end != null) break;
        // No stream credit yet, or the session is ending (its end follows).
        await Future<void>.delayed(backoff);
        backoff = backoff * 2;
        if (backoff > const Duration(milliseconds: 200)) {
          backoff = const Duration(milliseconds: 200);
        }
        continue;
      }
      backoff = const Duration(milliseconds: 5);
      final stream = WebQuicStream._fromPair(this, value);
      final error = _endError;
      if (error != null) {
        stream._sessionEnded(error);
        break;
      }
      if (_opens.isEmpty) {
        // Nobody waits any more (cannot happen while the session lives).
        stream._discard();
        break;
      }
      _opens.removeFirst().complete(stream);
    }
    _opening = false;
  }

  /// The keying material exporter of the session where the browser has
  /// `exportKeyingMaterial` (W3C; [label] and [context] as given, the
  /// browser applying WebTransport's per-session derivation); null where it
  /// has not (Chrome 149), where it fails, and where it does not export
  /// [length] bytes.
  @override
  Future<Uint8List?> exportKeyingMaterial(
    String label,
    Uint8List context,
    int length,
  ) async {
    final error = _endError;
    if (error != null) throw error;
    if (length <= 0) throw ArgumentError.value(length, 'length');
    if (!_hasFunction(_transport.exportKeyingMaterialProperty)) return null;
    final JSAny? value;
    try {
      value = await jsFuture(
        _transport.exportKeyingMaterial(
          Uint8List.fromList(utf8.encode(label)).toJS,
          Uint8List.fromList(context).toJS,
        ),
      );
    } on JsError {
      final ended = _endError;
      if (ended != null) throw ended;
      return null;
    }
    if (value == null || !value.isA<JSArrayBuffer>()) return null;
    final bytes = (value as JSArrayBuffer).toDart.asUint8List();
    return bytes.length == length ? Uint8List.fromList(bytes) : null;
  }

  /// `wt.close({closeCode, reason})`: [code] 0 to 2^32 - 1, [reason] cut to
  /// 1024 bytes of UTF-8 at a character boundary (Chrome 149 would send a
  /// longer one). The browser's network stack sends the close and ends the
  /// QUIC connection on its own, whatever the page does next; the future
  /// completes once the browser reports the session closed, at once.
  @override
  Future<void> close(int code, String reason) {
    _checkCloseCode(code);
    if (_end == null && !_closeSent) {
      _closeSent = true;
      _closeCode = code;
      _closeReason = _truncateUtf8(reason, _maxReasonBytes);
      try {
        _transport.close(
          web.WebTransportCloseInfo(closeCode: code, reason: _closeReason),
        );
      } on Object catch (e) {
        _ended(QuicSessionEnd.lost('close failed: $e'));
      }
    }
    return _done.future.then((_) {});
  }

  // Establishing ---------------------------------------------------------------

  Future<QuicSession> _connect(Duration deadline) {
    final completer = _connecting = Completer<QuicSession>();
    if (deadline > Duration.zero) {
      _handshakeTimer = Timer(deadline, () {
        _connectFailed(
          QuicException(
            QuicExceptionKind.unreachable,
            'the WebTransport session to $remote was not established within '
            '$deadline',
          ),
          abandon: true,
        );
      });
    }
    jsFuture(_transport.ready).then(
      (_) => _established(),
      onError: (Object e) => _connectFailed(
        QuicException(
          QuicExceptionKind.handshakeFailed,
          'the WebTransport session to $remote was not established: $e '
          '(a browser tells a refusal, an unreachable server and a rejected '
          'certificate apart to no one)',
        ),
      ),
    );
    return completer.future;
  }

  void _established() {
    final connecting = _connecting;
    if (connecting == null || _end != null) return;
    _connecting = null;
    _handshakeTimer?.cancel();
    _handshakeTimer = null;
    final protocol = _transport.protocolProperty;
    if (protocol != null && protocol.isA<JSString>()) {
      final value = (protocol as JSString).toDart;
      _protocol = value.isEmpty ? null : value;
    }
    final draining = _transport.drainingProperty;
    if (draining != null && draining.isA<JSPromise>()) {
      jsFuture(draining as JSPromise<JSAny?>).then((_) {
        if (_end == null && !_draining.isCompleted) _draining.complete();
      }, onError: (Object _) {});
    }
    connecting.complete(this);
  }

  void _connectFailed(QuicException error, {bool abandon = false}) {
    final connecting = _connecting;
    if (connecting == null) return;
    _connecting = null;
    _handshakeTimer?.cancel();
    _handshakeTimer = null;
    if (abandon) {
      try {
        _transport.close();
      } on Object {
        // Closed meanwhile.
      }
    }
    _ended(QuicSessionEnd.lost(error.message));
    connecting.completeError(error);
  }

  // The end ---------------------------------------------------------------------

  void _onClosed(JSAny? value) {
    if (_end != null) return;
    if (_connecting != null) {
      _connectFailed(
        QuicException(
          QuicExceptionKind.handshakeFailed,
          'the WebTransport session to $remote closed before it was '
          'established',
        ),
      );
      return;
    }
    var code = 0;
    var reason = '';
    if (value != null && value.isA<JSObject>()) {
      final info = value as _CloseInfo;
      code = _integer(info.closeCode) ?? 0;
      final text = info.reason;
      if (text != null && text.isA<JSString>()) {
        reason = (text as JSString).toDart;
      }
    }
    final local = _closeSent && code == _closeCode && reason == _closeReason;
    _ended(QuicSessionEnd.closed(code, reason, byPeer: !local));
  }

  void _onClosedError(Object error) {
    if (_end != null) return;
    if (_connecting != null) {
      _connectFailed(
        QuicException(
          QuicExceptionKind.handshakeFailed,
          'the WebTransport session to $remote was not established: $error',
        ),
      );
      return;
    }
    _ended(
      _closeSent
          ? QuicSessionEnd.closed(_closeCode, _closeReason, byPeer: false)
          : QuicSessionEnd.lost(
              error is JsError ? error.message : error.toString(),
            ),
    );
  }

  /// A stream reported the end of the session (a `WebTransportError` of
  /// source `session`), which the browser reports on the streams before
  /// `closed` settles: the session ends as lost if `closed` does not
  /// settle within two seconds.
  void _sessionGone(String message) {
    if (_end != null || _goneTimer != null) return;
    _goneTimer = Timer(const Duration(seconds: 2), () {
      _ended(QuicSessionEnd.lost(message));
    });
  }

  /// The error what is pending fails with once the session ends, or
  /// is ending ([message] from the browser).
  QuicException _sessionEndedError([String? message]) =>
      _endError ??
      QuicException(
        QuicExceptionKind.sessionEnded,
        message == null || message.isEmpty
            ? 'the session has ended'
            : 'the session has ended: $message',
      );

  static QuicException _endedError(QuicSessionEnd end) => QuicException(
    QuicExceptionKind.sessionEnded,
    end.lost
        ? 'the session was lost: ${end.reason}'
        : 'the session was closed with ${end.code}'
              '${end.byPeer ? ' by the peer' : ''}: ${end.reason}',
  );

  void _ended(QuicSessionEnd end) {
    if (_end != null) return;
    _end = end;
    final error = _endError = _endedError(end);
    _goneTimer?.cancel();
    _goneTimer = null;
    _handshakeTimer?.cancel();
    _handshakeTimer = null;
    while (_opens.isNotEmpty) {
      _opens.removeFirst()
        ..future.ignore()
        ..completeError(error);
    }
    for (final stream in [..._streams]) {
      stream._sessionEnded(error);
    }
    for (final stream in [..._receiveStreams]) {
      stream._release();
    }
    unawaited(_incoming.close());
    unawaited(_unidirectional.close());
    if (!_incomingPumping) _incomingReader = _releaseReader(_incomingReader);
    if (!_unidirectionalPumping) {
      _unidirectionalReader = _releaseReader(_unidirectionalReader);
    }
    _done.complete(end);
  }

  static web.ReadableStreamDefaultReader? _releaseReader(
    web.ReadableStreamDefaultReader? reader,
  ) {
    try {
      reader?.releaseLock();
    } on Object {
      // Released already.
    }
    return null;
  }

  // The peer's streams ---------------------------------------------------------

  /// Reads the next of the server's bidirectional streams while someone
  /// listens and is not paused: the others wait in the browser.
  void _pumpIncoming() {
    if (_incomingPumping || _end != null || _connecting != null) return;
    _incomingPumping = true;
    unawaited(_runIncoming());
  }

  Future<void> _runIncoming() async {
    final reader = _incomingReader ??=
        _transport.incomingBidirectionalStreams.getReader()
            as web.ReadableStreamDefaultReader;
    try {
      while (_end == null && _incoming.hasListener && !_incoming.isPaused) {
        final result =
            await jsFuture(reader.read()) as web.ReadableStreamReadResult;
        if (result.done) break;
        final stream = WebQuicStream._fromPair(this, result.value);
        final error = _endError;
        if (error != null) {
          stream._sessionEnded(error);
          break;
        }
        if (!_incoming.hasListener) {
          // Nobody takes it any more.
          stream._discard();
          break;
        }
        _incoming.add(stream);
      }
    } on JsError {
      // The session is ending; `closed` tells how.
    }
    _incomingPumping = false;
    if (_end != null) _incomingReader = _releaseReader(_incomingReader);
  }

  void _pumpUnidirectional() {
    if (_unidirectionalPumping || _end != null || _connecting != null) return;
    _unidirectionalPumping = true;
    unawaited(_runUnidirectional());
  }

  Future<void> _runUnidirectional() async {
    final reader = _unidirectionalReader ??=
        _transport.incomingUnidirectionalStreams.getReader()
            as web.ReadableStreamDefaultReader;
    try {
      while (_end == null &&
          _unidirectional.hasListener &&
          !_unidirectional.isPaused) {
        final result =
            await jsFuture(reader.read()) as web.ReadableStreamReadResult;
        if (result.done) break;
        final stream = WebQuicReceiveStream._(
          this,
          result.value as web.ReadableStream,
        );
        if (_end != null || !_unidirectional.hasListener) {
          stream.stop(0);
          break;
        }
        _receiveStreams.add(stream);
        _unidirectional.add(stream);
      }
    } on JsError {
      // The session is ending.
    }
    _unidirectionalPumping = false;
    if (_end != null) {
      _unidirectionalReader = _releaseReader(_unidirectionalReader);
    }
  }

  /// The send group of the priority class [priorityClass], creating the
  /// session's two groups on first use; null where the browser has none.
  JSObject? _sendGroupOf(int priorityClass) {
    if (!hasSendGroups) return null;
    try {
      return priorityClass > 0
          ? (_ordinaryGroup ??= _transport.createSendGroup())
          : (_bulkGroup ??= _transport.createSendGroup());
    } on Object {
      return null;
    }
  }

  @override
  String toString() => 'WebQuicSession($remote)';
}

/// The receive direction of one of the server's unidirectional streams.
final class WebQuicReceiveStream implements QuicReceiveStream {
  WebQuicReceiveStream._(this._session, this._readable);

  final WebQuicSession _session;
  final web.ReadableStream _readable;
  bool _released = false;

  /// `readable.cancel(new WebTransportError({streamErrorCode: code}))`, the
  /// `STOP_SENDING` (a code the browser carries, see
  /// [WebQuicProvider.maxStreamErrorCode]). Idempotent, also after the
  /// session ended.
  @override
  void stop(int code) {
    _checkStreamCode(code);
    if (_released) return;
    ignorePromise(_readable.cancel(StreamErrors.create(code, 'STOP_SENDING')));
    _release();
  }

  void _release() {
    _released = true;
    _session._receiveStreams.remove(this);
  }
}

/// One write, or the finish, queued on a stream.
final class _Write {
  _Write(this.bytes) : finish = false;
  _Write.fin() : bytes = Uint8List(0), finish = true;

  final Uint8List bytes;
  final bool finish;
  final done = Completer<void>();

  void complete() {
    if (!done.isCompleted) done.complete();
  }

  void fail(Object error) {
    if (done.isCompleted) return;
    done
      ..future.ignore()
      ..completeError(error);
  }
}

/// One bidirectional stream of a [WebQuicSession]: the default reader of
/// its readable and the writer of its writable, held for the stream's
/// life and released once each direction has ended.
final class WebQuicStream implements QuicStream {
  WebQuicStream._(
    this._session,
    web.ReadableStream readable,
    web.WritableStream writable,
  ) : _writable = writable,
      _reader = readable.getReader() as web.ReadableStreamDefaultReader,
      _writer = writable.getWriter() {
    _session._streams.add(this);
    _reset.future.ignore();
    jsFuture(_reader.closed).then((_) {}, onError: _receiveFailed);
    jsFuture(_writer.closed).then((_) => _sendClosed(), onError: _sendFailed);
  }

  factory WebQuicStream._fromPair(WebQuicSession session, JSAny? pair) {
    final stream = pair as web.WebTransportBidirectionalStream;
    return WebQuicStream._(
      session,
      stream.readable as web.ReadableStream,
      stream.writable as web.WritableStream,
    );
  }

  final WebQuicSession _session;
  final web.WritableStream _writable;
  final web.ReadableStreamDefaultReader _reader;
  final web.WritableStreamDefaultWriter _writer;

  // Receive direction.
  Uint8List? _chunk;
  int _offset = 0;
  Completer<Uint8List?>? _read;
  int _readMax = 0;
  bool _pulling = false;
  bool _cancelling = false;
  bool _fin = false;
  Object? _recvFailure;
  bool _recvEnded = false;
  bool _readerReleased = false;
  final _reset = Completer<int?>();

  // Send direction.
  final _writes = Queue<_Write>();
  final _handed = <_Write>{};
  bool _pumping = false;
  Future<void>? _finishing;
  bool _resetSent = false;
  bool _peerStop = false;
  Object? _sendFailure;
  bool _sendEnded = false;
  bool _writerReleased = false;
  final _stopped = Completer<int?>();

  /// Completes with the server's `RESET_STREAM` code (the readable's
  /// `closed` rejected with a `WebTransportError` of source `stream`; null
  /// when it carried no code, or the rejection was no `WebTransportError`),
  /// whether a read is pending or not; fails with `sessionEnded` when the
  /// session ends first; stays pending after FIN or a local [stop].
  @override
  Future<int?> get resetReceived => _reset.future;

  /// Completes with the server's `STOP_SENDING` code (the writable's
  /// `closed` rejected with it; a `STOP_SENDING` without a code fails it
  /// with [QuicStreamStopped] of null), or with null once the browser
  /// closed this side's direction after [finish] (it does not tell when the
  /// server acknowledged the data) or at once after [reset].
  @override
  Future<int?> get stopped => _stopped.future;

  /// Whether the browser has send orders on this stream (`sendOrder` on
  /// the writable, W3C `WebTransportSendStream`); Chrome 149 has none.
  bool get hasSendOrder =>
      _writable.sendOrderProperty?.isA<JSNumber>() ?? false;

  /// Where the browser has send orders (`sendOrder` on the writable, W3C
  /// `WebTransportSendStream`): [WebQuicProvider.sendOrderOf] the class,
  /// in the session's send group of the class where it has send groups.
  /// Chrome 149 has neither: its streams share the browser's own
  /// scheduling, the control stream included.
  @override
  set priority(int value) {
    if (_sendEnded || !hasSendOrder) return;
    try {
      final group = _session._sendGroupOf(value);
      if (group != null) _writable.sendGroup = group;
      _writable.sendOrder = WebQuicProvider.sendOrderOf(value);
    } on Object {
      // A stream that ended meanwhile.
    }
  }

  // Reading ---------------------------------------------------------------------

  @override
  Future<Uint8List?> read(int max) {
    if (max <= 0) throw ArgumentError.value(max, 'max');
    if (_read != null) throw StateError('a read is pending on this stream');
    final failure = _recvFailure;
    if (failure != null) return Future.error(failure);
    final buffered = _take(max);
    if (buffered != null) return Future.value(buffered);
    if (_fin) return Future.value(null);
    _readMax = max;
    final completer = _read = Completer<Uint8List?>();
    _pull();
    return completer.future;
  }

  /// At most [max] bytes of the chunk read last; null when none is left.
  Uint8List? _take(int max) {
    final chunk = _chunk;
    if (chunk == null) return null;
    final n = math.min(max, chunk.length - _offset);
    final bytes = Uint8List.sublistView(chunk, _offset, _offset + n);
    _offset += n;
    if (_offset == chunk.length) {
      _chunk = null;
      _offset = 0;
    }
    return bytes;
  }

  void _pull() {
    if (_pulling) return;
    _pulling = true;
    jsFuture(_reader.read()).then(_onChunk, onError: _onReadFailed);
  }

  void _onChunk(JSAny? value) {
    _pulling = false;
    if (_recvEnded) {
      _releaseReader();
      return;
    }
    final result = value as web.ReadableStreamReadResult;
    if (result.done) {
      _fin = true;
      final c = _read;
      _read = null;
      c?.complete(null);
      _endRecv();
      return;
    }
    final chunk = (result.value as JSUint8Array).toDart;
    if (chunk.isEmpty) {
      _pull();
      return;
    }
    _chunk = chunk;
    _offset = 0;
    final c = _read;
    if (c != null) {
      _read = null;
      c.complete(_take(_readMax));
    }
  }

  void _onReadFailed(Object error) {
    _pulling = false;
    if (_recvEnded) {
      _releaseReader();
      return;
    }
    _receiveFailed(error);
  }

  /// The readable failed (a read, or its `closed`): the server's reset, or
  /// the end of the session.
  void _receiveFailed(Object error) {
    if (_recvEnded) return;
    final e = error is JsError ? error : null;
    if ((e != null && e.fromSession) || _session._end != null) {
      _session._sessionGone(e?.message ?? '$error');
      _failReceive(_session._sessionEndedError(e?.message));
      return;
    }
    final code = e != null && e.fromStream ? e.streamErrorCode : null;
    if (!_reset.isCompleted) _reset.complete(code);
    _failReceive(QuicStreamReset(code));
  }

  void _failReceive(Object failure) {
    _recvFailure = failure;
    _chunk = null;
    if (failure is QuicException && !_reset.isCompleted) {
      _reset.completeError(failure);
    }
    final c = _read;
    if (c != null) {
      _read = null;
      c.completeError(failure);
    }
    _endRecv();
  }

  /// `reader.cancel(new WebTransportError({streamErrorCode: code}))`, the
  /// `STOP_SENDING`: this direction ends at once, a pending read and every
  /// later one failing with [QuicStreamReset] of [code].
  @override
  void stop(int code) {
    _checkStreamCode(code);
    if (_recvEnded) return;
    final failure = _recvFailure = QuicStreamReset(code);
    _chunk = null;
    final c = _read;
    if (c != null) {
      _read = null;
      c.completeError(failure);
    }
    _cancelling = true;
    jsFuture(_reader.cancel(StreamErrors.create(code, 'STOP_SENDING')))
        .then((_) {}, onError: (Object _) {})
        .whenComplete(() {
          _cancelling = false;
          _releaseReader();
        });
    _endRecv();
  }

  void _endRecv() {
    if (_recvEnded) return;
    _recvEnded = true;
    _chunk = null;
    _releaseReader();
    if (_sendEnded) _release();
  }

  /// Releases the reader's lock once this direction has ended and nothing
  /// of the reader is pending.
  void _releaseReader() {
    if (!_recvEnded || _pulling || _cancelling || _readerReleased) return;
    _readerReleased = true;
    try {
      _reader.releaseLock();
    } on Object {
      // Released with the stream.
    }
  }

  // Writing ---------------------------------------------------------------------

  @override
  Future<void> write(Uint8List bytes) {
    final failure = _sendFailure;
    if (failure != null) return Future.error(failure);
    if (_finishing != null || _resetSent) {
      return Future.error(StateError('the stream was finished or reset'));
    }
    final w = _Write(Uint8List.fromList(bytes));
    _writes.add(w);
    unawaited(_pump());
    return w.done.future;
  }

  /// `writer.close()` after everything written: completes once the
  /// browser closed the direction.
  @override
  Future<void> finish() {
    final f = _finishing;
    if (f != null) return f;
    final failure = _sendFailure;
    if (failure != null) return Future.error(failure);
    if (_resetSent) return Future.error(StateError('the stream was reset'));
    final w = _Write.fin();
    _writes.add(w);
    unawaited(_pump());
    return _finishing = w.done.future;
  }

  /// Hands the queued writes to the writer in order, each once its `ready`
  /// allows (the browser's backpressure).
  Future<void> _pump() async {
    if (_pumping) return;
    _pumping = true;
    try {
      while (_writes.isNotEmpty && !_sendEnded && !_resetSent) {
        final desired = _writer.desiredSize;
        if (desired == null) break;
        if (desired <= 0) {
          try {
            await jsFuture(_writer.ready);
          } on JsError {
            // Errored: its `closed` tells why.
            break;
          }
          continue;
        }
        final w = _writes.removeFirst();
        _handed.add(w);
        unawaited(
          jsFuture(w.finish ? _writer.close() : _writer.write(w.bytes.toJS))
              .then(
                (_) {
                  _handed.remove(w);
                  w.complete();
                },
                onError: (Object error) {
                  _handed.remove(w);
                  w.fail(_sendError(error));
                },
              ),
        );
      }
    } finally {
      _pumping = false;
    }
  }

  /// What a failed write or finish reports.
  Object _sendError(Object error) {
    if (_resetSent) return StateError('the stream was reset');
    final failure = _sendFailure;
    if (failure != null) return failure;
    if (error is JsError) {
      if (error.fromStream) {
        _peerStopped(error.streamErrorCode);
        return _sendFailure!;
      }
      if (error.fromSession || _session._end != null) {
        _session._sessionGone(error.message);
        return _session._sessionEndedError(error.message);
      }
    }
    return QuicException(QuicExceptionKind.internal, 'write failed: $error');
  }

  /// The writable's `closed` resolved: the browser closed the direction
  /// after FIN.
  void _sendClosed() {
    if (!_stopped.isCompleted) _stopped.complete(null);
    _endSend();
  }

  /// The writable's `closed` rejected: the server's `STOP_SENDING`, the
  /// end of the session, or this side's own reset (or released lock).
  void _sendFailed(Object error) {
    if (_resetSent || _sendEnded) return;
    final e = error is JsError ? error : null;
    if (e != null && e.fromStream) {
      _peerStopped(e.streamErrorCode);
      return;
    }
    if ((e != null && e.fromSession) || _session._end != null) {
      _session._sessionGone(e?.message ?? '$error');
      final failure = _sendFailure = _session._sessionEndedError(e?.message);
      _failWrites(failure);
      if (!_stopped.isCompleted) {
        _stopped
          ..future.ignore()
          ..completeError(failure);
      }
      _endSend();
    }
  }

  void _peerStopped(int? code) {
    if (_peerStop || _sendEnded) return;
    _peerStop = true;
    final failure = _sendFailure = QuicStreamStopped(code);
    _failWrites(failure);
    if (!_stopped.isCompleted) {
      if (code == null) {
        // Not to be read as an acknowledgement.
        _stopped
          ..future.ignore()
          ..completeError(failure);
      } else {
        _stopped.complete(code);
      }
    }
    _endSend();
  }

  void _failWrites(Object error) {
    for (final w in [..._handed, ..._writes]) {
      w.fail(error);
    }
    _handed.clear();
    _writes.clear();
  }

  /// `writer.abort(new WebTransportError({streamErrorCode: code}))`, the
  /// `RESET_STREAM` (a code the browser carries, see
  /// [WebQuicProvider.maxStreamErrorCode]). After [finish], once the
  /// browser has sent the FIN (Chrome 149 sends it at once) the abort is
  /// too late to reach the server, which reads the FIN.
  @override
  void reset(int code) {
    _checkStreamCode(code);
    if (_sendEnded || _resetSent || _sendFailure != null) return;
    _resetSent = true;
    _failWrites(StateError('the stream was reset'));
    ignorePromise(_writer.abort(StreamErrors.create(code, 'RESET_STREAM')));
    if (!_stopped.isCompleted) _stopped.complete(null);
    _endSend();
  }

  void _endSend() {
    if (_sendEnded) return;
    _sendEnded = true;
    if (!_writerReleased) {
      _writerReleased = true;
      try {
        _writer.releaseLock();
      } on Object {
        // Released with the stream.
      }
    }
    if (_recvEnded) _release();
  }

  // The end ---------------------------------------------------------------------

  /// Ends a stream nobody takes: `STOP_SENDING` and `RESET_STREAM` with
  /// code 0.
  void _discard() {
    stop(0);
    reset(0);
  }

  void _sessionEnded(QuicException error) {
    _sendFailure ??= error;
    _recvFailure ??= error;
    final c = _read;
    if (c != null) {
      _read = null;
      c.completeError(error);
    }
    _failWrites(error);
    if (!_stopped.isCompleted) {
      _stopped
        ..future.ignore()
        ..completeError(error);
    }
    if (!_reset.isCompleted) _reset.completeError(error);
    _endRecv();
    _endSend();
  }

  void _release() {
    _session._streams.remove(this);
  }
}

/// [text] cut to at most [max] bytes of UTF-8 at a character boundary.
String _truncateUtf8(String text, int max) {
  final bytes = utf8.encode(text);
  if (bytes.length <= max) return text;
  var n = max;
  while (n > 0 && (bytes[n] & 0xC0) == 0x80) {
    n--;
  }
  return utf8.decode(bytes.sublist(0, n));
}
