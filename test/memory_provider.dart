/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

// An in-memory stream provider for the tests of the binding: sessions with
// bidirectional streams whose directions are delivered independently, each
// in order, with a configurable delay per stream (so streams overtake one
// another and the control stream), stream and connection flow control
// (data stays with the sender until the receiver reads), a stream limit,
// resets and STOP_SENDING with codes (the sender's stack resets on
// STOP_SENDING, as RFC 9000 section 3.5 has it), FIN, an exporter equal at
// both ends of a session and different per session, and ends without one
// (a browser without exportKeyingMaterial).

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:switchboard_quic/core.dart';

/// What the delay of a stream direction is chosen by.
class MemoryQuicStreamInfo {
  MemoryQuicStreamInfo(this.ordinal, {required this.openedByInitiator});

  /// The stream's place among the session's streams, in the order they
  /// were opened (by either side), from 0.
  final int ordinal;

  /// Whether the initiator opened the stream.
  final bool openedByInitiator;
}

/// The delivery delay of a stream's records, per direction:
/// [fromInitiator] is the direction the initiator writes.
typedef MemoryQuicDelay = Duration Function(
  MemoryQuicStreamInfo stream, {
  required bool fromInitiator,
});

Duration noDelay(MemoryQuicStreamInfo stream, {required bool fromInitiator}) =>
    Duration.zero;

/// One end's configuration: what it grants its peer, and what it can do.
class MemoryQuicEndConfig {
  const MemoryQuicEndConfig({
    this.exporter = true,
    this.streamWindow = 64 * 1024,
    this.connectionWindow = 16 << 20,
    this.maxStreams = 128,
    this.certificateHash,
  });

  /// Whether this end can compute the exporter.
  final bool exporter;

  /// The receive window of each stream this end grants.
  final int streamWindow;

  /// The connection receive window this end grants.
  final int connectionWindow;

  /// How many streams the peer may have open toward this end at once.
  final int maxStreams;

  /// The hash of this end's certificate (servers).
  final Uint8List? certificateHash;

  MemoryQuicEndConfig copyWith({
    bool? exporter,
    int? streamWindow,
    int? connectionWindow,
    int? maxStreams,
  }) => MemoryQuicEndConfig(
    exporter: exporter ?? this.exporter,
    streamWindow: streamWindow ?? this.streamWindow,
    connectionWindow: connectionWindow ?? this.connectionWindow,
    maxStreams: maxStreams ?? this.maxStreams,
    certificateHash: certificateHash,
  );
}

/// Listeners by endpoint, and the connectors that reach them.
class MemoryQuicNetwork {
  MemoryQuicNetwork({this.delay = noDelay, this.closeDelay = Duration.zero});

  /// The delay of the stream directions of every session.
  MemoryQuicDelay delay;

  /// How long an application close takes to reach the peer.
  Duration closeDelay;

  final Map<String, MemoryQuicListener> _listeners = {};

  /// Every session pair created, initiator first.
  final List<(MemoryQuicSession, MemoryQuicSession)> pairs = [];

  static String _key(Uri endpoint) =>
      '${endpoint.scheme.toLowerCase()}://${endpoint.host.toLowerCase()}:'
      '${endpoint.port}';

  /// A listener at [endpoint] whose sessions grant what [config] says.
  MemoryQuicListener listen(
    Uri endpoint, {
    MemoryQuicEndConfig config = const MemoryQuicEndConfig(),
  }) {
    final listener = MemoryQuicListener._(this, endpoint, config);
    _listeners[_key(endpoint)] = listener;
    return listener;
  }

  /// A connector whose sessions are configured by [config] beyond what
  /// [QuicClientConfig] says. It dials `quic` endpoints, and `https` ones
  /// with [webTransport].
  MemoryQuicConnector connector({
    MemoryQuicEndConfig config = const MemoryQuicEndConfig(),
    bool webTransport = false,
  }) => MemoryQuicConnector._(this, config, webTransport);
}

class MemoryQuicConnector implements QuicConnector {
  MemoryQuicConnector._(this.network, this.config, this.webTransport);

  final MemoryQuicNetwork network;
  final MemoryQuicEndConfig config;
  final bool webTransport;

  /// The configurations the binding asked for, in order.
  final List<QuicClientConfig> configs = [];

  /// While set, a connect waits for it before it reaches the listener (a
  /// handshake that takes its time).
  Completer<void>? connectGate;

  @override
  Future<QuicSession> connect(Uri endpoint, QuicClientConfig config) async {
    for (final (name, duration) in [
      ('idleTimeout', config.idleTimeout),
      ('keepAlive', config.keepAlive),
      ('handshakeTimeout', config.handshakeTimeout),
    ]) {
      if (duration.isNegative) {
        throw ArgumentError.value(duration, name, 'must not be negative');
      }
    }
    configs.add(config);
    await connectGate?.future;
    await Future<void>.delayed(Duration.zero);
    final scheme = endpoint.scheme.toLowerCase();
    if (scheme != 'quic' && !(webTransport && scheme == 'https')) {
      throw QuicException(
        QuicExceptionKind.unsupportedScheme,
        'the memory provider does not dial $scheme',
      );
    }
    final listener = network._listeners[MemoryQuicNetwork._key(endpoint)];
    if (listener == null || listener._closed) {
      throw QuicException(
        QuicExceptionKind.unreachable,
        'no listener at $endpoint',
      );
    }
    final hash = listener.config.certificateHash;
    if (config.serverCertificateHashes.isNotEmpty &&
        (hash == null ||
            !config.serverCertificateHashes.any((h) => _equal(h, hash)))) {
      throw QuicException(
        QuicExceptionKind.certificateRejected,
        'the certificate is not pinned',
      );
    }
    final (client, server) = MemoryQuicSession.pair(
      network: network,
      initiator: this.config.copyWith(
        streamWindow: config.streamReceiveWindow,
        connectionWindow: config.connectionReceiveWindow,
        maxStreams: config.maxStreamsBidi,
      ),
      acceptor: listener.config,
      certificateHash: hash,
    );
    listener._sessions.add(server);
    return client;
  }
}

class MemoryQuicListener implements QuicListener {
  MemoryQuicListener._(this.network, this.endpoint, this.config);

  final MemoryQuicNetwork network;
  final MemoryQuicEndConfig config;
  final StreamController<QuicSession> _sessions = StreamController();

  void acceptSession(QuicSession session) => _sessions.add(session);
  bool _closed = false;

  @override
  final Uri endpoint;

  @override
  Stream<QuicSession> get sessions => _sessions.stream;

  @override
  Future<void> close() async {
    _closed = true;
    network._listeners.remove(MemoryQuicNetwork._key(endpoint));
    await _sessions.close();
  }
}

/// One end of a memory session.
class MemoryQuicSession implements QuicSession {
  MemoryQuicSession._(
    this.network,
    this.isInitiator,
    this.config,
    this._secret,
    this._certificateHash,
  ) {
    _incoming = StreamController<QuicStream>();
  }

  /// A connected pair: the initiator's end and the acceptor's.
  static (MemoryQuicSession, MemoryQuicSession) pair({
    MemoryQuicNetwork? network,
    MemoryQuicEndConfig initiator = const MemoryQuicEndConfig(),
    MemoryQuicEndConfig acceptor = const MemoryQuicEndConfig(),
    Uint8List? certificateHash,
  }) {
    final net = network ?? MemoryQuicNetwork();
    final secret = Uint8List.fromList(
      List.generate(32, (_) => _random.nextInt(256)),
    );
    final a = MemoryQuicSession._(
      net,
      true,
      initiator,
      secret,
      certificateHash,
    );
    final b = MemoryQuicSession._(net, false, acceptor, secret, null);
    a.peer = b;
    b.peer = a;
    net.pairs.add((a, b));
    return (a, b);
  }

  static final Random _random = Random(1234);

  final MemoryQuicNetwork network;

  @override
  final bool isInitiator;

  /// What this end grants its peer.
  final MemoryQuicEndConfig config;

  final Uint8List _secret;
  final Uint8List? _certificateHash;

  late final MemoryQuicSession peer;
  late final StreamController<QuicStream> _incoming;
  final Completer<void> _draining = Completer<void>();
  final StreamController<QuicReceiveStream> _unidirectional =
      StreamController();

  @override
  Future<void> get draining => _draining.future;

  @override
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams =>
      _unidirectional.stream;

  void drainPeer() {
    if (!peer._draining.isCompleted) peer._draining.complete();
  }

  MemoryQuicReceiveStream openUnidirectional() {
    final stream = MemoryQuicReceiveStream();
    peer._unidirectional.add(stream);
    return stream;
  }

  final Completer<QuicSessionEnd> _done = Completer<QuicSessionEnd>();
  final Queue<Completer<void>> _streamWaiters = Queue<Completer<void>>();
  final Set<_Direction> _blocked = {};

  /// Streams of this end, opened by either side, in order.
  final List<MemoryQuicStream> streams = [];

  /// The ordinals of the streams the peer opened, in the order they
  /// became visible here.
  final List<int> announced = [];

  /// Streams this end opened that its peer has not released yet.
  int _openStreams = 0;
  int _connectionSent = 0;
  int _connectionConsumed = 0;
  int _ordinal = 0;

  /// Application closes this end made: (code, reason).
  final List<(int, String)> closes = [];

  bool get ended => _done.isCompleted;

  @override
  String? get protocol => 'switchboard';

  @override
  String get remote => isInitiator ? 'memory acceptor' : 'memory initiator';

  @override
  int? get maxIncomingStreams => config.maxStreams;

  @override
  Uint8List? get peerCertificateHash => _certificateHash;

  @override
  Stream<QuicStream> get incomingStreams => _incoming.stream;

  @override
  Future<QuicSessionEnd> get done => _done.future;

  /// The labels the exporter was asked for.
  final List<String> exporterLabels = [];
  int exporterXor = 0;
  Object? exporterFailure;
  Completer<void>? exporterGate;
  Object? openFailure;
  void failIncoming(Object error) => _incoming.addError(error);

  @override
  Future<Uint8List?> exportKeyingMaterial(
    String label,
    Uint8List context,
    int length,
  ) async {
    exporterLabels.add(label);
    await exporterGate?.future;
    final failure = exporterFailure;
    if (failure != null) throw failure;
    if (!config.exporter) {
      return null;
    }
    final mix = utf8.encode(label) + context;
    var h = 0x811C9DC5;
    for (final b in mix) {
      h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF;
    }
    return Uint8List.fromList(
      List.generate(
        length,
        (i) =>
            _secret[i % _secret.length] ^
            ((h >> ((i % 4) * 8)) & 0xFF) ^
            i ^
            exporterXor,
      ),
    );
  }

  @override
  Future<QuicStream> openStream() async {
    final failure = openFailure;
    if (failure != null) throw failure;
    if (ended) {
      throw const QuicException(
        QuicExceptionKind.sessionEnded,
        'session ended',
      );
    }
    while (_openStreams >= peer.config.maxStreams) {
      final waiter = Completer<void>();
      _streamWaiters.add(waiter);
      await waiter.future;
      if (ended) {
        throw const QuicException(
          QuicExceptionKind.sessionEnded,
          'session ended',
        );
      }
    }
    _openStreams++;
    final info = MemoryQuicStreamInfo(
      _nextOrdinal(),
      openedByInitiator: isInitiator,
    );
    final shared = _Shared(this);
    final local = MemoryQuicStream._(this, info, locallyOpened: true);
    final remote = MemoryQuicStream._(peer, info, locallyOpened: false);
    final out = _Direction(this, peer, info, local, remote, shared);
    final back = _Direction(peer, this, info, remote, local, shared);
    local
      .._out = out
      .._in = back;
    remote
      .._out = back
      .._in = out;
    streams.add(local);
    return local;
  }

  int _nextOrdinal() {
    final ordinal = _ordinal;
    _ordinal = peer._ordinal = ordinal + 1;
    return ordinal;
  }

  /// The peer's stream became visible to it (its first bytes, FIN or
  /// reset arrived).
  void _announce(MemoryQuicStream stream) {
    if (stream._announced || ended) {
      return;
    }
    stream._announced = true;
    streams.add(stream);
    announced.add(stream.info.ordinal);
    _incoming.add(stream);
  }

  /// A stream this end opened is released by the peer: credit for another.
  void _streamReleased() {
    _openStreams--;
    if (_streamWaiters.isNotEmpty) {
      _streamWaiters.removeFirst().complete();
    }
  }

  int get _connectionCredit =>
      peer.config.connectionWindow - (_connectionSent - _connectionConsumed);

  void _retryBlocked() {
    final blocked = List.of(_blocked);
    _blocked.clear();
    for (final direction in blocked) {
      direction._pump();
    }
  }

  @override
  Future<void> close(int code, String reason) async {
    if (ended) {
      return;
    }
    reason = _truncate(reason, 1024);
    closes.add((code, reason));
    _end(QuicSessionEnd.closed(code, reason, byPeer: false));
    final other = peer;
    Timer(network.closeDelay, () {
      other._end(QuicSessionEnd.closed(code, reason, byPeer: true));
    });
  }

  /// Both ends lose the session (a QUIC error, the idle timeout).
  void lose([String reason = 'lost']) {
    _end(QuicSessionEnd.lost(reason));
    peer._end(QuicSessionEnd.lost(reason));
  }

  void _end(QuicSessionEnd end) {
    if (ended) {
      return;
    }
    _done.complete(end);
    for (final stream in streams) {
      stream._sessionEnded();
    }
    final waiters = List.of(_streamWaiters);
    _streamWaiters.clear();
    for (final waiter in waiters) {
      waiter.complete();
    }
    unawaited(_incoming.close());
    unawaited(_unidirectional.close());
  }

  @override
  String toString() =>
      'MemoryQuicSession(${isInitiator ? 'initiator' : 'acceptor'})';
}

/// What the two directions of a stream share: the opener's stream credit
/// returns once both closed at their receivers.
class _Shared {
  _Shared(this.opener);

  final MemoryQuicSession opener;
  int closed = 0;

  void directionClosed() {
    if (++closed == 2) {
      opener._streamReleased();
    }
  }
}

/// One direction of a stream: what [from] writes and [to] reads.
class _Direction {
  _Direction(
    this.from,
    this.to,
    this.info,
    this.sender,
    this.receiver,
    this.shared,
  ) : window = to.config.streamWindow {
    stopped.future.ignore();
    resetReceived.future.ignore();
  }

  final _Shared shared;
  final MemoryQuicSession from;
  final MemoryQuicSession to;
  final MemoryQuicStreamInfo info;
  final MemoryQuicStream sender;
  final MemoryQuicStream receiver;
  final int window;

  static const QuicException _ended = QuicException(
    QuicExceptionKind.sessionEnded,
    'session ended',
  );

  // Sender side: writes queued in order, the head sent as the windows
  // allow.
  int sent = 0;
  int consumed = 0;
  final Queue<(Uint8List, Completer<void>)> _writes =
      Queue<(Uint8List, Completer<void>)>();
  int _writeOffset = 0;
  bool finished = false;
  Completer<void>? _finish;
  bool resetSent = false;
  int? stopCode;
  bool stopReceived = false;
  final Completer<int?> stopped = Completer<int?>();
  final Completer<int?> resetReceived = Completer<int?>();

  // Receiver side.
  final Queue<Uint8List> buffer = Queue<Uint8List>();
  bool fin = false;
  bool finRead = false;
  bool reset = false;
  int? resetCode;
  // This side stopped its read direction (STOP_SENDING) with [stopSentCode].
  bool stopSent = false;
  int? stopSentCode;
  Completer<Uint8List?>? _read;
  int _readMax = 0;
  bool closedAtReceiver = false;

  // Delivery, in order.
  final Queue<(int, void Function())> _events = Queue<(int, void Function())>();
  Timer? _timer;
  static final Stopwatch _clock = Stopwatch()..start();

  Duration get _delay =>
      from.network.delay(info, fromInitiator: from.isInitiator);

  /// Runs [event] on the receiver's side after the delay, in order.
  void _post(void Function() event) {
    final now = _clock.elapsedMicroseconds;
    var due = now + _delay.inMicroseconds;
    if (_events.isNotEmpty && _events.last.$1 > due) {
      due = _events.last.$1;
    }
    _events.add((due, event));
    _arm();
  }

  void _arm() {
    if (_timer != null || _events.isEmpty) {
      return;
    }
    final wait = _events.first.$1 - _clock.elapsedMicroseconds;
    _timer = Timer(Duration(microseconds: wait < 0 ? 0 : wait), () {
      _timer = null;
      final now = _clock.elapsedMicroseconds;
      while (_events.isNotEmpty && _events.first.$1 <= now) {
        if (to.ended || from.ended) {
          _events.clear();
          return;
        }
        _events.removeFirst().$2();
      }
      _arm();
    });
  }

  // Writing ---------------------------------------------------------------

  Future<void> write(Uint8List bytes) {
    if (from.ended) {
      return Future.error(_ended);
    }
    if (stopReceived) {
      return Future.error(QuicStreamStopped(stopCode));
    }
    if (finished || resetSent) {
      return Future.error(StateError('the direction has ended'));
    }
    final completer = Completer<void>();
    _writes.add((Uint8List.fromList(bytes), completer));
    _pump();
    return completer.future;
  }

  /// Sends what the windows allow of the queued writes.
  void _pump() {
    while (_writes.isNotEmpty) {
      if (from.ended || resetSent || stopReceived) {
        return;
      }
      final (data, completer) = _writes.first;
      while (_writeOffset < data.length) {
        final streamCredit = window - (sent - consumed);
        final connectionCredit = from._connectionCredit;
        var n = data.length - _writeOffset;
        if (streamCredit < n) {
          n = streamCredit;
        }
        if (connectionCredit < n) {
          n = connectionCredit;
        }
        if (n <= 0) {
          if (connectionCredit <= 0) {
            from._blocked.add(this);
          }
          return;
        }
        final chunk = Uint8List.sublistView(
          data,
          _writeOffset,
          _writeOffset + n,
        );
        _writeOffset += n;
        sent += n;
        from._connectionSent += n;
        _post(() => _receive(chunk));
      }
      _writes.removeFirst();
      _writeOffset = 0;
      completer.complete();
    }
    _postFin();
  }

  /// Fails the writes still queued with [error].
  void _failWrites(Object error) {
    final writes = List.of(_writes);
    _writes.clear();
    _writeOffset = 0;
    for (final (_, completer) in writes) {
      completer.completeError(error);
    }
  }

  Future<void> finish() {
    if (from.ended) {
      return Future.error(_ended);
    }
    if (stopReceived) {
      return Future.error(QuicStreamStopped(stopCode));
    }
    if (resetSent) {
      return Future.error(StateError('the direction was reset'));
    }
    if (!finished) {
      finished = true;
      _finish = Completer<void>()..future.ignore();
      _finished = _finish!.future;
      _postFin();
    }
    return _finished!;
  }

  Future<void>? _finished;

  /// FIN goes once every queued write went.
  void _postFin() {
    final finish = _finish;
    if (!finished || _writes.isNotEmpty || finish == null) {
      return;
    }
    _finish = null;
    _post(_receiveFin);
    finish.complete();
  }

  void resetDirection(int? code) {
    if (resetSent || from.ended) {
      return;
    }
    if (finished && fin) {
      // Everything arrived already: the direction has ended.
      return;
    }
    resetSent = true;
    _failWrites(StateError('reset'));
    final finish = _finish;
    _finish = null;
    finish?.completeError(StateError('reset'));
    if (!stopped.isCompleted) {
      stopped.complete(null);
    }
    _post(() => _receiveReset(code));
  }

  // Receiving -------------------------------------------------------------

  void _receive(Uint8List chunk) {
    to._announce(receiver);
    if (reset) {
      // Discarded: credit back at once.
      _credit(chunk.length);
      return;
    }
    if (stopSent) {
      // Discarded; a stopped stream gets no more stream credit (the
      // sender is to stop), only the connection's.
      _creditConnection(chunk.length);
      return;
    }
    buffer.add(chunk);
    _serveRead();
  }

  void _receiveFin() {
    to._announce(receiver);
    fin = true;
    if (!stopped.isCompleted) {
      // Acknowledged.
      stopped.complete(null);
    }
    _serveRead();
    _checkClosed();
  }

  void _receiveReset(int? code) {
    to._announce(receiver);
    if (reset) {
      return;
    }
    reset = true;
    resetCode = code;
    if (!resetReceived.isCompleted) resetReceived.complete(code);
    var dropped = 0;
    for (final chunk in buffer) {
      dropped += chunk.length;
    }
    buffer.clear();
    if (dropped > 0) {
      _credit(dropped);
    }
    if (!stopSent) {
      final read = _read;
      _read = null;
      read?.completeError(QuicStreamReset(code));
    }
    _checkClosed();
  }

  Future<Uint8List?> read(int max) {
    if (to.ended) {
      return Future.error(_ended);
    }
    if (_read != null) {
      return Future.error(StateError('a read is pending'));
    }
    if (max <= 0) {
      return Future.error(ArgumentError.value(max, 'max'));
    }
    if (stopSent) {
      return Future.error(QuicStreamReset(stopSentCode));
    }
    final completer = _read = Completer<Uint8List?>();
    _readMax = max;
    _serveRead();
    return completer.future;
  }

  void _serveRead() {
    final read = _read;
    if (read == null) {
      return;
    }
    if (buffer.isNotEmpty) {
      final head = buffer.first;
      Uint8List out;
      if (head.length <= _readMax) {
        out = buffer.removeFirst();
      } else {
        out = Uint8List.fromList(Uint8List.sublistView(head, 0, _readMax));
        buffer
          ..removeFirst()
          ..addFirst(Uint8List.sublistView(head, _readMax));
      }
      _read = null;
      _credit(out.length);
      read.complete(out);
      return;
    }
    if (reset) {
      _read = null;
      read.completeError(QuicStreamReset(resetCode));
      return;
    }
    if (fin) {
      _read = null;
      finRead = true;
      read.complete(null);
      _checkClosed();
    }
  }

  /// The receiver consumed [n] bytes: window back to the sender.
  void _credit(int n) {
    scheduleMicrotask(() {
      consumed += n;
      from._connectionConsumed += n;
      _pump();
      from._retryBlocked();
    });
  }

  /// The receiver discarded [n] bytes of a direction it stopped: window
  /// back to the connection only.
  void _creditConnection(int n) {
    scheduleMicrotask(() {
      from._connectionConsumed += n;
      from._retryBlocked();
    });
  }

  /// This side's read direction ends at once: a pending read and every
  /// later one fail with a reset of [code]; STOP_SENDING goes to the
  /// sender, whose confirming reset is not observable here.
  void stop(int? code) {
    if (stopSent || reset || finRead || to.ended) {
      return;
    }
    stopSent = true;
    stopSentCode = code;
    var dropped = 0;
    for (final chunk in buffer) {
      dropped += chunk.length;
    }
    buffer.clear();
    if (dropped > 0) {
      // As a QUIC stack: no stream credit for a direction it stopped, so
      // a write stalled at the window fails with the STOP_SENDING rather
      // than completing first.
      _creditConnection(dropped);
    }
    final read = _read;
    _read = null;
    read?.completeError(QuicStreamReset(code));
    // STOP_SENDING travels back to the sender.
    final back = receiver._out!;
    back._post(() => _receiveStop(code));
    _checkClosed();
  }

  /// On the sender's side: the peer asked it to stop.
  void _receiveStop(int? code) {
    if (stopReceived) {
      return;
    }
    stopReceived = true;
    stopCode = code;
    _failWrites(QuicStreamStopped(code));
    final finish = _finish;
    _finish = null;
    finish?.completeError(QuicStreamStopped(code));
    if (!stopped.isCompleted) {
      if (code == null) {
        stopped.completeError(const QuicStreamStopped(null));
      } else {
        stopped.complete(code);
      }
    }
    // The stack answers with a reset of the same code, unless everything
    // arrived already.
    if (!resetSent && !(finished && fin)) {
      resetSent = true;
      _post(() => _receiveReset(code));
    }
  }

  void _checkClosed() {
    if (closedAtReceiver) {
      return;
    }
    if (reset || (fin && (finRead || stopSent)) || (stopSent && resetSent)) {
      closedAtReceiver = true;
      shared.directionClosed();
    }
  }

  /// The sender's session ended: what it has pending fails.
  void senderEnded() {
    _timer?.cancel();
    _timer = null;
    _events.clear();
    _failWrites(_ended);
    final finish = _finish;
    _finish = null;
    finish?.completeError(_ended);
    if (!stopped.isCompleted) {
      stopped.completeError(_ended);
    }
  }

  /// The receiver's session ended: its pending read fails.
  void receiverEnded() {
    if (!resetReceived.isCompleted) resetReceived.completeError(_ended);
    final read = _read;
    _read = null;
    read?.completeError(_ended);
  }
}

/// One end's view of a stream.
class MemoryQuicStream implements QuicStream {
  MemoryQuicStream._(this.session, this.info, {required this.locallyOpened})
    : _announced = locallyOpened;

  final MemoryQuicSession session;
  final MemoryQuicStreamInfo info;
  final bool locallyOpened;
  bool _announced;
  _Direction? _out;
  _Direction? _in;

  /// The last priority set.
  int lastPriority = 0;

  /// Codes of the resets and stops this end sent.
  final List<int> resets = [];
  final List<int> stops = [];

  /// Whether this end's direction ended with FIN.
  bool get finished => _out!.finished;

  @override
  Future<Uint8List?> read(int max) => _in!.read(max);

  Object? writeFailure;
  Object? finishFailure;

  void resetWithoutCode() => _out!.resetDirection(null);
  void stopWithoutCode() => _in!.stop(null);
  void failRead(Object error) {
    final reading = _in!._read;
    _in!._read = null;
    reading?.completeError(error);
  }

  @override
  Future<void> write(Uint8List bytes) =>
      writeFailure == null ? _out!.write(bytes) : Future.error(writeFailure!);

  @override
  Future<void> finish() =>
      finishFailure == null ? _out!.finish() : Future.error(finishFailure!);

  @override
  void reset(int code) {
    resets.add(code);
    _out!.resetDirection(code);
  }

  @override
  void stop(int code) {
    stops.add(code);
    _in!.stop(code);
  }

  @override
  set priority(int value) => lastPriority = value;

  @override
  Future<int?> get stopped => _out!.stopped.future;

  @override
  Future<int?> get resetReceived => _in!.resetReceived.future;

  void _sessionEnded() {
    _out?.senderEnded();
    _in?.receiverEnded();
  }

  @override
  String toString() =>
      'MemoryQuicStream(#${info.ordinal}, '
      '${locallyOpened ? 'local' : 'remote'})';
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

/// [text] cut to at most [max] bytes of UTF-8, at a character boundary.
String _truncate(String text, int max) {
  final bytes = utf8.encode(text);
  if (bytes.length <= max) {
    return text;
  }
  var cut = max;
  while (cut > 0 && bytes[cut] & 0xC0 == 0x80) {
    cut--;
  }
  return utf8.decode(bytes.sublist(0, cut));
}

/// A peer-created unidirectional receive direction.
class MemoryQuicReceiveStream implements QuicReceiveStream {
  final Completer<int> stopped = Completer<int>();
  @override
  void stop(int code) {
    if (!stopped.isCompleted) stopped.complete(code);
  }
}
