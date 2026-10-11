/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

/// The connection and channel of the QUIC and WebTransport binding (wiki
/// page "Polyverse Switchboard QUIC and WebTransport Binding"), written
/// against the stream provider contract (`quic_provider.dart`).
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:meta/meta.dart';
import 'package:switchboard/core.dart';

import '../provider/quic_provider.dart';
import 'exporter.dart';
import 'quic_options.dart';
import 'record_reader.dart';
import 'records.dart';

part 'quic_channel.dart';

final Logger _log = Logger('Switchboard.Quic');

/// The priority class of the control stream; see [QuicStream.priority].
const int quicControlPriority = 2;

/// The priority class of an ordinary channel's stream.
const int quicOrdinaryPriority = 1;

/// The priority class of a bulk channel's stream.
const int quicBulkPriority = 0;

/// A Switchboard connection over one QUIC connection or WebTransport
/// session ([QuicSession]): the connection contract of `MuxConnection`
/// carried by native streams, one per channel, as the binding page
/// specifies.
///
/// * Channels ([QuicChannel]): a bidirectional stream each, the opener's
///   direction starting with an OPEN record (`u48` channel id, then the
///   open payload); subframes travel as DATA records; each side ends its
///   direction with a CLOSE record and FIN, or a reset carrying the
///   status. Channel ids follow the mux's parity and reserved ids, are
///   allocated in increasing order and never reused.
/// * The control stream: the initiator's stream whose OPEN record names
///   channel 0, opened before any channel, on which both sides write
///   their control messages, each one a DATA record: `HELLO` first (the
///   record limit, the channels this side accepts, the `EXPORTER` flag),
///   then `PING`, `PONG`, `GOAWAY`, `NONCE` and `IDENT`; `LIMITS` and
///   `CREDIT` are protocol errors, QUIC's flow control and stream limits
///   taking their place.
/// * Identity: the `NONCE`/`IDENT` exchange, the proof bound to the TLS
///   exporter when both `HELLO`s carry `EXPORTER`, and the rules of
///   [QuicIdentityRules].
/// * The connection ends with an application close carrying the status
///   (0 after a graceful drain); a received one counts as a `GOAWAY` with
///   its status, any other end of the session is a lost connection.
///
/// [MuxOptions] apply as their documentation says for a stream binding;
/// [QuicBindingOptions] holds this binding's own. Start one with [start];
/// `QuicSwitchboardBinding` and `QuicSwitchboardListener` do for a
/// `Switchboard` node.
class QuicBindingConnection extends BindingConnection {
  QuicBindingConnection._(
    this.session,
    this.options,
    this.quicOptions,
    this._exporter, {
    required this.isWebTransport,
  }) : _nextId = session.isInitiator ? 2 : 3 {
    _incoming = StreamController<MuxChannel>(
      sync: true,
      onListen: _scheduleIncoming,
      onResume: _scheduleIncoming,
      onCancel: _cancelIncoming,
    );
    _controlReady.future.ignore();
    _mutualIdentification.future.ignore();
  }

  /// Starts the binding over [session], an established QUIC connection or
  /// WebTransport session ([isWebTransport]), and returns the connection
  /// once it can open channels: on the initiator, once the control stream
  /// is open, its OPEN record and `HELLO` written first.
  ///
  /// Asks the session for its exporter first (RFC 9266's
  /// `EXPORTER-Channel-Binding` on raw QUIC, the application label
  /// `switchboard-ident` over WebTransport), which decides the `EXPORTER`
  /// flag of this side's `HELLO`. [localIdentity] is set before anything
  /// from the peer is handled.
  ///
  /// Throws [ArgumentError] for a [QuicBindingOptions.recordLimit] outside
  /// [quicDefaultRecordLimit] to [quicMaxRecordLength]. A connection that
  /// ends while it starts (the session ended, or the identification rules
  /// refused it) is returned ended: its [done] has completed.
  static Future<QuicBindingConnection> start(
    QuicSession session, {
    MuxOptions options = const MuxOptions(),
    QuicBindingOptions quicOptions = const QuicBindingOptions(),
    bool isWebTransport = false,
    String? localIdentity,
  }) async {
    final limit = quicOptions.recordLimit;
    if (limit < quicDefaultRecordLimit || limit > quicMaxRecordLength) {
      throw ArgumentError.value(
        limit,
        'quicOptions.recordLimit',
        'must be $quicDefaultRecordLimit to $quicMaxRecordLength',
      );
    }
    if (quicOptions.maxPendingStreams < 1 ||
        quicOptions.controlOutputMark < 1 ||
        quicOptions.writeBatchBytes < 1 ||
        quicOptions.maxHeldControlMessages < 1 ||
        options.initialWindow < 1 ||
        options.initialWindow > 0xFFFFFFFF ||
        options.bulkChunkSize < 1) {
      throw ArgumentError('binding limits and windows must be positive');
    }
    Uint8List? exporter;
    Object? exporterFailure;
    try {
      final exporting = Future.any<Uint8List?>([
        session.exportKeyingMaterial(
          isWebTransport ? webTransportIdentLabel : rawQuicExporterLabel,
          Uint8List(0),
          quicExporterLength,
        ),
        session.done.then(
          (_) => throw const QuicException(
            QuicExceptionKind.sessionEnded,
            'session ended during export',
          ),
        ),
      ]);
      final timeout =
          quicOptions.controlStreamTimeout ??
          options.keepAliveInterval ??
          const Duration(seconds: 10);
      exporter = await (timeout > Duration.zero
          ? exporting.timeout(timeout)
          : exporting);
    } on Object catch (e) {
      exporterFailure = e;
      _log.fine('session exporter failed: $e');
    }
    if (exporter != null && exporter.length != quicExporterLength) {
      _log.warning(
        'the session exported ${exporter.length} bytes instead of '
        '$quicExporterLength',
      );
      exporterFailure = StateError('invalid exporter length');
      exporter = null;
    }
    final connection = QuicBindingConnection._(
      session,
      options,
      quicOptions,
      exporter == null ? null : Uint8List.fromList(exporter),
      isWebTransport: isWebTransport,
    )..localIdentity = localIdentity;
    connection._begin();
    if (exporterFailure != null && !isSessionEnd(exporterFailure)) {
      connection._fail(
        Status.of(StatusCode.internal, 'session exporter failed'),
      );
    }
    await connection._ready.future;
    return connection;
  }

  /// The QUIC connection or WebTransport session carrying this connection.
  final QuicSession session;

  /// Whether [session] is a WebTransport session rather than a raw QUIC
  /// connection: it decides how the exporter is asked for.
  final bool isWebTransport;

  @override
  final MuxOptions options;

  /// This binding's own options.
  final QuicBindingOptions quicOptions;

  @override
  bool get isInitiator => session.isInitiator;

  final Uint8List? _exporter;

  /// Whether this side can compute the exporter of the connection: the
  /// `EXPORTER` flag of its `HELLO`.
  bool get hasExporter => _exporter != null;

  // Channels.
  late final StreamController<MuxChannel> _incoming;
  final Map<int, QuicChannel> _channels = {};
  final Queue<QuicChannel> _undelivered = Queue<QuicChannel>();
  final Set<QuicChannel> _payloads = {};
  int _openPayloadBytes = 0;
  int _nextId;
  bool _incomingScheduled = false;
  bool _incomingCancelled = false;
  StreamSubscription<QuicStream>? _streams;
  final Set<QuicStream> _pendingStreams = {};
  StreamSubscription<QuicReceiveStream>? _unidirectional;

  // The control stream.
  QuicStream? _control;
  RecordReader? _controlReader;
  final Completer<void> _controlReady = Completer<void>();
  final Completer<void> _ready = Completer<void>();
  final Queue<Uint8List> _controlQueue = Queue<Uint8List>();
  int _controlQueued = 0;
  bool _controlWriting = false;
  Completer<void>? _controlDrained;
  Timer? _controlTimer;
  QuicHello? _peerHello;

  // The connection.
  final Completer<Status> _done = Completer<Status>();
  final Completer<Status> _peerGoAwayStatus = Completer<Status>();
  final List<_PendingPing> _pings = [];
  int _pingCounter = 0;
  bool _closing = false;
  bool _goAwaySent = false;
  Status? _ownGoAway;
  Status? _peerGoAway;
  Status? _peerGoAwayReceived;
  Status? _closeStatus;
  Future<void>? _closeFuture;
  Completer<void>? _idle;
  final Set<Future<void>> _finishing = {};

  // Keep-alive.
  Timer? _keepAliveTimer;
  final Stopwatch _sinceReceive = Stopwatch()..start();
  bool _probing = false;

  // Identity.
  Uint8List? _localNonce;
  Uint8List? _peerNonce;
  Completer<Uint8List>? _nonceWaiter;
  final Completer<void> _identityRequested = Completer<void>();
  PeerIdentity? _peerIdentity;
  bool _peerIdentityBound = false;
  final Completer<PeerIdentity> _peerIdentified = Completer<PeerIdentity>();
  Completer<PeerIdentity>? _boundIdentityWaiter;
  final Completer<void> _mutualIdentification = Completer<void>();
  Completer<void>? _identityEvent;
  bool _verifying = false;
  final Queue<MuxControlMessage> _heldControl = Queue<MuxControlMessage>();

  // The contract ------------------------------------------------------------

  @override
  Stream<MuxChannel> get incoming => _incoming.stream;

  @override
  Future<Status> get done => _done.future;

  @override
  bool get isOpen => !_closing && !_goAwaySent;

  @override
  bool get peerGoingAway => _peerGoAway != null;

  @override
  Future<Status> get peerGoAwayStatus => _peerGoAwayStatus.future;

  /// The channels the peer accepts at once, as its `HELLO` states them; 0
  /// before it arrives and when it states no limit. Advisory: the pool of
  /// a `Switchboard` opens a further connection once it is reached, and
  /// [open] beyond it waits for stream credit in the stack, which enforces
  /// the limit, instead of being refused.
  @override
  int get peerMaxChannels => _peerHello?.channels ?? 0;

  /// The peer's `HELLO`, null until it arrives.
  QuicHello? get peerHello => _peerHello;

  /// The largest record body the peer accepts on a channel's stream: its
  /// `HELLO`'s record limit, [quicDefaultRecordLimit] before it.
  int get peerRecordLimit => _peerHello?.recordLimit ?? quicDefaultRecordLimit;

  /// The record limit this side announced.
  int get recordLimit => quicOptions.recordLimit;

  /// Whether `IDENT` proofs on this connection are exporter-bound: this
  /// side can compute the exporter and the peer's `HELLO` says it can.
  bool get exporterBound =>
      _exporter != null && (_peerHello?.exporter ?? false);

  /// Whether the peer's current identity ([peerIdentity]) was proven with
  /// an exporter-bound `IDENT`.
  bool get peerIdentityBound => peerIdentity != null && _peerIdentityBound;

  /// Whether the other end of this connection is authenticated: by the TLS
  /// handshake ([QuicIdentityRules.tlsAuthenticatesPeer]), or by its
  /// exporter-bound `IDENT` ([peerIdentityBound]). A credential in a
  /// channel's application payload, which carries no proof bound to the
  /// connection, goes only to an authenticated end.
  bool get peerAuthenticated =>
      quicOptions.identity.tlsAuthenticatesPeer || peerIdentityBound;

  @override
  int get openChannelCount => _channels.length;

  @override
  int get openPayloadBytes => _openPayloadBytes;

  @override
  int get heldOutputBytes => _closing ? 0 : _controlQueued;

  /// What the channels hold for their listeners, plus the open payloads
  /// held for the channels the peer opened.
  @override
  int get bufferedBytes => super.bufferedBytes + _openPayloadBytes;

  @override
  MuxChannel? channelWithId(int id) => _channels[id];

  @override
  Iterable<MuxChannel> get channels => List.of(_channels.values);

  @override
  PeerIdentity? get peerIdentity {
    final identity = _peerIdentity;
    return identity == null || identity.isExpired() ? null : identity;
  }

  @override
  Future<PeerIdentity> get peerIdentified => _peerIdentified.future;

  @override
  Future<void> get identityRequested => _identityRequested.future;

  @override
  Future<void> get identityChanged =>
      (_identityEvent ??= Completer<void>()).future;

  /// Sets the next channel id this side allocates, which must be of its
  /// parity and above the ids it used: ids are never reused here. For
  /// tests of the reserved ids and of the end of the id space.
  @override
  @visibleForTesting
  set nextChannelIdForTesting(int id) {
    if (id.isOdd == isInitiator || id < _nextId || id > quicMaxChannelId) {
      throw ArgumentError.value(id, 'id', 'not an unused id of this side');
    }
    _nextId = id;
  }

  // Starting ----------------------------------------------------------------

  void _begin() {
    session.done
        .then(
          _onSessionEnd,
          onError: (Object e) {
            _onSessionEnd(QuicSessionEnd.lost('$e'));
          },
        )
        .ignore();
    _streams = session.incomingStreams.listen(
      _onIncomingStream,
      onError: (Object e) {
        if (!isSessionEnd(e)) _lost('incoming streams failed');
      },
    );
    session.draining.then((_) {
      if (!_closing) _onPeerGoAway(Status.of(StatusCode.goingAway));
    }).ignore();
    _unidirectional = session.incomingUnidirectionalStreams.listen(
      (stream) => _guarded(() => stream.stop(StatusCode.unsupported.code)),
      onError: (Object e) {
        if (!isSessionEnd(e)) _lost('incoming unidirectional streams failed');
      },
    );
    final timeout =
        quicOptions.controlStreamTimeout ??
        options.keepAliveInterval ??
        const Duration(seconds: 10);
    if (timeout > Duration.zero) {
      _controlTimer = Timer(timeout, () {
        if (_peerHello == null && !_closing) {
          _protocolError('no control HELLO within $timeout');
        }
      });
    }
    if (session.protocol != null && session.protocol != 'switchboard') {
      _fail(Status.of(StatusCode.unsupported, 'unsupported session protocol'));
      return;
    }
    final rules = quicOptions.identity;
    if (isInitiator) {
      if (rules.requireExporterBinding && _exporter == null) {
        _log.info(
          '$this: the stack cannot compute the exporter, which this side '
          'requires',
        );
        _fail(_unauthenticated);
        return;
      }
      if (rules.awaitPeerIdentity && options.identityVerifier == null) {
        // The acceptor's IDENT could never verify: nothing would open.
        _log.warning(
          '$this: awaiting the peer\'s identity needs '
          'MuxOptions.identityVerifier',
        );
        _fail(_unauthenticated);
        return;
      }
      _openControl().catchError((Object e) {
        if (!isSessionEnd(e)) _lost('control stream setup failed');
      }).ignore();
    } else {
      _ready.complete();
    }
    _startKeepAlive();
  }

  /// This side's `HELLO`.
  QuicHello _hello() {
    var channels = options.maxChannels > 0 ? options.maxChannels : 0;
    final streams = session.maxIncomingStreams;
    if (streams != null) {
      // The acceptor's stream limit counts the control stream.
      final usable = isInitiator ? streams : streams - 1;
      if (usable > 0 && (channels == 0 || usable < channels)) {
        channels = usable;
      }
    }
    return QuicHello(
      recordLimit: quicOptions.recordLimit,
      channels: channels > 0xFFFFFFFF ? 0xFFFFFFFF : channels,
      exporter: _exporter != null,
    );
  }

  /// Initiator: opens the control stream, its OPEN record and `HELLO` in
  /// the first flight.
  Future<void> _openControl() async {
    final QuicStream stream;
    try {
      stream = await session.openStream();
    } on Object catch (e) {
      _log.fine('$this: cannot open the control stream: $e');
      if (!isSessionEnd(e)) _lost('cannot open the control stream');
      if (!_ready.isCompleted) {
        _ready.complete();
      }
      return;
    }
    if (_closing) {
      stream
        ..stop(StatusCode.cancelled.code)
        ..reset(StatusCode.cancelled.code);
      if (!_ready.isCompleted) {
        _ready.complete();
      }
      return;
    }
    stream.priority = quicControlPriority;
    final hello = encodeDataRecord(_hello().toControlMessage().encode());
    final open = encodeOpenRecord(quicControlChannelId, const []);
    _controlQueue
      ..addFirst(hello)
      ..addFirst(open);
    _controlQueued += hello.length + open.length;
    _attachControl(stream, RecordReader(stream));
    if (!_ready.isCompleted) {
      _ready.complete();
    }
  }

  /// Acceptor: the stream whose OPEN record names channel 0 arrived.
  void _onControlStream(QuicStream stream, RecordReader reader) {
    stream.priority = quicControlPriority;
    final hello = encodeDataRecord(_hello().toControlMessage().encode());
    _controlQueue.addFirst(hello);
    _controlQueued += hello.length;
    _attachControl(stream, reader);
  }

  void _attachControl(QuicStream stream, RecordReader reader) {
    _control = stream;
    _controlReader = reader;
    stream.resetReceived
        .then(
          (_) {
            if (!_closing) _protocolError('the control stream was reset');
          },
          onError: (Object e) {
            if (!isSessionEnd(e) && !_closing) {
              _lost('control reset notification failed');
            }
          },
        )
        .ignore();
    stream.stopped
        .then(
          (code) {
            // Never finished, so only a STOP_SENDING completes it with a code.
            if (code != null && !_closing) {
              _protocolError('STOP_SENDING on the control stream');
            }
          },
          onError: (Object e) {
            if (e is QuicStreamStopped && !_closing) {
              _protocolError('STOP_SENDING on the control stream');
            } else if (!isSessionEnd(e) && !_closing) {
              _lost('control stream acknowledgement failed');
            }
          },
        )
        .ignore();
    _pumpControl();
    if (!_controlReady.isCompleted) {
      _controlReady.complete();
    }
    unawaited(_readControl());
  }

  // The control stream -------------------------------------------------------

  /// Queues [message] on the control stream; written once it exists.
  void _sendControl(MuxControlMessage message) {
    if (_closing) {
      return;
    }
    final record = encodeDataRecord(message.encode());
    // Reading-driven replies may overshoot the soft mark by one record.
    // Local callers (PING/IDENT) must not bypass the bound indefinitely.
    if (_controlQueued + record.length >
        quicOptions.controlOutputMark +
            1 +
            maxControlPayloadLength +
            quicRecordHeaderSize) {
      _fail(Status.of(StatusCode.resourceExhausted, 'control output full'));
      return;
    }
    _controlQueue.add(record);
    _controlQueued += record.length;
    _pumpControl();
  }

  void _pumpControl() {
    final stream = _control;
    if (stream == null ||
        _controlWriting ||
        _controlQueue.isEmpty ||
        _closing) {
      return;
    }
    _controlWriting = true;
    final batch = BytesBuilder(copy: false);
    while (_controlQueue.isNotEmpty) {
      batch.add(_controlQueue.removeFirst());
    }
    final bytes = batch.takeBytes();
    Future<void>.sync(() => stream.write(bytes))
        .then(
          (_) {
            _controlWriting = false;
            _controlQueued -= bytes.length;
            if (_controlQueued <= quicOptions.controlOutputMark) {
              final drained = _controlDrained;
              _controlDrained = null;
              drained?.complete();
            }
            _pumpControl();
          },
          onError: (Object e) {
            _controlWriting = false;
            if (e is QuicStreamStopped) {
              _protocolError('STOP_SENDING on the control stream');
            } else if (!isSessionEnd(e)) {
              _log.warning('$this: control stream write failed: $e');
              _lost('control stream write failed');
            }
          },
        )
        .catchError((Object e, StackTrace st) {
          _log.severe('$this: after a control stream write', e, st);
        });
  }

  Future<void> _readControl() async {
    final reader = _controlReader!;
    while (!_closing) {
      if (_controlQueued > quicOptions.controlOutputMark) {
        // Our own control output backs up: a peer that does not read
        // cannot make the answers to what it sends pile up.
        await (_controlDrained ??= Completer<void>()).future;
        continue;
      }
      final QuicRecord? record;
      try {
        record = await reader.next(limit: 1 + maxControlPayloadLength);
      } on RecordTooLarge catch (e) {
        _protocolError('control message of ${e.length} bytes');
        return;
      } on ProtocolException catch (e) {
        _fail(e.status);
        return;
      } on QuicStreamReset {
        _protocolError('the control stream was reset');
        return;
      } on QuicException catch (e) {
        if (!isSessionEnd(e)) {
          _log.warning('$this: reading the control stream: $e');
          _lost('the control stream failed');
        }
        return;
      } on Object catch (e, st) {
        _log.severe('$this: reading the control stream', e, st);
        _fail(Status.of(StatusCode.internal, 'internal error'));
        return;
      }
      if (_closing) {
        return;
      }
      if (record == null) {
        _protocolError('FIN on the control stream');
        return;
      }
      _noteReceive();
      switch (record.command) {
        case QuicRecordCommand.data:
          _guarded(() => _onControlRecord(record!.body));
        case QuicRecordCommand.open:
          _protocolError('a second OPEN record on the control stream');
          return;
        case QuicRecordCommand.close:
          _protocolError('a CLOSE record on the control stream');
          return;
      }
    }
  }

  /// Runs [action], ending the connection on a protocol error.
  void _guarded(void Function() action) {
    try {
      action();
    } on SwitchboardException catch (e) {
      _fail(e.status);
    } on Object catch (e, st) {
      _log.severe('$this: internal error', e, st);
      _fail(Status.of(StatusCode.internal, 'internal error'));
    }
  }

  void _onControlRecord(Uint8List body) {
    if (body.isEmpty) {
      throw ProtocolException('empty control record');
    }
    final message = MuxControlMessage.decode(body);
    if (_verifying) {
      // Handled once the IDENT being verified has taken effect.
      if (_heldControl.length >= quicOptions.maxHeldControlMessages) {
        _fail(
          Status.of(
            StatusCode.resourceExhausted,
            'too many control messages during an identification',
          ),
        );
        return;
      }
      _heldControl.add(message);
      return;
    }
    _handleControl(message);
  }

  void _handleControl(MuxControlMessage message) {
    if (_peerHello == null) {
      if (message.type != quicHelloType) {
        throw ProtocolException('control message ${message.type} before HELLO');
      }
      _onHello(QuicHello.decode(message.payload));
      return;
    }
    if (message.type == quicHelloType) {
      throw ProtocolException('second HELLO');
    }
    switch (message.knownType) {
      case MuxControlType.ping:
        _sendControl(MuxControlMessage.pong(message.payload));
      case MuxControlType.pong:
        _completePing(message.payload);
      case MuxControlType.goAway:
        _onPeerGoAway(statusFromWire(message.goAwayStatus));
      case MuxControlType.limits:
        throw ProtocolException('LIMITS over the QUIC binding');
      case MuxControlType.nonce:
        _onPeerNonce(message.payload);
      case MuxControlType.ident:
        _onIdent(message.payload);
      case MuxControlType.credit:
        throw ProtocolException('CREDIT over the QUIC binding');
      case null:
        _log.fine('$this: ignoring control type ${message.type}');
    }
  }

  void _onHello(QuicHello hello) {
    _controlTimer?.cancel();
    _controlTimer = null;
    _peerHello = hello;
    _log.fine('$this: peer $hello');
    final rules = quicOptions.identity;
    if (isInitiator && rules.requireExporterBinding && !exporterBound) {
      _log.info(
        '$this: the peer\'s HELLO lacks EXPORTER, which this side requires',
      );
      _fail(_unauthenticated);
      return;
    }
    // The largest subframe may have grown.
    for (final channel in List.of(_channels.values)) {
      channel._wakeWritable();
    }
  }

  void _onPeerGoAway(Status status) {
    if (_peerGoAway != null) {
      return;
    }
    _log.fine('$this: peer sent GOAWAY $status');
    _peerGoAwayReceived = status;
    _peerGoAway = status.known == StatusCode.goingAway
        ? status
        : Status.of(StatusCode.goingAway, status.toString());
    _peerGoAwayStatus.complete(status);
    Timer.run(_checkIdle);
  }

  // Incoming streams ----------------------------------------------------------

  Future<void> _onIncomingStream(QuicStream stream) async {
    if (_pendingStreams.length >= quicOptions.maxPendingStreams) {
      _release(stream, StatusCode.resourceExhausted.code);
      return;
    }
    _pendingStreams.add(stream);
    try {
      await _readOpen(stream);
    } finally {
      _pendingStreams.remove(stream);
      Timer.run(_checkIdle);
    }
  }

  Future<void> _readOpen(QuicStream stream) async {
    if (_closing) {
      _release(stream, StatusCode.goingAway.code);
      return;
    }
    final reader = RecordReader(stream);
    final QuicRecord? first;
    try {
      final reading = reader.next(limit: quicOptions.recordLimit);
      final timeout = quicOptions.openStreamTimeout;
      first = await (timeout > Duration.zero
          ? reading.timeout(timeout)
          : reading);
    } on TimeoutException {
      _release(stream, StatusCode.deadlineExceeded.code);
      return;
    } on QuicStreamReset {
      // Its opener gave it up before the OPEN record was complete.
      _release(stream, StatusCode.cancelled.code);
      return;
    } on RecordTooLarge catch (e) {
      _fail(
        Status.of(
          StatusCode.frameTooLarge,
          'OPEN record of ${e.length} bytes, limit ${e.limit}',
        ),
      );
      return;
    } on ProtocolException catch (e) {
      _fail(e.status);
      return;
    } on QuicException catch (e) {
      if (!isSessionEnd(e)) {
        _log.fine('$this: a stream failed before its OPEN record: $e');
        _release(stream, StatusCode.internal.code);
      }
      return;
    } on Object catch (e, st) {
      _log.severe('$this: reading an OPEN record', e, st);
      _fail(Status.of(StatusCode.internal, 'internal error'));
      return;
    }
    if (_closing) {
      _release(stream, StatusCode.goingAway.code);
      return;
    }
    if (first == null) {
      _protocolError('FIN before the OPEN record');
      return;
    }
    if (first.command != QuicRecordCommand.open) {
      _protocolError('a stream whose first record is ${first.command.name}');
      return;
    }
    _noteReceive();
    _guarded(() => _onOpen(stream, reader, first!.body));
  }

  /// Stops and resets [stream], which carries no channel.
  void _release(QuicStream stream, int code) {
    try {
      stream
        ..stop(code)
        ..reset(code);
    } on Object catch (e) {
      _log.fine('$this: releasing a stream: $e');
    }
  }

  void _onOpen(QuicStream stream, RecordReader reader, Uint8List body) {
    final (id, payload) = decodeOpenBody(body);
    if (id == quicControlChannelId) {
      if (isInitiator) {
        throw ProtocolException('channel 0 on a stream the acceptor opened');
      }
      if (_control != null) {
        throw ProtocolException('a second control stream');
      }
      if (payload.isNotEmpty) {
        throw ProtocolException('control OPEN has a payload');
      }
      _onControlStream(stream, reader);
      return;
    }
    if (MuxFrame.isReservedId(id)) {
      throw ProtocolException('OPEN of the reserved channel $id');
    }
    // The peer allocates odd ids if this side is the initiator.
    if (id.isOdd != isInitiator) {
      throw ProtocolException('OPEN of channel $id, of the wrong parity');
    }
    if (_channels.containsKey(id)) {
      throw ProtocolException('OPEN of channel $id, which is open');
    }
    final rejection = _admission(payload);
    if (rejection != null) {
      _reject(stream, id, rejection);
      return;
    }
    final channel = QuicChannel._(
      this,
      id,
      isLocallyOpened: false,
      openPayload: Uint8List.fromList(payload),
    );
    _channels[id] = channel;
    _payloads.add(channel);
    _openPayloadBytes += payload.length;
    _undelivered.add(channel);
    channel._attach(stream, reader, openWritten: true);
    _scheduleIncoming();
  }

  /// Why the peer's channel with [openPayload] is refused, or null.
  Status? _admission(Uint8List openPayload) {
    if (_goAwaySent && !_continuesOpenChannel(openPayload)) {
      return Status.of(StatusCode.goingAway);
    }
    if (_incomingCancelled) {
      return Status.of(StatusCode.unavailable, 'not accepting channels');
    }
    final max = options.maxChannels;
    if (max > 0 && (_channels.length >= max || _undelivered.length >= max)) {
      return Status.of(StatusCode.resourceExhausted, 'at most $max channels');
    }
    final budget = _openPayloadBudget;
    if (budget != null && _openPayloadBytes + openPayload.length > budget) {
      return Status.of(
        StatusCode.resourceExhausted,
        'open payloads exceed $budget bytes',
      );
    }
    return null;
  }

  /// [MuxOptions.maxOpenPayloadBytes], within half of
  /// [MuxOptions.receiveHighWaterMarkBytes] as on the frame mux; null for
  /// none.
  int? get _openPayloadBudget {
    final budget = options.maxOpenPayloadBytes;
    final mark = options.receiveHighWaterMarkBytes;
    final half = mark > 0 ? mark ~/ 2 : null;
    if (budget <= 0) {
      return half;
    }
    return half != null && half < budget ? half : budget;
  }

  /// A continuation of an open parent or one whose reader still waits
  /// for referenced bulk streams. A lower id alone proves no admission.
  bool _continuesOpenChannel(Uint8List openPayload) {
    try {
      final address = ChannelAddress.decode(openPayload);
      if (!TalkBulkOpen.isBulk(address)) {
        return false;
      }
      final parentId = TalkBulkOpen.decode(address).parentId;
      if (_channels.containsKey(parentId)) {
        return true;
      }
      return retainedForDrain(parentId);
    } on SwitchboardException {
      return false;
    } on FormatException {
      return false;
    }
  }

  /// Refuses the peer's channel [id] on [stream] with [status]: a CLOSE
  /// record and FIN, and `STOP_SENDING` with the same status.
  void _reject(QuicStream stream, int id, Status status) {
    _log.fine('$this: rejecting channel $id: $status');
    final code = quicErrorCode(status);
    final sending = Future<void>.sync(() async {
      stream.priority = quicOrdinaryPriority;
      stream.stop(code);
      await stream.write(encodeCloseRecord(status));
      await stream.finish();
      await stream.stopped;
    });
    final timeout = options.closeConfirmTimeout;
    final bounded = timeout > Duration.zero
        ? sending.timeout(timeout)
        : sending;
    final finished = bounded.catchError((Object _) => _release(stream, code));
    _trackFinishing(finished);
  }

  // Delivery of incoming channels ---------------------------------------------

  void _scheduleIncoming() {
    if (_incomingScheduled) {
      return;
    }
    _incomingScheduled = true;
    scheduleMicrotask(() {
      _incomingScheduled = false;
      while (_undelivered.isNotEmpty &&
          _incoming.hasListener &&
          !_incoming.isPaused) {
        final channel = _undelivered.removeFirst();
        if (channel.state == MuxChannelState.closed) {
          _releasePayload(channel);
        }
        _incoming.add(channel);
      }
      if (_closing && _undelivered.isEmpty && !_incoming.isClosed) {
        unawaited(_incoming.close());
      }
    });
  }

  void _cancelIncoming() {
    _incomingCancelled = true;
    final pending = List.of(_undelivered);
    _undelivered.clear();
    for (final channel in pending) {
      if (channel.state == MuxChannelState.closed) {
        _releasePayload(channel);
      }
      unawaited(
        channel.close(
          Status.of(StatusCode.unavailable, 'not accepting channels'),
        ),
      );
    }
  }

  void _releasePayload(QuicChannel channel) {
    if (_payloads.remove(channel)) {
      _openPayloadBytes -= channel.openPayload.length;
    }
  }

  /// [channel] ended: its id leaves the connection (never to be reused).
  void _releaseChannel(QuicChannel channel) {
    if (!identical(_channels[channel.id], channel)) {
      return;
    }
    _channels.remove(channel.id);
    if (!_undelivered.contains(channel)) {
      _releasePayload(channel);
    }
    Timer.run(_checkIdle);
  }

  @override
  void drainStateChanged() => Timer.run(_checkIdle);

  void _checkIdle() {
    if (_closing ||
        _channels.isNotEmpty ||
        hasDrainHolds ||
        _pendingStreams.isNotEmpty) {
      return;
    }
    final idle = _idle;
    _idle = null;
    if (idle != null && !idle.isCompleted) {
      idle.complete();
    }
    if (_peerGoAway != null) {
      _log.fine('$this: idle after the peer\'s GOAWAY, closing');
      unawaited(close());
    }
  }

  // Opening -------------------------------------------------------------------

  @override
  MuxChannel open(Uint8List openPayload) =>
      _openLocal(openPayload, continuation: false).._beginOpen().ignore();

  /// A channel of this side, registered under a new id; its stream is
  /// opened by [QuicChannel._beginOpen], now ([open]) or once its parent
  /// sent what came before ([QuicChannel.openAfter]).
  QuicChannel _openLocal(Uint8List openPayload, {required bool continuation}) {
    if (_closing || (_goAwaySent && !continuation)) {
      throw SwitchboardException.of(
        StatusCode.failedPrecondition,
        'connection is closing',
      );
    }
    if (_peerGoAway != null && !continuation) {
      throw SwitchboardException.of(
        StatusCode.failedPrecondition,
        'peer is going away',
      );
    }
    // The channels of the peer's HELLO are advisory (the pool reads them,
    // [peerMaxChannels]): beyond them an open waits for stream credit in
    // the stack, bounded by [QuicBindingOptions.openStreamTimeout].
    final size = quicChannelIdSize + openPayload.length;
    if (size > peerRecordLimit) {
      throw SwitchboardException.of(
        StatusCode.frameTooLarge,
        'OPEN record of $size bytes exceeds the peer\'s record limit of '
        '$peerRecordLimit',
      );
    }
    final id = _allocateId();
    final channel = QuicChannel._(
      this,
      id,
      isLocallyOpened: true,
      openPayload: Uint8List.fromList(openPayload),
    );
    _channels[id] = channel;
    return channel;
  }

  /// The next id of this side's parity, in increasing order, skipping the
  /// reserved ids; never one used before on this connection.
  int _allocateId() {
    var id = _nextId;
    while (MuxFrame.isReservedId(id)) {
      id += 2;
    }
    if (id > quicMaxChannelId) {
      throw SwitchboardException.of(
        StatusCode.resourceExhausted,
        'every channel id of this side was used; open on a new connection',
      );
    }
    _nextId = id + 2;
    return id;
  }

  /// Completes when this side may open a channel's stream: on the
  /// initiator, once the control stream is open (it goes first) and, with
  /// [QuicIdentityRules.awaitPeerIdentity], once the acceptor has
  /// identified. Fails with the reason the channel cannot be opened.
  Future<void> _openGate() async {
    if (isInitiator) {
      await _controlReady.future;
      if (quicOptions.identity.awaitPeerIdentity &&
          !_mutualIdentification.isCompleted) {
        final limit = options.identityTimeout;
        if (limit <= Duration.zero) {
          await _mutualIdentification.future;
        } else {
          await _mutualIdentification.future.timeout(
            limit,
            onTimeout: () => throw SwitchboardException.of(
              StatusCode.unauthenticated,
              'the peer did not identify within $limit',
            ),
          );
        }
      }
    }
    if (_closing) {
      throw SwitchboardException(_closeStatus ?? _lostStatus());
    }
  }

  // Ping, GOAWAY, close -------------------------------------------------------

  @override
  Future<Duration> ping([Uint8List? payload]) {
    final message = MuxControlMessage.ping(payload ?? _nextPingPayload());
    if (_closing) {
      return Future.error(
        SwitchboardException.of(
          StatusCode.failedPrecondition,
          'connection is closed',
        ),
      );
    }
    if (_pings.length >= MuxConnection.maxPendingPings) {
      _pings
          .removeAt(0)
          .completer
          .completeError(
            SwitchboardException.of(
              StatusCode.deadlineExceeded,
              'no PONG before ${MuxConnection.maxPendingPings} later PINGs',
            ),
          );
    }
    final pending = _PendingPing(Uint8List.fromList(message.payload));
    _pings.add(pending);
    _sendControl(message);
    return pending.completer.future;
  }

  Uint8List _nextPingPayload() {
    final n = _pingCounter;
    _pingCounter = (n + 1) & 0x7FFFFFFF;
    return Uint8List.fromList([
      n & 0xFF,
      (n >> 8) & 0xFF,
      (n >> 16) & 0xFF,
      (n >> 24) & 0xFF,
    ]);
  }

  void _completePing(Uint8List payload) {
    for (var i = 0; i < _pings.length; i++) {
      final pending = _pings[i];
      if (_bytesEqual(pending.payload, payload)) {
        _pings.removeAt(i);
        pending.completer.complete(pending.stopwatch.elapsed);
        return;
      }
    }
  }

  @override
  Future<void> goAway([Status status = const Status(33)]) {
    checkMuxStatus(status);
    if (_closing) {
      return close();
    }
    if (!_goAwaySent) {
      _goAwaySent = true;
      _ownGoAway = status;
      _log.fine('$this: sending GOAWAY $status');
      _sendControl(MuxControlMessage.goAway(statusForWire(status)));
    }
    return _goAwayWait();
  }

  Future<void> _goAwayWait() async {
    // Let channel stream listeners register their pending bulk work.
    await Future<void>.delayed(Duration.zero);
    if ((_channels.isNotEmpty || hasDrainHolds || _pendingStreams.isNotEmpty) &&
        !_closing) {
      final idle = _idle ??= Completer<void>();
      await idle.future.timeout(
        options.goAwayGrace,
        onTimeout: () {
          _log.fine(
            '$this: GOAWAY grace expired with ${_channels.length} channels',
          );
        },
      );
    }
    await close();
  }

  /// Closes the session: an application close with code 0 (or the status
  /// of this side's GOAWAY when it was not `GOING_AWAY`), once what this
  /// side finished writing on its streams has been acknowledged, within
  /// [MuxOptions.keepAliveTimeout]. The channels still open end with
  /// `CONNECTION_LOST`, or the GOAWAY status if either side sent one.
  /// Never throws.
  @override
  Future<void> close() {
    final own = _ownGoAway;
    final graceful = own == null || own.known == StatusCode.goingAway;
    return _shutdown(
      _lostStatus(),
      null,
      code: graceful ? 0 : quicErrorCode(own),
      reason: graceful ? '' : _closeReason(own),
      drain: true,
    );
  }

  /// The local `CONNECTION_LOST` status, unless a GOAWAY was received or
  /// sent first.
  Status _lostStatus([String reason = '']) =>
      _peerGoAway ?? _ownGoAway ?? Status.of(StatusCode.connectionLost, reason);

  static final Status _unauthenticated = Status.of(
    StatusCode.unauthenticated,
    'identification failed',
  );

  /// The reason of a connection close for [status], within 1024 bytes.
  static String _closeReason(Status status) =>
      truncateStatus(status, 2 + maxControlPayloadLength).reason;

  void _protocolError(String reason) =>
      _fail(Status.of(StatusCode.protocolError, reason));

  /// Ends the connection because the peer broke the protocol (or the
  /// identification rules): an application close carrying [status] at
  /// once, without a GOAWAY first, which could be lost with its stream.
  void _fail(Status status) {
    if (_closing) {
      return;
    }
    _log.warning('$this: closing with $status');
    unawaited(
      _shutdown(
        status,
        _lostStatus(),
        code: quicErrorCode(status),
        reason: _closeReason(status),
        drain: false,
      ),
    );
  }

  /// The session is lost to this side: closed without a status of its own.
  void _lost(String reason) {
    if (_closing) {
      return;
    }
    unawaited(
      _shutdown(
        _lostStatus(reason),
        null,
        code: StatusCode.unavailable.code,
        reason: reason,
        drain: false,
      ),
    );
  }

  Future<void> _shutdown(
    Status status,
    Status? channelStatus, {
    required int code,
    required String reason,
    required bool drain,
  }) {
    _closeStatus ??= status;
    return _closeFuture ??= _doShutdown(
      status,
      channelStatus ?? status,
      code,
      reason,
      drain,
    );
  }

  Future<void> _doShutdown(
    Status status,
    Status channelStatus,
    int code,
    String reason,
    bool drain,
  ) async {
    _closing = true;
    final finishing = drain ? List.of(_finishing) : const <Future<void>>[];
    _finish(status, channelStatus);
    if (finishing.isNotEmpty) {
      try {
        await Future.wait(finishing).timeout(options.keepAliveTimeout);
      } on Object {
        _log.fine('$this: closing before every stream was acknowledged');
      }
    }
    try {
      await session.close(code, reason).timeout(options.keepAliveTimeout);
    } on Object catch (e) {
      _log.fine('$this: session close: $e');
    }
    try {
      await _streams?.cancel();
      await _unidirectional?.cancel();
    } on Object catch (e) {
      _log.fine('$this: cancelling incoming streams: $e');
    }
  }

  void _finish(Status status, Status channelStatus) {
    _keepAliveTimer?.cancel();
    _keepAliveTimer = null;
    _controlTimer?.cancel();
    _controlTimer = null;
    _controlQueue.clear();
    for (final stream in _pendingStreams) {
      _release(stream, StatusCode.goingAway.code);
    }
    _pendingStreams.clear();
    final drained = _controlDrained;
    _controlDrained = null;
    drained?.complete();
    final channels = List.of(_channels.values);
    _channels.clear();
    for (final channel in channels) {
      try {
        channel._connectionLost(channelStatus);
      } on Object catch (e, st) {
        _log.warning('$this: ending channel ${channel.id}', e, st);
      }
      if (!_undelivered.contains(channel)) {
        _releasePayload(channel);
      }
    }
    final pings = List.of(_pings);
    _pings.clear();
    for (final pending in pings) {
      pending.completer.completeError(SwitchboardException(status));
    }
    _heldControl.clear();
    final nonceWaiter = _nonceWaiter;
    _nonceWaiter = null;
    nonceWaiter?.completeError(SwitchboardException(status));
    final bound = _boundIdentityWaiter;
    _boundIdentityWaiter = null;
    bound?.completeError(SwitchboardException(status));
    if (!_controlReady.isCompleted) {
      _controlReady.completeError(SwitchboardException(status));
    }
    if (!_mutualIdentification.isCompleted) {
      _mutualIdentification.completeError(SwitchboardException(status));
    }
    if (!_ready.isCompleted) {
      _ready.complete();
    }
    _signalIdentity();
    final idle = _idle;
    _idle = null;
    if (idle != null && !idle.isCompleted) {
      idle.complete();
    }
    _scheduleIncoming();
    if (!_done.isCompleted) {
      _done.complete(status);
    }
  }

  void _onSessionEnd(QuicSessionEnd end) {
    if (_closing) {
      return;
    }
    if (!end.lost && end.byPeer) {
      // An application close counts as a GOAWAY with its status (code 0:
      // GOING_AWAY), then the end of the transport.
      final code = end.code;
      _onPeerGoAway(
        code == 0
            ? Status.of(StatusCode.goingAway, end.reason)
            : statusFromWire(statusOfQuicErrorCode(code, end.reason)),
      );
      _log.fine('$this: the peer closed the session ($code ${end.reason})');
    } else {
      _log.fine('$this: the session ended: ${end.reason}');
    }
    unawaited(
      _shutdown(
        _lostStatus(end.reason),
        null,
        code: 0,
        reason: '',
        drain: false,
      ),
    );
  }

  /// Tracks the acknowledgement of a stream direction this side finished,
  /// which a graceful [close] waits for.
  void _trackFinishing(Future<void> acknowledged) {
    if (_closing) {
      return;
    }
    _finishing.add(acknowledged);
    acknowledged.whenComplete(() => _finishing.remove(acknowledged)).ignore();
  }

  // Keep-alive ----------------------------------------------------------------

  void _startKeepAlive() {
    final interval = options.keepAliveInterval;
    if (interval == null || _closing) {
      return;
    }
    _keepAliveTimer = Timer(interval, _onKeepAliveTimer);
  }

  /// A record arrived from the peer: it is alive.
  void _noteReceive() {
    _sinceReceive.reset();
    if (_probing) {
      _probing = false;
      _keepAliveTimer?.cancel();
      _startKeepAlive();
    }
  }

  void _onKeepAliveTimer() {
    final interval = options.keepAliveInterval;
    if (_closing || interval == null) {
      return;
    }
    if (_controlQueued > quicOptions.controlOutputMark) {
      // Reading is paused locally; that silence is not a dead peer.
      _probing = false;
      _keepAliveTimer = Timer(interval, _onKeepAliveTimer);
      return;
    }
    if (_probing) {
      _log.info('$this: no answer to keep-alive PING, closing');
      unawaited(
        _shutdown(
          _lostStatus('keep-alive timeout'),
          null,
          code: StatusCode.deadlineExceeded.code,
          reason: 'keep-alive timeout',
          drain: false,
        ),
      );
      return;
    }
    final silence = _sinceReceive.elapsed;
    if (silence < interval || _verifying) {
      _keepAliveTimer = Timer(
        silence < interval ? interval - silence : interval,
        _onKeepAliveTimer,
      );
      return;
    }
    _probing = true;
    _keepAliveTimer = Timer(options.keepAliveTimeout, _onKeepAliveTimer);
    _sendControl(MuxControlMessage.ping(_nextPingPayload()));
  }

  // Identity ------------------------------------------------------------------

  /// Identifies this side to the peer, as `MuxConnection.identify` does,
  /// with the proof bound to the TLS exporter when both `HELLO`s carry
  /// `EXPORTER` ([exporterBound]), and under the [QuicIdentityRules] of
  /// [quicOptions]:
  ///
  /// * With [QuicIdentityRules.requireExporterBinding], fails with
  ///   `UNAUTHENTICATED` without identifying when the proof could not be
  ///   exporter-bound.
  /// * With [QuicIdentityRules.bearerOnlyToAuthenticatedPeer], a bearer
  ///   credential fails with `FAILED_PRECONDITION` unless the peer is an
  ///   authenticated end ([peerAuthenticated]); with
  ///   [QuicIdentityRules.identifyOnlyToIdentifiedPeer], every credential
  ///   does.
  /// * With [QuicIdentityRules.awaitPeerIdentity] on the initiator,
  ///   completes only once the acceptor's exporter-bound `IDENT` naming
  ///   this side (and, when [receiver] is given, proving that identity)
  ///   has verified; the channels opened meanwhile wait for it. The wait
  ///   counts toward [timeout].
  @override
  Future<void> identify(
    Credential credential, {
    HolderKey? holderKey,
    Uint8List? intent,
    String? receiver,
    Duration? timeout,
  }) async {
    final holder = credential.holderKey;
    if (holder != null) {
      if (holderKey == null) {
        throw ArgumentError.value(
          holderKey,
          'holderKey',
          'the credential names a holder key, the proof needs its key pair',
        );
      }
      if (!_bytesEqual(holderKey.publicKey, holder)) {
        throw ArgumentError.value(
          holderKey,
          'holderKey',
          'not the holder key the credential names',
        );
      }
    }
    final intentBytes = intent == null
        ? Uint8List(0)
        : Uint8List.fromList(intent);
    final receiverBytes = receiver == null
        ? Uint8List(0)
        : Uint8List.fromList(utf8.encode(receiver));
    final credentialBytes = credential.encode();
    // Checks the lengths before anything is sent.
    MuxIdent(
      credential: credentialBytes,
      intent: intentBytes,
      receiver: receiverBytes,
      proof: holder == null ? null : Uint8List(MuxIdent.proofLength),
    ).encode();
    if (_closing) {
      throw SwitchboardException.of(
        StatusCode.failedPrecondition,
        'connection is closed',
      );
    }
    final rules = quicOptions.identity;
    if (rules.identifyOnlyToIdentifiedPeer && !peerAuthenticated) {
      throw SwitchboardException.of(
        StatusCode.failedPrecondition,
        'the peer has not identified with an exporter-bound proof',
      );
    }
    if (holder == null &&
        rules.bearerOnlyToAuthenticatedPeer &&
        !peerAuthenticated) {
      throw SwitchboardException.of(
        StatusCode.failedPrecondition,
        'a bearer credential goes only to an authenticated peer',
      );
    }
    final limit = timeout ?? options.identityTimeout;
    final watch = Stopwatch()..start();
    Future<T> bounded<T>(Future<T> future, String what) {
      if (limit <= Duration.zero) {
        return future;
      }
      final left = limit - watch.elapsed;
      return future.timeout(
        left > Duration.zero ? left : Duration.zero,
        onTimeout: () => throw SwitchboardException.of(
          StatusCode.deadlineExceeded,
          '$what within $limit',
        ),
      );
    }

    final localNonce = _localNonce ?? _sendNonce();
    final Uint8List peerNonce;
    try {
      peerNonce =
          _peerNonce ??
          await bounded(
            (_nonceWaiter ??= Completer<Uint8List>()..future.ignore()).future,
            'no NONCE from the peer',
          );
    } on SwitchboardException catch (e) {
      throw e.code == StatusCode.deadlineExceeded ? e : _identifyFailure();
    }
    // The peer's HELLO came before its NONCE, so both are known.
    final bound = exporterBound;
    if (!bound && rules.requireExporterBinding) {
      throw SwitchboardException.of(
        StatusCode.unauthenticated,
        'the identification cannot be bound to the TLS session',
      );
    }
    final proof = holder == null
        ? null
        : await bounded(
            holderKey!.sign(
              MuxIdent.proofMessage(
                localNonce,
                peerNonce,
                intentBytes,
                receiverBytes,
                exporter: bound ? _exporter : null,
              ),
            ),
            'proof not signed',
          );
    if (_closing) {
      throw _identifyFailure();
    }
    final awaitPeer = isInitiator && rules.awaitPeerIdentity;
    final peerWaiter = awaitPeer
        ? (_boundIdentityWaiter ??= Completer<PeerIdentity>()..future.ignore())
        : null;
    _log.fine(
      '$this: identifying as "${credential.identity}"'
      '${receiver == null || receiver.isEmpty ? '' : ' to "$receiver"'}'
      '${bound ? ', exporter-bound' : ''}',
    );
    _sendControl(
      MuxControlMessage.ident(
        MuxIdent(
          credential: credentialBytes,
          intent: intentBytes,
          receiver: receiverBytes,
          proof: proof,
        ),
      ),
    );
    try {
      await bounded(ping(), 'IDENT not confirmed');
    } on SwitchboardException catch (e) {
      throw e.code == StatusCode.deadlineExceeded ? e : _identifyFailure();
    }
    if (peerWaiter == null) {
      return;
    }
    final PeerIdentity identity;
    try {
      identity = peerIdentityBound
          ? peerIdentity!
          : await bounded(
              peerWaiter.future,
              'no exporter-bound IDENT from the peer',
            );
    } on SwitchboardException catch (e) {
      throw e.code == StatusCode.deadlineExceeded ? e : _identifyFailure();
    }
    if (receiver != null &&
        receiver.isNotEmpty &&
        identity.identity != receiver) {
      _log.info(
        '$this: the peer identified as "${identity.identity}", not '
        '"$receiver"',
      );
      _fail(_unauthenticated);
      throw SwitchboardException.of(
        StatusCode.unauthenticated,
        'the peer is not "$receiver"',
      );
    }
    if (!_mutualIdentification.isCompleted) {
      _mutualIdentification.complete();
    }
  }

  SwitchboardException _identifyFailure() {
    final peer = _peerGoAwayReceived;
    if (peer != null && peer.known == StatusCode.unauthenticated) {
      return SwitchboardException.of(
        StatusCode.unauthenticated,
        'the peer refused the credential',
      );
    }
    if (_done.isCompleted || _closing) {
      return SwitchboardException(_closeStatus ?? _lostStatus());
    }
    return SwitchboardException.of(
      StatusCode.failedPrecondition,
      'connection is closed',
    );
  }

  Uint8List _sendNonce() {
    final nonce = secureRandomBytes(MuxIdent.nonceLength);
    _localNonce = nonce;
    _sendControl(MuxControlMessage.nonce(nonce));
    return nonce;
  }

  void _onPeerNonce(Uint8List payload) {
    if (payload.length != MuxIdent.nonceLength) {
      throw ProtocolException('NONCE of ${payload.length} bytes');
    }
    if (_peerNonce != null) {
      throw ProtocolException('second NONCE');
    }
    final local = _localNonce;
    if (local != null && _bytesEqual(local, payload)) {
      throw ProtocolException('NONCE equal to ours');
    }
    final nonce = Uint8List.fromList(payload);
    _peerNonce = nonce;
    final requested = _localNonce == null;
    if (requested) {
      _sendNonce();
    }
    final waiter = _nonceWaiter;
    _nonceWaiter = null;
    waiter?.complete(nonce);
    if (requested && !_identityRequested.isCompleted) {
      _identityRequested.complete();
    }
  }

  void _onIdent(Uint8List payload) {
    final localNonce = _localNonce;
    final peerNonce = _peerNonce;
    if (localNonce == null || peerNonce == null) {
      throw ProtocolException('IDENT before both nonces were exchanged');
    }
    final ident = MuxIdent.decode(payload);
    final verifier = options.identityVerifier;
    final bound = exporterBound;
    if (!bound && quicOptions.identity.requireExporterBinding) {
      _log.info('$this: IDENT refused: not bound to the TLS session');
      _fail(_unauthenticated);
      return;
    }
    if (verifier == null) {
      _log.fine('$this: ignoring IDENT, no identity verifier');
      return;
    }
    // Control messages after the IDENT wait for its verification; the
    // channels do not, being streams of their own.
    _verifying = true;
    unawaited(_verifyIdent(verifier, ident, peerNonce, localNonce, bound));
  }

  Future<void> _verifyIdent(
    CredentialVerifier verifier,
    MuxIdent ident,
    Uint8List senderNonce,
    Uint8List receiverNonce,
    bool bound,
  ) async {
    PeerIdentity? identity;
    var failure = '';
    try {
      final verification = Future.any<PeerIdentity>([
        verifyIdent(
          ident,
          verifier: verifier,
          senderNonce: senderNonce,
          receiverNonce: receiverNonce,
          localIdentity: localIdentity,
          requireNamedIdent:
              options.requireNamedIdent ||
              (isInitiator && quicOptions.identity.awaitPeerIdentity),
          exporter: bound ? _exporter : null,
        ),
        done.then((status) => throw SwitchboardException(status)),
      ]);
      identity = await (options.identityTimeout > Duration.zero
          ? verification.timeout(options.identityTimeout)
          : verification);
    } on SwitchboardException catch (e) {
      failure = e.status.reason;
    } on Object catch (e, st) {
      _log.warning('$this: IDENT verification failed', e, st);
      failure = 'verification failed';
    }
    _verifying = false;
    if (_closing) {
      _heldControl.clear();
      return;
    }
    if (identity == null) {
      _log.info('$this: IDENT refused: $failure');
      _heldControl.clear();
      _fail(_unauthenticated);
      return;
    }
    _log.fine(
      '$this: peer identified as $identity'
      '${bound && ident.proof.isNotEmpty ? ', exporter-bound' : ''}',
    );
    // A bearer credential carries no proof: nothing bound it to the session.
    final proven = bound && ident.proof.isNotEmpty;
    _peerIdentity = identity;
    _peerIdentityBound = proven;
    if (proven) {
      final waiter = _boundIdentityWaiter;
      _boundIdentityWaiter = null;
      waiter?.complete(identity);
    }
    if (!_peerIdentified.isCompleted) {
      _peerIdentified.complete(identity);
    }
    _signalIdentity();
    while (_heldControl.isNotEmpty && !_verifying && !_closing) {
      final message = _heldControl.removeFirst();
      _guarded(() => _handleControl(message));
    }
  }

  void _signalIdentity() {
    final event = _identityEvent;
    _identityEvent = null;
    event?.complete();
  }

  @override
  String toString() =>
      'QuicBindingConnection(${isInitiator ? 'initiator' : 'acceptor'}, '
      '${session.remote}, ${_channels.length} channels'
      '${_closing ? ', closed' : ''})';
}

class _PendingPing {
  _PendingPing(this.payload) {
    completer.future.ignore();
  }

  final Uint8List payload;
  final Completer<Duration> completer = Completer<Duration>();
  final Stopwatch stopwatch = Stopwatch()..start();
}

bool _bytesEqual(List<int> a, List<int> b) {
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

/// Whether [error] is the end of the session, which every pending
/// operation reports, rather than a failure of one stream.
bool isSessionEnd(Object error) =>
    error is QuicException && error.kind == QuicExceptionKind.sessionEnded;
