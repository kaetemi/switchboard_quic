/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

part of 'quic_binding_connection.dart';

/// A channel of a [QuicBindingConnection]: one bidirectional stream, as
/// the binding page specifies (sections "Channels" and "Flow control and
/// scheduling"), keeping the contract of [MuxChannel].
///
/// * The opener's direction starts with the OPEN record, written as the
///   stream opens, together with whatever was sent meanwhile. Each
///   subframe is a DATA record; records waiting on the stream go to the
///   stack together, and [send] completes once the stack has taken its
///   record (exact backpressure: the stack waits for the peer's stream and
///   connection windows).
/// * Close: a CLOSE record carrying the status payload, then FIN, after
///   what was sent before; with `STOP_SENDING` carrying the status as well
///   when the status is not `OK` (a rejection, a failure), so that the
///   peer stops sending what would be discarded. The peer's close is its
///   CLOSE record, its reset, or its `STOP_SENDING`, after which this side
///   resets its own direction with the same code (the stack's echo) and
///   keeps reading until the peer's direction ends: its CLOSE record, if
///   it has one, carries the full status, which is the one reported. A
///   close not answered within [MuxOptions.closeConfirmTimeout] sends
///   `STOP_SENDING` `DEADLINE_EXCEEDED`, resets this side's direction if
///   its CLOSE record is still queued behind data (an `OK` close becoming
///   `DEADLINE_EXCEEDED`), and ends the channel with its first status.
/// * Flow control: the stack's stream window is the channel's window. The
///   binding reads the next record only once the layer above has taken
///   the previous one (the [stream]'s listener, or [consumed] under
///   [manualCredit]), so that unread data stays in the stack and a reader
///   that stops stalls its own channel; [grant] lets it read that much
///   further ahead, and so does an `OK` close of this side, by a window,
///   so that the peer's CLOSE record is found behind data nobody takes. A
///   subframe costs its record: its length plus the 4-byte header
///   ([sendCost]). The stack's send window is not visible to the binding,
///   so [sendWindow] is an estimate, which nothing here counts on.
/// * [maxSubframeLength] is the peer's record limit; a bulk channel's
///   payload goes in records of at most the smaller of it and
///   [MuxOptions.bulkChunkSize].
class QuicChannel extends MuxChannel {
  QuicChannel._(
    this.connection,
    this.id, {
    required this.isLocallyOpened,
    required this.openPayload,
  }) {
    _incoming = StreamController<Uint8List>(
      sync: true,
      onListen: _scheduleDrain,
      onResume: _scheduleDrain,
      onCancel: _discard,
    );
    _sink = _QuicSink(this);
  }

  @override
  final QuicBindingConnection connection;

  @override
  final int id;

  @override
  final bool isLocallyOpened;

  @override
  final Uint8List openPayload;

  QuicStream? _stream;
  RecordReader? _reader;
  late final StreamController<Uint8List> _incoming;
  // Closed by the application through close().
  // ignore: close_sinks
  late final _QuicSink _sink;
  final Completer<Status> _done = Completer<Status>();
  MuxChannelState _state = MuxChannelState.open;
  MuxPriority _priority = MuxPriority.normal;
  Status _endStatus = Status.ok;
  // Whether [_endStatus] came from an error code only (a reset or a
  // STOP_SENDING of the peer), so that the peer's CLOSE record replaces it.
  bool _endFromCode = false;
  bool _ended = false;

  // Sending.
  final Queue<_Out> _out = Queue<_Out>();
  bool _writing = false;
  bool _openWritten = false;
  Status? _pendingClose;
  // This side's close, once its CLOSE record went into a write.
  Status? _closeInFlight;
  // FIN went: the stack acknowledges the direction ([QuicStream.stopped]).
  bool _finWritten = false;
  // This side has closed: its CLOSE is queued or written, or it reset.
  bool _closeQueued = false;
  // This side's direction ended on the wire (CLOSE and FIN, or a reset).
  bool _sendEnded = false;
  bool _stopSent = false;
  Timer? _confirmTimer;
  Timer? _openTimer;
  Completer<QuicStream?>? _openingResult;
  // Completes once this side's direction is acknowledged, or will never
  // be: what a graceful close of the connection waits for.
  Completer<void>? _acknowledged;
  final List<Completer<void>> _writableWaiters = [];

  // Receiving.
  // The peer's direction ended: its CLOSE record or its reset.
  bool _peerEnded = false;
  final Queue<Uint8List> _queue = Queue<Uint8List>();
  int _queuedCost = 0;
  int _held = 0;
  int _readAhead = 0;
  bool _manualCredit = false;
  Completer<void>? _consumedSignal;
  bool _drainScheduled = false;
  bool _discarding = false;
  bool _incomingEnded = false;

  // The contract ------------------------------------------------------------

  @override
  MuxChannelState get state => _state;

  @override
  bool get canSend => _state == MuxChannelState.open;

  @override
  MuxPriority get priority => _priority;

  @override
  set priority(MuxPriority value) {
    _priority = value;
    final stream = _stream;
    if (stream != null && !_sendEnded) {
      stream.priority = _priorityClass;
    }
  }

  int get _priorityClass =>
      _priority == MuxPriority.bulk ? quicBulkPriority : quicOrdinaryPriority;

  @override
  int get bufferedBytes => _queuedCost;

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  bool get hasListener => _incoming.hasListener;

  int get _unconsumed => _queuedCost + _held;

  /// The stream window this side grants ([MuxOptions.initialWindow], as
  /// the binding configures its stack), plus what [grant] added, less
  /// what arrived and was not consumed yet; 0 once the peer's direction
  /// ended.
  @override
  int get receiveWindow {
    if (_peerEnded || _ended) {
      return 0;
    }
    final window = connection.options.initialWindow + _readAhead - _unconsumed;
    return window < 0 ? 0 : window;
  }

  @override
  bool get manualCredit => _manualCredit;

  @override
  set manualCredit(bool value) {
    if (value == _manualCredit) {
      return;
    }
    _manualCredit = value;
    if (!value && _held > 0) {
      _held = 0;
      _signalConsumed();
    }
  }

  @override
  int get heldBytes => _held;

  @override
  void consumed(int bytes, {int subframes = 1}) {
    if (bytes < 0 || subframes < 0) {
      throw ArgumentError('negative bytes ($bytes) or subframes ($subframes)');
    }
    if (_ended) {
      return;
    }
    final cost = bytes + quicRecordHeaderSize * subframes;
    if (cost > _held) {
      throw StateError('$cost credit reported consumed, $_held held');
    }
    _held -= cost;
    _signalConsumed();
  }

  /// Lets the binding read [bytes] further ahead of what the layer above
  /// consumed, which returns as much window to the peer through the stack.
  @override
  void grant(int bytes) {
    if (bytes <= 0) {
      throw ArgumentError.value(bytes, 'bytes', 'must be positive');
    }
    if (_peerEnded || _ended) {
      return;
    }
    if (connection.options.initialWindow + _readAhead + bytes > 0xFFFFFFFF) {
      throw ArgumentError.value(bytes, 'bytes', 'window exceeds 2^32 - 1');
    }
    _readAhead += bytes;
    _signalConsumed();
  }

  @override
  StreamSink<Uint8List> get sink => _sink;

  @override
  Future<Status> get done => _done.future;

  /// An estimate, as [MuxChannel.sendWindow] has it for a binding whose
  /// streams the stack flow-controls: the stack's window is not visible to
  /// the binding, so this is room for one largest subframe ([sendCost] of
  /// [maxSubframeLength]) while the channel [isWritable], else 0. A
  /// diagnostic, not a count: whether to produce a subframe is decided by
  /// [isWritable] and [whenWritable], and a subframe is followed by the
  /// future of [send].
  @override
  int get sendWindow => isWritable ? sendCost(maxSubframeLength) : 0;

  /// A DATA record: the subframe and its 4-byte header.
  @override
  int sendCost(int length) => length + quicRecordHeaderSize;

  /// The peer's record limit: [quicDefaultRecordLimit] until its `HELLO`
  /// raises it.
  @override
  int get maxSubframeLength => connection.peerRecordLimit;

  @override
  Future<void> send(Uint8List subframe) {
    if (!canSend) {
      throw SwitchboardException.of(
        StatusCode.failedPrecondition,
        'channel $id is ${_state.name}',
      );
    }
    final split = _priority == MuxPriority.bulk && subframe.isNotEmpty;
    if (!split && subframe.length > maxSubframeLength) {
      throw SwitchboardException.of(
        StatusCode.frameTooLarge,
        'subframe of ${subframe.length} bytes, at most $maxSubframeLength',
      );
    }
    final item = _Out(subframe, split: split);
    _out.add(item);
    _pump();
    return item.completer.future;
  }

  /// Whether a subframe would be handed to the stack at once: the stream
  /// is open with this side's OPEN record written, and nothing of the
  /// channel waits for the stack.
  @override
  bool get isWritable =>
      canSend && _stream != null && _openWritten && !_writing && _out.isEmpty;

  @override
  Future<void> get whenWritable {
    final waiter = Completer<void>()..future.ignore();
    if (!canSend) {
      waiter.completeError(_cannotSend());
    } else if (isWritable) {
      waiter.complete();
    } else {
      _writableWaiters.add(waiter);
    }
    return waiter.future;
  }

  SwitchboardException _cannotSend() => SwitchboardException.of(
    StatusCode.failedPrecondition,
    'channel $id is ${_state.name}',
  );

  void _wakeWritable() {
    if (_writableWaiters.isEmpty || (canSend && !isWritable)) {
      return;
    }
    final waiters = List.of(_writableWaiters);
    _writableWaiters.clear();
    for (final waiter in waiters) {
      if (canSend) {
        waiter.complete();
      } else {
        waiter.completeError(_cannotSend());
      }
    }
  }

  /// Opens a channel on the connection whose stream is opened once what
  /// this channel was given before the call has been handed to the stack:
  /// the peer may still receive it first, since streams are not ordered
  /// (`MuxConnection.hasOrderedChannels` is false).
  @override
  MuxChannel openAfter(Uint8List openPayload) {
    if (!canSend) {
      throw _cannotSend();
    }
    final child = connection._openLocal(openPayload, continuation: true);
    if (_out.isEmpty && !_writing && _openWritten && _stream != null) {
      child._beginOpen().ignore();
    } else {
      _out.add(_Out.open(child));
    }
    return child;
  }

  @override
  Future<void> close([Status status = Status.ok]) {
    checkMuxStatus(status);
    if (_state == MuxChannelState.open) {
      _state = MuxChannelState.halfClosedLocal;
      _closeQueued = true;
      _noteStatus(status);
      _pendingClose = status;
      _trackAcknowledgement();
      _startConfirmTimer();
      if (!status.isOk) {
        // A rejection or a failure: this side will not read what is still
        // coming, and the channel has ended for it, the peer's direction
        // being reset. Its CLOSE record still follows what it sent.
        _stopReceiving(quicErrorCode(status));
      } else if (!_peerEnded) {
        // What the peer sends before it sees the close is still delivered;
        // reading up to a window ahead finds its CLOSE record behind data
        // nobody takes, as the frame mux would.
        _readAhead += connection.options.initialWindow;
        _signalConsumed();
      }
      _pump();
      _wakeWritable();
      _checkEnd();
    }
    return _done.future.then((_) {});
  }

  // Opening and attaching -----------------------------------------------------

  /// Opens this channel's stream (a channel of this side), within the
  /// connection's gate and [QuicBindingOptions.openStreamTimeout].
  Future<void> _beginOpen() async {
    try {
      await connection._openGate();
    } on SwitchboardException catch (e) {
      _openFailed(e.status);
      return;
    }
    if (_ended) {
      _neverWritten();
      return;
    }
    final opening = Future<QuicStream>.sync(connection.session.openStream);
    final result = _openingResult = Completer<QuicStream?>();
    unawaited(
      opening.then(
        (stream) {
          if (result.isCompleted) {
            // Given up on meanwhile.
            connection._release(stream, StatusCode.cancelled.code);
          } else {
            result.complete(stream);
          }
        },
        onError: (Object e) {
          if (!result.isCompleted) {
            result.completeError(e);
          }
        },
      ),
    );
    final timeout = connection.quicOptions.openStreamTimeout;
    final timer = _openTimer = timeout > Duration.zero
        ? Timer(timeout, () {
            if (!result.isCompleted) {
              result.complete(null);
            }
          })
        : null;
    final QuicStream? stream;
    try {
      stream = await result.future;
    } on Object catch (e) {
      timer?.cancel();
      _log.fine('$this: no stream: $e');
      if (isSessionEnd(e)) {
        // Session.done determines whether this was an application close.
        return;
      }
      _openFailed(
        Status.of(
          e is QuicException && e.kind == QuicExceptionKind.streamLimit
              ? StatusCode.resourceExhausted
              : StatusCode.internal,
          'stream open failed',
        ),
      );
      return;
    }
    timer?.cancel();
    _openTimer = null;
    _openingResult = null;
    if (stream == null) {
      _openFailed(
        Status.of(
          StatusCode.resourceExhausted,
          'no stream credit from the peer within $timeout',
        ),
      );
      return;
    }
    if (_ended) {
      connection._release(stream, StatusCode.cancelled.code);
      _neverWritten();
      return;
    }
    _attach(stream, RecordReader(stream), openWritten: false);
  }

  /// The channel ended before its stream opened (closed with a failure,
  /// or the confirmation timed out): nothing of it will be written.
  void _neverWritten() {
    _sendEnded = true;
    _pendingClose = null;
    _dropOut();
    _acknowledge();
  }

  /// The stream of this channel: [openWritten] for the peer's channels,
  /// whose OPEN record was read already.
  void _attach(
    QuicStream stream,
    RecordReader reader, {
    required bool openWritten,
  }) {
    _stream = stream;
    _reader = reader;
    _openWritten = openWritten;
    stream.priority = _priorityClass;
    stream.resetReceived
        .then(
          (code) {
            if (!_peerEnded && !_ended && !_stopSent) _onPeerReset(code);
          },
          onError: (Object e) {
            if (!isSessionEnd(e) && !_ended) {
              _abort(
                Status.of(StatusCode.internal, 'reset notification failed'),
              );
            }
          },
        )
        .ignore();
    stream.stopped
        .then(
          (code) {
            if (code != null) {
              _onStopSending(code);
            }
          },
          onError: (Object e) {
            if (e is QuicStreamStopped) {
              _onStopSending(e.code);
            } else if (!isSessionEnd(e) && !_ended) {
              _abort(
                Status.of(StatusCode.internal, 'stream acknowledgement failed'),
              );
            }
          },
        )
        .ignore();
    unawaited(_readLoop());
    if (_stopSent) {
      // Closed with a failure before the stream existed.
      stream.stop(quicErrorCode(_endStatus));
    }
    _pump();
    _wakeWritable();
  }

  /// The open never reached the wire: the channel ends locally with
  /// [status]; the peer never heard of it.
  void _openFailed(Status status) {
    if (_ended) {
      return;
    }
    _noteStatus(status);
    _sendEnded = true;
    _peerEnded = true;
    _closeQueued = true;
    _pendingClose = null;
    _dropOut();
    _acknowledge();
    _endIncoming();
    _end();
  }

  // Sending -------------------------------------------------------------------

  /// Hands what waits to the stack, one write at a time: the OPEN record
  /// first, then the queued records, then the CLOSE record and FIN.
  void _pump() {
    final stream = _stream;
    if (_writing || stream == null || _sendEnded) {
      return;
    }
    final close = _pendingClose;
    if (_openWritten && _out.isEmpty && close == null) {
      _wakeWritable();
      return;
    }
    final batch = BytesBuilder(copy: false);
    final completers = <Completer<void>>[];
    if (!_openWritten) {
      batch.add(encodeOpenRecord(id, openPayload));
    }
    final limit = connection.quicOptions.writeBatchBytes;
    while (_out.isNotEmpty && batch.length < limit) {
      final head = _out.first;
      final child = head.opens;
      if (child != null) {
        if (batch.isNotEmpty) {
          // Opened once what came before it was taken.
          break;
        }
        _out.removeFirst();
        child._beginOpen().ignore();
        continue;
      }
      if (head.split) {
        var chunk = connection.options.bulkChunkSize;
        final peerLimit = maxSubframeLength;
        if (peerLimit < chunk) {
          chunk = peerLimit;
        }
        if (chunk < 1) {
          chunk = 1;
        }
        while (head.offset < head.data.length && batch.length < limit) {
          final rest = head.data.length - head.offset;
          final n = rest < chunk ? rest : chunk;
          batch
            ..add(_header(QuicRecordCommand.data, n))
            ..add(
              Uint8List.sublistView(head.data, head.offset, head.offset + n),
            );
          head.offset += n;
        }
        if (head.offset < head.data.length) {
          break;
        }
      } else {
        batch
          ..add(_header(QuicRecordCommand.data, head.data.length))
          ..add(head.data);
      }
      _out.removeFirst();
      completers.add(head.completer);
    }
    var finishing = false;
    if (_out.isEmpty && close != null) {
      _pendingClose = null;
      _closeInFlight = close;
      batch.add(encodeCloseRecord(close));
      finishing = true;
    }
    if (batch.isEmpty) {
      // Only child opens were waiting.
      _wakeWritable();
      return;
    }
    _openWritten = true;
    _writing = true;
    final bytes = batch.takeBytes();
    Future<void>.sync(() => stream.write(bytes))
        .then(
          (_) {
            _writing = false;
            for (final completer in completers) {
              completer.complete();
            }
            if (finishing) {
              _finishDirection(stream);
            }
            _pump();
            _wakeWritable();
          },
          onError: (Object e) {
            _writing = false;
            final error = SwitchboardException.of(
              StatusCode.failedPrecondition,
              'channel $id can no longer send',
            );
            for (final completer in completers) {
              completer.completeError(error);
            }
            if (_sendEnded) {
              // This side reset its direction meanwhile.
              _wakeWritable();
              return;
            }
            if (e is QuicStreamStopped) {
              _onStopSending(e.code);
            } else if (isSessionEnd(e)) {
              // The channel ends with the connection.
              _sendEnded = true;
              _closeQueued = true;
              _pendingClose = null;
              _dropOut();
              _acknowledge();
            } else {
              _log.warning('$this: write failed: $e');
              _abort(Status.of(StatusCode.internal, 'write failed'));
            }
            _wakeWritable();
          },
        )
        .catchError((Object e, StackTrace st) {
          _log.severe('$this: after a write', e, st);
        });
  }

  static Uint8List _header(QuicRecordCommand command, int length) {
    final header = Uint8List(quicRecordHeaderSize);
    writeQuicRecordHeader(header, 0, command, length);
    return header;
  }

  /// The CLOSE record was taken: FIN ends this side's direction.
  void _finishDirection(QuicStream stream) {
    Future<void>.sync(stream.finish)
        .then(
          (_) {
            _sendEnded = true;
            _finWritten = true;
            if (_ended) {
              _confirmTimer?.cancel();
              _confirmTimer = null;
            }
            stream.stopped
                .then(
                  (_) => _acknowledge(),
                  onError: (Object _) => _acknowledge(),
                )
                .ignore();
            _checkEnd();
          },
          onError: (Object e) {
            if (e is QuicStreamStopped) {
              _onStopSending(e.code);
            } else if (!isSessionEnd(e)) {
              _abort(Status.of(StatusCode.internal, 'FIN failed'));
            }
          },
        )
        .ignore();
  }

  /// This side closed: a graceful close of the connection waits until its
  /// direction is acknowledged (or never will be).
  void _trackAcknowledgement() {
    if (_acknowledged != null) {
      return;
    }
    final acknowledged = _acknowledged = Completer<void>();
    connection._trackFinishing(acknowledged.future);
  }

  void _acknowledge() {
    final acknowledged = _acknowledged;
    if (acknowledged != null && !acknowledged.isCompleted) {
      acknowledged.complete();
    }
  }

  /// Ends this side's direction with a reset carrying [code]: what was
  /// not delivered is discarded.
  void _resetDirection(int code) {
    if (_sendEnded) {
      return;
    }
    _sendEnded = true;
    _closeQueued = true;
    _pendingClose = null;
    _dropOut();
    _stream?.reset(code);
    if (_ended) {
      _confirmTimer?.cancel();
      _confirmTimer = null;
    }
    _acknowledge();
  }

  /// Sends `STOP_SENDING` with [code] once: this side reads no more of
  /// the peer's direction, which the peer resets. What arrived and waits
  /// for the listener is still delivered.
  void _stopReceiving(int code) {
    if (_stopSent || _peerEnded) {
      return;
    }
    _stopSent = true;
    _stream?.stop(code);
  }

  /// Fails what waits to be sent, and never opens the channels of
  /// [openAfter] still waiting for their turn.
  void _dropOut() {
    if (_out.isEmpty) {
      return;
    }
    final error = SwitchboardException.of(
      StatusCode.failedPrecondition,
      'channel $id closed before the subframe was sent',
    );
    final items = List.of(_out);
    _out.clear();
    for (final item in items) {
      final child = item.opens;
      if (child != null) {
        child._openFailed(
          Status.of(StatusCode.cancelled, 'the open never went out'),
        );
      } else {
        item.completer.completeError(error);
      }
    }
  }

  // Closing -------------------------------------------------------------------

  void _noteStatus(Status status, {bool fromCode = false}) {
    if (_endStatus.isOk && !status.isOk) {
      _endStatus = status;
      _endFromCode = fromCode;
    }
  }

  /// The peer's close arrived before this side closed: close in turn, at
  /// once, dropping what was not sent yet.
  void _closeInTurn() {
    if (_writing && !_sendEnded) {
      // An in-flight write can be stalled at the peer's window. A reset
      // confirms now and abandons that write, including a partial record.
      _resetDirection(
        quicErrorCode(_pendingClose ?? _closeInFlight ?? Status.ok),
      );
    }
    if (_state == MuxChannelState.open) {
      _dropOut();
      _closeQueued = true;
      if (!_sendEnded) {
        _pendingClose = Status.ok;
        _trackAcknowledgement();
      }
    } else if (!_sendEnded && _pendingClose != null) {
      // Ours waited behind data: it goes at once.
      _dropOut();
    }
    _state = MuxChannelState.closed;
    if (!_sendEnded) _startConfirmTimer();
    _pump();
    _wakeWritable();
  }

  /// The peer's `STOP_SENDING`: its close, arriving early. This side
  /// stops sending at once, resetting its direction with the same code,
  /// and keeps reading until the peer's direction ends.
  void _onStopSending(int? code) {
    if (connection._closing) return;
    final status = statusOfQuicErrorCode(code);
    if (_ended) {
      // Ended for this side already; what it still had to send goes no
      // further.
      _resetDirection(code ?? quicErrorCode(status));
      return;
    }
    if (_peerEnded) {
      // The peer's direction ended first (its CLOSE record, say), and its
      // STOP_SENDING now ends this side's close in turn, which the peer
      // gave up waiting for (its confirmation timeout): this side's
      // direction ends here (the stack reset it with the code), and with
      // it the channel, instead of waiting for its own timeout.
      _noteStatus(status);
      _resetDirection(code ?? quicErrorCode(status));
      _wakeWritable();
      _checkEnd();
      return;
    }
    _noteStatus(status, fromCode: true);
    _resetDirection(code ?? quicErrorCode(status));
    if (_state == MuxChannelState.open) {
      _state = MuxChannelState.halfClosedLocal;
    }
    _startConfirmTimer();
    _wakeWritable();
    _checkEnd();
  }

  void _onPeerCloseRecord(Status status) {
    _peerEnded = true;
    if (_endFromCode && _endStatus.code == status.code) {
      // The same close, known first by its code: the record carries the
      // reason and the fields.
      _endStatus = status;
      _endFromCode = false;
    } else {
      _noteStatus(status);
    }
    _endIncoming();
    _closeInTurn();
    _checkEnd();
  }

  void _onPeerReset(int? code) => _peerReset(code);

  void _peerReset(int? code) {
    if (_ended || _peerEnded) {
      return;
    }
    if (connection._closing) {
      // The channel ends as the connection's channels do.
      return;
    }
    _peerEnded = true;
    if (!_stopSent) {
      _noteStatus(statusOfQuicErrorCode(code), fromCode: true);
    }
    // After this side's STOP_SENDING the reset is its confirmation,
    // whatever the code (a browser cannot choose it).
    _endIncoming();
    _closeInTurn();
    _checkEnd();
  }

  /// Bounds the wait for the peer's close, and, once the channel ended,
  /// the write of this side's CLOSE record behind what it sent.
  void _startConfirmTimer() {
    final timeout = connection.options.closeConfirmTimeout;
    if (timeout <= Duration.zero || _confirmTimer != null) {
      return;
    }
    _confirmTimer = Timer(timeout, _onConfirmTimeout);
  }

  void _onConfirmTimeout() {
    _confirmTimer = null;
    final deadline = StatusCode.deadlineExceeded.code;
    if (_ended) {
      if (!_sendEnded) {
        // The CLOSE record is still queued behind data the peer does not
        // read: the direction is reset instead.
        final close = _pendingClose ?? _closeInFlight;
        _resetDirection(
          close == null || close.isOk ? deadline : quicErrorCode(close),
        );
      }
      return;
    }
    _log.fine(
      '$this: no answer to the close within '
      '${connection.options.closeConfirmTimeout}',
    );
    if (!_peerEnded) {
      // Forces the peer to reset its direction.
      _stopReceiving(deadline);
    }
    if (!_sendEnded) {
      // The CLOSE record is still queued behind data the peer does not
      // read.
      final close = _pendingClose ?? _closeInFlight;
      if (close == null || close.isOk) {
        _noteStatus(Status.of(StatusCode.deadlineExceeded));
        _resetDirection(deadline);
      } else {
        _resetDirection(quicErrorCode(close));
      }
    }
    _peerEnded = true;
    _endIncoming();
    _end();
  }

  /// Ends the channel when both directions have ended: the peer's
  /// received (or stopped by this side's `STOP_SENDING`), this side's sent
  /// (or queued behind what it sent).
  void _checkEnd() {
    if (!_ended && _sendEnded && _closeQueued && (_peerEnded || _stopSent)) {
      _end();
    }
  }

  /// A local failure of the stream: both directions are given up (reset
  /// and `STOP_SENDING`), and the channel ends with [status] unless it
  /// ended already.
  void _abort(Status status) {
    if (!_ended) {
      _noteStatus(status);
    }
    final code = quicErrorCode(status);
    _stopReceiving(code);
    _resetDirection(code);
    _peerEnded = true;
    _endIncoming();
    _end();
  }

  void _connectionLost(Status status) {
    _noteStatus(status);
    _pendingClose = null;
    _sendEnded = true;
    _closeQueued = true;
    _peerEnded = true;
    _dropOut();
    if (!_finWritten) {
      // Nothing more goes; a FIN written is acknowledged (or fails with the
      // session) on its own, which a graceful close waits for.
      _acknowledge();
    }
    _endIncoming();
    _end();
  }

  void _end() {
    if (_ended) {
      return;
    }
    _ended = true;
    _openTimer?.cancel();
    _openTimer = null;
    final opening = _openingResult;
    _openingResult = null;
    if (opening != null && !opening.isCompleted) opening.complete(null);
    _state = MuxChannelState.closed;
    if (_sendEnded) {
      _confirmTimer?.cancel();
      _confirmTimer = null;
    } else {
      // What this side queued before its CLOSE record still goes, within
      // the confirmation timeout.
      _startConfirmTimer();
    }
    _held = 0;
    _wakeWritable();
    _signalConsumed();
    _endIncoming();
    connection._releaseChannel(this);
    if (!_done.isCompleted) {
      _done.complete(_endStatus);
    }
  }

  // Receiving -----------------------------------------------------------------

  Future<void> _readLoop() async {
    final reader = _reader!;
    while (true) {
      while (!_ended &&
          !_peerEnded &&
          !_stopSent &&
          _unconsumed > 0 &&
          _unconsumed >= _readAhead) {
        await (_consumedSignal ??= Completer<void>()).future;
      }
      if (_peerEnded || _stopSent || connection._closing) {
        return;
      }
      QuicRecord? record;
      Object? failure;
      try {
        record = await reader.next(limit: connection.recordLimit);
      } on Object catch (e) {
        failure = e;
      }
      if (_stopSent || _peerEnded || connection._closing) {
        // This side stopped reading meanwhile, or the connection ends.
        return;
      }
      if (failure != null) {
        _readFailed(failure);
        return;
      }
      if (record == null) {
        connection._protocolError('FIN without a CLOSE record on channel $id');
        return;
      }
      connection._noteReceive();
      switch (record.command) {
        case QuicRecordCommand.data:
          _onData(record.body);
        case QuicRecordCommand.open:
          connection._protocolError('a second OPEN record on channel $id');
          return;
        case QuicRecordCommand.close:
          final Status status;
          try {
            status = decodeCloseBody(record.body);
          } on ProtocolException catch (e) {
            connection._fail(e.status);
            return;
          }
          _onPeerCloseRecord(status);
          final ending = reader.expectEnd();
          final timeout = connection.options.closeConfirmTimeout;
          // CLOSE ends the application channel, but its stream must not
          // keep a read and stream credit forever if FIN never follows.
          final finished = timeout > Duration.zero
              ? ending.timeout(
                  timeout,
                  onTimeout: () =>
                      _stream!.stop(StatusCode.deadlineExceeded.code),
                )
              : ending;
          connection._trackFinishing(finished);
          try {
            await finished;
          } on ProtocolException catch (e) {
            connection._fail(e.status);
          } on Object {
            // The session ended meanwhile.
          }
          return;
      }
    }
  }

  /// Reading the peer's direction failed with [failure].
  void _readFailed(Object failure) {
    switch (failure) {
      case QuicStreamReset(:final code):
        _onPeerReset(code);
      case RecordTooLarge(:final length, :final limit):
        connection._fail(
          Status.of(
            StatusCode.frameTooLarge,
            'record of $length bytes on channel $id, limit $limit',
          ),
        );
      case ProtocolException(:final status):
        connection._fail(status);
      default:
        if (isSessionEnd(failure)) {
          // The channel ends with the connection.
          break;
        }
        _log.warning('$this: reading failed: $failure');
        _abort(Status.of(StatusCode.internal, 'read failed'));
    }
  }

  void _onData(Uint8List subframe) {
    if (_discarding || _stopSent || _ended) {
      return;
    }
    _queue.add(subframe);
    _queuedCost += sendCost(subframe.length);
    _scheduleDrain();
  }

  void _signalConsumed() {
    final signal = _consumedSignal;
    _consumedSignal = null;
    signal?.complete();
  }

  void _discard() {
    _discarding = true;
    _queue.clear();
    if (_queuedCost > 0) {
      _queuedCost = 0;
      _signalConsumed();
    }
  }

  void _endIncoming() {
    _incomingEnded = true;
    _scheduleDrain();
  }

  void _scheduleDrain() {
    if (_drainScheduled) {
      return;
    }
    _drainScheduled = true;
    scheduleMicrotask(_drain);
  }

  void _drain() {
    _drainScheduled = false;
    var delivered = false;
    while (_queue.isNotEmpty && _incoming.hasListener && !_incoming.isPaused) {
      final data = _queue.removeFirst();
      final cost = sendCost(data.length);
      _queuedCost -= cost;
      if (_manualCredit && !_ended) {
        _held += cost;
      }
      delivered = true;
      _incoming.add(data);
    }
    if (delivered) {
      _signalConsumed();
    }
    if (_incomingEnded && _queue.isEmpty && !_incoming.isClosed) {
      unawaited(_incoming.close());
    }
  }

  @override
  String toString() =>
      'QuicChannel($id, ${_state.name}, '
      '${isLocallyOpened ? 'local' : 'remote'})';
}

/// A subframe (or a bulk payload) waiting for the stack, or the open of a
/// channel of [QuicChannel.openAfter] in order with them.
class _Out {
  _Out(this.data, {required this.split}) : opens = null;

  _Out.open(QuicChannel this.opens) : data = Uint8List(0), split = false;

  final Uint8List data;
  final bool split;
  final QuicChannel? opens;
  int offset = 0;
  final Completer<void> completer = Completer<void>()..future.ignore();
}

class _QuicSink implements StreamSink<Uint8List> {
  _QuicSink(this._channel);

  final QuicChannel _channel;
  bool _closed = false;

  @override
  void add(Uint8List event) {
    if (_closed) {
      throw StateError('sink closed');
    }
    if (_channel.canSend) {
      _channel.send(event).ignore();
    }
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {
    _closed = true;
    var status = error is SwitchboardException
        ? error.status
        : Status.of(StatusCode.internal, '$error');
    if (status.isApplicationCode) {
      status = Status.of(StatusCode.unknown, '$status');
    }
    unawaited(_channel.close(status));
  }

  @override
  Future<void> addStream(Stream<Uint8List> stream) async {
    await for (final event in stream) {
      if (_closed) {
        break;
      }
      if (_channel.canSend) {
        try {
          await _channel.send(event);
        } on SwitchboardException catch (e) {
          if (e.code != StatusCode.failedPrecondition) {
            rethrow;
          }
        }
      }
    }
  }

  @override
  Future<void> close() {
    _closed = true;
    return _channel.close();
  }

  @override
  Future<void> get done => _channel.done;
}
