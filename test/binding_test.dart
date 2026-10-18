/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

// QuicBindingConnection and QuicChannel over the memory provider: channel
// ids, records, the close handshake (CLOSE records, resets, STOP_SENDING,
// the confirmation timeout), flow control, priorities, openAfter, GOAWAY
// and the ends of the connection, the PING barrier after GOAWAY, resets and
// STOP_SENDING without a code over WebTransport, keep-alive, the resource
// limits of the binding page, and identification at the connection level.

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/core.dart';
import 'package:switchboard_quic/core.dart';
import 'package:test/test.dart';

import 'harness.dart';
import 'memory_provider.dart';
import 'review_cases.dart';

/// Every channel of [connection] delivered to [into].
void collect(QuicBindingConnection connection, List<MuxChannel> into) =>
    connection.incoming.listen(into.add);

/// The channel [connection] delivers next.
Future<MuxChannel> nextChannel(QuicBindingConnection connection) =>
    connection.incoming.first.timeout(limit);

/// [connection]'s end of the memory stream the raw peer holds as [stream].
MemoryQuicStream bindingEnd(
  QuicBindingConnection connection,
  QuicStream stream,
) {
  final ordinal = (stream as MemoryQuicStream).info.ordinal;
  return (connection.session as MemoryQuicSession).streams.firstWhere(
    (s) => s.info.ordinal == ordinal,
  );
}

/// A channel a raw peer opened on an acceptor binding, delivered and
/// listened to.
class OpenedChannel {
  OpenedChannel._(this.connection, this.raw, this.stream, this.channel) {
    channel.stream.listen(received.add, onDone: incomingDone.complete);
  }

  /// Channel [id], opened by the raw peer of a new acceptor binding over a
  /// memory session flagged WebTransport ([isWebTransport]), with [data]
  /// after its OPEN record.
  static Future<OpenedChannel> start({
    List<int> data = const [],
    bool isWebTransport = true,
    int id = 2,
    MuxOptions options = fast,
  }) async {
    final (connection, raw) = await bindingAndRaw(
      isWebTransport: isWebTransport,
      options: options,
    );
    return _open(
      connection,
      raw,
      StreamIterator(connection.incoming),
      id,
      data,
    );
  }

  static Future<OpenedChannel> _open(
    QuicBindingConnection connection,
    RawPeer raw,
    StreamIterator<MuxChannel> incoming,
    int id,
    List<int> data,
  ) async {
    final stream = await raw.openRaw([
      ...encodeOpenRecord(id, const []),
      ...data,
    ]);
    expect(await incoming.moveNext().timeout(limit), isTrue);
    return OpenedChannel._(connection, raw, stream, incoming.current)
      .._incoming = incoming;
  }

  final QuicBindingConnection connection;
  final RawPeer raw;

  /// The raw peer's end of the channel's stream.
  final QuicStream stream;
  final MuxChannel channel;
  final List<Uint8List> received = [];
  final Completer<void> incomingDone = Completer<void>();
  late final StreamIterator<MuxChannel> _incoming;

  MemoryQuicStream get rawStream => stream as MemoryQuicStream;

  /// Channel [id] of the same raw peer, on the same connection.
  Future<OpenedChannel> another(int id) =>
      _open(connection, raw, _incoming, id, const []);
}

/// Whether [future] has completed, checked after the current microtasks.
Future<bool> completed(Future<Object?> future) async {
  var done = false;
  future.then((_) => done = true, onError: (Object _) => done = true).ignore();
  await Future<void>.delayed(Duration.zero);
  return done;
}

/// Runs [body] in a zone that records the timers created in it, lets
/// [ms] pass once it completed, and returns the durations of the timers
/// still active then: what the ends [body] went through left behind.
Future<List<Duration>> timersLeftBehind(
  Future<void> Function() body, {
  int ms = 100,
}) async {
  final timers = <(Timer, Duration)>[];
  await runZoned(
    () async {
      await body();
      await settle(ms);
    },
    zoneSpecification: ZoneSpecification(
      createTimer: (self, parent, zone, duration, callback) {
        final timer = parent.createTimer(zone, duration, callback);
        timers.add((timer, duration));
        return timer;
      },
      createPeriodicTimer: (self, parent, zone, period, callback) {
        final timer = parent.createPeriodicTimer(zone, period, callback);
        timers.add((timer, period));
        return timer;
      },
    ),
  );
  return [
    for (final (timer, duration) in timers)
      if (timer.isActive) duration,
  ];
}

late CredentialIssuer authority;
late HolderKey holder;

Future<CredentialVerifier> verifier() async {
  final v = CredentialVerifier();
  await v.addIssuer(authority);
  return v;
}

Future<Credential> credentialOf(String identity) => authority.issue(
  kind: CredentialKind.node,
  identity: identity,
  holderKey: holder.publicKey,
);

/// A verifier whose answer the test gives.
class HeldVerifier extends CredentialVerifier {
  final Completer<Credential> result = Completer<Credential>();
  int calls = 0;

  @override
  Future<Credential> verify(Uint8List bytes, {DateTime? now}) {
    calls++;
    return result.future;
  }
}

void main() {
  reviewCases();
  setUpAll(() async {
    authority = await CredentialIssuer.ed25519FromSeed(
      Name('auth1'),
      Uint8List.fromList(List.generate(32, (i) => 7 * i)),
    );
    holder = await HolderKey.generate();
  });

  group('channel ids', () {
    test('even from 2 for the initiator, odd from 3 for the acceptor, '
        'increasing, the same at both ends, never reused', () async {
      final (a, b) = await connectionPair();
      final atA = <MuxChannel>[];
      final atB = <MuxChannel>[];
      collect(a, atA);
      collect(b, atB);
      final fromA = [for (var i = 0; i < 3; i++) a.open(Uint8List(0))];
      final fromB = [for (var i = 0; i < 2; i++) b.open(Uint8List(0))];
      expect(fromA.map((c) => c.id), [2, 4, 6]);
      expect(fromB.map((c) => c.id), [3, 5]);
      await until(() => atA.length == 2 && atB.length == 3);
      expect(atB.map((c) => c.id), [2, 4, 6]);
      expect(atA.map((c) => c.id), [3, 5]);
      expect(b.channelWithId(4), same(atB[1]));
      // Closed both ways, an id is never used again.
      for (final c in atB) {
        c.stream.listen((_) {});
      }
      await fromA.first.close();
      expect(a.channelWithId(2), isNull);
      expect(a.open(Uint8List(0)).id, 8);
    });

    test('the reserved ids are skipped, and a side that used every id of '
        'its parity opens no more', () async {
      final (a, b) = await connectionPair();
      b.nextChannelIdForTesting = 0xFFFD;
      expect(b.open(Uint8List(0)).id, 0xFFFD);
      expect(b.open(Uint8List(0)).id, 0x10001);
      a.nextChannelIdForTesting = 0xFFFEFFFFFFFE;
      expect(a.open(Uint8List(0)).id, 0xFFFEFFFFFFFE);
      expect(a.open(Uint8List(0)).id, 0xFFFF00000002);
      a.nextChannelIdForTesting = 0xFFFFFFFFFFFE;
      expect(a.open(Uint8List(0)).id, 0xFFFFFFFFFFFE);
      expect(
        () => a.open(Uint8List(0)),
        throwsCode(StatusCode.resourceExhausted),
      );
      expect(() => a.nextChannelIdForTesting = 3, throwsArgumentError);
      // The peer sees the long ids as they are.
      final seen = <MuxChannel>[];
      collect(b, seen);
      await until(() => seen.length == 3);
      expect(seen.map((c) => c.id), [
        0xFFFEFFFFFFFE,
        0xFFFF00000002,
        0xFFFFFFFFFFFE,
      ]);
    });

    test('the OPEN record is the first thing on the stream, written as the '
        'channel opens', () async {
      final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
      final channel = connection.open(bytes('payload'));
      final stream = await raw.nextStream();
      final reader = RecordReader(stream);
      final open = await reader.next(limit: 1 << 20);
      expect(open!.command, QuicRecordCommand.open);
      final (id, payload) = decodeOpenBody(open.body);
      expect(id, 2);
      expect(text(payload), 'payload');
      await channel.send(bytes('x'));
      final data = await reader.next(limit: 1 << 20);
      expect(data!.command, QuicRecordCommand.data);
      expect(text(data.body), 'x');
    });

    test('channels arriving before the control stream are handled under '
        'the defaults', () async {
      final (connection, raw) = await bindingAndRaw(rawControl: false);
      final arriving = nextChannel(connection);
      await raw.openRaw([
        ...encodeOpenRecord(2, bytes('early')),
        ...encodeDataRecord(Uint8List(quicDefaultRecordLimit)),
      ]);
      final channel = await arriving;
      expect(text(channel.openPayload), 'early');
      expect(
        (await channel.stream.first.timeout(limit)).length,
        quicDefaultRecordLimit,
      );
      await raw.openControl();
      expect((await raw.nextControl()).type, quicHelloType);
      expect(connection.isOpen, isTrue);
    });

    test(
      'a stream reset before its OPEN record is complete is ignored',
      () async {
        final (connection, raw) = await bindingAndRaw();
        final seen = <MuxChannel>[];
        collect(connection, seen);
        final stream = await raw.openRaw(hexBytes('06 00 00'));
        await settle();
        stream.reset(1);
        await settle(50);
        expect(seen, isEmpty);
        expect(connection.isOpen, isTrue);
        await raw.sendControl(MuxControlMessage.ping(bytes('alive')));
        final pong = await raw.nextControlOf(MuxControlType.pong.code);
        expect(text(pong.payload), 'alive');
      },
    );
  });

  group('subframes', () {
    test('whole and in order, empty ones included, at their record\'s '
        'cost', () async {
      final (a, b) = await connectionPair();
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      expect(channel.sendCost(10), 14);
      expect(channel.sendCost(0), 4);
      final frames = [
        bytes('one'),
        Uint8List(0),
        pattern(30000),
        bytes('four'),
        Uint8List(0),
      ];
      for (final frame in frames) {
        unawaited(channel.send(frame));
      }
      await channel.close();
      final received = await (await arriving).stream.toList().timeout(limit);
      expect(received, frames);
    });

    test('the largest subframe is the peer\'s record limit, which its HELLO '
        'raises', () async {
      final (a, b) = await connectionPair(
        acceptorQuic: const QuicBindingOptions(recordLimit: 1 << 20),
      );
      await until(() => a.peerHello != null);
      expect(a.peerRecordLimit, 1 << 20);
      expect(b.peerRecordLimit, quicDefaultRecordLimit);
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      expect(channel.maxSubframeLength, 1 << 20);
      final big = pattern(400000);
      await channel.send(big);
      final remote = await arriving;
      expect(await remote.stream.first.timeout(limit), big);
      expect(remote.maxSubframeLength, quicDefaultRecordLimit);
      expect(
        () => remote.send(Uint8List(quicDefaultRecordLimit + 1)),
        throwsCode(StatusCode.frameTooLarge),
      );
    });

    test('a record over the record limit ends the connection with '
        'FRAME_TOO_LARGE, its body unread', () async {
      final (connection, raw) = await bindingAndRaw();
      connection.incoming.listen((c) => c.stream.listen((_) {}));
      final header = Uint8List(4);
      writeQuicRecordHeader(
        header,
        0,
        QuicRecordCommand.data,
        quicDefaultRecordLimit + 1,
      );
      await raw.openRaw([...encodeOpenRecord(2, const []), ...header]);
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.frameTooLarge),
      );
      final end = await raw.end;
      expect(end.code, StatusCode.frameTooLarge.code);
      expect(end.reason, contains('32753'));
    });

    test('a bulk channel sends a payload in records of at most the chunk '
        'size and the peer\'s limit', () async {
      final (a, b) = await connectionPair(
        initiator: fast.copyWith(bulkChunkSize: 10000),
      );
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0))..priority = MuxPriority.bulk;
      final payload = pattern(100000);
      final receiving = (await arriving).stream.toList();
      await channel.send(payload);
      await channel.close();
      final chunks = await receiving.timeout(limit);
      expect(chunks.every((c) => c.length <= 10000), isTrue);
      expect(chunks.expand((c) => c).toList(), payload);
    });
  });

  group('close', () {
    test('a CLOSE record and FIN, confirmed by the peer\'s', () async {
      final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
      final channel = connection.open(Uint8List(0));
      unawaited(channel.send(bytes('last')));
      final closing = channel.close();
      final stream = await raw.nextStream();
      final (records, end) = await RawPeer.drain(stream);
      expect(records.map((r) => r.command), [
        QuicRecordCommand.open,
        QuicRecordCommand.data,
        QuicRecordCommand.close,
      ]);
      expect(records.last.body, isEmpty);
      expect(end, 'fin');
      expect(channel.state, MuxChannelState.halfClosedLocal);
      await stream.write(encodeCloseRecord(Status.ok));
      await stream.finish();
      await closing.timeout(limit);
      expect(await channel.done, Status.ok);
      expect(connection.openChannelCount, 0);
    });

    test('a status with its reason and the fields of MOVED travel in the '
        'CLOSE record', () async {
      final (a, b) = await connectionPair();
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      final remote = await arriving;
      remote.stream.listen((_) {});
      final moved = MovedStatus(owner: 0x1A2B, epoch: 7, reason: 'moved');
      await remote.close(moved.toStatus());
      final status = await channel.done.timeout(limit);
      expect(status.known, StatusCode.moved);
      final fields = MovedStatus.fromStatus(status);
      expect((fields.owner, fields.epoch, fields.reason), (0x1A2B, 7, 'moved'));
    });

    test('a rejection: a CLOSE record and STOP_SENDING with the status; the '
        'opener reports the record\'s status, reason included', () async {
      final (connection, raw) = await bindingAndRaw();
      connection.incoming.listen(
        (c) => unawaited(
          c.close(Status.of(StatusCode.notFound, 'no such service')),
        ),
      );
      final stream = await raw.openRaw([
        ...encodeOpenRecord(2, const []),
        ...encodeDataRecord(bytes('request')),
      ]);
      expect(await stream.stopped.timeout(limit), StatusCode.notFound.code);
      final (records, end) = await RawPeer.drain(stream);
      expect(records.single.command, QuicRecordCommand.close);
      expect(
        decodeCloseBody(records.single.body),
        Status.of(StatusCode.notFound, 'no such service'),
      );
      expect(end, 'fin');
      // Between two bindings the opener reports the record's status.
      final (a, b) = await connectionPair();
      b.incoming.listen(
        (c) => unawaited(c.close(Status.of(StatusCode.notFound, 'nope'))),
      );
      final channel = a.open(Uint8List(0));
      unawaited(channel.send(bytes('request')).catchError((Object _) {}));
      expect(
        await channel.done.timeout(limit),
        Status.of(StatusCode.notFound, 'nope'),
      );
    });

    test('a reset is the peer\'s close by its code: a partial record is '
        'discarded, and this side closes in turn', () async {
      final (connection, raw) = await bindingAndRaw();
      final arriving = nextChannel(connection);
      final stream = await raw.openRaw([
        ...encodeOpenRecord(2, const []),
        ...encodeDataRecord(bytes('whole')),
        ...hexBytes('05 00 00 00 01 02'),
      ]);
      final channel = await arriving;
      final received = <Uint8List>[];
      channel.stream.listen(received.add);
      await until(() => received.isNotEmpty);
      stream.reset(StatusCode.permissionDenied.code);
      expect(
        await channel.done.timeout(limit),
        Status.of(StatusCode.permissionDenied),
      );
      expect(received.map(text), ['whole']);
      final (records, end) = await RawPeer.drain(stream);
      expect(records.single.command, QuicRecordCommand.close);
      expect(records.single.body, isEmpty);
      expect(end, 'fin');
    });

    test('a reset code above 255 reads as UNKNOWN', () async {
      final (connection, raw) = await bindingAndRaw();
      final arriving = nextChannel(connection);
      final stream = await raw.openRaw(encodeOpenRecord(2, const []));
      final channel = await arriving;
      stream.reset(300);
      final status = await channel.done.timeout(limit);
      expect(status.known, StatusCode.unknown);
      expect(status.reason, contains('300'));
    });

    test('STOP_SENDING is the peer\'s close arriving early: this side resets '
        'with the code and reports the CLOSE record that follows', () async {
      final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
      final channel = connection.open(Uint8List(0));
      final stream = await raw.nextStream();
      final reader = RecordReader(stream);
      expect((await reader.next(limit: 100))!.command, QuicRecordCommand.open);
      stream.stop(StatusCode.notFound.code);
      await expectLater(
        reader.next(limit: 100),
        throwsA(
          isA<QuicStreamReset>().having(
            (e) => e.code,
            'code',
            StatusCode.notFound.code,
          ),
        ),
      );
      await until(() => !channel.canSend);
      expect(
        () => channel.send(bytes('late')),
        throwsCode(StatusCode.failedPrecondition),
      );
      await stream.write(
        encodeCloseRecord(Status.of(StatusCode.notFound, 'gone')),
      );
      await stream.finish();
      expect(
        await channel.done.timeout(limit),
        Status.of(StatusCode.notFound, 'gone'),
      );
    });

    test('the confirmation timeout sends STOP_SENDING DEADLINE_EXCEEDED; '
        'the close is OK when it went out', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        options: fast.copyWith(
          closeConfirmTimeout: const Duration(milliseconds: 150),
        ),
      );
      final channel = connection.open(Uint8List(0));
      final closing = channel.close();
      final stream = await raw.nextStream();
      expect(
        await stream.stopped.timeout(limit),
        StatusCode.deadlineExceeded.code,
      );
      await closing.timeout(limit);
      expect(await channel.done, Status.ok);
      expect(connection.openChannelCount, 0);
    });

    test('STOP_SENDING after the peer\'s CLOSE record ends a close in turn '
        'stalled at the peer\'s window at once', () async {
      // The peer closed, then gave up waiting for the confirmation, which
      // waits behind a window the peer does not read: its STOP_SENDING
      // ends the channel here too, not this side's own timeout (5 s).
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawEnd: const MemoryQuicEndConfig(streamWindow: 1000),
      );
      final channel = connection.open(Uint8List(0));
      channel.stream.listen((_) {});
      // The OPEN record (10 bytes) and this DATA record fill the window.
      await channel.send(pattern(1000 - 10 - 4)).timeout(limit);
      final stream = await raw.nextStream();
      await stream.write(encodeCloseRecord(Status.ok));
      await stream.finish();
      await until(() => channel.state == MuxChannelState.closed);
      stream.stop(StatusCode.deadlineExceeded.code);
      expect(
        await channel.done.timeout(const Duration(seconds: 2)),
        hasCode(StatusCode.deadlineExceeded),
      );
      expect(connection.openChannelCount, 0);
    });

    test('the confirmation timeout resets a direction whose CLOSE is stuck '
        'behind data the peer does not read: DEADLINE_EXCEEDED', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        options: fast.copyWith(
          closeConfirmTimeout: const Duration(milliseconds: 150),
        ),
        rawEnd: const MemoryQuicEndConfig(streamWindow: 1000),
      );
      final channel = connection.open(Uint8List(0));
      final sending = channel.send(pattern(5000));
      final closing = channel.close();
      final stream = await raw.nextStream();
      await closing.timeout(limit);
      expect(await channel.done, hasCode(StatusCode.deadlineExceeded));
      await expectLater(sending, throwsCode(StatusCode.failedPrecondition));
      final (_, end) = await RawPeer.drain(stream);
      expect(end, StatusCode.deadlineExceeded.code);
    });

    test(
      'a close whose CLOSE record waits behind data the peer does not '
      'read is reset with its own status at the confirmation timeout',
      () async {
        final (connection, raw) = await bindingAndRaw(
          bindingIsInitiator: true,
          options: fast.copyWith(
            closeConfirmTimeout: const Duration(milliseconds: 150),
          ),
          rawEnd: const MemoryQuicEndConfig(streamWindow: 1000),
        );
        final channel = connection.open(Uint8List(0));
        unawaited(channel.send(pattern(5000)).catchError((Object _) {}));
        final stream = await raw.nextStream();
        await channel.close(Status.of(StatusCode.notFound, 'gone'));
        expect(await channel.done, Status.of(StatusCode.notFound, 'gone'));
        // The peer reads nothing until the confirmation timed out.
        await settle(300);
        final (_, end) = await RawPeer.drain(stream);
        expect(end, StatusCode.notFound.code);
      },
    );

    test('a side that closes without reading still finds the peer\'s CLOSE '
        'behind what it did not take', () async {
      final (a, b) = await connectionPair(
        initiator: fast.copyWith(closeConfirmTimeout: limit),
        acceptor: fast.copyWith(closeConfirmTimeout: limit),
      );
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      unawaited(channel.send(pattern(3000)));
      final remote = await arriving;
      await settle();
      // Nobody listens on the remote side, which closes.
      final watch = Stopwatch()..start();
      await remote.close().timeout(limit);
      expect(watch.elapsed, lessThan(const Duration(seconds: 2)));
      expect(await remote.done, Status.ok);
      expect(await channel.done.timeout(limit), Status.ok);
    });

    test('a failure close does not wait: what the peer still sends is not '
        'read', () async {
      final (a, b) = await connectionPair();
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      final remote = await arriving;
      await channel.close(Status.of(StatusCode.aborted, 'enough'));
      expect(await channel.done, Status.of(StatusCode.aborted, 'enough'));
      remote.stream.listen((_) {});
      expect(
        await remote.done.timeout(limit),
        Status.of(StatusCode.aborted, 'enough'),
      );
    });
  });

  group('flow control', () {
    test(
      'a reader that stops stalls its own channel and nothing else',
      () async {
        final (a, b) = await connectionPair();
        final atB = <MuxChannel>[];
        collect(b, atB);
        final slow = a.open(bytes('slow'));
        final other = a.open(bytes('other'));
        await until(() => atB.length == 2);
        final paused = atB[0].stream.listen((_) {})..pause();
        final otherReceived = <Uint8List>[];
        atB[1].stream.listen(otherReceived.add);
        final stuck = slow.send(pattern(30000));
        for (var i = 0; i < 10; i++) {
          unawaited(slow.send(pattern(30000)));
        }
        await settle(50);
        for (var i = 0; i < 20; i++) {
          await other.send(bytes('$i'));
        }
        await until(() => otherReceived.length == 20);
        // The stalled channel holds at most one record beyond the window.
        expect(slow.isWritable, isFalse);
        expect(atB[0].bufferedBytes, lessThanOrEqualTo(30004));
        paused.resume();
        await stuck.timeout(limit);
        await until(() => slow.isWritable);
        await paused.cancel();
      },
    );

    test('with manualCredit the next record is read once the previous one '
        'is consumed; grant reads further ahead', () async {
      final (a, b) = await connectionPair();
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      for (var i = 0; i < 20; i++) {
        unawaited(channel.send(Uint8List(1000)));
      }
      final remote = await arriving;
      remote.manualCredit = true;
      final received = <Uint8List>[];
      remote.stream.listen(received.add);
      await settle(50);
      expect(received, hasLength(1));
      expect(remote.heldBytes, 1004);
      remote.consumed(1000);
      await until(() => received.length == 2);
      // Read ahead while what is held stays below the grant.
      remote.grant(5000);
      await until(() => received.length == 6);
      await settle(30);
      expect(received, hasLength(6));
      expect(remote.heldBytes, 5 * 1004);
      expect(remote.receiveWindow, greaterThan(0));
      remote.manualCredit = false;
      await until(() => received.length == 20);
    });
  });

  group('priorities', () {
    test('2 for the control stream, 1 for ordinary channels, 0 for bulk '
        'ones', () async {
      final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
      final initiator = raw.session.peer;
      final control = initiator.streams.first;
      expect(control.lastPriority, quicControlPriority);
      final channel = connection.open(Uint8List(0));
      await until(() => initiator.streams.length == 2);
      await settle();
      final stream = initiator.streams[1];
      expect(stream.lastPriority, quicOrdinaryPriority);
      channel.priority = MuxPriority.bulk;
      expect(stream.lastPriority, quicBulkPriority);
    });
  });

  group('openAfter', () {
    test('the child stream opens once what the parent was given before was '
        'taken, and may reach the peer first', () async {
      final network = MemoryQuicNetwork(
        delay: (info, {required fromInitiator}) =>
            Duration(milliseconds: info.ordinal == 1 ? 80 : 0),
      );
      final (a, b) = await connectionPair(network: network);
      final atB = <MuxChannel>[];
      collect(b, atB);
      final parent = a.open(bytes('parent'));
      unawaited(parent.send(bytes('before')));
      final child = parent.openAfter(bytes('child'));
      unawaited(child.send(bytes('child data')));
      await until(() => atB.isNotEmpty);
      expect(text(atB.first.openPayload), 'child');
      await until(() => atB.length == 2);
      expect(text(atB[1].openPayload), 'parent');
      expect(a.hasOrderedChannels, isFalse);
    });

    test('a child whose parent stops sending before its turn is never '
        'opened: CANCELLED', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawEnd: const MemoryQuicEndConfig(streamWindow: 1000),
      );
      final parent = connection.open(Uint8List(0));
      unawaited(parent.send(pattern(5000)).catchError((Object _) {}));
      final child = parent.openAfter(bytes('child'));
      final stream = await raw.nextStream();
      stream.reset(StatusCode.aborted.code);
      expect(await parent.done.timeout(limit), hasCode(StatusCode.aborted));
      expect(await child.done.timeout(limit), hasCode(StatusCode.cancelled));
      expect(raw.session.announced, hasLength(2));
    });
  });

  group('GOAWAY and the end of the connection', () {
    test('GOAWAY: no new channels either way, the open ones finish, then the '
        'session closes', () async {
      final (a, b) = await connectionPair();
      final atB = <MuxChannel>[];
      collect(b, atB);
      final channel = a.open(Uint8List(0));
      await until(() => atB.length == 1);
      final going = b.goAway();
      await until(() => a.peerGoingAway);
      expect(
        () => a.open(Uint8List(0)),
        throwsCode(StatusCode.failedPrecondition),
      );
      expect(
        () => b.open(Uint8List(0)),
        throwsCode(StatusCode.failedPrecondition),
      );
      // A bulk channel for the open channel still goes.
      final bulk = channel.openAfter(TalkBulkOpen(channel.id, 1).encode());
      await until(() => atB.length == 2);
      atB[1].stream.listen((_) {});
      await bulk.close();
      atB[0].stream.listen((_) {});
      await channel.close();
      await going.timeout(limit);
      expect(await a.done.timeout(limit), hasCode(StatusCode.goingAway));
      expect(await b.done.timeout(limit), hasCode(StatusCode.goingAway));
    });

    test('a channel the peer opened before it saw the GOAWAY is rejected '
        'GOING_AWAY, a bulk channel for an open one admitted', () async {
      final (connection, raw) = await bindingAndRaw();
      final atBinding = <MuxChannel>[];
      collect(connection, atBinding);
      await raw.openRaw(encodeOpenRecord(2, const []));
      await until(() => atBinding.length == 1);
      unawaited(connection.goAway());
      expect(
        (await raw.nextControlOf(MuxControlType.goAway.code)).goAwayStatus,
        hasCode(StatusCode.goingAway),
      );
      final late = await raw.openRaw(encodeOpenRecord(4, const []));
      expect(await late.stopped.timeout(limit), StatusCode.goingAway.code);
      final (records, _) = await RawPeer.drain(late);
      expect(
        decodeCloseBody(records.single.body),
        hasCode(StatusCode.goingAway),
      );
      await raw.openRaw(encodeOpenRecord(6, TalkBulkOpen(2, 1).encode()));
      await until(() => atBinding.length == 2);
      expect(atBinding[1].id, 6);
    });

    test('after GOAWAY, a bulk channel whose parent was admitted before it '
        'is admitted even once the parent ended; one for a parent never '
        'admitted is not', () async {
      final (connection, raw) = await bindingAndRaw();
      final atBinding = <MuxChannel>[];
      connection.incoming.listen((c) {
        atBinding.add(c);
        c.stream.listen((_) {});
      });
      final parent = await raw.openRaw(encodeOpenRecord(2, const []));
      // Another channel keeps the connection busy meanwhile.
      await raw.openRaw(encodeOpenRecord(4, const []));
      await until(() => atBinding.length == 2);
      unawaited(connection.goAway());
      await raw.nextControlOf(MuxControlType.goAway.code);
      final bulkPending = Completer<void>();
      connection.retainForDrain(2, bulkPending.future);
      addTearDown(() {
        if (!bulkPending.isCompleted) bulkPending.complete();
      });
      // The parent's close overtakes its bulk stream.
      await parent.write(encodeCloseRecord(Status.ok));
      await parent.finish();
      await until(() => connection.channelWithId(2) == null);
      await raw.openRaw(encodeOpenRecord(6, TalkBulkOpen(2, 1).encode()));
      await until(() => atBinding.length == 3);
      expect(atBinding[2].id, 6);
      final stray = await raw.openRaw(
        encodeOpenRecord(8, TalkBulkOpen(10, 1).encode()),
      );
      expect(await stray.stopped.timeout(limit), StatusCode.goingAway.code);
    });

    test(
      'a received application close counts as a GOAWAY with its status',
      () async {
        for (final (code, reason, expected) in [
          (0, '', Status.of(StatusCode.goingAway)),
          (14, 'maintenance', Status.of(StatusCode.unavailable, 'maintenance')),
          (300, 'odd', null),
        ]) {
          final (connection, raw) = await bindingAndRaw();
          final arriving = nextChannel(connection);
          await raw.openRaw(encodeOpenRecord(2, const []));
          final channel = await arriving;
          await raw.session.close(code, reason);
          final status = await connection.peerGoAwayStatus.timeout(limit);
          if (expected != null) {
            expect(status, expected);
          } else {
            expect(status.known, StatusCode.unknown);
          }
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.goingAway),
          );
          expect(
            await channel.done.timeout(limit),
            hasCode(StatusCode.goingAway),
          );
        }
      },
    );

    test('a lost session ends the connection and its channels with '
        'CONNECTION_LOST', () async {
      final (connection, raw) = await bindingAndRaw();
      final arriving = nextChannel(connection);
      await raw.openRaw(encodeOpenRecord(2, const []));
      final channel = await arriving;
      raw.session.lose();
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
      expect(
        await channel.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
    });

    test('close waits for the FIN of a channel still waiting for the peer\'s '
        'close', () async {
      final network = MemoryQuicNetwork(
        delay: (info, {required fromInitiator}) =>
            Duration(milliseconds: info.ordinal == 1 ? 60 : 0),
      );
      final (a, b) = await connectionPair(network: network);
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      final remote = await arriving;
      remote.stream.listen((_) {});
      unawaited(channel.close());
      await until(() => network.pairs.single.$1.streams[1].finished);
      await a.close();
      // The CLOSE arrived before the session ended.
      expect(await remote.done.timeout(limit), Status.ok);
    });

    test('close waits for the CLOSE records this side wrote to be '
        'acknowledged', () async {
      final network = MemoryQuicNetwork(
        delay: (info, {required fromInitiator}) =>
            Duration(milliseconds: info.ordinal == 1 ? 60 : 0),
      );
      final (a, b) = await connectionPair(network: network);
      final arriving = nextChannel(b);
      final channel = a.open(Uint8List(0));
      final remote = await arriving;
      remote.stream.listen((_) {});
      final remoteDone = remote.done;
      unawaited(remote.close());
      await until(() => channel.state != MuxChannelState.open);
      await channel.close();
      await a.close();
      // The confirming CLOSE arrived before the session closed.
      expect(await remoteDone.timeout(limit), Status.ok);
    });
  });

  group('the PING barrier after GOAWAY', () {
    test(
      'a second GOAWAY shares the wait and sends no second barrier',
      () async {
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(closeConfirmTimeout: Duration.zero),
        );
        final going = connection.goAway();
        final ping = await raw.nextControlOf(MuxControlType.ping.code);
        expect(connection.goAway(), same(going));
        final user = connection.ping(bytes('next'));
        user.ignore();
        expect((await raw.nextControl()).payload, bytes('next'));
        await raw.sendControl(MuxControlMessage.pong(bytes('next')));
        await user.timeout(limit);
        expect(await completed(going), isFalse);
        await raw.sendControl(MuxControlMessage.pong(ping.payload));
        await going.timeout(limit);
        await connection.goAway().timeout(limit);
      },
    );

    test(
      'keep-alive PONG is not the barrier; expiry ends an unbounded wait',
      () async {
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(
            closeConfirmTimeout: Duration.zero,
            keepAliveInterval: const Duration(milliseconds: 100),
            keepAliveTimeout: const Duration(seconds: 1),
          ),
        );
        final going = connection.goAway();
        final barrier = await raw.nextControlOf(MuxControlType.ping.code);
        final probe = await raw.nextControlOf(MuxControlType.ping.code);
        expect(probe.payload, isNot(barrier.payload));
        await raw.sendControl(MuxControlMessage.pong(probe.payload));
        await settle();
        expect(await completed(going), isFalse);
        await going.timeout(limit);
        expect((await raw.end).code, StatusCode.deadlineExceeded.code);
      },
    );

    test(
      'a pending OPEN that arrives during the barrier is drained too',
      () async {
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(goAwayGrace: const Duration(seconds: 5)),
        );
        final going = connection.goAway();
        final ping = await raw.nextControlOf(MuxControlType.ping.code);
        await settle();
        final open = encodeOpenRecord(2, const []);
        final stream = await raw.openRaw(open.sublist(0, 1));
        await settle(50);
        await raw.sendControl(MuxControlMessage.pong(ping.payload));
        await settle(50);
        expect(await completed(going), isFalse);
        await stream.write(Uint8List.sublistView(open, 1));
        final (records, _) = await RawPeer.drain(stream);
        expect(
          decodeCloseBody(records.single.body),
          hasCode(StatusCode.goingAway),
        );
        await going.timeout(limit);
      },
    );

    test(
      'a drain hold added while the PONG is pending still delays close',
      () async {
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(goAwayGrace: const Duration(seconds: 5)),
        );
        final going = connection.goAway();
        final ping = await raw.nextControlOf(MuxControlType.ping.code);
        await settle();
        final hold = Completer<void>();
        connection.retainForDrain(2, hold.future);
        await raw.sendControl(MuxControlMessage.pong(ping.payload));
        await settle(100);
        expect(await completed(going), isFalse);
        expect(raw.session.ended, isFalse);
        hold.complete();
        await going.timeout(limit);
      },
    );

    test(
      'the barrier payload differs from an outstanding explicit PING',
      () async {
        final (connection, raw) = await bindingAndRaw();
        final user = connection.ping(Uint8List(4));
        user.ignore();
        final first = await raw.nextControlOf(MuxControlType.ping.code);
        final going = connection.goAway();
        final barrier = await raw.nextControlOf(MuxControlType.ping.code);
        expect(barrier.payload, isNot(first.payload));
        await raw.sendControl(MuxControlMessage.pong(first.payload));
        await user.timeout(limit);
        expect(await completed(going), isFalse);
        await raw.sendControl(MuxControlMessage.pong(barrier.payload));
        await going.timeout(limit);
      },
    );

    test('the barrier PING evicts no application PING and counts toward '
        'no cap; it fails as the oldest when a later PING evicts, which '
        'ends an unbounded wait', () async {
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(closeConfirmTimeout: Duration.zero),
      );
      const cap = MuxConnection.maxPendingPings;
      // The application's PINGs evicted; the connection's end fails the
      // rest with its own status.
      var evicted = 0;
      void ping(String payload) => connection
          .ping(bytes(payload))
          .then<void>(
            (_) {},
            onError: (Object e) {
              if (e is SwitchboardException &&
                  e.code == StatusCode.deadlineExceeded) {
                evicted++;
              }
            },
          )
          .ignore();
      for (var i = 0; i < cap; i++) {
        ping('app $i');
      }
      final going = connection.goAway();
      await raw.nextControlOf(MuxControlType.goAway.code);
      expect((await raw.nextControl()).knownType, MuxControlType.ping);
      await settle();
      expect(evicted, 0);
      // The application's PINGs keep their own cap: one more evicts one.
      ping('more 0');
      await settle();
      expect(evicted, 1);
      expect(await completed(going), isFalse);
      // Once the barrier is the oldest, the next eviction takes it too.
      for (var i = 1; i < cap; i++) {
        ping('more $i');
      }
      await settle();
      expect(evicted, cap);
      expect(await completed(going), isFalse);
      ping('last');
      await going.timeout(limit);
      expect(evicted, cap + 1);
      expect((await raw.end).code, 0);
    });

    test(
      'an expired barrier leaves no pending PING while the drain continues',
      () async {
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(
            closeConfirmTimeout: const Duration(milliseconds: 100),
            goAwayGrace: const Duration(seconds: 5),
          ),
        );
        final hold = Completer<void>();
        connection.retainForDrain(2, hold.future);
        final user = connection.ping(bytes('user'));
        user.ignore();
        await raw.nextControlOf(MuxControlType.ping.code);
        final going = connection.goAway();
        final barrier = await raw.nextControlOf(MuxControlType.ping.code);
        await settle(200);
        for (var i = 0; i < MuxConnection.maxPendingPings - 1; i++) {
          connection.ping(bytes('user $i')).ignore();
        }
        expect(await completed(user), isFalse);
        await raw.sendControl(MuxControlMessage.pong(barrier.payload));
        await raw.sendControl(MuxControlMessage.pong(bytes('user')));
        await user.timeout(limit);
        hold.complete();
        await going.timeout(limit);
      },
    );

    test('a goAwayGrace of zero and a drain hold that never releases skip '
        'the drain, not the barrier', () async {
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(goAwayGrace: Duration.zero),
      );
      final arriving = nextChannel(connection);
      await raw.openRaw(encodeOpenRecord(2, const []));
      final channel = await arriving;
      channel.stream.listen((_) {});
      connection.retainForDrain(2, Completer<void>().future);
      final going = connection.goAway();
      final ping = await raw.nextControlOf(MuxControlType.ping.code);
      await settle(200);
      expect(raw.session.ended, isFalse);
      expect(await completed(going), isFalse);
      await raw.sendControl(MuxControlMessage.pong(ping.payload));
      await going.timeout(limit);
      expect((await raw.end).code, 0);
      expect(await channel.done.timeout(limit), hasCode(StatusCode.goingAway));
    });

    test('with no channel open, the session closes only once the PONG of '
        'the PING sent right after the GOAWAY record is back', () async {
      final (connection, raw) = await bindingAndRaw();
      final going = connection.goAway();
      await raw.nextControlOf(MuxControlType.goAway.code);
      final ping = await raw.nextControl();
      expect(ping.knownType, MuxControlType.ping);
      // Well past the GOAWAY grace: the drain is done, the PONG withheld.
      await settle(400);
      expect(raw.session.ended, isFalse);
      expect(await completed(going), isFalse);
      expect(await completed(connection.done), isFalse);
      await raw.sendControl(MuxControlMessage.pong(ping.payload));
      await going.timeout(limit);
      final end = await raw.end;
      expect((end.code, end.byPeer, end.lost), (0, true, false));
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
    });

    test('the peer\'s own close ends the wait', () async {
      final (connection, raw) = await bindingAndRaw();
      final going = connection.goAway(Status.of(StatusCode.unavailable, 'x'));
      await raw.nextControlOf(MuxControlType.ping.code);
      await settle(300);
      expect(await completed(going), isFalse);
      final watch = Stopwatch()..start();
      await raw.session.close(0, '');
      await going.timeout(limit);
      // Long before the bound (closeConfirmTimeout, 5 s here).
      expect(watch.elapsed, lessThan(const Duration(seconds: 2)));
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
    });

    test('the bound, closeConfirmTimeout from the GOAWAY, ends the wait; '
        'a lost session too', () async {
      const bound = Duration(milliseconds: 400);
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(closeConfirmTimeout: bound),
      );
      final watch = Stopwatch()..start();
      final going = connection.goAway();
      await raw.nextControlOf(MuxControlType.ping.code);
      await going.timeout(limit);
      expect(
        watch.elapsed,
        greaterThanOrEqualTo(bound - const Duration(milliseconds: 20)),
      );
      final end = await raw.end;
      expect((end.code, end.byPeer), (0, true));
      // The end of the connection, lost or closed, ends it at once.
      final (other, otherRaw) = await bindingAndRaw();
      final otherGoing = other.goAway();
      await otherRaw.nextControlOf(MuxControlType.ping.code);
      otherRaw.session.lose();
      await otherGoing.timeout(const Duration(seconds: 2));
      expect(await other.done.timeout(limit), hasCode(StatusCode.goingAway));
    });

    test('a failure close, and close() with or without a GOAWAY before it, '
        'do not wait for a PONG', () async {
      // A protocol error after the GOAWAY: closed at once with its status.
      final (failing, failingRaw) = await bindingAndRaw();
      final going = failing.goAway();
      await failingRaw.nextControlOf(MuxControlType.ping.code);
      await failingRaw.sendControl(
        MuxControlMessage(MuxControlType.limits.code, Uint8List(12)),
      );
      expect((await failingRaw.end).code, StatusCode.protocolError.code);
      await going.timeout(const Duration(seconds: 1));
      // close() after a GOAWAY closes now.
      final (closing, closingRaw) = await bindingAndRaw();
      final closingGoing = closing.goAway();
      await closingRaw.nextControlOf(MuxControlType.ping.code);
      await closing.close().timeout(const Duration(seconds: 1));
      await closingGoing.timeout(const Duration(seconds: 1));
      expect((await closingRaw.end).code, 0);
      // close() alone sends no GOAWAY and waits for nothing.
      final (plain, plainRaw) = await bindingAndRaw();
      await plain.close().timeout(const Duration(seconds: 1));
      expect((await plainRaw.end).code, 0);
    });

    test('with a channel open, the close waits for the drain and the '
        'barrier together; the grace still applies', () async {
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(goAwayGrace: const Duration(seconds: 5)),
      );
      final arriving = nextChannel(connection);
      final stream = await raw.openRaw(encodeOpenRecord(2, const []));
      final channel = await arriving;
      channel.stream.listen((_) {});
      final going = connection.goAway();
      await raw.nextControlOf(MuxControlType.goAway.code);
      final ping = await raw.nextControl();
      // The PONG first: the open channel keeps the session.
      await raw.sendControl(MuxControlMessage.pong(ping.payload));
      await settle(200);
      expect(raw.session.ended, isFalse);
      await stream.write(encodeCloseRecord(Status.ok));
      await stream.finish();
      await going.timeout(limit);
      expect(await channel.done.timeout(limit), Status.ok);
      expect((await raw.end).code, 0);

      // The channel first: the withheld PONG keeps the session.
      final (second, secondRaw) = await bindingAndRaw(
        options: fast.copyWith(goAwayGrace: const Duration(seconds: 5)),
      );
      final secondArriving = nextChannel(second);
      final secondStream = await secondRaw.openRaw(
        encodeOpenRecord(2, const []),
      );
      final secondChannel = await secondArriving;
      secondChannel.stream.listen((_) {});
      final secondGoing = second.goAway();
      await secondRaw.nextControlOf(MuxControlType.goAway.code);
      final secondPing = await secondRaw.nextControl();
      await secondStream.write(encodeCloseRecord(Status.ok));
      await secondStream.finish();
      expect(await secondChannel.done.timeout(limit), Status.ok);
      await settle(300);
      expect(secondRaw.session.ended, isFalse);
      await secondRaw.sendControl(MuxControlMessage.pong(secondPing.payload));
      await secondGoing.timeout(limit);
      expect((await secondRaw.end).code, 0);

      // The grace (200 ms) passes with the channel still open, the PONG
      // back: the session closes all the same.
      final (third, thirdRaw) = await bindingAndRaw();
      final thirdArriving = nextChannel(third);
      await thirdRaw.openRaw(encodeOpenRecord(2, const []));
      final thirdChannel = await thirdArriving;
      thirdChannel.stream.listen((_) {});
      final thirdGoing = third.goAway();
      await thirdRaw.nextControlOf(MuxControlType.goAway.code);
      final thirdPing = await thirdRaw.nextControl();
      await thirdRaw.sendControl(MuxControlMessage.pong(thirdPing.payload));
      await thirdGoing.timeout(limit);
      expect((await thirdRaw.end).code, 0);
      expect(
        await thirdChannel.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
    });

    test('a side that sent GOAWAY and reads the peer\'s with no channel left '
        'closes only once its PONG is back as well', () async {
      final (connection, raw) = await bindingAndRaw();
      final going = connection.goAway();
      await raw.nextControlOf(MuxControlType.goAway.code);
      final ping = await raw.nextControl();
      await raw.sendControl(
        MuxControlMessage.goAway(Status.of(StatusCode.goingAway)),
      );
      await until(() => connection.peerGoingAway);
      await settle(300);
      expect(raw.session.ended, isFalse);
      await raw.sendControl(MuxControlMessage.pong(ping.payload));
      await going.timeout(limit);
      expect((await raw.end).code, 0);
    });

    test('between two bindings the PONG is back at once', () async {
      final (a, b) = await connectionPair();
      final watch = Stopwatch()..start();
      await a.goAway(Status.of(StatusCode.goingAway, 'bye')).timeout(limit);
      expect(watch.elapsed, lessThan(const Duration(seconds: 2)));
      expect(
        await b.peerGoAwayStatus.timeout(limit),
        Status.of(StatusCode.goingAway, 'bye'),
      );
      expect(
        await b.done.timeout(limit),
        Status.of(StatusCode.goingAway, 'bye'),
      );
    });
  });

  group('resets and STOP_SENDING without a code over WebTransport', () {
    for (final reset in [true, false]) {
      test('a short confirmation timeout waits for a held '
          '${reset ? 'reset' : 'STOP_SENDING'}', () async {
        final c = await OpenedChannel.start(
          options: fast.copyWith(
            closeConfirmTimeout: const Duration(milliseconds: 100),
          ),
        );
        if (reset) {
          c.rawStream.resetWithoutCode();
        } else {
          c.rawStream.stopWithoutCode();
        }
        await settle(50);
        final closing = c.channel.close();
        await settle(200);
        expect(await completed(closing), isFalse);
        final local = bindingEnd(c.connection, c.stream);
        expect(local.stops, isEmpty);
        expect(local.resets, isEmpty);
        await c.raw.session.close(0, '');
        await closing.timeout(limit);
        expect(await c.channel.done, hasCode(StatusCode.goingAway));
      });
    }

    test(
      'an expired confirmation is applied once a STOP_SENDING hold expires',
      () async {
        final c = await OpenedChannel.start(
          options: fast.copyWith(
            closeConfirmTimeout: const Duration(milliseconds: 100),
          ),
        );
        c.rawStream.stopWithoutCode();
        await settle(50);
        final watch = Stopwatch()..start();
        await c.channel.close().timeout(limit);
        expect(watch.elapsed, greaterThan(const Duration(seconds: 1)));
        expect(await c.channel.done, hasCode(StatusCode.unknown));
        expect(bindingEnd(c.connection, c.stream).stops, [
          StatusCode.deadlineExceeded.code,
        ]);
      },
    );

    for (final heldParent in [true, false]) {
      test('Talk waits for the session status with a held '
          '${heldParent ? 'parent' : 'bulk stream'}', () async {
        final (connection, raw) = await bindingAndRaw(isWebTransport: true);
        final arrived = Completer<TalkChannel>();
        connection.incoming.listen((channel) {
          if (TalkBulkOpen.isBulk(ChannelAddress.decode(channel.openPayload))) {
            TalkChannel.adoptBulk(channel);
          } else {
            arrived.complete(TalkChannel(channel));
          }
        });
        final parent = await raw.openRaw(
          encodeOpenRecord(2, ChannelAddress(type: Name('echo')).encode()),
        ) as MemoryQuicStream;
        final talk = await arrived.future.timeout(limit);
        final response = talk.request('REQ', Uint8List(0));
        response.ignore();
        final request = await RecordReader(parent)
            .next(limit: quicDefaultRecordLimit);
        final requestId = TalkFrame.decode(request!.body).requestId;
        await parent.write(
          encodeDataRecord(
            TalkFrame(
              kind: TalkKind.message,
              responseId: requestId,
              payload: Uint8List(0),
            ).withBulk(TalkBulkReference(1, length: 3)).encode(),
          ),
        );
        final bulk = await raw.openRaw(
          encodeOpenRecord(4, TalkBulkOpen(2, 1).encode()),
        ) as MemoryQuicStream;
        await until(() => connection.channelWithId(4) != null);
        final held = connection.channelWithId(heldParent ? 2 : 4)!;
        (heldParent ? parent : bulk).resetWithoutCode();
        await settle(50);
        expect(await completed(held.done), isFalse);
        expect(await completed(response), isFalse);
        await raw.session.close(0, '');
        expect(await held.done.timeout(limit), hasCode(StatusCode.goingAway));
        await expectLater(response, throwsCode(StatusCode.goingAway));
      });
    }

    test(
      'STOP_SENDING pauses provider reads inside a record until the grace',
      () async {
        final (connection, raw) = await bindingAndRaw(
          isWebTransport: true,
          bindingEnd: const MemoryQuicEndConfig(streamWindow: 32),
        );
        final arriving = nextChannel(connection);
        final stream = await raw.openRaw(
          encodeOpenRecord(2, const []),
        ) as MemoryQuicStream;
        final channel = await arriving;
        final received = <Uint8List>[];
        channel.stream.listen(received.add);
        stream.stopWithoutCode();
        await settle(50);
        final writing = stream.write(encodeDataRecord(Uint8List(128)));
        writing.ignore();
        await settle(100);
        expect(await completed(writing), isFalse);
        expect(received, isEmpty);
        await writing.timeout(limit);
        await until(() => received.isNotEmpty);
        expect(received.single, hasLength(128));
        await stream.write(encodeCloseRecord(Status.ok));
        await stream.finish();
        expect(await channel.done.timeout(limit), hasCode(StatusCode.unknown));
      },
    );

    test(
      'a held reset after STOP_SENDING releases a paused record and credit',
      () async {
        final c = await OpenedChannel.start();
        c.channel.manualCredit = true;
        await c.stream.write(encodeDataRecord(bytes('first')));
        await until(() => c.channel.heldBytes > 0);
        c.rawStream.stopWithoutCode();
        await settle(50);
        c.channel.consumed(5);
        await c.stream.write(encodeDataRecord(bytes('discarded')));
        await settle(50);
        c.rawStream.resetWithoutCode();
        await c.incomingDone.future.timeout(limit);
        expect(c.received.map(text), ['first']);
        expect(c.channel.receiveWindow, 0);
        c.channel.grant(0xFFFFFFFF);
        expect(c.channel.receiveWindow, 0);
        await c.raw.session.close(0, '');
        expect(
          await c.channel.done.timeout(limit),
          hasCode(StatusCode.goingAway),
        );
        expect(c.channel.heldBytes, 0);
      },
    );

    for (final path in ['read', 'write', 'FIN']) {
      test('a codeless $path failure is held until the session ends', () async {
        final c = await OpenedChannel.start();
        final local = bindingEnd(c.connection, c.stream);
        await settle();
        switch (path) {
          case 'read':
            local.failRead(const QuicStreamReset(null));
          case 'write':
            local.writeFailure = const QuicStreamStopped(null);
            await expectLater(
              c.channel.send(bytes('x')),
              throwsCode(StatusCode.failedPrecondition),
            );
          case 'FIN':
            local.finishFailure = const QuicStreamStopped(null);
            c.channel.close().ignore();
        }
        await settle(50);
        expect(await completed(c.channel.done), isFalse);
        expect(local.resets, isEmpty);
        expect(local.stops, isEmpty);
        await c.raw.session.close(0, '');
        expect(
          await c.channel.done.timeout(limit),
          hasCode(StatusCode.goingAway),
        );
      });
    }

    test(
      'an application failure close during a hold keeps its own status',
      () async {
        final c = await OpenedChannel.start();
        c.rawStream.resetWithoutCode();
        await c.incomingDone.future.timeout(limit);
        final status = Status.of(StatusCode.cancelled, 'local');
        await c.channel.close(status).timeout(limit);
        expect(await c.channel.done, status);
        expect(c.connection.isOpen, isTrue);
        // The cancelled hold must not subsequently send UNKNOWN or end the session.
        await settle(2100);
        expect(await c.channel.done, status);
        expect(bindingEnd(c.connection, c.stream).resets, isEmpty);
        expect(c.connection.isOpen, isTrue);
      },
    );

    for (final reset in [true, false]) {
      test('buffered DATA is not delivered during a held '
          '${reset ? 'reset' : 'STOP_SENDING'}', () async {
        final (connection, raw) = await bindingAndRaw(isWebTransport: true);
        final arriving = nextChannel(connection);
        final stream = await raw.openRaw([
          ...encodeOpenRecord(2, const []),
          ...encodeDataRecord(bytes('buffered')),
        ]) as MemoryQuicStream;
        final channel = await arriving;
        await until(() => channel.bufferedBytes > 0);
        if (reset) {
          stream.resetWithoutCode();
        } else {
          stream.stopWithoutCode();
        }
        await settle(50);
        final received = <Uint8List>[];
        channel.stream.listen(received.add);
        await settle(50);
        expect(received, isEmpty);
        expect(await completed(channel.done), isFalse);
        await raw.session.close(0, '');
        expect(
          await channel.done.timeout(limit),
          hasCode(StatusCode.goingAway),
        );
        expect(received, isEmpty);
      });
    }

    test('a reset is held: nothing more is delivered, a partial record is '
        'discarded, nothing is sent; the session\'s graceful close within the '
        'grace ends the channel GOING_AWAY', () async {
      final c = await OpenedChannel.start(
        data: [
          ...encodeDataRecord(bytes('whole')),
          ...hexBytes('05 00 00 00 01 02'),
        ],
      );
      await until(() => c.received.isNotEmpty);
      c.rawStream.resetWithoutCode();
      await c.incomingDone.future.timeout(limit);
      await settle(200);
      expect(await completed(c.channel.done), isFalse);
      expect(c.channel.state, MuxChannelState.open);
      expect(c.channel.receiveWindow, 0);
      final local = bindingEnd(c.connection, c.stream);
      void sentNothing() {
        expect(local.finished, isFalse);
        expect(local.resets, isEmpty);
        expect(local.stops, isEmpty);
      }

      sentNothing();
      await c.raw.session.close(0, '');
      expect(
        await c.channel.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
      expect(c.received.map(text), ['whole']);
      sentNothing();
    });

    test('any other end of the session within the grace ends a held channel '
        'as the connection\'s other channels end, never UNKNOWN', () async {
      // A close with another status.
      final c = await OpenedChannel.start();
      final other = await c.another(4);
      c.rawStream.resetWithoutCode();
      await settle(100);
      await c.raw.session.close(StatusCode.unavailable.code, 'upgrade');
      final held = await c.channel.done.timeout(limit);
      expect(held, await other.channel.done.timeout(limit));
      expect(held.known, StatusCode.goingAway);
      // A lost session.
      final lost = await OpenedChannel.start();
      lost.rawStream.resetWithoutCode();
      await settle(100);
      lost.raw.session.lose();
      expect(
        await lost.channel.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
      // This side's own close.
      final closed = await OpenedChannel.start();
      closed.rawStream.resetWithoutCode();
      await settle(100);
      await closed.connection.close();
      expect(
        await closed.channel.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
    });

    test('with no session end within the grace, a held reset is the peer\'s '
        'close, UNKNOWN, and this side closes in turn', () async {
      final c = await OpenedChannel.start();
      final watch = Stopwatch()..start();
      c.rawStream.resetWithoutCode();
      final status = await c.channel.done.timeout(limit);
      expect(status.known, StatusCode.unknown);
      expect(
        watch.elapsed,
        greaterThanOrEqualTo(
          QuicBindingConnection.webTransportSessionGoneGrace -
              const Duration(milliseconds: 50),
        ),
      );
      final (records, end) = await RawPeer.drain(c.stream);
      expect(records.single.command, QuicRecordCommand.close);
      expect(records.single.body, isEmpty);
      expect(end, 'fin');
    });

    test('this side\'s own close waits for the outcome too', () async {
      final c = await OpenedChannel.start();
      c.rawStream.resetWithoutCode();
      await settle(50);
      final closing = c.channel.close();
      // Its CLOSE record and FIN go, as they would anyway; the channel
      // ends with the session.
      final (records, end) = await RawPeer.drain(c.stream);
      expect(records.single.command, QuicRecordCommand.close);
      expect(end, 'fin');
      await settle(100);
      expect(await completed(closing), isFalse);
      await c.raw.session.close(0, '');
      await closing.timeout(limit);
      expect(await c.channel.done, hasCode(StatusCode.goingAway));
    });

    test('a reset held after this side\'s close went: the session\'s close '
        'ends the channel GOING_AWAY, the grace UNKNOWN', () async {
      for (final sessionEnds in [true, false]) {
        final c = await OpenedChannel.start();
        final closing = c.channel.close();
        final (records, end) = await RawPeer.drain(c.stream);
        expect(records.single.command, QuicRecordCommand.close);
        expect(end, 'fin');
        c.rawStream.resetWithoutCode();
        await settle(100);
        expect(await completed(closing), isFalse);
        if (sessionEnds) {
          await c.raw.session.close(0, '');
        }
        await closing.timeout(limit);
        expect(
          await c.channel.done,
          hasCode(sessionEnds ? StatusCode.goingAway : StatusCode.unknown),
        );
        expect(bindingEnd(c.connection, c.stream).resets, isEmpty);
      }
    });

    test('a STOP_SENDING is held too: nothing more is read, nothing sent in '
        'answer; the session\'s close ends the channel GOING_AWAY', () async {
      final c = await OpenedChannel.start();
      c.rawStream.stopWithoutCode();
      await settle(50);
      await c.stream.write(encodeDataRecord(bytes('late')));
      await settle(200);
      expect(c.received, isEmpty);
      expect(await completed(c.channel.done), isFalse);
      final local = bindingEnd(c.connection, c.stream);
      expect(local.resets, isEmpty);
      expect(local.stops, isEmpty);
      await c.raw.session.close(0, '');
      expect(
        await c.channel.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
      expect(c.received, isEmpty);
    });

    test('with no session end within the grace, a held STOP_SENDING is the '
        'peer\'s close as any: UNKNOWN, and reading resumes', () async {
      final c = await OpenedChannel.start();
      final watch = Stopwatch()..start();
      c.rawStream.stopWithoutCode();
      await settle(50);
      await c.stream.write(encodeDataRecord(bytes('late')));
      await until(() => c.received.isNotEmpty);
      expect(
        watch.elapsed,
        greaterThanOrEqualTo(
          QuicBindingConnection.webTransportSessionGoneGrace -
              const Duration(milliseconds: 50),
        ),
      );
      expect(c.received.map(text), ['late']);
      expect(c.channel.canSend, isFalse);
      await c.stream.write(encodeCloseRecord(Status.ok));
      await c.stream.finish();
      expect((await c.channel.done.timeout(limit)).known, StatusCode.unknown);
    });

    test('a reset without a code after this side\'s STOP_SENDING is its '
        'confirmation: not held', () async {
      final c = await OpenedChannel.start();
      final watch = Stopwatch()..start();
      final closing = c.channel.close(Status.of(StatusCode.cancelled, 'no'));
      // Before the STOP_SENDING reaches the peer, whose stack then does not
      // answer it with a reset of its own.
      c.rawStream.resetWithoutCode();
      await closing.timeout(limit);
      expect(watch.elapsed, lessThan(const Duration(seconds: 1)));
      expect(await c.channel.done, Status.of(StatusCode.cancelled, 'no'));
    });

    test(
      'with closeConfirmTimeout zero, a held reset still ends with the '
      'session, or after the grace with this side\'s close in turn',
      () async {
        const unbounded = MuxOptions(
          goAwayGrace: Duration(milliseconds: 200),
          keepAliveInterval: null,
          closeConfirmTimeout: Duration.zero,
        );
        final closed = await OpenedChannel.start(options: unbounded);
        final expiring = await OpenedChannel.start(options: unbounded);
        closed.rawStream.resetWithoutCode();
        expiring.rawStream.resetWithoutCode();
        await settle(100);
        expect(await completed(closed.channel.done), isFalse);
        await closed.raw.session.close(0, '');
        expect(
          await closed.channel.done.timeout(limit),
          hasCode(StatusCode.goingAway),
        );
        expect(
          await expiring.channel.done.timeout(limit),
          hasCode(StatusCode.unknown),
        );
        final (records, end) = await RawPeer.drain(expiring.stream);
        expect(records.single.command, QuicRecordCommand.close);
        expect(end, 'fin');
      },
    );

    test('a reset with a code is not held; over raw QUIC (whose resets '
        'always carry one) neither is one without', () async {
      final coded = await OpenedChannel.start();
      coded.stream.reset(StatusCode.permissionDenied.code);
      expect(
        await coded.channel.done.timeout(const Duration(seconds: 1)),
        Status.of(StatusCode.permissionDenied),
      );
      final raw = await OpenedChannel.start(isWebTransport: false);
      raw.rawStream.resetWithoutCode();
      expect(
        (await raw.channel.done.timeout(const Duration(seconds: 1))).known,
        StatusCode.unknown,
      );
    });
  });

  test('no timer outlives the connection after any end of the PING barrier '
      'or of a held reset or STOP_SENDING', () async {
    const short = Duration(milliseconds: 100);
    Future<List<Duration>> barrier(
      Future<void> Function(
        QuicBindingConnection connection,
        RawPeer raw,
        MuxControlMessage ping,
      )
      end, {
      MuxOptions options = fast,
    }) => timersLeftBehind(() async {
      final (connection, raw) = await bindingAndRaw(options: options);
      final going = connection.goAway();
      final ping = await raw.nextControlOf(MuxControlType.ping.code);
      await end(connection, raw, ping);
      await going.timeout(limit);
      await connection.done.timeout(limit);
      await raw.end;
    });

    Future<List<Duration>> hold(
      Future<void> Function(OpenedChannel) end, {
      bool reset = true,
      bool closeFirst = false,
      MuxOptions options = fast,
    }) => timersLeftBehind(() async {
      final c = await OpenedChannel.start(options: options);
      if (closeFirst) {
        // The peer's close, then this side's close in turn meets the hold.
        await c.stream.write(encodeCloseRecord(Status.ok));
        await until(() => c.channel.state != MuxChannelState.open);
      }
      if (reset) {
        c.rawStream.resetWithoutCode();
      } else {
        c.rawStream.stopWithoutCode();
      }
      await settle(50);
      await end(c);
      await c.channel.done.timeout(limit);
      if (c.connection.isOpen) {
        await c.connection.close();
      }
      await c.raw.end;
    });

    // Each end is checked on its own, soon after it: a timer left behind
    // would still be active then.
    final left = await Future.wait([
      // The barrier: its PONG, the peer's close, its bound with a drain
      // that never ends, close(), a lost session, a failure close.
      barrier(
        (_, raw, ping) => raw.sendControl(MuxControlMessage.pong(ping.payload)),
      ),
      barrier((_, raw, _) => raw.session.close(0, '')),
      barrier((connection, _, _) async {
        connection.retainForDrain(2, Completer<void>().future);
      }, options: fast.copyWith(closeConfirmTimeout: short)),
      barrier((connection, _, _) => connection.close()),
      barrier((_, raw, _) async => raw.session.lose()),
      barrier(
        (_, raw, _) => raw.sendControl(
          MuxControlMessage(MuxControlType.limits.code, Uint8List(12)),
        ),
      ),
      // The hold: the session's close, its loss, this side's close, the
      // grace, an application failure close, a confirmation expiring
      // within the hold, then the session's close or the grace, and the
      // close in turn after the peer's CLOSE record.
      hold((c) => c.raw.session.close(0, '')),
      hold((c) async => c.raw.session.lose(), reset: false),
      hold((c) => c.connection.close()),
      hold((c) async {}),
      hold((c) async {
        // The STOP_SENDING is the peer's close once the grace passed;
        // its direction then ends with its CLOSE record.
        await until(() => !c.channel.canSend);
        await c.stream.write(encodeCloseRecord(Status.ok));
        await c.stream.finish();
      }, reset: false),
      hold((c) => c.channel.close(Status.of(StatusCode.cancelled))),
      hold(
        (c) async {
          c.channel.close().ignore();
          await settle(200);
          await c.raw.session.close(0, '');
        },
        reset: false,
        options: fast.copyWith(closeConfirmTimeout: short),
      ),
      hold(
        (c) async => c.channel.close().ignore(),
        reset: false,
        options: fast.copyWith(closeConfirmTimeout: short),
      ),
      hold((c) => c.raw.session.close(0, ''), reset: false, closeFirst: true),
    ]);
    expect([
      for (final (i, timers) in left.indexed)
        if (timers.isNotEmpty) (i, timers),
    ], isEmpty);
  });

  group('keep-alive and the control stream', () {
    test('a peer that does not answer PING is lost after the keep-alive '
        'timeout', () async {
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(
          keepAliveInterval: const Duration(milliseconds: 60),
          keepAliveTimeout: const Duration(milliseconds: 60),
        ),
      );
      final status = await connection.done.timeout(limit);
      expect(status.known, StatusCode.connectionLost);
      expect(status.reason, 'keep-alive timeout');
      expect((await raw.end).code, StatusCode.deadlineExceeded.code);
    });

    test('two bindings with keep-alive stay connected', () async {
      final options = fast.copyWith(
        keepAliveInterval: const Duration(milliseconds: 30),
        keepAliveTimeout: const Duration(milliseconds: 60),
      );
      final (a, b) = await connectionPair(
        initiator: options,
        acceptor: options,
      );
      await settle(300);
      expect(a.isOpen && b.isOpen, isTrue);
    });

    test('an acceptor without a control stream in time closes with '
        'PROTOCOL_ERROR', () async {
      final (connection, raw) = await bindingAndRaw(
        rawControl: false,
        quicOptions: const QuicBindingOptions(
          controlStreamTimeout: Duration(milliseconds: 100),
        ),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.protocolError),
      );
      expect((await raw.end).code, StatusCode.protocolError.code);
    });

    test('over WebTransport, a control stream reset without a code (the '
        'peer\'s WT_SESSION_GONE) waits for the session\'s end, which ends '
        'the connection as the close says', () async {
      final (connection, raw) = await bindingAndRaw(isWebTransport: true);
      await until(() => connection.peerHello != null);
      (raw.control! as MemoryQuicStream).resetWithoutCode();
      await settle(100);
      expect(connection.isOpen, isTrue);
      await raw.session.close(StatusCode.unavailable.code, 'upgrade');
      // A received close: a GOAWAY with its status, then the end.
      expect(
        await connection.peerGoAwayStatus.timeout(limit),
        Status.of(StatusCode.unavailable, 'upgrade'),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
    });

    test('over WebTransport, STOP_SENDING without a code on the control '
        'stream that no session end follows is a protocol error after the '
        'grace', () async {
      final (connection, raw) = await bindingAndRaw(isWebTransport: true);
      await until(() => connection.peerHello != null);
      final watch = Stopwatch()..start();
      (raw.control! as MemoryQuicStream).stopWithoutCode();
      expect(
        await connection.done.timeout(const Duration(seconds: 10)),
        hasCode(StatusCode.protocolError),
      );
      expect(
        watch.elapsed,
        greaterThanOrEqualTo(
          QuicBindingConnection.webTransportSessionGoneGrace -
              const Duration(milliseconds: 50),
        ),
      );
    });

    test('over WebTransport, a control stream reset with a code is a '
        'protocol error at once', () async {
      final (connection, raw) = await bindingAndRaw(isWebTransport: true);
      await until(() => connection.peerHello != null);
      raw.control!.reset(StatusCode.cancelled.code);
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.protocolError),
      );
    });

    test('the control stream is not read while this side\'s control output '
        'backs up', () async {
      final (connection, raw) = await bindingAndRaw(
        quicOptions: const QuicBindingOptions(controlOutputMark: 200),
        rawEnd: const MemoryQuicEndConfig(streamWindow: 2000),
        bindingEnd: const MemoryQuicEndConfig(streamWindow: 4000),
      );
      // The raw peer sends PINGs and reads nothing: PONGs fill its window,
      // then the binding's output queue, then the binding stops reading.
      var written = 0;
      final pinging = () async {
        for (var i = 0; i < 2000; i++) {
          await raw.sendControl(MuxControlMessage.ping(Uint8List(100)));
          written++;
        }
      }();
      await settle(200);
      expect(written, lessThan(2000));
      final stalled = written;
      await settle(100);
      expect(written, stalled);
      expect(connection.isOpen, isTrue);
      // Reading lets everything through.
      var pongs = 0;
      unawaited(() async {
        while (pongs < 2000) {
          final message = await raw.nextControl();
          if (message.knownType == MuxControlType.pong) {
            pongs++;
          }
        }
      }());
      await pinging.timeout(limit);
      await until(() => pongs == 2000);
    });
  });

  group('resource limits', () {
    test('channels beyond maxChannels are rejected RESOURCE_EXHAUSTED, with '
        'STOP_SENDING', () async {
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(maxChannels: 2),
      );
      await raw.openRaw(encodeOpenRecord(2, const []));
      await raw.openRaw(encodeOpenRecord(4, const []));
      final third = await raw.openRaw(encodeOpenRecord(6, const []));
      expect(
        await third.stopped.timeout(limit),
        StatusCode.resourceExhausted.code,
      );
      final (records, end) = await RawPeer.drain(third);
      expect(
        decodeCloseBody(records.single.body),
        hasCode(StatusCode.resourceExhausted),
      );
      expect(end, 'fin');
      expect(connection.openChannelCount, 2);
    });

    test('open payloads beyond their budget are rejected '
        'RESOURCE_EXHAUSTED', () async {
      final (connection, raw) = await bindingAndRaw(
        options: fast.copyWith(maxOpenPayloadBytes: 100),
      );
      await raw.openRaw(encodeOpenRecord(2, Uint8List(80)));
      final second = await raw.openRaw(encodeOpenRecord(4, Uint8List(80)));
      expect(
        await second.stopped.timeout(limit),
        StatusCode.resourceExhausted.code,
      );
      expect(connection.openPayloadBytes, 80);
    });

    test('the peer\'s HELLO states its channels, which are advisory: an '
        'open beyond them waits for the stack\'s stream credit', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawHello: QuicHello(channels: 2),
      );
      await until(() => connection.peerHello != null);
      expect(connection.peerMaxChannels, 2);
      for (var i = 0; i < 3; i++) {
        connection.open(Uint8List(0));
      }
      // The stack granted more streams than the HELLO stated.
      for (var i = 0; i < 3; i++) {
        await raw.nextStream();
      }
    });

    test('a side states the channels it accepts: its stream limit less the '
        'control stream, within maxChannels', () async {
      final (a, b) = await connectionPair(
        initiator: fast.copyWith(maxChannels: 50),
        acceptorEnd: const MemoryQuicEndConfig(maxStreams: 11),
      );
      await until(() => a.peerHello != null && b.peerHello != null);
      expect(a.peerMaxChannels, 10);
      expect(b.peerMaxChannels, 50);
    });

    test('an open without stream credit waits, then fails '
        'RESOURCE_EXHAUSTED', () async {
      final (connection, _) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawEnd: const MemoryQuicEndConfig(maxStreams: 2),
        quicOptions: const QuicBindingOptions(
          openStreamTimeout: Duration(milliseconds: 100),
        ),
      );
      final first = connection.open(Uint8List(0));
      final second = connection.open(Uint8List(0));
      expect(
        await second.done.timeout(limit),
        hasCode(StatusCode.resourceExhausted),
      );
      expect(first.state, MuxChannelState.open);
    });

    test(
      'control messages held during an identification are bounded',
      () async {
        final held = HeldVerifier();
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(identityVerifier: held),
          quicOptions: const QuicBindingOptions(maxHeldControlMessages: 3),
        );
        await raw.sendControl(MuxControlMessage.nonce(Uint8List(32)..[0] = 1));
        await raw.nextControlOf(MuxControlType.nonce.code);
        await raw.sendControl(
          MuxControlMessage.ident(MuxIdent(credential: Uint8List(1))),
        );
        for (var i = 0; i < 4; i++) {
          await raw.sendControl(MuxControlMessage.ping(Uint8List(1)));
        }
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.resourceExhausted),
        );
      },
    );
  });

  group('identity', () {
    /// The exporter of [session].
    Future<Uint8List> exporterOf(MemoryQuicSession session) async =>
        (await session.exportKeyingMaterial(
          rawQuicExporterLabel,
          Uint8List(0),
          32,
        ))!;

    /// The binding's IDENT as the raw peer sees it, after the nonces.
    Future<(MuxIdent, Uint8List, Uint8List)> identOf(
      QuicBindingConnection connection,
      RawPeer raw, {
      bool exporter = true,
    }) async {
      final credential = await credentialOf('npc-7');
      final identifying = connection.identify(credential, holderKey: holder);
      final nonce = await raw.nextControlOf(MuxControlType.nonce.code);
      final ours = Uint8List(32)..fillRange(0, 32, 0x42);
      await raw.sendControl(MuxControlMessage.nonce(ours));
      final ident = MuxIdent.decode(
        (await raw.nextControlOf(MuxControlType.ident.code)).payload,
      );
      final ping = await raw.nextControlOf(MuxControlType.ping.code);
      await raw.sendControl(MuxControlMessage.pong(ping.payload));
      await identifying.timeout(limit);
      return (ident, nonce.payload, ours);
    }

    test('the exporter: RFC 9266\'s label on raw QUIC, the application '
        'label over WebTransport', () async {
      for (final webTransport in [false, true]) {
        final (a, b) = MemoryQuicSession.pair();
        final starting = QuicBindingConnection.start(
          b,
          options: fast,
          isWebTransport: webTransport,
        );
        final connection = await QuicBindingConnection.start(
          a,
          options: fast,
          isWebTransport: webTransport,
        );
        final accepted = await starting;
        addTearDown(connection.close);
        addTearDown(accepted.close);
        expect(a.exporterLabels, [
          webTransport ? 'switchboard-ident' : 'EXPORTER-Channel-Binding',
        ]);
        expect(connection.hasExporter, isTrue);
        await until(() => connection.exporterBound && accepted.exporterBound);
      }
      // A stack without one announces none.
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        bindingEnd: const MemoryQuicEndConfig(exporter: false),
        rawHello: QuicHello(exporter: true),
      );
      expect(connection.hasExporter, isFalse);
      await until(() => connection.peerHello != null);
      expect(connection.exporterBound, isFalse);
      expect(raw.session.peer.exporterLabels, hasLength(1));
    });

    test('both HELLOs with EXPORTER: the proof signs the exporter', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawHello: QuicHello(exporter: true),
      );
      await until(() => connection.peerHello != null);
      expect(connection.exporterBound, isTrue);
      final (ident, sender, receiver) = await identOf(connection, raw);
      final exporter = await exporterOf(raw.session);
      final v = await verifier();
      expect(
        (await verifyIdent(
          ident,
          verifier: v,
          senderNonce: sender,
          receiverNonce: receiver,
          exporter: exporter,
        )).identity,
        'npc-7',
      );
      await expectLater(
        verifyIdent(
          ident,
          verifier: v,
          senderNonce: sender,
          receiverNonce: receiver,
        ),
        throwsCode(StatusCode.unauthenticated),
      );
    });

    test('a HELLO without EXPORTER: the proof is nonce-bound', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawHello: QuicHello(),
      );
      await until(() => connection.peerHello != null);
      expect(connection.exporterBound, isFalse);
      final (ident, sender, receiver) = await identOf(connection, raw);
      expect(
        (await verifyIdent(
          ident,
          verifier: await verifier(),
          senderNonce: sender,
          receiverNonce: receiver,
        )).identity,
        'npc-7',
      );
    });

    test('a side that requires the binding neither sends nor accepts a '
        'nonce-bound IDENT', () async {
      const rules = QuicIdentityRules(requireExporterBinding: true);
      // Sending: refused before anything is sent.
      final (sender, rawReceiver) = await bindingAndRaw(
        quicOptions: const QuicBindingOptions(identity: rules),
        rawHello: QuicHello(),
      );
      await until(() => sender.peerHello != null);
      final identifying = sender.identify(
        await credentialOf('npc-7'),
        holderKey: holder,
      );
      await rawReceiver.nextControlOf(MuxControlType.nonce.code);
      await rawReceiver.sendControl(
        MuxControlMessage.nonce(Uint8List(32)..[0] = 9),
      );
      await expectLater(identifying, throwsCode(StatusCode.unauthenticated));
      // Receiving: one is refused as failing verification.
      final (receiver, raw) = await bindingAndRaw(
        options: fast.copyWith(identityVerifier: await verifier()),
        quicOptions: const QuicBindingOptions(identity: rules),
        rawHello: QuicHello(),
      );
      await raw.sendControl(MuxControlMessage.nonce(Uint8List(32)..[0] = 1));
      final theirs = await raw.nextControlOf(MuxControlType.nonce.code);
      final ours = Uint8List(32)..[0] = 1;
      final credential = await credentialOf('npc-7');
      await raw.sendControl(
        MuxControlMessage.ident(
          MuxIdent(
            credential: credential.encode(),
            proof: await holder.sign(
              MuxIdent.proofMessage(ours, theirs.payload, const [], const []),
            ),
          ),
        ),
      );
      expect(
        await receiver.done.timeout(limit),
        hasCode(StatusCode.unauthenticated),
      );
      expect((await raw.end).code, StatusCode.unauthenticated.code);
    });

    test('an initiator that requires the binding closes UNAUTHENTICATED on a '
        'HELLO without EXPORTER', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        quicOptions: const QuicBindingOptions(
          identity: QuicIdentityRules(requireExporterBinding: true),
        ),
        rawHello: QuicHello(),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.unauthenticated),
      );
      expect((await raw.end).code, StatusCode.unauthenticated.code);
    });

    test('an initiator awaiting the acceptor\'s identity opens no channel '
        'before it verified', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        options: fast.copyWith(identityVerifier: await verifier()),
        quicOptions: const QuicBindingOptions(
          identity: QuicIdentityRules(
            requireExporterBinding: true,
            awaitPeerIdentity: true,
          ),
        ),
        rawHello: QuicHello(exporter: true),
      );
      connection.localIdentity = 'npc-7';
      final early = connection.open(bytes('early'));
      final identifying = connection.identify(
        await credentialOf('npc-7'),
        holderKey: holder,
        receiver: 'server-1',
      );
      final theirs = await raw.nextControlOf(MuxControlType.nonce.code);
      final ours = Uint8List(32)..[0] = 3;
      await raw.sendControl(MuxControlMessage.nonce(ours));
      await raw.nextControlOf(MuxControlType.ident.code);
      final ping = await raw.nextControlOf(MuxControlType.ping.code);
      await raw.sendControl(MuxControlMessage.pong(ping.payload));
      await settle(50);
      // Identified, but the acceptor has not: nothing opened but the
      // control stream.
      expect(raw.session.announced, [0]);
      expect(early.isWritable, isFalse);
      final exporter = await exporterOf(raw.session);
      await raw.sendControl(
        MuxControlMessage.ident(
          MuxIdent(
            credential: (await credentialOf('server-1')).encode(),
            receiver: bytes('npc-7'),
            proof: await holder.sign(
              MuxIdent.proofMessage(
                ours,
                theirs.payload,
                const [],
                bytes('npc-7'),
                exporter: exporter,
              ),
            ),
          ),
        ),
      );
      await identifying.timeout(limit);
      expect(connection.peerIdentity?.identity, 'server-1');
      expect(connection.peerIdentityBound, isTrue);
      final stream = await raw.nextStream();
      final open = await RecordReader(stream).next(limit: 100);
      expect(text(decodeOpenBody(open!.body).$2), 'early');
    });

    test('an acceptor identifies only to a peer that identified with an '
        'exporter-bound proof; a bearer credential only to an authenticated '
        'end', () async {
      final (connection, _) = await bindingAndRaw(
        quicOptions: const QuicBindingOptions(
          identity: QuicIdentityRules.listener,
        ),
      );
      await expectLater(
        connection.identify(await credentialOf('server-1'), holderKey: holder),
        throwsCode(StatusCode.failedPrecondition),
      );
      final bearer = await CredentialIssuer.hmac(
        Name('k1'),
        Uint8List(32),
      ).issue(kind: CredentialKind.node, identity: 'bearer');
      final (initiator, _) = await bindingAndRaw(
        bindingIsInitiator: true,
        quicOptions: const QuicBindingOptions(
          identity: QuicIdentityRules(bearerOnlyToAuthenticatedPeer: true),
        ),
      );
      await expectLater(
        initiator.identify(bearer),
        throwsCode(StatusCode.failedPrecondition),
      );
      expect(initiator.peerAuthenticated, isFalse);
    });

    test(
      'a bearer IDENT is not exporter-bound: it authenticates nobody',
      () async {
        final key = Uint8List(32);
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(
            identityVerifier: CredentialVerifier(hmacKeys: {Name('k1'): key}),
          ),
          rawHello: QuicHello(exporter: true),
        );
        await raw.nextControl();
        await raw.sendControl(MuxControlMessage.nonce(Uint8List(32)..[0] = 1));
        await raw.nextControlOf(MuxControlType.nonce.code);
        final bearer = await CredentialIssuer.hmac(
          Name('k1'),
          key,
        ).issue(kind: CredentialKind.node, identity: 'bearer');
        await raw.sendControl(
          MuxControlMessage.ident(MuxIdent(credential: bearer.encode())),
        );
        await raw.sendControl(MuxControlMessage.ping(bytes('p')));
        await raw.nextControlOf(MuxControlType.pong.code);
        expect(connection.exporterBound, isTrue);
        expect(connection.peerIdentity?.identity, 'bearer');
        expect(connection.peerIdentityBound, isFalse);
        expect(connection.peerAuthenticated, isFalse);
      },
    );

    test('an initiator awaiting the acceptor\'s identity without a verifier '
        'could never use the connection: it closes at once', () async {
      final (a, _) = MemoryQuicSession.pair();
      final connection = await QuicBindingConnection.start(
        a,
        options: fast,
        quicOptions: const QuicBindingOptions(
          identity: QuicIdentityRules(awaitPeerIdentity: true),
        ),
      );
      expect(connection.isOpen, isFalse);
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.unauthenticated),
      );
    });

    test(
      'the control messages after an IDENT wait for its verification',
      () async {
        final held = HeldVerifier();
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(identityVerifier: held),
          rawHello: QuicHello(exporter: true),
        );
        await raw.nextControl();
        await raw.sendControl(MuxControlMessage.nonce(Uint8List(32)..[0] = 1));
        final theirs = await raw.nextControlOf(MuxControlType.nonce.code);
        final ours = Uint8List(32)..[0] = 1;
        final credential = await credentialOf('npc-7');
        final exporter = await exporterOf(raw.session);
        await raw.sendControl(
          MuxControlMessage.ident(
            MuxIdent(
              credential: credential.encode(),
              proof: await holder.sign(
                MuxIdent.proofMessage(
                  ours,
                  theirs.payload,
                  const [],
                  const [],
                  exporter: exporter,
                ),
              ),
            ),
          ),
        );
        await raw.sendControl(MuxControlMessage.ping(bytes('after')));
        await until(() => held.calls == 1);
        await settle(50);
        expect(connection.peerIdentity, isNull);
        held.result.complete(credential);
        final pong = await raw.nextControlOf(MuxControlType.pong.code);
        expect(text(pong.payload), 'after');
        expect(connection.peerIdentity?.identity, 'npc-7');
        expect(connection.peerIdentityBound, isTrue);
      },
    );

    test('an IDENT before the nonces, a second NONCE and a NONCE equal to '
        'ours are protocol errors', () async {
      for (final mistake in ['early ident', 'second nonce', 'echoed nonce']) {
        final (connection, raw) = await bindingAndRaw();
        await raw.nextControl();
        switch (mistake) {
          case 'early ident':
            await raw.sendControl(
              MuxControlMessage.ident(MuxIdent(credential: Uint8List(1))),
            );
          case 'second nonce':
            await raw.sendControl(
              MuxControlMessage.nonce(Uint8List(32)..[0] = 1),
            );
            await raw.sendControl(
              MuxControlMessage.nonce(Uint8List(32)..[0] = 2),
            );
          case 'echoed nonce':
            unawaited(
              connection
                  .identify(await credentialOf('npc-7'), holderKey: holder)
                  .catchError((Object _) {}),
            );
            final theirs = await raw.nextControlOf(MuxControlType.nonce.code);
            await raw.sendControl(MuxControlMessage.nonce(theirs.payload));
        }
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.protocolError),
          reason: mistake,
        );
      }
    });
  });
}
