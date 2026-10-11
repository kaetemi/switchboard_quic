/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// Helpers of the binding's tests: connection pairs over the fake provider,
// and a raw peer that writes and reads records by hand.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:switchboard/core.dart';
import 'package:switchboard_quic/core.dart';
import 'package:test/test.dart';

import 'fake_provider.dart';

const limit = Duration(seconds: 10);

/// Options without keep-alive and with short waits.
const fast = MuxOptions(
  goAwayGrace: Duration(milliseconds: 200),
  keepAliveInterval: null,
  closeConfirmTimeout: Duration(seconds: 5),
);

Uint8List bytes(String value) => Uint8List.fromList(utf8.encode(value));
String text(List<int> data) => utf8.decode(data);

/// [length] bytes of a pattern a corrupted transfer would not keep.
Uint8List pattern(int length, [int seed = 0]) => Uint8List.fromList(
  List.generate(length, (i) => (i * 7 + i ~/ 251 + seed) & 0xFF),
);

Matcher throwsCode(StatusCode code) =>
    throwsA(isA<SwitchboardException>().having((e) => e.code, 'code', code));

Matcher hasCode(StatusCode code) =>
    isA<Status>().having((s) => s.known, 'known', code);

Future<void> until(bool Function() condition, {Duration within = limit}) async {
  final deadline = DateTime.now().add(within);
  while (!condition()) {
    if (DateTime.now().isAfter(deadline)) {
      fail('condition not met within $within');
    }
    await Future<void>.delayed(const Duration(milliseconds: 2));
  }
}

Future<void> settle([int ms = 20]) =>
    Future<void>.delayed(Duration(milliseconds: ms));

/// Two connections of the binding over a fake session pair, closed after
/// the test.
Future<(QuicBindingConnection, QuicBindingConnection)> connectionPair({
  MuxOptions initiator = fast,
  MuxOptions acceptor = fast,
  QuicBindingOptions initiatorQuic = const QuicBindingOptions(),
  QuicBindingOptions acceptorQuic = const QuicBindingOptions(),
  FakeEndConfig initiatorEnd = const FakeEndConfig(),
  FakeEndConfig acceptorEnd = const FakeEndConfig(),
  FakeQuicNetwork? network,
  String? initiatorIdentity,
  String? acceptorIdentity,
}) async {
  final (a, b) = FakeQuicSession.pair(
    network: network,
    initiator: initiatorEnd,
    acceptor: acceptorEnd,
  );
  final server = QuicBindingConnection.start(
    b,
    options: acceptor,
    quicOptions: acceptorQuic,
    localIdentity: acceptorIdentity,
  );
  final client = await QuicBindingConnection.start(
    a,
    options: initiator,
    quicOptions: initiatorQuic,
    localIdentity: initiatorIdentity,
  );
  final accepted = await server;
  addTearDown(client.close);
  addTearDown(accepted.close);
  return (client, accepted);
}

/// A peer that speaks the binding by hand, over the other end of a fake
/// session.
class RawPeer {
  RawPeer(this.session) {
    session.incomingStreams.listen(_incoming.add);
  }

  final FakeQuicSession session;
  // Fed for the session's life.
  // ignore: close_sinks
  final StreamController<QuicStream> _incoming = StreamController();
  late final StreamIterator<QuicStream> streams = StreamIterator(
    _incoming.stream,
  );

  QuicStream? control;
  RecordReader? controlReader;

  /// The next stream the binding opened.
  Future<QuicStream> nextStream() async {
    if (!await streams.moveNext().timeout(limit)) {
      throw StateError('no more streams');
    }
    return streams.current;
  }

  /// Initiator: opens the control stream with the OPEN record of channel 0
  /// and [hello] (a default `HELLO` when null, none with [sendHello]
  /// false).
  Future<QuicStream> openControl({
    QuicHello? hello,
    bool sendHello = true,
  }) async {
    final stream = await session.openStream();
    final first = BytesBuilder()..add(encodeOpenRecord(0, const []));
    if (sendHello) {
      first.add(
        encodeDataRecord((hello ?? QuicHello()).toControlMessage().encode()),
      );
    }
    await stream.write(first.takeBytes());
    control = stream;
    controlReader = RecordReader(stream);
    return stream;
  }

  /// Acceptor: takes the binding's control stream, checks its OPEN record
  /// and `HELLO`, and answers with [hello] unless [sendHello] is false.
  Future<QuicHello> acceptControl({
    QuicHello? hello,
    bool sendHello = true,
  }) async {
    final stream = await nextStream();
    final reader = RecordReader(stream);
    final open = await reader.next(limit: 1 << 20);
    expect(open!.command, QuicRecordCommand.open);
    expect(decodeOpenBody(open.body).$1, 0);
    final first = await reader.next(limit: 1 << 20);
    expect(first!.command, QuicRecordCommand.data);
    final message = MuxControlMessage.decode(first.body);
    expect(message.type, quicHelloType);
    if (sendHello) {
      await stream.write(
        encodeDataRecord((hello ?? QuicHello()).toControlMessage().encode()),
      );
    }
    control = stream;
    controlReader = reader;
    return QuicHello.decode(message.payload);
  }

  /// Writes a control message on the control stream.
  Future<void> sendControl(MuxControlMessage message) =>
      control!.write(encodeDataRecord(message.encode()));

  /// The next control message the binding wrote.
  Future<MuxControlMessage> nextControl() async {
    final record = await controlReader!.next(limit: 1 << 20).timeout(limit);
    expect(record!.command, QuicRecordCommand.data);
    return MuxControlMessage.decode(record.body);
  }

  /// The next control message of [type], skipping others.
  Future<MuxControlMessage> nextControlOf(int type) async {
    while (true) {
      final message = await nextControl();
      if (message.type == type) {
        return message;
      }
    }
  }

  /// Opens a stream and writes [data] on it.
  Future<QuicStream> openRaw(List<int> data) async {
    final stream = await session.openStream();
    if (data.isNotEmpty) {
      await stream.write(Uint8List.fromList(data));
    }
    return stream;
  }

  /// Everything the binding writes on [stream] until it ends: the records,
  /// and how the direction ended (`'fin'`, or the reset code).
  static Future<(List<QuicRecord>, Object)> drain(QuicStream stream) async {
    final reader = RecordReader(stream);
    final records = <QuicRecord>[];
    try {
      while (true) {
        final record = await reader.next(limit: 1 << 30).timeout(limit);
        if (record == null) {
          return (records, 'fin');
        }
        records.add(record);
      }
    } on QuicStreamReset catch (e) {
      return (records, e.code ?? 'reset');
    }
  }

  /// How the session ended for this peer.
  Future<QuicSessionEnd> get end => session.done.timeout(limit);
}

/// A binding connection against a raw peer: the binding is the initiator
/// unless [bindingIsInitiator] is false. With the binding as acceptor, the
/// raw peer opens the control stream first unless [rawControl] is false.
Future<(QuicBindingConnection, RawPeer)> bindingAndRaw({
  bool bindingIsInitiator = false,
  MuxOptions options = fast,
  QuicBindingOptions quicOptions = const QuicBindingOptions(),
  FakeEndConfig bindingEnd = const FakeEndConfig(),
  FakeEndConfig rawEnd = const FakeEndConfig(),
  bool rawControl = true,
  QuicHello? rawHello,
}) async {
  final (a, b) = FakeQuicSession.pair(
    initiator: bindingIsInitiator ? bindingEnd : rawEnd,
    acceptor: bindingIsInitiator ? rawEnd : bindingEnd,
  );
  final raw = RawPeer(bindingIsInitiator ? b : a);
  if (bindingIsInitiator) {
    final connecting = QuicBindingConnection.start(
      a,
      options: options,
      quicOptions: quicOptions,
    );
    final connection = await connecting;
    addTearDown(connection.close);
    await raw.acceptControl(hello: rawHello);
    return (connection, raw);
  }
  final connection = await QuicBindingConnection.start(
    b,
    options: options,
    quicOptions: quicOptions,
  );
  addTearDown(connection.close);
  if (rawControl) {
    await raw.openControl(hello: rawHello);
  }
  return (connection, raw);
}
