/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

// The test vectors of the wiki page "Polyverse Switchboard QUIC and
// WebTransport Binding", section "Test vectors", and the records of its
// "Example": the codecs byte for byte, and the negative vectors, which
// depend on connection state, through a connection of the binding fed by a
// raw peer. The exporter-bound proof X is in the core package's identity
// vectors.

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/core.dart';
import 'package:switchboard_quic/core.dart';
import 'package:test/test.dart';

import 'harness.dart';
import 'memory_provider.dart';

/// C1 of the page "Polyverse Switchboard Test Vectors".
const c1 =
    '01 01 6B 31 00 00 00 00 00 00 05 6E 70 63 2D 37 '
    '00 B9 55 69 80 29 56 69 00 03 01 6E 70 63 00 00 '
    '00 00 00 02 2A 00 00 00 00 00 00 00 03 6E 70 63 '
    '2D 2A 00 00 00 01 84 DB E9 02 5A 34 E5 C3 7A C8 '
    'BC C2 B7 7C 7B 6D E6 84 51 7A F1 7B C8 41 66 34 '
    '8A BE 22 D9 E3 C9';

String hex(List<int> data) => hexString(Uint8List.fromList(data));

/// A stream that returns [data] in chunks of at most [chunk] bytes, and
/// records how much was asked of it.
class _ScriptedStream implements QuicStream {
  _ScriptedStream(this.data, {this.chunk = 1 << 30});

  final Uint8List data;
  final int chunk;
  int offset = 0;
  int read_ = 0;

  @override
  Future<Uint8List?> read(int max) async {
    if (offset >= data.length) {
      return null;
    }
    var n = data.length - offset;
    if (n > max) {
      n = max;
    }
    if (n > chunk) {
      n = chunk;
    }
    final out = Uint8List.sublistView(data, offset, offset + n);
    offset += n;
    read_ += n;
    return out;
  }

  @override
  Future<void> write(Uint8List bytes) async {}

  @override
  Future<void> finish() async {}

  @override
  void reset(int code) {}

  @override
  void stop(int code) {}

  @override
  set priority(int value) {}

  @override
  Future<int?> get stopped => Completer<int?>().future;

  @override
  Future<int?> get resetReceived => Completer<int?>().future;
}

Future<QuicRecord?> decode(String bytes, {int limit = 1 << 20}) =>
    RecordReader(_ScriptedStream(hexBytes(bytes))).next(limit: limit);

void main() {
  group('records', () {
    test('DATA, subframe 01 02 03', () async {
      expect(hex(encodeDataRecord([1, 2, 3])), '03 00 00 00 01 02 03');
      final record = await decode('03 00 00 00 01 02 03');
      expect(record!.command, QuicRecordCommand.data);
      expect(record.body, [1, 2, 3]);
    });

    test('DATA, empty subframe', () async {
      expect(hex(encodeDataRecord(const [])), '00 00 00 00');
      final record = await decode('00 00 00 00');
      expect(record!.command, QuicRecordCommand.data);
      expect(record.body, isEmpty);
    });

    test('DATA header of a 32752-byte subframe', () {
      final header = Uint8List(4);
      writeQuicRecordHeader(header, 0, QuicRecordCommand.data, 32752);
      expect(hex(header), 'F0 7F 00 00');
      expect(
        hex(encodeDataRecord(Uint8List(32752)).sublist(0, 4)),
        hex(header),
      );
    });

    test('OPEN, channel 0 (the control stream), empty open payload', () async {
      expect(
        hex(encodeOpenRecord(0, const [])),
        '06 00 00 40 00 00 00 00 00 00',
      );
      final record = await decode('06 00 00 40 00 00 00 00 00 00');
      expect(record!.command, QuicRecordCommand.open);
      final (id, payload) = decodeOpenBody(record.body);
      expect(id, 0);
      expect(payload, isEmpty);
    });

    test('OPEN, channel 2, open payload 00 (default service)', () {
      expect(
        hex(encodeOpenRecord(2, ChannelAddress().encode())),
        '07 00 00 40 02 00 00 00 00 00 00',
      );
    });

    test('OPEN, channel 3, service "api", application payload 01 02', () async {
      final payload = ChannelAddress(
        type: Name('api'),
        payload: Uint8List.fromList([1, 2]),
      ).encode();
      const vector =
          '11 00 00 40 03 00 00 00 00 00 01 61 70 69 00 00 00 00 00 01 02';
      expect(hex(encodeOpenRecord(3, payload)), vector);
      final (id, decoded) = decodeOpenBody((await decode(vector))!.body);
      expect(id, 3);
      final address = ChannelAddress.decode(decoded);
      expect(address.type, Name('api'));
      expect(address.payload, [1, 2]);
    });

    test('OPEN, channel 0x1234567890AB, empty open payload', () async {
      expect(
        hex(encodeOpenRecord(0x1234567890AB, const [])),
        '06 00 00 40 AB 90 78 56 34 12',
      );
      final record = await decode('06 00 00 40 AB 90 78 56 34 12');
      expect(decodeOpenBody(record!.body).$1, 0x1234567890AB);
    });

    test('CLOSE, no status payload (OK)', () async {
      expect(hex(encodeCloseRecord(Status.ok)), '00 00 00 80');
      final record = await decode('00 00 00 80');
      expect(record!.command, QuicRecordCommand.close);
      expect(decodeCloseBody(record.body), Status.ok);
    });

    test('CLOSE, OK, no reason', () async {
      expect(
        hex(encodeQuicRecord(QuicRecordCommand.close, Status.ok.encode())),
        '02 00 00 80 00 00',
      );
      final record = await decode('02 00 00 80 00 00');
      expect(decodeCloseBody(record!.body).isOk, isTrue);
    });

    test('CLOSE, NOT_FOUND, reason "x"', () async {
      final status = Status.of(StatusCode.notFound, 'x');
      expect(hex(encodeCloseRecord(status)), '03 00 00 80 05 00 78');
      final record = await decode('03 00 00 80 05 00 78');
      expect(decodeCloseBody(record!.body), status);
    });

    test('CLOSE, MOVED, owner 0x1A2B, epoch 7', () async {
      final status = MovedStatus(owner: 0x1A2B, epoch: 7).toStatus();
      const vector = '0C 00 00 80 25 00 2B 1A 00 00 00 00 07 00 00 00';
      expect(hex(encodeCloseRecord(status)), vector);
      final decoded = decodeCloseBody((await decode(vector))!.body);
      expect(decoded.known, StatusCode.moved);
      final moved = MovedStatus.fromStatus(decoded);
      expect(moved.owner, 0x1A2B);
      expect(moved.epoch, 7);
    });

    test('FF FF FF 3F is DATA of 1073741823 bytes, over every limit, and '
        'FF FF FF 7F OPEN of as many; the body is not read', () async {
      for (final (vector, command) in [
        ('FF FF FF 3F', QuicRecordCommand.data),
        ('FF FF FF 7F', QuicRecordCommand.open),
      ]) {
        final stream = _ScriptedStream(hexBytes('$vector 01 02 03'));
        final header = readQuicRecordHeader(hexBytes(vector));
        expect(quicHeaderCommand(header), command.code);
        expect(quicHeaderLength(header), 1073741823);
        await expectLater(
          RecordReader(stream).next(limit: quicMaxRecordLength - 1),
          throwsA(
            isA<RecordTooLarge>()
                .having((e) => e.length, 'length', 1073741823)
                .having((e) => e.command, 'command', command.code),
          ),
        );
        expect(stream.read_, 4);
      }
    });

    test('a record arriving in pieces is reassembled; only its bytes are '
        'read', () async {
      final stream = _ScriptedStream(
        hexBytes('05 00 00 00 01 02 03 04 05 00 00 00 80'),
        chunk: 2,
      );
      final reader = RecordReader(stream);
      final record = await reader.next(limit: 100);
      expect(record!.body, [1, 2, 3, 4, 5]);
      expect(stream.read_, 9);
      expect((await reader.next(limit: 100))!.command, QuicRecordCommand.close);
      expect(await reader.next(limit: 100), isNull);
    });

    group('negative (protocol error)', () {
      test('command 3', () async {
        await expectLater(
          decode('00 00 00 C0'),
          throwsA(isA<ProtocolException>()),
        );
      });

      test('CLOSE with a one-byte body', () async {
        final record = await decode('01 00 00 80 00');
        expect(
          () => decodeCloseBody(record!.body),
          throwsA(isA<ProtocolException>()),
        );
      });

      test('OPEN with a truncated channel id', () async {
        final record = await decode('05 00 00 40 02 00 00 00 00');
        expect(
          () => decodeOpenBody(record!.body),
          throwsA(isA<ProtocolException>()),
        );
      });

      test('FIN inside a record', () async {
        await expectLater(
          decode('03 00 00 00 01'),
          throwsA(isA<ProtocolException>()),
        );
        await expectLater(decode('03 00'), throwsA(isA<ProtocolException>()));
      });

      // Through a connection: each ends it with PROTOCOL_ERROR.
      for (final (name, vector) in [
        ('command 3', '06 00 00 40 02 00 00 00 00 00 00 00 00 C0'),
        (
          'CLOSE with a one-byte body',
          '06 00 00 40 02 00 00 00 00 00 01 00 00 80 00',
        ),
        ('a stream whose first record is DATA', '00 00 00 00'),
        ('OPEN with a truncated channel id', '05 00 00 40 02 00 00 00 00'),
        ('OPEN of reserved channel 1', '06 00 00 40 01 00 00 00 00 00'),
        ('OPEN of reserved channel 0xFFFF', '06 00 00 40 FF FF 00 00 00 00'),
        (
          'a record after a CLOSE record',
          '06 00 00 40 02 00 00 00 00 00 00 00 00 80 00 00 00 00',
        ),
        (
          'a second OPEN record',
          '06 00 00 40 02 00 00 00 00 00 06 00 00 40 04 00 00 00 00 00',
        ),
      ]) {
        test('$name ends the connection', () async {
          final (connection, raw) = await bindingAndRaw();
          connection.incoming.listen((_) {});
          final stream = await raw.openRaw(hexBytes(vector));
          if (name == 'a record after a CLOSE record') {
            await stream.finish();
          }
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.protocolError),
          );
          final end = await raw.end;
          expect(end.code, StatusCode.protocolError.code);
          expect(end.byPeer, isTrue);
        });
      }

      test('a channel id of the wrong parity, a second channel-0 OPEN, and a '
          'FIN without a CLOSE record end the connection', () async {
        for (final (vector, fin) in [
          ('06 00 00 40 03 00 00 00 00 00', false),
          ('06 00 00 40 00 00 00 00 00 00', false),
          ('06 00 00 40 02 00 00 00 00 00 01 00 00 00 07', true),
        ]) {
          final (connection, raw) = await bindingAndRaw();
          // Read, so that the binding reads on to the FIN.
          connection.incoming.listen((c) => c.stream.listen((_) {}));
          final stream = await raw.openRaw(hexBytes(vector));
          if (fin) {
            await stream.finish();
          }
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.protocolError),
          );
        }
      });

      test(
        'channel 0 on a stream the acceptor opened ends the connection',
        () async {
          final (connection, raw) = await bindingAndRaw(
            bindingIsInitiator: true,
          );
          await raw.openRaw(hexBytes('06 00 00 40 00 00 00 00 00 00'));
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.protocolError),
          );
        },
      );
    });
  });

  group('control stream', () {
    test('HELLO, record limit 32752, no stated channel limit, no flags', () {
      final hello = QuicHello();
      const vector = '0A 00 00 00 08 F0 7F 00 00 00 00 00 00 00';
      expect(hex(encodeDataRecord(hello.toControlMessage().encode())), vector);
      expect(QuicHello.decode(hexBytes(vector).sublist(5)), hello);
    });

    test('HELLO, record limit 1 MiB, 100 channels, EXPORTER', () {
      final hello = QuicHello(
        recordLimit: 1 << 20,
        channels: 100,
        exporter: true,
      );
      const vector = '0A 00 00 00 08 00 00 10 00 64 00 00 00 01';
      expect(hex(encodeDataRecord(hello.toControlMessage().encode())), vector);
      expect(QuicHello.decode(hexBytes(vector).sublist(5)), hello);
    });

    test('HELLO with a further field AA, ignored', () {
      final decoded = QuicHello.decode(
        hexBytes('0B 00 00 00 08 F0 7F 00 00 00 00 00 00 00 AA').sublist(5),
      );
      expect(decoded, QuicHello());
    });

    test('HELLO: other flag bits are ignored, a record limit above '
        '0x3FFFFFFF reads as it', () {
      final decoded = QuicHello.decode(hexBytes('FF FF FF FF 00 00 00 00 FE'));
      expect(decoded.recordLimit, quicMaxRecordLength);
      expect(decoded.exporter, isFalse);
    });

    test('PING and PONG, payload DE AD', () {
      final payload = hexBytes('DE AD');
      expect(
        hex(encodeDataRecord(MuxControlMessage.ping(payload).encode())),
        '03 00 00 00 01 DE AD',
      );
      expect(
        hex(encodeDataRecord(MuxControlMessage.pong(payload).encode())),
        '03 00 00 00 02 DE AD',
      );
    });

    test('GOAWAY, GOING_AWAY, no reason', () {
      expect(
        hex(
          encodeDataRecord(
            MuxControlMessage.goAway(Status.of(StatusCode.goingAway)).encode(),
          ),
        ),
        '03 00 00 00 03 21 00',
      );
    });

    test('NONCE, 32 bytes of 11', () {
      final nonce = Uint8List(32)..fillRange(0, 32, 0x11);
      expect(
        hex(encodeDataRecord(MuxControlMessage.nonce(nonce).encode())),
        '21 00 00 00 05 ${List.filled(32, '11').join(' ')}',
      );
    });

    test('IDENT, credential C1, no intent, no receiver, no proof', () {
      final ident = MuxIdent(credential: hexBytes(c1));
      expect(
        hex(encodeDataRecord(MuxControlMessage.ident(ident).encode())),
        '5B 00 00 00 06 56 00 $c1 00 00',
      );
    });

    group('negative (protocol error)', () {
      for (final (name, vector) in [
        ('a HELLO of 8 bytes', '09 00 00 00 08 F0 7F 00 00 00 00 00 00'),
        (
          'a HELLO with a record limit of 1024',
          '0A 00 00 00 08 00 04 00 00 00 00 00 00 00',
        ),
        ('an empty control record', '00 00 00 00'),
        ('a control message before HELLO', '03 00 00 00 01 DE AD'),
      ]) {
        test('$name as the first message ends the connection', () async {
          final (connection, raw) = await bindingAndRaw(rawControl: false);
          await raw.openControl(sendHello: false);
          await raw.control!.write(hexBytes(vector));
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.protocolError),
          );
          expect((await raw.end).code, StatusCode.protocolError.code);
        });
      }

      for (final (name, vector) in [
        ('LIMITS', '0D 00 00 00 04 00 04 00 00 04 00 00 00 00 00 01 00'),
        ('CREDIT', '0B 00 00 00 07 02 00 00 00 00 00 00 80 00 00'),
        ('an empty control record', '00 00 00 00'),
        ('a second HELLO', '0A 00 00 00 08 F0 7F 00 00 00 00 00 00 00'),
        ('a CLOSE record on the control stream', '00 00 00 80'),
        (
          'a control payload over 1024 bytes',
          '02 04 00 00 01 ${List.filled(1025, '00').join(' ')}',
        ),
      ]) {
        test('$name after HELLO ends the connection', () async {
          final (connection, raw) = await bindingAndRaw();
          await raw.control!.write(hexBytes(vector));
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.protocolError),
          );
        });
      }

      test('FIN, a reset or STOP_SENDING on the control stream ends the '
          'connection', () async {
        for (final action in ['fin', 'reset', 'stop']) {
          final (connection, raw) = await bindingAndRaw();
          // The binding has the control stream: its HELLO came back.
          expect((await raw.nextControl()).type, quicHelloType);
          final control = raw.control!;
          switch (action) {
            case 'fin':
              await control.finish();
            case 'reset':
              control.reset(0);
            case 'stop':
              control.stop(0);
          }
          expect(
            await connection.done.timeout(limit),
            hasCode(StatusCode.protocolError),
            reason: action,
          );
        }
      });

      test('an unknown control type is ignored', () async {
        final (connection, raw) = await bindingAndRaw();
        expect((await raw.nextControl()).type, quicHelloType);
        await raw.sendControl(MuxControlMessage(0x7E, Uint8List(3)));
        await raw.sendControl(MuxControlMessage.ping(hexBytes('DE AD')));
        final pong = await raw.nextControl();
        expect(pong.knownType, MuxControlType.pong);
        expect(pong.payload, hexBytes('DE AD'));
        expect(connection.isOpen, isTrue);
      });
    });
  });

  group('bulk channels', () {
    test('OPEN, channel 3, _bulk for parent channel 2, bulk number 1', () {
      expect(
        hex(encodeOpenRecord(3, TalkBulkOpen(2, 1).encode())),
        '19 00 00 40 03 00 00 00 00 00 01 5F 62 75 6C 6B 00 00 00 02 00 00 '
        '00 00 00 01 00 00 00',
      );
    });

    test('OPEN, channel 4, _bulk for parent channel 2, bulk number 2', () {
      expect(
        hex(encodeOpenRecord(4, TalkBulkOpen(2, 2).encode())),
        '19 00 00 40 04 00 00 00 00 00 01 5F 62 75 6C 6B 00 00 00 02 00 00 '
        '00 00 00 02 00 00 00',
      );
    });
  });

  group('status codes', () {
    for (final (status, raw, http3, wire) in [
      (0, '00', 0x52E4A40FA8DB, 'C0 00 52 E4 A4 0F A8 DB'),
      (1, '01', 0x52E4A40FA8DC, 'C0 00 52 E4 A4 0F A8 DC'),
      (5, '05', 0x52E4A40FA8E0, 'C0 00 52 E4 A4 0F A8 E0'),
      (8, '08', 0x52E4A40FA8E3, 'C0 00 52 E4 A4 0F A8 E3'),
      (14, '0E', 0x52E4A40FA8E9, 'C0 00 52 E4 A4 0F A8 E9'),
      (16, '10', 0x52E4A40FA8EB, 'C0 00 52 E4 A4 0F A8 EB'),
      (32, '20', 0x52E4A40FA8FC, 'C0 00 52 E4 A4 0F A8 FC'),
      (33, '21', 0x52E4A40FA8FD, 'C0 00 52 E4 A4 0F A8 FD'),
      (35, '23', 0x52E4A40FA8FF, 'C0 00 52 E4 A4 0F A8 FF'),
      (36, '24', 0x52E4A40FA900, 'C0 00 52 E4 A4 0F A9 00'),
      (37, '25', 0x52E4A40FA901, 'C0 00 52 E4 A4 0F A9 01'),
      (255, '40 FF', 0x52E4A40FA9E2, 'C0 00 52 E4 A4 0F A9 E2'),
    ]) {
      test('$status', () {
        expect(quicErrorCode(Status(status)), status);
        expect(hex(encodeQuicVarint(status)), raw);
        expect(webTransportCodeToHttp3(status), http3);
        expect(hex(encodeQuicVarint(http3)), wire);
        expect(webTransportCodeFromHttp3(http3), status);
        expect(statusOfQuicErrorCode(status).code, status);
      });
    }

    test('the mapping skips the reserved HTTP/3 codepoints', () {
      expect(webTransportCodeToHttp3(29), 0x52E4A40FA8F8);
      expect(webTransportCodeToHttp3(30), 0x52E4A40FA8FA);
      expect(webTransportCodeFromHttp3(0x52E4A40FA8F9), isNull);
      for (var code = 0; code < 1000; code++) {
        expect(webTransportCodeFromHttp3(webTransportCodeToHttp3(code)), code);
      }
      expect(webTransportCodeFromHttp3(0x52E4A40FA8DA), isNull);
    });

    test('a received code of 256 or more, or none, reads as UNKNOWN', () {
      expect(statusOfQuicErrorCode(256).known, StatusCode.unknown);
      expect(statusOfQuicErrorCode(0x52E4A40FA8DB).known, StatusCode.unknown);
      expect(statusOfQuicErrorCode(null).known, StatusCode.unknown);
    });

    test('only codes 0 to 255 are sent: CONNECTION_LOST as UNAVAILABLE, '
        'application codes never', () {
      expect(
        quicErrorCode(Status.of(StatusCode.connectionLost)),
        StatusCode.unavailable.code,
      );
      expect(() => quicErrorCode(const Status(256)), throwsArgumentError);
    });
  });

  group('exporter', () {
    test('WebTransport: TLS exporter label EXPORTER-WebTransport', () {
      expect(
        hex(webTransportExporterLabel.codeUnits),
        '45 58 50 4F 52 54 45 52 2D 57 65 62 54 72 61 6E 73 70 6F 72 74',
      );
    });

    test('WebTransport: TLS exporter context, session ID 0 and 4', () {
      expect(
        hex(webTransportExporterContext(0)),
        '00 00 00 00 00 00 00 00 11 73 77 69 74 63 68 62 6F 61 72 64 2D 69 '
        '64 65 6E 74 00',
      );
      expect(
        hex(webTransportExporterContext(4)),
        '00 00 00 00 00 00 00 04 11 73 77 69 74 63 68 62 6F 61 72 64 2D 69 '
        '64 65 6E 74 00',
      );
    });

    test('Raw QUIC: TLS exporter label EXPORTER-Channel-Binding', () {
      expect(
        hex(rawQuicExporterLabel.codeUnits),
        '45 58 50 4F 52 54 45 52 2D 43 68 61 6E 6E 65 6C 2D 42 69 6E 64 69 '
        '6E 67',
      );
    });

    test('both ends of a session derive the same exporter, two sessions '
        'different ones', () async {
      final (a, b) = MemoryQuicSession.pair();
      final (c, _) = MemoryQuicSession.pair();
      final x = await a.exportKeyingMaterial(
        rawQuicExporterLabel,
        Uint8List(0),
        32,
      );
      expect(
        await b.exportKeyingMaterial(rawQuicExporterLabel, Uint8List(0), 32),
        x,
      );
      expect(
        await c.exportKeyingMaterial(rawQuicExporterLabel, Uint8List(0), 32),
        isNot(x),
      );
    });
  });

  group('example', () {
    test('the browser opens chat/1 and asks for its HISTORY', () {
      // Its control stream: the OPEN record and its HELLO.
      expect(
        hex([
          ...encodeOpenRecord(0, const []),
          ...encodeDataRecord(QuicHello().toControlMessage().encode()),
        ]),
        '06 00 00 40 00 00 00 00 00 00 '
        '0A 00 00 00 08 F0 7F 00 00 00 00 00 00 00',
      );
      // The hub's HELLO.
      expect(
        hex(
          encodeDataRecord(
            QuicHello(
              recordLimit: 1 << 20,
              channels: 100,
              exporter: true,
            ).toControlMessage().encode(),
          ),
        ),
        '0A 00 00 00 08 00 00 10 00 64 00 00 00 01',
      );
      // Channel 2 and the request.
      expect(
        hex(
          encodeOpenRecord(
            2,
            ChannelAddress(type: Name('chat'), instance: 1).encode(),
          ),
        ),
        '15 00 00 40 02 00 00 00 00 00 03 63 68 61 74 00 00 00 00 01 00 00 '
        '00 00 00',
      );
      expect(
        hex(
          encodeDataRecord(
            TalkFrame(
              kind: TalkKind.message,
              procedure: Name('HISTORY'),
              requestId: 1,
              payload: hexBytes('14 00'),
            ).encode(),
          ),
        ),
        '0E 00 00 00 03 48 49 53 54 4F 52 59 00 01 00 00 14 00',
      );
    });

    test('the hub answers with a bulk payload on channel 3', () {
      expect(
        hex(encodeOpenRecord(3, TalkBulkOpen(2, 1).encode())),
        '19 00 00 40 03 00 00 00 00 00 01 5F 62 75 6C 6B 00 00 00 02 00 00 '
        '00 00 00 01 00 00 00',
      );
      expect(
        hex(
          encodeDataRecord(
            TalkFrame(
              kind: TalkKind.message,
              responseId: 1,
            ).withBulk(TalkBulkReference(1, length: 100000)).encode(),
          ),
        ),
        '0E 00 00 00 44 01 00 00 01 00 00 00 A0 86 01 00 00 00',
      );
      // The payload in records of the browser's limit, then the close.
      final headers = <String>[];
      var left = 100000;
      while (left > 0) {
        final n = left < quicDefaultRecordLimit ? left : quicDefaultRecordLimit;
        final header = Uint8List(4);
        writeQuicRecordHeader(header, 0, QuicRecordCommand.data, n);
        headers.add(hex(header));
        left -= n;
      }
      expect(headers, [
        'F0 7F 00 00',
        'F0 7F 00 00',
        'F0 7F 00 00',
        'D0 06 00 00',
      ]);
      expect(hex(encodeCloseRecord(Status.ok)), '00 00 00 80');
    });
  });
}
