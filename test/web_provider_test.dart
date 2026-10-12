/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// The web provider against the provider contract, in a browser, against the
// native WebTransport listeners of tool/web_server.dart (started by
// tool/web_smoke.sh; without it every test skips): the protocol, echo,
// read(max), FIN, resets and STOP_SENDING both ways with their codes, the
// application close both ways, draining, refusals, the handshake deadline,
// the exporter, the server's streams, the stream limit, backpressure, two
// sessions at once, and the code ranges of the browser.

@TestOn('browser')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard_quic/switchboard_quic_web.dart';
import 'package:test/test.dart';

import 'web_harness.dart';

Matcher isQuic(QuicExceptionKind kind) =>
    isA<QuicException>().having((e) => e.kind, 'kind', kind);

void main() {
  watchUnhandledRejections();
  test('the browser has WebTransport, and the server selects '
      'switchboard', () async {
    final s = await server();
    if (s == null) return;
    expect(WebQuicProvider.isSupported, isTrue);
    final session = await s.open('echo', newId());
    expect(session.protocol, 'switchboard');
    expect(session.isInitiator, isTrue);
    expect(session.remote, '127.0.0.1:${s.provider.port}');
    expect(session.maxIncomingStreams, isNull);
    expect(session.peerCertificateHash, isNull);
    print(
      'web provider: ${session.capabilities}, stream error codes up to '
      '${WebQuicProvider.maxStreamErrorCode}',
    );
  });

  test('a session that offers no protocol: none selected', () async {
    final s = await server();
    if (s == null) return;
    final session = await const WebQuicProvider().connect(
      s.provider.replace(queryParameters: {'case': 'echo', 'id': newId()}),
      QuicClientConfig(alpn: const [], serverCertificateHashes: [s.hash]),
    );
    expect(session.protocol, isNull);
    await session.close(0, '');
  });

  test('a stream echoed, FIN both ways, acknowledgement', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('echo', id);
    final stream = await session.openStream();
    stream.priority = quicOrdinaryPriority;
    await stream.write(bytes('hello '));
    await stream.write(bytes('switchboard'));
    await stream.finish();
    expect(await stream.stopped.timeout(limit), isNull);
    expect(text(await readAll(stream)), 'hello switchboard');
    expect(await stream.read(10), isNull);
    expect(await stream.read(10), isNull);
    await expectLater(stream.write(bytes('more')), throwsStateError);
    await s.reported(id, (e) => e['event'] == 'fin' && e['bytes'] == 17);
  });

  test('read(max) returns at most max bytes, keeps the rest of a chunk, '
      'then FIN', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('send', newId());
    final stream = await session.openStream();
    const size = 300000;
    await stream.write(Uint8List(4)..buffer.asByteData().setUint32(0, size));
    await stream.finish();
    final got = BytesBuilder();
    final sizes = [1, 7, 4, 1000, 65536, 3, 100000];
    var i = 0;
    while (true) {
      final max = sizes[i++ % sizes.length];
      final chunk = await stream.read(max).timeout(limit);
      if (chunk == null) break;
      expect(chunk, isNotEmpty);
      expect(chunk.length, lessThanOrEqualTo(max));
      got.add(chunk);
    }
    expect(got.takeBytes(), pattern(size));
    expect(await stream.read(1), isNull);
    expect(() => stream.read(0), throwsArgumentError);
  });

  test('a quiet session outlives the server\'s handshake deadline (which '
      'bounds its HTTP/3 exchanges)', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('echo', newId());
    await Future<void>.delayed(
      s.handshakeTimeout + const Duration(milliseconds: 1500),
    );
    final stream = await session.openStream();
    await stream.write(bytes('still here'));
    await stream.finish();
    expect(text(await readAll(stream)), 'still here');
    expect(await pendingAfter(session.done, Duration.zero), isTrue);
  });

  test('only one read may be pending', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('hold', newId());
    final stream = await session.openStream();
    await stream.write(bytes('x'));
    final pending = expectLater(
      stream.read(10),
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    expect(() => stream.read(10), throwsStateError);
    await session.close(0, '');
    await pending;
  });

  test('reset(42) reaches the server as 42; writes after it are state '
      'errors', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('sink', id);
    final stream = await session.openStream();
    await stream.write(bytes('abc'));
    // Once the server has the stream: quinn drops what it buffered of a
    // stream once its reset arrives, so a reset that reaches the server
    // before it read the stream's header loses the header, and without
    // RESET_STREAM_AT the server cannot tell which session the stream
    // belonged to (Chrome sends the header, the data and the reset about a
    // millisecond apart).
    await s.reported(id, (e) => e['event'] == 'stream');
    stream.reset(42);
    stream.reset(43); // A no-op.
    expect(await stream.stopped.timeout(limit), isNull);
    await expectLater(stream.write(bytes('d')), throwsStateError);
    await expectLater(stream.finish(), throwsStateError);
    await s.reported(id, (e) => e['event'] == 'reset' && e['code'] == 42);
  });

  test('the server\'s reset arrives as 14, also for a reader that is not '
      'reading', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('reset', id);
    final stream = await session.openStream();
    await stream.write(bytes('go'));
    // Nobody reads: the reset is still observed.
    expect(await stream.resetReceived.timeout(limit), 14);
    await expectLater(
      stream.read(100),
      throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 14)),
    );
    await expectLater(
      stream.read(100),
      throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 14)),
    );
  });

  test('stop(5) reaches the server as STOP_SENDING 5, and ends the read '
      'direction at once', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('sink', id);
    final stream = await session.openStream();
    await stream.write(bytes('x'));
    final pending = stream.read(100);
    stream.stop(5);
    stream.stop(6); // A no-op.
    await expectLater(
      pending,
      throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 5)),
    );
    await expectLater(
      stream.read(100),
      throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 5)),
    );
    await s.reported(id, (e) => e['event'] == 'stopped' && e['code'] == 5);
    expect(await pendingAfter(stream.resetReceived, Duration.zero), isTrue);
  });

  test('the server\'s STOP_SENDING 9 completes stopped with 9 and fails '
      'writes', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('stop', newId());
    final stream = await session.openStream();
    await stream.write(bytes('first'));
    expect(await stream.stopped.timeout(limit), 9);
    await expectLater(
      stream.write(bytes('second')),
      throwsA(isA<QuicStreamStopped>().having((e) => e.code, 'code', 9)),
    );
    await expectLater(stream.finish(), throwsA(isA<QuicStreamStopped>()));
  });

  test('close(7, reason) reaches the server; the session ends as a local '
      'application close', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('sink', id);
    final stream = await session.openStream();
    await stream.write(bytes('x'));
    await session.close(7, 'browser done').timeout(limit);
    final end = await session.done;
    expect(end.code, 7);
    expect(end.reason, 'browser done');
    expect(end.byPeer, isFalse);
    expect(end.lost, isFalse);
    await session.close(8, 'again'); // Idempotent.
    await expectLater(
      session.openStream(),
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    await expectLater(
      stream.write(bytes('y')),
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    final seen = await s.reported(id, (e) => e['event'] == 'end');
    expect(seen['code'], 7);
    expect(seen['reason'], 'browser done');
    expect(seen['byPeer'], isTrue);
  });

  test('a reason is cut to 1024 bytes of UTF-8 at a character '
      'boundary', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('sink', id);
    await session.close(300, 'é' * 600);
    final seen = await s.reported(id, (e) => e['event'] == 'end');
    expect(seen['code'], 300);
    expect(seen['reason'], 'é' * 512);
    expect(() => session.close(-1, ''), throwsArgumentError);
    expect(() => session.close(0x100000000, ''), throwsArgumentError);
  });

  test('the server\'s close is the session\'s end with its code and reason; '
      'what is pending fails', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('close', newId());
    final stream = await session.openStream();
    final reset = expectLater(
      stream.resetReceived,
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    final stopped = expectLater(
      stream.stopped,
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    final pending = expectLater(
      stream.read(10),
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    await stream.write(bytes('x'));
    final end = await session.done.timeout(limit);
    expect(end.code, 9);
    expect(end.reason, 'server bye');
    expect(end.byPeer, isTrue);
    expect(end.lost, isFalse);
    await pending;
    await reset;
    await stopped;
    await expectLater(
      session.openStream(),
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
    await expectLater(
      session.exportKeyingMaterial('switchboard-ident', Uint8List(0), 32),
      throwsA(isQuic(QuicExceptionKind.sessionEnded)),
    );
  });

  test('draining completes on the server\'s drain where the browser has '
      'the promise, and stays pending where it has not', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('drain', id);
    final stream = await session.openStream();
    await stream.write(bytes('x'));
    await s.reported(id, (e) => e['event'] == 'drain sent');
    if (session.capabilities['draining']!) {
      await session.draining.timeout(limit);
    } else {
      expect(
        await pendingAfter(session.draining, const Duration(milliseconds: 300)),
        isTrue,
      );
    }
  });

  test('a refused path, a wrong certificate hash, a closed port: the '
      'connect fails', () async {
    final s = await server();
    if (s == null) return;
    const provider = WebQuicProvider();
    await expectLater(
      provider.connect(s.provider.replace(path: '/nope'), s.config()),
      throwsA(isQuic(QuicExceptionKind.handshakeFailed)),
    );
    await expectLater(
      provider.connect(
        s.provider,
        QuicClientConfig(
          alpn: const ['switchboard'],
          serverCertificateHashes: [Uint8List(32)],
        ),
      ),
      throwsA(isQuic(QuicExceptionKind.handshakeFailed)),
    );
    await expectLater(
      provider.connect(s.provider.replace(port: 1), s.config()),
      throwsA(isQuic(QuicExceptionKind.handshakeFailed)),
    );
  });

  test('the handshake deadline: a server that never answers', () async {
    final s = await server();
    if (s == null) return;
    final watch = Stopwatch()..start();
    await expectLater(
      const WebQuicProvider().connect(
        s.silent,
        s.config(handshake: const Duration(milliseconds: 500)),
      ),
      throwsA(isQuic(QuicExceptionKind.unreachable)),
    );
    expect(watch.elapsed, lessThan(const Duration(seconds: 5)));
  });

  test('schemes and arguments', () async {
    const provider = WebQuicProvider();
    final config = QuicClientConfig(alpn: const ['switchboard']);
    for (final uri in ['quic://127.0.0.1:4433', 'wss://127.0.0.1/sb']) {
      await expectLater(
        provider.connect(Uri.parse(uri), config),
        throwsA(isQuic(QuicExceptionKind.unsupportedScheme)),
      );
    }
    await expectLater(
      provider.connect(
        Uri.parse('https://127.0.0.1:1/sb'),
        QuicClientConfig(
          alpn: const ['switchboard'],
          idleTimeout: const Duration(seconds: -1),
        ),
      ),
      throwsArgumentError,
    );
    await expectLater(
      provider.connect(
        Uri.parse('https://127.0.0.1:1/sb'),
        QuicClientConfig(
          alpn: const ['switchboard'],
          serverCertificateHashes: [Uint8List(16)],
        ),
      ),
      throwsArgumentError,
    );
    await expectLater(
      provider.connect(
        Uri.parse('https://127.0.0.1:1/sb'),
        QuicClientConfig(alpn: const ['a', 'a']),
      ),
      throwsArgumentError,
    );
  });

  test('the exporter: null without exportKeyingMaterial (Chrome 149), the '
      'server\'s value with it', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final session = await s.open('sink', id);
    final exporter = await session.exportKeyingMaterial(
      'switchboard-ident',
      Uint8List(0),
      32,
    );
    final seen = await s.reported(id, (e) => e['event'] == 'exporter');
    if (!session.capabilities['exportKeyingMaterial']!) {
      expect(exporter, isNull);
      expect(seen['value'], hasLength(64));
    } else {
      expect(exporter, hasLength(32));
      expect(
        exporter!.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
        seen['value'],
      );
    }
    expect(
      () => session.exportKeyingMaterial('x', Uint8List(0), 0),
      throwsArgumentError,
    );
  });

  test('a stream the server opens arrives on incomingStreams', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('open', newId());
    final stream = await session.incomingStreams.first.timeout(limit);
    expect(text(await readAll(stream)), 'from server');
    await stream.finish();
  });

  test('incomingUnidirectionalStreams: the native server cannot open one; '
      'the stream ends with the session', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('hold', newId());
    final streams = session.incomingUnidirectionalStreams.toList();
    await session.close(0, '');
    expect(await streams.timeout(limit), isEmpty);
  });

  test('openStream waits for stream credit, in order', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('echo', newId(), base: s.limited);
    final first = await session.openStream();
    final second = await session.openStream();
    await first.write(bytes('1'));
    await second.write(bytes('2'));
    final third = session.openStream();
    final fourth = session.openStream();
    expect(
      await pendingAfter(third, const Duration(milliseconds: 500)),
      isTrue,
    );
    // The first stream ends both ways: its credit returns.
    await first.finish();
    expect(text(await readAll(first)), '1');
    final opened = await third.timeout(limit);
    await opened.write(bytes('3'));
    await opened.finish();
    expect(await pendingAfter(fourth, Duration.zero), isTrue);
    await second.finish();
    expect(text(await readAll(second)), '2');
    expect(text(await readAll(opened)), '3');
    final last = await fourth.timeout(limit);
    await last.write(bytes('4'));
    await last.finish();
    expect(text(await readAll(last)), '4');
  });

  test('writes wait while the server reads nothing, and fail when the '
      'session ends', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('hold', newId());
    final stream = await session.openStream();
    final chunk = Uint8List(65536);
    var written = 0;
    Future<void>? stalled;
    for (var i = 0; i < 256; i++) {
      final w = stream.write(chunk);
      if (await pendingAfter(w, const Duration(milliseconds: 300))) {
        stalled = w;
        break;
      }
      written += chunk.length;
    }
    expect(stalled, isNotNull, reason: 'wrote $written bytes unhindered');
    expect(written, lessThan(16 << 20));
    print('web provider: writes stalled after $written bytes');
    await session.close(0, '');
    await expectLater(stalled, throwsA(isQuic(QuicExceptionKind.sessionEnded)));
  });

  test('two sessions at once', () async {
    final s = await server();
    if (s == null) return;
    final a = await s.open('echo', newId());
    final b = await s.open('echo', newId());
    final sa = await a.openStream();
    final sb = await b.openStream();
    await sa.write(bytes('alpha'));
    await sb.write(bytes('beta'));
    await sb.finish();
    await sa.finish();
    expect(text(await readAll(sb)), 'beta');
    expect(text(await readAll(sa)), 'alpha');
    await a.close(1, 'a');
    expect(
      (await b.done.timeout(
        Duration.zero,
        onTimeout: () {
          return const QuicSessionEnd.lost('still open');
        },
      )).reason,
      'still open',
    );
    final again = await b.openStream();
    await again.write(bytes('gamma'));
    await again.finish();
    expect(text(await readAll(again)), 'gamma');
  });

  test('stream codes: what the browser carries, and no more', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('hold', newId());
    final stream = await session.openStream();
    final max = WebQuicProvider.maxStreamErrorCode;
    expect(max, greaterThanOrEqualTo(255));
    expect(() => stream.reset(-1), throwsArgumentError);
    expect(() => stream.stop(0x100000000), throwsArgumentError);
    if (max < 0xFFFFFFFF) {
      expect(() => stream.reset(max + 1), throwsArgumentError);
      expect(() => stream.stop(max + 1), throwsArgumentError);
    }
    stream.reset(255);
    stream.stop(255);
  });

  test('priorities: send orders where the browser has them', () async {
    final s = await server();
    if (s == null) return;
    expect(WebQuicProvider.sendOrderOf(quicControlPriority), 1);
    expect(WebQuicProvider.sendOrderOf(quicOrdinaryPriority), 0);
    expect(WebQuicProvider.sendOrderOf(quicBulkPriority), 0);
    final session = await s.open('echo', newId());
    final stream = await session.openStream() as WebQuicStream;
    stream.priority = quicControlPriority;
    print(
      'web provider: send orders ${stream.hasSendOrder}, '
      'send groups ${session.hasSendGroups}',
    );
    await stream.write(bytes('p'));
    await stream.finish();
    expect(text(await readAll(stream)), 'p');
  });

  test('stats where the browser has getStats', () async {
    final s = await server();
    if (s == null) return;
    final session = await s.open('echo', newId());
    final stats = await session.stats();
    if (session.capabilities['getStats']!) {
      expect(stats, isNotNull);
    } else {
      expect(stats, isNull);
    }
  });
}
