/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GLM 5.3 Flash <noreply@z.ai>
*/

// The native provider end to end over loopback: both sides in this isolate,
// the shim's runtime underneath.

@TestOn('vm')
library;

import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:switchboard_quic/switchboard_quic_native.dart';
import 'package:test/test.dart';

const _exporterLabel = 'EXPORTER-Channel-Binding';

late NativeQuicProvider provider;
late NativeCertificate cert;

QuicServerConfig serverConfig({
  int maxStreams = 128,
  int window = 1 << 20,
  int connectionWindow = 16 << 20,
  Duration idle = const Duration(seconds: 30),
  Duration keepAlive = const Duration(seconds: 10),
}) => QuicServerConfig(
  alpn: const [quicAlpn],
  certificateDer: cert.certificateDer,
  privateKeyDer: cert.privateKeyDer,
  maxStreamsBidi: maxStreams,
  streamReceiveWindow: window,
  connectionReceiveWindow: connectionWindow,
  idleTimeout: idle,
  keepAlive: keepAlive,
);

QuicClientConfig clientConfig({
  List<Uint8List> pins = const [],
  bool verify = false,
  int window = 1 << 20,
  Duration idle = const Duration(seconds: 30),
  Duration keepAlive = const Duration(seconds: 10),
}) => QuicClientConfig(
  alpn: const [quicAlpn],
  serverCertificateHashes: pins,
  verifyCertificate: verify,
  streamReceiveWindow: window,
  idleTimeout: idle,
  keepAlive: keepAlive,
);

/// A listener and its accepted sessions, closed after the test.
class Server {
  Server._(this.listener) : sessions = StreamQueue(listener.sessions);

  static Future<Server> start([QuicServerConfig? config]) async {
    final listener = await provider.listen(
      '127.0.0.1',
      0,
      config ?? serverConfig(),
    );
    final server = Server._(listener);
    addTearDown(server.close);
    return server;
  }

  final NativeQuicListener listener;
  final StreamQueue<QuicSession> sessions;
  final _accepted = <QuicSession>[];

  Future<QuicSession> accept() async {
    final s = await sessions.next;
    _accepted.add(s);
    return s;
  }

  Future<void> close() async {
    for (final s in _accepted) {
      await s.close(0, '');
    }
    await listener.close();
    await sessions.cancel();
  }
}

/// A client session and the server session it reached.
class Pair {
  Pair(this.client, this.server)
    : serverStreams = StreamQueue(server.incomingStreams),
      clientStreams = StreamQueue(client.incomingStreams);

  final QuicSession client;
  final QuicSession server;
  final StreamQueue<QuicStream> serverStreams;
  final StreamQueue<QuicStream> clientStreams;

  static Future<Pair> connect(Server server, [QuicClientConfig? config]) async {
    final accepted = server.accept();
    final client = await provider.connect(
      server.listener.endpoint,
      config ?? clientConfig(),
    );
    final pair = Pair(client, await accepted);
    addTearDown(() => client.close(0, ''));
    return pair;
  }
}

Uint8List bytes(String s) => Uint8List.fromList(s.codeUnits);

Uint8List pattern(int length, [int seed = 0]) {
  final b = Uint8List(length);
  for (var i = 0; i < length; i++) {
    b[i] = (i * 31 + seed) & 0xFF;
  }
  return b;
}

Future<Uint8List> readAll(QuicStream s, [int max = 65536]) async {
  final out = BytesBuilder(copy: false);
  while (true) {
    final c = await s.read(max);
    if (c == null) return out.takeBytes();
    out.add(c);
  }
}

/// Completes with true if [f] completes within [d], false otherwise.
Future<bool> completesWithin(Future<Object?> f, Duration d) => f
    .then((_) => true, onError: (_) => true)
    .timeout(d, onTimeout: () => false);

/// Connects from a new isolate, echoes a message through one stream, closes
/// with 9; the isolate has to exit by itself afterwards.
Future<String> clientInIsolate(Uri endpoint) => Isolate.run(() async {
  final provider = NativeQuicProvider();
  final client = await provider.connect(
    endpoint,
    const QuicClientConfig(alpn: [quicAlpn], verifyCertificate: false),
  );
  final s = await client.openStream();
  await s.write(Uint8List.fromList('from another isolate'.codeUnits));
  await s.finish();
  final back = await readAll(s);
  await client.close(9, 'bye');
  return String.fromCharCodes(back);
});

void main() {
  setUpAll(() {
    provider = NativeQuicProvider();
    cert = NativeQuicProvider.generateSelfSigned('localhost');
  });

  tearDownAll(NativeQuicProvider.shutdown);

  group('certificates and handshake', () {
    test('self-signed certificate', () {
      expect(cert.certificateDer[0], 0x30);
      expect(cert.privateKeyDer, isNotEmpty);
      expect(cert.sha256, hasLength(32));
      expect(
        NativeQuicProvider.certificateHash(cert.certificateDer),
        cert.sha256,
      );
      final other = NativeQuicProvider.generateSelfSigned('10.0.0.1');
      expect(other.sha256, isNot(cert.sha256));
    });

    test('unverified client: handshake, protocol, remote', () async {
      final server = await Server.start();
      final p = await Pair.connect(server);
      expect(p.client.isInitiator, isTrue);
      expect(p.server.isInitiator, isFalse);
      expect(p.client.protocol, quicAlpn);
      expect(p.server.protocol, quicAlpn);
      expect(p.client.remote, '127.0.0.1:${server.listener.port}');
      expect(p.server.remote, startsWith('127.0.0.1:'));
      expect(p.client.peerCertificateHash, cert.sha256);
      expect(p.server.peerCertificateHash, isNull);
      expect(p.client.maxIncomingStreams, 128);
      expect(server.listener.endpoint.scheme, 'quic');
      final stats = (p.client as NativeQuicSession).stats!;
      expect(stats.udpTxBytes, greaterThan(0));
    });

    test('pinned client: the right hash connects', () async {
      final server = await Server.start();
      final other = NativeQuicProvider.generateSelfSigned('localhost');
      final p = await Pair.connect(
        server,
        clientConfig(pins: [other.sha256, cert.sha256]),
      );
      expect(p.client.peerCertificateHash, cert.sha256);
    });

    test('pinned client: a wrong hash is rejected', () async {
      final server = await Server.start();
      final other = NativeQuicProvider.generateSelfSigned('localhost');
      await expectLater(
        provider.connect(
          server.listener.endpoint,
          clientConfig(pins: [other.sha256]),
        ),
        throwsA(
          isA<QuicException>().having(
            (e) => e.kind,
            'kind',
            QuicExceptionKind.certificateRejected,
          ),
        ),
      );
    });

    test('platform verification rejects a self-signed certificate', () async {
      final server = await Server.start();
      await expectLater(
        provider.connect(server.listener.endpoint, clientConfig(verify: true)),
        throwsA(
          isA<QuicException>().having(
            (e) => e.kind,
            'kind',
            QuicExceptionKind.certificateRejected,
          ),
        ),
      );
    });

    test('unsupported schemes and unreachable endpoints', () async {
      await expectLater(
        provider.connect(
          Uri.parse('https://127.0.0.1:4433/sb'),
          clientConfig(),
        ),
        throwsA(
          isA<QuicException>().having(
            (e) => e.kind,
            'kind',
            QuicExceptionKind.unsupportedScheme,
          ),
        ),
      );
      await expectLater(
        provider.connect(Uri.parse('quic://127.0.0.1'), clientConfig()),
        throwsA(isA<QuicException>()),
      );
      await expectLater(
        provider.connect(
          Uri.parse('quic://127.0.0.1:9'),
          clientConfig(idle: const Duration(milliseconds: 300)),
        ),
        throwsA(
          isA<QuicException>().having(
            (e) => e.kind,
            'kind',
            QuicExceptionKind.unreachable,
          ),
        ),
      );
    });

    test('IPv6 loopback', () async {
      final NativeQuicListener listener;
      try {
        listener = await provider.listen('::1', 0, serverConfig());
      } on QuicException catch (e) {
        markTestSkipped('no IPv6 loopback: $e');
        return;
      }
      addTearDown(listener.close);
      expect(listener.endpoint.toString(), startsWith('quic://[::1]:'));
      final accepted = listener.sessions.first;
      final client = await provider.connect(listener.endpoint, clientConfig());
      addTearDown(() => client.close(0, ''));
      final server = await accepted;
      addTearDown(() => server.close(0, ''));
      expect(client.remote, '[::1]:${listener.port}');
      expect(server.remote, startsWith('[::1]:'));
    });

    test(
      'exporter: equal on both ends, different across connections',
      () async {
        final server = await Server.start();
        final p1 = await Pair.connect(server);
        final p2 = await Pair.connect(server);
        Future<Uint8List> ex(
          QuicSession s, [
          String label = _exporterLabel,
        ]) async => (await s.exportKeyingMaterial(label, Uint8List(0), 32))!;
        final c1 = await ex(p1.client), s1 = await ex(p1.server);
        final c2 = await ex(p2.client), s2 = await ex(p2.server);
        expect(c1, hasLength(32));
        expect(c1, s1);
        expect(c2, s2);
        expect(c1, isNot(c2));
        expect(await ex(p1.client, 'other label'), isNot(c1));
        final ctx = await p1.client.exportKeyingMaterial(
          _exporterLabel,
          Uint8List.fromList([1, 2, 3]),
          32,
        );
        expect(ctx, isNot(c1));
      },
    );
  });

  group('streams', () {
    late Server server;
    late Pair p;
    setUp(() async {
      server = await Server.start();
      p = await Pair.connect(server);
    });

    test('a second read while one is pending throws StateError', () async {
      final cs = await p.client.openStream();
      // A write first: nothing of the stream is visible to the peer before it.
      await cs.write(bytes('hi'));
      // Nothing from the peer yet: the read stays pending, a second is rejected.
      final pending = cs.read(10);
      expect(() => cs.read(10), throwsStateError);
      final ss = await p.serverStreams.next;
      await ss.write(bytes('x'));
      expect(await pending, bytes('x'));
    });

    test('both directions with FIN; read returns null at FIN', () async {
      final cs = await p.client.openStream();
      await cs.write(bytes('hello '));
      await cs.write(bytes('world'));
      await cs.finish();
      final ss = await p.serverStreams.next;
      expect(String.fromCharCodes(await readAll(ss)), 'hello world');
      expect(await ss.read(10), isNull);
      await ss.write(bytes('back'));
      await ss.finish();
      expect(String.fromCharCodes(await readAll(cs)), 'back');
      expect(await cs.read(10), isNull);
      // Finish, then stopped completes with null once acknowledged.
      expect(await cs.stopped, isNull);
      expect(await ss.stopped, isNull);
      expect(() => cs.write(bytes('late')), throwsStateError);
    });

    test(
      'finish is idempotent; write after finish throws StateError',
      () async {
        final cs = await p.client.openStream();
        await cs.write(bytes('fin'));
        final f = cs.finish();
        // Same future on a second call; writes are rejected at once, before the
        // FIN has reached the peer.
        expect(cs.finish(), same(f));
        await f;
        expect(() => cs.write(bytes('late')), throwsStateError);
        final ss = await p.serverStreams.next;
        expect(await readAll(ss), bytes('fin'));
      },
    );

    test('writes take views and unmodifiable lists', () async {
      final cs = await p.client.openStream();
      final data = pattern(100000, 3);
      await cs.write(Uint8List.sublistView(data, 0, 10));
      await cs.write(data.sublist(10, 50000).asUnmodifiableView());
      await cs.write(Uint8List.sublistView(data, 50000));
      await cs.write(Uint8List(0));
      await cs.finish();
      final ss = await p.serverStreams.next;
      expect(await readAll(ss), data);
    });

    test('a stream the server opens', () async {
      final ss = await p.server.openStream();
      await ss.write(bytes('push'));
      await ss.finish();
      final cs = await p.clientStreams.next;
      expect(String.fromCharCodes(await readAll(cs)), 'push');
      await cs.finish();
      expect(await readAll(ss), isEmpty);
    });

    test('reset is observed as QuicStreamReset with the code', () async {
      final cs = await p.client.openStream();
      await cs.write(bytes('abc'));
      final ss = await p.serverStreams.next;
      cs.reset(9);
      expect(await cs.stopped, isNull);
      await expectLater(
        readAll(ss),
        throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 9)),
      );
      await expectLater(
        ss.read(10),
        throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 9)),
      );
      expect(() => cs.write(bytes('x')), throwsStateError);
    });

    test('stop is observed as QuicStreamStopped, stopped completes with the '
        'code', () async {
      final cs = await p.client.openStream();
      await cs.write(bytes('x'));
      final ss = await p.serverStreams.next;
      expect(await ss.read(10), bytes('x'));
      final pending = ss.read(10);
      ss.stop(7);
      // The stopping side's read direction ends at once, with its own code.
      await expectLater(
        pending,
        throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 7)),
      );
      expect(await cs.stopped, 7);
      await expectLater(
        cs.write(bytes('y')),
        throwsA(isA<QuicStreamStopped>().having((e) => e.code, 'code', 7)),
      );
      await expectLater(cs.finish(), throwsA(isA<QuicStreamStopped>()));
      // The other direction still works.
      await ss.write(bytes('z'));
      await ss.finish();
      expect(await readAll(cs), bytes('z'));
    });

    test(
      'a second stop is a no-op; reads keep failing with the code',
      () async {
        final cs = await p.client.openStream();
        await cs.write(bytes('x'));
        final ss = await p.serverStreams.next;
        await ss.read(10);
        ss.stop(7);
        ss.stop(7);
        for (var i = 0; i < 2; i++) {
          await expectLater(
            ss.read(10),
            throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 7)),
          );
        }
      },
    );

    test('a write waiting for credit fails when the peer stops', () async {
      final cs = await p.client.openStream();
      final write = cs.write(pattern(4 << 20));
      final ss = await p.serverStreams.next;
      expect(
        await completesWithin(write, const Duration(milliseconds: 200)),
        isFalse,
      );
      ss.stop(3);
      await expectLater(
        write,
        throwsA(isA<QuicStreamStopped>().having((e) => e.code, 'code', 3)),
      );
    });

    test('backpressure: a 4 MiB write stalls until the peer reads', () async {
      final data = pattern(4 << 20, 5);
      final cs = await p.client.openStream();
      final write = cs.write(data);
      final ss = await p.serverStreams.next;
      expect(
        await completesWithin(write, const Duration(milliseconds: 300)),
        isFalse,
      );
      final reading = readAll(ss, 1 << 20);
      await write;
      await cs.finish();
      expect(await reading, data);
    });

    test('pending operations fail when the session ends', () async {
      final cs = await p.client.openStream();
      await cs.write(bytes('x'));
      final ss = await p.serverStreams.next;
      expect(await ss.read(1), bytes('x'));
      final read = ss.read(10);
      final stopped = ss.stopped;
      await p.client.close(5, 'gone');
      final sessionEnded = isA<QuicException>().having(
        (e) => e.kind,
        'kind',
        QuicExceptionKind.sessionEnded,
      );
      await expectLater(read, throwsA(sessionEnded));
      await expectLater(stopped, throwsA(sessionEnded));
      await expectLater(p.server.openStream(), throwsA(sessionEnded));
      await expectLater(ss.write(bytes('x')), throwsA(sessionEnded));
      await expectLater(p.client.openStream(), throwsA(sessionEnded));
    });
  });

  test('priorities: the higher-priority stream finishes first', () async {
    // Windows hold everything, so the server's stack takes (and acknowledges)
    // all data without its application reading: the order in which the two
    // finishes are acknowledged is the order the sender transmitted them in.
    final server = await Server.start(
      serverConfig(window: 8 << 20, connectionWindow: 32 << 20),
    );
    final p = await Pair.connect(server);
    final low = await p.client.openStream();
    final high = await p.client.openStream();
    low.priority = 0;
    high.priority = 1;
    final data = pattern(4 << 20);
    final sw = Stopwatch()..start();
    final acked = <String, int>{};
    final done = Future.wait([
      low.stopped.then((_) => acked['low'] = sw.elapsedMicroseconds),
      high.stopped.then((_) => acked['high'] = sw.elapsedMicroseconds),
    ]);
    // Low first, high second, in the same turn. Round robin would interleave
    // them and finish both within a packet or two of each other (measured:
    // under 1% of the transfer apart); strict priority sends the high one
    // first, and the low one's last bytes go out well later (measured: about
    // 20% of the transfer, the low one having had a head start while the high
    // one was being handed over).
    await Future.wait([
      low.write(data).then((_) => low.finish()),
      high.write(data).then((_) => high.finish()),
    ]);
    await done.timeout(const Duration(seconds: 20));
    final gap = acked['low']! - acked['high']!;
    expect(gap, greaterThan(0), reason: 'acknowledged: $acked');
    expect(
      gap / acked['low']!,
      greaterThan(0.1),
      reason: 'acknowledged: $acked',
    );
    for (var i = 0; i < 2; i++) {
      expect(await readAll(await p.serverStreams.next, 1 << 20), data);
    }
  });

  test('stream limit: openStream waits until a stream closes', () async {
    final server = await Server.start(serverConfig(maxStreams: 2));
    final p = await Pair.connect(server);
    final s1 = await p.client.openStream();
    final s2 = await p.client.openStream();
    await s1.write(bytes('1'));
    await s2.write(bytes('2'));
    final third = p.client.openStream();
    expect(
      await completesWithin(third, const Duration(milliseconds: 300)),
      isFalse,
    );
    // End the first stream in both directions: the peer grants a new one.
    await s1.finish();
    final r1 = await p.serverStreams.next;
    expect(await readAll(r1), bytes('1'));
    await r1.finish();
    final s3 = await third.timeout(const Duration(seconds: 5));
    await s3.write(bytes('3'));
    // Raising the limit at runtime lets a waiting open through as well.
    final fourth = p.client.openStream();
    expect(
      await completesWithin(fourth, const Duration(milliseconds: 200)),
      isFalse,
    );
    (p.server as NativeQuicSession).setMaxIncomingStreams(3);
    expect(p.server.maxIncomingStreams, 3);
    await fourth.timeout(const Duration(seconds: 5));
  });

  group('session end', () {
    test('close with code and reason is seen by the peer', () async {
      final server = await Server.start();
      final p = await Pair.connect(server);
      final reason = 'bad record ${'é' * 600}';
      await p.client.close(42, reason);
      final mine = await p.client.done;
      final theirs = await p.server.done;
      expect(mine.code, 42);
      expect(mine.byPeer, isFalse);
      expect(mine.lost, isFalse);
      expect(theirs.code, 42);
      expect(theirs.byPeer, isTrue);
      expect(theirs.lost, isFalse);
      // Cut to 1024 bytes at a character boundary, possibly more by QUIC.
      expect(reason, startsWith(theirs.reason));
      expect(theirs.reason, startsWith('bad record é'));
      // Idempotent.
      await p.client.close(1, 'again');
    });

    test('the server closes', () async {
      final server = await Server.start();
      final p = await Pair.connect(server);
      await p.server.close(33, 'going away');
      final end = await p.client.done;
      expect((end.code, end.reason, end.byPeer), (33, 'going away', true));
    });

    test('lost on idle timeout', () async {
      const idle = Duration(milliseconds: 300);
      final server = await Server.start(
        serverConfig(idle: idle, keepAlive: Duration.zero),
      );
      final p = await Pair.connect(
        server,
        clientConfig(idle: idle, keepAlive: Duration.zero),
      );
      final client = await p.client.done.timeout(const Duration(seconds: 5));
      final peer = await p.server.done.timeout(const Duration(seconds: 5));
      expect(client.lost, isTrue);
      expect(client.code, isNull);
      expect(peer.lost, isTrue);
    });

    test('the exporter fails once the session has ended', () async {
      final server = await Server.start();
      final p = await Pair.connect(server);
      await p.client.close(0, '');
      await p.client.done;
      await expectLater(
        p.client.exportKeyingMaterial(_exporterLabel, Uint8List(0), 32),
        throwsA(
          isA<QuicException>().having(
            (e) => e.kind,
            'kind',
            QuicExceptionKind.sessionEnded,
          ),
        ),
      );
    });

    test('keep-alive holds an idle connection open', () async {
      const idle = Duration(milliseconds: 400);
      const keepAlive = Duration(milliseconds: 100);
      final server = await Server.start(
        serverConfig(idle: idle, keepAlive: keepAlive),
      );
      final p = await Pair.connect(
        server,
        clientConfig(idle: idle, keepAlive: keepAlive),
      );
      expect(
        await completesWithin(p.client.done, const Duration(seconds: 1)),
        isFalse,
      );
      await p.client.close(0, '');
    });
  });

  test('256 streams concurrently', () async {
    final server = await Server.start(serverConfig(maxStreams: 300));
    final p = await Pair.connect(server);
    final echo = () async {
      final tasks = <Future<void>>[];
      for (var i = 0; i < 256; i++) {
        final s = await p.serverStreams.next;
        tasks.add(() async {
          final data = await readAll(s);
          await s.write(data);
          await s.finish();
        }());
      }
      await Future.wait(tasks);
    }();
    final results = await Future.wait([
      for (var i = 0; i < 256; i++)
        () async {
          final s = await p.client.openStream();
          final data = pattern(16 << 10, i);
          await s.write(data);
          await s.finish();
          final back = await readAll(s);
          return back.length == data.length && back[1] == data[1];
        }(),
    ]);
    await echo;
    expect(results.every((ok) => ok), isTrue);
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('64 MiB through one stream', () async {
    final server = await Server.start();
    final p = await Pair.connect(server);
    const total = 64 << 20;
    final chunk = pattern(256 << 10);
    final sw = Stopwatch()..start();
    final tx = await p.client.openStream();
    final writer = () async {
      for (var sent = 0; sent < total; sent += chunk.length) {
        await tx.write(chunk);
      }
      await tx.finish();
    }();
    final rx = await p.serverStreams.next;
    var received = 0;
    while (true) {
      final c = await rx.read(1 << 20);
      if (c == null) break;
      received += c.length;
    }
    await writer;
    sw.stop();
    expect(received, total);
    final mbs = total / sw.elapsedMicroseconds;
    // ignore: avoid_print
    print(
      'native provider throughput: 64 MiB in ${sw.elapsedMilliseconds} ms = '
      '${mbs.toStringAsFixed(0)} MB/s (one stream, 1 MiB window, JIT)',
    );
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('events while Dart is inside shim calls do not deadlock: 200 '
      'iterations of connect, open, write, read, close', () async {
    final server = await Server.start();
    final data = pattern(64 << 10);
    for (var i = 0; i < 200; i++) {
      final accepted = server.accept();
      final client = await provider.connect(
        server.listener.endpoint,
        clientConfig(),
      );
      final peer = await accepted;
      final echo = peer.incomingStreams.first.then((s) async {
        final got = await readAll(s);
        await s.write(got);
        await s.finish();
      });
      final s = await client.openStream();
      await s.write(data);
      await s.finish();
      final back = await readAll(s);
      expect(back.length, data.length);
      await echo;
      await client.close(0, 'iteration $i');
      await peer.done;
    }
  }, timeout: const Timeout(Duration(seconds: 120)));

  test(
    'another isolate has a context of its own, and exits when done',
    () async {
      final server = await Server.start();
      final endpoint = server.listener.endpoint;
      final echoed = () async {
        final session = await server.accept();
        final s = await session.incomingStreams.first;
        final got = await readAll(s);
        await s.write(got);
        await s.finish();
        return session.done;
      }();
      final reply = await clientInIsolate(endpoint)
          .timeout(const Duration(seconds: 20));
      expect(reply, 'from another isolate');
      final end = await echoed.timeout(const Duration(seconds: 5));
      expect((end.code, end.byPeer), (9, true));
    },
  );

  test('shutdown ends every session of the isolate', () async {
    final server = await Server.start();
    final p = await Pair.connect(server);
    final cs = await p.client.openStream();
    final read = expectLater(cs.read(10), throwsA(isA<QuicException>()));
    NativeQuicProvider.shutdown();
    final end = await p.client.done;
    expect(end.byPeer, isFalse);
    expect(end.reason, 'shutdown');
    await read;
    // The provider starts again on next use.
    final again = await Server.start();
    final q = await Pair.connect(again);
    expect(q.client.protocol, quicAlpn);
  });
}
