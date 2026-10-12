/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GLM 5.3 Flash <noreply@z.ai>
  GPT-6 Astra <noreply@openai.com>
*/

// The native provider end to end over loopback: both sides in this isolate,
// the shim's runtime underneath. The cases of the contract run twice, over
// raw QUIC and over WebTransport sessions (HTTP/3 in the shim); the cases
// particular to either follow.

@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:switchboard_quic/switchboard_quic_native.dart';
import 'package:test/test.dart';

late NativeQuicProvider provider;
late NativeCertificate cert;

/// The two kinds of session the provider runs.
enum Mode {
  raw('raw QUIC'),
  webTransport('WebTransport');

  const Mode(this.label);
  final String label;

  bool get wt => this == Mode.webTransport;

  /// The label the binding asks for: RFC 9266's on raw QUIC, the
  /// application's over WebTransport (where the provider derives the rest).
  String get exporterLabel =>
      wt ? 'switchboard-ident' : 'EXPORTER-Channel-Binding';

  /// The largest stream and close code.
  int get maxCode => wt ? 0xFFFFFFFF : (1 << 62) - 1;

  String get scheme => wt ? 'https' : 'quic';
}

QuicServerConfig serverConfig({
  int maxStreams = 128,
  int window = 1 << 20,
  int connectionWindow = 16 << 20,
  Duration idle = const Duration(seconds: 30),
  Duration keepAlive = const Duration(seconds: 10),
  Duration handshake = const Duration(seconds: 10),
}) => QuicServerConfig(
  alpn: const [quicAlpn],
  certificateDer: cert.certificateDer,
  privateKeyDer: cert.privateKeyDer,
  maxStreamsBidi: maxStreams,
  streamReceiveWindow: window,
  connectionReceiveWindow: connectionWindow,
  idleTimeout: idle,
  keepAlive: keepAlive,
  handshakeTimeout: handshake,
);

QuicClientConfig clientConfig({
  List<String> alpn = const [quicAlpn],
  List<Uint8List> pins = const [],
  bool verify = false,
  int window = 1 << 20,
  Duration idle = const Duration(seconds: 30),
  Duration keepAlive = const Duration(seconds: 10),
  Duration handshake = const Duration(seconds: 10),
}) => QuicClientConfig(
  alpn: alpn,
  serverCertificateHashes: pins,
  verifyCertificate: verify,
  streamReceiveWindow: window,
  idleTimeout: idle,
  keepAlive: keepAlive,
  handshakeTimeout: handshake,
);

/// A listener and its accepted sessions, closed after the test: raw QUIC, or
/// WebTransport on the path `/sb`.
class Server {
  Server._(this.listener, this.mode)
    : sessions = StreamQueue(listener.sessions);

  static Future<Server> start(
    Mode mode, [
    QuicServerConfig? config,
    Iterable<String>? allowedOrigins,
    List<String> protocols = const ['switchboard'],
  ]) async {
    final QuicListener listener = mode.wt
        ? await provider.listenWebTransport(
            '127.0.0.1',
            0,
            config ?? serverConfig(),
            path: '/sb',
            allowedOrigins: allowedOrigins,
            protocols: protocols,
          )
        : await provider.listen('127.0.0.1', 0, config ?? serverConfig());
    final server = Server._(listener, mode);
    addTearDown(server.close);
    return server;
  }

  final QuicListener listener;
  final Mode mode;
  final StreamQueue<QuicSession> sessions;
  final _accepted = <QuicSession>[];

  Uri get endpoint => listener.endpoint;
  int get port => endpoint.port;

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
      server.endpoint,
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

Matcher throwsKind(QuicExceptionKind kind) =>
    throwsA(isA<QuicException>().having((e) => e.kind, 'kind', kind));

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

Future<void> closeOnlyInIsolate(String endpoint) => Isolate.run(() async {
  final session = await NativeQuicProvider().connect(
    Uri.parse(endpoint),
    const QuicClientConfig(alpn: ['switchboard'], verifyCertificate: false),
  );
  await session.close(9, 'x' * 1024);
  // Give automatic context cleanup a turn before Isolate.run exits.
  await Future<void>.delayed(const Duration(milliseconds: 100));
});

void main() {
  setUpAll(() {
    provider = NativeQuicProvider();
    cert = NativeQuicProvider.generateSelfSigned('localhost');
  });

  tearDownAll(NativeQuicProvider.shutdown);

  group('certificates and configurations', () {
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

    test('unsupported schemes and unreachable endpoints', () async {
      await expectLater(
        provider.connect(Uri.parse('wss://127.0.0.1:4433/sb'), clientConfig()),
        throwsKind(QuicExceptionKind.unsupportedScheme),
      );
      await expectLater(
        provider.connectWebTransport(
          Uri.parse('quic://127.0.0.1:4433'),
          clientConfig(),
        ),
        throwsKind(QuicExceptionKind.unsupportedScheme),
      );
      await expectLater(
        provider.connect(Uri.parse('quic://127.0.0.1'), clientConfig()),
        throwsA(isA<QuicException>()),
      );
      for (final endpoint in ['quic://127.0.0.1:9', 'https://127.0.0.1:9/sb']) {
        await expectLater(
          provider.connect(
            Uri.parse(endpoint),
            clientConfig(idle: const Duration(milliseconds: 300)),
          ),
          throwsKind(QuicExceptionKind.unreachable),
        );
      }
      // WebTransport fields are printable ASCII.
      await expectLater(
        provider.connect(
          Uri.parse('https://127.0.0.1:9/sb'),
          clientConfig(alpn: const ['é']),
        ),
        throwsArgumentError,
      );
    });

    test('the handshake deadline ends a connect to a peer that never answers, '
        'even without an idle timeout', () async {
      // Bound, so that nothing reports the port unreachable, and silent.
      final silent = await RawDatagramSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      addTearDown(silent.close);
      var received = 0;
      silent.listen((event) {
        if (event == RawSocketEvent.read) {
          while (silent.receive() != null) {
            received++;
          }
        }
      });
      for (final scheme in ['quic', 'https']) {
        final watch = Stopwatch()..start();
        await expectLater(
          provider.connect(
            Uri.parse('$scheme://127.0.0.1:${silent.port}/sb'),
            clientConfig(
              idle: Duration.zero,
              keepAlive: Duration.zero,
              handshake: const Duration(milliseconds: 300),
            ),
          ),
          throwsKind(QuicExceptionKind.unreachable),
        );
        expect(
          watch.elapsed,
          greaterThanOrEqualTo(const Duration(milliseconds: 290)),
        );
        expect(watch.elapsed, lessThan(const Duration(seconds: 2)));
      }
      expect(received, greaterThan(0));
    });

    test('a negative duration in a configuration is an ArgumentError, and a '
        'deadline under a millisecond is still a deadline', () async {
      const negative = Duration(microseconds: -1);
      for (final nowhere in [
        Uri.parse('quic://127.0.0.1:9'),
        Uri.parse('https://127.0.0.1:9/sb'),
      ]) {
        for (final config in [
          clientConfig(idle: negative),
          clientConfig(keepAlive: negative),
          clientConfig(handshake: negative),
        ]) {
          await expectLater(
            provider.connect(nowhere, config),
            throwsArgumentError,
          );
        }
      }
      for (final config in [
        serverConfig(idle: negative),
        serverConfig(keepAlive: negative),
        serverConfig(handshake: negative),
      ]) {
        await expectLater(
          provider.listen('127.0.0.1', 0, config),
          throwsArgumentError,
        );
        await expectLater(
          provider.listenWebTransport('127.0.0.1', 0, config, path: '/sb'),
          throwsArgumentError,
        );
      }
      await expectLater(
        provider.listenWebTransport('127.0.0.1', 0, serverConfig(), path: 'sb'),
        throwsArgumentError,
      );
      // Rounded up to a millisecond, not down to none: without an idle
      // timeout nothing else would end this connect.
      final silent = await RawDatagramSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      addTearDown(silent.close);
      await expectLater(
        provider
            .connect(
              Uri.parse('quic://127.0.0.1:${silent.port}'),
              clientConfig(
                idle: Duration.zero,
                keepAlive: Duration.zero,
                handshake: const Duration(microseconds: 1),
              ),
            )
            .timeout(const Duration(seconds: 2)),
        throwsKind(QuicExceptionKind.unreachable),
      );
    });
  });

  for (final mode in Mode.values) {
    group(mode.label, () => contract(mode));
  }

  group('raw QUIC only', () {
    test('no unidirectional streams and no draining signal', () async {
      final server = await Server.start(Mode.raw);
      final p = await Pair.connect(server);
      final serverUni = p.server.incomingUnidirectionalStreams.toList();
      final clientUni = p.client.incomingUnidirectionalStreams.toList();
      var draining = false;
      unawaited(p.server.draining.then((_) => draining = true));
      unawaited(p.client.draining.then((_) => draining = true));
      // drain() does nothing on raw QUIC.
      (p.client as NativeQuicSession).drain();
      // The binding's traffic goes on as usual meanwhile.
      final cs = await p.client.openStream();
      await cs.write(bytes('x'));
      await cs.finish();
      expect(await readAll(await p.serverStreams.next), bytes('x'));
      await p.client.close(0, '');
      await p.server.done;
      // Both are done with the session, having delivered nothing.
      expect(await clientUni.timeout(const Duration(seconds: 5)), isEmpty);
      expect(await serverUni.timeout(const Duration(seconds: 5)), isEmpty);
      await Future<void>.delayed(Duration.zero);
      expect(draining, isFalse);
    });
  });

  group('WebTransport only', () {
    test('the request: path, origin, protocols, draft', () async {
      final server = await Server.start(Mode.webTransport);
      expect(server.endpoint.toString(), 'https://127.0.0.1:${server.port}/sb');
      final accepted = server.accept();
      final client = await provider.connectWebTransport(
        Uri.parse('https://127.0.0.1:${server.port}/sb?room=1#ignored'),
        clientConfig(alpn: const ['other', 'switchboard']),
        origin: 'https://app.example',
      );
      addTearDown(() => client.close(0, ''));
      final session = await accepted as NativeQuicSession;
      expect(session.isWebTransport, isTrue);
      expect(session.requestPath, '/sb?room=1');
      expect(session.requestOrigin, 'https://app.example');
      expect(session.requestAuthority, '127.0.0.1:${server.port}');
      expect(session.requestProtocols, ['other', 'switchboard']);
      // This provider's client sends the draft-02 header too.
      expect(session.requestDraft, 2);
      // The first offered protocol the listener serves, in the client's order.
      expect(client.protocol, 'switchboard');
      expect(session.protocol, 'switchboard');
      expect((client as NativeQuicSession).requestPath, isNull);
    });

    test('refusals: another path 404, an origin not allowed 403, a protocol '
        'not served 400', () async {
      final server = await Server.start(Mode.webTransport, null, [
        'https://app.example',
      ]);
      final listener = server.listener as NativeWebTransportListener;
      Future<void> refused(
        String path,
        int status, {
        String? origin,
        List<String> alpn = const [quicAlpn],
      }) => expectLater(
        provider.connectWebTransport(
          Uri.parse('https://127.0.0.1:${server.port}$path'),
          clientConfig(alpn: alpn),
          origin: origin,
        ),
        throwsA(
          isA<QuicException>()
              .having((e) => e.kind, 'kind', QuicExceptionKind.refused)
              .having((e) => e.message, 'message', contains('$status')),
        ),
      );
      await refused('/elsewhere', 404);
      await refused('/sb/', 404);
      await refused('/sb', 403, origin: 'https://evil.example');
      await refused('/sb', 400, alpn: const ['other']);
      expect(listener.answered, {404: 2, 403: 1, 400: 1});
      // An allowed origin, and no origin at all (not a browser), pass.
      for (final origin in ['https://app.example', null]) {
        final accepted = server.accept();
        final client = await provider.connectWebTransport(
          server.endpoint,
          clientConfig(),
          origin: origin,
        );
        await accepted;
        await client.close(0, '');
      }
      expect(listener.answered[200], 2);
    });

    test(
      'partial stream headers arm writable notifications for writes and FIN',
      () async {
        for (final window in [1, 2]) {
          final server = await Server.start(
            Mode.webTransport,
            serverConfig(window: window),
          );
          final p = await Pair.connect(server, clientConfig(window: window));
          final empty = await p.client.openStream();
          await empty.finish().timeout(const Duration(seconds: 5));
          expect(
            await readAll(await p.serverStreams.next)
                .timeout(const Duration(seconds: 5)),
            isEmpty,
          );
          final received = p.serverStreams.next.then(readAll);
          final stream = await p.client.openStream();
          await stream.write(bytes('data')).timeout(const Duration(seconds: 5));
          await stream.finish();
          expect(await received, bytes('data'));
        }
      },
    );

    test('the last session close survives context shutdown with a small CONNECT window', () async {
      final server = await provider.listenWebTransport(
        '127.0.0.1',
        0,
        serverConfig(window: 768),
        path: '/sb',
        advertisedHost: '127.0.0.2',
      );
      addTearDown(server.close);
      // Delay each UDP flight. The close exceeds one stream window and therefore cannot
      // finish before the provider is allowed to tear down the client's context.
      final proxy = await RawDatagramSocket.bind('127.0.0.2', server.port);
      final timers = <Timer>[];
      addTearDown(() {
        for (final timer in timers) {
          timer.cancel();
        }
        proxy.close();
      });
      InternetAddress? peerAddress;
      int? peerPort;
      proxy.listen((event) {
        if (event != RawSocketEvent.read) return;
        Datagram? packet;
        while ((packet = proxy.receive()) != null) {
          final data = packet!;
          final fromServer = data.port == server.port;
          if (!fromServer) {
            peerAddress = data.address;
            peerPort = data.port;
          }
          final target = fromServer
              ? peerAddress!
              : InternetAddress.loopbackIPv4;
          final port = fromServer ? peerPort! : server.port;
          timers.add(
            Timer(const Duration(milliseconds: 100), () {
              proxy.send(data.data, target, port);
            }),
          );
        }
      });
      final incoming = server.sessions.first;
      final endpoint = server.endpoint.toString();
      final client = closeOnlyInIsolate(endpoint);
      final session = await incoming;
      await client.timeout(const Duration(seconds: 10));
      final end = await session.done.timeout(const Duration(seconds: 5));
      expect((end.lost, end.code, end.reason), (false, 9, 'x' * 1024));
    });

    test('binary protocol lengths 127, 128 and 255 survive the ABI', () async {
      for (final length in [127, 128, 255]) {
        final protocol = 'p' * length;
        final server = await Server.start(Mode.webTransport, null, null, [
          protocol,
        ]);
        final p = await Pair.connect(server, clientConfig(alpn: [protocol]));
        expect(p.client.protocol, protocol);
        expect((p.server as NativeQuicSession).requestProtocols, [protocol]);
      }
    });

    test(
      'userinfo and out-of-range ports are refused before dialing',
      () async {
        for (final url in [
          'https://user@localhost/sb',
          'https://localhost:65536/sb',
          'https://localhost:0/sb',
        ]) {
          await expectLater(
            provider.connect(Uri.parse(url), clientConfig()),
            throwsArgumentError,
          );
        }
      },
    );

    test('advertised authority is enforced', () async {
      final listener = await provider.listenWebTransport(
        '127.0.0.1',
        0,
        serverConfig(),
        path: '/sb',
        advertisedHost: 'localhost',
      );
      addTearDown(listener.close);
      final incoming = StreamQueue(listener.sessions);
      addTearDown(incoming.cancel);
      await expectLater(
        provider.connect(
          listener.endpoint.replace(host: '127.0.0.1'),
          clientConfig(),
        ),
        throwsA(
          isA<QuicException>().having(
            (e) => e.message,
            'status',
            contains('404'),
          ),
        ),
      );
      final client = await provider.connect(listener.endpoint, clientConfig());
      final server = await incoming.next;
      await client.close(0, '');
      await server.done;
      expect(listener.answered, {404: 1, 200: 1});
    });

    test('allowed origins match the exact string', () async {
      final server = await Server.start(Mode.webTransport, null, [
        'https://app.example',
      ]);
      for (final origin in [
        'https://app.example/',
        'https://APP.example',
        'https://app.example:443',
        'http://app.example',
        'https://app.example:444',
      ]) {
        await expectLater(
          provider.connectWebTransport(
            server.endpoint,
            clientConfig(),
            origin: origin,
          ),
          throwsA(
            isA<QuicException>().having(
              (e) => e.message,
              'status',
              contains('403'),
            ),
          ),
        );
      }
    });

    test('no protocol offered: accepted without one', () async {
      final server = await Server.start(Mode.webTransport);
      final p = await Pair.connect(server, clientConfig(alpn: const []));
      expect(p.client.protocol, isNull);
      expect(p.server.protocol, isNull);
      expect((p.server as NativeQuicSession).requestProtocols, isEmpty);
    });

    test('draining both ways, and the session goes on', () async {
      final server = await Server.start(Mode.webTransport);
      final p = await Pair.connect(server);
      var serverDraining = false;
      unawaited(p.server.draining.then((_) => serverDraining = true));
      (p.client as NativeQuicSession).drain();
      await p.server.draining.timeout(const Duration(seconds: 5));
      expect(serverDraining, isTrue);
      (p.server as NativeQuicSession).drain();
      await p.client.draining.timeout(const Duration(seconds: 5));
      final cs = await p.client.openStream();
      await cs.write(bytes('still'));
      await cs.finish();
      expect(await readAll(await p.serverStreams.next), bytes('still'));
    });

    test('codes beyond a u32 are argument errors; the largest goes through, '
        'and close codes are WebTransport codes', () async {
      final server = await Server.start(Mode.webTransport);
      final p = await Pair.connect(server);
      final cs = await p.client.openStream();
      await cs.write(bytes('x'));
      final ss = await p.serverStreams.next;
      expect(() => cs.reset(0x100000000), throwsArgumentError);
      expect(() => ss.stop(0x100000000), throwsArgumentError);
      expect(() => p.client.close(0x100000000, ''), throwsArgumentError);
      cs.reset(0xFFFFFFFF);
      await expectLater(
        readAll(ss),
        throwsA(
          isA<QuicStreamReset>().having((e) => e.code, 'code', 0xFFFFFFFF),
        ),
      );
      await p.server.close(0xFFFFFFFF, 'the largest');
      final end = await p.client.done;
      expect(
        (end.code, end.reason, end.byPeer),
        (0xFFFFFFFF, 'the largest', true),
      );
    });

    test('the closed listener accepts no new session', () async {
      final server = await Server.start(Mode.webTransport);
      final p = await Pair.connect(server);
      await server.listener.close();
      await expectLater(
        provider.connect(
          server.endpoint,
          clientConfig(handshake: const Duration(seconds: 2)),
        ),
        throwsA(isA<QuicException>()),
      );
      // The open session is left to its owners.
      final cs = await p.client.openStream();
      await cs.write(bytes('open'));
      await cs.finish();
      expect(await readAll(await p.serverStreams.next), bytes('open'));
    });
  });
}

/// The cases of the provider contract, over [mode].
void contract(Mode mode) {
  final label = mode.exporterLabel;

  group('handshake', () {
    test('unverified client: handshake, protocol, remote', () async {
      final server = await Server.start(mode);
      final p = await Pair.connect(server);
      expect(p.client.isInitiator, isTrue);
      expect(p.server.isInitiator, isFalse);
      expect(p.client.protocol, quicAlpn);
      expect(p.server.protocol, quicAlpn);
      expect(p.client.remote, '127.0.0.1:${server.port}');
      expect(p.server.remote, startsWith('127.0.0.1:'));
      expect(p.client.peerCertificateHash, cert.sha256);
      expect(p.server.peerCertificateHash, isNull);
      expect(p.client.maxIncomingStreams, 128);
      expect(server.endpoint.scheme, mode.scheme);
      expect((p.client as NativeQuicSession).isWebTransport, mode.wt);
      final stats = (p.client as NativeQuicSession).stats!;
      expect(stats.udpTxBytes, greaterThan(0));
    });

    test('pinned client: the right hash connects', () async {
      final server = await Server.start(mode);
      final other = NativeQuicProvider.generateSelfSigned('localhost');
      final p = await Pair.connect(
        server,
        clientConfig(pins: [other.sha256, cert.sha256]),
      );
      expect(p.client.peerCertificateHash, cert.sha256);
    });

    test('pinned client: a wrong hash is rejected', () async {
      final server = await Server.start(mode);
      final other = NativeQuicProvider.generateSelfSigned('localhost');
      await expectLater(
        provider.connect(server.endpoint, clientConfig(pins: [other.sha256])),
        throwsKind(QuicExceptionKind.certificateRejected),
      );
    });

    test('platform verification rejects a self-signed certificate', () async {
      final server = await Server.start(mode);
      await expectLater(
        provider.connect(server.endpoint, clientConfig(verify: true)),
        throwsKind(QuicExceptionKind.certificateRejected),
      );
    });

    test('IPv6 loopback', () async {
      final QuicListener listener;
      try {
        listener = mode.wt
            ? await provider.listenWebTransport(
                '::1',
                0,
                serverConfig(),
                path: '/sb',
              )
            : await provider.listen('::1', 0, serverConfig());
      } on QuicException catch (e) {
        markTestSkipped('no IPv6 loopback: $e');
        return;
      }
      addTearDown(listener.close);
      expect(
        listener.endpoint.toString(),
        startsWith('${mode.scheme}://[::1]:'),
      );
      final accepted = listener.sessions.first;
      final client = await provider.connect(listener.endpoint, clientConfig());
      addTearDown(() => client.close(0, ''));
      final server = await accepted;
      addTearDown(() => server.close(0, ''));
      expect(client.remote, '[::1]:${listener.endpoint.port}');
      expect(server.remote, startsWith('[::1]:'));
    });

    test('exporter: equal on both ends, different across sessions', () async {
      final server = await Server.start(mode);
      final p1 = await Pair.connect(server);
      final p2 = await Pair.connect(server);
      Future<Uint8List> ex(QuicSession s, [String l = '']) async => (await s
          .exportKeyingMaterial(l.isEmpty ? label : l, Uint8List(0), 32))!;
      final c1 = await ex(p1.client), s1 = await ex(p1.server);
      final c2 = await ex(p2.client), s2 = await ex(p2.server);
      expect(c1, hasLength(32));
      expect(c1, s1);
      expect(c2, s2);
      expect(c1, isNot(c2));
      expect(await ex(p1.client, 'other label'), isNot(c1));
      final ctx = await p1.client.exportKeyingMaterial(
        label,
        Uint8List.fromList([1, 2, 3]),
        32,
      );
      expect(ctx, isNot(c1));
      // More than the exporter can produce (255 hash lengths).
      await expectLater(
        p1.client.exportKeyingMaterial(label, Uint8List(0), 1 << 16),
        throwsArgumentError,
      );
    });
  });

  group('streams', () {
    late Server server;
    late Pair p;
    setUp(() async {
      server = await Server.start(mode);
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

    test('a stream with nothing but FIN', () async {
      final cs = await p.client.openStream();
      await cs.finish();
      final ss = await p.serverStreams.next;
      expect(await readAll(ss), isEmpty);
    });

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

    test('a reset is observed by resetReceived while no read is pending, its '
        'unread data discarded', () async {
      final cs = await p.client.openStream();
      await cs.write(pattern(5000));
      final ss = await p.serverStreams.next;
      // The reader takes one byte and pauses; the rest stays in the stack.
      expect(await ss.read(1), pattern(1));
      var reset = false;
      unawaited(ss.resetReceived.then((_) => reset = true));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(reset, isFalse);
      cs.reset(12);
      expect(await ss.resetReceived.timeout(const Duration(seconds: 5)), 12);
      await expectLater(
        ss.read(10),
        throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 12)),
      );
    });

    test('a reset seen by a pending read completes resetReceived too; FIN '
        'never does', () async {
      final cs = await p.client.openStream();
      await cs.write(bytes('a'));
      final ss = await p.serverStreams.next;
      expect(await ss.read(10), bytes('a'));
      final read = ss.read(10);
      cs.reset(4);
      await expectLater(
        read,
        throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 4)),
      );
      expect(await ss.resetReceived, 4);
      final fin = await p.client.openStream();
      await fin.write(bytes('done'));
      await fin.finish();
      final finished = await p.serverStreams.next;
      expect(await readAll(finished), bytes('done'));
      expect(
        await completesWithin(
          finished.resetReceived,
          const Duration(milliseconds: 200),
        ),
        isFalse,
      );
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
      'the opener stops at once: the acceptor\'s stopped has the code',
      () async {
        // The stream and the STOP_SENDING arrive together; the stream is
        // announced before its events, so neither is dropped.
        for (var i = 0; i < 20; i++) {
          final cs = await p.client.openStream();
          await cs.write(bytes('x'));
          cs.stop(5);
          final ss = await p.serverStreams.next;
          expect(await ss.stopped.timeout(const Duration(seconds: 5)), 5);
          await expectLater(
            ss.write(bytes('y')),
            throwsA(isA<QuicStreamStopped>().having((e) => e.code, 'code', 5)),
          );
          expect(await ss.read(10), bytes('x'));
          cs.reset(0);
          await expectLater(
            ss.read(10),
            throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', 0)),
          );
        }
      },
    );

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

    test('codes beyond the range are argument errors', () async {
      final max = mode.maxCode;
      final cs = await p.client.openStream();
      await cs.write(bytes('x'));
      final ss = await p.serverStreams.next;
      expect(() => cs.reset(max + 1), throwsArgumentError);
      expect(() => cs.reset(-1), throwsArgumentError);
      expect(() => ss.stop(max + 1), throwsArgumentError);
      expect(() => p.client.close(max + 1, ''), throwsArgumentError);
      // Nothing was sent: the largest code still goes through afterwards.
      cs.reset(max);
      await expectLater(
        readAll(ss),
        throwsA(isA<QuicStreamReset>().having((e) => e.code, 'code', max)),
      );
    });

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
      final sessionEnded = isA<QuicException>().having(
        (e) => e.kind,
        'kind',
        QuicExceptionKind.sessionEnded,
      );
      // Over WebTransport the closing side resets and stops the session's
      // streams with WT_SESSION_GONE, which may reach the peer before the
      // close itself: a reset or STOP_SENDING without an application code.
      final ended = mode.wt
          ? anyOf(
              sessionEnded,
              isA<QuicStreamReset>().having((e) => e.code, 'code', isNull),
              isA<QuicStreamStopped>().having((e) => e.code, 'code', isNull),
            )
          : sessionEnded;
      // Install both error handlers before closing; the peer may finish before our
      // WebTransport close has been acknowledged and close() completes.
      final readCheck = expectLater(read, throwsA(ended));
      final stoppedCheck = expectLater(stopped, throwsA(ended));
      await p.client.close(5, 'gone');
      await readCheck;
      await stoppedCheck;
      // A reset without a code completes resetReceived with null.
      final reset = await ss.resetReceived.then<Object?>(
        (code) => code,
        onError: (Object e) => e,
      );
      expect(reset, mode.wt ? anyOf(isNull, sessionEnded) : sessionEnded);
      await expectLater(cs.resetReceived, throwsA(sessionEnded));
      await p.server.done;
      await expectLater(p.server.openStream(), throwsA(sessionEnded));
      await expectLater(ss.write(bytes('x')), throwsA(sessionEnded));
      await expectLater(p.client.openStream(), throwsA(sessionEnded));
    });
  });

  group('priorities', () {
    // The contract's classes on quinn's strict levels: 2 (control) strictly
    // first, 1 (ordinary) and 0 (bulk) on one level, interleaved.
    test('the classes on quinn\'s levels', () {
      int level(int c) => NativeQuicStream.quinnPriority(c);
      expect(level(1), level(0));
      expect(level(2), greaterThan(level(1)));
      expect(level(3), greaterThan(level(2)));
      expect(level(-1), lessThan(level(0)));
      expect(level(1 << 40), 0x7FFFFFFF);
    });

    // How far ahead of a stream of class [first] one of class [second]
    // finishes, as a fraction of the transfer, with [first] handed to the
    // stack first and [second] right after, in the same turn. Windows hold
    // everything, so the server's stack takes (and acknowledges) all data
    // without its application reading: the order in which the two finishes
    // are acknowledged is the order the sender transmitted them in. Round
    // robin finishes both within a packet or two of each other (measured:
    // under 1% of the transfer apart); strict priority sends the second one
    // first, and the first one's last bytes go out well later (measured:
    // about 20% of the transfer, the first one having had a head start while
    // the second was being handed over).
    Future<double> lead(Server server, int first, int second) async {
      final p = await Pair.connect(server);
      final a = await p.client.openStream();
      final b = await p.client.openStream();
      a.priority = first;
      b.priority = second;
      final data = pattern(4 << 20);
      final sw = Stopwatch()..start();
      late int ackedA, ackedB;
      final done = Future.wait([
        a.stopped.then((_) => ackedA = sw.elapsedMicroseconds),
        b.stopped.then((_) => ackedB = sw.elapsedMicroseconds),
      ]);
      await Future.wait([
        a.write(data).then((_) => a.finish()),
        b.write(data).then((_) => b.finish()),
      ]);
      await done.timeout(const Duration(seconds: 20));
      for (var i = 0; i < 2; i++) {
        expect(await readAll(await p.serverStreams.next, 1 << 20), data);
      }
      await p.client.close(0, '');
      return (ackedA - ackedB) / math.max(ackedA, ackedB);
    }

    // A measurement that loses a packet at the very end waits for a probe
    // timeout and says nothing about the scheduler: up to three tries.
    Future<double> measure(
      int first,
      int second,
      bool Function(double) ok,
    ) async {
      final server = await Server.start(
        mode,
        serverConfig(window: 8 << 20, connectionWindow: 32 << 20),
      );
      var v = 0.0;
      for (var i = 0; i < 3; i++) {
        v = await lead(server, first, second);
        // ignore: avoid_print
        print(
          '${mode.label}: priority class $second ahead of class $first by '
          '${(v * 100).toStringAsFixed(1)}% of the transfer',
        );
        if (ok(v)) break;
      }
      return v;
    }

    test('control goes strictly before bulk', () async {
      bool ok(double v) => v > 0.1;
      final v = await measure(0, 2, ok);
      expect(ok(v), isTrue, reason: 'control ahead by $v of the transfer');
    });

    test('ordinary and bulk interleave', () async {
      bool ok(double v) => v.abs() < 0.1;
      final v = await measure(0, 1, ok);
      expect(ok(v), isTrue, reason: 'ordinary ahead by $v of the transfer');
    });
  });

  test('stream limit: openStream waits until a stream closes', () async {
    final server = await Server.start(mode, serverConfig(maxStreams: 2));
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
    // End the first stream in both directions: the peer grants a new one. (The
    // streams of a WebTransport session may arrive out of their order: each
    // one's header is read on its own.)
    await s1.finish();
    final a = await p.serverStreams.next;
    final b = await p.serverStreams.next;
    final firstOfA = await a.read(1);
    final r1 = firstOfA![0] == 0x31 ? a : b;
    if (identical(r1, b)) expect(await b.read(1), bytes('1'));
    expect(await readAll(r1), isEmpty);
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
      final server = await Server.start(mode);
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
      final server = await Server.start(mode);
      final p = await Pair.connect(server);
      await p.server.close(33, 'going away');
      final end = await p.client.done;
      expect((end.code, end.reason, end.byPeer), (33, 'going away', true));
    });

    test('lost on idle timeout', () async {
      const idle = Duration(milliseconds: 300);
      final server = await Server.start(
        mode,
        serverConfig(idle: idle, keepAlive: Duration.zero),
      );
      final p = await Pair.connect(
        server,
        clientConfig(idle: idle, keepAlive: Duration.zero),
      );
      // quinn waits at least three probe timeouts, which a handshake on a
      // loaded runner (another suite moving data meanwhile) can stretch to
      // seconds: the bound is generous.
      final client = await p.client.done.timeout(const Duration(seconds: 20));
      final peer = await p.server.done.timeout(const Duration(seconds: 20));
      expect(client.lost, isTrue);
      expect(client.code, isNull);
      expect(peer.lost, isTrue);
    });

    test('the exporter fails once the session has ended', () async {
      final server = await Server.start(mode);
      final p = await Pair.connect(server);
      await p.client.close(0, '');
      await p.client.done;
      await expectLater(
        p.client.exportKeyingMaterial(label, Uint8List(0), 32),
        throwsKind(QuicExceptionKind.sessionEnded),
      );
    });

    test('keep-alive holds an idle connection open', () async {
      const idle = Duration(milliseconds: 400);
      const keepAlive = Duration(milliseconds: 100);
      final server = await Server.start(
        mode,
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
    final server = await Server.start(mode, serverConfig(maxStreams: 300));
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
    final server = await Server.start(mode);
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
      'native provider throughput (${mode.label}): 64 MiB in '
      '${sw.elapsedMilliseconds} ms = ${mbs.toStringAsFixed(0)} MB/s (one '
      'stream, 1 MiB window, JIT)',
    );
  }, timeout: const Timeout(Duration(seconds: 60)));

  test('events while Dart is inside shim calls do not deadlock: 200 '
      'iterations of connect, open, write, read, close', () async {
    final server = await Server.start(mode);
    final data = pattern(64 << 10);
    for (var i = 0; i < 200; i++) {
      final accepted = server.accept();
      final client = await provider.connect(server.endpoint, clientConfig());
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
      final server = await Server.start(mode);
      final endpoint = server.endpoint;
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
    final server = await Server.start(mode);
    final p = await Pair.connect(server);
    final cs = await p.client.openStream();
    final read = expectLater(cs.read(10), throwsA(isA<QuicException>()));
    NativeQuicProvider.shutdown();
    final end = await p.client.done;
    expect(end.byPeer, isFalse);
    expect(end.reason, 'shutdown');
    await read;
    // The provider starts again on next use.
    final again = await Server.start(mode);
    final q = await Pair.connect(again);
    expect(q.client.protocol, quicAlpn);
  });
}
