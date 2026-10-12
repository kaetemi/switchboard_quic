/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// The server side of tool/web_smoke.sh, for the browser tests of the web
// provider (test/web_provider_test.dart, test/web_binding_test.dart): native
// WebTransport listeners on 127.0.0.1 with a fresh self-signed certificate
// (ECDSA P-256, valid 14 days, what a browser accepts for
// serverCertificateHashes), any origin allowed, the protocol `switchboard`:
//
// * /provider: sessions for the provider tests, each behaving as the query
//   says (`?case=echo&id=...`; see _serve) and recording what the server saw
//   under its id; a `?case=report&id=...` session answers the records of an
//   id on its first stream, as JSON;
// * /limited: the same, on a listener that grants two streams at once;
// * /sb: a Switchboard node (QuicSwitchboardListener, QuicIdentityRules.none,
//   so that the nonce-bound IDENTs of a browser without
//   exportKeyingMaterial are accepted) with Talk services: `echo`,
//   `control` (TAG, WHOAMI, GOAWAY, CLOSE), and `issue` (a credential for a
//   holder key, so that a browser can identify);
// * a UDP port that never answers, for a handshake that times out.
//
// Prints `READY {json}` (the URLs and the certificate hash), then serves
// until SIGTERM or SIGINT (or a watchdog of 10 minutes), and exits 0.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:switchboard/switchboard.dart';
import 'package:switchboard_quic/switchboard_quic.dart';
import 'package:switchboard_quic/switchboard_quic_native.dart';

final Map<String, List<Map<String, Object?>>> records = {};

/// The listeners' handshake deadline, which the tests outlive.
const Duration handshakeTimeout = Duration(seconds: 2);

void record(String id, Map<String, Object?> event) =>
    (records[id] ??= []).add(event);

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Future<void> main() async {
  if (Platform.environment['WEB_SERVER_LOG'] == '1') {
    hierarchicalLoggingEnabled = true;
    Logger.root.level = Level.ALL;
    Logger.root.onRecord.listen(
      (r) => stderr.writeln(
        'server ${r.time.toIso8601String().substring(17)} ${r.loggerName} '
        '${r.level.name}: ${r.message}',
      ),
    );
  }
  final provider = NativeQuicProvider();
  final cert = NativeQuicProvider.generateSelfSigned('127.0.0.1');
  // A short handshake deadline (it also bounds the HTTP/3 exchanges), so
  // that the tests show a quiet session outliving it.
  QuicServerConfig config({int streams = 129}) => QuicServerConfig(
    alpn: const [switchboardAlpn],
    certificateDer: cert.certificateDer,
    privateKeyDer: cert.privateKeyDer,
    maxStreamsBidi: streams,
    handshakeTimeout: handshakeTimeout,
  );

  final raw = await provider.listenWebTransport(
    '127.0.0.1',
    0,
    config(),
    path: '/provider',
  );
  final limited = await provider.listenWebTransport(
    '127.0.0.1',
    0,
    config(streams: 2),
    path: '/limited',
  );
  raw.sessions.listen((s) => unawaited(_serve(s as NativeQuicSession)));
  limited.sessions.listen((s) => unawaited(_serve(s as NativeQuicSession)));

  final authority = await CredentialIssuer.ed25519FromSeed(
    Name('webauth'),
    Uint8List.fromList(List.generate(32, (i) => 11 * i + 1)),
  );
  final verifier = CredentialVerifier();
  await verifier.addIssuer(authority);
  final node = Switchboard(verifier: verifier);
  node.registerService(Name('echo'), (incoming) {
    incoming.talk().messages.listen((m) {
      if (m.expectsReply) unawaited(m.reply(m.payload));
    });
  });
  node.registerService(Name('issue'), (incoming) {
    incoming.talk().messages.listen((m) async {
      final credential = await authority.issue(
        kind: CredentialKind.node,
        identity: 'browser-1',
        holderKey: m.payload,
      );
      if (m.expectsReply) await m.reply(credential.encode());
    });
  });
  node.registerService(Name('control'), (incoming) {
    final connection = incoming.connection;
    incoming.talk().messages.listen((m) {
      final text = utf8.decode(m.payload);
      switch (m.procedureName) {
        case 'TAG':
          record(text, {'event': 'tagged', 'remote': incoming.remote});
          connection.done.then((status) {
            record(text, {
              'event': 'connection done',
              'code': status.code,
              'reason': status.reason,
            });
          });
          connection.peerGoAwayStatus.then((status) {
            record(text, {'event': 'peer goaway', 'code': status.code});
          });
          if (m.expectsReply) unawaited(m.reply(Uint8List(0)));
        case 'WHOAMI':
          final identity = connection.peerIdentity?.identity ?? '';
          if (m.expectsReply) unawaited(m.reply(utf8.encode(identity)));
        case 'GOAWAY':
          if (m.expectsReply) unawaited(m.reply(Uint8List(0)));
          Timer(const Duration(milliseconds: 50), () {
            unawaited(connection.goAway());
          });
        case 'CLOSE':
          Timer(const Duration(milliseconds: 50), () {
            unawaited(connection.close());
          });
      }
    });
  });
  final sb = await provider.listenWebTransport(
    '127.0.0.1',
    0,
    config(),
    path: '/sb',
  );
  final listener = await QuicSwitchboardListener.start(
    node,
    sb,
    identityRules: QuicIdentityRules.none,
  );

  final silent = await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0);
  silent.listen((_) => silent.receive());

  final ready = {
    'provider': 'https://127.0.0.1:${raw.port}/provider',
    'limited': 'https://127.0.0.1:${limited.port}/limited',
    'node': 'https://127.0.0.1:${sb.port}/sb',
    'silent': 'https://127.0.0.1:${silent.port}/sb',
    'certificateSha256': hex(cert.sha256),
    'handshakeTimeoutMs': handshakeTimeout.inMilliseconds,
  };
  print('READY ${jsonEncode(ready)}');

  final stop = Completer<void>();
  final watchdog = Timer(const Duration(minutes: 10), () {
    stderr.writeln('web server: watchdog expired');
    if (!stop.isCompleted) stop.complete();
  });
  final signals = [
    ProcessSignal.sigterm.watch().listen((_) {
      if (!stop.isCompleted) stop.complete();
    }),
    ProcessSignal.sigint.watch().listen((_) {
      if (!stop.isCompleted) stop.complete();
    }),
  ];
  await stop.future;
  watchdog.cancel();
  for (final s in signals) {
    await s.cancel();
  }
  silent.close();
  await listener.close();
  await node.close();
  await raw.close();
  await limited.close();
  NativeQuicProvider.shutdown();
  exit(0);
}

/// One session of the provider tests, as its query's `case` says, recording
/// under its `id`.
Future<void> _serve(NativeQuicSession session) async {
  final query = Uri.parse(session.requestPath ?? '/').queryParameters;
  final kind = query['case'] ?? '';
  final id = query['id'] ?? '';
  if (kind == 'report') {
    await _report(session, id);
    return;
  }
  record(id, {
    'event': 'session',
    'case': kind,
    'protocol': session.protocol,
    'origin': session.requestOrigin,
  });
  final exporter = await session.exportKeyingMaterial(
    'switchboard-ident',
    Uint8List(0),
    32,
  );
  record(id, {
    'event': 'exporter',
    'value': exporter == null ? null : hex(exporter),
  });
  unawaited(
    session.done.then((end) {
      record(id, {
        'event': 'end',
        'code': end.code,
        'reason': end.reason,
        'byPeer': end.byPeer,
        'lost': end.lost,
      });
    }),
  );
  if (kind == 'open') {
    try {
      final s = await session.openStream();
      await s.write(utf8.encode('from server'));
      await s.finish();
      record(id, {'event': 'opened'});
    } on Object catch (e) {
      record(id, {'event': 'open failed', 'error': '$e'});
    }
  }
  var index = 0;
  await for (final stream in session.incomingStreams) {
    final i = index++;
    unawaited(_stream(session, stream, kind, id, i));
  }
}

Future<void> _stream(
  NativeQuicSession session,
  QuicStream stream,
  String kind,
  String id,
  int i,
) async {
  stream.resetReceived
      .then(
        (code) => record(id, {'event': 'reset', 'stream': i, 'code': code}),
        onError: (Object _) {},
      )
      .ignore();
  stream.stopped
      .then(
        (code) => record(id, {
          'event': code == null ? 'acknowledged' : 'stopped',
          'stream': i,
          'code': code,
        }),
        onError: (Object e) {
          if (e is QuicStreamStopped) {
            record(id, {'event': 'stopped', 'stream': i, 'code': e.code});
          }
        },
      )
      .ignore();
  try {
    switch (kind) {
      case 'echo':
        final bytes = await _readAll(stream);
        record(id, {'event': 'fin', 'stream': i, 'bytes': bytes.length});
        await stream.write(bytes);
        await stream.finish();
      case 'sink':
        final bytes = await _readAll(stream);
        record(id, {'event': 'fin', 'stream': i, 'bytes': bytes.length});
      case 'send':
        final header = await _readExactly(stream, 4);
        final size = ByteData.sublistView(header).getUint32(0);
        await stream.write(pattern(size));
        await stream.finish();
        record(id, {'event': 'sent', 'stream': i, 'bytes': size});
      case 'reset':
        await stream.read(65536);
        await stream.write(utf8.encode('partial'));
        await Future<void>.delayed(const Duration(milliseconds: 100));
        stream.reset(14);
        record(id, {'event': 'reset sent', 'stream': i});
      case 'stop':
        await stream.read(65536);
        stream.stop(9);
        record(id, {'event': 'stop sent', 'stream': i});
      case 'close':
        await stream.read(65536);
        await session.close(9, 'server bye');
      case 'drain':
        await stream.read(65536);
        session.drain();
        record(id, {'event': 'drain sent'});
      case 'hold':
        break;
    }
  } on QuicStreamReset catch (e) {
    record(id, {'event': 'read reset', 'stream': i, 'code': e.code});
  } on QuicStreamStopped catch (e) {
    record(id, {'event': 'write stopped', 'stream': i, 'code': e.code});
  } on QuicException catch (e) {
    record(id, {'event': 'stream failed', 'stream': i, 'error': e.kind.name});
  }
}

/// The records of [id] on the first stream of the session, then its end.
Future<void> _report(NativeQuicSession session, String id) async {
  await for (final stream in session.incomingStreams) {
    try {
      await _readAll(stream);
      await stream.write(utf8.encode(jsonEncode(records[id] ?? const [])));
      await stream.finish();
    } on Object {
      // The browser gave up.
    }
    break;
  }
}

Future<Uint8List> _readAll(QuicStream stream) async {
  final got = BytesBuilder();
  while (true) {
    final chunk = await stream.read(65536);
    if (chunk == null) return got.takeBytes();
    got.add(chunk);
  }
}

Future<Uint8List> _readExactly(QuicStream stream, int n) async {
  final got = BytesBuilder();
  while (got.length < n) {
    final chunk = await stream.read(n - got.length);
    if (chunk == null) throw StateError('FIN after ${got.length} bytes');
    got.add(chunk);
  }
  return got.takeBytes();
}

/// [n] bytes of a pattern the browser checks.
Uint8List pattern(int n) =>
    Uint8List.fromList(List.generate(n, (i) => (i * 31 + (i >> 8)) & 0xFF));
