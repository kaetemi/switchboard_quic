/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// What the browser tests of the web provider share: the server's
// description, which tool/web_smoke.sh writes to test/web_server.json
// before the run (the test runner serves the package directory, so the
// page fetches it next to itself), sessions to the server's cases, and the
// records of what the server saw.

import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:math';
import 'dart:typed_data';

import 'package:switchboard_quic/switchboard_quic_web.dart';
import 'package:test/test.dart';
import 'package:web/web.dart' as web;

/// The longest any one wait of a test takes.
const Duration limit = Duration(seconds: 10);

/// The server tool/web_server.dart runs: its endpoints and certificate.
class WebServer {
  WebServer._(
    this.provider,
    this.limited,
    this.node,
    this.silent,
    this.hash,
    this.handshakeTimeout,
  );

  /// The provider tests' listener (`?case=...&id=...`).
  final Uri provider;

  /// The same, granting two streams at once.
  final Uri limited;

  /// The Switchboard node's WebTransport listener.
  final Uri node;

  /// A UDP port that never answers.
  final Uri silent;

  /// The SHA-256 of the server's certificate.
  final Uint8List hash;

  /// The handshake deadline of the server's listeners.
  final Duration handshakeTimeout;

  /// The client configuration of the server's sessions.
  QuicClientConfig config({Duration handshake = limit}) => QuicClientConfig(
    alpn: const ['switchboard'],
    serverCertificateHashes: [hash],
    handshakeTimeout: handshake,
  );

  /// A session of [kind] on [base] (the provider listener by default),
  /// whose records go under [id].
  Future<WebQuicSession> open(String kind, String id, {Uri? base}) async {
    final uri = (base ?? provider).replace(
      queryParameters: {'case': kind, 'id': id},
    );
    final session = await const WebQuicProvider()
        .connect(uri, config())
        .timeout(limit);
    addTearDown(() => session.close(0, '').timeout(limit));
    return session as WebQuicSession;
  }

  /// What the server recorded under [id].
  Future<List<Map<String, Object?>>> report(String id) async {
    final uri = provider.replace(queryParameters: {'case': 'report', 'id': id});
    final session = await const WebQuicProvider().connect(uri, config());
    try {
      final stream = await session.openStream();
      await stream.finish();
      final bytes = await readAll(stream);
      return [
        for (final e in jsonDecode(utf8.decode(bytes)) as List<Object?>)
          (e! as Map).cast<String, Object?>(),
      ];
    } finally {
      await session.close(0, '');
    }
  }

  /// The first record under [id] for which [test] holds, asking until
  /// [limit] passed.
  Future<Map<String, Object?>> reported(
    String id,
    bool Function(Map<String, Object?> event) test,
  ) async {
    final watch = Stopwatch()..start();
    while (true) {
      final events = await report(id);
      for (final e in events) {
        if (test(e)) return e;
      }
      if (watch.elapsed > limit) {
        fail('the server did not record it; it recorded $events');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }
}

WebServer? _server;
bool _loaded = false;

/// The server, or null when tool/web_smoke.sh did not start one (the
/// tests then skip).
Future<WebServer?> loadServer() async {
  if (_loaded) return _server;
  _loaded = true;
  try {
    final response = await web.window.fetch('web_server.json'.toJS).toDart;
    if (!response.ok) return null;
    final text = (await response.text().toDart).toDart;
    final json = jsonDecode(text) as Map<String, Object?>;
    final hex = json['certificateSha256']! as String;
    return _server = WebServer._(
      Uri.parse(json['provider']! as String),
      Uri.parse(json['limited']! as String),
      Uri.parse(json['node']! as String),
      Uri.parse(json['silent']! as String),
      Uint8List.fromList([
        for (var i = 0; i < hex.length; i += 2)
          int.parse(hex.substring(i, i + 2), radix: 16),
      ]),
      Duration(milliseconds: json['handshakeTimeoutMs']! as int),
    );
  } on Object catch (e) {
    print('no server description: $e');
    return null;
  }
}

/// The server for a test, or null after marking it skipped.
Future<WebServer?> server() async {
  final s = await loadServer();
  if (s == null) {
    markTestSkipped('no server: run tool/web_smoke.sh');
  }
  return s;
}

final Random _random = Random();

/// An id for the records of one test.
String newId() =>
    List.generate(12, (_) => _random.nextInt(36).toRadixString(36)).join();

/// Everything [stream] delivers up to FIN.
Future<Uint8List> readAll(QuicStream stream, {int max = 65536}) async {
  final got = BytesBuilder();
  while (true) {
    final chunk = await stream.read(max).timeout(limit);
    if (chunk == null) return got.takeBytes();
    got.add(chunk);
  }
}

/// The pattern tool/web_server.dart sends.
Uint8List pattern(int n) =>
    Uint8List.fromList(List.generate(n, (i) => (i * 31 + (i >> 8)) & 0xFF));

Uint8List bytes(String text) => Uint8List.fromList(utf8.encode(text));

String text(List<int> bytes) => utf8.decode(bytes);

/// Waits until [condition] holds, or fails after [limit].
Future<void> until(bool Function() condition, [Duration within = limit]) async {
  final watch = Stopwatch()..start();
  while (!condition()) {
    if (watch.elapsed > within) fail('timed out waiting');
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
}

/// Whether [future] is still pending after [wait] (false as soon as it
/// settles).
Future<bool> pendingAfter(Future<Object?> future, Duration wait) {
  final settled = future.then((_) => false, onError: (Object _) => false);
  return Future.any([settled, Future.delayed(wait, () => true)]);
}
