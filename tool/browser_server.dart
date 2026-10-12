/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// The server side of tool/browser_smoke.sh: a WebTransport listener of the
// native provider on https://127.0.0.1:port/sb with a fresh self-signed
// certificate (ECDSA P-256, valid 14 days, what a browser accepts for
// serverCertificateHashes), and a plain HTTP server for the page the browser
// runs the probe in (http://127.0.0.1 is a secure context). It prints
// `READY {json}` (the URLs and the certificate hash), serves one session —
// echoing its first stream, reading the code of the reset of its second, and
// reading how it closed — and prints `RESULT {json}`; it exits non-zero when
// what it saw is not what the probe does (a stream reset with 42, a close
// with 7 and "browser done", a request to another path refused 404).

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:switchboard_quic/switchboard_quic_native.dart';

Future<void> main() async {
  final watchdog = Timer(const Duration(seconds: 60), () {
    stderr.writeln('browser server: timed out');
    exit(2);
  });
  final provider = NativeQuicProvider();
  final cert = NativeQuicProvider.generateSelfSigned('127.0.0.1');
  final http = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final origin = 'http://127.0.0.1:${http.port}';
  http.listen((request) {
    request.response
      ..headers.contentType = ContentType.html
      ..write('<!doctype html><title>switchboard browser smoke</title>')
      ..close();
  });
  final listener = await provider.listenWebTransport(
    '127.0.0.1',
    0,
    QuicServerConfig(
      alpn: const [quicAlpn],
      certificateDer: cert.certificateDer,
      privateKeyDer: cert.privateKeyDer,
    ),
    path: '/sb',
    allowedOrigins: [origin],
  );
  final hash = cert.sha256
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
  print(
    'READY ${jsonEncode({'webtransport': listener.endpoint.toString(), 'page': '$origin/', 'origin': origin, 'certificateSha256': hash, 'certificateBytes': cert.certificateDer.length})}',
  );

  final result = <String, Object?>{};
  final failures = <String>[];
  void expectThat(bool ok, String what) {
    if (!ok) failures.add(what);
  }

  final session = await listener.sessions.first as NativeQuicSession;
  result['requestOrigin'] = session.requestOrigin;
  result['requestPath'] = session.requestPath;
  result['requestAuthority'] = session.requestAuthority;
  result['requestProtocols'] = session.requestProtocols;
  result['requestDraft'] = session.requestDraft;
  result['protocol'] = session.protocol;
  result['remote'] = session.remote;
  final exporter = await session.exportKeyingMaterial(
    'switchboard-ident',
    Uint8List(0),
    32,
  );
  result['exporter'] = exporter
      ?.map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
  expectThat(session.requestOrigin == origin, 'the Origin of the request');
  expectThat(session.protocol == 'switchboard', 'the protocol selected');

  final streams = StreamIterator(session.incomingStreams);
  // The first stream: echoed.
  if (await streams.moveNext()) {
    final s = streams.current;
    final got = BytesBuilder();
    while (true) {
      final c = await s.read(65536);
      if (c == null) break;
      got.add(c);
    }
    final bytes = got.takeBytes();
    result['echoed'] = utf8.decode(bytes, allowMalformed: true);
    await s.write(bytes);
    await s.finish();
  }
  // The second stream: aborted by the browser with 42.
  if (await streams.moveNext()) {
    final s = streams.current;
    int? code;
    var how = 'fin';
    try {
      while (await s.read(65536) != null) {}
    } on QuicStreamReset catch (e) {
      code = e.code;
      how = 'reset';
    }
    result['abortedStream'] = {'end': how, 'code': code};
    expectThat(how == 'reset' && code == 42, 'the reset code 42');
  }
  final end = await session.done;
  result['sessionEnd'] = {
    'code': end.code,
    'reason': end.reason,
    'byPeer': end.byPeer,
    'lost': end.lost,
  };
  expectThat(
    end.code == 7 && end.reason == 'browser done' && end.byPeer,
    'the close code 7 and its reason',
  );
  // The probe's request to another path, refused before the close.
  result['answered'] = {
    for (final e in listener.answered.entries) '${e.key}': e.value,
  };
  expectThat(listener.answered[404] == 1, 'a request to another path, 404');
  await streams.cancel();
  await listener.close();
  await http.close(force: true);
  NativeQuicProvider.shutdown();
  watchdog.cancel();
  result['failures'] = failures;
  print('RESULT ${jsonEncode(result)}');
  exit(failures.isEmpty ? 0 : 1);
}
