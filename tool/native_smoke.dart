/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// Smoke test of the native provider, for JIT (`dart run tool/native_smoke.dart`)
// and AOT (tool/aot_smoke.sh builds it with `dart build cli`): a listener with
// a self-signed certificate, a pinned client, an echo in both directions with
// FIN, the exporter on both ends, an application close seen by the peer, and
// 64 MiB through one stream. Exits non-zero on any failure.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:switchboard_quic/switchboard_quic_native.dart';

Future<void> main() async {
  final watchdog = Timer(const Duration(seconds: 60), () {
    stderr.writeln('native smoke: timed out');
    exit(2);
  });
  final provider = NativeQuicProvider();
  final cert = NativeQuicProvider.generateSelfSigned('localhost');
  final listener = await provider.listen(
    '127.0.0.1',
    0,
    QuicServerConfig(
      alpn: const [quicAlpn],
      certificateDer: cert.certificateDer,
      privateKeyDer: cert.privateKeyDer,
    ),
  );
  final accepted = listener.sessions.first;
  final client = await provider.connect(
    listener.endpoint,
    QuicClientConfig(
      alpn: const [quicAlpn],
      serverCertificateHashes: [cert.sha256],
    ),
  );
  final server = await accepted;
  check(client.protocol == quicAlpn && server.protocol == quicAlpn, 'ALPN');
  check(_eq(client.peerCertificateHash!, cert.sha256), 'peer certificate hash');

  final label = 'EXPORTER-Channel-Binding';
  final a = await client.exportKeyingMaterial(label, Uint8List(0), 32);
  final b = await server.exportKeyingMaterial(label, Uint8List(0), 32);
  check(a != null && b != null && _eq(a, b), 'exporter');

  // Echo with FIN.
  final serverStreams = StreamIterator(server.incomingStreams);
  final cs = await client.openStream();
  await cs.write(Uint8List.fromList('hello'.codeUnits));
  await cs.finish();
  check(await serverStreams.moveNext(), 'server stream');
  final ss = serverStreams.current;
  final got = await _readAll(ss);
  check(String.fromCharCodes(got) == 'hello', 'server read');
  await ss.write(got);
  await ss.finish();
  check(String.fromCharCodes(await _readAll(cs)) == 'hello', 'client read');
  check(await cs.stopped == null && await ss.stopped == null, 'acknowledged');

  // Throughput.
  const total = 64 << 20;
  final chunk = Uint8List(64 << 10);
  final sw = Stopwatch()..start();
  final tx = await client.openStream();
  final writer = () async {
    for (var sent = 0; sent < total; sent += chunk.length) {
      await tx.write(chunk);
    }
    await tx.finish();
  }();
  check(await serverStreams.moveNext(), 'server stream');
  final rx = serverStreams.current;
  var received = 0;
  while (true) {
    final c = await rx.read(1 << 20);
    if (c == null) break;
    received += c.length;
  }
  await writer;
  sw.stop();
  check(received == total, 'throughput bytes');
  final mbs = total / sw.elapsedMicroseconds;
  print(
    'native smoke: 64 MiB in ${sw.elapsedMilliseconds} ms (${mbs.toStringAsFixed(0)} MB/s)',
  );

  await client.close(7, 'done');
  final end = await server.done;
  check(
    end.code == 7 && end.reason == 'done' && end.byPeer,
    'close seen by the peer',
  );
  await listener.close();
  watchdog.cancel();
  print('native smoke: OK');
}

Future<Uint8List> _readAll(QuicStream s) async {
  final out = BytesBuilder();
  while (true) {
    final c = await s.read(65536);
    if (c == null) return out.takeBytes();
    out.add(c);
  }
}

bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void check(bool ok, String what) {
  if (ok) return;
  stderr.writeln('native smoke: FAILED: $what');
  exit(1);
}
