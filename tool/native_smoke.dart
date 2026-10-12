/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

// Smoke test of the native provider, for JIT (`dart run tool/native_smoke.dart`)
// and AOT (tool/aot_smoke.sh builds it with `dart build cli`): a listener with
// a self-signed certificate, a pinned client, an echo in both directions with
// FIN, the exporter on both ends, an application close seen by the peer, and
// 64 MiB through one stream; then the binding over the provider: two
// connections with exporter-bound HELLOs, a channel echoing a subframe, the
// close of the connection seen as a GOAWAY; then the same over a WebTransport
// session (HTTP/3 in the shim): the protocol selected, an echo, the
// session's exporter equal at both ends, a reset code, the close code and
// reason, and the binding over the session. Exits non-zero on any failure.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:switchboard_quic/core.dart' show QuicBindingConnection;
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
  final sessions = StreamIterator(listener.sessions);
  final client = await provider.connect(
    listener.endpoint,
    QuicClientConfig(
      alpn: const [quicAlpn],
      serverCertificateHashes: [cert.sha256],
    ),
  );
  check(await sessions.moveNext(), 'accepted session');
  final server = sessions.current;
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

  // The binding over the provider.
  final dialled = await provider.connect(
    listener.endpoint,
    const QuicClientConfig(alpn: [quicAlpn], verifyCertificate: false),
  );
  check(await sessions.moveNext(), 'second accepted session');
  final accepting = QuicBindingConnection.start(sessions.current);
  final initiator = await QuicBindingConnection.start(dialled);
  final acceptor = await accepting;
  final incoming = StreamIterator(acceptor.incoming);
  final channel = initiator.open(Uint8List.fromList([0]));
  await channel.send(Uint8List.fromList('ping'.codeUnits));
  check(await incoming.moveNext(), 'binding channel');
  final served = incoming.current;
  final request = StreamIterator(served.stream);
  check(await request.moveNext(), 'binding subframe');
  await served.send(request.current);
  // Its close completes once the dialler took the reply and confirmed: the
  // binding reads a channel's next record only once the previous one was
  // taken.
  final closing = served.close();
  final reply = await channel.stream.toList();
  check(
    reply.length == 1 && String.fromCharCodes(reply.single) == 'ping',
    'binding echo',
  );
  check((await channel.done).isOk, 'binding channel closed');
  await closing;
  await request.cancel();
  await _hellos(initiator, acceptor);
  check(initiator.exporterBound && acceptor.exporterBound, 'HELLO EXPORTER');
  await initiator.close();
  check((await acceptor.peerGoAwayStatus).code == 33, 'binding close');
  await acceptor.done;
  await sessions.cancel();
  await listener.close();
  print('native smoke: binding OK');

  await _webTransport(provider, cert);
  watchdog.cancel();
  print('native smoke: OK');
}

/// The provider and the binding over a WebTransport session.
Future<void> _webTransport(
  NativeQuicProvider provider,
  NativeCertificate cert,
) async {
  final listener = await provider.listenWebTransport(
    '127.0.0.1',
    0,
    QuicServerConfig(
      alpn: const [quicAlpn],
      certificateDer: cert.certificateDer,
      privateKeyDer: cert.privateKeyDer,
    ),
    path: '/sb',
  );
  final sessions = StreamIterator(listener.sessions);
  final client = await provider.connect(
    listener.endpoint,
    QuicClientConfig(
      alpn: const [quicAlpn],
      serverCertificateHashes: [cert.sha256],
    ),
  );
  check(await sessions.moveNext(), 'accepted WebTransport session');
  final server = sessions.current;
  check(
    client.protocol == 'switchboard' && server.protocol == 'switchboard',
    'WebTransport protocol',
  );
  const label = 'switchboard-ident';
  final a = await client.exportKeyingMaterial(label, Uint8List(0), 32);
  final b = await server.exportKeyingMaterial(label, Uint8List(0), 32);
  check(a != null && b != null && _eq(a, b), 'WebTransport exporter');

  final serverStreams = StreamIterator(server.incomingStreams);
  final cs = await client.openStream();
  await cs.write(Uint8List.fromList('over h3'.codeUnits));
  await cs.finish();
  check(await serverStreams.moveNext(), 'WebTransport stream');
  final ss = serverStreams.current;
  final got = await _readAll(ss);
  await ss.write(got);
  await ss.finish();
  check(String.fromCharCodes(await _readAll(cs)) == 'over h3', 'WT echo');
  final rs = await client.openStream();
  await rs.write(Uint8List(1));
  check(await serverStreams.moveNext(), 'WebTransport stream to reset');
  rs.reset(42);
  int? code;
  try {
    await _readAll(serverStreams.current);
  } on QuicStreamReset catch (e) {
    code = e.code;
  }
  check(code == 42, 'WebTransport reset code');
  await client.close(7, 'done');
  final end = await server.done;
  check(
    end.code == 7 && end.reason == 'done' && end.byPeer,
    'WebTransport close seen by the peer',
  );

  final dialled = await provider.connect(
    listener.endpoint,
    const QuicClientConfig(alpn: [quicAlpn], verifyCertificate: false),
  );
  check(await sessions.moveNext(), 'second WebTransport session');
  final accepting = QuicBindingConnection.start(
    sessions.current,
    isWebTransport: true,
  );
  final initiator = await QuicBindingConnection.start(
    dialled,
    isWebTransport: true,
  );
  final acceptor = await accepting;
  final incoming = StreamIterator(acceptor.incoming);
  final channel = initiator.open(Uint8List.fromList([0]));
  await channel.send(Uint8List.fromList('ping'.codeUnits));
  check(await incoming.moveNext(), 'WebTransport binding channel');
  final served = incoming.current;
  final request = StreamIterator(served.stream);
  check(await request.moveNext(), 'WebTransport binding subframe');
  await served.send(request.current);
  final closing = served.close();
  final reply = await channel.stream.toList();
  check(
    reply.length == 1 && String.fromCharCodes(reply.single) == 'ping',
    'WebTransport binding echo',
  );
  await closing;
  await request.cancel();
  await _hellos(initiator, acceptor);
  check(
    initiator.exporterBound && acceptor.exporterBound,
    'WebTransport HELLO EXPORTER',
  );
  await initiator.close();
  check(
    (await acceptor.peerGoAwayStatus).code == 33,
    'WebTransport binding close',
  );
  await acceptor.done;
  await sessions.cancel();
  await listener.close();
  print('native smoke: WebTransport OK');
}

/// Waits (up to 5 s) until both ends have the other's `HELLO`. It travels on
/// the control stream, which a channel's records may overtake: the acceptor
/// writes its `HELLO` once it has read the initiator's control stream, and may
/// have answered a channel before that.
Future<void> _hellos(QuicBindingConnection a, QuicBindingConnection b) async {
  final elapsed = Stopwatch()..start();
  while (a.peerHello == null || b.peerHello == null) {
    if (elapsed.elapsed >= const Duration(seconds: 5)) {
      throw TimeoutException('both peers must receive HELLO', elapsed.elapsed);
    }
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
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
