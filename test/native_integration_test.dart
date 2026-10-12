/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// The binding over the real native provider: Switchboard nodes in this
// isolate talking raw QUIC over UDP on the loopback, through quinn. A
// listener node with a self-signed certificate behind
// QuicSwitchboardListener; dialling nodes with QuicSwitchboardBinding,
// which do not verify the certificate, so the identification rules of the
// binding page apply (QuicIdentityRules.initiator and .listener).

@TestOn('vm')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/switchboard.dart';
import 'package:switchboard_quic/switchboard_quic.dart';
import 'package:switchboard_quic/switchboard_quic_native.dart';
import 'package:test/test.dart';

import 'harness.dart'
    show bytes, fast, hasCode, limit, pattern, settle, text, throwsCode, until;

final echo = Name('echo');
final npc = Name('npc');
final sink = Name('sink');

late NativeQuicProvider provider;
late NativeCertificate cert;
late CredentialIssuer authority;
late HolderKey clientKey;
late HolderKey serverKey;

Future<CredentialVerifier> verifier() async {
  final v = CredentialVerifier();
  await v.addIssuer(authority);
  return v;
}

Future<Credential> credential(String identity, HolderKey key) =>
    authority.issue(
      kind: CredentialKind.node,
      identity: identity,
      scopes: [Scope.of(Right.open, '*')],
      holderKey: key.publicKey,
    );

/// A node closed after the test.
Switchboard node({
  List<SwitchboardBinding> bindings = const [],
  Credential? credential,
  HolderKey? holderKey,
  CredentialVerifier? verifier,
  Resolver? resolver,
  ExpectedIdentity? expectedIdentityFor,
  Duration identityTimeout = const Duration(seconds: 2),
  MuxOptions options = fast,
}) {
  final s = Switchboard(
    muxOptions: options,
    bindings: bindings,
    credential: credential,
    holderKey: holderKey,
    verifier: verifier,
    resolver: resolver,
    expectedIdentityFor: expectedIdentityFor,
    identityTimeout: identityTimeout,
    connectTimeout: const Duration(seconds: 5),
  );
  addTearDown(s.close);
  return s;
}

/// A native listener of [server] on the loopback, with the self-signed
/// certificate and the node's windows, accepted into the node; closed after
/// the test.
Future<QuicSwitchboardListener> listen(
  Switchboard server, {
  ChannelPolicy? policy,
  QuicIdentityRules rules = QuicIdentityRules.listener,
  Duration idle = const Duration(seconds: 30),
  Duration keepAlive = const Duration(seconds: 10),
}) async {
  final quic = await provider.listen(
    '127.0.0.1',
    0,
    QuicServerConfig(
      alpn: const [switchboardAlpn],
      certificateDer: cert.certificateDer,
      privateKeyDer: cert.privateKeyDer,
      // The channels a peer may have open, plus its control stream.
      maxStreamsBidi: 129,
      streamReceiveWindow: server.muxOptions.initialWindow,
      connectionReceiveWindow: server.muxOptions.receiveHighWaterMarkBytes,
      idleTimeout: idle,
      keepAlive: keepAlive,
    ),
  );
  final listener = await QuicSwitchboardListener.start(
    server,
    quic,
    policy: policy,
    identityRules: rules,
  );
  addTearDown(listener.close);
  return listener;
}

/// A Talk service answering every request with its payload.
void echoService(IncomingChannel incoming) {
  incoming.talk().messages.listen((m) {
    if (m.expectsReply) {
      unawaited(m.reply(m.payload));
    }
  });
}

/// A handler answering with the peer's identity and closing.
void answer(IncomingChannel incoming) {
  unawaited(
    incoming.channel.send(
      bytes(
        '${incoming.address.type} for '
        '${incoming.peerIdentity?.identity ?? 'nobody'}',
      ),
    ),
  );
  unawaited(incoming.channel.close());
}

/// What an [answer] handler said, or the close status.
Future<String> answerOf(MuxChannel channel) async {
  final frames = await channel.stream.toList().timeout(limit);
  final status = await channel.done.timeout(limit);
  if (frames.isEmpty) {
    return 'closed ${status.known?.name ?? status.code}';
  }
  return text(frames.single);
}

String rate(int bytes, Duration elapsed) {
  final ms = elapsed.inMicroseconds / 1000;
  final mbs = bytes / (elapsed.inMicroseconds / 1e6) / 1e6;
  return '${bytes >> 20} MiB in ${ms.toStringAsFixed(0)} ms = '
      '${mbs.toStringAsFixed(0)} MB/s';
}

void main() {
  setUpAll(() async {
    provider = NativeQuicProvider();
    cert = NativeQuicProvider.generateSelfSigned('localhost');
    authority = await CredentialIssuer.ed25519FromSeed(
      Name('auth1'),
      Uint8List.fromList(List.generate(32, (i) => 3 * i)),
    );
    clientKey = await HolderKey.generate();
    serverKey = await HolderKey.generate();
  });

  tearDownAll(NativeQuicProvider.shutdown);

  group('identity', () {
    test('nodes identify both ways with exporter-bound proofs over the TLS '
        'exporter both ends derived', () async {
      final server = node(
        verifier: await verifier(),
        credential: await credential('server-1', serverKey),
        holderKey: serverKey,
      );
      server.registerService(npc, answer);
      final listener = await listen(server, policy: ChannelPolicies.scoped());
      final binding = QuicSwitchboardBinding(provider);
      final client = node(
        bindings: [binding],
        verifier: await verifier(),
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
        expectedIdentityFor: (endpoint, record) => 'server-1',
      );
      expect(
        await answerOf(
          await client.openChannelAt(
            listener.endpoint,
            ChannelAddress(type: npc),
          ),
        ),
        'npc for npc-7',
      );
      final initiated = binding.dialled.single;
      final accepted = listener.accepted.single;
      expect(initiated.session, isA<NativeQuicSession>());
      expect(initiated.session.protocol, 'switchboard');
      expect(initiated.session.peerCertificateHash, cert.sha256);
      expect(initiated.quicOptions.identity.awaitPeerIdentity, isTrue);
      expect(initiated.exporterBound, isTrue);
      expect(accepted.exporterBound, isTrue);
      expect(accepted.peerIdentity?.identity, 'npc-7');
      expect(accepted.peerIdentityBound, isTrue);
      // The listener identified in turn, naming the client.
      expect(initiated.peerIdentity?.identity, 'server-1');
      expect(initiated.peerIdentity?.receiver, 'npc-7');
      expect(initiated.peerIdentityBound, isTrue);
      expect(initiated.peerAuthenticated, isTrue);
      // The proofs signed RFC 9266's tls-exporter: 32 bytes, the same at
      // both ends of the session.
      final exporter = initiated.exporterForTesting!;
      expect(exporter, hasLength(32));
      expect(accepted.exporterForTesting, exporter);
      // Another session derives another.
      final other = node(
        bindings: [QuicSwitchboardBinding(provider)],
        verifier: await verifier(),
        credential: await credential('npc-8', clientKey),
        holderKey: clientKey,
      );
      expect(
        await answerOf(
          await other.openChannelAt(
            listener.endpoint,
            ChannelAddress(type: npc),
          ),
        ),
        'npc for npc-8',
      );
      await until(() => listener.accepted.length == 2);
      final second = listener.accepted.last.exporterForTesting!;
      expect(second, hasLength(32));
      expect(second, isNot(exporter));
    });

    test('a dialler without a credential is refused UNAUTHENTICATED where '
        'identity is required, and served where it is not', () async {
      final server = node(
        verifier: await verifier(),
        identityTimeout: const Duration(milliseconds: 500),
      );
      server.registerService(npc, answer);
      final listener = await listen(server, policy: ChannelPolicies.scoped());
      final binding = QuicSwitchboardBinding(provider);
      final client = node(bindings: [binding]);
      final channel = await client.openChannelAt(
        listener.endpoint,
        ChannelAddress(type: npc),
      );
      expect(await answerOf(channel), 'closed unauthenticated');
      expect(binding.dialled.single.peerIdentity, isNull);
      final open = node();
      open.registerService(npc, answer);
      final openListener = await listen(open);
      expect(
        await answerOf(
          await client.openChannelAt(
            openListener.endpoint,
            ChannelAddress(type: npc),
          ),
        ),
        'npc for nobody',
      );
    });

    test('a pinned dialler reaches the listener with the right certificate '
        'hash, and not with a wrong one', () async {
      final server = node();
      server.registerService(npc, answer);
      final listener = await listen(server);
      final pinned = QuicSwitchboardBinding(
        provider,
        certificateHashes: [cert.sha256],
      );
      final client = node(bindings: [pinned]);
      expect(
        await answerOf(
          await client.openChannelAt(
            listener.endpoint,
            ChannelAddress(type: npc),
          ),
        ),
        'npc for nobody',
      );
      final connection = pinned.dialled.single;
      expect(connection.quicOptions.identity.tlsAuthenticatesPeer, isTrue);
      expect(connection.peerAuthenticated, isTrue);
      expect(connection.session.peerCertificateHash, cert.sha256);
      final wrong = node(
        bindings: [
          QuicSwitchboardBinding(
            provider,
            certificateHashes: [Uint8List(32)..fillRange(0, 32, 0xA5)],
          ),
        ],
      );
      await expectLater(
        wrong.connect(listener.endpoint),
        throwsCode(StatusCode.unavailable),
      );
    });
  });

  group('channels', () {
    test('Talk request and reply', () async {
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(server);
      final binding = QuicSwitchboardBinding(provider);
      final client = node(bindings: [binding]);
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      expect(talk.raw, isA<QuicChannel>());
      final reply = await talk.request('ECHO', bytes('hello')).timeout(limit);
      expect(text(reply.payload), 'hello');
      final again = await talk.request('ECHO', Uint8List(0)).timeout(limit);
      expect(again.payload, isEmpty);
      await talk.close().timeout(limit);
      expect(binding.dialled.single.peerHello, isNotNull);
    });

    test('an 8 MiB bulk payload each way', () async {
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(server);
      final client = node(bindings: [QuicSwitchboardBinding(provider)]);
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      final payload = pattern(8 << 20, 3);
      final watch = Stopwatch()..start();
      final reply = await talk
          .request('BIG', payload)
          .timeout(const Duration(seconds: 60));
      final elapsed = watch.elapsed;
      expect(reply.isBulk, isTrue);
      expect(reply.payload, payload);
      print(
        'native binding, Talk bulk echo: ${rate(16 << 20, elapsed)} '
        '(8 MiB each way, 64 KiB stream windows, JIT)',
      );
      // Two at once, their bulk streams racing.
      final twins = await Future.wait([
        talk.request('A', pattern(300000, 1)),
        talk.request('B', pattern(200000, 2)),
      ]).timeout(const Duration(seconds: 30));
      expect(twins[0].payload, pattern(300000, 1));
      expect(twins[1].payload, pattern(200000, 2));
    });

    test('whenWritable paces a publisher at the stream window', () async {
      final server = node();
      final received = <TalkMessage>[];
      final serving = Completer<StreamSubscription<TalkMessage>>();
      server.registerService(echo, (incoming) {
        serving.complete(
          incoming.talk().messages.listen(received.add)..pause(),
        );
      });
      final listener = await listen(server);
      final client = node(bindings: [QuicSwitchboardBinding(provider)]);
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      const count = 400;
      var sent = 0;
      final publisher = () async {
        for (var i = 0; i < count; i++) {
          await talk.whenWritable;
          unawaited(talk.send('EVENT', Uint8List(1000)));
          sent++;
        }
      }();
      final subscription = await serving.future.timeout(limit);
      // Until the publisher stalls (a loaded runner may take a while).
      final watch = Stopwatch()..start();
      var last = -1;
      while (sent != last && watch.elapsed < limit) {
        last = sent;
        await settle(300);
      }
      // The receiver takes nothing: the stream window (64 KiB) and the
      // record the binding reads are all the publisher got out.
      expect(sent, last);
      expect(talk.isWritable, isFalse);
      expect(sent, lessThan(80));
      subscription.resume();
      await publisher.timeout(limit);
      await until(() => received.length == count);
      await subscription.cancel();
    });

    test('a reader paused by its application observes the peer\'s reset '
        'at once', () async {
      // The listener's own confirmation timeout is long: only the reset
      // ends its channel early.
      final server = node(
        options: const MuxOptions(
          goAwayGrace: Duration(milliseconds: 200),
          keepAliveInterval: null,
          closeConfirmTimeout: Duration(seconds: 30),
        ),
      );
      final served = Completer<MuxChannel>();
      server.registerService(sink, (incoming) {
        // Takes nothing: the stream window fills and the dialler's writes
        // stall behind it.
        incoming.channel.stream.listen((_) {}).pause();
        served.complete(incoming.channel);
      });
      final listener = await listen(server);
      final client = node(
        options: const MuxOptions(
          goAwayGrace: Duration(milliseconds: 200),
          keepAliveInterval: null,
          closeConfirmTimeout: Duration(milliseconds: 300),
        ),
        bindings: [QuicSwitchboardBinding(provider)],
      );
      final channel = await client.openChannelAt(
        listener.endpoint,
        ChannelAddress(type: sink),
      );
      for (var i = 0; i < 10; i++) {
        unawaited(channel.send(pattern(30000, i)).catchError((Object _) {}));
      }
      final accepted = await served.future.timeout(limit);
      await settle(100);
      // A failure: STOP_SENDING at once, and the CLOSE record behind data
      // the listener does not read, which the confirmation timeout turns
      // into a reset.
      final watch = Stopwatch()..start();
      unawaited(channel.close(Status.of(StatusCode.cancelled, 'abandoned')));
      expect(await channel.done.timeout(limit), hasCode(StatusCode.cancelled));
      expect(
        await accepted.done.timeout(const Duration(seconds: 5)),
        hasCode(StatusCode.cancelled),
      );
      expect(watch.elapsed, lessThan(const Duration(seconds: 5)));
    });

    test('64 channels in parallel on one connection, three times over: the '
        'stream credit of ended channels comes back', () async {
      final server = node();
      server.registerService(echo, echoService);
      // 129 streams: 128 channels and the control stream.
      final listener = await listen(server);
      final binding = QuicSwitchboardBinding(provider);
      final client = node(bindings: [binding]);
      for (var round = 0; round < 3; round++) {
        final results = await Future.wait([
          for (var i = 0; i < 64; i++)
            () async {
              final talk = await client.openTalkAt(
                listener.endpoint,
                ChannelAddress(type: echo),
              );
              // Every eighth one carries a bulk payload.
              final payload = pattern(
                i % 8 == 0 ? 100000 + i : 100 + i,
                i + round,
              );
              final reply = await talk.request('ECHO', payload);
              final same = _same(reply.payload, payload);
              await talk.close();
              return same;
            }(),
        ]).timeout(const Duration(seconds: 60));
        expect(results.every((ok) => ok), isTrue);
      }
      expect(binding.dialled, hasLength(1));
      expect(binding.dialled.single.peerMaxChannels, 128);
      await until(() => binding.dialled.single.openChannelCount == 0);
    });

    test('throughput of one channel', () async {
      Future<String> measure(MuxOptions options, String label) async {
        const total = 64 << 20;
        final server = node(options: options);
        final got = Completer<void>();
        server.registerService(sink, (incoming) {
          var n = 0;
          incoming.channel.stream.listen((data) {
            n += data.length;
            if (n >= total && !got.isCompleted) {
              got.complete();
            }
          });
        });
        final listener = await listen(server);
        final client = node(
          options: options,
          bindings: [QuicSwitchboardBinding(provider)],
        );
        final channel = await client.openChannelAt(
          listener.endpoint,
          ChannelAddress(type: sink),
        );
        final connection = channel.connection as QuicBindingConnection;
        await until(() => connection.peerHello != null);
        final chunk = pattern(channel.maxSubframeLength);
        final watch = Stopwatch()..start();
        var sent = 0;
        while (sent < total) {
          await channel.whenWritable;
          // Two records per write: the binding batches what waits.
          for (var i = 0; i < 2 && sent < total; i++) {
            final n = total - sent < chunk.length ? total - sent : chunk.length;
            unawaited(
              channel.send(n == chunk.length ? chunk : chunk.sublist(0, n)),
            );
            sent += n;
          }
        }
        await got.future.timeout(const Duration(seconds: 60));
        final line =
            'native binding, one channel: ${rate(total, watch.elapsed)} '
            '($label, ${chunk.length}-byte records, JIT)';
        await channel.close();
        return line;
      }

      print(await measure(fast, '64 KiB stream window'));
      print(
        await measure(
          const MuxOptions(
            goAwayGrace: Duration(milliseconds: 200),
            keepAliveInterval: null,
            closeConfirmTimeout: Duration(seconds: 5),
            initialWindow: 1 << 20,
          ),
          '1 MiB stream window',
        ),
      );
    });
  });

  group('the end of a connection', () {
    test('GOAWAY with a code and a reason, from the dialler', () async {
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(server);
      final binding = QuicSwitchboardBinding(provider);
      final client = node(bindings: [binding]);
      // An open channel: the receiver of the GOAWAY keeps the connection
      // while it lasts, so the close is the GOAWAY sender's, after its
      // grace.
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      await talk.request('ECHO', bytes('x')).timeout(limit);
      final connection = binding.dialled.single;
      final accepted = listener.accepted.single;
      await connection.goAway(Status.of(StatusCode.unavailable, 'upgrade'));
      expect(
        await accepted.peerGoAwayStatus.timeout(limit),
        Status.of(StatusCode.unavailable, 'upgrade'),
      );
      expect(
        await connection.done.timeout(limit),
        Status.of(StatusCode.unavailable, 'upgrade'),
      );
      final end = await accepted.session.done.timeout(limit);
      expect(
        (end.code, end.reason, end.byPeer, end.lost),
        (14, 'upgrade', true, false),
      );
      expect(
        await (talk.raw as MuxChannel).done.timeout(limit),
        hasCode(StatusCode.unavailable),
      );
    });

    test('GOAWAY with a code and a reason, from the listener', () async {
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(server);
      final binding = QuicSwitchboardBinding(provider);
      final client = node(bindings: [binding]);
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      await talk.request('ECHO', bytes('x')).timeout(limit);
      final connection = binding.dialled.single;
      final accepted = listener.accepted.single;
      await accepted.goAway(
        Status.of(StatusCode.resourceExhausted, 'too busy'),
      );
      expect(
        await connection.peerGoAwayStatus.timeout(limit),
        Status.of(StatusCode.resourceExhausted, 'too busy'),
      );
      final end = await connection.session.done.timeout(limit);
      expect(
        (end.code, end.reason, end.byPeer, end.lost),
        (8, 'too busy', true, false),
      );
      expect(
        await (talk.raw as MuxChannel).done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
    });

    test('the idle timeout ends the channels with CONNECTION_LOST', () async {
      final server = node();
      server.registerService(echo, echoService);
      const idle = Duration(milliseconds: 800);
      final listener = await listen(
        server,
        idle: idle,
        keepAlive: Duration.zero,
      );
      final binding = QuicSwitchboardBinding(provider, idleTimeout: idle);
      // No keep-alive of the binding's own ([fast]): nothing is sent once
      // the request is answered.
      final client = node(bindings: [binding]);
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      await talk.request('ECHO', bytes('x')).timeout(limit);
      final connection = binding.dialled.single;
      // quinn waits at least three probe timeouts, which a loaded runner
      // can stretch to seconds.
      const lost = Duration(seconds: 20);
      expect(
        await (talk.raw as MuxChannel).done.timeout(lost),
        hasCode(StatusCode.connectionLost),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
      final end = await connection.session.done.timeout(limit);
      expect(end.lost, isTrue);
    });
  });

  test('the proxy: a frame mux backend behind a QUIC front, bulk twins '
      'forwarded in order', () async {
    final backend = node();
    final received = <Uint8List>[];
    backend.registerService(echo, (incoming) {
      incoming.talk().messages.listen((m) {
        received.add(m.payload);
        if (m.expectsReply) {
          unawaited(m.reply(m.payload));
        }
      });
    }, instance: 1);
    final backendUri = await backend.listenMemory();
    final resolver = StaticResolver([
      ServiceRecord(ServiceAddress(echo, 1), endpoints: [backendUri]),
    ]);
    addTearDown(resolver.close);
    final proxy = node(resolver: resolver);
    proxy.catchAll = proxyHandler(proxy);
    final front = await listen(proxy, rules: QuicIdentityRules.none);
    final client = node(bindings: [QuicSwitchboardBinding(provider)]);
    final talk = await client.openTalkAt(
      front.endpoint,
      ChannelAddress(type: echo),
    );
    expect(talk.raw, isA<QuicChannel>());
    final small = await talk.request('ECHO', bytes('through')).timeout(limit);
    expect(text(small.payload), 'through');
    final first = pattern(400000, 1);
    final second = pattern(300000, 2);
    final replies = await Future.wait([
      talk.request('A', first),
      talk.request('B', second),
    ]).timeout(const Duration(seconds: 30));
    expect(replies[0].payload, first);
    expect(replies[1].payload, second);
    expect(received, [bytes('through'), first, second]);
  });
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}
