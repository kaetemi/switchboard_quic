/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// Switchboard nodes over the QUIC binding, end to end over the fake
// provider: QuicSwitchboardBinding and QuicSwitchboardListener, Talk with
// bulk payloads whose streams overtake their parents, whenWritable pacing,
// identity under the rules of the binding page (a man in the middle
// included), the proxy between the frame mux and the binding, and the ends
// of connections.

@TestOn('vm')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/switchboard.dart';
import 'package:switchboard_quic/switchboard_quic.dart';
import 'package:test/test.dart';

import 'fake_provider.dart';
import 'harness.dart';

final echo = Name('echo');
final npc = Name('npc');

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
  bool identifyOutgoing = true,
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
    identifyOutgoing: identifyOutgoing,
    connectTimeout: const Duration(seconds: 5),
  );
  addTearDown(s.close);
  return s;
}

/// A listener of [server] at `quic://[host]:4433`, closed after the test.
Future<QuicSwitchboardListener> listen(
  FakeQuicNetwork network,
  Switchboard server,
  String host, {
  ChannelPolicy? policy,
  QuicIdentityRules rules = QuicIdentityRules.listener,
  FakeEndConfig config = const FakeEndConfig(),
  bool identifyInReturn = true,
}) async {
  final listener = await QuicSwitchboardListener.start(
    server,
    network.listen(Uri.parse('quic://$host:4433'), config: config),
    policy: policy,
    identityRules: rules,
    identifyInReturn: identifyInReturn,
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

void main() {
  setUpAll(() async {
    authority = await CredentialIssuer.ed25519FromSeed(
      Name('auth1'),
      Uint8List.fromList(List.generate(32, (i) => 3 * i)),
    );
    clientKey = await HolderKey.generate();
    serverKey = await HolderKey.generate();
  });

  group('two nodes', () {
    test('Talk request and reply, each channel on a stream of its own, '
        'pooled by endpoint', () async {
      final network = FakeQuicNetwork();
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(network, server, 'echo-1');
      expect(server.listeningEndpoints, contains(listener.endpoint));
      expect(server.isOwnEndpoint(Uri.parse('quic://echo-1:4433')), isTrue);
      final binding = QuicSwitchboardBinding(network.connector());
      final client = node(bindings: [binding]);
      expect(client.bindingSchemes, {'quic', 'https'});
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      expect(talk.raw, isA<QuicChannel>());
      final reply = await talk.request('ECHO', bytes('hello')).timeout(limit);
      expect(text(reply.payload), 'hello');
      final again = await client.openTalkAt(
        Uri.parse('QUIC://Echo-1:4433#echo'),
        ChannelAddress(type: echo),
      );
      expect(
        text((await again.request('ECHO', bytes('again'))).payload),
        'again',
      );
      expect(binding.dialled, hasLength(1));
      final connection = binding.dialled.single;
      expect(connection.isInitiator, isTrue);
      expect(connection.exporterBound, isTrue);
      expect(listener.accepted.single.peerHello, isNotNull);
      // Raw QUIC: the session was dialled with the binding's ALPN and the
      // node's windows.
      final config = (binding.connector as FakeQuicConnector).configs.single;
      expect(config.alpn, ['switchboard']);
      expect(config.streamReceiveWindow, fast.initialWindow);
      expect(config.verifyCertificate, isFalse);
    });

    test('a 3 MiB bulk payload each way, its streams overtaking the parent '
        'and arriving out of order', () async {
      // The first channel's stream is slow both ways: the bulk streams
      // opened after it arrive first; the others jitter.
      final network = FakeQuicNetwork(
        delay: (info, {required fromInitiator}) => Duration(
          milliseconds: info.ordinal == 1 ? 60 : (info.ordinal * 7) % 5,
        ),
      );
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(network, server, 'bulk-1');
      final client = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
      );
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      final payload = pattern(3 * 1024 * 1024, 3);
      final reply = await talk
          .request('BIG', payload)
          .timeout(const Duration(seconds: 30));
      expect(reply.isBulk, isTrue);
      expect(reply.payload, payload);
      // The bulk stream (2) arrived before its parent (1).
      final (_, accepted) = network.pairs.single;
      expect(
        accepted.announced.indexOf(2),
        lessThan(accepted.announced.indexOf(1)),
      );
      // Two at once, numbers 1 and 2 racing each other.
      final twins = await Future.wait([
        talk.request('A', pattern(300000, 1)),
        talk.request('B', pattern(200000, 2)),
      ]).timeout(const Duration(seconds: 30));
      expect(twins[0].payload, pattern(300000, 1));
      expect(twins[1].payload, pattern(200000, 2));
    });

    test('many channels at once over jittered streams: beyond the channels a '
        'listener states the pool opens another connection, and a burst '
        'of opens waits for stream credit', () async {
      final network = FakeQuicNetwork(
        delay: (info, {required fromInitiator}) => Duration(
          microseconds:
              ((info.ordinal * 7919 + (fromInitiator ? 13 : 0)) % 97) * 50,
        ),
      );
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(
        network,
        server,
        'many-1',
        config: const FakeEndConfig(maxStreams: 101),
      );
      final binding = QuicSwitchboardBinding(network.connector());
      final client = node(bindings: [binding]);
      // 120 channels kept open: beyond the 100 the listener states, the
      // pool dials another connection.
      final talks = <TalkChannel>[];
      for (var i = 0; i < 120; i++) {
        talks.add(
          await client.openTalkAt(
            listener.endpoint,
            ChannelAddress(type: echo),
          ),
        );
        if (i == 0) {
          await until(() => binding.dialled.single.peerHello != null);
        }
      }
      expect(binding.dialled.first.peerMaxChannels, 100);
      expect(binding.dialled, hasLength(2));
      // Requests on all of them at once; bulk payloads on the channels of
      // the second connection, the first having no stream left for them.
      final results = await Future.wait([
        for (var i = 0; i < talks.length; i++)
          () async {
            final payload = pattern(i >= 100 ? 70000 + i : 100 + i, i);
            final reply = await talks[i].request('ECHO', payload);
            return _same(reply.payload, payload);
          }(),
      ]).timeout(const Duration(seconds: 60));
      expect(results.every((ok) => ok), isTrue);
      await Future.wait([for (final talk in talks) talk.close()]);
      // And as many opened at once on a pooled connection wait for stream
      // credit instead of failing.
      final burst = await Future.wait([
        for (var i = 0; i < 150; i++)
          () async {
            final talk = await client.openTalkAt(
              listener.endpoint,
              ChannelAddress(type: echo),
            );
            final reply = await talk.request('ECHO', pattern(10, i));
            await talk.close();
            return _same(reply.payload, pattern(10, i));
          }(),
      ]).timeout(const Duration(seconds: 60));
      expect(burst.every((ok) => ok), isTrue);
    });

    test('whenWritable paces a publisher at the stream window', () async {
      final network = FakeQuicNetwork();
      final server = node();
      final received = <TalkMessage>[];
      final serving = Completer<StreamSubscription<TalkMessage>>();
      server.registerService(echo, (incoming) {
        serving.complete(
          incoming.talk().messages.listen(received.add)..pause(),
        );
      });
      final listener = await listen(
        network,
        server,
        'pace-1',
        config: const FakeEndConfig(streamWindow: 64 * 1024),
      );
      final client = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
      );
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
      await settle(100);
      // The receiver takes nothing: the stack's window, plus the record
      // being read, is all the publisher got out.
      expect(talk.isWritable, isFalse);
      expect(sent, lessThan(80));
      final stalled = sent;
      await settle(100);
      expect(sent, stalled);
      subscription.resume();
      await publisher.timeout(limit);
      await until(() => received.length == count);
      await subscription.cancel();
    });

    test('https endpoints go to the connector, which may not dial them: the '
        'node moves to the next endpoint', () async {
      final network = FakeQuicNetwork();
      final server = node();
      server.registerService(echo, echoService, instance: 1);
      final listener = await listen(network, server, 'both-1');
      final resolver = StaticResolver([
        ServiceRecord(
          ServiceAddress(echo, 1),
          endpoints: [Uri.parse('https://both-1/sb'), listener.endpoint],
        ),
      ]);
      addTearDown(resolver.close);
      final binding = QuicSwitchboardBinding(network.connector());
      final client = node(bindings: [binding], resolver: resolver);
      await expectLater(
        client.connect(Uri.parse('https://both-1/sb')),
        throwsCode(StatusCode.unimplemented),
      );
      final talk = await client.openTalk(ServiceAddress(echo));
      expect(
        text((await talk.request('ECHO', bytes('fell back'))).payload),
        'fell back',
      );
      // WebTransport endpoints compare with their path, 443 by default.
      expect(
        binding.normalise(Uri.parse('HTTPS://Hub.Example/sb#x')),
        Uri.parse('https://hub.example:443/sb'),
      );
      expect(
        binding.normalise(Uri.parse('quic://Hub:9/x')),
        Uri.parse('quic://hub:9'),
      );
    });

    test('a quic endpoint without a port is refused, an unreachable one is '
        'unavailable', () async {
      final client = node(
        bindings: [QuicSwitchboardBinding(FakeQuicNetwork().connector())],
      );
      await expectLater(
        client.connect(Uri.parse('quic://nowhere')),
        throwsCode(StatusCode.invalidArgument),
      );
      await expectLater(
        client.connect(Uri.parse('quic://nowhere:1')),
        throwsCode(StatusCode.unavailable),
      );
    });
  });

  group('dialling', () {
    Matcher unavailableWith(String text) => throwsA(
      isA<SwitchboardException>()
          .having((e) => e.code, 'code', StatusCode.unavailable)
          .having((e) => e.status.reason, 'reason', contains(text)),
    );

    test('a connect that outlasts the dial timeout fails UNAVAILABLE, and '
        'the session it yields later is closed CANCELLED', () async {
      final network = FakeQuicNetwork();
      final server = node();
      final listener = await listen(network, server, 'slow-1');
      final connector = network.connector()..connectGate = Completer<void>();
      final binding = QuicSwitchboardBinding(connector);
      const timeout = Duration(milliseconds: 100);
      // A direct caller, without a node's own timeout around the dial.
      await expectLater(
        binding.dial(
          listener.endpoint,
          const BindingDialSettings(options: fast, timeout: timeout),
        ),
        unavailableWith('not connected within $timeout'),
      );
      // The stack was asked for the same deadline.
      expect(connector.configs.single.handshakeTimeout, timeout);
      expect(network.pairs, isEmpty);
      // The handshake completes after all: its session is closed at once.
      connector.connectGate!.complete();
      await until(() => network.pairs.isNotEmpty);
      final (client, acceptor) = network.pairs.single;
      final end = await client.done.timeout(limit);
      expect(client.closes, [(StatusCode.cancelled.code, 'dial abandoned')]);
      expect((end.code, end.byPeer), (StatusCode.cancelled.code, false));
      expect(
        (await acceptor.done.timeout(limit)).code,
        StatusCode.cancelled.code,
      );
      expect(binding.dialled, isEmpty);
    });

    test('through a node: its connect timeout bounds the dial, and the late '
        'session is closed CANCELLED', () async {
      final network = FakeQuicNetwork();
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(network, server, 'slow-2');
      final connector = network.connector()..connectGate = Completer<void>();
      final binding = QuicSwitchboardBinding(connector);
      final client = Switchboard(
        muxOptions: fast,
        bindings: [binding],
        connectTimeout: const Duration(milliseconds: 100),
      );
      addTearDown(client.close);
      await expectLater(
        client.connect(listener.endpoint),
        throwsCode(StatusCode.unavailable),
      );
      expect(
        connector.configs.single.handshakeTimeout,
        const Duration(milliseconds: 100),
      );
      connector.connectGate!.complete();
      await until(() => network.pairs.isNotEmpty);
      final (session, _) = network.pairs.single;
      await session.done.timeout(limit);
      expect(session.closes, [(StatusCode.cancelled.code, 'dial abandoned')]);
      expect(binding.dialled, isEmpty);
      // The next dial, not held, connects.
      connector.connectGate = null;
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      expect(text((await talk.request('ECHO', bytes('late'))).payload), 'late');
      expect(binding.dialled, hasLength(1));
    });

    test('without a dial timeout the connect is not bounded, nor its '
        'handshake', () async {
      final network = FakeQuicNetwork();
      final server = node();
      final listener = await listen(network, server, 'slow-3');
      final connector = network.connector()..connectGate = Completer<void>();
      final binding = QuicSwitchboardBinding(connector);
      final dialling = binding.dial(
        listener.endpoint,
        const BindingDialSettings(options: fast, timeout: Duration.zero),
      );
      await settle(150);
      expect(connector.configs.single.handshakeTimeout, Duration.zero);
      connector.connectGate!.complete();
      final connection = await dialling.timeout(limit);
      addTearDown(connection.close);
      expect(binding.dialled, [connection]);
    });

    test('the stack keep-alive is the binding\'s: a third of the idle '
        'timeout by default, none without one, or as given, whatever the '
        'control PING interval', () async {
      final network = FakeQuicNetwork();
      Future<QuicClientConfig> dialledWith(
        QuicSwitchboardBinding binding,
        MuxOptions options,
      ) async {
        // Nothing listens: the dial fails, and the connector kept the
        // configuration it was asked for.
        await expectLater(
          binding.dial(
            Uri.parse('quic://nowhere:1'),
            BindingDialSettings(options: options, timeout: limit),
          ),
          throwsCode(StatusCode.unavailable),
        );
        return (binding.connector as FakeQuicConnector).configs.single;
      }

      for (final interval in [
        null,
        const Duration(seconds: 1),
        const Duration(seconds: 10),
        const Duration(minutes: 5),
      ]) {
        final options = MuxOptions(keepAliveInterval: interval);
        final byDefault = await dialledWith(
          QuicSwitchboardBinding(network.connector()),
          options,
        );
        expect(byDefault.idleTimeout, const Duration(seconds: 30));
        expect(byDefault.keepAlive, const Duration(seconds: 10));
        expect(byDefault.handshakeTimeout, limit);
        final shorter = await dialledWith(
          QuicSwitchboardBinding(
            network.connector(),
            idleTimeout: const Duration(seconds: 3),
          ),
          options,
        );
        expect(shorter.keepAlive, const Duration(seconds: 1));
        final noIdle = await dialledWith(
          QuicSwitchboardBinding(
            network.connector(),
            idleTimeout: Duration.zero,
          ),
          options,
        );
        expect(noIdle.idleTimeout, Duration.zero);
        expect(noIdle.keepAlive, Duration.zero);
        final given = await dialledWith(
          QuicSwitchboardBinding(
            network.connector(),
            keepAlive: const Duration(seconds: 4),
          ),
          options,
        );
        expect(given.keepAlive, const Duration(seconds: 4));
        final off = await dialledWith(
          QuicSwitchboardBinding(network.connector(), keepAlive: Duration.zero),
          options,
        );
        expect(off.keepAlive, Duration.zero);
        expect(off.idleTimeout, const Duration(seconds: 30));
      }
    });

    test('a negative idle timeout or keep-alive is an ArgumentError', () {
      final connector = FakeQuicNetwork().connector();
      const negative = Duration(microseconds: -1);
      expect(
        () => QuicSwitchboardBinding(connector, idleTimeout: negative),
        throwsArgumentError,
      );
      expect(
        () => QuicSwitchboardBinding(connector, keepAlive: negative),
        throwsArgumentError,
      );
    });
  });

  group('identity', () {
    test('nodes identify both ways with exporter-bound proofs, and the '
        'scoped policy admits the identified peer', () async {
      final network = FakeQuicNetwork();
      final server = node(
        verifier: await verifier(),
        credential: await credential('server-1', serverKey),
        holderKey: serverKey,
      );
      server.registerService(npc, answer);
      final listener = await listen(
        network,
        server,
        'id-1',
        policy: ChannelPolicies.scoped(),
      );
      final binding = QuicSwitchboardBinding(network.connector());
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
      expect(initiated.exporterBound, isTrue);
      expect(accepted.peerIdentity?.identity, 'npc-7');
      expect(accepted.peerIdentityBound, isTrue);
      // The listener identified in turn, naming the client.
      expect(initiated.peerIdentity?.identity, 'server-1');
      expect(initiated.peerIdentity?.receiver, 'npc-7');
      expect(initiated.peerIdentityBound, isTrue);
      expect(initiated.peerAuthenticated, isTrue);
      expect(initiated.quicOptions.identity.awaitPeerIdentity, isTrue);
    });

    test('a channel that overtakes the IDENT on its own stream is held by '
        'the node until the peer identified', () async {
      // The control stream (0) is slow: the channel's stream arrives first.
      final network = FakeQuicNetwork(
        delay: (info, {required fromInitiator}) =>
            Duration(milliseconds: info.ordinal == 0 ? 60 : 0),
      );
      var asked = 0;
      final scoped = ChannelPolicies.scoped();
      final server = node(verifier: await verifier());
      server.registerService(npc, answer);
      final listener = await listen(
        network,
        server,
        'hold-1',
        policy: (address, connection) {
          asked++;
          return scoped(address, connection);
        },
      );
      final client = node(
        bindings: [
          QuicSwitchboardBinding(
            network.connector(),
            identityRules: const QuicIdentityRules(
              requireExporterBinding: true,
            ),
          ),
        ],
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
        identifyOutgoing: false,
      );
      final connection = await client.connect(listener.endpoint);
      final identified = client.identifyOn(connection);
      // Opened while the identification is under way: its stream arrives
      // before the IDENT.
      await until(() => (connection as QuicBindingConnection).exporterBound);
      final channel = client.openChannelOn(
        connection,
        ChannelAddress(type: npc),
      );
      expect(await answerOf(channel), 'npc for npc-7');
      await identified.timeout(limit);
      expect(asked, 2);
    });

    test('an initiator with a credential reaches only an acceptor that '
        'identifies in turn', () async {
      final network = FakeQuicNetwork();
      // A listener without a credential cannot identify.
      final server = node(verifier: await verifier());
      server.registerService(npc, answer);
      final listener = await listen(network, server, 'id-2');
      final client = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
        verifier: await verifier(),
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
        identityTimeout: const Duration(milliseconds: 300),
      );
      await expectLater(
        client.openChannelAt(listener.endpoint, ChannelAddress(type: npc)),
        throwsCode(StatusCode.unauthenticated),
      );
      // One whose identity is not the one expected is refused as well.
      final other = node(
        verifier: await verifier(),
        credential: await credential('server-x', serverKey),
        holderKey: serverKey,
      );
      other.registerService(npc, answer);
      final elsewhere = await listen(network, other, 'id-3');
      final strict = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
        verifier: await verifier(),
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
        expectedIdentityFor: (endpoint, record) => 'server-1',
      );
      await expectLater(
        strict.openChannelAt(elsewhere.endpoint, ChannelAddress(type: npc)),
        throwsCode(StatusCode.unauthenticated),
      );
    });

    test('a node without the exporter cannot identify to a self-signed '
        'listener, and a nonce-bound IDENT is refused', () async {
      final network = FakeQuicNetwork();
      final server = node(verifier: await verifier());
      server.registerService(npc, answer);
      final listener = await listen(
        network,
        server,
        'id-4',
        policy: ChannelPolicies.scoped(),
      );
      // Browser-like: the stack has no exporter. Under the rules the
      // initiator closes at once.
      final browserLike = network.connector(
        config: const FakeEndConfig(exporter: false),
      );
      final careful = node(
        bindings: [QuicSwitchboardBinding(browserLike)],
        verifier: await verifier(),
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
      );
      await expectLater(
        careful.openChannelAt(listener.endpoint, ChannelAddress(type: npc)),
        throwsCode(StatusCode.unauthenticated),
      );
      // Without the rules it sends a nonce-bound IDENT, which the listener
      // refuses: the connection ends UNAUTHENTICATED.
      final binding = QuicSwitchboardBinding(
        browserLike,
        identityRules: QuicIdentityRules.none,
      );
      final careless = node(
        bindings: [binding],
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
      );
      await expectLater(
        careless.openChannelAt(listener.endpoint, ChannelAddress(type: npc)),
        throwsCode(StatusCode.unauthenticated),
      );
      expect(
        await binding.dialled.single.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
      expect(
        await binding.dialled.single.peerGoAwayStatus.timeout(limit),
        hasCode(StatusCode.unauthenticated),
      );
      // A browser-like client without a credential talks all the same,
      // with what its policy admits.
      final open = node(bindings: [QuicSwitchboardBinding(browserLike)]);
      final server2 = node();
      server2.registerService(npc, answer);
      final listener2 = await listen(network, server2, 'id-5');
      expect(
        await answerOf(
          await open.openChannelAt(
            listener2.endpoint,
            ChannelAddress(type: npc),
          ),
        ),
        'npc for nobody',
      );
    });

    test('a bearer credential goes only to an authenticated end: a pin, '
        'not a self-signed certificate', () async {
      final network = FakeQuicNetwork();
      final hmac = CredentialIssuer.hmac(Name('k1'), Uint8List(32));
      final bearer = await hmac.issue(
        kind: CredentialKind.node,
        identity: 'bearer-1',
        scopes: [Scope.of(Right.open, '*')],
      );
      final hash = Uint8List.fromList(List.generate(32, (i) => i));
      final server = node(
        verifier: CredentialVerifier(hmacKeys: {Name('k1'): Uint8List(32)}),
      );
      server.registerService(npc, answer);
      final listener = await listen(
        network,
        server,
        'bearer-1',
        policy: ChannelPolicies.scoped(),
        config: FakeEndConfig(certificateHash: hash),
        // The listener's clients pin its certificate.
        rules: QuicIdentityRules.none,
      );
      final unpinned = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
        credential: bearer,
      );
      await expectLater(
        unpinned.openChannelAt(listener.endpoint, ChannelAddress(type: npc)),
        throwsCode(StatusCode.unauthenticated),
      );
      final pinned = node(
        bindings: [
          QuicSwitchboardBinding(
            network.connector(),
            certificateHashes: [hash],
          ),
        ],
        credential: bearer,
      );
      expect(
        await answerOf(
          await pinned.openChannelAt(
            listener.endpoint,
            ChannelAddress(type: npc),
          ),
        ),
        'npc for bearer-1',
      );
      // A wrong pin does not reach the listener at all.
      final wrong = node(
        bindings: [
          QuicSwitchboardBinding(
            network.connector(),
            certificateHashes: [Uint8List(32)],
          ),
        ],
        credential: bearer,
      );
      await expectLater(
        wrong.connect(listener.endpoint),
        throwsCode(StatusCode.unavailable),
      );
    });

    group('a man in the middle', () {
      /// Relays every session dialled to `quic://mitm:4433` to [target],
      /// stream by stream, clearing the EXPORTER flags of both HELLOs when
      /// [strip].
      Future<void> mitm(
        FakeQuicNetwork network,
        Uri target, {
        required bool strip,
      }) async {
        final listener = network.listen(Uri.parse('quic://mitm:4433'));
        addTearDown(listener.close);
        final connector = network.connector();
        listener.sessions.listen((victim) async {
          final upstream = await connector.connect(
            target,
            const QuicClientConfig(alpn: ['switchboard']),
          );
          // The control stream is the first stream either way: its HELLO
          // flags at offset 23 from the initiator (after the OPEN record),
          // 13 from the acceptor.
          Future<void> pump(
            QuicStream from,
            QuicStream to, {
            int? flagAt,
          }) async {
            var offset = 0;
            try {
              while (true) {
                final chunk = await from.read(1 << 16);
                if (chunk == null) {
                  await to.finish();
                  return;
                }
                final copy = Uint8List.fromList(chunk);
                if (strip && flagAt != null) {
                  final at = flagAt - offset;
                  if (at >= 0 && at < copy.length) {
                    copy[at] &= ~QuicHello.flagExporter;
                  }
                }
                offset += chunk.length;
                await to.write(copy);
              }
            } on QuicStreamReset catch (e) {
              to.reset(e.code ?? 0);
            } on Object {
              // Either session ended.
            }
          }

          var first = true;
          victim.incomingStreams.listen((down) async {
            final control = first;
            first = false;
            final up = await upstream.openStream();
            unawaited(pump(down, up, flagAt: control ? 23 : null));
            unawaited(pump(up, down, flagAt: control ? 13 : null));
          });
          upstream.incomingStreams.listen((up) async {
            final down = await victim.openStream();
            unawaited(pump(up, down));
            unawaited(pump(down, up));
          });
          unawaited(
            upstream.done.then(
              (end) => victim.close(end.code ?? 0, end.reason),
            ),
          );
          unawaited(
            victim.done.then(
              (end) => upstream.close(end.code ?? 0, end.reason),
            ),
          );
        });
      }

      Future<(Switchboard, Uri)> target(
        FakeQuicNetwork network,
        String host, {
        QuicIdentityRules rules = QuicIdentityRules.listener,
      }) async {
        final server = node(
          verifier: await verifier(),
          credential: await credential('server-1', serverKey),
          holderKey: serverKey,
        );
        server.registerService(npc, answer);
        final listener = await listen(
          network,
          server,
          host,
          policy: ChannelPolicies.scoped(),
          rules: rules,
        );
        return (server, listener.endpoint);
      }

      Future<Switchboard> victim(
        FakeQuicNetwork network, {
        QuicIdentityRules? rules,
      }) async => node(
        bindings: [
          QuicSwitchboardBinding(network.connector(), identityRules: rules),
        ],
        verifier: await verifier(),
        credential: await credential('npc-7', clientKey),
        holderKey: clientKey,
        expectedIdentityFor: (endpoint, record) => 'server-1',
      );

      test('relaying the HELLOs as they are: the exporters differ, the '
          'identification fails', () async {
        final network = FakeQuicNetwork();
        final (_, uri) = await target(network, 'real-1');
        await mitm(network, uri, strip: false);
        final client = await victim(network);
        // The victim reaches the real listener directly.
        expect(
          await answerOf(
            await client.openChannelAt(uri, ChannelAddress(type: npc)),
          ),
          'npc for npc-7',
        );
        await expectLater(
          client.openChannelAt(
            Uri.parse('quic://mitm:4433'),
            ChannelAddress(type: npc),
          ),
          throwsCode(StatusCode.unauthenticated),
        );
      });

      test('stripping the EXPORTER flags makes the identification fail, '
          'never succeed', () async {
        final network = FakeQuicNetwork();
        final (_, uri) = await target(network, 'real-2');
        await mitm(network, uri, strip: true);
        final client = await victim(network);
        await expectLater(
          client.openChannelAt(
            Uri.parse('quic://mitm:4433'),
            ChannelAddress(type: npc),
          ),
          throwsCode(StatusCode.unauthenticated),
        );
      });

      test('without the rules on either side, stripping the flags relays '
          'the identification: what the rules prevent', () async {
        final network = FakeQuicNetwork();
        final (_, uri) = await target(
          network,
          'real-3',
          rules: QuicIdentityRules.none,
        );
        await mitm(network, uri, strip: true);
        final client = await victim(network, rules: QuicIdentityRules.none);
        expect(
          await answerOf(
            await client.openChannelAt(
              Uri.parse('quic://mitm:4433'),
              ChannelAddress(type: npc),
            ),
          ),
          'npc for npc-7',
        );
      });
    });
  });

  group('the proxy between the frame mux and the binding', () {
    test('a frame mux client through a proxy to a QUIC backend, bulk '
        'payloads included', () async {
      final network = FakeQuicNetwork(
        delay: (info, {required fromInitiator}) =>
            Duration(milliseconds: info.ordinal == 1 ? 30 : 0),
      );
      final backend = node();
      backend.registerService(echo, echoService, instance: 1);
      final backendListener = await listen(
        network,
        backend,
        'backend-1',
        rules: QuicIdentityRules.none,
      );
      final resolver = StaticResolver([
        ServiceRecord(
          ServiceAddress(echo, 1),
          endpoints: [backendListener.endpoint],
        ),
      ]);
      addTearDown(resolver.close);
      final binding = QuicSwitchboardBinding(network.connector());
      final proxy = node(bindings: [binding], resolver: resolver);
      proxy.catchAll = proxyHandler(proxy);
      final proxyUri = await proxy.listenMemory();
      final client = node();
      final talk = await client.openTalkAt(
        proxyUri,
        ChannelAddress(type: echo),
      );
      expect(talk.raw, isA<FrameMuxChannel>());
      final small = await talk.request('ECHO', bytes('through')).timeout(limit);
      expect(text(small.payload), 'through');
      final payload = pattern(3 * 1024 * 1024, 5);
      final big = await talk
          .request('BIG', payload)
          .timeout(const Duration(seconds: 30));
      expect(big.isBulk, isTrue);
      expect(big.payload, payload);
      final twins = await Future.wait([
        talk.request('A', pattern(200000, 1)),
        talk.request('B', pattern(150000, 2)),
      ]).timeout(const Duration(seconds: 30));
      expect(twins[0].payload, pattern(200000, 1));
      expect(twins[1].payload, pattern(150000, 2));
    });

    test('a QUIC client through a proxy to a frame mux backend: bulk twins '
        'forwarded in order', () async {
      // The parent stream is slow: the two bulk streams of the client
      // reach the proxy before their references, the second one first.
      final network = FakeQuicNetwork(
        delay: (info, {required fromInitiator}) => Duration(
          milliseconds: switch (info.ordinal) {
            1 => 50,
            2 => 25,
            _ => 0,
          },
        ),
      );
      final backend = node();
      final received = <Uint8List>[];
      backend.registerService(echo, (incoming) {
        incoming.talk().messages.listen((m) {
          received.add(m.payload);
          if (m.expectsReply) {
            unawaited(m.reply(bytes('${m.payload.length}')));
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
      final proxyListener = await listen(
        network,
        proxy,
        'proxy-1',
        rules: QuicIdentityRules.none,
      );
      final client = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
      );
      final talk = await client.openTalkAt(
        proxyListener.endpoint,
        ChannelAddress(type: echo),
      );
      final first = pattern(120000, 1);
      final second = pattern(90000, 2);
      final replies = await Future.wait([
        talk.request('A', first),
        talk.request('B', second),
      ]).timeout(const Duration(seconds: 30));
      expect(text(replies[0].payload), '120000');
      expect(text(replies[1].payload), '90000');
      expect(received, [first, second]);
      // The second bulk stream reached the proxy first.
      final (_, accepted) = network.pairs.single;
      expect(
        accepted.announced.indexOf(3),
        lessThan(accepted.announced.indexOf(2)),
      );
    });
  });

  group('the end of a connection', () {
    test('a node closing sends GOAWAY: the peer\'s channels end GOING_AWAY, '
        'and the session closes with code 0', () async {
      final network = FakeQuicNetwork();
      final server = Switchboard(muxOptions: fast);
      server.registerService(echo, echoService);
      final listener = await listen(
        network,
        server,
        'end-1',
        rules: QuicIdentityRules.none,
      );
      final binding = QuicSwitchboardBinding(network.connector());
      final client = node(bindings: [binding]);
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      await talk.request('ECHO', bytes('x')).timeout(limit);
      final connection = binding.dialled.single;
      await server.close();
      expect(
        await connection.peerGoAwayStatus.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.goingAway),
      );
      final (_, accepted) = network.pairs.single;
      expect(accepted.closes.single.$1, 0);
    });

    test('a GOAWAY with a status reaches the peer, and the session close '
        'carries it with its reason', () async {
      final network = FakeQuicNetwork();
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(
        network,
        server,
        'end-2',
        rules: QuicIdentityRules.none,
      );
      final binding = QuicSwitchboardBinding(network.connector());
      final client = node(bindings: [binding]);
      await client.connect(listener.endpoint);
      final connection = binding.dialled.single;
      final accepted = listener.accepted.single;
      await connection.goAway(Status.of(StatusCode.unavailable, 'upgrade'));
      expect(
        await accepted.peerGoAwayStatus.timeout(limit),
        Status.of(StatusCode.unavailable, 'upgrade'),
      );
      final (initiator, _) = network.pairs.single;
      expect(initiator.closes.single, (14, 'upgrade'));
      expect(
        await connection.done.timeout(limit),
        Status.of(StatusCode.unavailable, 'upgrade'),
      );
    });

    test('a lost session ends the channels with CONNECTION_LOST', () async {
      final network = FakeQuicNetwork();
      final server = node();
      server.registerService(echo, echoService);
      final listener = await listen(
        network,
        server,
        'end-3',
        rules: QuicIdentityRules.none,
      );
      final client = node(
        bindings: [QuicSwitchboardBinding(network.connector())],
      );
      final talk = await client.openTalkAt(
        listener.endpoint,
        ChannelAddress(type: echo),
      );
      await talk.request('ECHO', bytes('x')).timeout(limit);
      final (initiator, _) = network.pairs.single;
      initiator.lose('idle timeout');
      expect(
        await (talk.raw as MuxChannel).done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
    });
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
