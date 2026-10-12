/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// The binding over the web provider, in a browser, against the Switchboard
// node of tool/web_server.dart (started by tool/web_smoke.sh; without it
// every test skips): QuicBindingConnection through connectQuicBinding (HELLO,
// a channel, Talk through the node's service, a nonce-bound IDENT accepted
// by a listener with QuicIdentityRules.none, the node's GOAWAY, a close from
// the browser), and ReconnectingClient.connections over it (a request, the
// node closing the connection, the reconnect, the node's GOAWAY).

@TestOn('browser')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/core.dart';
import 'package:switchboard_quic/switchboard_quic_web.dart';
import 'package:test/test.dart';

import 'web_harness.dart';

final echo = Name('echo');
final control = Name('control');
final issue = Name('issue');

/// A connection to the node, closed after the test. The node's bulk
/// channels go to the Talk channels they belong to (what a `Switchboard` or
/// a `ReconnectingClient` does with the channels a connection delivers).
Future<QuicBindingConnection> dialNode(
  WebServer s, {
  MuxOptions options = const MuxOptions(),
}) async {
  final connection = await connectQuicBinding(
    const WebQuicProvider(),
    s.node,
    options: options,
    certificateHashes: [s.hash],
  ).timeout(limit);
  connection.incoming.listen(TalkChannel.adoptBulk);
  addTearDown(() => connection.close().timeout(limit));
  return connection;
}

/// A Talk channel to [service] on [connection].
TalkChannel talkTo(MuxConnection connection, Name service) =>
    TalkChannel(connection.open(ChannelAddress(type: service).encode()));

void main() {
  test('the connection: HELLO both ways, the session WebTransport, the '
      'certificate authenticating the node', () async {
    final s = await server();
    if (s == null) return;
    final connection = await dialNode(s);
    await connection.ping().timeout(limit);
    expect(connection.peerHello, isNotNull);
    expect(connection.isInitiator, isTrue);
    expect(connection.isWebTransport, isTrue);
    expect(connection.session, isA<WebQuicSession>());
    expect(connection.session.protocol, 'switchboard');
    expect(connection.quicOptions.identity.tlsAuthenticatesPeer, isTrue);
    expect(connection.peerAuthenticated, isTrue);
    final session = connection.session as WebQuicSession;
    // Exporter-bound only where the browser has exportKeyingMaterial.
    expect(
      connection.hasExporter,
      session.capabilities['exportKeyingMaterial'],
    );
    expect(connection.exporterBound, connection.hasExporter);
  });

  test('a channel and a Talk request through the node\'s service', () async {
    final s = await server();
    if (s == null) return;
    final connection = await dialNode(s);
    final talk = talkTo(connection, echo);
    expect(talk.raw, isA<QuicChannel>());
    final reply = await talk.request('ECHO', bytes('hello')).timeout(limit);
    expect(text(reply.payload), 'hello');
    final big = pattern(200000);
    final bulk = await talk.request('BIG', big).timeout(limit);
    expect(bulk.payload, big);
    await talk.close().timeout(limit);
    expect(connection.openChannelCount, 0);
  });

  test('a nonce-bound IDENT from the browser, accepted by a listener with '
      'QuicIdentityRules.none', () async {
    final s = await server();
    if (s == null) return;
    final connection = await dialNode(s);
    final key = await HolderKey.generate();
    final issuing = talkTo(connection, issue);
    final credential = Credential.decode(
      (await issuing.request('ISSUE', key.publicKey).timeout(limit)).payload,
    );
    await issuing.close();
    expect(credential.identity, 'browser-1');
    await connection.identify(credential, holderKey: key).timeout(limit);
    final asking = talkTo(connection, control);
    final who = await asking.request('WHOAMI', Uint8List(0)).timeout(limit);
    expect(text(who.payload), 'browser-1');
    await asking.close();
  });

  test('the node\'s GOAWAY: the browser stops opening, finishes, and the '
      'connection closes', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final connection = await dialNode(s);
    final asking = talkTo(connection, control);
    await asking.request('TAG', bytes(id)).timeout(limit);
    await asking.request('GOAWAY', Uint8List(0)).timeout(limit);
    final status = await connection.peerGoAwayStatus.timeout(limit);
    expect(status.known, StatusCode.goingAway);
    expect(connection.peerGoingAway, isTrue);
    expect(
      () => connection.open(ChannelAddress(type: echo).encode()),
      throwsA(isA<SwitchboardException>()),
    );
    await asking.close();
    final done = await connection.done.timeout(limit);
    expect(done.known, StatusCode.goingAway);
    final end = await connection.session.done.timeout(limit);
    expect(end.lost, isFalse);
    final seen = await s.reported(id, (e) => e['event'] == 'connection done');
    expect(seen['code'], StatusCode.goingAway.code);
  });

  test('a close from the browser: the node reads it as GOING_AWAY', () async {
    final s = await server();
    if (s == null) return;
    final id = newId();
    final connection = await dialNode(s);
    final asking = talkTo(connection, control);
    await asking.request('TAG', bytes(id)).timeout(limit);
    await asking.close().timeout(limit);
    await connection.close().timeout(limit);
    final end = await connection.session.done.timeout(limit);
    expect(end.code, 0);
    expect(end.byPeer, isFalse);
    expect(connection.isOpen, isFalse);
    final seen = await s.reported(id, (e) => e['event'] == 'connection done');
    expect(seen['code'], StatusCode.goingAway.code);
  });

  group('ReconnectingClient.connections', () {
    ReconnectingClient client(WebServer s) {
      final c = ReconnectingClient.connections(
        (options) => connectQuicBinding(
          const WebQuicProvider(),
          s.node,
          options: options,
          certificateHashes: [s.hash],
        ),
        initialBackoff: const Duration(milliseconds: 50),
        maxBackoff: const Duration(seconds: 1),
        jitter: 0,
      );
      addTearDown(() => c.close().timeout(limit));
      return c;
    }

    test('connects and serves a request', () async {
      final s = await server();
      if (s == null) return;
      final c = client(s);
      final talk = await c.openTalk(ChannelAddress(type: echo)).timeout(limit);
      expect(c.connection, isA<QuicBindingConnection>());
      final reply = await talk.request('ECHO', bytes('one')).timeout(limit);
      expect(text(reply.payload), 'one');
      await talk.close();
    });

    test('reconnects after the node closes the connection, and serves '
        'again', () async {
      final s = await server();
      if (s == null) return;
      final c = client(s);
      final ready = <TalkChannel>[];
      c.openPersistentTalk(
        ChannelAddress(type: echo),
        (talk) async => ready.add(talk),
      );
      await until(() => ready.length == 1);
      final first = c.connection;
      expect(text((await ready.last.request('ECHO', bytes('a'))).payload), 'a');
      final asking = await c.openTalk(ChannelAddress(type: control));
      await asking.send('CLOSE', Uint8List(0));
      await until(() => ready.length == 2);
      expect(c.connection, isNot(same(first)));
      expect(c.state.isConnected, isTrue);
      expect(text((await ready.last.request('ECHO', bytes('b'))).payload), 'b');
    });

    test('moves to a new connection on the node\'s GOAWAY', () async {
      final s = await server();
      if (s == null) return;
      final c = client(s);
      final talk = await c.openTalk(ChannelAddress(type: control));
      final first = c.connection!;
      await talk.request('GOAWAY', Uint8List(0)).timeout(limit);
      await talk.close();
      await until(() => c.connection != null && c.connection != first);
      final again = await c.openTalk(ChannelAddress(type: echo));
      expect(text((await again.request('ECHO', bytes('c'))).payload), 'c');
      expect((await first.done.timeout(limit)).known, StatusCode.goingAway);
      await again.close();
    });
  });
}
