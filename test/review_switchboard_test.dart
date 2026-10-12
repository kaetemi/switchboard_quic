/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  GPT-6 Astra <noreply@openai.com>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

// Review cases of the binding with Switchboard nodes (the node API needs
// dart:io).

@TestOn('vm')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/switchboard.dart';
import 'package:switchboard_quic/switchboard_quic.dart';
import 'package:test/test.dart';

import 'fake_provider.dart';
import 'harness.dart';

void main() {
  final echo = Name('echo');
  Switchboard node() {
    final server = Switchboard(muxOptions: fast);
    server.registerService(echo, (incoming) {
      incoming.talk().messages.listen((message) {
        if (message.expectsReply) unawaited(message.reply(message.payload));
      });
    });
    addTearDown(server.close);
    return server;
  }

  test('adopt owns a QUIC connection once and closes late arrivals', () async {
    final server = node();
    final (a, b) = await connectionPair();
    expect(await server.adopt(b), same(b));
    await expectLater(server.adopt(b), throwsArgumentError);
    final talk = TalkChannel(a.open(ChannelAddress(type: echo).encode()));
    expect(
      (await talk.request('ECHO', bytes('hello'))).payload,
      bytes('hello'),
    );
    final (c, d) = await connectionPair();
    d.incoming.listen((_) {});
    await expectLater(server.adopt(d), throwsStateError);
    await c.close();
    await server.close();
    expect(await a.done.timeout(limit), hasCode(StatusCode.goingAway));
    final (e, f) = await connectionPair();
    await expectLater(
      server.adopt(f),
      throwsCode(StatusCode.failedPrecondition),
    );
    expect(
      await e.peerGoAwayStatus.timeout(limit),
      hasCode(StatusCode.goingAway),
    );
  });

  test(
    'closing the listener during exporter setup prevents adoption',
    () async {
      final server = node();
      final network = FakeQuicNetwork();
      final provider = network.listen(Uri.parse('quic://listener:4433'));
      final listener = await QuicSwitchboardListener.start(server, provider);
      final (a, b) = FakeQuicSession.pair();
      b.exporterGate = Completer<void>();
      provider.acceptSession(b);
      await until(() => b.exporterLabels.isNotEmpty);
      await listener.close();
      b.exporterGate!.complete();
      expect((await a.done.timeout(limit)).code, 0);
      expect(listener.accepted, isEmpty);
    },
  );

  test('SlotChannel accounts held sends at QUIC record cost', () async {
    final (a, b) = await connectionPair();
    b.incoming.listen((channel) {
      unawaited(channel.close(Status.of(StatusCode.moved)));
    });
    final first = a.open(ChannelAddress(type: echo).encode());
    final reopened = Completer<MuxChannel?>();
    addTearDown(() {
      if (!reopened.isCompleted) reopened.complete(null);
    });
    // Exercise the internal seam used by the public slot-opening API.
    // ignore: invalid_use_of_internal_member
    final slot = SlotChannel(
      echo,
      3,
      first,
      (_) => reopened.future,
      maxHeldBytes: 100,
    );
    expect(await first.done.timeout(limit), hasCode(StatusCode.moved));
    final sends = [slot.send(Uint8List(40)), slot.send(Uint8List(40))];
    await expectLater(
      slot.send(Uint8List(40)),
      throwsCode(StatusCode.resourceExhausted),
    );
    expect(
      await slot.done.timeout(limit),
      hasCode(StatusCode.resourceExhausted),
    );
    for (final sending in sends) {
      await expectLater(sending, throwsCode(StatusCode.failedPrecondition));
    }
  });

  test(
    'ReconnectingClient reopens over a new QUIC session after loss',
    () async {
      final server = node();
      final accepted = <QuicBindingConnection>[];
      final client = ReconnectingClient.connections(
        (options) async {
          final (a, b) = FakeQuicSession.pair();
          final remote = await QuicBindingConnection.start(b, options: fast);
          final local = await QuicBindingConnection.start(a, options: options);
          accepted.add(remote);
          await server.adopt(remote);
          return local;
        },
        muxOptions: fast,
        initialBackoff: const Duration(milliseconds: 10),
        jitter: 0,
      );
      addTearDown(client.close);
      final ready = <TalkChannel>[];
      client.openPersistentTalk(ChannelAddress(type: echo), (talk) async {
        ready.add(talk);
      });
      await until(() => ready.length == 1);
      expect(
        (await ready.single.request('ECHO', bytes('one'))).payload,
        bytes('one'),
      );
      (accepted.single.session as FakeQuicSession).lose();
      await until(() => ready.length == 2);
      expect(accepted, hasLength(2));
      expect(
        (await ready.last.request('ECHO', bytes('two'))).payload,
        bytes('two'),
      );
    },
  );
}
