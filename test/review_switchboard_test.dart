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

import 'harness.dart';
import 'memory_provider.dart';

void main() {
  test('a proxy waits for a held far side and forwards GOING_AWAY', () async {
    final (front, raw) = await bindingAndRaw(isWebTransport: true);
    final arriving = front.incoming.first;
    final stream =
        await raw.openRaw(encodeOpenRecord(2, const [])) as MemoryQuicStream;
    final source = await arriving;
    final (back, destination) = await connectionPair();
    final receiving = destination.incoming.first;
    final target = back.open(Uint8List(0));
    final remote = await receiving;
    remote.stream.listen((_) {});
    final piping = pipeChannels(source, target);
    stream.resetWithoutCode();
    await settle(100);
    expect(source.state, MuxChannelState.open);
    expect(target.state, MuxChannelState.open);
    expect(remote.state, MuxChannelState.open);
    await raw.session.close(0, '');
    await piping.timeout(limit);
    expect(await remote.done.timeout(limit), hasCode(StatusCode.goingAway));
    expect(back.isOpen, isTrue);
  });

  test(
    'a channel in the identity hold ends with its WebTransport session',
    () async {
      final server = Switchboard(muxOptions: fast);
      addTearDown(server.close);
      var checked = false;
      var dispatched = false;
      final service = Name('held');
      server.registerService(service, (_) => dispatched = true);
      final (connection, raw) = await bindingAndRaw(isWebTransport: true);
      await server.adopt(
        connection,
        policy: (address, connection) {
          checked = true;
          throw SwitchboardException.of(StatusCode.unauthenticated);
        },
      );
      final stream = await raw.openRaw(
        encodeOpenRecord(2, ChannelAddress(type: service).encode()),
      ) as MemoryQuicStream;
      await until(() => checked);
      final channel = connection.channelWithId(2)!;
      stream.resetWithoutCode();
      await settle(100);
      expect(channel.state, MuxChannelState.open);
      expect(dispatched, isFalse);
      await raw.session.close(0, '');
      expect(await channel.done.timeout(limit), hasCode(StatusCode.goingAway));
      expect(dispatched, isFalse);
    },
  );

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
      final network = MemoryQuicNetwork();
      final provider = network.listen(Uri.parse('quic://listener:4433'));
      final listener = await QuicSwitchboardListener.start(server, provider);
      final (a, b) = MemoryQuicSession.pair();
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
          final (a, b) = MemoryQuicSession.pair();
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
      (accepted.single.session as MemoryQuicSession).lose();
      await until(() => ready.length == 2);
      expect(accepted, hasLength(2));
      expect(
        (await ready.last.request('ECHO', bytes('two'))).payload,
        bytes('two'),
      );
    },
  );
}
