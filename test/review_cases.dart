/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/core.dart';
import 'package:switchboard_quic/core.dart';
import 'package:test/test.dart';

import 'harness.dart';
import 'memory_provider.dart';

void reviewCases() {
  group('review regressions', () {
    test(
      'CLOSE without FIN releases the stream after confirmation timeout',
      () async {
        final (connection, raw) = await bindingAndRaw(
          options: fast.copyWith(
            closeConfirmTimeout: const Duration(milliseconds: 60),
          ),
        );
        final incoming = connection.incoming.first;
        final stream = await raw.openRaw([
          ...encodeOpenRecord(2, []),
          ...encodeCloseRecord(Status.ok),
        ]);
        final channel = await incoming;
        expect(await channel.done.timeout(limit), hasCode(StatusCode.ok));
        expect(
          await stream.stopped.timeout(limit),
          StatusCode.deadlineExceeded.code,
        );
        final reader = RecordReader(stream);
        expect(
          (await reader.next(limit: quicDefaultRecordLimit))!.command,
          QuicRecordCommand.close,
        );
        await reader.expectEnd();
        expect(connection.openChannelCount, 0);
        expect(connection.isOpen, isTrue);
      },
    );

    test(
      'control reset is observed while control reading is throttled',
      () async {
        final (connection, raw) = await bindingAndRaw(
          rawEnd: const MemoryQuicEndConfig(streamWindow: 32),
          quicOptions: const QuicBindingOptions(controlOutputMark: 128),
        );
        await raw.sendControl(MuxControlMessage.ping(Uint8List(125)));
        await raw.sendControl(MuxControlMessage.ping(Uint8List(125)));
        await until(() => connection.heldOutputBytes > 128);
        raw.control!.reset(StatusCode.cancelled.code);
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.protocolError),
        );
      },
    );

    test(
      'peer reset ends a channel whose application consumes nothing',
      () async {
        final (connection, raw) = await bindingAndRaw();
        final incoming = connection.incoming.first;
        final stream = await raw.openRaw([
          ...encodeOpenRecord(2, []),
          ...encodeDataRecord([1, 2, 3]),
        ]);
        final channel = await incoming;
        await until(() => channel.bufferedBytes == 7);
        // The binding waits on consumption and has no pending read.
        stream.reset(StatusCode.cancelled.code);
        expect(
          await channel.done.timeout(limit),
          hasCode(StatusCode.cancelled),
        );
        expect(connection.openChannelCount, 0);
        expect(connection.isOpen, isTrue);
      },
    );

    test('no-code STOP_SENDING is not a successful acknowledgement', () async {
      final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
      final channel = connection.open(Uint8List(0));
      final stream = await raw.nextStream();
      await channel.whenWritable;
      (stream as MemoryQuicStream).stopWithoutCode();
      await until(() => !channel.canSend);
      await stream.write(
        encodeCloseRecord(Status.of(StatusCode.unknown, 'stopped')),
      );
      await stream.finish();
      expect(
        await channel.done.timeout(limit),
        Status.of(StatusCode.unknown, 'stopped'),
      );
    });

    test('no-code STOP_SENDING on control is a protocol error', () async {
      final (connection, raw) = await bindingAndRaw();
      await until(() => connection.peerHello != null);
      (raw.control! as MemoryQuicStream).stopWithoutCode();
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.protocolError),
      );
    });

    test('failed exporter is not silently negotiated as unavailable', () async {
      final (a, _) = MemoryQuicSession.pair();
      a.exporterFailure = StateError('export failed');
      final connection = await QuicBindingConnection.start(a, options: fast);
      addTearDown(connection.close);
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.internal),
      );
    });

    test('session loss interrupts an exporter still pending', () async {
      final (a, _) = MemoryQuicSession.pair();
      a.exporterGate = Completer<void>();
      final starting = QuicBindingConnection.start(a, options: fast);
      await until(() => a.exporterLabels.isNotEmpty);
      a.lose();
      final connection = await starting.timeout(limit);
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
      a.exporterGate!.complete();
    });

    test(
      'identity defaults gate unverified peers whenever identity is used',
      () {
        final rules = QuicIdentityRules.initiator(
          certificateVerified: false,
          hasCredential: false,
          verifiesCredentials: true,
        );
        expect(rules.requireExporterBinding, isTrue);
        expect(rules.awaitPeerIdentity, isTrue);
        expect(rules.bearerOnlyToAuthenticatedPeer, isTrue);
      },
    );

    for (final sentGoAway in [true, false]) {
      test('Talk waits for late bulk after parent CLOSE and GOAWAY '
          '(sent $sentGoAway)', () async {
        final (connection, raw) = await bindingAndRaw();
        final parentArrived = Completer<TalkChannel>();
        connection.incoming.listen((channel) {
          if (TalkBulkOpen.isBulk(ChannelAddress.decode(channel.openPayload))) {
            TalkChannel.adoptBulk(channel);
          } else {
            parentArrived.complete(TalkChannel(channel));
          }
        });
        final parent = await raw.openRaw(
          encodeOpenRecord(2, ChannelAddress(type: Name('echo')).encode()),
        );
        final talk = await parentArrived.future.timeout(limit);
        // A receiver may grant ahead while the response payload is pending;
        // its parent's CLOSE is then visible before the bulk stream.
        (talk.raw as MuxChannel).grant(65536);
        final message = talk.request('REQ', Uint8List(0));
        message.ignore();
        final request = await RecordReader(parent)
            .next(limit: quicDefaultRecordLimit);
        final requestId = TalkFrame.decode(request!.body).requestId;
        await parent.write(
          encodeDataRecord(
            TalkFrame(
              kind: TalkKind.message,
              responseId: requestId,
              payload: Uint8List(0),
            ).withBulk(TalkBulkReference(1, length: 3)).encode(),
          ),
        );
        if (sentGoAway) {
          unawaited(connection.goAway());
          await raw.nextControlOf(MuxControlType.goAway.code);
          // The PING right after the GOAWAY, answered as a peer does: the
          // close then waits only for the drain.
          final ping = await raw.nextControl();
          expect(ping.knownType, MuxControlType.ping);
          await raw.sendControl(MuxControlMessage.pong(ping.payload));
        } else {
          await raw.sendControl(
            MuxControlMessage.goAway(Status.of(StatusCode.goingAway)),
          );
          await connection.peerGoAwayStatus;
        }
        await parent.write(encodeCloseRecord(Status.ok));
        await parent.finish();
        await until(
          () => connection.channelWithId(2) == null && connection.hasDrainHolds,
        );
        final bulk = await raw.openRaw([
          ...encodeOpenRecord(4, TalkBulkOpen(2, 1).encode()),
          ...encodeDataRecord([1, 2, 3]),
          ...encodeCloseRecord(Status.ok),
        ]);
        await bulk.finish();
        expect((await message.timeout(limit)).payload, [1, 2, 3]);
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.goingAway),
        );
      });
    }

    test('failure close before opening still writes OPEN and CLOSE', () async {
      final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
      final channel = connection.open(bytes('open'));
      final closing = channel.close(Status.of(StatusCode.notFound, 'gone'));
      final stream = await raw.nextStream();
      final (records, end) = await RawPeer.drain(stream);
      expect(records.map((r) => r.command), [
        QuicRecordCommand.open,
        QuicRecordCommand.close,
      ]);
      expect(decodeOpenBody(records.first.body).$1, channel.id);
      expect(decodeOpenBody(records.first.body).$2, bytes('open'));
      expect(
        decodeCloseBody(records.last.body),
        Status.of(StatusCode.notFound, 'gone'),
      );
      expect(end, 'fin');
      await closing.timeout(limit);
    });

    test('concurrent error closes preserve each side first status', () async {
      final (a, b) = await connectionPair();
      final incoming = b.incoming.first;
      final local = a.open(Uint8List(0));
      final remote = await incoming;
      final first = local.close(Status.of(StatusCode.aborted, 'local'));
      final second = remote.close(Status.of(StatusCode.cancelled, 'remote'));
      await Future.wait([first, second]).timeout(limit);
      expect(await local.done, Status.of(StatusCode.aborted, 'local'));
      expect(await remote.done, Status.of(StatusCode.cancelled, 'remote'));
      expect(a.isOpen && b.isOpen, isTrue);
    });

    test('peer CLOSE interrupts a write stalled at the window', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawEnd: const MemoryQuicEndConfig(streamWindow: 100),
      );
      final channel = connection.open(Uint8List(0));
      final stream = await raw.nextStream();
      final sending = channel.send(pattern(1000));
      final failed = expectLater(
        sending,
        throwsCode(StatusCode.failedPrecondition),
      );
      await stream.write(encodeCloseRecord(Status.of(StatusCode.cancelled)));
      await stream.finish();
      expect(await channel.done.timeout(limit), hasCode(StatusCode.cancelled));
      await failed;
      expect((connection.session as MemoryQuicSession).streams.last.resets, [
        0,
      ]);
    });

    test('second HELLO is a protocol error', () async {
      final (connection, raw) = await bindingAndRaw();
      await raw.sendControl(QuicHello().toControlMessage());
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.protocolError),
      );
      expect((await raw.end).code, StatusCode.protocolError.code);
    });

    test('control OPEN must have an empty payload', () async {
      final (connection, raw) = await bindingAndRaw(rawControl: false);
      await raw.openRaw(encodeOpenRecord(0, [1]));
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.protocolError),
      );
    });

    test(
      'a record exactly at the limit makes progress over a small window',
      () async {
        final (a, b) = await connectionPair(
          acceptorEnd: const MemoryQuicEndConfig(streamWindow: 100),
        );
        final incoming = b.incoming.first;
        final channel = a.open(Uint8List(0));
        final remote = await incoming;
        final data = remote.stream.first;
        await channel.send(pattern(quicDefaultRecordLimit));
        expect(await data.timeout(limit), pattern(quicDefaultRecordLimit));
        expect(
          () => channel.send(pattern(quicDefaultRecordLimit + 1)),
          throwsCode(StatusCode.frameTooLarge),
        );
        await channel.close().timeout(limit);
      },
    );

    for (final initiator in [true, false]) {
      test('missing HELLO is bounded (initiator $initiator)', () async {
        final (a, b) = MemoryQuicSession.pair();
        final raw = RawPeer(initiator ? b : a);
        final connection = await QuicBindingConnection.start(
          initiator ? a : b,
          options: fast,
          quicOptions: const QuicBindingOptions(
            controlStreamTimeout: Duration(milliseconds: 100),
          ),
        );
        addTearDown(connection.close);
        if (initiator) {
          await raw.acceptControl(sendHello: false);
        } else {
          await raw.openControl(sendHello: false);
        }
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.protocolError),
        );
      });
    }

    test(
      'listener refuses nonce-bound IDENT even without a verifier',
      () async {
        final (connection, raw) = await bindingAndRaw(
          quicOptions: const QuicBindingOptions(
            identity: QuicIdentityRules.listener,
          ),
        );
        await raw.sendControl(MuxControlMessage.nonce(pattern(32)));
        await raw.nextControlOf(MuxControlType.nonce.code);
        await raw.sendControl(
          MuxControlMessage.ident(MuxIdent(credential: Uint8List(0))),
        );
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.unauthenticated),
        );
      },
    );

    test('mismatched exporters cannot authenticate', () async {
      final issuer = await CredentialIssuer.ed25519FromSeed(
        Name('issuer'),
        pattern(32),
      );
      final key = await HolderKey.fromSeed(pattern(32, 1));
      final credential = await issuer.issue(
        kind: CredentialKind.node,
        identity: 'sender',
        holderKey: key.publicKey,
      );
      final verifier = CredentialVerifier();
      await verifier.addIssuer(issuer);
      final (a, b) = MemoryQuicSession.pair();
      b.exporterXor = 1;
      final receiver = await QuicBindingConnection.start(
        b,
        options: fast.copyWith(identityVerifier: verifier),
      );
      final sender = await QuicBindingConnection.start(a, options: fast);
      addTearDown(sender.close);
      addTearDown(receiver.close);
      await expectLater(
        sender.identify(credential, holderKey: key),
        throwsCode(StatusCode.unauthenticated),
      );
      expect(await receiver.done, hasCode(StatusCode.unauthenticated));
    });

    test('pending OPEN streams are capped and expire', () async {
      final (connection, raw) = await bindingAndRaw(
        quicOptions: const QuicBindingOptions(
          maxPendingStreams: 1,
          openStreamTimeout: Duration(milliseconds: 200),
        ),
      );
      await until(() => connection.peerHello != null);
      final first = await raw.openRaw([6]);
      // A header byte has arrived; the first OPEN remains incomplete.
      await until(
        () => (connection.session as MemoryQuicSession).announced.length == 2,
      );
      final second = await raw.openRaw([6]);
      expect(
        await second.stopped.timeout(limit),
        StatusCode.resourceExhausted.code,
      );
      expect(
        await first.stopped.timeout(limit),
        StatusCode.deadlineExceeded.code,
      );
      expect(connection.isOpen, isTrue);
    });

    test(
      'locally queued PING output is bounded without unhandled futures',
      () async {
        final (connection, _) = await bindingAndRaw(
          bindingIsInitiator: true,
          rawEnd: const MemoryQuicEndConfig(streamWindow: 32),
          quicOptions: const QuicBindingOptions(controlOutputMark: 128),
        );
        // Intentionally do not listen to the returned futures.
        for (var i = 0; i < 400 && connection.isOpen; i++) {
          unawaited(connection.ping(Uint8List(125)));
        }
        expect(
          await connection.done.timeout(limit),
          hasCode(StatusCode.resourceExhausted),
        );
      },
    );

    test('no-code reset is UNKNOWN without an arbitrary delay', () async {
      final (connection, raw) = await bindingAndRaw();
      final incoming = connection.incoming.first;
      final stream = await raw.openRaw(encodeOpenRecord(2, []));
      final channel = await incoming;
      (stream as MemoryQuicStream).resetWithoutCode();
      expect(await channel.done.timeout(limit), hasCode(StatusCode.unknown));
      expect(connection.isOpen, isTrue);
    });

    test(
      'provider draining is GOAWAY while admitted work can finish',
      () async {
        final (a, b) = await connectionPair();
        final incoming = b.incoming.first;
        final channel = a.open(Uint8List(0));
        await incoming;
        (b.session as MemoryQuicSession).drainPeer();
        expect(
          await a.peerGoAwayStatus.timeout(limit),
          hasCode(StatusCode.goingAway),
        );
        expect(
          () => a.open(Uint8List(0)),
          throwsCode(StatusCode.failedPrecondition),
        );
        await channel.close().timeout(limit);
        expect(await a.done.timeout(limit), hasCode(StatusCode.goingAway));
      },
    );

    test(
      'unidirectional streams are refused without losing the connection',
      () async {
        final (a, b) = await connectionPair();
        final stream = (a.session as MemoryQuicSession).openUnidirectional();
        expect(
          await stream.stopped.future.timeout(limit),
          StatusCode.unsupported.code,
        );
        await b.ping().timeout(limit);
        expect(a.isOpen && b.isOpen, isTrue);
      },
    );

    for (final operation in ['write', 'finish', 'read']) {
      test('provider $operation failure ends only its channel', () async {
        final (connection, raw) = await bindingAndRaw(bindingIsInitiator: true);
        final channel = connection.open(Uint8List(0));
        await raw.nextStream();
        await channel.whenWritable;
        final stream = (connection.session as MemoryQuicSession).streams.last;
        final error = StateError('injected $operation failure');
        if (operation == 'write') {
          stream.writeFailure = error;
          await expectLater(
            channel.send(bytes('data')),
            throwsCode(StatusCode.failedPrecondition),
          );
        } else if (operation == 'finish') {
          stream.finishFailure = error;
          await channel.close();
        } else {
          stream.failRead(error);
        }
        expect(await channel.done.timeout(limit), hasCode(StatusCode.internal));
        expect(connection.isOpen, isTrue);
      });
    }

    test(
      'stream open failure has a channel status, not CONNECTION_LOST',
      () async {
        final (connection, _) = await bindingAndRaw(bindingIsInitiator: true);
        (connection.session as MemoryQuicSession).openFailure =
            const QuicException(QuicExceptionKind.streamLimit, 'limit');
        final channel = connection.open(Uint8List(0));
        expect(
          await channel.done.timeout(limit),
          hasCode(StatusCode.resourceExhausted),
        );
        expect(connection.isOpen, isTrue);
      },
    );

    test('session loss resolves pending writes and writable waiters', () async {
      final (connection, raw) = await bindingAndRaw(
        bindingIsInitiator: true,
        rawEnd: const MemoryQuicEndConfig(streamWindow: 100),
      );
      final channel = connection.open(Uint8List(0));
      await raw.nextStream();
      final sent = expectLater(
        channel.send(pattern(1000)),
        throwsCode(StatusCode.failedPrecondition),
      );
      final ready = expectLater(
        channel.whenWritable,
        throwsCode(StatusCode.failedPrecondition),
      );
      raw.session.lose();
      expect(
        await channel.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
      await Future.wait([sent, ready]);
      await connection.goAway();
    });

    test('incoming stream source failure ends the session', () async {
      final (connection, _) = await bindingAndRaw();
      (connection.session as MemoryQuicSession).failIncoming(
        StateError('failed source'),
      );
      expect(
        await connection.done.timeout(limit),
        hasCode(StatusCode.connectionLost),
      );
      await connection.goAway();
    });
  });
}
