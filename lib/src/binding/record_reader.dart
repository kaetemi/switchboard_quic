/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

import 'dart:typed_data';

import 'package:switchboard/core.dart';

import '../provider/quic_provider.dart';
import 'records.dart';

/// A record whose header announces a body over the receiver's limit: the
/// body is not read.
class RecordTooLarge implements Exception {
  /// The header's command code and length.
  RecordTooLarge(this.command, this.length, this.limit);

  /// The command code (0 to 3).
  final int command;

  /// The body length the header announced.
  final int length;

  /// The limit it exceeds.
  final int limit;

  @override
  String toString() => 'RecordTooLarge(record of $length bytes, limit $limit)';
}

/// Reads records from the peer's direction of a [QuicStream], pulling
/// exactly the bytes of one record at a time, so that what follows stays
/// in the stack and holds back the peer's credit.
class RecordReader {
  /// A reader of [stream].
  RecordReader(this.stream);

  /// The stream read.
  final QuicStream stream;

  final Uint8List _header = Uint8List(quicRecordHeaderSize);

  /// The largest chunk asked of the provider at once while a body arrives.
  static const int maxChunk = 256 * 1024;

  /// The next record, or null at the end of the direction (FIN) between
  /// records.
  ///
  /// The header is checked before the body is read: command 3 is a
  /// [ProtocolException], a body over [limit] a [RecordTooLarge]. FIN
  /// inside a record is a [ProtocolException]. A reset fails with the
  /// provider's [QuicStreamReset] (the partial record is dropped), the end
  /// of the session with its [QuicException].
  Future<QuicRecord?> next({required int limit}) async {
    var have = 0;
    while (have < quicRecordHeaderSize) {
      final chunk = await stream.read(quicRecordHeaderSize - have);
      if (chunk == null) {
        if (have == 0) {
          return null;
        }
        throw ProtocolException('FIN inside a record header');
      }
      if (chunk.isEmpty || chunk.length > quicRecordHeaderSize - have) {
        throw StateError('the provider returned an invalid read chunk');
      }
      _header.setRange(have, have + chunk.length, chunk);
      have += chunk.length;
    }
    final header = readQuicRecordHeader(_header);
    final command = QuicRecordCommand.fromCode(quicHeaderCommand(header));
    final length = quicHeaderLength(header);
    if (command == null) {
      throw ProtocolException('record of the reserved command 3');
    }
    if (length > limit) {
      throw RecordTooLarge(command.code, length, limit);
    }
    if (length == 0) {
      return QuicRecord(command, Uint8List(0));
    }
    final first = await _read(length);
    if (first.length == length) {
      return QuicRecord(command, first);
    }
    // Allocate in proportion to bytes received. A header and one body
    // byte must not allocate an entire (possibly very large) limit.
    final body = BytesBuilder()..add(first);
    var filled = first.length;
    while (filled < length) {
      final chunk = await _read(length - filled);
      body.add(chunk);
      filled += chunk.length;
    }
    return QuicRecord(command, body.takeBytes());
  }

  /// Up to [wanted] bytes of a body; FIN is a protocol error.
  Future<Uint8List> _read(int wanted) async {
    final max = wanted < maxChunk ? wanted : maxChunk;
    final chunk = await stream.read(max);
    if (chunk == null) {
      throw ProtocolException('FIN inside a record');
    }
    if (chunk.isEmpty || chunk.length > max) {
      throw StateError('the provider returned an invalid read chunk');
    }
    return chunk;
  }

  /// Reads past a CLOSE record: completes at FIN or at a reset (the peer
  /// gave up on its direction after its close, which changes nothing).
  /// Anything else is a [ProtocolException].
  Future<void> expectEnd() async {
    try {
      while (true) {
        final chunk = await stream.read(1);
        if (chunk == null) {
          return;
        }
        if (chunk.isNotEmpty) {
          throw ProtocolException('a record after the CLOSE record');
        }
      }
    } on QuicStreamReset {
      // The direction ended all the same.
    }
  }
}
