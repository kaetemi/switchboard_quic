/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The wire format of the QUIC and WebTransport binding (wiki page
/// "Polyverse Switchboard QUIC and WebTransport Binding", sections
/// "Records", "Channels", "Control stream" and "Status codes on streams
/// and connections"): records, the OPEN and CLOSE bodies, `HELLO`, and the
/// status of a stream or connection error code.
///
/// Every integer is little endian, and the arithmetic stays within what a
/// JavaScript number holds exactly, so that the web provider runs the same
/// codecs.
library;

import 'dart:typed_data';

import 'package:switchboard/core.dart';

/// The command of a record: the top two bits of its header.
enum QuicRecordCommand {
  /// One subframe, possibly empty; on the control stream, one control
  /// message.
  data(0),

  /// The first record of the opener's direction of a stream: `u48` channel
  /// id, then the open payload.
  open(1),

  /// The last record of a direction: a status payload, possibly absent
  /// (`OK`). Followed by the end of the stream (FIN).
  close(2);

  const QuicRecordCommand(this.code);

  /// The value of the header's top two bits.
  final int code;

  /// The command of [code], or null for the reserved value 3.
  static QuicRecordCommand? fromCode(int code) => switch (code) {
    0 => data,
    1 => open,
    2 => close,
    _ => null,
  };
}

/// Bytes of a record header: a `u32`.
const int quicRecordHeaderSize = 4;

/// The largest body length a header holds: `0x3FFFFFFF`.
const int quicMaxRecordLength = 0x3FFFFFFF;

/// The smallest record limit a side may announce, and the default: the
/// largest subframe a frame mux peer with the default 64 KiB window takes
/// in one DATA frame (half the window less the 16 bytes a frame costs).
const int quicDefaultRecordLimit = 32752;

/// The channel id of the control stream's OPEN record.
const int quicControlChannelId = 0;

/// The largest channel id, `2^48 - 1`.
const int quicMaxChannelId = 0xFFFFFFFFFFFF;

/// Bytes of the channel id at the start of an OPEN record's body.
const int quicChannelIdSize = 6;

/// A record: a command and its body.
class QuicRecord {
  /// A record of [command] carrying [body].
  QuicRecord(this.command, this.body);

  /// The command.
  final QuicRecordCommand command;

  /// The body, exactly the length the header gave.
  final Uint8List body;

  /// The record on the wire: header and body.
  Uint8List encode() => encodeQuicRecord(command, body);

  @override
  String toString() => 'QuicRecord(${command.name}, ${body.length} bytes)';
}

/// The header of a record of [command] whose body is [length] bytes.
///
/// Throws [ArgumentError] for a length outside 0 to [quicMaxRecordLength].
int quicRecordHeader(QuicRecordCommand command, int length) {
  if (length < 0 || length > quicMaxRecordLength) {
    throw ArgumentError.value(
      length,
      'length',
      'a record body is 0 to $quicMaxRecordLength bytes',
    );
  }
  return command.code * 0x40000000 + length;
}

/// Writes the header of a record of [command] with a [length]-byte body at
/// [offset] of [out].
void writeQuicRecordHeader(
  Uint8List out,
  int offset,
  QuicRecordCommand command,
  int length,
) {
  ByteData.sublistView(out)
      .setUint32(offset, quicRecordHeader(command, length), Endian.little);
}

/// The command code (0 to 3) of a header read as a `u32`.
int quicHeaderCommand(int header) => header ~/ 0x40000000;

/// The body length of a header read as a `u32`.
int quicHeaderLength(int header) => header & quicMaxRecordLength;

/// Reads the `u32` header at [offset] of [bytes].
int readQuicRecordHeader(Uint8List bytes, [int offset = 0]) =>
    ByteData.sublistView(bytes).getUint32(offset, Endian.little);

/// A record of [command] carrying [body], header included.
Uint8List encodeQuicRecord(QuicRecordCommand command, List<int> body) {
  final out = Uint8List(quicRecordHeaderSize + body.length);
  writeQuicRecordHeader(out, 0, command, body.length);
  out.setRange(quicRecordHeaderSize, out.length, body);
  return out;
}

/// A DATA record carrying [subframe].
Uint8List encodeDataRecord(List<int> subframe) =>
    encodeQuicRecord(QuicRecordCommand.data, subframe);

/// An OPEN record for channel [id] carrying [openPayload].
///
/// Throws [RangeError] for an id outside `u48`.
Uint8List encodeOpenRecord(int id, List<int> openPayload) {
  RangeError.checkValueInInterval(id, 0, quicMaxChannelId, 'id');
  final out = Uint8List(
    quicRecordHeaderSize + quicChannelIdSize + openPayload.length,
  );
  writeQuicRecordHeader(
    out,
    0,
    QuicRecordCommand.open,
    quicChannelIdSize + openPayload.length,
  );
  writeU48(out, quicRecordHeaderSize, id);
  out.setRange(
    quicRecordHeaderSize + quicChannelIdSize,
    out.length,
    openPayload,
  );
  return out;
}

/// A CLOSE record carrying [status], prepared for the wire with
/// `statusForWire` (application codes refused, `CONNECTION_LOST` sent as
/// `UNAVAILABLE`, the payload kept within 1024 bytes). An `OK` without a
/// reason has no body: `00 00 00 80`.
Uint8List encodeCloseRecord(Status status) {
  final wire = statusForWire(status);
  if (wire.code == 0 && wire.reason.isEmpty) {
    return encodeQuicRecord(QuicRecordCommand.close, const []);
  }
  return encodeQuicRecord(QuicRecordCommand.close, wire.encode());
}

/// The channel id and open payload of an OPEN record's [body]; the payload
/// is a view into it.
///
/// Throws [ProtocolException] for a body shorter than the channel id.
(int, Uint8List) decodeOpenBody(Uint8List body) {
  if (body.length < quicChannelIdSize) {
    throw ProtocolException('OPEN record of ${body.length} bytes');
  }
  return (readU48(body, 0), Uint8List.sublistView(body, quicChannelIdSize));
}

/// The status of a CLOSE record's [body]: `OK` when empty.
///
/// Throws [ProtocolException] for a body of one byte. An application code
/// (which the peer must not send) reads as `UNKNOWN` (`statusFromWire`).
Status decodeCloseBody(Uint8List body) =>
    statusFromWire(decodeStatusPayload(body, 'CLOSE record'));

/// Reads a `u48` at [offset] of [bytes].
int readU48(Uint8List bytes, int offset) {
  final data = ByteData.sublistView(bytes);
  return data.getUint32(offset, Endian.little) +
      data.getUint16(offset + 4, Endian.little) * 0x100000000;
}

/// Writes [value], a `u48`, at [offset] of [bytes].
void writeU48(Uint8List bytes, int offset, int value) {
  final data = ByteData.sublistView(bytes);
  data.setUint32(offset, value % 0x100000000, Endian.little);
  data.setUint16(offset + 4, value ~/ 0x100000000, Endian.little);
}

/// The control type of `HELLO`, which belongs to this binding only.
const int quicHelloType = 0x08;

/// The `HELLO` control message: the first one in each direction of the
/// control stream.
///
/// ```
/// offset  size  field
/// 0       u32   record limit, at least 32752
/// 4       u32   channels: how many channels opened by the peer this side
///               accepts at once; 0 = no stated limit
/// 8       u8    flags: 0x01 EXPORTER
/// 9       ...   further fields, ignored
/// ```
class QuicHello {
  /// A `HELLO`.
  ///
  /// Throws [ArgumentError] for a [recordLimit] below
  /// [quicDefaultRecordLimit] or above `u32`, or [channels] outside `u32`.
  QuicHello({
    this.recordLimit = quicDefaultRecordLimit,
    this.channels = 0,
    this.exporter = false,
  }) {
    if (recordLimit < quicDefaultRecordLimit || recordLimit > 0xFFFFFFFF) {
      throw ArgumentError.value(
        recordLimit,
        'recordLimit',
        'at least $quicDefaultRecordLimit and a u32',
      );
    }
    if (channels < 0 || channels > 0xFFFFFFFF) {
      throw ArgumentError.value(channels, 'channels', 'a u32');
    }
  }

  QuicHello._decoded(this.recordLimit, this.channels, this.exporter);

  /// The `EXPORTER` flag.
  static const int flagExporter = 0x01;

  /// Bytes of the fields this version knows.
  static const int encodedLength = 9;

  /// The largest record body this side accepts on a channel's stream. A
  /// decoded value above [quicMaxRecordLength] reads as it.
  final int recordLimit;

  /// How many channels opened by the peer this side accepts at once; 0
  /// for no stated limit. Advisory: the stream limit enforces it.
  final int channels;

  /// Whether this side can compute the exporter of the connection.
  final bool exporter;

  /// The payload, after the control type.
  Uint8List encode() {
    final out = Uint8List(encodedLength);
    ByteData.sublistView(out)
      ..setUint32(0, recordLimit, Endian.little)
      ..setUint32(4, channels, Endian.little)
      ..setUint8(8, exporter ? flagExporter : 0);
    return out;
  }

  /// The control message: type [quicHelloType] and [encode].
  MuxControlMessage toControlMessage() =>
      MuxControlMessage(quicHelloType, encode());

  /// Decodes a `HELLO` payload. Unknown flags and further fields are
  /// ignored; a record limit above [quicMaxRecordLength] reads as it.
  ///
  /// Throws [ProtocolException] for a payload shorter than 9 bytes or a
  /// record limit below [quicDefaultRecordLimit].
  static QuicHello decode(Uint8List payload) {
    if (payload.length < encodedLength) {
      throw ProtocolException('HELLO of ${payload.length} bytes');
    }
    final data = ByteData.sublistView(payload);
    final limit = data.getUint32(0, Endian.little);
    if (limit < quicDefaultRecordLimit) {
      throw ProtocolException('HELLO with a record limit of $limit');
    }
    return QuicHello._decoded(
      limit > quicMaxRecordLength ? quicMaxRecordLength : limit,
      data.getUint32(4, Endian.little),
      data.getUint8(8) & flagExporter != 0,
    );
  }

  @override
  bool operator ==(Object other) =>
      other is QuicHello &&
      other.recordLimit == recordLimit &&
      other.channels == channels &&
      other.exporter == exporter;

  @override
  int get hashCode => Object.hash(recordLimit, channels, exporter);

  @override
  String toString() =>
      'QuicHello(record limit $recordLimit, channels $channels'
      '${exporter ? ', EXPORTER' : ''})';
}

/// The error code a stream reset, a `STOP_SENDING` or a connection close
/// carries for [status]: the status code itself. Only codes 0 to 255 are
/// sent: `CONNECTION_LOST` goes as `UNAVAILABLE`, as on the frame mux.
///
/// Throws [ArgumentError] for an application code (256 and above), which a
/// CLOSE or a GOAWAY never carries either.
int quicErrorCode(Status status) {
  checkMuxStatus(status);
  if (status.known == StatusCode.connectionLost) {
    return StatusCode.unavailable.code;
  }
  if (status.code > 0xFF) {
    // Reserved codes above 255 (none are defined) go as UNKNOWN.
    return StatusCode.unknown.code;
  }
  return status.code;
}

/// The status of an error code a stream reset, a `STOP_SENDING` or a
/// connection close carried: the code from 0 to 255 is that status; a
/// larger code, or none (null: a WebTransport reset without an
/// application code), reads as `UNKNOWN`, the code kept in the reason.
Status statusOfQuicErrorCode(int? code, [String reason = '']) {
  if (code == null) {
    return Status.of(
      StatusCode.unknown,
      reason.isEmpty ? 'no application error code' : reason,
    );
  }
  if (code < 0 || code > 0xFF) {
    return Status.of(
      StatusCode.unknown,
      'error code $code${reason.isEmpty ? '' : ': $reason'}',
    );
  }
  return Status(code, reason);
}
