/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The exporter of a connection and the WebTransport error code mapping
/// (wiki page "Polyverse Switchboard QUIC and WebTransport Binding",
/// sections "Exporter-bound proof", "Status codes on streams and
/// connections" and "Test vectors"): what the binding asks of a provider,
/// and the arithmetic a provider that builds the WebTransport layer itself
/// (on a raw TLS exporter and raw HTTP/3 codes) needs.
library;

import 'dart:convert';
import 'dart:typed_data';

/// Bytes of the exporter an exporter-bound `IDENT` proof signs.
const int quicExporterLength = 32;

/// The TLS exporter label of a raw QUIC connection's exporter: RFC 9266's
/// `tls-exporter` channel binding, with an empty context.
const String rawQuicExporterLabel = 'EXPORTER-Channel-Binding';

/// The application label of a WebTransport session's exporter, with an
/// empty application context.
const String webTransportIdentLabel = 'switchboard-ident';

/// The TLS exporter label of WebTransport's keying material exporter
/// (draft-ietf-webtrans-http3, "Use of Keying Material Exporters").
const String webTransportExporterLabel = 'EXPORTER-WebTransport';

/// The TLS exporter context of WebTransport's keying material exporter for
/// the session [sessionId] and the application's [label] and [context]:
/// `u64 session ID` (big endian, a plain `u64`), `len8 label`, label,
/// `len8 context`, context.
///
/// Throws [ArgumentError] for a negative session ID, or a label or context
/// over 255 bytes.
Uint8List webTransportExporterContext(
  int sessionId, {
  String label = webTransportIdentLabel,
  List<int> context = const [],
}) {
  if (sessionId < 0) {
    throw ArgumentError.value(sessionId, 'sessionId', 'not a u64');
  }
  final labelBytes = utf8.encode(label);
  if (labelBytes.length > 0xFF || context.length > 0xFF) {
    throw ArgumentError('label or context longer than 255 bytes');
  }
  final out = Uint8List(8 + 1 + labelBytes.length + 1 + context.length);
  final data = ByteData.sublistView(out);
  // Within 2^53 for JavaScript: the high word, then the low one.
  data
    ..setUint32(0, sessionId ~/ 0x100000000)
    ..setUint32(4, sessionId % 0x100000000);
  var offset = 8;
  out[offset++] = labelBytes.length;
  out.setRange(offset, offset + labelBytes.length, labelBytes);
  offset += labelBytes.length;
  out[offset++] = context.length;
  out.setRange(offset, offset + context.length, context);
  return out;
}

/// The first HTTP/3 error code of the WebTransport application error
/// codes.
const int webTransportHttp3CodeBase = 0x52e4a40fa8db;

/// The HTTP/3 error code a stack puts on the wire for the WebTransport
/// application error code [code] (a `u32`): `0x52e4a40fa8db + n +
/// floor(n / 0x1e)`, which skips HTTP/3's reserved codepoints.
int webTransportCodeToHttp3(int code) {
  RangeError.checkValueInInterval(code, 0, 0xFFFFFFFF, 'code');
  return webTransportHttp3CodeBase + code + code ~/ 0x1e;
}

/// The WebTransport application error code of the HTTP/3 error code
/// [http3], or null when it is none (outside the range, or a reserved
/// codepoint).
int? webTransportCodeFromHttp3(int http3) {
  final last = webTransportCodeToHttp3(0xFFFFFFFF);
  if (http3 < webTransportHttp3CodeBase || http3 > last) {
    return null;
  }
  final shifted = http3 - webTransportHttp3CodeBase;
  // One value in every 0x1f is a reserved codepoint, the one after the
  // code of every multiple of 0x1e less one (29, 59, ...).
  if (shifted % 0x1f == 0x1e) {
    return null;
  }
  return shifted - shifted ~/ 0x1f;
}

/// [value] as a QUIC variable-length integer (RFC 9000, section 16): 1, 2,
/// 4 or 8 bytes, the two top bits of the first byte giving the length.
///
/// Throws [RangeError] for a value outside 0 to `2^62 - 1`, and for one
/// above `2^53` where it cannot be exact (JavaScript).
Uint8List encodeQuicVarint(int value) {
  RangeError.checkValueInInterval(value, 0, 0x1FFFFFFFFFFFFF, 'value');
  if (value < 0x40) {
    return Uint8List.fromList([value]);
  }
  if (value < 0x4000) {
    return Uint8List.fromList([0x40 | (value >> 8), value & 0xFF]);
  }
  if (value < 0x40000000) {
    final out = Uint8List(4);
    ByteData.sublistView(out).setUint32(0, value);
    out[0] |= 0x80;
    return out;
  }
  final out = Uint8List(8);
  ByteData.sublistView(out)
    ..setUint32(0, value ~/ 0x100000000)
    ..setUint32(4, value % 0x100000000);
  out[0] |= 0xC0;
  return out;
}
