/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// What the web provider needs of the W3C WebTransport API beyond
/// `package:web` 1.1.1, as `dart:js_interop` extensions. Every member that
/// a browser may lack is read as a property first and feature-tested at
/// run time (a function, a promise, a number), never assumed.
library;

import 'dart:async';
import 'dart:js_interop';

import 'package:web/web.dart' as web;

/// The `WebTransport` constructor, undefined where the browser has none
/// (or outside a secure context).
@JS('WebTransport')
external JSAny? get webTransportClass;

/// Members of the W3C API that `package:web` 1.1.1 does not declare.
extension WebTransportExtras on web.WebTransport {
  /// The protocol the server selected (`WT-Protocol`); absent in browsers
  /// that predate protocol negotiation.
  @JS('protocol')
  external JSAny? get protocolProperty;

  /// The promise that resolves when the session starts draining; absent in
  /// Chrome 149.
  @JS('draining')
  external JSAny? get drainingProperty;

  @JS('exportKeyingMaterial')
  external JSAny? get exportKeyingMaterialProperty;

  /// The session's keying material exporter (W3C: `exportKeyingMaterial(
  /// label, context)`, an `ArrayBuffer`); absent in Chrome 149.
  @JS('exportKeyingMaterial')
  external JSPromise<JSAny?> exportKeyingMaterial(
    JSUint8Array label,
    JSUint8Array context,
  );

  @JS('getStats')
  external JSAny? get getStatsProperty;

  /// The session's statistics (W3C `getStats`); absent in Chrome 149.
  @JS('getStats')
  external JSPromise<JSAny?> getStats();

  @JS('createSendGroup')
  external JSAny? get createSendGroupProperty;

  /// A send group (W3C `createSendGroup`); absent in Chrome 149.
  @JS('createSendGroup')
  external JSObject createSendGroup();
}

/// The `protocols` member of the options, which `package:web` 1.1.1 lacks.
extension WebTransportOptionsExtras on web.WebTransportOptions {
  @JS('protocols')
  external set protocols(JSArray<JSString> value);
}

/// The options of `createBidirectionalStream` (W3C
/// `WebTransportSendStreamOptions`).
extension type SendStreamOptions._(JSObject _) implements JSObject {
  external factory SendStreamOptions({bool waitUntilAvailable});
}

/// The send stream attributes of the W3C API (`WebTransportSendStream`),
/// which Chrome 149 does not have: its streams are plain `WritableStream`s.
extension SendStreamExtras on web.WritableStream {
  @JS('sendOrder')
  external JSAny? get sendOrderProperty;

  @JS('sendOrder')
  external set sendOrder(int value);

  @JS('sendGroup')
  external set sendGroup(JSObject? value);
}

/// `then` of a promise, which `dart:js_interop` does not expose: the
/// rejection arrives as the JS value itself.
extension PromiseThen on JSPromise<JSAny?> {
  @JS('then')
  external JSAny? _then(JSFunction onFulfilled, JSFunction onRejected);
}

/// [promise] as a future, in the zone of the caller: its value, or a
/// [JsError] carrying the rejection. The promise always has a rejection
/// handler, so that nothing is reported as unhandled.
Future<JSAny?> jsFuture(JSPromise<JSAny?> promise) {
  final completer = Completer<JSAny?>();
  promise._then(
    ((JSAny? value) => completer.complete(value)).toJS,
    ((JSAny? error) => completer.completeError(JsError(error))).toJS,
  );
  return completer.future;
}

/// Settles [promise] into nothing: for the promises whose outcome nobody
/// needs (an abort, a cancel), so that a rejection is not unhandled.
void ignorePromise(JSPromise<JSAny?> promise) {
  promise._then(_ignoreValue, _ignoreValue);
}

final JSFunction _ignoreValue = ((JSAny? _) {}).toJS;

/// The fields of an error thrown or rejected by the API (a
/// `WebTransportError`, a `DOMException`, a `TypeError`).
extension type _ErrorFields._(JSObject _) implements JSObject {
  external JSAny? get name;
  external JSAny? get message;
  external JSAny? get source;
  external JSAny? get streamErrorCode;
}

/// A rejection of the WebTransport API, read into Dart.
final class JsError implements Exception {
  /// Reads [error]: its `name`, `message`, and the `source` and
  /// `streamErrorCode` of a `WebTransportError`.
  factory JsError(JSAny? error) {
    if (error == null || !error.isA<JSObject>()) {
      return JsError._('', error?.dartify()?.toString() ?? 'undefined');
    }
    final fields = error as _ErrorFields;
    String? text(JSAny? value) => value != null && value.isA<JSString>()
        ? (value as JSString).toDart
        : null;
    final code = fields.streamErrorCode;
    return JsError._(
      text(fields.name) ?? '',
      text(fields.message) ?? '',
      source: text(fields.source),
      streamErrorCode: code != null && code.isA<JSNumber>()
          ? (code as JSNumber).toDartDouble.toInt()
          : null,
    );
  }

  JsError._(this.name, this.message, {this.source, this.streamErrorCode});

  /// The error's `name` (`WebTransportError`, `NetworkError`, ...).
  final String name;
  final String message;

  /// `stream` or `session` for a `WebTransportError`.
  final String? source;

  /// The application code of a `WebTransportError` from a stream, null
  /// when it carried none.
  final int? streamErrorCode;

  bool get isWebTransportError => name == 'WebTransportError';

  /// A `WebTransportError` about one stream: the peer's `RESET_STREAM` on
  /// a readable, its `STOP_SENDING` on a writable.
  bool get fromStream => isWebTransportError && source == 'stream';

  /// A `WebTransportError` about the session: it closed or was lost.
  bool get fromSession => isWebTransportError && source == 'session';

  @override
  String toString() =>
      '$name: $message'
      '${source == null ? '' : ' (source $source'
                '${streamErrorCode == null ? '' : ', code $streamErrorCode'})'}';
}

/// The `WebTransportError` constructor in the form of the W3C
/// specification: `new WebTransportError(message, {streamErrorCode})`.
@JS('WebTransportError')
extension type _SpecError._(JSObject _) implements JSObject {
  external factory _SpecError(String message, _ErrorInit options);
  external JSAny? get streamErrorCode;
}

/// The constructor in the form Chrome 149 has: `new WebTransportError({
/// message, streamErrorCode})`, whose code is an octet (clamped to 255).
@JS('WebTransportError')
extension type _InitError._(JSObject _) implements JSObject {
  external factory _InitError(_ErrorInit init);
  external JSAny? get streamErrorCode;
}

extension type _ErrorInit._(JSObject _) implements JSObject {
  external factory _ErrorInit({String message, int streamErrorCode});
}

/// Builds the `WebTransportError`s that carry a code to the peer (the
/// reason of `abort` on a writable, `RESET_STREAM`, and of `cancel` on a
/// readable, `STOP_SENDING`), in whichever constructor form this browser
/// has, and knows the largest code it carries.
abstract final class StreamErrors {
  static bool? _specForm;
  static int _maxCode = 0;

  /// The largest stream error code this browser carries: 2^32 - 1 by the
  /// specification, 255 in Chrome 149 (an octet); 0 where neither form of
  /// the constructor works.
  static int get maxCode {
    _probe();
    return _maxCode;
  }

  /// A `WebTransportError` with [code] and [message].
  static JSObject create(int code, String message) {
    _probe();
    final options = _ErrorInit(message: message, streamErrorCode: code);
    return _specForm == true
        ? _SpecError(message, options)
        : _InitError(options);
  }

  static void _probe() {
    if (_specForm != null) return;
    const probe = 0xFFFFFFFF;
    int? readBack(JSAny? Function() build) {
      try {
        final code = build();
        return code != null && code.isA<JSNumber>()
            ? (code as JSNumber).toDartDouble.toInt()
            : null;
      } on Object {
        return null;
      }
    }

    final spec = readBack(
      () => _SpecError(
        'probe',
        _ErrorInit(streamErrorCode: probe),
      ).streamErrorCode,
    );
    if (spec != null) {
      _specForm = true;
      _maxCode = spec == probe ? probe : spec;
      return;
    }
    _specForm = false;
    final init = readBack(
      () =>
          _InitError(_ErrorInit(message: 'probe', streamErrorCode: probe))
              .streamErrorCode,
    );
    _maxCode = init ?? 0;
  }
}
