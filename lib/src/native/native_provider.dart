/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GLM 5.3 Flash <noreply@z.ai>
*/

/// The native stream provider: raw QUIC and WebTransport over HTTP/3, over
/// quinn through the sbq shim (native/sbq), on the Dart VM.
///
/// Every call into the shim is synchronous and returns at once; an operation
/// that cannot complete yet leaves a [Completer] behind, and the shim's event
/// for the handle (READABLE, WRITABLE, OPENED, ...) polls it again. Events
/// arrive through one `NativeCallable.listener` per isolate (the doorbell),
/// which drains the isolate's event queue with `sbq_poll`.
///
/// Reads are pull-based: data stays in quinn, holding back the peer's flow
/// control credit, until [QuicStream.read] takes it. Writes complete once
/// quinn accepted every byte, which the peer's credit bounds. While no read
/// is pending, the stream asks the shim whether the peer reset its
/// direction (`sbq_stream_poll_reset`, which arms the same READABLE event),
/// so that [QuicStream.resetReceived] completes for a paused reader too.
///
/// Raw QUIC has no session layer: [QuicSession.draining] never completes, and
/// [QuicSession.incomingUnidirectionalStreams] never delivers a stream (the
/// shim grants the peer none, `initial_max_streams_uni` 0, so a peer that
/// opens one commits a transport error).
///
/// WebTransport (`https://host:port/path`): the shim runs HTTP/3 and the
/// session (its CONNECT, its capsules, the stream headers, the mapping of
/// codes); a session is a handle the same calls take as a connection. Stream
/// and close codes are WebTransport application codes (0 to 2^32 - 1); a
/// reset or `STOP_SENDING` outside the WebTransport range reaches the
/// application without a code (null). [QuicSession.draining] completes on
/// `WT_DRAIN_SESSION` or an HTTP/3 `GOAWAY`; the peer's unidirectional
/// streams are delivered for the application to refuse.
library;

import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../provider/quic_provider.dart';
import 'sbq_bindings.g.dart';

/// The ALPN protocol of raw QUIC Switchboard connections.
const String quicAlpn = 'switchboard';

/// The ALPN protocol of HTTP/3, which the provider offers itself for
/// WebTransport.
const String h3Alpn = 'h3';

/// The largest application error code QUIC carries (a variable-length
/// integer).
const int _maxCode = (1 << 62) - 1;

/// The largest WebTransport application error code (a `u32`).
const int _maxWebTransportCode = 0xFFFFFFFF;

void _checkCode(int code, {bool webTransport = false}) {
  if (webTransport) {
    if (code < 0 || code > _maxWebTransportCode) {
      throw ArgumentError.value(code, 'code', 'must be 0 to 2^32 - 1');
    }
  } else if (code < 0 || code > _maxCode) {
    throw ArgumentError.value(code, 'code', 'must be 0 to 2^62 - 1');
  }
}

/// A certificate and its private key, both DER, with the certificate's
/// SHA-256 (what a client pins).
final class NativeCertificate {
  NativeCertificate(this.certificateDer, this.privateKeyDer)
    : sha256 = NativeQuicProvider.certificateHash(certificateDer);

  final Uint8List certificateDer;

  /// PKCS#8.
  final Uint8List privateKeyDer;
  final Uint8List sha256;
}

/// Statistics of a native session.
final class NativeQuicStats {
  const NativeQuicStats({
    required this.rtt,
    required this.congestionWindow,
    required this.congestionEvents,
    required this.lostPackets,
    required this.sentPackets,
    required this.udpTxBytes,
    required this.udpRxBytes,
  });

  final Duration rtt;
  final int congestionWindow;
  final int congestionEvents;
  final int lostPackets;
  final int sentPackets;
  final int udpTxBytes;
  final int udpRxBytes;
}

/// Raw QUIC (`quic://host:port`, ALPN `switchboard`) and WebTransport
/// (`https://host:port/path`, over HTTP/3) over quinn. One instance per
/// isolate; the shim's runtime is shared by the process.
final class NativeQuicProvider implements QuicConnector {
  factory NativeQuicProvider() => _instance ??= NativeQuicProvider._();
  NativeQuicProvider._();
  static NativeQuicProvider? _instance;

  /// The number of tokio worker threads the shim starts with. Read once per
  /// process, by the first isolate that uses the provider.
  static int workerThreads = 2;

  /// Generates a self-signed ECDSA P-256 certificate for [subject] (its
  /// common name and subject alternative name; an IP address when it parses
  /// as one), valid from five minutes ago for [validityDays] days. With the
  /// default 14 days it also suits WebTransport's `serverCertificateHashes`.
  static NativeCertificate generateSelfSigned(
    String subject, {
    int validityDays = 14,
  }) {
    _Sbq.checkLibrary();
    final name = utf8.encode(subject);
    return using((arena) {
      const cap = 4096;
      final cert = arena<Uint8>(cap);
      final key = arena<Uint8>(cap);
      final certLen = arena<Size>();
      final keyLen = arena<Size>();
      final r = sbq_generate_self_signed(
        _native(arena, name),
        name.length,
        validityDays,
        cert,
        cap,
        certLen,
        key,
        cap,
        keyLen,
      );
      if (r != SBQ_OK) throw _Sbq.failure(r, 'generateSelfSigned');
      return NativeCertificate(
        Uint8List.fromList(cert.asTypedList(certLen.value)),
        Uint8List.fromList(key.asTypedList(keyLen.value)),
      );
    });
  }

  /// SHA-256 of [der] (a certificate), the form [QuicClientConfig.serverCertificateHashes]
  /// and [QuicSession.peerCertificateHash] use.
  static Uint8List certificateHash(Uint8List der) {
    _Sbq.checkLibrary();
    final data = Uint8List.fromList(der);
    final out = Uint8List(32);
    sbq_sha256(data.address, data.length, out.address);
    return out;
  }

  /// Ends every session and listener of this isolate at once (sessions close
  /// with code 0) and releases the shim's context. The provider starts again
  /// on the next [connect] or [listen].
  static void shutdown() => _Sbq._current?.shutdown();

  /// Connects to a `quic://host:port` endpoint (raw QUIC, the ALPN tokens
  /// of [QuicClientConfig.alpn]) or an `https://host:port/path` endpoint (a
  /// WebTransport session, see [connectWebTransport]).
  @override
  Future<QuicSession> connect(Uri endpoint, QuicClientConfig config) async {
    if (endpoint.scheme == 'https') {
      return connectWebTransport(endpoint, config);
    }
    if (endpoint.scheme != 'quic') {
      throw QuicException(
        QuicExceptionKind.unsupportedScheme,
        'the native provider dials quic:// and https:// only, not '
        '${endpoint.scheme}://',
      );
    }
    if (endpoint.host.isEmpty || !endpoint.hasPort) {
      throw QuicException(
        QuicExceptionKind.unreachable,
        'a quic:// endpoint needs a host and a port: $endpoint',
      );
    }
    final rt = _Sbq.current;
    final host = utf8.encode(endpoint.host);
    final cfg = _clientConfig(config);
    final int h;
    try {
      h = using(
        (arena) => sbq_connect(
          rt.ctx,
          cfg,
          _native(arena, host),
          host.length,
          endpoint.port,
          _native(arena, host),
          host.length,
        ),
      );
    } finally {
      sbq_config_free(cfg);
    }
    if (h <= 0) throw _Sbq.failure(h, 'connect');
    final session = NativeQuicSession._(
      rt,
      h,
      isInitiator: true,
      maxIncomingStreams: config.maxStreamsBidi,
    );
    return session._connecting!.future;
  }

  /// Opens a WebTransport session to `https://host:port/path` (port 443 by
  /// default; the path with its query, never the fragment): a QUIC
  /// connection with ALPN `h3` (the provider's own: [QuicClientConfig.alpn]
  /// lists the WebTransport protocols to offer instead, `switchboard` for
  /// Switchboard), HTTP/3 over it, and the extended CONNECT. The session is
  /// established by the server's 2xx response; [QuicSession.protocol] is the
  /// protocol it selected (null when none). Another response fails the
  /// connect with [QuicExceptionKind.refused] and the status in the message.
  /// [origin] is sent as the `Origin` header (a browser always sends one; a
  /// node need not). Certificate verification is as for raw QUIC. The
  /// handshake deadline bounds the QUIC handshake and again the HTTP/3
  /// exchange. The session has its QUIC connection to itself.
  Future<QuicSession> connectWebTransport(
    Uri endpoint,
    QuicClientConfig config, {
    String? origin,
  }) async {
    if (endpoint.scheme != 'https') {
      throw QuicException(
        QuicExceptionKind.unsupportedScheme,
        'a WebTransport endpoint is https://, not ${endpoint.scheme}://',
      );
    }
    if (endpoint.host.isEmpty) {
      throw QuicException(
        QuicExceptionKind.unreachable,
        'an https:// endpoint needs a host: $endpoint',
      );
    }
    final port = endpoint.hasPort ? endpoint.port : 443;
    final hostPart = endpoint.host.contains(':')
        ? '[${endpoint.host}]'
        : endpoint.host;
    final authority = utf8.encode(port == 443 ? hostPart : '$hostPart:$port');
    final path = utf8.encode(
      '${endpoint.path.isEmpty ? '/' : endpoint.path}'
      '${endpoint.hasQuery ? '?${endpoint.query}' : ''}',
    );
    final protocols = _alpnWire(config.alpn);
    final originBytes = utf8.encode(origin ?? '');
    final rt = _Sbq.current;
    final host = utf8.encode(endpoint.host);
    final cfg = _clientConfig(config, alpn: const [h3Alpn]);
    final int h;
    try {
      h = using(
        (arena) => sbq_connect_wt(
          rt.ctx,
          cfg,
          _native(arena, host),
          host.length,
          port,
          _native(arena, host),
          host.length,
          _native(arena, authority),
          authority.length,
          _native(arena, path),
          path.length,
          _native(arena, originBytes),
          originBytes.length,
          _native(arena, protocols),
          protocols.length,
        ),
      );
    } finally {
      sbq_config_free(cfg);
    }
    if (h <= 0) {
      if (h == SBQ_ERR_ARG) {
        throw ArgumentError(
          'a WebTransport endpoint, origin and protocols are printable ASCII: '
          '${_Sbq.lastError()}',
        );
      }
      throw _Sbq.failure(h, 'connect');
    }
    final session = NativeQuicSession._(
      rt,
      h,
      isInitiator: true,
      maxIncomingStreams: config.maxStreamsBidi,
      isWebTransport: true,
    );
    return session._connecting!.future;
  }

  /// Listens on [host] (an address, `0.0.0.0` or `::` for every interface)
  /// and [port] (0 for any free port) for raw QUIC connections.
  /// [advertisedHost] is the host of [NativeQuicListener.endpoint]
  /// (default [host]). A negative duration in [config] is an
  /// [ArgumentError], as in [connect]'s configuration.
  Future<NativeQuicListener> listen(
    String host,
    int port,
    QuicServerConfig config, {
    String? advertisedHost,
  }) async {
    final rt = _Sbq.current;
    final name = utf8.encode(host);
    final cfg = _serverConfig(config);
    final int h;
    try {
      h = using(
        (arena) =>
            sbq_listen(rt.ctx, cfg, _native(arena, name), name.length, port),
      );
    } finally {
      sbq_config_free(cfg);
    }
    if (h <= 0) throw _Sbq.failure(h, 'listen');
    final endpoint = Uri(
      scheme: 'quic',
      host: advertisedHost ?? host,
      port: sbq_listener_port(h),
    );
    return NativeQuicListener._(rt, h, endpoint, config.maxStreamsBidi);
  }

  /// Listens on [host] and [port] (as [listen]) for WebTransport sessions to
  /// `https://host:port/path`: QUIC connections with ALPN `h3` (the
  /// configuration's own [QuicServerConfig.alpn] is not used), HTTP/3 over
  /// them, and each extended CONNECT a session request, answered here:
  ///
  /// * a request for another path than [path] (its query aside) is refused
  ///   with 404;
  /// * one whose `Origin` is not among [allowedOrigins] with 403 (null, the
  ///   default, allows any; a request without `Origin` comes from a client
  ///   that is not a browser, and passes);
  /// * one that offers protocols selects the first of them in its order that
  ///   is among [protocols]; one that offers protocols of which none is
  ///   served is refused with 400; one that offers none is accepted without
  ///   a protocol ([QuicSession.protocol] null);
  /// * after [NativeWebTransportListener.close], 503 (on the connections
  ///   still open; new connections are not accepted).
  ///
  /// Accepted sessions arrive on [NativeWebTransportListener.sessions]. A
  /// connection may carry up to 16 sessions; the stream limit
  /// ([QuicServerConfig.maxStreamsBidi]) is the connection's, plus one for a
  /// CONNECT stream. [QuicServerConfig.handshakeTimeout] also bounds the wait
  /// of a request for its answer, and the life of a connection without a
  /// session. The listener's endpoint is `https://advertisedHost:port/path`.
  Future<NativeWebTransportListener> listenWebTransport(
    String host,
    int port,
    QuicServerConfig config, {
    required String path,
    Iterable<String>? allowedOrigins,
    List<String> protocols = const ['switchboard'],
    String? advertisedHost,
  }) async {
    if (!path.startsWith('/')) {
      throw ArgumentError.value(path, 'path', 'must start with /');
    }
    final rt = _Sbq.current;
    final name = utf8.encode(host);
    final cfg = _serverConfig(config, alpn: const [h3Alpn]);
    final int h;
    try {
      h = using(
        (arena) =>
            sbq_listen(rt.ctx, cfg, _native(arena, name), name.length, port),
      );
    } finally {
      sbq_config_free(cfg);
    }
    if (h <= 0) throw _Sbq.failure(h, 'listen');
    final endpoint = Uri(
      scheme: 'https',
      host: advertisedHost ?? host,
      port: sbq_listener_port(h),
      path: path,
    );
    return NativeWebTransportListener._(
      rt,
      h,
      endpoint,
      config.maxStreamsBidi,
      path: path,
      allowedOrigins: allowedOrigins?.toSet(),
      protocols: List.unmodifiable(protocols),
    );
  }

  static int _clientConfig(QuicClientConfig c, {List<String>? alpn}) {
    final idle = _millis(c.idleTimeout, 'idleTimeout');
    final keepAlive = _millis(c.keepAlive, 'keepAlive');
    final handshake = _millis(c.handshakeTimeout, 'handshakeTimeout');
    final alpnWire = _alpnWire(alpn ?? c.alpn);
    final pins = BytesBuilder(copy: false);
    for (final h in c.serverCertificateHashes) {
      if (h.length != 32) {
        throw ArgumentError('a certificate hash is 32 bytes (SHA-256)');
      }
      pins.add(h);
    }
    final verify = c.serverCertificateHashes.isNotEmpty
        ? SBQ_VERIFY_PINNED
        : c.verifyCertificate
        ? SBQ_VERIFY_PLATFORM
        : SBQ_VERIFY_NONE;
    final pinBytes = pins.takeBytes();
    final r = using(
      (arena) => sbq_client_config(
        _native(arena, alpnWire),
        alpnWire.length,
        verify,
        _native(arena, pinBytes),
        c.serverCertificateHashes.length,
        c.maxStreamsBidi,
        c.streamReceiveWindow,
        c.connectionReceiveWindow,
        idle,
        keepAlive,
        handshake,
      ),
    );
    if (r <= 0) throw _Sbq.failure(r, 'client configuration');
    return r;
  }

  static int _serverConfig(QuicServerConfig c, {List<String>? alpn}) {
    final idle = _millis(c.idleTimeout, 'idleTimeout');
    final keepAlive = _millis(c.keepAlive, 'keepAlive');
    final handshake = _millis(c.handshakeTimeout, 'handshakeTimeout');
    final alpnWire = _alpnWire(alpn ?? c.alpn);
    final r = using(
      (arena) => sbq_server_config(
        _native(arena, alpnWire),
        alpnWire.length,
        _native(arena, c.certificateDer),
        c.certificateDer.length,
        _native(arena, c.privateKeyDer),
        c.privateKeyDer.length,
        c.maxStreamsBidi,
        c.streamReceiveWindow,
        c.connectionReceiveWindow,
        idle,
        keepAlive,
        handshake,
      ),
    );
    if (r <= 0) throw _Sbq.failure(r, 'server configuration');
    return r;
  }

  /// A duration of a configuration in whole milliseconds for the shim, where
  /// 0 is none: rounded up, so that a positive one stays positive. A
  /// negative one, which would reach the shim as a huge unsigned value, is
  /// an [ArgumentError].
  static int _millis(Duration d, String name) {
    if (d.isNegative) {
      throw ArgumentError.value(d, name, 'must not be negative');
    }
    final ms = d.inMilliseconds;
    return d.inMicroseconds.remainder(1000) == 0 ? ms : ms + 1;
  }

  static Uint8List _alpnWire(List<String> tokens) {
    final b = BytesBuilder();
    for (final t in tokens) {
      final bytes = utf8.encode(t);
      if (bytes.isEmpty || bytes.length > 255) {
        throw ArgumentError.value(t, 'alpn', 'an ALPN token is 1 to 255 bytes');
      }
      b
        ..addByte(bytes.length)
        ..add(bytes);
    }
    return b.takeBytes();
  }
}

/// What the shim tells a listener.
abstract interface class _ListenerEvents {
  /// A raw QUIC connection completed its handshake.
  void _accepted(int conn);

  /// A WebTransport request arrived (the session handle, pending, and the
  /// draft version the client signalled).
  void _request(int session, int version);

  void _close();
}

/// Accepts raw QUIC sessions on one UDP port.
final class NativeQuicListener implements QuicListener, _ListenerEvents {
  NativeQuicListener._(
    this._rt,
    this._handle,
    this.endpoint,
    this._maxIncoming,
  ) {
    _rt.listeners[_handle] = this;
    _rt.retain();
  }

  final _Sbq _rt;
  final int _handle;
  final int _maxIncoming;
  final _sessions = StreamController<QuicSession>();
  bool _closed = false;

  @override
  final Uri endpoint;

  /// The UDP port the listener is bound to.
  int get port => endpoint.port;

  @override
  Stream<QuicSession> get sessions => _sessions.stream;

  @override
  void _accepted(int conn) {
    _sessions.add(
      NativeQuicSession._(
        _rt,
        conn,
        isInitiator: false,
        maxIncomingStreams: _maxIncoming,
      ),
    );
  }

  /// A raw listener serves no WebTransport (its configuration offered `h3`
  /// anyway): 404.
  @override
  void _request(int session, int version) {
    sbq_wt_reject(session, 404);
    sbq_conn_release(session);
  }

  @override
  Future<void> close() async => _close();

  @override
  void _close() {
    if (_closed) return;
    _closed = true;
    sbq_listener_close(_handle);
    _rt.listeners.remove(_handle);
    unawaited(_sessions.close());
    _rt.release();
  }
}

/// Accepts WebTransport sessions on one UDP port and one path
/// ([NativeQuicProvider.listenWebTransport]).
final class NativeWebTransportListener
    implements QuicListener, _ListenerEvents {
  NativeWebTransportListener._(
    this._rt,
    this._handle,
    this.endpoint,
    this._maxIncoming, {
    required this.path,
    required this.allowedOrigins,
    required this.protocols,
  }) {
    _rt.listeners[_handle] = this;
    _rt.retain();
  }

  final _Sbq _rt;
  final int _handle;
  final int _maxIncoming;
  final _sessions = StreamController<QuicSession>();
  bool _closed = false;

  @override
  final Uri endpoint;

  /// The path sessions are accepted on.
  final String path;

  /// The origins a browser's session may come from; null for any.
  final Set<String>? allowedOrigins;

  /// The protocols this listener serves, the first it shares with a client
  /// selected (in the client's order).
  final List<String> protocols;

  /// The UDP port the listener is bound to.
  int get port => endpoint.port;

  @override
  Stream<QuicSession> get sessions => _sessions.stream;

  /// Requests answered so far by status (200 for an accepted one), for logs
  /// and tests.
  final Map<int, int> answered = {};

  @override
  void _accepted(int conn) {
    // Not WebTransport: nothing this listener serves.
    sbq_conn_close(conn, 0, nullptr, 0);
    sbq_conn_release(conn);
  }

  @override
  void _request(int session, int version) {
    final request = _WebTransportRequest.read(session, version);
    final offered = request.protocols;
    String? selected;
    var status = 0;
    if (_closed) {
      status = 503;
    } else if (request.path.split('?').first != path) {
      status = 404;
    } else if (request.origin != null &&
        allowedOrigins != null &&
        !allowedOrigins!.contains(request.origin)) {
      status = 403;
    } else if (offered.isNotEmpty) {
      for (final p in offered) {
        if (protocols.contains(p)) {
          selected = p;
          break;
        }
      }
      if (selected == null) status = 400;
    }
    if (status != 0) {
      answered[status] = (answered[status] ?? 0) + 1;
      sbq_wt_reject(session, status);
      sbq_conn_release(session);
      return;
    }
    final p = utf8.encode(selected ?? '');
    if (sbq_wt_accept(session, p.address, p.length) != SBQ_OK) {
      // Refused meanwhile for lack of an answer.
      sbq_conn_release(session);
      return;
    }
    answered[200] = (answered[200] ?? 0) + 1;
    _sessions.add(
      NativeQuicSession._(
        _rt,
        session,
        isInitiator: false,
        maxIncomingStreams: _maxIncoming,
        isWebTransport: true,
        request: request,
      ),
    );
  }

  /// Stops accepting: new connections are refused, and requests on the
  /// connections still open are answered 503. Open sessions are left to
  /// their owners.
  @override
  Future<void> close() async => _close();

  @override
  void _close() {
    if (_closed) return;
    _closed = true;
    sbq_listener_close(_handle);
    _rt.listeners.remove(_handle);
    unawaited(_sessions.close());
    _rt.release();
  }
}

/// The request of a WebTransport session a listener accepted.
final class _WebTransportRequest {
  _WebTransportRequest(
    this.authority,
    this.path,
    this.origin,
    this.protocols,
    this.draft,
  );

  factory _WebTransportRequest.read(int session, int draft) {
    String? field(int f) =>
        _Sbq.text((b) => sbq_wt_request(session, f, b.address, b.length));
    final wire = utf8.encode(field(SBQ_WT_PROTOCOLS) ?? '');
    final protocols = <String>[];
    for (var i = 0; i < wire.length;) {
      final n = wire[i];
      protocols.add(utf8.decode(wire.sublist(i + 1, i + 1 + n)));
      i += 1 + n;
    }
    return _WebTransportRequest(
      field(SBQ_WT_AUTHORITY) ?? '',
      field(SBQ_WT_PATH) ?? '',
      field(SBQ_WT_ORIGIN),
      protocols,
      draft,
    );
  }

  final String authority;
  final String path;
  final String? origin;
  final List<String> protocols;
  final int draft;
}

/// One raw QUIC connection or WebTransport session.
final class NativeQuicSession implements QuicSession {
  NativeQuicSession._(
    this._rt,
    this._handle, {
    required this.isInitiator,
    required int maxIncomingStreams,
    this.isWebTransport = false,
    this._request,
  }) : _maxIncoming = maxIncomingStreams {
    _rt.sessions[_handle] = this;
    _rt.retain();
    if (isInitiator) {
      _connecting = Completer<QuicSession>();
    } else {
      _established();
    }
  }

  final _Sbq _rt;
  final int _handle;
  Completer<QuicSession>? _connecting;
  String? _protocol;
  String _remote = '';
  Uint8List? _peerHash;
  int _maxIncoming;
  final _incoming = StreamController<QuicStream>();
  final _unidirectional = StreamController<QuicReceiveStream>();
  final _done = Completer<QuicSessionEnd>();
  final _opens = Queue<Completer<QuicStream>>();
  final _spare = Queue<NativeQuicStream>();
  final _streams = <NativeQuicStream>{};
  final _receiveStreams = <NativeQuicReceiveStream>{};
  final _draining = Completer<void>();
  final _WebTransportRequest? _request;
  QuicSessionEnd? _end;
  QuicException? _endError;
  bool _closeSent = false;

  @override
  final bool isInitiator;

  /// Whether this is a WebTransport session rather than a raw QUIC
  /// connection.
  final bool isWebTransport;

  /// The `:path` of an accepted WebTransport session's request (null on
  /// clients and raw QUIC).
  String? get requestPath => _request?.path;

  /// The `Origin` of an accepted WebTransport session's request (null when
  /// it had none, on clients and raw QUIC).
  String? get requestOrigin => _request?.origin;

  /// The `:authority` of an accepted WebTransport session's request.
  String? get requestAuthority => _request?.authority;

  /// The protocols an accepted WebTransport session's client offered.
  List<String>? get requestProtocols => _request?.protocols;

  /// The WebTransport draft an accepted session's client signalled: 2 (the
  /// `sec-webtransport-http3-draft02` header or draft-02 settings alone,
  /// what Chrome sends) or 7 (draft-07 settings). Null on clients and raw
  /// QUIC.
  int? get requestDraft => _request?.draft;

  @override
  String? get protocol => _protocol;

  @override
  String get remote => _remote;

  @override
  Uint8List? get peerCertificateHash => _peerHash;

  @override
  int? get maxIncomingStreams => _maxIncoming;

  /// Changes how many streams the peer may have open at once (`MAX_STREAMS`).
  /// Lowering it takes effect as the peer's streams end.
  void setMaxIncomingStreams(int count) {
    if (count < 0) {
      throw ArgumentError.value(count, 'count', 'must not be negative');
    }
    if (_end != null) return;
    final r = sbq_conn_set_max_bidi(_handle, count);
    if (r != SBQ_OK) throw _Sbq.failure(r, 'setMaxIncomingStreams');
    _maxIncoming = count;
  }

  /// Statistics of the connection; null once it has ended.
  NativeQuicStats? get stats {
    if (_end != null) return null;
    return using((arena) {
      final s = arena<SbqStats>();
      if (sbq_conn_stats(_handle, s) != SBQ_OK) return null;
      final v = s.ref;
      return NativeQuicStats(
        rtt: Duration(microseconds: v.rtt_us),
        congestionWindow: v.cwnd,
        congestionEvents: v.congestion_events,
        lostPackets: v.lost_packets,
        sentPackets: v.sent_packets,
        udpTxBytes: v.udp_tx_bytes,
        udpRxBytes: v.udp_rx_bytes,
      );
    });
  }

  @override
  Stream<QuicStream> get incomingStreams => _incoming.stream;

  /// Raw QUIC: never delivers a stream; raw QUIC as the binding page
  /// configures it grants the peer no unidirectional streams
  /// (`initial_max_streams_uni` 0), so quinn has none to accept; a peer that
  /// opens one anyway commits a transport error (`STREAM_LIMIT_ERROR`), which
  /// ends the session. WebTransport: the session's unidirectional streams
  /// (their stream header stripped), for the application to stop. Done when
  /// the session ends.
  @override
  Stream<QuicReceiveStream> get incomingUnidirectionalStreams =>
      _unidirectional.stream;

  /// Raw QUIC: never completes; raw QUIC has no draining signal (no HTTP/3
  /// `GOAWAY`, no `WT_DRAIN_SESSION`), and the binding's `GOAWAY` travels on
  /// its control stream. WebTransport: completes on the peer's
  /// `WT_DRAIN_SESSION`, or an HTTP/3 `GOAWAY` on the session's connection.
  @override
  Future<void> get draining =>
      isWebTransport ? _draining.future : _neverDraining;

  /// Asks the peer to drain a WebTransport session (`WT_DRAIN_SESSION`, at
  /// most once; its [draining] completes). Nothing on raw QUIC, which has no
  /// such signal, nor once the session has ended.
  void drain() {
    if (!isWebTransport || _end != null || _connecting != null) return;
    sbq_wt_drain(_handle);
  }

  static final Future<void> _neverDraining = Completer<void>().future;

  @override
  Future<QuicSessionEnd> get done => _done.future;

  @override
  Future<QuicStream> openStream() {
    final error = _endError;
    if (error != null) return Future.error(error);
    if (_spare.isNotEmpty) return Future.value(_spare.removeFirst());
    final r = sbq_stream_open(_handle);
    if (r > 0) {
      final stream = NativeQuicStream._(this, r);
      if (_opens.isEmpty) return Future.value(stream);
      // Earlier calls are waiting: the stream goes to the first of them, and
      // this call waits in turn (for the OPENED of the first call's request).
      _opens.removeFirst().complete(stream);
    } else if (r < 0) {
      return Future.error(
        r == SBQ_ERR_CONNECTION
            ? _sessionEnded()
            : _Sbq.failure(r, 'openStream'),
      );
    }
    final c = Completer<QuicStream>();
    _opens.add(c);
    return c.future;
  }

  @override
  Future<Uint8List?> exportKeyingMaterial(
    String label,
    Uint8List context,
    int length,
  ) async {
    final error = _endError;
    if (error != null) throw error;
    if (length <= 0) throw ArgumentError.value(length, 'length');
    final l = utf8.encode(label);
    final ctx = Uint8List.fromList(context);
    final out = Uint8List(length);
    final r = sbq_conn_exporter(
      _handle,
      l.address,
      l.length,
      ctx.address,
      ctx.length,
      out.address,
      length,
    );
    if (r == SBQ_OK) return out;
    if (r == SBQ_ERR_STATE) return null;
    if (r == SBQ_ERR_ARG) {
      throw ArgumentError.value(length, 'length', _Sbq.lastError());
    }
    throw _Sbq.failure(r, 'exportKeyingMaterial');
  }

  /// Closes the session with [code] and [reason] (at most 1024 bytes of
  /// UTF-8). Raw QUIC: `CONNECTION_CLOSE` with the code (0 to 2^62 - 1).
  /// WebTransport: `WT_CLOSE_SESSION` with the code (0 to 2^32 - 1) and the
  /// reason, then FIN on the CONNECT stream; the shim closes the QUIC
  /// connection once the peer has closed the CONNECT stream in turn, or
  /// after a bounded wait.
  @override
  Future<void> close(int code, String reason) {
    _checkCode(code, webTransport: isWebTransport);
    if (_end == null && !_closeSent) {
      _closeSent = true;
      final r = _truncateUtf8(utf8.encode(reason), 1024);
      sbq_conn_close(_handle, code, r.address, r.length);
    }
    return _done.future.then((_) {});
  }

  QuicException _sessionEnded() => _endError ?? _endedError(null);

  static QuicException _endedError(QuicSessionEnd? end) => QuicException(
    QuicExceptionKind.sessionEnded,
    end == null
        ? 'the session has ended'
        : end.lost
        ? 'the session was lost: ${end.reason}'
        : 'the session was closed with ${end.code}'
              '${end.byPeer ? ' by the peer' : ''}: ${end.reason}',
  );

  void _established() {
    _protocol = _Sbq.text(
      (b) => sbq_conn_protocol(_handle, b.address, b.length),
    );
    // A WebTransport session without a selected protocol.
    if (_protocol == '') _protocol = null;
    _remote =
        _Sbq.text((b) => sbq_conn_remote(_handle, b.address, b.length)) ?? '';
    if (isInitiator) {
      final h = Uint8List(32);
      if (sbq_conn_peer_cert_sha256(_handle, h.address) == SBQ_OK) {
        _peerHash = h;
      }
    }
  }

  void _connected() {
    final c = _connecting;
    if (c == null || _end != null) return;
    _connecting = null;
    _established();
    c.complete(this);
  }

  void _peerStream(int h) {
    final stream = NativeQuicStream._(this, h);
    _incoming.add(stream);
  }

  void _peerUniStream(int h) {
    final stream = NativeQuicReceiveStream._(this, h);
    _receiveStreams.add(stream);
    _unidirectional.add(stream);
  }

  void _drainSignal() {
    if (!_draining.isCompleted && _end == null) _draining.complete();
  }

  void _opened(int h) {
    final stream = NativeQuicStream._(this, h);
    if (_opens.isNotEmpty) {
      _opens.removeFirst().complete(stream);
    } else {
      _spare.add(stream);
    }
  }

  /// The CLOSED event (or a local shutdown): ends everything and releases
  /// the handles.
  void _ended(int kind, int code, {String? reason}) {
    if (_end != null) return;
    final why =
        reason ??
        _Sbq.text((b) => sbq_conn_close_reason(_handle, b.address, b.length)) ??
        '';
    final end = switch (kind) {
      SBQ_CLOSE_APP_REMOTE => QuicSessionEnd.closed(code, why, byPeer: true),
      SBQ_CLOSE_APP_LOCAL => QuicSessionEnd.closed(code, why, byPeer: false),
      _ => QuicSessionEnd.lost(why.isEmpty ? 'connection lost' : why),
    };
    _end = end;
    final error = _endError = _endedError(end);
    final connecting = _connecting;
    if (connecting != null) {
      _connecting = null;
      connecting.completeError(_connectError(kind, why));
    }
    while (_opens.isNotEmpty) {
      _opens.removeFirst()
        ..future.ignore()
        ..completeError(error);
    }
    for (final s in [..._streams, ..._spare]) {
      s._sessionEnded(error);
    }
    for (final s in [..._receiveStreams]) {
      s._release();
    }
    _spare.clear();
    unawaited(_incoming.close());
    unawaited(_unidirectional.close());
    sbq_conn_release(_handle);
    _rt.sessions.remove(_handle);
    _done.complete(end);
    _rt.release();
  }

  static QuicException _connectError(int kind, String reason) => switch (kind) {
    SBQ_CLOSE_CERT_REJECTED => QuicException(
      QuicExceptionKind.certificateRejected,
      'the server certificate was rejected: $reason',
    ),
    SBQ_CLOSE_UNREACHABLE || SBQ_CLOSE_TIMED_OUT => QuicException(
      QuicExceptionKind.unreachable,
      'unreachable: $reason',
    ),
    SBQ_CLOSE_APP_LOCAL => QuicException(
      QuicExceptionKind.sessionEnded,
      'the connection attempt was abandoned',
    ),
    SBQ_CLOSE_REFUSED => QuicException(
      QuicExceptionKind.refused,
      'the server refused the session: $reason',
    ),
    _ => QuicException(
      QuicExceptionKind.handshakeFailed,
      'the handshake failed: $reason',
    ),
  };
}

/// The receive direction of a peer's unidirectional WebTransport stream.
final class NativeQuicReceiveStream implements QuicReceiveStream {
  NativeQuicReceiveStream._(this._session, this._handle);

  final NativeQuicSession _session;
  final int _handle;
  bool _released = false;

  /// Stops the direction with the WebTransport application [code] (0 to
  /// 2^32 - 1) and forgets the stream. Idempotent, also after the session
  /// ended.
  @override
  void stop(int code) {
    _checkCode(code, webTransport: true);
    if (_released) return;
    sbq_stream_stop(_handle, code);
    _release();
  }

  void _release() {
    if (_released) return;
    _released = true;
    sbq_stream_release(_handle);
    _session._receiveStreams.remove(this);
  }
}

/// One write, or the finish, queued on a stream.
final class _Write {
  _Write(this.bytes) : finish = false;
  _Write.fin() : bytes = Uint8List(0), finish = true;

  final Uint8List bytes;
  final bool finish;
  int offset = 0;
  final done = Completer<void>();

  void fail(Object error) {
    done
      ..future.ignore()
      ..completeError(error);
  }
}

/// One bidirectional stream of a [NativeQuicSession].
final class NativeQuicStream implements QuicStream {
  NativeQuicStream._(this._session, this._handle) {
    _session._rt.streams[_handle] = this;
    _session._streams.add(this);
    _reset.future.ignore();
    _scheduleResetCheck();
  }

  final NativeQuicSession _session;
  final int _handle;
  _Sbq get _rt => _session._rt;

  // Receive direction.
  Completer<Uint8List?>? _read;
  int _readMax = 0;
  bool _fin = false;
  Object? _recvFailure;
  bool _recvEnded = false;
  final _reset = Completer<int?>();
  // No reset can be observed any more (FIN, a local stop, the end).
  bool _resetSettled = false;
  bool _resetCheckScheduled = false;

  // Send direction.
  final _writes = Queue<_Write>();
  bool _awaitingWritable = false;
  Future<void>? _finishing;
  bool _resetSent = false;
  bool _peerStop = false;
  Object? _sendFailure;
  bool _sendEnded = false;
  final _stopped = Completer<int?>();
  bool _released = false;

  static const Object _blocked = Object();

  @override
  Future<int?> get stopped => _stopped.future;

  /// Completes with the peer's reset code, whether a read is pending or not
  /// (a raw QUIC reset always carries one; a WebTransport one carries none,
  /// null, when its code is outside the WebTransport range); fails with
  /// `sessionEnded` when the session ends first; stays pending after FIN or
  /// a local [stop].
  @override
  Future<int?> get resetReceived => _reset.future;

  @override
  set priority(int value) {
    if (!_released && !_sendEnded) {
      sbq_stream_set_priority(_handle, quinnPriority(value));
    }
  }

  /// quinn's send priority for a priority class of the contract. quinn's
  /// levels are strict, and the contract wants class 2 (the control stream)
  /// strictly first but classes 1 (ordinary) and 0 (bulk) never starving
  /// each other: 1 and 0 share quinn's level 0 (a new stream's), where quinn
  /// sends their streams round robin; a class `c` above 1 is level `c - 1`,
  /// so 2 is level 1; a negative class is the level of the same value.
  static int quinnPriority(int priorityClass) =>
      (priorityClass > 0 ? priorityClass - 1 : priorityClass).clamp(
        -0x80000000,
        0x7FFFFFFF,
      );

  @override
  Future<Uint8List?> read(int max) {
    if (max <= 0) throw ArgumentError.value(max, 'max');
    if (_read != null) throw StateError('a read is pending on this stream');
    final o = _pollRead(max);
    if (identical(o, _blocked)) {
      _readMax = max;
      return (_read = Completer<Uint8List?>()).future;
    }
    if (o is Uint8List) _scheduleResetCheck();
    if (o == null || o is Uint8List) return Future.value(o as Uint8List?);
    return Future.error(o);
  }

  /// One read from the shim: the bytes, null at FIN, [_blocked], or the
  /// error to report.
  Object? _pollRead(int max) {
    final failure = _recvFailure;
    if (failure != null) return failure;
    if (_fin) return null;
    final scratch = _rt.scratch;
    final n = sbq_stream_read(
      _handle,
      scratch.address,
      math.min(max, scratch.length),
    );
    if (n > 0) return scratch.sublist(0, n);
    if (n == SBQ_WOULD_BLOCK) return _blocked;
    if (n == SBQ_FIN) {
      _fin = true;
      _resetSettled = true;
      _endRecv();
      return null;
    }
    if (n <= -SBQ_CODE_BASE || n == SBQ_NO_CODE) {
      final code = n == SBQ_NO_CODE ? null : -n - SBQ_CODE_BASE;
      _recvFailure = QuicStreamReset(code);
      _resetSeen(code);
      _endRecv();
      return _recvFailure;
    }
    if (n == SBQ_ERR_CONNECTION) return _session._sessionEnded();
    return _Sbq.failure(n, 'read');
  }

  void _readable() {
    final c = _read;
    if (c == null) {
      // Data, FIN or a reset arrived while nobody reads.
      _checkReset();
      return;
    }
    final o = _pollRead(_readMax);
    if (identical(o, _blocked)) return;
    _read = null;
    if (o is Uint8List) _scheduleResetCheck();
    if (o == null || o is Uint8List) {
      c.complete(o as Uint8List?);
    } else {
      c.completeError(o);
    }
  }

  /// Checks for a reset once the reader has had its turn: a reader that
  /// reads on at once observes the reset with its read instead.
  void _scheduleResetCheck() {
    if (_resetCheckScheduled || _resetSettled || _reset.isCompleted) return;
    _resetCheckScheduled = true;
    scheduleMicrotask(() {
      _resetCheckScheduled = false;
      _checkReset();
    });
  }

  /// While no read is pending: asks the shim whether the peer reset its
  /// direction, which arms READABLE for the next change when it did not.
  void _checkReset() {
    if (_read != null ||
        _released ||
        _recvEnded ||
        _resetSettled ||
        _reset.isCompleted) {
      return;
    }
    final r = sbq_stream_poll_reset(_handle);
    if (r == SBQ_WOULD_BLOCK) return;
    if (r <= -SBQ_CODE_BASE || r == SBQ_NO_CODE) {
      final code = r == SBQ_NO_CODE ? null : -r - SBQ_CODE_BASE;
      _recvFailure = QuicStreamReset(code);
      _resetSeen(code);
      _endRecv();
      return;
    }
    // FIN behind the unread data, stopped here, or the session is ending
    // (its CLOSED event fails what waits).
    _resetSettled = true;
  }

  void _resetSeen(int? code) {
    _resetSettled = true;
    if (!_reset.isCompleted) _reset.complete(code);
  }

  @override
  Future<void> write(Uint8List bytes) {
    final failure = _sendFailure;
    if (failure != null) return Future.error(failure);
    if (_finishing != null || _resetSent) {
      return Future.error(StateError('the stream was finished or reset'));
    }
    final w = _Write(bytes);
    _writes.add(w);
    _pump();
    return w.done.future;
  }

  @override
  Future<void> finish() {
    final f = _finishing;
    if (f != null) return f;
    final failure = _sendFailure;
    if (failure != null) return Future.error(failure);
    if (_resetSent) return Future.error(StateError('the stream was reset'));
    final w = _Write.fin();
    _writes.add(w);
    _pump();
    return _finishing = w.done.future;
  }

  void _pump() {
    if (_awaitingWritable) return;
    while (_writes.isNotEmpty) {
      final w = _writes.first;
      if (w.finish) {
        final r = sbq_stream_finish(_handle);
        if (r == SBQ_RETRY) {
          // The stream header of a WebTransport stream waits for credit.
          _awaitingWritable = true;
          return;
        }
        if (r != SBQ_OK) return _sendError(r);
        _writes.removeFirst();
        w.done.complete();
        continue;
      }
      final remaining = w.bytes.length - w.offset;
      if (remaining == 0) {
        _writes.removeFirst();
        w.done.complete();
        continue;
      }
      final n = w.offset == 0
          ? sbq_stream_write(_handle, w.bytes.address, remaining)
          : sbq_stream_write(
              _handle,
              Uint8List.sublistView(w.bytes, w.offset).address,
              remaining,
            );
      if (n > 0) {
        w.offset += n;
      } else if (n == SBQ_WOULD_BLOCK) {
        _awaitingWritable = true;
        return;
      } else {
        return _sendError(n);
      }
    }
  }

  void _writable() {
    if (!_awaitingWritable) return;
    _awaitingWritable = false;
    _pump();
  }

  void _sendError(int r) {
    if (r <= -SBQ_CODE_BASE) return _peerStopped(-r - SBQ_CODE_BASE);
    if (r == SBQ_NO_CODE) return _peerStopped(null);
    _failWrites(
      r == SBQ_ERR_CONNECTION
          ? _session._sessionEnded()
          : _Sbq.failure(r, 'write'),
    );
  }

  void _failWrites(Object error) {
    _awaitingWritable = false;
    while (_writes.isNotEmpty) {
      _writes.removeFirst().fail(error);
    }
  }

  @override
  void reset(int code) {
    _checkCode(code, webTransport: _session.isWebTransport);
    if (_released || _resetSent || _sendFailure != null) return;
    _resetSent = true;
    sbq_stream_reset(_handle, code);
    _failWrites(StateError('the stream was reset'));
    if (!_stopped.isCompleted) _stopped.complete(null);
    _endSend();
  }

  @override
  void stop(int code) {
    _checkCode(code, webTransport: _session.isWebTransport);
    if (_released || _recvEnded) return;
    _resetSettled = true;
    sbq_stream_stop(_handle, code);
    final failure = _recvFailure = QuicStreamReset(code);
    final c = _read;
    if (c != null) {
      _read = null;
      c.completeError(failure);
    }
    _endRecv();
  }

  void _peerStopped(int? code) {
    if (_peerStop || _sendEnded) return;
    _peerStop = true;
    final failure = _sendFailure = QuicStreamStopped(code);
    _failWrites(failure);
    if (!_stopped.isCompleted) {
      if (code == null) {
        // Not to be read as an acknowledgement.
        _stopped
          ..future.ignore()
          ..completeError(failure);
      } else {
        _stopped.complete(code);
      }
    }
    _endSend();
  }

  void _acked() {
    if (!_stopped.isCompleted) _stopped.complete(null);
    _endSend();
  }

  void _sessionEnded(QuicException error) {
    _sendFailure ??= error;
    _recvFailure ??= error;
    final c = _read;
    if (c != null) {
      _read = null;
      c.completeError(error);
    }
    _failWrites(error);
    if (!_stopped.isCompleted) {
      _stopped
        ..future.ignore()
        ..completeError(error);
    }
    _resetSettled = true;
    if (!_reset.isCompleted) _reset.completeError(error);
    _recvEnded = true;
    _sendEnded = true;
    _release();
  }

  void _endRecv() {
    _recvEnded = true;
    if (_sendEnded) _release();
  }

  void _endSend() {
    _sendEnded = true;
    if (_recvEnded) _release();
  }

  void _release() {
    if (_released) return;
    _released = true;
    sbq_stream_release(_handle);
    _rt.streams.remove(_handle);
    _session._streams.remove(this);
  }
}

/// The shim's context of this isolate: the doorbell, the event buffer, and
/// the handles of the live objects. Started on first use, shut down once no
/// listener or session is left (so that the isolate can exit and no doorbell
/// rings for it afterwards).
final class _Sbq {
  _Sbq._(this.ctx, this._bell, this._events);

  static const int _batch = 256;
  static const int _readChunk = 256 * 1024;

  final int ctx;
  final NativeCallable<Void Function(Uint64)> _bell;
  final Pointer<SbqEvent> _events;
  final Uint8List scratch = Uint8List(_readChunk);
  final sessions = <int, NativeQuicSession>{};
  final streams = <int, NativeQuicStream>{};
  final listeners = <int, _ListenerEvents>{};
  int _live = 0;
  bool _down = false;

  static _Sbq? _current;
  static bool _checked = false;

  static _Sbq get current => _current ??= _start();

  /// Throws if the native library cannot be resolved or has another ABI.
  static void checkLibrary() {
    if (_checked) return;
    int version;
    try {
      version = sbq_abi_version();
    } on ArgumentError catch (e) {
      // No code asset: a program compiled with `dart compile exe`, which does
      // not run build hooks. The @Native lookup falls back to the process,
      // so a library loaded into its global namespace serves as well.
      final loaded = _loadIntoProcess();
      if (loaded == null) {
        throw QuicException(
          QuicExceptionKind.internal,
          'the native library of switchboard_quic is not available '
          '(${e.message}); build with `dart build cli`, or set SBQ_LIBRARY '
          'to the path of the library (see native/README.md)',
        );
      }
      version = sbq_abi_version();
    }
    if (version != SBQ_ABI_VERSION) {
      throw QuicException(
        QuicExceptionKind.internal,
        'the native library has ABI $version, this package expects '
        '$SBQ_ABI_VERSION',
      );
    }
    _checked = true;
  }

  /// Loads the shim into the process's global symbol namespace: the file
  /// named by the environment variable SBQ_LIBRARY, else the library next to
  /// the executable or in `../lib` (the `dart build cli` layout). Returns the
  /// path loaded, or null.
  static String? _loadIntoProcess() {
    final name = Platform.isWindows
        ? 'sbq.dll'
        : Platform.isMacOS
        ? 'libsbq.dylib'
        : 'libsbq.so';
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    final sep = Platform.pathSeparator;
    final candidates = [
      ?Platform.environment['SBQ_LIBRARY'],
      '$exeDir$sep$name',
      '$exeDir$sep..${sep}lib$sep$name',
    ];
    for (final path in candidates) {
      if (!File(path).existsSync()) continue;
      if (_openGlobal(path)) return path;
    }
    return null;
  }

  static bool _openGlobal(String path) {
    if (Platform.isWindows) {
      // Process lookups on Windows search every loaded module.
      try {
        DynamicLibrary.open(path);
        return true;
      } on ArgumentError {
        return false;
      }
    }
    final dlopen = DynamicLibrary.process()
        .lookupFunction<
          Pointer<Void> Function(Pointer<Utf8>, Int32),
          Pointer<Void> Function(Pointer<Utf8>, int)
        >('dlopen');
    // RTLD_NOW | RTLD_GLOBAL.
    final flags = Platform.isMacOS ? 0x2 | 0x8 : 0x2 | 0x100;
    return using(
          (arena) => dlopen(path.toNativeUtf8(allocator: arena), flags),
        ) !=
        nullptr;
  }

  static _Sbq _start() {
    checkLibrary();
    late final _Sbq rt;
    final bell = NativeCallable<Void Function(Uint64)>.listener(
      (int id) => rt._drain(id),
    )..keepIsolateAlive = false;
    final ctx = sbq_init(bell.nativeFunction, NativeQuicProvider.workerThreads);
    if (ctx == 0) {
      bell.close();
      throw QuicException(
        QuicExceptionKind.internal,
        'the native runtime did not start: ${lastError()}',
      );
    }
    return rt = _Sbq._(ctx, bell, calloc<SbqEvent>(_batch));
  }

  void retain() {
    if (_live++ == 0) _bell.keepIsolateAlive = true;
  }

  void release() {
    if (--_live > 0 || _down) return;
    _bell.keepIsolateAlive = false;
    scheduleMicrotask(() {
      if (_live == 0) shutdown();
    });
  }

  void shutdown() {
    if (_down) return;
    _down = true;
    if (identical(_current, this)) _current = null;
    for (final s in sessions.values.toList()) {
      s._ended(SBQ_CLOSE_APP_LOCAL, 0, reason: 'shutdown');
    }
    for (final l in listeners.values.toList()) {
      l._close();
    }
    sbq_shutdown(ctx);
    _bell.close();
    calloc.free(_events);
  }

  void _drain(int id) {
    if (_down || id != ctx) return;
    while (true) {
      final n = sbq_poll(ctx, _events, _batch);
      for (var i = 0; i < n && !_down; i++) {
        final e = (_events + i).ref;
        final kind = e.kind, handle = e.handle, a = e.a, b = e.b;
        try {
          _dispatch(kind, handle, a, b);
        } catch (error, stack) {
          Zone.current.handleUncaughtError(error, stack);
        }
      }
      if (n < _batch || _down) return;
    }
  }

  void _dispatch(int kind, int handle, int a, int b) {
    switch (kind) {
      case SBQ_EV_READABLE:
        streams[handle]?._readable();
      case SBQ_EV_WRITABLE:
        streams[handle]?._writable();
      case SBQ_EV_STREAM:
        final s = sessions[a];
        s == null ? sbq_stream_release(handle) : s._peerStream(handle);
      case SBQ_EV_OPENED:
        final s = sessions[a];
        s == null ? sbq_stream_release(handle) : s._opened(handle);
      case SBQ_EV_STOPPED:
        streams[handle]?._peerStopped(a < 0 ? null : a);
      case SBQ_EV_FINISHED_ACKED:
        streams[handle]?._acked();
      case SBQ_EV_CONNECTED:
        sessions[handle]?._connected();
      case SBQ_EV_INCOMING:
        final l = listeners[a];
        if (l == null) {
          sbq_conn_release(handle);
        } else {
          l._accepted(handle);
        }
      case SBQ_EV_CLOSED:
        final s = sessions[handle];
        if (s == null) {
          sbq_conn_release(handle);
        } else {
          s._ended(a, b);
        }
      case SBQ_EV_WT_REQUEST:
        final l = listeners[a];
        if (l == null) {
          sbq_wt_reject(handle, 503);
          sbq_conn_release(handle);
        } else {
          l._request(handle, b);
        }
      case SBQ_EV_DRAINING:
        sessions[handle]?._drainSignal();
      case SBQ_EV_UNI_STREAM:
        final s = sessions[a];
        if (s == null) {
          sbq_stream_stop(handle, 0);
          sbq_stream_release(handle);
        } else {
          s._peerUniStream(handle);
        }
    }
  }

  /// A string the shim copies out: called with a buffer, returns the full
  /// length (or a negative error, giving null).
  static String? text(int Function(Uint8List buffer) call) {
    var buffer = Uint8List(256);
    var n = call(buffer);
    if (n > buffer.length) {
      buffer = Uint8List(n);
      n = call(buffer);
    }
    if (n < 0) return null;
    return utf8.decode(buffer.sublist(0, n), allowMalformed: true);
  }

  static String lastError() =>
      text((b) => sbq_last_error(b.address, b.length)) ?? '';

  /// The exception for a failed synchronous call.
  static QuicException failure(int code, String what) {
    final message = '$what: ${lastError()} ($code)';
    return QuicException(switch (code) {
      SBQ_ERR_IO => QuicExceptionKind.unreachable,
      SBQ_ERR_CONNECTION => QuicExceptionKind.sessionEnded,
      _ => QuicExceptionKind.internal,
    }, message);
  }
}

/// [bytes] in native memory of [arena]; a valid pointer even when empty.
Pointer<Uint8> _native(Arena arena, List<int> bytes) {
  final p = arena<Uint8>(math.max(bytes.length, 1));
  p.asTypedList(bytes.length).setAll(0, bytes);
  return p;
}

/// At most [max] bytes of [bytes], cut at a UTF-8 character boundary.
Uint8List _truncateUtf8(Uint8List bytes, int max) {
  if (bytes.length <= max) return bytes;
  var n = max;
  while (n > 0 && (bytes[n] & 0xC0) == 0x80) {
    n--;
  }
  return Uint8List.sublistView(bytes, 0, n);
}
