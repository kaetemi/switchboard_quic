/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

import 'dart:async';
import 'dart:typed_data';

import 'package:logging/logging.dart';
import 'package:switchboard/switchboard.dart';

import '../provider/quic_provider.dart';
import 'quic_binding_connection.dart';
import 'quic_options.dart';

final Logger _log = Logger('Switchboard.Quic');

/// The ALPN token of raw QUIC, and the WebTransport protocol value.
const String switchboardAlpn = 'switchboard';

/// The [SwitchboardBinding] of the QUIC and WebTransport binding: a
/// `Switchboard` node dials `quic://host:port` endpoints (raw QUIC, ALPN
/// `switchboard`) and `https://host:port/path` endpoints (WebTransport)
/// through [connector], and runs [QuicBindingConnection] over the
/// sessions.
///
/// A connector that cannot dial a scheme fails with
/// [QuicExceptionKind.unsupportedScheme], which the node reads as
/// `UNIMPLEMENTED` and moves to a record's next endpoint: the native
/// provider dials `quic` only until its WebTransport layer exists, the web
/// provider `https` only.
///
/// Between nodes the acceptor's certificate is self-signed and not
/// verified ([verifyCertificate] false, no [certificateHashes]), and the
/// identification rules of the specification apply where identity is in
/// use ([QuicIdentityRules.initiator]); a pin or a verified certificate
/// authenticates the acceptor, and lifts them. [identityRules] overrides
/// them.
class QuicSwitchboardBinding extends SwitchboardBinding {
  /// A binding dialling through [connector].
  QuicSwitchboardBinding(
    this.connector, {
    this.verifyCertificate = false,
    this.certificateHashes = const [],
    this.quicOptions = const QuicBindingOptions(),
    this.identityRules,
    this.idleTimeout = const Duration(seconds: 30),
    this.webTransportCertificateVerified = true,
  });

  /// The URI scheme of raw QUIC endpoints.
  static const String quicScheme = 'quic';

  /// The URI scheme of WebTransport endpoints.
  static const String webTransportScheme = 'https';

  /// The provider's connector.
  final QuicConnector connector;

  /// Whether the acceptor's certificate of a `quic` endpoint is verified
  /// against the platform roots. False by default: node certificates are
  /// self-signed, and identity comes from `IDENT`.
  final bool verifyCertificate;

  /// SHA-256 hashes of the acceptable server certificates (a pin), which
  /// authenticate the acceptor.
  final List<Uint8List> certificateHashes;

  /// The binding's own options; their [QuicBindingOptions.identity] is
  /// replaced by the rules of each dial.
  final QuicBindingOptions quicOptions;

  /// The identification rules of every connection, instead of
  /// [QuicIdentityRules.initiator] computed per dial.
  final QuicIdentityRules? identityRules;

  /// The QUIC idle timeout; longer than the keep-alive interval, so that a
  /// connection with nothing to say is not closed between two probes.
  final Duration idleTimeout;

  /// Whether the server certificate of an `https` endpoint is verified
  /// (the platform roots, or [certificateHashes] as
  /// `serverCertificateHashes`). True by default, as a browser does.
  final bool webTransportCertificateVerified;

  /// Every connection this binding dialled, for diagnostics and tests.
  final List<QuicBindingConnection> dialled = [];

  @override
  Set<String> get schemes => const {quicScheme, webTransportScheme};

  /// Raw QUIC endpoints compare by scheme, host and port; WebTransport
  /// endpoints by scheme, host, port (443 by default) and path, as the
  /// path names the listener.
  @override
  Uri normalise(Uri endpoint) {
    final scheme = endpoint.scheme.toLowerCase();
    if (scheme == webTransportScheme) {
      return Uri(
        scheme: scheme,
        host: endpoint.host.toLowerCase(),
        port: endpoint.hasPort ? endpoint.port : 443,
        path: endpoint.path.isEmpty ? '/' : endpoint.path,
      );
    }
    return super.normalise(endpoint);
  }

  @override
  Future<MuxConnection> dial(Uri endpoint, BindingDialSettings settings) async {
    final scheme = endpoint.scheme.toLowerCase();
    final webTransport = scheme == webTransportScheme;
    if (!webTransport && (endpoint.host.isEmpty || !endpoint.hasPort)) {
      throw SwitchboardException.of(
        StatusCode.invalidArgument,
        'a quic endpoint names a host and a port: $endpoint',
      );
    }
    final options = settings.options;
    final verified = webTransport
        ? webTransportCertificateVerified || certificateHashes.isNotEmpty
        : verifyCertificate || certificateHashes.isNotEmpty;
    final config = QuicClientConfig(
      alpn: const [switchboardAlpn],
      serverCertificateHashes: certificateHashes,
      verifyCertificate: webTransport
          ? webTransportCertificateVerified
          : verifyCertificate,
      maxStreamsBidi: options.maxChannels > 0 ? options.maxChannels : 65536,
      streamReceiveWindow: options.initialWindow,
      receiveWindow: options.receiveHighWaterMarkBytes > 0
          ? options.receiveHighWaterMarkBytes
          : 16 << 20,
      idleTimeout: idleTimeout,
      keepAlive: options.keepAliveInterval ?? const Duration(seconds: 10),
    );
    final QuicSession session;
    try {
      session = await connector.connect(
        Uri(
          scheme: scheme,
          host: endpoint.host,
          port: endpoint.hasPort ? endpoint.port : null,
          path: webTransport ? endpoint.path : null,
        ),
        config,
      );
    } on QuicException catch (e) {
      throw SwitchboardException.of(
        e.kind == QuicExceptionKind.unsupportedScheme
            ? StatusCode.unimplemented
            : StatusCode.unavailable,
        'cannot reach $endpoint: ${e.message}',
      );
    }
    final rules =
        identityRules ??
        QuicIdentityRules.initiator(
          certificateVerified: verified,
          hasCredential: settings.localIdentity != null,
          verifiesCredentials: options.identityVerifier != null,
        );
    final connection = await QuicBindingConnection.start(
      session,
      options: options,
      quicOptions: quicOptions.copyWith(identity: rules),
      isWebTransport: webTransport,
      localIdentity: settings.localIdentity,
    );
    if (!connection.isOpen) {
      // Ended while it started: the session, or the identification rules.
      final status = await connection.done;
      throw SwitchboardException(
        status.known == StatusCode.unauthenticated
            ? status
            : Status.of(StatusCode.unavailable, '$endpoint: $status'),
      );
    }
    dialled.add(connection);
    return connection;
  }
}

/// Accepts the sessions of a [QuicListener] into a `Switchboard` node:
/// each one runs [QuicBindingConnection] and is handed to
/// `Switchboard.adopt` under [policy]; the listener's endpoint is declared
/// with `Switchboard.addListeningEndpoint`, so that the node lists it and
/// knows it as its own.
///
/// A node listener's certificate is self-signed, so its clients cannot
/// verify it, and the identification rules of the specification apply by
/// default ([QuicIdentityRules.listener]): nonce-bound `IDENT`s are
/// refused, and with [identifyInReturn] (the default) a node with a
/// credential identifies in turn, naming the peer, once the peer's own
/// exporter-bound `IDENT` has verified, and to nobody else. A listener
/// that serves only browsers, which verify its certificate, passes
/// [QuicIdentityRules.none].
class QuicSwitchboardListener {
  QuicSwitchboardListener._(
    this.node,
    this.listener,
    this.policy,
    this.quicOptions,
    this.identifyInReturn,
  );

  /// Starts accepting [listener]'s sessions into [node], under [policy]
  /// (null allows everything; a listener open to untrusted peers needs one
  /// that refuses the reserved types). [quicOptions] apply to every
  /// connection, its [QuicBindingOptions.identity] replaced by
  /// [identityRules]. With [declareEndpoint] (the default), the
  /// listener's endpoint is declared to the node.
  ///
  /// Throws as `Switchboard.addListeningEndpoint` does.
  static Future<QuicSwitchboardListener> start(
    Switchboard node,
    QuicListener listener, {
    ChannelPolicy? policy,
    QuicBindingOptions quicOptions = const QuicBindingOptions(),
    QuicIdentityRules identityRules = QuicIdentityRules.listener,
    bool identifyInReturn = true,
    bool declareEndpoint = true,
  }) async {
    if (declareEndpoint) {
      await node.addListeningEndpoint(listener.endpoint, policy: policy);
    }
    final accepting = QuicSwitchboardListener._(
      node,
      listener,
      policy,
      quicOptions.copyWith(identity: identityRules),
      identifyInReturn,
    ).._declared = declareEndpoint;
    accepting._subscription = listener.sessions.listen(
      (session) => unawaited(accepting._accept(session)),
      onError: (Object e) => _log.fine('listener ${listener.endpoint}: $e'),
    );
    return accepting;
  }

  /// The node the connections join.
  final Switchboard node;

  /// The provider's listener.
  final QuicListener listener;

  /// The policy of the channels peers open.
  final ChannelPolicy? policy;

  /// The options of every connection.
  final QuicBindingOptions quicOptions;

  /// Whether the node identifies in turn to a peer whose exporter-bound
  /// `IDENT` verified.
  final bool identifyInReturn;

  /// Every connection accepted so far, for diagnostics and tests.
  final List<QuicBindingConnection> accepted = [];

  StreamSubscription<QuicSession>? _subscription;
  bool _declared = false;
  bool _closed = false;

  /// The endpoint peers dial.
  Uri get endpoint => listener.endpoint;

  Future<void> _accept(QuicSession session) async {
    if (_closed) {
      unawaited(session.close(StatusCode.goingAway.code, 'not accepting'));
      return;
    }
    final QuicBindingConnection connection;
    try {
      connection = await QuicBindingConnection.start(
        session,
        options: node.muxOptions,
        quicOptions: quicOptions,
        isWebTransport:
            listener.endpoint.scheme.toLowerCase() ==
            QuicSwitchboardBinding.webTransportScheme,
        localIdentity: node.credential?.identity,
      );
    } on Object catch (e) {
      _log.warning('cannot start a connection from ${session.remote}: $e');
      unawaited(session.close(StatusCode.internal.code, 'internal error'));
      return;
    }
    accepted.add(connection);
    try {
      await node.adopt(connection, policy: policy, remote: session.remote);
    } on Object catch (e) {
      _log.fine('connection from ${session.remote} not adopted: $e');
      return;
    }
    if (identifyInReturn && node.credential != null) {
      connection.peerIdentified
          .then((identity) => _identifyInReturn(connection, identity))
          .ignore();
    }
  }

  /// Identifies to [connection]'s peer, naming it, once its `IDENT`
  /// verified: that verification is what asks this side to. Under
  /// [QuicIdentityRules.identifyOnlyToIdentifiedPeer] (the listener's
  /// default) only once its exporter-bound `IDENT` verified.
  Future<void> _identifyInReturn(
    QuicBindingConnection connection,
    PeerIdentity identity,
  ) async {
    final rules = connection.quicOptions.identity;
    if (!connection.isOpen ||
        (rules.identifyOnlyToIdentifiedPeer && !connection.peerAuthenticated)) {
      return;
    }
    try {
      await node.identifyOn(connection, receiver: identity.identity);
    } on Object catch (e) {
      _log.info(
        'identifying to "${identity.identity}" at ${connection.session.remote} '
        'failed: $e',
      );
    }
  }

  /// Stops accepting sessions and withdraws the endpoint; the connections
  /// accepted stay the node's.
  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    await _subscription?.cancel();
    if (_declared) {
      node.removeListeningEndpoint(listener.endpoint);
    }
    await listener.close();
  }
}
