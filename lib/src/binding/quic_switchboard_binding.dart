/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
  GLM 5.3 Flash <noreply@z.ai>
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
///
/// A dial is bounded by the node's connect timeout
/// ([BindingDialSettings.timeout]), which is also the handshake deadline
/// of the session it asks for ([QuicClientConfig.handshakeTimeout]). The
/// QUIC idle timeout and keep-alive are the binding's own ([idleTimeout],
/// [keepAlive]); the control `PING` is the node's
/// ([MuxOptions.keepAliveInterval]).
class QuicSwitchboardBinding extends SwitchboardBinding {
  /// A binding dialling through [connector]. Throws [ArgumentError] for a
  /// negative [idleTimeout] or [keepAlive].
  QuicSwitchboardBinding(
    this.connector, {
    this.verifyCertificate = false,
    this.certificateHashes = const [],
    this.quicOptions = const QuicBindingOptions(),
    this.identityRules,
    this.idleTimeout = const Duration(seconds: 30),
    this.keepAlive,
    this.webTransportCertificateVerified = true,
  }) {
    if (idleTimeout.isNegative) {
      throw ArgumentError.value(
        idleTimeout,
        'idleTimeout',
        'must not be negative',
      );
    }
    if (keepAlive?.isNegative ?? false) {
      throw ArgumentError.value(keepAlive, 'keepAlive', 'must not be negative');
    }
  }

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

  /// The QUIC idle timeout of the sessions this binding dials: one on which
  /// nothing arrived for this long is lost (the stacks apply the shorter of
  /// both ends' timeouts). Zero for none of this side's. Longer than the
  /// stack's keep-alive interval ([keepAlive]), so that a connection with
  /// nothing to say is not closed between two of its `PING`s; the default
  /// keep-alive, a third of it, is by construction.
  final Duration idleTimeout;

  /// The interval of the QUIC stack's own keep-alive on the sessions this
  /// binding dials: `PING` frames the stack sends while the connection is
  /// quiet, so that a live path does not reach [idleTimeout]. They show
  /// that the peer's stack answers, not that its application reads.
  ///
  /// The control `PING` of the binding is another thing: the application's
  /// probe of its peer, every [MuxOptions.keepAliveInterval] of the node
  /// (null disables it), which this setting neither reads nor replaces
  /// (binding page, "Keep-alive").
  ///
  /// Null, the default: a third of [idleTimeout], none when [idleTimeout]
  /// is zero. [Duration.zero]: none, so that only traffic (the control
  /// `PING` among it) keeps a quiet connection from its idle timeout.
  final Duration? keepAlive;

  /// [keepAlive] as the sessions are configured with it.
  Duration get _stackKeepAlive => keepAlive ?? idleTimeout ~/ 3;

  /// Whether the server certificate of an `https` endpoint is verified
  /// (the platform roots, or [certificateHashes] as
  /// `serverCertificateHashes`). True by default, as a browser does.
  final bool webTransportCertificateVerified;

  /// The most recent 64 connections dialled, for diagnostics and tests.
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

  /// Dials [endpoint]. The connect is bounded by
  /// [BindingDialSettings.timeout] when it is positive: on expiry the dial
  /// fails with [StatusCode.unavailable], and a session the provider still
  /// yields afterwards is closed with [StatusCode.cancelled] (a connect
  /// cannot be cancelled), so that it never reaches [dialled].
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
    final timeout = settings.timeout > Duration.zero
        ? settings.timeout
        : Duration.zero;
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
      connectionReceiveWindow: options.receiveHighWaterMarkBytes > 0
          ? options.receiveHighWaterMarkBytes
          : 16 << 20,
      idleTimeout: idleTimeout,
      keepAlive: _stackKeepAlive,
      handshakeTimeout: timeout,
    );
    final QuicSession session;
    try {
      final connecting = connector.connect(
        Uri(
          scheme: scheme,
          host: endpoint.host,
          port: endpoint.hasPort ? endpoint.port : null,
          path: webTransport ? endpoint.path : null,
        ),
        config,
      );
      session = await (timeout > Duration.zero
          ? connecting.timeout(
              timeout,
              onTimeout: () {
                _abandon(connecting);
                throw SwitchboardException.of(
                  StatusCode.unavailable,
                  'cannot reach $endpoint: not connected within $timeout',
                );
              },
            )
          : connecting);
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
    if (dialled.length == 64) dialled.removeAt(0);
    dialled.add(connection);
    return connection;
  }

  /// Closes the session a connect given up on still yields, and swallows
  /// its failure.
  static void _abandon(Future<QuicSession> connecting) {
    connecting
        .then(
          (session) =>
              session.close(StatusCode.cancelled.code, 'dial abandoned'),
          onError: (Object _) {},
        )
        .ignore();
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

  /// The most recent 64 accepted connections, for diagnostics and tests.
  final List<QuicBindingConnection> accepted = [];

  StreamSubscription<QuicSession>? _subscription;
  bool _declared = false;
  bool _closed = false;

  /// The endpoint peers dial.
  Uri get endpoint => listener.endpoint;

  Future<void> _accept(QuicSession session) async {
    if (_closed) {
      session.close(StatusCode.goingAway.code, 'not accepting').ignore();
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
      session.close(StatusCode.internal.code, 'internal error').ignore();
      return;
    }
    if (_closed) {
      await connection.close();
      return;
    }
    if (accepted.length == 64) accepted.removeAt(0);
    accepted.add(connection);
    try {
      await node.adopt(connection, policy: policy, remote: session.remote);
    } on Object catch (e) {
      _log.fine('connection from ${session.remote} not adopted: $e');
      await connection.close();
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
