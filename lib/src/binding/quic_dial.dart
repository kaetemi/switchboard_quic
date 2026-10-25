/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Fable 5.1 <noreply@anthropic.com>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

import 'dart:async';
import 'dart:typed_data';

import 'package:switchboard/core.dart';

import '../provider/quic_provider.dart';
import 'quic_binding_connection.dart';
import 'quic_options.dart';

/// The ALPN token of raw QUIC, and the WebTransport protocol value.
const String switchboardAlpn = 'switchboard';

/// Dials [endpoint] through [connector] and starts a [QuicBindingConnection]
/// over the session as its initiator: a `quic://host:port` endpoint (raw
/// QUIC, ALPN `switchboard`) or an `https://host:port/path` endpoint (a
/// WebTransport session offering the protocol `switchboard`). This is the
/// dial of `QuicSwitchboardBinding`, and what a browser frontend gives
/// `ReconnectingClient.connections`, over the web provider:
///
/// ```dart
/// final client = ReconnectingClient.connections(
///   (options) => connectQuicBinding(
///     const WebQuicProvider(),
///     Uri.parse('https://node.example:4433/sb'),
///     options: options,
///     certificateHashes: [hash],               // a self-signed certificate
///   ),
/// );
/// ```
///
/// [options] are the connection's (`MuxOptions`): its windows and channel
/// limit become the session's [QuicClientConfig] where the provider can
/// configure its stack. The acceptor's certificate is verified when
/// [verifyCertificate] is true (the platform roots) or [certificateHashes]
/// pin it (SHA-256 of the DER), and the identification rules are then
/// [QuicIdentityRules.initiator] for a verified certificate (nothing more
/// is required; a browser always verifies, so its nonce-bound `IDENT`s are
/// safe); with neither, they are the specification's rules for an
/// unverified acceptor where identity is in use ([localIdentity], or an
/// identity verifier in [options]). [identityRules] overrides them;
/// [quicOptions] are the binding's own (their identity replaced by the
/// rules).
///
/// [timeout] bounds the connect and is the handshake deadline asked of the
/// provider (zero: none of this side's); on expiry the dial fails with
/// `UNAVAILABLE`, and a session the provider still yields is closed with
/// `CANCELLED`, since a connect cannot be cancelled. [idleTimeout] and
/// [keepAlive] (default a third of [idleTimeout]) are the stack's, where
/// the provider can set them (a browser cannot).
///
/// Fails with a [SwitchboardException]: `UNIMPLEMENTED` when the connector
/// cannot dial the scheme (`unsupportedScheme`), `INVALID_ARGUMENT` for a
/// `quic` endpoint without a host or port, `UNAUTHENTICATED` when the
/// identification rules ended the connection while it started, and
/// `UNAVAILABLE` for any other failure. A negative [idleTimeout] or
/// [keepAlive] is an [ArgumentError].
Future<QuicBindingConnection> connectQuicBinding(
  QuicConnector connector,
  Uri endpoint, {
  MuxOptions options = const MuxOptions(),
  QuicBindingOptions quicOptions = const QuicBindingOptions(),
  QuicIdentityRules? identityRules,
  bool verifyCertificate = true,
  List<Uint8List> certificateHashes = const [],
  Duration timeout = const Duration(seconds: 10),
  Duration idleTimeout = const Duration(seconds: 30),
  Duration? keepAlive,
  String? localIdentity,
}) async {
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
  final scheme = endpoint.scheme.toLowerCase();
  final webTransport = scheme == 'https';
  if (!webTransport && (endpoint.host.isEmpty || !endpoint.hasPort)) {
    throw SwitchboardException.of(
      StatusCode.invalidArgument,
      'a quic endpoint names a host and a port: $endpoint',
    );
  }
  final deadline = timeout > Duration.zero ? timeout : Duration.zero;
  final verified = verifyCertificate || certificateHashes.isNotEmpty;
  final config = QuicClientConfig(
    alpn: const [switchboardAlpn],
    serverCertificateHashes: certificateHashes,
    verifyCertificate: verifyCertificate,
    maxStreamsBidi: options.maxChannels > 0 ? options.maxChannels : 65536,
    streamReceiveWindow: options.initialWindow,
    connectionReceiveWindow: options.receiveHighWaterMarkBytes > 0
        ? options.receiveHighWaterMarkBytes
        : 16 << 20,
    idleTimeout: idleTimeout,
    keepAlive: keepAlive ?? idleTimeout ~/ 3,
    handshakeTimeout: deadline,
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
    session = await (deadline > Duration.zero
        ? connecting.timeout(
            deadline,
            onTimeout: () {
              _abandon(connecting);
              throw SwitchboardException.of(
                StatusCode.unavailable,
                'cannot reach $endpoint: not connected within $deadline',
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
  } on SwitchboardException {
    rethrow;
  } on Object catch (e) {
    // Any other failure of the connector, as documented.
    throw SwitchboardException.of(
      StatusCode.unavailable,
      'cannot reach $endpoint: $e',
    );
  }
  final rules =
      identityRules ??
      QuicIdentityRules.initiator(
        certificateVerified: verified,
        hasCredential: localIdentity != null,
        verifiesCredentials: options.identityVerifier != null,
      );
  final connection = await QuicBindingConnection.start(
    session,
    options: options,
    quicOptions: quicOptions.copyWith(identity: rules),
    isWebTransport: webTransport,
    localIdentity: localIdentity,
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
  return connection;
}

/// Closes the session a connect given up on still yields, and swallows its
/// failure.
void _abandon(Future<QuicSession> connecting) {
  connecting
      .then(
        (session) => session.close(StatusCode.cancelled.code, 'dial abandoned'),
        onError: (Object _) {},
      )
      .ignore();
}
