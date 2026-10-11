/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

import 'package:meta/meta.dart';

import 'records.dart';

/// The identification rules of a connection of the QUIC and WebTransport
/// binding (wiki page "Polyverse Switchboard QUIC and WebTransport
/// Binding", sections "Exporter-bound proof" and "Certificates").
///
/// Between nodes, certificates are self-signed and the TLS handshake
/// authenticates nobody, so where identity is in use the connection is
/// authenticated by exporter-bound `IDENT`s, in each direction, and these
/// rules are requirements (MUST) of the specification. A mesh without
/// identity, or a connection whose peer the TLS handshake authenticated (a
/// browser verifying a frontend's certificate), relaxes them.
/// [QuicIdentityRules.initiator] and [QuicIdentityRules.listener] give the
/// specification's defaults; [QuicIdentityRules.none] none of them.
@immutable
class QuicIdentityRules {
  /// Rules with every requirement given explicitly; all off by default.
  const QuicIdentityRules({
    this.tlsAuthenticatesPeer = false,
    this.requireExporterBinding = false,
    this.awaitPeerIdentity = false,
    this.identifyOnlyToIdentifiedPeer = false,
    this.bearerOnlyToAuthenticatedPeer = false,
  });

  /// No requirement: nonce-bound proofs are sent and accepted when a
  /// `HELLO` lacks `EXPORTER`, as over the frame mux.
  static const QuicIdentityRules none = QuicIdentityRules();

  /// The specification's rules for an initiator. When the acceptor's
  /// certificate is not verified ([certificateVerified] false: neither the
  /// platform roots nor a pin) and identity is in use (the side has a
  /// credential, [hasCredential], or verifies the peer's,
  /// [verifiesCredentials]), it neither sends nor accepts nonce-bound
  /// `IDENT`s and closes the connection with `UNAUTHENTICATED` when a
  /// `HELLO` lacks `EXPORTER`; while identity is in use it waits for the
  /// acceptor's exporter-bound `IDENT` naming it before using the
  /// connection; and a bearer credential goes only to an authenticated
  /// end. A verified certificate authenticates the acceptor, and nothing
  /// more is required.
  factory QuicIdentityRules.initiator({
    required bool certificateVerified,
    required bool hasCredential,
    required bool verifiesCredentials,
  }) {
    if (certificateVerified) {
      return const QuicIdentityRules(tlsAuthenticatesPeer: true);
    }
    final inUse = hasCredential || verifiesCredentials;
    return QuicIdentityRules(
      requireExporterBinding: inUse,
      awaitPeerIdentity: inUse,
      bearerOnlyToAuthenticatedPeer: true,
    );
  }

  /// The specification's rules for a node listener whose clients may not
  /// verify its certificate (every listener with a self-signed one): it
  /// refuses nonce-bound `IDENT`s, identifies only to a peer whose
  /// exporter-bound `IDENT` has verified, and presents a bearer credential
  /// only to such a peer. A listener that serves only browsers, which
  /// verify its certificate, has no need of them ([none]).
  static const QuicIdentityRules listener = QuicIdentityRules(
    requireExporterBinding: true,
    identifyOnlyToIdentifiedPeer: true,
    bearerOnlyToAuthenticatedPeer: true,
  );

  /// Whether the TLS handshake authenticated the peer: the initiator
  /// verified the acceptor's certificate against the platform roots or a
  /// pin. A peer so authenticated is an authenticated end for
  /// [bearerOnlyToAuthenticatedPeer] and [identifyOnlyToIdentifiedPeer].
  final bool tlsAuthenticatesPeer;

  /// Whether this side depends on the exporter binding: it neither sends
  /// nor accepts a nonce-bound `IDENT`. An `IDENT` received while a
  /// `HELLO` lacks `EXPORTER` is refused as one that fails verification
  /// (the connection ends with `UNAUTHENTICATED`), and
  /// `MuxConnection.identify` fails with `UNAUTHENTICATED` without
  /// identifying. On an initiator, a `HELLO` without `EXPORTER` (the
  /// peer's, or its own when its stack cannot compute the exporter) closes
  /// the connection with `UNAUTHENTICATED`.
  final bool requireExporterBinding;

  /// Initiator: the connection reaches the endpoint's owner only once the
  /// acceptor's exporter-bound `IDENT` naming this side has verified
  /// (naming the identity this side named in its own `IDENT`, when it
  /// named one). `MuxConnection.identify` completes only then, and
  /// channels opened before wait for it (bounded by
  /// `MuxOptions.identityTimeout`, after which they end with
  /// `UNAUTHENTICATED`). An `IDENT` from the acceptor that names nobody is
  /// refused.
  final bool awaitPeerIdentity;

  /// Acceptor: `MuxConnection.identify` fails with `FAILED_PRECONDITION`
  /// unless the peer is an authenticated end ([tlsAuthenticatesPeer], or
  /// its exporter-bound `IDENT` has verified), so that this side's
  /// credential goes only to holders of the mesh's credentials and its
  /// proof cannot leave the connection.
  final bool identifyOnlyToIdentifiedPeer;

  /// `MuxConnection.identify` with a bearer credential, which carries no
  /// proof, fails with `FAILED_PRECONDITION` unless the peer is an
  /// authenticated end. The same holds for credentials in channel
  /// payloads, which the binding does not see: the application reads
  /// `QuicBindingConnection.peerAuthenticated` before sending one.
  final bool bearerOnlyToAuthenticatedPeer;

  /// A copy with the given fields replaced.
  QuicIdentityRules copyWith({
    bool? tlsAuthenticatesPeer,
    bool? requireExporterBinding,
    bool? awaitPeerIdentity,
    bool? identifyOnlyToIdentifiedPeer,
    bool? bearerOnlyToAuthenticatedPeer,
  }) => QuicIdentityRules(
    tlsAuthenticatesPeer: tlsAuthenticatesPeer ?? this.tlsAuthenticatesPeer,
    requireExporterBinding:
        requireExporterBinding ?? this.requireExporterBinding,
    awaitPeerIdentity: awaitPeerIdentity ?? this.awaitPeerIdentity,
    identifyOnlyToIdentifiedPeer:
        identifyOnlyToIdentifiedPeer ?? this.identifyOnlyToIdentifiedPeer,
    bearerOnlyToAuthenticatedPeer:
        bearerOnlyToAuthenticatedPeer ?? this.bearerOnlyToAuthenticatedPeer,
  );

  @override
  bool operator ==(Object other) =>
      other is QuicIdentityRules &&
      other.tlsAuthenticatesPeer == tlsAuthenticatesPeer &&
      other.requireExporterBinding == requireExporterBinding &&
      other.awaitPeerIdentity == awaitPeerIdentity &&
      other.identifyOnlyToIdentifiedPeer == identifyOnlyToIdentifiedPeer &&
      other.bearerOnlyToAuthenticatedPeer == bearerOnlyToAuthenticatedPeer;

  @override
  int get hashCode => Object.hash(
    tlsAuthenticatesPeer,
    requireExporterBinding,
    awaitPeerIdentity,
    identifyOnlyToIdentifiedPeer,
    bearerOnlyToAuthenticatedPeer,
  );

  @override
  String toString() =>
      'QuicIdentityRules(${[if (tlsAuthenticatesPeer) 'tlsAuthenticatesPeer', if (requireExporterBinding) 'requireExporterBinding', if (awaitPeerIdentity) 'awaitPeerIdentity', if (identifyOnlyToIdentifiedPeer) 'identifyOnlyToIdentifiedPeer', if (bearerOnlyToAuthenticatedPeer) 'bearerOnlyToAuthenticatedPeer'].join(', ')})';
}

/// What a connection of the QUIC and WebTransport binding needs beyond the
/// `MuxOptions` every binding shares: the record limit, the identification
/// rules, and the bounds of this binding's own.
@immutable
class QuicBindingOptions {
  /// Options. Every value has the specification's default.
  const QuicBindingOptions({
    this.recordLimit = quicDefaultRecordLimit,
    this.identity = QuicIdentityRules.none,
    this.controlStreamTimeout,
    this.openStreamTimeout = const Duration(seconds: 10),
    this.controlOutputMark = 64 * 1024,
    this.maxHeldControlMessages = 1024,
    this.maxPendingStreams = 128,
    this.writeBatchBytes = 64 * 1024,
  });

  /// The largest record body this side accepts on a channel's stream,
  /// announced in `HELLO`: at least [quicDefaultRecordLimit], which is the
  /// default, and at most [quicMaxRecordLength]. A record over it ends the
  /// connection with `FRAME_TOO_LARGE`, without its body being read. A
  /// proxy toward frame mux backends announces no more than the largest
  /// subframe they take (32752 bytes with the default window).
  final int recordLimit;

  /// The identification rules; see [QuicIdentityRules].
  final QuicIdentityRules identity;

  /// How long after the connection started either side waits for the
  /// peer's first HELLO before closing the connection with `PROTOCOL_ERROR`.
  /// Null, the default: `MuxOptions.keepAliveInterval`, or 10 s without
  /// keep-alive. [Duration.zero] waits without bound.
  final Duration? controlStreamTimeout;

  /// How long opening a channel waits for stream credit from the peer (the
  /// stack waits for `MAX_STREAMS`) before the channel fails with
  /// `RESOURCE_EXHAUSTED`. [Duration.zero] waits without bound. Default
  /// 10 s.
  final Duration openStreamTimeout;

  /// Bytes of control messages waiting for the control stream above which
  /// this side stops reading the peer's direction of the control stream,
  /// until they drained: a peer that sends `PING`s without reading cannot
  /// make `PONG`s pile up. Default 64 KiB.
  final int controlOutputMark;

  /// Most control messages held while an `IDENT` is verified; beyond it
  /// the connection ends with `RESOURCE_EXHAUSTED`. Default 1024.
  final int maxHeldControlMessages;

  /// Streams whose first OPEN record is still being read. Further streams
  /// are stopped and reset with RESOURCE_EXHAUSTED. Their reads are also
  /// bounded by [openStreamTimeout], as are outgoing stream opens.
  final int maxPendingStreams;

  /// Records waiting on a stream are handed to the provider together, in
  /// one write of up to this many bytes (a record larger than it goes
  /// alone). Default 64 KiB.
  final int writeBatchBytes;

  /// A copy with the given fields replaced.
  QuicBindingOptions copyWith({
    int? recordLimit,
    QuicIdentityRules? identity,
    Duration? controlStreamTimeout,
    Duration? openStreamTimeout,
    int? controlOutputMark,
    int? maxHeldControlMessages,
    int? maxPendingStreams,
    int? writeBatchBytes,
  }) => QuicBindingOptions(
    recordLimit: recordLimit ?? this.recordLimit,
    identity: identity ?? this.identity,
    controlStreamTimeout: controlStreamTimeout ?? this.controlStreamTimeout,
    openStreamTimeout: openStreamTimeout ?? this.openStreamTimeout,
    controlOutputMark: controlOutputMark ?? this.controlOutputMark,
    maxHeldControlMessages:
        maxHeldControlMessages ?? this.maxHeldControlMessages,
    maxPendingStreams: maxPendingStreams ?? this.maxPendingStreams,
    writeBatchBytes: writeBatchBytes ?? this.writeBatchBytes,
  );
}
