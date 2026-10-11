/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Fable 5.1 <noreply@anthropic.com>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The QUIC and WebTransport binding of Polyverse Switchboard: every
/// channel on a native stream of its own (wiki page "Polyverse Switchboard
/// QUIC and WebTransport Binding").
///
/// * [QuicSwitchboardBinding] and [QuicSwitchboardListener] give a
///   `Switchboard` node its `quic://` and `https://` endpoints (they need
///   `dart:io`, as the node does).
/// * Everything of `package:switchboard_quic/core.dart`, which compiles for
///   the web: [QuicBindingConnection] and [QuicChannel], the connection and
///   channel contracts of `MuxConnection` and `MuxChannel` over a
///   [QuicSession] of any stream provider; the stream provider contract
///   ([QuicConnector], [QuicListener], [QuicSession], [QuicStream]); and the
///   wire format (records, `HELLO`, error codes, the exporter).
library;

export 'core.dart';
export 'src/binding/quic_switchboard_binding.dart';
