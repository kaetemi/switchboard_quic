/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The parts of the QUIC and WebTransport binding that compile for the web
/// (no `dart:io`): the stream provider contract, the connection and channel
/// of the binding over it, and the wire format. A browser frontend runs a
/// `QuicBindingConnection` over the web provider's session (with
/// `ReconnectingClient.connections`, say); a `Switchboard` node uses
/// `package:switchboard_quic/switchboard_quic.dart`, which adds its
/// `SwitchboardBinding` and listener.
library;

export 'src/binding/exporter.dart';
export 'src/binding/quic_binding_connection.dart'
    show
        QuicBindingConnection,
        QuicChannel,
        quicBulkPriority,
        quicControlPriority,
        quicOrdinaryPriority;
export 'src/binding/quic_options.dart';
export 'src/binding/record_reader.dart';
export 'src/binding/records.dart';
export 'src/provider/quic_provider.dart';
