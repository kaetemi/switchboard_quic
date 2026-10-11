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
///   `Switchboard` node its `quic://` and `https://` endpoints.
/// * [QuicBindingConnection] and [QuicChannel] are the connection and
///   channel contracts of `MuxConnection` and `MuxChannel` over a
///   [QuicSession] of any stream provider.
/// * The stream provider contract ([QuicConnector], [QuicListener],
///   [QuicSession], [QuicStream]) is what a provider implements.
/// * The wire format (records, `HELLO`, error codes, the exporter) is
///   public for providers and tests.
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
export 'src/binding/quic_switchboard_binding.dart';
export 'src/binding/record_reader.dart';
export 'src/binding/records.dart';
export 'src/provider/quic_provider.dart';
