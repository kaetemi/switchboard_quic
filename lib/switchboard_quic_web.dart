/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The web stream provider of the QUIC and WebTransport binding (browsers
/// only: `dart:js_interop` and `package:web`): [WebQuicProvider], a
/// [QuicConnector] of WebTransport sessions through the browser's W3C API,
/// and everything of `package:switchboard_quic/core.dart`, so that a
/// browser frontend reaches a Switchboard node over WebTransport with one
/// import:
///
/// ```dart
/// final client = ReconnectingClient.connections(
///   (options) => connectQuicBinding(
///     const WebQuicProvider(),
///     Uri.parse('https://node.example:4433/sb'),
///     options: options,
///     certificateHashes: [hash], // a self-signed certificate's SHA-256
///   ),
/// );
/// final talk = await client.openTalk(ChannelAddress(type: Name('echo')));
/// ```
library;

export 'core.dart';
export 'src/web/web_provider.dart'
    show
        WebQuicProvider,
        WebQuicReceiveStream,
        WebQuicSession,
        WebQuicStats,
        WebQuicStream;
