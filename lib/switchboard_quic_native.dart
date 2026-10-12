/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

/// The native stream provider of the QUIC binding (Dart VM only): raw QUIC
/// and WebTransport over HTTP/3, over quinn through the sbq shim, built by
/// the package's build hook.
library;

export 'src/native/native_provider.dart'
    show
        NativeCertificate,
        NativeQuicListener,
        NativeQuicProvider,
        NativeQuicReceiveStream,
        NativeQuicSession,
        NativeQuicStats,
        NativeQuicStream,
        NativeWebTransportListener,
        h3Alpn,
        quicAlpn;
export 'src/provider/quic_provider.dart';
