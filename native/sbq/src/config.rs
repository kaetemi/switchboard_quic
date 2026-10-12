/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GLM 5.3 Flash <noreply@z.ai>
*/

//! Client and server configuration: TLS 1.3 through rustls with ring, certificate verification
//! (platform roots, pinned SHA-256 hashes, or none), transport limits, self-signed certificates.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

use crate::h3conn::{H3_ALPN, H3_DATAGRAM_BUFFER, H3_UNI_STREAMS};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};

/// Transport limits and the handshake deadline, the same for both sides.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Bidirectional streams the peer may have open at once (`initial_max_streams_bidi`).
    pub max_bidi: u64,
    /// Receive window of each stream (`initial_max_stream_data_*`).
    pub stream_window: u64,
    /// Receive window of the connection (`initial_max_data`).
    pub conn_window: u64,
    /// Idle timeout in milliseconds, 0 for none.
    pub idle_ms: u64,
    /// Keep-alive interval in milliseconds, 0 for none.
    pub keep_alive_ms: u64,
    /// How long a handshake may take, in milliseconds, 0 for no deadline of its own (quinn then
    /// bounds it by the idle timeout alone). Not a transport parameter: the shim enforces it.
    pub handshake_ms: u64,
}

impl Limits {
    /// The handshake deadline, None for none.
    pub fn handshake(&self) -> Option<Duration> {
        (self.handshake_ms > 0).then(|| Duration::from_millis(self.handshake_ms))
    }
}

fn varint(v: u64, what: &str) -> Result<quinn::VarInt, String> {
    quinn::VarInt::from_u64(v).map_err(|_| format!("{what} out of range"))
}

/// The transport configuration. Raw QUIC: no unidirectional streams and no datagrams (the
/// binding uses neither), the given limits. HTTP/3 (`h3`): the unidirectional streams HTTP/3 and
/// WebTransport need, the datagram parameter H3_DATAGRAM requires, and on a server one more
/// bidirectional stream for a session's CONNECT stream.
pub fn transport(l: &Limits, h3: bool, server: bool) -> Result<quinn::TransportConfig, String> {
    let mut t = quinn::TransportConfig::default();
    let bidi = if h3 && server {
        l.max_bidi.saturating_add(1)
    } else {
        l.max_bidi
    };
    t.max_concurrent_bidi_streams(varint(bidi, "max_bidi")?)
        .max_concurrent_uni_streams(if h3 { H3_UNI_STREAMS } else { 0 }.into())
        .stream_receive_window(varint(l.stream_window, "stream_window")?)
        .receive_window(varint(l.conn_window.max(l.stream_window), "conn_window")?)
        .datagram_receive_buffer_size(h3.then_some(H3_DATAGRAM_BUFFER))
        .keep_alive_interval(if l.keep_alive_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(l.keep_alive_ms))
        });
    let idle = if l.idle_ms == 0 {
        None
    } else {
        Some(
            quinn::IdleTimeout::try_from(Duration::from_millis(l.idle_ms))
                .map_err(|_| "idle timeout out of range".to_string())?,
        )
    };
    t.max_idle_timeout(idle);
    Ok(t)
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    static P: OnceLock<Arc<rustls::crypto::CryptoProvider>> = OnceLock::new();
    P.get_or_init(|| Arc::new(rustls::crypto::ring::default_provider()))
        .clone()
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, b);
    let mut o = [0u8; 32];
    o.copy_from_slice(d.as_ref());
    o
}

/// How a client checks the server's certificate.
#[derive(Clone, Debug)]
pub enum Verify {
    /// The platform's trust store and name checks.
    Platform,
    /// The end-entity certificate's SHA-256 over its DER encoding must be one of these.
    Pinned(Vec<[u8; 32]>),
    /// Any certificate (identity comes from elsewhere); only the handshake signature is checked.
    None,
}

pub struct ClientParams {
    pub alpn: Vec<Vec<u8>>,
    pub verify: Verify,
    pub limits: Limits,
}

impl ClientParams {
    /// Whether the ALPN list offers HTTP/3 (and the transport parameters are HTTP/3's).
    pub fn h3(&self) -> bool {
        offers_h3(&self.alpn)
    }
}

/// Whether an ALPN list includes `h3`.
pub fn offers_h3(alpn: &[Vec<u8>]) -> bool {
    alpn.iter().any(|a| a.as_slice() == H3_ALPN)
}

/// A listener's configuration: quinn's, the deadline of each handshake it accepts (which also
/// bounds an HTTP/3 request's wait for its answer), and whether it serves `h3`.
pub struct ServerParams {
    pub config: quinn::ServerConfig,
    pub handshake: Option<Duration>,
    pub h3: bool,
}

pub enum ConfigObj {
    Client(ClientParams),
    Server(ServerParams),
}

/// Parses an ALPN list in its wire form (each token prefixed by its length byte).
pub fn parse_alpn(mut b: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::new();
    while let Some((&n, rest)) = b.split_first() {
        let n = n as usize;
        if n == 0 || rest.len() < n {
            return Err("malformed ALPN list".into());
        }
        out.push(rest[..n].to_vec());
        b = &rest[n..];
    }
    Ok(out)
}

fn verify_signatures_12(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls12_signature(
        message,
        cert,
        dss,
        &provider().signature_verification_algorithms,
    )
}

fn verify_signatures_13(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider().signature_verification_algorithms,
    )
}

/// Whether `hash` equals one of `pins`, in time that depends only on the number of pins: every
/// byte of every pin is compared, the per-pin result is turned into 0 or 1 arithmetically (no
/// comparison the compiler could make a branch of), and `black_box` keeps the optimiser from
/// reasoning about the accumulated values (for example stopping once a pin has matched).
pub(crate) fn pin_matches(pins: &[[u8; 32]], hash: &[u8; 32]) -> bool {
    let mut any = 0u8;
    for pin in pins {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= pin[i] ^ hash[i];
        }
        let diff = std::hint::black_box(diff);
        // 1 when diff is 0: 0 - 1 borrows into the high byte, 1..=255 - 1 does not.
        let equal = ((u16::from(diff).wrapping_sub(1) >> 8) & 1) as u8;
        any = std::hint::black_box(any | equal);
    }
    any == 1
}

/// Pinned hashes, or nothing at all when the list is empty (Verify::None). The handshake
/// signature is always checked against the presented certificate's key.
#[derive(Debug)]
struct PinVerifier {
    pins: Vec<[u8; 32]>,
    any: bool,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.any || pin_matches(&self.pins, &sha256(end_entity.as_ref())) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signatures_12(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_signatures_13(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wraps a verifier to remember that it rejected the server's certificate, so that the failed
/// handshake is reported as a rejected certificate and not as a generic TLS failure.
#[derive(Debug)]
struct Recording {
    inner: Arc<dyn ServerCertVerifier>,
    rejected: Arc<AtomicBool>,
}

impl ServerCertVerifier for Recording {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let r = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now);
        if r.is_err() {
            self.rejected.store(true, Ordering::Relaxed);
        }
        r
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let r = self.inner.verify_tls13_signature(message, cert, dss);
        if r.is_err() {
            self.rejected.store(true, Ordering::Relaxed);
        }
        r
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }
}

fn platform_verifier() -> Result<Arc<dyn ServerCertVerifier>, String> {
    static V: OnceLock<Result<Arc<rustls_platform_verifier::Verifier>, String>> = OnceLock::new();
    V.get_or_init(|| {
        rustls_platform_verifier::Verifier::new(provider())
            .map(Arc::new)
            .map_err(|e| format!("platform verifier: {e}"))
    })
    .clone()
    .map(|v| v as Arc<dyn ServerCertVerifier>)
}

/// Builds the quinn client configuration of one connection; `rejected` is set if the server's
/// certificate fails verification.
pub fn client_config(
    p: &ClientParams,
    rejected: Arc<AtomicBool>,
) -> Result<quinn::ClientConfig, String> {
    let inner: Arc<dyn ServerCertVerifier> = match &p.verify {
        Verify::Platform => platform_verifier()?,
        Verify::Pinned(pins) => Arc::new(PinVerifier {
            pins: pins.clone(),
            any: false,
        }),
        Verify::None => Arc::new(PinVerifier {
            pins: Vec::new(),
            any: true,
        }),
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Recording { inner, rejected }))
        .with_no_client_auth();
    tls.alpn_protocols = p.alpn.clone();
    tls.enable_early_data = false;
    let q = QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut cc = quinn::ClientConfig::new(Arc::new(q));
    cc.transport_config(Arc::new(transport(&p.limits, p.h3(), false)?));
    Ok(cc)
}

/// Splits concatenated DER certificates (the end entity first, then its chain).
pub fn split_der_chain(mut b: &[u8]) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = der_len(b).ok_or("malformed certificate DER")?;
        if n > b.len() {
            return Err("truncated certificate DER".into());
        }
        out.push(CertificateDer::from(b[..n].to_vec()));
        b = &b[n..];
    }
    if out.is_empty() {
        return Err("no certificate".into());
    }
    Ok(out)
}

/// The total length (header included) of the DER SEQUENCE at the start of `b`.
fn der_len(b: &[u8]) -> Option<usize> {
    if b.len() < 2 || b[0] != 0x30 {
        return None;
    }
    let first = b[1] as usize;
    if first < 0x80 {
        return Some(2 + first);
    }
    let count = first & 0x7f;
    if count == 0 || count > 4 || b.len() < 2 + count {
        return None;
    }
    let len = b[2..2 + count]
        .iter()
        .fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
    // Checked: on a 32-bit target four length bytes near 2^32 would wrap the sum.
    usize::try_from(len).ok()?.checked_add(2 + count)
}

/// Builds the quinn server configuration: TLS 1.3 only, no client authentication, no 0-RTT.
pub fn server_config(
    alpn: Vec<Vec<u8>>,
    cert_der: &[u8],
    key_der: &[u8],
    limits: &Limits,
) -> Result<quinn::ServerConfig, String> {
    let chain = split_der_chain(cert_der)?;
    let key = PrivateKeyDer::try_from(key_der.to_vec()).map_err(|e| format!("private key: {e}"))?;
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("certificate or key rejected: {e}"))?;
    let h3 = offers_h3(&alpn);
    tls.alpn_protocols = alpn;
    // 0-RTT is on by default in rustls/quinn servers that set this; a replayed OPEN would be
    // served twice, so it stays off.
    tls.max_early_data_size = 0;
    let q = QuicServerConfig::try_from(tls).map_err(|e| e.to_string())?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(q));
    sc.transport_config(Arc::new(transport(limits, h3, true)?));
    Ok(sc)
}

/// A self-signed ECDSA P-256 certificate for `subject` (its common name and its one subject
/// alternative name, an IP address if it parses as one), valid from five minutes ago for
/// `validity_days` days. Returns the certificate DER and the PKCS#8 private key DER. A validity
/// that reaches past what a timestamp can hold is an error, not an overflow.
pub fn self_signed(subject: &str, validity_days: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(vec![subject.to_string()]).map_err(|e| e.to_string())?;
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, subject);
    params.distinguished_name = dn;
    let start = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_before = start;
    let days = validity_days.max(1) as i64;
    params.not_after = start
        .checked_add(time::Duration::days(days))
        .ok_or_else(|| format!("a validity of {days} days is out of range"))?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((cert.der().to_vec(), key.serialize_der()))
}
