/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

//! The HTTP/3 layer of a QUIC connection that negotiated `h3`, and the WebTransport sessions on
//! it (draft-ietf-webtrans-http3).
//!
//! An `H3Conn` runs the connection: this side's control stream with its SETTINGS, the peer's
//! control and QPACK streams, the peer's streams (request streams on a server, WebTransport data
//! streams on both sides, which it routes to their session or holds until the session exists),
//! and the end of the connection. A session is a `ConnObj` with a `WtSession` inside, in the
//! handle table of connections, so that the stream and connection calls of the ABI take it:
//! its CONNECT stream is written by a writer task in order (response or request, capsules, FIN)
//! and read by a capsule task once the session is established.
//!
//! Versions: the client advertises draft-02 (`SETTINGS_ENABLE_WEBTRANSPORT`, what Chrome speaks)
//! and draft-07 (`SETTINGS_WEBTRANSPORT_MAX_SESSIONS`, what web-transport-quinn speaks), sends
//! the draft-02 request header and `WT-Available-Protocols`, and reads `WT-Protocol`. A server
//! advertises both, and answers in the version the client signalled. Neither side enables the
//! session flow control of the later drafts (nor sends their settings), so a client opens one
//! session per connection, and the QUIC limits do the work.
//!
//! Every peer input is bounded: the encoded and decoded field section (`MAX_FIELD_SECTION`), the
//! SETTINGS frame, the frames this side must buffer on a control or CONNECT stream (a varint
//! payload, or a capsule of at most `wt::MAX_CLOSE_MESSAGE` and its code), the bytes skipped
//! before a request's HEADERS, the sessions per connection (`MAX_SESSIONS`), the streams held for
//! a session that does not exist yet (`MAX_BUFFERED_STREAMS`, each for the request timeout), and
//! the time a stream may take to send its header. Unknown frame types, settings, capsules and
//! unidirectional stream types are ignored (frames and capsules skipped without buffering).
//!
//! Locks: the connection's `state` and a session's `st` are never held together. A session's
//! `st` comes before its stream set and the stream table: registering a stream and a close's
//! snapshot of the session's streams both hold it, so that no stream escapes the close. Events
//! are posted to the context's queue only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use quinn::{
    Connection, ConnectionError, ReadError, ReadExactError, RecvStream, SendStream, VarInt,
};
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;

use crate::conn::{CloseInfo, ConnObj};
use crate::ctx::{get, lock, rt, Ctx, CONNS, H3S, STREAMS};
use crate::h3::{self, err, frame, setting, stream_type, FieldError, PeerSettings};
use crate::stream::{self, NewStream, StreamObj};
use crate::wt;
use crate::*;

/// The sessions a server accepts on one connection (it advertises as much).
pub(crate) const MAX_SESSIONS: u64 = 16;
/// The streams held for a session that does not exist yet, per connection.
pub(crate) const MAX_BUFFERED_STREAMS: usize = 16;
/// The largest field section (HEADERS payload, encoded, and decoded as RFC 9114 counts it).
pub(crate) const MAX_FIELD_SECTION: usize = 16 << 10;
/// The largest SETTINGS frame payload.
const MAX_SETTINGS_FRAME: u64 = 4096;
/// The most bytes of unknown frames a request may carry before its HEADERS.
const MAX_SKIP_BEFORE_HEADERS: u64 = 64 << 10;
/// How long a request may wait for an answer, a stream for its header, a stream for its session,
/// when nothing else sets it (the configuration's handshake deadline does).
pub(crate) const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// The bounds of the wait for the peer to close a CONNECT stream before the QUIC connection is
/// closed, and of a server's wait for the client to close the QUIC connection itself (three
/// round trips, within these).
const MIN_CLOSE_WAIT: Duration = Duration::from_millis(200);
const MAX_CLOSE_WAIT: Duration = Duration::from_secs(2);
/// Unidirectional streams granted to the peer of an `h3` connection: its control and QPACK
/// streams, and room for the WebTransport and reserved streams this side refuses.
pub(crate) const H3_UNI_STREAMS: u32 = 16;
/// The datagram receive buffer of an `h3` connection: it makes `max_datagram_frame_size`
/// non-zero, as H3_DATAGRAM requires; received datagrams are never read, and quinn drops the
/// oldest beyond this.
pub(crate) const H3_DATAGRAM_BUFFER: usize = 65536;
/// The ALPN token of HTTP/3.
pub(crate) const H3_ALPN: &[u8] = b"h3";

/// The draft versions a session can use.
pub(crate) const VERSION_DRAFT02: u8 = 2;
pub(crate) const VERSION_DRAFT07: u8 = 7;

/// Request fields the embedder reads (`sbq_wt_request`).
pub(crate) const FIELD_AUTHORITY: i32 = 1;
pub(crate) const FIELD_PATH: i32 = 2;
pub(crate) const FIELD_ORIGIN: i32 = 3;
pub(crate) const FIELD_PROTOCOLS: i32 = 4;

/// Whether `SBQ_TRACE` is set: the HTTP/3 layer then writes what peers send (their SETTINGS,
/// requests and responses, the stream types and capsules it ignores) to stderr, for interop
/// work. Read once.
fn tracing() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("SBQ_TRACE").is_some_and(|v| !v.is_empty() && v != "0"))
}

macro_rules! trace {
    ($($arg:tt)*) => {
        if tracing() {
            eprintln!("sbq: {}", format_args!($($arg)*));
        }
    };
}

fn fields_text(fields: &[h3::Field]) -> String {
    fields
        .iter()
        .map(|(n, v)| {
            format!(
                "{}: {}",
                String::from_utf8_lossy(n),
                String::from_utf8_lossy(v)
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

// ---------------------------------------------------------------------------------------------
// Reading.

/// Why reading a stream stopped.
#[derive(Debug)]
enum Fail {
    /// A connection error this side detected: close the connection with this HTTP/3 code.
    Conn(u64, &'static str),
    /// A stream error: reset and stop the stream with this code.
    Stream(u64),
    /// FIN where more was expected.
    Fin,
    /// The peer reset the stream with this code.
    Reset(u64),
    /// The connection is gone.
    Lost,
}

fn read_fail(e: ReadError) -> Fail {
    match e {
        ReadError::Reset(c) => Fail::Reset(c.into_inner()),
        ReadError::ConnectionLost(_) => Fail::Lost,
        _ => Fail::Lost,
    }
}

fn exact_fail(e: ReadExactError) -> Fail {
    match e {
        ReadExactError::FinishedEarly(_) => Fail::Fin,
        ReadExactError::ReadError(e) => read_fail(e),
    }
}

/// Stream ownership includes explicit cancellation, including future cancellation at an await.
struct Receive(Option<RecvStream>);

impl Receive {
    fn take(mut self) -> RecvStream {
        self.0.take().expect("owned receive stream")
    }
}
impl Deref for Receive {
    type Target = RecvStream;
    fn deref(&self) -> &RecvStream {
        self.0.as_ref().expect("owned receive stream")
    }
}
impl DerefMut for Receive {
    fn deref_mut(&mut self) -> &mut RecvStream {
        self.0.as_mut().expect("owned receive stream")
    }
}
impl Drop for Receive {
    fn drop(&mut self) {
        if let Some(r) = self.0.as_mut() {
            let _ = r.stop(varint(err::H3_REQUEST_CANCELLED));
        }
    }
}

struct SendGuard(Option<SendStream>);
impl SendGuard {
    fn take(mut self) -> SendStream {
        self.0.take().expect("owned send stream")
    }
}
impl Deref for SendGuard {
    type Target = SendStream;
    fn deref(&self) -> &SendStream {
        self.0.as_ref().expect("owned send stream")
    }
}
impl DerefMut for SendGuard {
    fn deref_mut(&mut self) -> &mut SendStream {
        self.0.as_mut().expect("owned send stream")
    }
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if let Some(s) = self.0.as_mut() {
            let _ = s.reset(varint(err::H3_REQUEST_CANCELLED));
        }
    }
}

fn frame_failure(e: Fail) -> Fail {
    match e {
        Fail::Fin => Fail::Conn(err::H3_FRAME_ERROR, "truncated frame"),
        e => e,
    }
}

/// Reads a stream exactly as far as asked, never beyond: what follows stays in quinn for the
/// next reader (the embedder, after a stream header).
struct Reader {
    recv: Receive,
}

impl Reader {
    async fn exact(&mut self, buf: &mut [u8]) -> Result<(), Fail> {
        self.recv.read_exact(buf).await.map_err(exact_fail)
    }

    /// A variable-length integer; None at FIN before its first byte.
    async fn varint(&mut self) -> Result<Option<u64>, Fail> {
        let mut b = [0u8; 8];
        match self.recv.read_exact(&mut b[..1]).await {
            Ok(()) => {}
            Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(e) => return Err(exact_fail(e)),
        }
        let n = h3::varint_len_of_first(b[0]);
        self.exact(&mut b[1..n]).await?;
        Ok(h3::get_varint(&b[..n]).map(|(v, _)| v))
    }

    async fn take(&mut self, n: u64) -> Result<Vec<u8>, Fail> {
        let mut v = vec![0u8; n as usize];
        self.exact(&mut v).await.map_err(frame_failure)?;
        Ok(v)
    }

    /// Discards `n` bytes without holding them.
    async fn skip(&mut self, mut n: u64) -> Result<(), Fail> {
        while n > 0 {
            let max = n.min(65536) as usize;
            match self.recv.read_chunk(max, true).await.map_err(read_fail)? {
                Some(c) => n -= c.bytes.len() as u64,
                None => return Err(frame_failure(Fail::Fin)),
            }
        }
        Ok(())
    }

    /// A frame header; None at FIN before it. A FIN inside it is a frame error.
    async fn frame_header(&mut self) -> Result<Option<(u64, u64)>, Fail> {
        let Some(t) = self.varint().await.map_err(frame_failure)? else {
            return Ok(None);
        };
        match self.varint().await {
            Ok(Some(len)) => Ok(Some((t, len))),
            Ok(None) | Err(Fail::Fin) => Err(Fail::Conn(err::H3_FRAME_ERROR, "truncated frame")),
            Err(e) => Err(e),
        }
    }

    /// The payload of a frame that holds one variable-length integer.
    async fn varint_payload(&mut self, len: u64) -> Result<u64, Fail> {
        if len == 0 || len > 8 {
            return Err(Fail::Conn(err::H3_FRAME_ERROR, "malformed frame"));
        }
        let b = self.take(len).await.map_err(|e| match e {
            Fail::Fin => Fail::Conn(err::H3_FRAME_ERROR, "truncated frame"),
            e => e,
        })?;
        match h3::get_varint(&b) {
            Some((v, n)) if n == b.len() => Ok(v),
            _ => Err(Fail::Conn(err::H3_FRAME_ERROR, "malformed frame")),
        }
    }
}

/// Frames that never appear on a request or CONNECT stream (H3_FRAME_UNEXPECTED there).
fn forbidden_on_request(t: u64) -> bool {
    matches!(
        t,
        frame::CANCEL_PUSH | frame::SETTINGS | frame::GOAWAY | frame::MAX_PUSH_ID
    ) || frame::is_reserved_h2(t)
}

/// The capsule stream of a CONNECT stream: the payloads of its DATA frames, one after the other.
struct Capsules {
    r: Reader,
    /// Bytes left in the current DATA frame.
    left: u64,
    trailers: bool,
}

enum Capsule {
    Close(u32, Vec<u8>),
    Drain,
    /// A capsule the draft forbids over HTTP/3.
    Forbidden,
    /// Anything else, skipped.
    Other,
}

impl Capsules {
    /// Moves to the next DATA payload byte, skipping other frames; false at FIN between frames.
    async fn data(&mut self) -> Result<bool, Fail> {
        while self.left == 0 {
            tokio::task::yield_now().await;
            let Some((t, len)) = self.r.frame_header().await? else {
                return Ok(false);
            };
            match t {
                frame::DATA if self.trailers => {
                    return Err(Fail::Conn(err::H3_FRAME_UNEXPECTED, "DATA after trailers"))
                }
                frame::DATA => self.left = len,
                frame::HEADERS if len > MAX_FIELD_SECTION as u64 => {
                    return Err(Fail::Stream(err::H3_EXCESSIVE_LOAD))
                }
                frame::HEADERS => {
                    if self.trailers {
                        return Err(Fail::Conn(err::H3_FRAME_UNEXPECTED, "second trailers"));
                    }
                    let fields = decode_fields(&self.r.take(len).await?)?;
                    check_fields(&fields, |_, _| Err(()), |_, _| {})
                        .map_err(|_| Fail::Stream(err::H3_MESSAGE_ERROR))?;
                    self.trailers = true;
                }
                frame::WT_STREAM => {
                    return Err(Fail::Conn(err::H3_FRAME_ERROR, "WT_STREAM inside a stream"))
                }
                frame::PUSH_PROMISE => {
                    return Err(Fail::Conn(
                        err::H3_FRAME_UNEXPECTED,
                        "unexpected PUSH_PROMISE",
                    ))
                }
                t if forbidden_on_request(t) => {
                    return Err(Fail::Conn(err::H3_FRAME_UNEXPECTED, "unexpected frame"))
                }
                // Trailers and unknown frames.
                _ => self.r.skip(len).await?,
            }
        }
        Ok(true)
    }

    /// Fills `buf` from the DATA payloads; a FIN before it is full is `Fail::Fin`.
    async fn exact(&mut self, buf: &mut [u8]) -> Result<(), Fail> {
        let mut off = 0;
        while off < buf.len() {
            if !self.data().await? {
                return Err(Fail::Fin);
            }
            let n = (buf.len() - off).min(self.left.min(usize::MAX as u64) as usize);
            self.r
                .exact(&mut buf[off..off + n])
                .await
                .map_err(frame_failure)?;
            self.left -= n as u64;
            off += n;
        }
        Ok(())
    }

    async fn skip(&mut self, mut n: u64) -> Result<(), Fail> {
        while n > 0 {
            if !self.data().await? {
                return Err(Fail::Fin);
            }
            let k = n.min(self.left);
            self.r.skip(k).await?;
            self.left -= k;
            n -= k;
        }
        Ok(())
    }

    /// A variable-length integer of the capsule stream; None at FIN before it.
    async fn varint(&mut self) -> Result<Option<u64>, Fail> {
        if !self.data().await? {
            return Ok(None);
        }
        let mut b = [0u8; 8];
        self.exact(&mut b[..1]).await?;
        let n = h3::varint_len_of_first(b[0]);
        self.exact(&mut b[1..n]).await?;
        Ok(h3::get_varint(&b[..n]).map(|(v, _)| v))
    }

    /// The next capsule; None at FIN between capsules. A malformed capsule is a stream error
    /// (H3_MESSAGE_ERROR), as is a truncated one.
    async fn next(&mut self) -> Result<Option<Capsule>, Fail> {
        let malformed = |e: Fail| match e {
            Fail::Fin => Fail::Stream(err::H3_MESSAGE_ERROR),
            e => e,
        };
        let Some(t) = self.varint().await.map_err(malformed)? else {
            return Ok(None);
        };
        let len = self
            .varint()
            .await
            .map_err(malformed)?
            .ok_or(Fail::Stream(err::H3_MESSAGE_ERROR))?;
        match t {
            wt::capsule::WT_CLOSE_SESSION => {
                if !(4..=4 + wt::MAX_CLOSE_MESSAGE as u64).contains(&len) {
                    return Err(Fail::Stream(err::H3_MESSAGE_ERROR));
                }
                let mut b = vec![0u8; len as usize];
                self.exact(&mut b).await.map_err(malformed)?;
                let code = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let message = b.split_off(4);
                if std::str::from_utf8(&message).is_err() {
                    return Err(Fail::Stream(err::H3_MESSAGE_ERROR));
                }
                Ok(Some(Capsule::Close(code, message)))
            }
            wt::capsule::WT_DRAIN_SESSION => {
                if len != 0 {
                    return Err(Fail::Stream(err::H3_MESSAGE_ERROR));
                }
                Ok(Some(Capsule::Drain))
            }
            wt::capsule::WT_MAX_STREAM_DATA | wt::capsule::WT_STREAM_DATA_BLOCKED => {
                Ok(Some(Capsule::Forbidden))
            }
            _ => {
                trace!("capsule of type {t:#x} ({len} bytes): ignored");
                self.skip(len).await.map_err(malformed)?;
                Ok(Some(Capsule::Other))
            }
        }
    }
}

/// `f`, or None once `d` has passed.
async fn within<F: Future>(d: Duration, f: F) -> Option<F::Output> {
    tokio::time::timeout(d, f).await.ok()
}

fn varint(v: u64) -> VarInt {
    VarInt::from_u64(v).unwrap_or_default()
}

fn stream_id(s: &SendStream) -> u64 {
    VarInt::from(s.id()).into_inner()
}

/// Resets and stops a stream with `code`.
fn abort(send: Option<&mut SendStream>, recv: Option<&mut RecvStream>, code: u64) {
    if let Some(s) = send {
        let _ = s.reset(varint(code));
    }
    if let Some(r) = recv {
        let _ = r.stop(varint(code));
    }
}

// ---------------------------------------------------------------------------------------------
// Messages.

/// A request's fields, as far as WebTransport needs them.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: Vec<u8>,
    pub protocol: Option<Vec<u8>>,
    pub authority: Vec<u8>,
    pub path: Vec<u8>,
    pub origin: Option<Vec<u8>>,
    /// `WT-Available-Protocols`, None when absent or malformed (and so ignored).
    pub protocols: Option<Vec<String>>,
    /// The draft-02 request header was present.
    pub draft02: bool,
}

impl Request {
    fn webtransport(&self) -> bool {
        self.method == b"CONNECT" && self.protocol.as_deref() == Some(b"webtransport")
    }
}

/// Field names RFC 9114 section 4.2 forbids.
fn connection_specific(name: &[u8]) -> bool {
    matches!(
        name,
        b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade"
    )
}

fn token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

fn decode_fields(b: &[u8]) -> Result<Vec<h3::Field>, Fail> {
    h3::decode_field_section(b, MAX_FIELD_SECTION).map_err(|e| match e {
        FieldError::Qpack => Fail::Conn(err::QPACK_DECOMPRESSION_FAILED, "a field section"),
        FieldError::TooLarge => Fail::Stream(err::H3_EXCESSIVE_LOAD),
    })
}

/// Checks the generic rules of a message's fields (RFC 9114 section 4.2 and 4.3): lowercase
/// names, pseudo-header fields first and at most once each, no connection-specific fields, no
/// NUL, CR or LF in a value. Calls `pseudo` and `regular` with each field.
fn check_fields(
    fields: &[h3::Field],
    mut pseudo: impl FnMut(&[u8], &[u8]) -> Result<(), ()>,
    mut regular: impl FnMut(&[u8], &[u8]),
) -> Result<(), ()> {
    let mut seen_regular = false;
    let mut seen_pseudo: Vec<&[u8]> = Vec::new();
    for (name, value) in fields {
        if name.is_empty()
            || name.iter().any(|c| c.is_ascii_uppercase())
            || !name
                .strip_prefix(b":")
                .unwrap_or(name)
                .iter()
                .all(|&c| token_char(c))
            || value.iter().any(|&c| (c < 0x20 && c != b'\t') || c == 0x7f)
            || matches!(value.first(), Some(b' ' | b'\t'))
            || matches!(value.last(), Some(b' ' | b'\t'))
        {
            return Err(());
        }
        if name[0] == b':' {
            if seen_regular || seen_pseudo.contains(&name.as_slice()) {
                return Err(());
            }
            seen_pseudo.push(name);
            pseudo(name, value)?;
        } else {
            seen_regular = true;
            if connection_specific(name)
                || (name == b"te" && !value.eq_ignore_ascii_case(b"trailers"))
            {
                return Err(());
            }
            regular(name, value);
        }
    }
    Ok(())
}

/// Parses a request's fields; Err for a malformed request.
fn parse_request(fields: &[h3::Field]) -> Result<Request, ()> {
    let mut r = Request::default();
    let mut scheme = None;
    let mut has_path = false;
    let mut protocols: Vec<u8> = Vec::new();
    let mut has_protocols = false;
    let mut duplicate_origin = false;
    let mut host = None;
    let mut duplicate_host = false;
    check_fields(
        fields,
        |name, value| {
            match name {
                b":method" => r.method = value.to_vec(),
                b":scheme" => scheme = Some(value.to_vec()),
                b":authority" => r.authority = value.to_vec(),
                b":path" => {
                    has_path = true;
                    r.path = value.to_vec();
                }
                b":protocol" => r.protocol = Some(value.to_vec()),
                _ => return Err(()),
            }
            Ok(())
        },
        |name, value| match name {
            b"origin" => {
                duplicate_origin |= r.origin.is_some();
                r.origin = Some(value.to_vec());
            }
            b"host" => {
                duplicate_host |= host.is_some();
                host = Some(value.to_vec());
            }
            b"sec-webtransport-http3-draft02" => r.draft02 |= value == b"1",
            b"wt-available-protocols" => {
                // Several field lines are one list, joined with commas (RFC 9651).
                if has_protocols {
                    protocols.push(b',');
                }
                has_protocols = true;
                protocols.extend_from_slice(value);
            }
            _ => {}
        },
    )?;
    if r.method.is_empty() || !r.method.iter().all(|&c| token_char(c)) || duplicate_origin {
        return Err(());
    }
    if r.method == b"CONNECT" && r.protocol.is_none() {
        // A classic CONNECT names an authority only.
        if r.authority.is_empty() || scheme.is_some() || has_path {
            return Err(());
        }
    } else {
        // Extended CONNECT (RFC 9220) and the other methods name a scheme and a path.
        if scheme.as_ref().is_none_or(Vec::is_empty) || r.path.is_empty() {
            return Err(());
        }
        if r.protocol.is_some() && (r.method != b"CONNECT" || r.authority.is_empty()) {
            return Err(());
        }
    }
    if host
        .as_ref()
        .is_some_and(|h| !r.authority.is_empty() && !h.eq_ignore_ascii_case(&r.authority))
    {
        return Err(());
    }
    if r.webtransport()
        && (scheme.as_deref() != Some(b"https")
            || r.path.first() != Some(&b'/')
            || r.path.contains(&b'#')
            || r.path.iter().any(|&c| !(0x21..=0x7e).contains(&c))
            || r.authority
                .iter()
                .any(|&c| !(0x21..=0x7e).contains(&c) || b"/@?#\\".contains(&c)))
    {
        return Err(());
    }
    if has_protocols {
        r.protocols = wt::parse_string_list(&protocols);
    }
    Ok(r)
}

/// A response's status and the fields WebTransport reads.
struct Response {
    status: u16,
    protocol: Option<String>,
    draft02: bool,
}

fn parse_response(fields: &[h3::Field]) -> Result<Response, ()> {
    let mut status = None;
    let mut protocol: Option<Vec<u8>> = None;
    let mut draft02 = false;
    check_fields(
        fields,
        |name, value| {
            if name != b":status" || value.len() != 3 || !value.iter().all(u8::is_ascii_digit) {
                return Err(());
            }
            status = std::str::from_utf8(value).ok().and_then(|s| s.parse().ok());
            Ok(())
        },
        |name, value| match name {
            b"wt-protocol" => {
                if let Some(p) = protocol.as_mut() {
                    p.push(b',');
                    p.extend_from_slice(value);
                } else {
                    protocol = Some(value.to_vec());
                }
            }
            b"sec-webtransport-http3-draft" => draft02 |= value == b"draft02",
            _ => {}
        },
    )?;
    let status = status.ok_or(())?;
    if !(100..=599).contains(&status) || status == 101 {
        return Err(());
    }
    Ok(Response {
        status,
        protocol: protocol.and_then(|p| wt::parse_string_item(&p)),
        draft02,
    })
}

/// A HEADERS frame of a response with `status` and, for a 2xx, the version's header and the
/// selected protocol.
fn response_frame(status: u16, version: u8, protocol: Option<&[u8]>) -> Vec<u8> {
    let status = status.to_string();
    let mut fields: Vec<(&[u8], &[u8])> = vec![(b":status", status.as_bytes())];
    let selected = protocol.map(wt::sf_string);
    if (200..300).contains(&status.parse::<u16>().unwrap_or(0)) {
        if version == VERSION_DRAFT02 {
            fields.push((b"sec-webtransport-http3-draft", b"draft02"));
        }
        if let Some(p) = selected.as_deref() {
            fields.push((b"wt-protocol", p.as_bytes()));
        }
    }
    h3::frame(frame::HEADERS, &h3::encode_field_section(&fields))
}

/// This side's SETTINGS on its control stream, with the stream type in front.
fn control_stream_start(client: bool) -> Vec<u8> {
    let mut pairs = vec![
        (setting::QPACK_MAX_TABLE_CAPACITY, 0),
        (setting::QPACK_BLOCKED_STREAMS, 0),
        (setting::MAX_FIELD_SECTION_SIZE, MAX_FIELD_SECTION as u64),
    ];
    if !client {
        pairs.push((setting::ENABLE_CONNECT_PROTOCOL, 1));
    }
    pairs.extend([
        (setting::H3_DATAGRAM, 1),
        (setting::H3_DATAGRAM_DRAFT, 1),
        (setting::ENABLE_WEBTRANSPORT_DRAFT02, 1),
        (
            setting::WEBTRANSPORT_MAX_SESSIONS_DRAFT07,
            if client { 1 } else { MAX_SESSIONS },
        ),
    ]);
    let mut out = Vec::new();
    h3::put_varint(&mut out, stream_type::CONTROL);
    h3::put_frame(&mut out, frame::SETTINGS, &h3::encode_settings(&pairs));
    out
}

// ---------------------------------------------------------------------------------------------
// Sessions.

/// Where a session is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// A client's session before its response.
    Connecting,
    /// A server's session whose request waits for the embedder's answer.
    Pending,
    Live,
    Ended,
}

/// What a session's writer task does with its CONNECT stream, in order.
enum Write {
    Bytes(Vec<u8>),
    /// FIN, then wait for its acknowledgement within the close wait.
    Finish,
    /// A close capsule and FIN own the deferred resets and CLOSED notification even if writing
    /// fails or is cancelled. Receipt of the close precedes the resets on the normal path.
    Close(Vec<u8>, DeferredStreams, ClosedNotification),
    Reset(u64),
}

/// Reporting a local close lets the embedder tear down its context. Keep that notification
/// until the CONNECT close is acknowledged (or its bounded attempt ends), including failures
/// and cancellation. The end info itself is recorded synchronously so further I/O fails now.
struct ClosedNotification {
    ctx: Arc<Ctx>,
    handle: u64,
    code: u64,
    report: bool,
}
impl Drop for ClosedNotification {
    fn drop(&mut self) {
        if self.report {
            self.ctx.post(
                SBQ_EV_CLOSED,
                self.handle,
                SBQ_CLOSE_APP_LOCAL,
                self.code as i64,
            );
        }
    }
}

struct DeferredStreams(Vec<Arc<StreamObj>>);
impl Drop for DeferredStreams {
    fn drop(&mut self) {
        for s in &self.0 {
            s.session_gone();
        }
    }
}

/// The WebTransport part of a session's `ConnObj`.
pub struct WtSession {
    pub client: bool,
    /// The connection, once there is one.
    pub h3: Mutex<Option<Arc<H3Conn>>>,
    /// The session ID (the CONNECT stream's ID), once there is one.
    pub id: Mutex<Option<u64>>,
    pub st: Mutex<SessionState>,
}

pub struct SessionState {
    pub phase: Phase,
    /// A server's request.
    pub request: Option<Request>,
    /// The draft version: 2 or 7.
    pub version: u8,
    /// The protocol selected (empty: none).
    pub protocol: Vec<u8>,
    writer: Option<mpsc::UnboundedSender<Write>>,
    writer_task: Option<AbortHandle>,
    reader_task: Option<AbortHandle>,
    /// A server's CONNECT stream reader, until the request is answered.
    reader: Option<Reader>,
    /// The session went live once (its protocol is known).
    established: bool,
    drain_sent: bool,
    draining_posted: bool,
}

impl WtSession {
    fn new(client: bool, phase: Phase) -> Self {
        WtSession {
            client,
            h3: Mutex::new(None),
            id: Mutex::new(None),
            st: Mutex::new(SessionState {
                phase,
                request: None,
                version: VERSION_DRAFT07,
                protocol: Vec::new(),
                writer: None,
                writer_task: None,
                reader_task: None,
                reader: None,
                established: false,
                drain_sent: false,
                draining_posted: false,
            }),
        }
    }

    pub fn client() -> Self {
        Self::new(true, Phase::Connecting)
    }

    pub(crate) fn h3(&self) -> Option<Arc<H3Conn>> {
        lock(&self.h3).clone()
    }

    fn sid(&self) -> Option<u64> {
        *lock(&self.id)
    }

    /// The stream header of a bidirectional stream of this session (None unless it is live).
    pub fn stream_header(&self) -> Option<Vec<u8>> {
        if lock(&self.st).phase != Phase::Live {
            return None;
        }
        let mut out = Vec::new();
        h3::put_varint(&mut out, frame::WT_STREAM);
        h3::put_varint(&mut out, self.sid()?);
        Some(out)
    }
}

/// A peer stream held until its session exists.
enum Held {
    Bi(SendStream, RecvStream),
    Uni(RecvStream),
}

impl Held {
    fn reject(self, code: u64) {
        match self {
            Held::Bi(mut s, mut r) => abort(Some(&mut s), Some(&mut r), code),
            Held::Uni(mut r) => abort(None, Some(&mut r), code),
        }
    }
}

/// A session as its connection knows it.
enum Slot {
    Pending(Weak<ConnObj>),
    Live(Weak<ConnObj>),
    /// Ended; the CONNECT stream is still being closed: by the peer (`peer`) and by this side
    /// (`us`, its FIN acknowledged or its reset sent), within a bound from `since`.
    Closing {
        peer: bool,
        us: bool,
        since: Instant,
        tasks: Vec<AbortHandle>,
    },
}

struct State {
    control: Option<SendGuard>,
    peer_settings: Option<Arc<PeerSettings>>,
    seen_control: bool,
    seen_encoder: bool,
    seen_decoder: bool,
    sessions: HashMap<u64, Slot>,
    /// QUIC accepts peer bidirectional streams in ID order. An older ID that is neither
    /// still being classified nor a session can never become a session later. This avoids
    /// retaining unbounded closed-session history on a long-lived pooled connection.
    last_peer_bidi: Option<u64>,
    classifying: HashSet<u64>,
    /// Includes answered/expired requests whose ABI handles the embedder has not released.
    /// Otherwise a stalled embedder could accumulate unlimited WT_REQUEST/CLOSED events.
    handles: Vec<Weak<ConnObj>>,
    /// Sessions that ended recently (their streams are refused with WT_SESSION_GONE).
    gone: VecDeque<u64>,
    held: Vec<(u64, Held, Instant)>,
    /// When the connection last had no session at all.
    idle_since: Instant,
    goaway: Option<u64>,
    max_push_id: Option<u64>,
    tasks: Vec<AbortHandle>,
    stopped: bool,
}

struct Classification {
    h3: Arc<H3Conn>,
    sid: u64,
}
impl Drop for Classification {
    fn drop(&mut self) {
        let absent = {
            let mut st = lock(&self.h3.state);
            st.classifying.remove(&self.sid);
            !st.sessions.contains_key(&self.sid)
        };
        if absent {
            for held in self.h3.take_held(self.sid) {
                held.reject(wt::err::WT_SESSION_GONE);
            }
        }
    }
}

/// The HTTP/3 connection under one or more sessions.
pub struct H3Conn {
    /// Its key in `H3S`.
    pub id: u64,
    pub ctx: Arc<Ctx>,
    pub conn: Connection,
    pub client: bool,
    /// A server's listener (its handle, and whether it was closed).
    listener: u64,
    listener_closed: Option<Arc<AtomicBool>>,
    request_timeout: Duration,
    state: Mutex<State>,
    settings: watch::Sender<Option<Arc<PeerSettings>>>,
    /// The close this side made of the QUIC connection (an HTTP/3 code and reason).
    local_close: Mutex<Option<(u64, Vec<u8>)>>,
}

impl H3Conn {
    /// Starts the HTTP/3 layer of an established connection: its control stream, the peer's
    /// streams, housekeeping, and the watch for the end.
    pub fn start(
        ctx: Arc<Ctx>,
        conn: Connection,
        client: bool,
        listener: u64,
        listener_closed: Option<Arc<AtomicBool>>,
        request_timeout: Option<Duration>,
    ) -> Arc<H3Conn> {
        let (settings, _) = watch::channel(None);
        let h3 = Arc::new(H3Conn {
            id: ctx::next_handle(),
            ctx,
            conn,
            client,
            listener,
            listener_closed,
            request_timeout: request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
            state: Mutex::new(State {
                control: None,
                peer_settings: None,
                seen_control: false,
                seen_encoder: false,
                seen_decoder: false,
                sessions: HashMap::new(),
                last_peer_bidi: None,
                classifying: HashSet::new(),
                handles: Vec::new(),
                gone: VecDeque::new(),
                held: Vec::new(),
                idle_since: Instant::now(),
                goaway: None,
                max_push_id: None,
                tasks: Vec::new(),
                stopped: false,
            }),
            settings,
            local_close: Mutex::new(None),
        });
        lock(&H3S).insert(h3.id, h3.clone());
        // `sbq_shutdown` closes the context before it sweeps the table: a connection that
        // starts during the sweep either is in the table for it, or sees the context closed.
        if h3.ctx.is_closed() {
            h3.close(err::H3_NO_ERROR, b"shutdown");
            lock(&H3S).remove(&h3.id);
            return h3;
        }
        let h = h3.clone();
        h3.spawn(async move { h.open_control().await });
        let h = h3.clone();
        h3.spawn(async move {
            while let Ok(recv) = h.conn.accept_uni().await {
                let g = h.clone();
                let r = Reader {
                    recv: Receive(Some(recv)),
                };
                h.spawn(g.uni(r));
            }
        });
        let h = h3.clone();
        h3.spawn(async move {
            while let Ok((send, recv)) = h.conn.accept_bi().await {
                let g = h.clone();
                let sid = stream_id(&send);
                {
                    let mut st = lock(&h.state);
                    st.last_peer_bidi = Some(sid);
                    st.classifying.insert(sid);
                }
                let classification = Classification { h3: h.clone(), sid };
                let send = SendGuard(Some(send));
                let r = Reader {
                    recv: Receive(Some(recv)),
                };
                h.spawn(g.bi(send, r, classification));
            }
        });
        let h = h3.clone();
        h3.spawn(async move { h.housekeeping().await });
        let h = h3.clone();
        // Not in `tasks`: it is what aborts them.
        rt().spawn(async move {
            let e = h.conn.closed().await;
            h.ended(&e);
        });
        h3
    }

    fn spawn<F>(&self, f: F) -> AbortHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let t = rt().spawn(f);
        let mut st = lock(&self.state);
        st.tasks.retain(|t| !t.is_finished());
        let handle = t.abort_handle();
        if st.stopped {
            handle.abort();
        } else {
            st.tasks.push(handle.clone());
        }
        handle
    }

    /// Closes the QUIC connection with an HTTP/3 code (the first close wins).
    pub fn close(&self, code: u64, reason: &[u8]) {
        {
            let mut lc = lock(&self.local_close);
            if lc.is_none() {
                *lc = Some((code, reason.to_vec()));
            }
        }
        self.conn.close(varint(code), reason);
    }

    /// A connection error this side detected.
    fn fail(&self, code: u64, why: &str) {
        self.close(code, why.as_bytes());
    }

    /// What a session reports when the QUIC connection under it ends.
    fn lost_info(&self, e: &ConnectionError) -> CloseInfo {
        let (kind, code, reason) = match e {
            ConnectionError::ApplicationClosed(a) => (
                SBQ_CLOSE_H3_REMOTE,
                a.error_code.into_inner(),
                a.reason.to_vec(),
            ),
            ConnectionError::LocallyClosed => {
                let (code, reason) = lock(&self.local_close)
                    .clone()
                    .unwrap_or((err::H3_NO_ERROR, Vec::new()));
                (SBQ_CLOSE_H3_LOCAL, code, reason)
            }
            ConnectionError::TimedOut => (SBQ_CLOSE_TIMED_OUT, 0, b"timed out".to_vec()),
            ConnectionError::Reset => (SBQ_CLOSE_RESET, 0, b"stateless reset".to_vec()),
            ConnectionError::TransportError(t) => (
                SBQ_CLOSE_TRANSPORT_LOCAL,
                u64::from(t.code),
                t.to_string().into_bytes(),
            ),
            ConnectionError::ConnectionClosed(c) => (
                SBQ_CLOSE_TRANSPORT_REMOTE,
                u64::from(c.error_code),
                c.to_string().into_bytes(),
            ),
            other => (SBQ_CLOSE_OTHER, 0, other.to_string().into_bytes()),
        };
        CloseInfo { kind, code, reason }
    }

    /// The QUIC connection ended: so did every session on it.
    fn ended(&self, e: &ConnectionError) {
        let (sessions, tasks) = {
            let mut st = lock(&self.state);
            st.stopped = true;
            let sessions: Vec<Arc<ConnObj>> = st
                .sessions
                .drain()
                .filter_map(|(_, s)| match s {
                    Slot::Pending(w) | Slot::Live(w) => w.upgrade(),
                    Slot::Closing { .. } => None,
                })
                .collect();
            for (_, held, _) in st.held.drain(..) {
                held.reject(wt::err::WT_SESSION_GONE);
            }
            st.control = None;
            (sessions, std::mem::take(&mut st.tasks))
        };
        let info = self.lost_info(e);
        for o in sessions {
            if let Some(wt) = o.wt.as_ref() {
                let mut st = lock(&wt.st);
                st.phase = Phase::Ended;
                st.reader.take();
                st.writer.take();
            }
            o.finish(info.clone());
            streams_gone(&o);
            for task in lock(&o.tasks).drain(..) {
                task.abort();
            }
        }
        for t in tasks {
            t.abort();
        }
        lock(&H3S).remove(&self.id);
    }

    async fn open_control(self: Arc<Self>) {
        let Ok(s) = self.conn.open_uni().await else {
            return;
        };
        let mut s = SendGuard(Some(s));
        if !matches!(
            within(
                self.request_timeout,
                s.write_all(&control_stream_start(self.client))
            )
            .await,
            Some(Ok(()))
        ) {
            self.fail(
                err::H3_CLOSED_CRITICAL_STREAM,
                "cannot write the control stream",
            );
            return;
        }
        // A peer stopping our control stream is also a critical-stream failure.
        let stopped = s.stopped();
        lock(&self.state).control = Some(s);
        if stopped.await.is_ok() {
            self.fail(
                err::H3_CLOSED_CRITICAL_STREAM,
                "our control stream was stopped",
            );
        }
    }

    /// The peer's SETTINGS, once they arrived; None when the connection ended first.
    async fn peer_settings(&self) -> Option<Arc<PeerSettings>> {
        let mut rx = self.settings.subscribe();
        tokio::select! {
            r = rx.wait_for(Option::is_some) => r.ok().and_then(|s| s.clone()),
            _ = self.conn.closed() => None,
        }
    }

    // --- The peer's unidirectional streams.

    async fn uni(self: Arc<Self>, mut r: Reader) {
        // No deadline on the stream type: a peer sends it when it pleases. quiche (Chrome) sends
        // the type of a QPACK stream with its first instruction, and the stream a peer opens opens
        // the lower ones of its kind with it, typeless; stopping a peer's QPACK stream is fatal to
        // the connection (Chrome closes it, "STOP_SENDING received for QPACK send stream"). The
        // unidirectional stream limit (H3_UNI_STREAMS) bounds what such streams hold, and they
        // end with the connection.
        let ty = match r.varint().await {
            Ok(Some(t)) => t,
            // Nothing to keep, but stopped explicitly rather than dropped (quinn stops a dropped
            // stream with 0).
            _ => {
                abort(None, Some(&mut r.recv), err::H3_STREAM_CREATION_ERROR);
                return;
            }
        };
        match ty {
            stream_type::CONTROL => {
                if std::mem::replace(&mut lock(&self.state).seen_control, true) {
                    return self.fail(err::H3_STREAM_CREATION_ERROR, "a second control stream");
                }
                if let Err(e) = self.control(&mut r).await {
                    self.critical(e);
                }
            }
            stream_type::QPACK_ENCODER | stream_type::QPACK_DECODER => {
                let encoder = ty == stream_type::QPACK_ENCODER;
                {
                    let mut st = lock(&self.state);
                    let seen = if encoder {
                        &mut st.seen_encoder
                    } else {
                        &mut st.seen_decoder
                    };
                    if std::mem::replace(seen, true) {
                        drop(st);
                        return self.fail(err::H3_STREAM_CREATION_ERROR, "a second QPACK stream");
                    }
                }
                let mut check = h3::DecoderStreamCheck::default();
                loop {
                    match r.recv.read_chunk(4096, true).await {
                        Ok(Some(c)) => {
                            let ok = if encoder {
                                h3::check_encoder_stream(&c.bytes)
                            } else {
                                check.feed(&c.bytes)
                            };
                            if let Err(code) = ok {
                                return self.fail(code, "a QPACK instruction this side refuses");
                            }
                        }
                        Ok(None) => return self.critical(Fail::Fin),
                        Err(e) => return self.critical(read_fail(e)),
                    }
                }
            }
            stream_type::PUSH => {
                if self.client {
                    // No MAX_PUSH_ID was ever sent: every push ID is beyond it.
                    self.fail(err::H3_ID_ERROR, "a push stream")
                } else {
                    self.fail(err::H3_STREAM_CREATION_ERROR, "a push stream from a client")
                }
            }
            stream_type::WEBTRANSPORT => match within(self.request_timeout, r.varint()).await {
                Some(Ok(Some(sid))) => self.route(sid, Held::Uni(r.recv.take())),
                _ => abort(None, Some(&mut r.recv), err::H3_STREAM_CREATION_ERROR),
            },
            // Reserved and unknown types: abort reading (RFC 9114 section 6.2).
            t => {
                trace!("peer unidirectional stream of type {t:#x}: refused");
                abort(None, Some(&mut r.recv), err::H3_STREAM_CREATION_ERROR)
            }
        }
    }

    /// A critical stream (control, QPACK) ended: a connection error, unless the connection is
    /// ending anyway.
    fn critical(&self, e: Fail) {
        match e {
            Fail::Lost => {}
            Fail::Conn(code, why) => self.fail(code, why),
            _ => self.fail(err::H3_CLOSED_CRITICAL_STREAM, "a critical stream closed"),
        }
    }

    /// The peer's control stream: SETTINGS first, then GOAWAY, MAX_PUSH_ID and the frames to
    /// ignore. Returns how it ended (always an error: the stream lasts as long as the
    /// connection).
    async fn control(&self, r: &mut Reader) -> Result<(), Fail> {
        let (t, len) = r.frame_header().await?.ok_or(Fail::Fin)?;
        if t != frame::SETTINGS {
            return Err(Fail::Conn(
                err::H3_MISSING_SETTINGS,
                "the first frame is not SETTINGS",
            ));
        }
        if len > MAX_SETTINGS_FRAME {
            return Err(Fail::Conn(
                err::H3_EXCESSIVE_LOAD,
                "a SETTINGS frame too large",
            ));
        }
        let payload = r.take(len).await?;
        let settings = h3::parse_settings(&payload).map_err(|code| Fail::Conn(code, "SETTINGS"))?;
        trace!(
            "{} {}: peer SETTINGS {}",
            if self.client { "client" } else { "server" },
            self.conn.remote_address(),
            settings
                .order
                .iter()
                .map(|(k, v)| format!("{k:#x}={v}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if settings.datagrams() && self.conn.max_datagram_size().is_none() {
            return Err(Fail::Conn(
                err::H3_SETTINGS_ERROR,
                "H3_DATAGRAM without the datagram transport parameter",
            ));
        }
        let settings = Arc::new(settings);
        lock(&self.state).peer_settings = Some(settings.clone());
        self.settings.send_replace(Some(settings));
        loop {
            tokio::task::yield_now().await;
            let (t, len) = r.frame_header().await?.ok_or(Fail::Fin)?;
            match t {
                frame::GOAWAY => {
                    let id = r.varint_payload(len).await?;
                    if self.client && id % 4 != 0 {
                        return Err(Fail::Conn(
                            err::H3_ID_ERROR,
                            "a GOAWAY with a stream ID that is not a request's",
                        ));
                    }
                    let previous = lock(&self.state).goaway.replace(id);
                    if previous.is_some_and(|p| id > p) {
                        return Err(Fail::Conn(err::H3_ID_ERROR, "a GOAWAY with a larger ID"));
                    }
                    self.goaway();
                }
                frame::MAX_PUSH_ID => {
                    if self.client {
                        return Err(Fail::Conn(
                            err::H3_FRAME_UNEXPECTED,
                            "MAX_PUSH_ID to a client",
                        ));
                    }
                    let id = r.varint_payload(len).await?;
                    let previous = lock(&self.state).max_push_id.replace(id);
                    if previous.is_some_and(|p| id < p) {
                        return Err(Fail::Conn(err::H3_ID_ERROR, "a smaller MAX_PUSH_ID"));
                    }
                }
                frame::CANCEL_PUSH => {
                    r.varint_payload(len).await?;
                    return Err(Fail::Conn(
                        err::H3_ID_ERROR,
                        "CANCEL_PUSH for an unpromised push",
                    ));
                }
                frame::WT_STREAM => {
                    return Err(Fail::Conn(
                        err::H3_FRAME_ERROR,
                        "WT_STREAM on the control stream",
                    ))
                }
                frame::DATA | frame::HEADERS | frame::SETTINGS | frame::PUSH_PROMISE => {
                    return Err(Fail::Conn(
                        err::H3_FRAME_UNEXPECTED,
                        "a frame the control stream does not carry",
                    ))
                }
                t if frame::is_reserved_h2(t) => {
                    return Err(Fail::Conn(err::H3_FRAME_UNEXPECTED, "an HTTP/2 frame type"))
                }
                _ => r.skip(len).await?,
            }
        }
    }

    /// An HTTP/3 GOAWAY: every session of the connection is draining.
    fn goaway(&self) {
        let sessions: Vec<Arc<ConnObj>> = lock(&self.state)
            .sessions
            .values()
            .filter_map(|s| match s {
                Slot::Pending(w) | Slot::Live(w) => w.upgrade(),
                Slot::Closing { .. } => None,
            })
            .collect();
        for o in sessions {
            if self.client
                && o.wt.as_ref().is_some_and(|w| {
                    let connecting = lock(&w.st).phase == Phase::Connecting;
                    connecting
                        && w.sid()
                            .is_some_and(|sid| lock(&self.state).goaway.is_some_and(|id| sid >= id))
                })
            {
                // One client session per connection; closing it also wakes the response reader.
                if let Some(h3) = o.wt.as_ref().and_then(WtSession::h3) {
                    connect_failed(
                        &o,
                        Some(&h3),
                        CloseInfo {
                            kind: SBQ_CLOSE_H3_REMOTE,
                            code: err::H3_REQUEST_REJECTED,
                            reason: b"GOAWAY rejected the CONNECT request".to_vec(),
                        },
                    );
                }
            } else {
                post_draining(&o);
            }
        }
    }

    // --- The peer's bidirectional streams.

    async fn bi(
        self: Arc<Self>,
        mut send: SendGuard,
        mut r: Reader,
        _classification: Classification,
    ) {
        let started = Instant::now();
        let first = match within(
            self.request_timeout.saturating_sub(started.elapsed()),
            r.varint(),
        )
        .await
        {
            Some(Ok(Some(t))) => t,
            Some(Err(Fail::Fin)) => {
                return self.fail(err::H3_FRAME_ERROR, "truncated stream frame type");
            }
            // FIN, a reset, or nothing in time: nothing to keep, both directions ended explicitly
            // rather than dropped.
            _ => {
                return abort(
                    Some(&mut send),
                    Some(&mut r.recv),
                    err::H3_REQUEST_INCOMPLETE,
                );
            }
        };
        if first == frame::WT_STREAM {
            match within(
                self.request_timeout.saturating_sub(started.elapsed()),
                r.varint(),
            )
            .await
            {
                Some(Ok(Some(sid))) => self.route(sid, Held::Bi(send.take(), r.recv.take())),
                _ => abort(
                    Some(&mut send),
                    Some(&mut r.recv),
                    err::H3_REQUEST_INCOMPLETE,
                ),
            }
            return;
        }
        if self.client {
            return self.fail(
                err::H3_STREAM_CREATION_ERROR,
                "a server-initiated stream that is not WebTransport",
            );
        }
        self.request(first, send, r, started).await;
    }

    /// Routes a WebTransport data stream to its session, holds it until the session exists, or
    /// refuses it.
    fn route(self: &Arc<Self>, sid: u64, s: Held) {
        if sid % 4 != 0 {
            s.reject(err::H3_ID_ERROR);
            return self.fail(
                err::H3_ID_ERROR,
                "a session ID that is not a client-initiated bidirectional stream",
            );
        }
        enum Do {
            Deliver(Arc<ConnObj>, Held),
            Reject(Held, u64),
            Held,
        }
        let action = {
            let mut st = lock(&self.state);
            match st.sessions.get(&sid) {
                Some(Slot::Live(w)) => match w.upgrade() {
                    Some(o) => Do::Deliver(o, s),
                    None => Do::Reject(s, wt::err::WT_SESSION_GONE),
                },
                Some(Slot::Closing { .. }) => Do::Reject(s, wt::err::WT_SESSION_GONE),
                _ if st.stopped => Do::Reject(s, wt::err::WT_SESSION_GONE),
                None if st.gone.contains(&sid)
                    || (!self.client
                        && st.last_peer_bidi.is_some_and(|last| sid <= last)
                        && !st.classifying.contains(&sid)) =>
                {
                    Do::Reject(s, wt::err::WT_SESSION_GONE)
                }
                // Pending, or not seen yet.
                _ => {
                    if st.held.len() >= MAX_BUFFERED_STREAMS {
                        Do::Reject(s, wt::err::WT_BUFFERED_STREAM_REJECTED)
                    } else {
                        st.held.push((sid, s, Instant::now()));
                        Do::Held
                    }
                }
            }
        };
        match action {
            Do::Deliver(o, s) => deliver(&o, s),
            Do::Reject(s, code) => s.reject(code),
            Do::Held => {}
        }
    }

    /// The streams held for `sid`.
    fn take_held(&self, sid: u64) -> Vec<Held> {
        let mut st = lock(&self.state);
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut st.held)
            .into_iter()
            .partition(|(s, _, _)| *s == sid);
        st.held = rest;
        mine.into_iter().map(|(_, h, _)| h).collect()
    }

    /// Reads a request until its HEADERS.
    async fn read_request(
        &self,
        first: u64,
        r: &mut Reader,
        started: Instant,
    ) -> Result<Request, Fail> {
        let headers = within(
            self.request_timeout.saturating_sub(started.elapsed()),
            async {
                let mut t = first;
                let mut skipped = 0u64;
                loop {
                    let len = r
                        .varint()
                        .await
                        .map_err(frame_failure)?
                        .ok_or_else(|| frame_failure(Fail::Fin))?;
                    match t {
                        frame::HEADERS => {
                            if len > MAX_FIELD_SECTION as u64 {
                                return Err(Fail::Stream(err::H3_EXCESSIVE_LOAD));
                            }
                            return r.take(len).await;
                        }
                        frame::DATA => {
                            return Err(Fail::Conn(err::H3_FRAME_UNEXPECTED, "DATA before HEADERS"))
                        }
                        frame::PUSH_PROMISE => {
                            return Err(Fail::Conn(
                                err::H3_FRAME_UNEXPECTED,
                                "PUSH_PROMISE from a client",
                            ))
                        }
                        frame::WT_STREAM => {
                            return Err(Fail::Conn(
                                err::H3_FRAME_ERROR,
                                "WT_STREAM inside a request",
                            ))
                        }
                        t if forbidden_on_request(t) => {
                            return Err(Fail::Conn(
                                err::H3_FRAME_UNEXPECTED,
                                "unexpected frame on a request",
                            ))
                        }
                        _ => {
                            skipped = skipped.saturating_add(len).saturating_add(2);
                            if skipped > MAX_SKIP_BEFORE_HEADERS {
                                return Err(Fail::Stream(err::H3_EXCESSIVE_LOAD));
                            }
                            r.skip(len).await?;
                        }
                    }
                    tokio::task::yield_now().await;
                    t = r.varint().await.map_err(frame_failure)?.ok_or(Fail::Fin)?;
                }
            },
        )
        .await
        .ok_or(Fail::Stream(err::H3_REQUEST_INCOMPLETE))??;
        let fields = match h3::decode_field_section(&headers, MAX_FIELD_SECTION) {
            Ok(f) => f,
            Err(FieldError::Qpack) => {
                return Err(Fail::Conn(
                    err::QPACK_DECOMPRESSION_FAILED,
                    "a field section",
                ))
            }
            Err(FieldError::TooLarge) => return Err(Fail::Stream(err::H3_EXCESSIVE_LOAD)),
        };
        trace!(
            "server {}: request {}",
            self.conn.remote_address(),
            fields_text(&fields)
        );
        parse_request(&fields).map_err(|_| Fail::Stream(err::H3_MESSAGE_ERROR))
    }

    /// Handles a request stream: a WebTransport request becomes a pending session and a
    /// WT_REQUEST event; any other request is answered 404, and a malformed one refused.
    async fn request(
        self: Arc<Self>,
        first: u64,
        mut send: SendGuard,
        mut r: Reader,
        started: Instant,
    ) {
        let request = match self.read_request(first, &mut r, started).await {
            Ok(req) => req,
            Err(Fail::Conn(code, why)) => return self.fail(code, why),
            Err(Fail::Stream(code)) => {
                return abort(Some(&mut send), Some(&mut r.recv), code);
            }
            Err(Fail::Fin) => return abort(Some(&mut send), None, err::H3_REQUEST_INCOMPLETE),
            Err(Fail::Reset(_)) => return abort(Some(&mut send), None, err::H3_REQUEST_CANCELLED),
            Err(Fail::Lost) => return,
        };
        if !request.webtransport() {
            return answer(send, r, 404, self.request_timeout).await;
        }
        // The draft: no WebTransport request is processed before the client's SETTINGS.
        let Some(settings) = within(
            self.request_timeout.saturating_sub(started.elapsed()),
            self.peer_settings(),
        )
        .await
        .flatten() else {
            return abort(Some(&mut send), Some(&mut r.recv), err::H3_REQUEST_REJECTED);
        };
        if !settings.webtransport() {
            // Malformed, as the draft has it for a client whose SETTINGS lack WebTransport.
            return abort(Some(&mut send), Some(&mut r.recv), err::H3_MESSAGE_ERROR);
        }
        if self
            .listener_closed
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
        {
            return answer(send, r, 503, self.request_timeout).await;
        }
        // The ABI represents protocols with a nonzero one-byte length. Refuse an offer
        // outside that bound instead of silently turning it into "no protocol offered".
        if request
            .protocols
            .as_ref()
            .is_some_and(|p| p.iter().any(|p| p.is_empty() || p.len() > 255))
        {
            return answer(send, r, 400, self.request_timeout).await;
        }
        let version = if request.draft02 || settings.draft07_sessions() == 0 {
            VERSION_DRAFT02
        } else {
            VERSION_DRAFT07
        };
        let sid = stream_id(&send);
        let session = WtSession::new(false, Phase::Pending);
        *lock(&session.h3) = Some(self.clone());
        *lock(&session.id) = Some(sid);
        let o = ConnObj::new_session(self.ctx.clone(), session, Some(self.conn.clone()));
        {
            let mut st = lock(&self.state);
            let open = st
                .sessions
                .values()
                .filter(|s| !matches!(s, Slot::Closing { .. }))
                .count() as u64;
            st.handles.retain(|w| w.strong_count() > 0);
            if st.stopped || open >= MAX_SESSIONS || st.handles.len() >= MAX_SESSIONS as usize {
                drop(st);
                return abort(Some(&mut send), Some(&mut r.recv), err::H3_REQUEST_REJECTED);
            }
            st.sessions.insert(sid, Slot::Pending(Arc::downgrade(&o)));
            st.handles.push(Arc::downgrade(&o));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let wt = o.wt.as_ref().expect("a session");
            let mut st = lock(&wt.st);
            st.request = Some(request);
            st.version = version;
            st.writer = Some(tx);
            st.reader = Some(r);
        }
        let task = self.spawn(writer(Arc::downgrade(&o), self.clone(), sid, send, rx));
        lock(&o.wt.as_ref().expect("a session").st).writer_task = Some(task);
        lock(&CONNS).insert(o.handle, o.clone());
        if o.ctx.is_closed() {
            if let Some(o) = lock(&CONNS).remove(&o.handle) {
                o.release();
            }
            return;
        }
        o.ctx.post(
            SBQ_EV_WT_REQUEST,
            o.handle,
            self.listener as i64,
            i64::from(version),
        );
        // Not answered in time: refused 503.
        let weak = Arc::downgrade(&o);
        let deadline = self.request_timeout;
        let timer = rt().spawn(async move {
            tokio::time::sleep(deadline).await;
            if let Some(o) = weak.upgrade() {
                if refuse(&o, 503) {
                    o.finish(CloseInfo {
                        kind: SBQ_CLOSE_REFUSED,
                        code: 503,
                        reason: b"the request was not answered in time".to_vec(),
                    });
                }
            }
        });
        o.add_task(timer.abort_handle());
    }

    /// The session `sid` is live (its slot was pending): deliver what was held for it.
    fn set_live(&self, sid: u64, o: &Arc<ConnObj>) {
        {
            let mut st = lock(&self.state);
            if st.stopped {
                return;
            }
            // An ended session must not be revived by a concurrent accept or handshake.
            if !matches!(st.sessions.get(&sid), Some(Slot::Pending(_))) {
                return;
            }
            st.sessions.insert(sid, Slot::Live(Arc::downgrade(o)));
        }
        for s in self.take_held(sid) {
            deliver(o, s);
        }
    }

    /// The session `sid` ended without being established (refused, abandoned): it is
    /// forgotten, and what was held for it refused.
    fn forget(&self, sid: u64) {
        {
            let mut st = lock(&self.state);
            st.sessions.remove(&sid);
            remember_gone(&mut st, sid);
            if st.sessions.is_empty() {
                st.idle_since = Instant::now();
            }
        }
        for s in self.take_held(sid) {
            s.reject(wt::err::WT_SESSION_GONE);
        }
    }

    /// The session `sid` ended after it was established: its CONNECT stream is closing.
    fn closing(self: &Arc<Self>, sid: u64, o: &ConnObj) {
        let tasks = {
            let st = lock(&o.wt.as_ref().expect("a session").st);
            st.writer_task
                .iter()
                .chain(st.reader_task.iter())
                .cloned()
                .collect()
        };
        {
            let mut st = lock(&self.state);
            if st.stopped {
                return;
            }
            st.sessions.insert(
                sid,
                Slot::Closing {
                    peer: false,
                    us: false,
                    since: Instant::now(),
                    tasks,
                },
            );
            remember_gone(&mut st, sid);
        }
        for s in self.take_held(sid) {
            s.reject(wt::err::WT_SESSION_GONE);
        }
        self.check_close();
        let h = self.clone();
        self.spawn(async move {
            tokio::time::sleep(h.close_wait()).await;
            h.check_close();
        });
    }

    /// Progress of a closing CONNECT stream.
    fn closed_by(&self, sid: u64, by_peer: bool) {
        {
            let mut st = lock(&self.state);
            if let Some(Slot::Closing { peer, us, .. }) = st.sessions.get_mut(&sid) {
                if by_peer {
                    *peer = true;
                } else {
                    *us = true;
                }
            }
        }
        self.check_close();
    }

    fn close_wait(&self) -> Duration {
        (self.conn.rtt() * 3).clamp(MIN_CLOSE_WAIT, MAX_CLOSE_WAIT)
    }

    /// Closes the QUIC connection once its last session has finished closing: the draft's
    /// advice, so that the close of a session reaches the peer before the connection's. A client
    /// closes it once both sides closed the CONNECT stream (or the wait for that is over). A
    /// server leaves it to the client for the close wait: Chrome reports a session closed only
    /// after it sent its FIN in answer, and a connection close that arrives first fails the
    /// session instead (the page sees "Connection lost.", whatever the close said), while it
    /// closes the connection itself once it has reported the close.
    fn check_close(&self) {
        let wait = self.close_wait();
        let (close, tasks) = {
            let mut st = lock(&self.state);
            let mut done = Vec::new();
            for (sid, s) in &st.sessions {
                if let Slot::Closing {
                    peer, us, since, ..
                } = s
                {
                    if (self.client && *peer && *us) || since.elapsed() >= wait {
                        done.push(*sid);
                    }
                }
            }
            let closed_one = !done.is_empty();
            let mut tasks = Vec::new();
            for sid in done {
                if let Some(Slot::Closing { tasks: ended, .. }) = st.sessions.remove(&sid) {
                    tasks.extend(ended);
                }
            }
            if st.sessions.is_empty() && closed_one {
                st.idle_since = Instant::now();
            }
            (closed_one && st.sessions.is_empty(), tasks)
        };
        for task in tasks {
            task.abort();
        }
        if close {
            self.close(err::H3_NO_ERROR, b"");
        }
    }

    /// Expires held streams and closing waits; closes a connection that has had no session for
    /// the request timeout.
    async fn housekeeping(self: Arc<Self>) {
        let tick =
            (self.request_timeout / 4).clamp(Duration::from_millis(50), Duration::from_secs(1));
        loop {
            tokio::time::sleep(tick).await;
            if self.conn.close_reason().is_some() {
                return;
            }
            let (expired, idle) = {
                let mut st = lock(&self.state);
                let timeout = self.request_timeout;
                let (old, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut st.held)
                    .into_iter()
                    .partition(|(_, _, at)| at.elapsed() >= timeout);
                st.held = keep;
                let idle =
                    !self.client && st.sessions.is_empty() && st.idle_since.elapsed() >= timeout;
                (old, idle)
            };
            for (_, s, _) in expired {
                s.reject(wt::err::WT_BUFFERED_STREAM_REJECTED);
            }
            self.check_close();
            if idle {
                self.close(err::H3_NO_ERROR, b"no session");
            }
        }
    }
}

/// Answers a request that is not a session: the response, FIN, and the rest of the request
/// left unread.
async fn answer(mut send: SendGuard, mut r: Reader, status: u16, timeout: Duration) {
    if !matches!(
        within(
            timeout,
            send.write_all(&response_frame(status, VERSION_DRAFT07, None))
        )
        .await,
        Some(Ok(()))
    ) {
        return;
    }
    if send.finish().is_ok() {
        drop(send.take());
    }
    let _ = r.recv.stop(varint(err::H3_NO_ERROR));
}

fn remember_gone(st: &mut State, sid: u64) {
    if st.gone.len() >= 64 {
        st.gone.pop_front();
    }
    st.gone.push_back(sid);
}

/// Hands a peer stream to its session (STREAM or UNI_STREAM), or refuses it if the session was
/// released meanwhile.
fn deliver(o: &Arc<ConnObj>, s: Held) {
    let (new, announce) = match s {
        Held::Bi(send, recv) => (
            NewStream {
                send: Some(send),
                recv,
                wt: true,
                prefix: Vec::new(),
            },
            SBQ_EV_STREAM,
        ),
        Held::Uni(recv) => (
            NewStream {
                send: None,
                recv,
                wt: true,
                prefix: Vec::new(),
            },
            SBQ_EV_UNI_STREAM,
        ),
    };
    if let Err(mut s) = stream::insert(o, new, Some(announce)) {
        abort(s.send.as_mut(), Some(&mut s.recv), wt::err::WT_SESSION_GONE);
    }
}

fn post_draining(o: &Arc<ConnObj>) {
    let Some(wt) = o.wt.as_ref() else { return };
    {
        let mut st = lock(&wt.st);
        if st.draining_posted || st.phase == Phase::Ended {
            return;
        }
        st.draining_posted = true;
    }
    o.ctx.post(SBQ_EV_DRAINING, o.handle, 0, 0);
}

/// The session's streams.
fn session_streams(o: &ConnObj) -> Vec<Arc<StreamObj>> {
    let ids: Vec<u64> = lock(&o.streams)
        .as_ref()
        .map(|s| s.iter().copied().collect())
        .unwrap_or_default();
    ids.into_iter().filter_map(|id| get(&STREAMS, id)).collect()
}

/// Resets and stops every stream of the session with WT_SESSION_GONE.
fn streams_gone(o: &ConnObj) {
    for s in session_streams(o) {
        s.session_gone();
    }
}

/// A session's writer task: writes its CONNECT stream in order, and reports this side's close
/// of it.
async fn writer(
    o: Weak<ConnObj>,
    h3: Arc<H3Conn>,
    sid: u64,
    mut send: SendGuard,
    mut rx: mpsc::UnboundedReceiver<Write>,
) {
    let mut failed = false;
    loop {
        let w = tokio::select! {
            w = rx.recv() => w,
            stopped = send.stopped() => { failed = stopped.is_ok(); None },
        };
        let Some(w) = w else { break };
        match w {
            Write::Bytes(b) => {
                if !matches!(
                    within(h3.request_timeout, send.write_all(&b)).await,
                    Some(Ok(()))
                ) {
                    failed = true;
                    break;
                }
            }
            Write::Close(b, streams, notification) => {
                // The close wait, and the slot's closing timer (which cancels this task), cover
                // a peer that gives no send credit, never acknowledges the FIN, or leaves
                // CONNECT open forever.
                let wait = h3.close_wait();
                let started = Instant::now();
                let finished = matches!(
                    within(wait, async {
                        send.write_all(&b).await.ok()?;
                        send.finish().ok()
                    })
                    .await,
                    Some(Some(()))
                );
                if finished {
                    // Out of the guard: a FIN sent stays sent. Resetting the stream now would
                    // only discard a close still in flight, which quinn retransmits while the
                    // connection lasts.
                    let fin = send.take();
                    let _ = within(wait.saturating_sub(started.elapsed()), fin.stopped()).await;
                }
                drop(streams);
                drop(notification);
                break;
            }
            Write::Finish => {
                if send.finish().is_ok() {
                    let fin = send.take();
                    let _ = within(h3.close_wait(), fin.stopped()).await;
                }
                break;
            }
            Write::Reset(code) => {
                let _ = send.reset(varint(code));
                // A reset has no stopped() acknowledgement to wait for. Allow it a flight
                // before the final session takes down the QUIC connection beneath it.
                tokio::time::sleep(h3.close_wait()).await;
                break;
            }
        }
    }
    // A failed writer must not leave a session live waiting for a read that may never end.
    // Dropping rx also runs the deferred resets of any close queued behind the failed write.
    drop(rx);
    if failed {
        if let Some(o) = o.upgrade() {
            let info = CloseInfo {
                kind: SBQ_CLOSE_SESSION_RESET,
                code: 0,
                reason: b"the CONNECT send direction ended".to_vec(),
            };
            let phase = lock(&o.wt.as_ref().expect("a session").st).phase;
            match phase {
                Phase::Live => end_session(&o, info, None),
                Phase::Pending => {
                    let mut st = lock(&o.wt.as_ref().expect("a session").st);
                    st.phase = Phase::Ended;
                    st.reader.take();
                    drop(st);
                    h3.forget(sid);
                    o.finish(info);
                }
                // A rejection may stop the request body before its response arrives.
                // The response reader (and handshake deadline) decides the connect outcome.
                Phase::Connecting => {}
                Phase::Ended => {}
            }
        }
    }
    h3.closed_by(sid, false);
}

/// A live session's capsule task: reads its CONNECT stream until the session ends, and on
/// until the peer has closed the stream.
async fn capsules(o: Weak<ConnObj>, h3: Arc<H3Conn>, sid: u64, r: Reader) {
    let mut c = Capsules {
        r,
        left: 0,
        trailers: false,
    };
    loop {
        let next = c.next().await;
        let Some(o) = o.upgrade() else {
            // Released: keep reading to see the peer close the stream.
            match next {
                Ok(Some(_)) => continue,
                _ => break,
            }
        };
        let live =
            o.wt.as_ref()
                .is_some_and(|w| lock(&w.st).phase == Phase::Live);
        match next {
            Ok(Some(Capsule::Close(code, message))) if live => {
                end_session(
                    &o,
                    CloseInfo {
                        kind: SBQ_CLOSE_APP_REMOTE,
                        code: u64::from(code),
                        reason: message,
                    },
                    None,
                );
                let extra = if c.left > 0 {
                    true
                } else {
                    matches!(
                        within(h3.close_wait(), c.r.recv.read(&mut [0u8; 1])).await,
                        Some(Ok(Some(_)))
                    )
                };
                let last = if extra {
                    let _ = c.r.recv.stop(varint(err::H3_MESSAGE_ERROR));
                    Write::Reset(err::H3_MESSAGE_ERROR)
                } else {
                    Write::Finish
                };
                if let Some(tx) = lock(&o.wt.as_ref().expect("a session").st).writer.as_ref() {
                    let _ = tx.send(last);
                }
                break;
            }
            Ok(Some(Capsule::Drain)) if live => post_draining(&o),
            Ok(Some(Capsule::Forbidden)) if live => {
                abort_session(
                    &o,
                    &mut c.r,
                    err::H3_MESSAGE_ERROR,
                    "a capsule HTTP/3 forbids",
                );
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                if live {
                    remote_close(&o, 0, b"");
                }
                break;
            }
            Err(Fail::Reset(code)) => {
                if live {
                    end_session(
                        &o,
                        CloseInfo {
                            kind: SBQ_CLOSE_SESSION_RESET,
                            code,
                            reason: b"the peer reset the session's CONNECT stream".to_vec(),
                        },
                        Some(Write::Reset(err::H3_REQUEST_CANCELLED)),
                    );
                }
                break;
            }
            Err(Fail::Lost) => return,
            Err(Fail::Conn(code, why)) => {
                h3.fail(code, why);
                return;
            }
            Err(e @ (Fail::Stream(_) | Fail::Fin)) if live => {
                let code = match e {
                    Fail::Stream(code) => code,
                    _ => err::H3_MESSAGE_ERROR,
                };
                abort_session(&o, &mut c.r, code, "a malformed capsule");
                break;
            }
            Err(_) => {
                let _ = c.r.recv.stop(varint(err::H3_MESSAGE_ERROR));
                break;
            }
        }
    }
    h3.closed_by(sid, true);
}

/// Ends a live session: CLOSED with `info`, its streams gone, its CONNECT stream finished or
/// reset (`last`), and its slot closing.
fn end_session(o: &Arc<ConnObj>, info: CloseInfo, last: Option<Write>) {
    let Some(wt) = o.wt.as_ref() else { return };
    let tx = {
        let mut st = lock(&wt.st);
        if st.phase != Phase::Live {
            return;
        }
        st.phase = Phase::Ended;
        st.writer.clone()
    };
    if let (Some(h3), Some(sid)) = (wt.h3(), wt.sid()) {
        h3.closing(sid, o);
    }
    if let (Some(tx), Some(w)) = (tx, last) {
        let _ = tx.send(w);
    }
    for task in lock(&o.tasks).drain(..) {
        task.abort();
    }
    streams_gone(o);
    o.finish(info);
}

fn remote_close(o: &Arc<ConnObj>, code: u32, message: &[u8]) {
    end_session(
        o,
        CloseInfo {
            kind: SBQ_CLOSE_APP_REMOTE,
            code: u64::from(code),
            reason: message.to_vec(),
        },
        Some(Write::Finish),
    );
}

/// A protocol error on a session's CONNECT stream: reset it, and end the session as this side's
/// HTTP/3 layer ended it.
fn abort_session(o: &Arc<ConnObj>, r: &mut Reader, code: u64, why: &str) {
    let _ = r.recv.stop(varint(code));
    end_session(
        o,
        CloseInfo {
            kind: SBQ_CLOSE_H3_LOCAL,
            code,
            reason: why.as_bytes().to_vec(),
        },
        Some(Write::Reset(code)),
    );
}

// ---------------------------------------------------------------------------------------------
// The calls of the ABI on sessions.

/// A client's request: where, from where, and the protocols to offer.
pub struct ClientRequest {
    pub authority: Vec<u8>,
    pub path: Vec<u8>,
    pub origin: Option<Vec<u8>>,
    pub protocols: Vec<Vec<u8>>,
}

fn response_read_failure(h3: &H3Conn, e: Fail) -> CloseInfo {
    match e {
        Fail::Conn(code, why) => {
            h3.fail(code, why);
            h3.lost_info(&ConnectionError::LocallyClosed)
        }
        Fail::Reset(code) => CloseInfo {
            kind: SBQ_CLOSE_SESSION_RESET,
            code,
            reason: b"the peer reset the CONNECT response".to_vec(),
        },
        _ => h3
            .conn
            .close_reason()
            .map(|e| h3.lost_info(&e))
            .unwrap_or(CloseInfo {
                kind: SBQ_CLOSE_SESSION_RESET,
                code: 0,
                reason: b"the CONNECT response ended".to_vec(),
            }),
    }
}

/// The client side of a session, once its QUIC connection is up: the server's SETTINGS, the
/// CONNECT request, the response. CONNECTED is posted on a 2xx; anything else is the CLOSED
/// info to report.
pub async fn client_session(
    o: &Arc<ConnObj>,
    h3: &Arc<H3Conn>,
    req: ClientRequest,
) -> Result<(), CloseInfo> {
    let wt = o.wt.as_ref().expect("a session");
    let lost = |e: Option<ConnectionError>| match e {
        Some(e) => h3.lost_info(&e),
        None => CloseInfo {
            kind: SBQ_CLOSE_OTHER,
            code: 0,
            reason: b"the connection ended".to_vec(),
        },
    };
    let Some(settings) = h3.peer_settings().await else {
        return Err(lost(h3.conn.close_reason()));
    };
    if !settings.webtransport()
        || (!settings.draft02() && settings.get(setting::ENABLE_CONNECT_PROTOCOL) != Some(1))
    {
        let why = b"the server does not support WebTransport";
        h3.close(wt::err::WT_REQUIREMENTS_NOT_MET, why);
        return Err(CloseInfo {
            kind: SBQ_CLOSE_H3_LOCAL,
            code: wt::err::WT_REQUIREMENTS_NOT_MET,
            reason: why.to_vec(),
        });
    }
    if lock(&h3.state).goaway.is_some() {
        return Err(CloseInfo {
            kind: SBQ_CLOSE_H3_REMOTE,
            code: err::H3_REQUEST_REJECTED,
            reason: b"GOAWAY before the CONNECT request".to_vec(),
        });
    }
    let (send, recv) = h3.conn.open_bi().await.map_err(|e| lost(Some(e)))?;
    let sid = stream_id(&send);
    *lock(&wt.id) = Some(sid);
    {
        let mut st = lock(&h3.state);
        if st.goaway.is_some() || st.stopped {
            drop(st);
            let mut send = send;
            let mut recv = recv;
            abort(Some(&mut send), Some(&mut recv), err::H3_REQUEST_REJECTED);
            return Err(CloseInfo {
                kind: SBQ_CLOSE_H3_REMOTE,
                code: err::H3_REQUEST_REJECTED,
                reason: b"GOAWAY before the CONNECT request".to_vec(),
            });
        }
        st.sessions.insert(sid, Slot::Pending(Arc::downgrade(o)));
    }
    let (tx, rx) = mpsc::unbounded_channel();
    lock(&wt.st).writer = Some(tx.clone());
    let task = h3.spawn(writer(
        Arc::downgrade(o),
        h3.clone(),
        sid,
        SendGuard(Some(send)),
        rx,
    ));
    lock(&wt.st).writer_task = Some(task);
    // The request.
    let protocols = (!req.protocols.is_empty()).then(|| wt::sf_string_list(&req.protocols));
    let mut fields: Vec<(&[u8], &[u8])> = vec![
        (b":method", b"CONNECT"),
        (b":protocol", b"webtransport"),
        (b":scheme", b"https"),
        (b":authority", &req.authority),
        (b":path", &req.path),
    ];
    if let Some(origin) = req.origin.as_deref() {
        fields.push((b"origin", origin));
    }
    fields.push((b"sec-webtransport-http3-draft02", b"1"));
    if let Some(p) = protocols.as_deref() {
        fields.push((b"wt-available-protocols", p.as_bytes()));
    }
    let _ = tx.send(Write::Bytes(h3::frame(
        frame::HEADERS,
        &h3::encode_field_section(&fields),
    )));
    // The response: interim ones skipped, the final one decides.
    let mut r = Reader {
        recv: Receive(Some(recv)),
    };
    let refused = |h3: &H3Conn, info: CloseInfo| {
        h3.forget(sid);
        info
    };
    let mut response_bytes = 0u64;
    let response = loop {
        tokio::task::yield_now().await;
        let header = match r.frame_header().await {
            Ok(Some(h)) => h,
            Ok(None) | Err(Fail::Fin) => {
                return Err(refused(
                    h3,
                    CloseInfo {
                        kind: SBQ_CLOSE_SESSION_RESET,
                        code: 0,
                        reason: b"the server ended the CONNECT stream without a response".to_vec(),
                    },
                ))
            }
            Err(Fail::Reset(code)) => {
                return Err(refused(
                    h3,
                    CloseInfo {
                        kind: SBQ_CLOSE_SESSION_RESET,
                        code,
                        reason: b"the server reset the CONNECT stream".to_vec(),
                    },
                ))
            }
            Err(Fail::Conn(code, why)) => {
                h3.fail(code, why);
                return Err(h3.lost_info(&ConnectionError::LocallyClosed));
            }
            Err(_) => return Err(lost(h3.conn.close_reason())),
        };
        let (t, len) = header;
        response_bytes = response_bytes.saturating_add(len).saturating_add(2);
        if response_bytes > MAX_SKIP_BEFORE_HEADERS {
            h3.fail(err::H3_EXCESSIVE_LOAD, "too much before the final response");
            return Err(h3.lost_info(&ConnectionError::LocallyClosed));
        }
        match t {
            frame::HEADERS => {
                if len > MAX_FIELD_SECTION as u64 {
                    abort(None, Some(&mut r.recv), err::H3_EXCESSIVE_LOAD);
                    let _ = tx.send(Write::Reset(err::H3_EXCESSIVE_LOAD));
                    return Err(refused(
                        h3,
                        CloseInfo {
                            kind: SBQ_CLOSE_H3_LOCAL,
                            code: err::H3_EXCESSIVE_LOAD,
                            reason: b"the response is too large".to_vec(),
                        },
                    ));
                }
                let b = r
                    .take(len)
                    .await
                    .map_err(|e| response_read_failure(h3, e))?;
                let fields = match h3::decode_field_section(&b, MAX_FIELD_SECTION) {
                    Ok(f) => f,
                    Err(FieldError::Qpack) => {
                        h3.fail(err::QPACK_DECOMPRESSION_FAILED, "a field section");
                        return Err(h3.lost_info(&ConnectionError::LocallyClosed));
                    }
                    Err(FieldError::TooLarge) => {
                        let _ = tx.send(Write::Reset(err::H3_EXCESSIVE_LOAD));
                        abort(None, Some(&mut r.recv), err::H3_EXCESSIVE_LOAD);
                        return Err(refused(
                            h3,
                            CloseInfo {
                                kind: SBQ_CLOSE_H3_LOCAL,
                                code: err::H3_EXCESSIVE_LOAD,
                                reason: b"the response is too large".to_vec(),
                            },
                        ));
                    }
                };
                trace!(
                    "client {}: response {}",
                    h3.conn.remote_address(),
                    fields_text(&fields)
                );
                let Ok(response) = parse_response(&fields) else {
                    let _ = tx.send(Write::Reset(err::H3_MESSAGE_ERROR));
                    abort(None, Some(&mut r.recv), err::H3_MESSAGE_ERROR);
                    return Err(refused(
                        h3,
                        CloseInfo {
                            kind: SBQ_CLOSE_H3_LOCAL,
                            code: err::H3_MESSAGE_ERROR,
                            reason: b"a malformed response".to_vec(),
                        },
                    ));
                };
                if response.status < 200 {
                    continue;
                }
                break response;
            }
            frame::DATA => {
                h3.fail(err::H3_FRAME_UNEXPECTED, "DATA before the response");
                return Err(h3.lost_info(&ConnectionError::LocallyClosed));
            }
            frame::WT_STREAM => {
                h3.fail(err::H3_FRAME_ERROR, "WT_STREAM inside a response");
                return Err(h3.lost_info(&ConnectionError::LocallyClosed));
            }
            t if forbidden_on_request(t) || t == frame::PUSH_PROMISE => {
                h3.fail(err::H3_FRAME_UNEXPECTED, "unexpected frame on a response");
                return Err(h3.lost_info(&ConnectionError::LocallyClosed));
            }
            _ => {
                if len > MAX_SKIP_BEFORE_HEADERS {
                    h3.fail(err::H3_EXCESSIVE_LOAD, "too much before the response");
                    return Err(h3.lost_info(&ConnectionError::LocallyClosed));
                }
                r.skip(len)
                    .await
                    .map_err(|e| response_read_failure(h3, e))?;
            }
        }
    };
    if !(200..300).contains(&response.status) {
        let _ = tx.send(Write::Finish);
        let _ = r.recv.stop(varint(err::H3_NO_ERROR));
        return Err(refused(
            h3,
            CloseInfo {
                kind: SBQ_CLOSE_REFUSED,
                code: u64::from(response.status),
                reason: format!("HTTP status {}", response.status).into_bytes(),
            },
        ));
    }
    if !response.draft02
        && (settings.draft07_sessions() == 0
            || settings.get(setting::ENABLE_CONNECT_PROTOCOL) != Some(1))
    {
        h3.fail(
            wt::err::WT_REQUIREMENTS_NOT_MET,
            "missing draft-02 response header",
        );
        return Err(h3.lost_info(&ConnectionError::LocallyClosed));
    }
    let protocol = match response.protocol {
        Some(p) if !req.protocols.iter().any(|o| o.as_slice() == p.as_bytes()) => {
            let _ = tx.send(Write::Reset(wt::err::WT_ALPN_ERROR));
            abort(None, Some(&mut r.recv), wt::err::WT_ALPN_ERROR);
            return Err(refused(
                h3,
                CloseInfo {
                    kind: SBQ_CLOSE_OTHER,
                    code: wt::err::WT_ALPN_ERROR,
                    reason: format!(
                        "the server selected the protocol \"{p}\", which was not offered"
                    )
                    .into_bytes(),
                },
            ));
        }
        Some(p) => p.into_bytes(),
        None => Vec::new(),
    };
    {
        let mut st = lock(&wt.st);
        if st.phase != Phase::Connecting {
            // Abandoned meanwhile; the close took care of the rest.
            return Ok(());
        }
        st.phase = Phase::Live;
        st.established = true;
        st.protocol = protocol;
        st.version = if response.draft02 {
            VERSION_DRAFT02
        } else {
            VERSION_DRAFT07
        };
    }
    *lock(&o.conn) = Some(h3.conn.clone());
    o.ctx.post(SBQ_EV_CONNECTED, o.handle, 0, 0);
    h3.set_live(sid, o);
    if lock(&h3.state).goaway.is_some() {
        post_draining(o);
    }
    let task = h3.spawn(capsules(Arc::downgrade(o), h3.clone(), sid, r));
    lock(&wt.st).reader_task = Some(task);
    Ok(())
}

/// A client's session failed before it was established (`info`): reported, and its QUIC
/// connection, which carries nothing else, closed.
pub fn connect_failed(o: &Arc<ConnObj>, h3: Option<&Arc<H3Conn>>, info: CloseInfo) {
    if let Some(wt) = o.wt.as_ref() {
        let mut st = lock(&wt.st);
        if st.phase != Phase::Connecting {
            return;
        }
        st.phase = Phase::Ended;
    }
    o.finish(info);
    if let Some(h3) = h3 {
        if let Some(sid) = o.wt.as_ref().and_then(|w| w.sid()) {
            h3.forget(sid);
        }
        h3.close(err::H3_NO_ERROR, b"");
    }
}

fn keep_reader_task(wt: &WtSession, h3: &H3Conn, sid: u64, task: AbortHandle) {
    lock(&wt.st).reader_task = Some(task.clone());
    let mut st = lock(&h3.state);
    match st.sessions.get_mut(&sid) {
        Some(Slot::Pending(_) | Slot::Live(_)) if !task.is_finished() => {}
        Some(Slot::Closing { tasks, .. }) => tasks.push(task),
        _ => task.abort(),
    }
}

/// Reads a request field of a pending or live server session into `out`.
pub fn request_field(o: &ConnObj, field: i32) -> Result<Vec<u8>, i64> {
    let wt = o.wt.as_ref().ok_or(SBQ_ERR_ARG)?;
    let st = lock(&wt.st);
    let r = st.request.as_ref().ok_or(SBQ_ERR_STATE)?;
    match field {
        FIELD_AUTHORITY => Ok(r.authority.clone()),
        FIELD_PATH => Ok(r.path.clone()),
        FIELD_ORIGIN => r.origin.clone().ok_or(SBQ_ERR_STATE),
        FIELD_PROTOCOLS => {
            let mut out = Vec::new();
            for p in r.protocols.iter().flatten() {
                if let Ok(n) = u8::try_from(p.len()) {
                    if n > 0 {
                        out.push(n);
                        out.extend_from_slice(p.as_bytes());
                    }
                }
            }
            Ok(out)
        }
        _ => Err(SBQ_ERR_ARG),
    }
}

/// Accepts a pending session with `protocol` (empty: none), which must be one the client
/// offered. The session is live when this returns `SBQ_OK`.
pub fn accept(o: &Arc<ConnObj>, protocol: &[u8]) -> i32 {
    let Some(wt) = o.wt.as_ref() else {
        return SBQ_ERR_ARG as i32;
    };
    let (Some(h3), Some(sid)) = (wt.h3(), wt.sid()) else {
        return SBQ_ERR_STATE as i32;
    };
    if h3
        .listener_closed
        .as_ref()
        .is_some_and(|closed| closed.load(Ordering::Relaxed))
    {
        if refuse(o, 503) {
            o.finish(CloseInfo {
                kind: SBQ_CLOSE_REFUSED,
                code: 503,
                reason: b"the listener closed before the request was answered".to_vec(),
            });
        }
        return SBQ_ERR_STATE as i32;
    }
    let reader = {
        let mut st = lock(&wt.st);
        if st.phase != Phase::Pending {
            return SBQ_ERR_STATE as i32;
        }
        if !protocol.is_empty() {
            let offered = st
                .request
                .as_ref()
                .and_then(|r| r.protocols.as_ref())
                .is_some_and(|p| p.iter().any(|x| x.as_bytes() == protocol));
            if !offered {
                return SBQ_ERR_ARG as i32;
            }
        }
        let response = response_frame(200, st.version, (!protocol.is_empty()).then_some(protocol));
        if let Some(tx) = st.writer.as_ref() {
            let _ = tx.send(Write::Bytes(response));
        }
        st.phase = Phase::Live;
        st.established = true;
        st.protocol = protocol.to_vec();
        st.reader.take()
    };
    for t in lock(&o.tasks).drain(..) {
        // The answer timer.
        t.abort();
    }
    h3.set_live(sid, o);
    if lock(&h3.state).goaway.is_some() {
        post_draining(o);
    }
    if let Some(r) = reader {
        let task = h3.spawn(capsules(Arc::downgrade(o), h3.clone(), sid, r));
        keep_reader_task(wt, &h3, sid, task);
    }
    SBQ_OK as i32
}

/// Refuses a pending session with `status`: the response and FIN, the request left unread,
/// the session forgotten by its connection. False when it was not pending.
fn refuse(o: &Arc<ConnObj>, status: u16) -> bool {
    let Some(wt) = o.wt.as_ref() else {
        return false;
    };
    let (Some(h3), Some(sid)) = (wt.h3(), wt.sid()) else {
        return false;
    };
    {
        let mut st = lock(&wt.st);
        if st.phase != Phase::Pending {
            return false;
        }
        st.phase = Phase::Ended;
        if let Some(tx) = st.writer.as_ref() {
            let _ = tx.send(Write::Bytes(response_frame(status, st.version, None)));
            let _ = tx.send(Write::Finish);
        }
        if let Some(mut r) = st.reader.take() {
            let _ = r.recv.stop(varint(err::H3_NO_ERROR));
        }
    }
    for t in lock(&o.tasks).drain(..) {
        t.abort();
    }
    h3.forget(sid);
    true
}

/// Records how a session ended without reporting it (no CLOSED follows).
fn end_quietly(o: &ConnObj, info: CloseInfo) -> bool {
    let mut end = lock(&o.end);
    if end.is_some() {
        return false;
    }
    *end = Some(info);
    true
}

/// Refuses a pending session with an HTTP status (300 to 599). Its handle stays until released;
/// no CLOSED follows.
pub fn reject(o: &Arc<ConnObj>, status: u32) -> i32 {
    if o.wt.is_none() {
        return SBQ_ERR_ARG as i32;
    }
    if !(300..=599).contains(&status) {
        return SBQ_ERR_ARG as i32;
    }
    if !refuse(o, status as u16) {
        return SBQ_ERR_STATE as i32;
    }
    end_quietly(
        o,
        CloseInfo {
            kind: SBQ_CLOSE_REFUSED,
            code: u64::from(status),
            reason: format!("refused with HTTP status {status}").into_bytes(),
        },
    );
    SBQ_OK as i32
}

/// Sends WT_DRAIN_SESSION on a live session (once).
pub fn drain(o: &ConnObj) -> i32 {
    let Some(wt) = o.wt.as_ref() else {
        return SBQ_ERR_ARG as i32;
    };
    let mut st = lock(&wt.st);
    if st.phase != Phase::Live {
        return SBQ_ERR_STATE as i32;
    }
    if !std::mem::replace(&mut st.drain_sent, true) {
        if let Some(tx) = st.writer.as_ref() {
            let _ = tx.send(Write::Bytes(h3::frame(frame::DATA, &wt::drain_capsule())));
        }
    }
    SBQ_OK as i32
}

/// Closes a session with an application code (u32) and a message (cut to 1024 bytes): a live
/// session sends WT_CLOSE_SESSION and FIN; a client still connecting is abandoned; a pending
/// request is refused 503. When `report`, a live session posts CLOSED (APP_LOCAL) after its
/// bounded CONNECT close attempt; further application I/O fails immediately.
pub fn close(o: &Arc<ConnObj>, code: u64, message: &[u8], report: bool) -> i32 {
    let Some(wt) = o.wt.as_ref() else {
        return SBQ_ERR_ARG as i32;
    };
    if std::str::from_utf8(message).is_err() {
        return SBQ_ERR_ARG as i32;
    }
    let Ok(code32) = u32::try_from(code) else {
        return SBQ_ERR_ARG as i32;
    };
    let message = wt::truncate_utf8(message, wt::MAX_CLOSE_MESSAGE).to_vec();
    {
        let mut lc = lock(&o.local_close);
        if lc.is_none() {
            *lc = Some((code, message.clone()));
        }
    }
    let info = CloseInfo {
        kind: SBQ_CLOSE_APP_LOCAL,
        code,
        reason: message.clone(),
    };
    let phase = lock(&wt.st).phase;
    match phase {
        Phase::Ended => {}
        Phase::Connecting => {
            lock(&wt.st).phase = Phase::Ended;
            for t in lock(&o.tasks).drain(..) {
                t.abort();
            }
            if let Some(h3) = wt.h3() {
                if let Some(sid) = wt.sid() {
                    h3.forget(sid);
                }
                h3.close(err::H3_REQUEST_CANCELLED, b"");
            }
            if report {
                o.finish(info);
            } else {
                end_quietly(o, info);
            }
        }
        Phase::Pending => {
            if refuse(o, 503) {
                if report {
                    o.finish(info);
                } else {
                    end_quietly(o, info);
                }
            }
        }
        Phase::Live => {
            let (tx, streams) = {
                let mut st = lock(&wt.st);
                if st.phase != Phase::Live {
                    return SBQ_OK as i32;
                }
                st.phase = Phase::Ended;
                let streams = DeferredStreams(session_streams(o));
                for stream in &streams.0 {
                    stream.session_ended();
                }
                (st.writer.clone(), streams)
            };
            let recorded = end_quietly(o, info);
            let notification = ClosedNotification {
                ctx: o.ctx.clone(),
                handle: o.handle,
                code,
                report: report && recorded,
            };
            if let (Some(h3), Some(sid)) = (wt.h3(), wt.sid()) {
                h3.closing(sid, o);
            }
            if let Some(tx) = tx {
                let capsule = wt::close_capsule(code32, &message);
                let _ = tx.send(Write::Close(
                    h3::frame(frame::DATA, &capsule),
                    streams,
                    notification,
                ));
            }
            for task in lock(&o.tasks).drain(..) {
                task.abort();
            }
        }
    }
    SBQ_OK as i32
}

/// The session's keying material exporter: the TLS exporter with the label
/// `EXPORTER-WebTransport` and the session's context for the application's `label` and
/// `context`.
pub fn exporter(o: &ConnObj, label: &[u8], context: &[u8], out: &mut [u8]) -> i32 {
    let Some(wt) = o.wt.as_ref() else {
        return SBQ_ERR_ARG as i32;
    };
    let (Some(h3), Some(sid)) = (wt.h3(), wt.sid()) else {
        return SBQ_ERR_STATE as i32;
    };
    {
        let st = lock(&wt.st);
        if wt.client && !st.established {
            return SBQ_ERR_STATE as i32;
        }
    }
    let Some(ctx) = wt::exporter_context(sid, label, context) else {
        return SBQ_ERR_ARG as i32;
    };
    match h3
        .conn
        .export_keying_material(out, wt::EXPORTER_LABEL, &ctx)
    {
        Ok(()) => SBQ_OK as i32,
        Err(_) => SBQ_ERR_ARG as i32,
    }
}

/// The protocol the session selected (empty: none); None before it is established.
pub fn protocol(o: &ConnObj) -> Option<Vec<u8>> {
    let st = lock(&o.wt.as_ref()?.st);
    st.established.then(|| st.protocol.clone())
}

/// Forgets a session: closes it quietly (code 0) if it is still open. The QUIC connection is the
/// HTTP/3 layer's, which closes it once its sessions are done.
pub fn release(o: &Arc<ConnObj>) {
    close(o, 0, b"", false);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Vec<h3::Field> {
        [
            (b":method".as_slice(), b"CONNECT".as_slice()),
            (b":protocol", b"webtransport"),
            (b":scheme", b"https"),
            (b":authority", b"example.test"),
            (b":path", b"/sb"),
        ]
        .into_iter()
        .map(|(n, v)| (n.to_vec(), v.to_vec()))
        .collect()
    }

    #[test]
    fn request_field_validation() {
        let good = request();
        assert!(parse_request(&good).is_ok());
        for index in 0..good.len() {
            let mut fields = good.clone();
            fields.remove(index);
            assert!(parse_request(&fields).is_err(), "missing {index}");
            let mut fields = good.clone();
            fields.insert(index, fields[index].clone());
            assert!(parse_request(&fields).is_err(), "duplicate {index}");
        }
        for (name, value) in [
            (b"bad name".as_slice(), b"x".as_slice()),
            (b"x", b"\x01"),
            (b"x", b" x"),
            (b"x", b"x\t"),
            (b"host", b"other.test"),
            (b"te", b"chunked"),
            (b"connection", b"close"),
        ] {
            let mut fields = good.clone();
            fields.push((name.to_vec(), value.to_vec()));
            assert!(parse_request(&fields).is_err(), "{name:?} {value:?}");
        }
        let mut fields = good.clone();
        fields.extend([
            (b"origin".to_vec(), b"https://a.test".to_vec()),
            (b"origin".to_vec(), b"https://b.test".to_vec()),
        ]);
        assert!(parse_request(&fields).is_err());
        let classic = vec![
            (b":method".to_vec(), b"CONNECT".to_vec()),
            (b":authority".to_vec(), b"example.test:443".to_vec()),
        ];
        assert!(!parse_request(&classic).unwrap().webtransport());
        let mut empty_path = classic;
        empty_path.push((b":path".to_vec(), Vec::new()));
        assert!(parse_request(&empty_path).is_err());
        for path in [b"relative".as_slice(), b"/sb#fragment", b"/sb space"] {
            let mut fields = good.clone();
            fields[4].1 = path.to_vec();
            assert!(parse_request(&fields).is_err());
        }
    }

    #[test]
    fn legitimate_fields_are_accepted() {
        let mut fields = request();
        fields[3].1 = b"[::1]:4433".to_vec();
        fields[4].1 = b"/sb?x=1&y=%20".to_vec();
        fields.extend(
            [
                (b"te".as_slice(), b"Trailers".as_slice()),
                (b"origin", b"null"),
                (b"user-agent", b"Mozilla/5.0 (X11) HeadlessChrome/149.0.0.0"),
                (b"x-empty", b""),
                (b"x-obs-text", b"a\xe9b"),
                (b"x-tab", b"a\tb"),
                (b"sec-webtransport-http3-draft02", b"1"),
                (b"wt-available-protocols", b"\"switchboard\";q=1"),
                (b"wt-available-protocols", b"\"other\""),
                (b"host", b"[::1]:4433"),
            ]
            .into_iter()
            .map(|(n, v)| (n.to_vec(), v.to_vec())),
        );
        let r = parse_request(&fields).unwrap();
        assert!(r.webtransport() && r.draft02);
        assert_eq!(r.path, b"/sb?x=1&y=%20");
        assert_eq!(r.origin.as_deref(), Some(b"null".as_slice()));
        assert_eq!(
            r.protocols,
            Some(vec!["switchboard".to_string(), "other".to_string()])
        );
        // Field names are lowercase in HTTP/3: an uppercase one is malformed (RFC 9114 4.2).
        let mut fields = request();
        fields.push((b"Origin".to_vec(), b"https://a.test".to_vec()));
        assert!(parse_request(&fields).is_err());
        let response = [
            (b":status".as_slice(), b"200".as_slice()),
            (b"sec-webtransport-http3-draft", b"draft02"),
            (b"wt-protocol", b"\"switchboard\";x"),
            (b"server", b"Example/1.0"),
        ]
        .map(|(n, v)| (n.to_vec(), v.to_vec()));
        let r = parse_response(&response).unwrap();
        assert_eq!((r.status, r.draft02), (200, true));
        assert_eq!(r.protocol.as_deref(), Some("switchboard"));
    }

    #[test]
    fn response_fields_and_duplicate_structured_items() {
        let status = (b":status".to_vec(), b"200".to_vec());
        for first in [b"\"switchboard\"".as_slice(), b""] {
            let fields = vec![
                status.clone(),
                (b"wt-protocol".to_vec(), first.to_vec()),
                (b"wt-protocol".to_vec(), b"\"other\"".to_vec()),
            ];
            assert!(parse_response(&fields).unwrap().protocol.is_none());
        }
        assert!(parse_response(&[]).is_err());
        assert!(parse_response(&[status.clone(), status]).is_err());
        for value in [b"101".as_slice(), b"600", b"020", b"2oo", b"20"] {
            assert!(parse_response(&[(b":status".to_vec(), value.to_vec())]).is_err());
        }
    }
}
