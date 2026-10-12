/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GLM 5.3 Flash <noreply@z.ai>
  GPT-6 Astra <noreply@openai.com>
*/

//! sbq: a flat extern "C" shim over quinn (QUIC with rustls and ring) for the native stream
//! provider of switchboard_quic.
//!
//! Every call is synchronous and never blocks on the network: an operation that cannot complete
//! now returns `SBQ_WOULD_BLOCK` and an event follows once it may succeed, so every wait lives in
//! Rust (wakers and tasks on a tokio runtime that also owns the UDP sockets) and the caller polls
//! once per event. Events are queued per context and announced by a doorbell callback from a
//! dedicated notifier thread, which holds no quinn lock (see `ctx`).
//!
//! Objects are named by handles (u64 table ids, never pointers, never 0). Buffers passed in are
//! copied before the call returns; buffers passed out are filled before it returns.
//!
//! Results: `i64` results are a count or handle when >= 0 (0 also meaning `SBQ_WOULD_BLOCK` or
//! `SBQ_OK` where documented), one of the `SBQ_ERR_*` codes, `SBQ_FIN`, `SBQ_NO_CODE`,
//! `SBQ_RETRY`, or, at or below `-SBQ_CODE_BASE`, an application error code `code = -result -
//! SBQ_CODE_BASE` (a reset or a STOP_SENDING from the peer). `sbq_last_error` describes the last
//! failure on the calling thread.
//!
//! WebTransport: a connection whose ALPN is `h3` runs HTTP/3 (`h3`, `h3conn`) and carries
//! WebTransport sessions (`wt`). A session is a handle in the same table as connections: the
//! stream and connection calls take it, with WebTransport application codes (u32) where they take
//! codes, and the session's exporter, close and protocol.

#![allow(clippy::missing_safety_doc)]

mod config;
mod conn;
mod ctx;
mod h3;
mod h3_tables;
mod h3conn;
mod stream;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_wt;
mod wt;

use std::net::SocketAddr;
use std::sync::Arc;

use config::{ClientParams, ConfigObj, Limits, ServerParams, Verify};
use ctx::{get, lock, set_error, CONFIGS, CONNS, CTXS, LISTENERS, STREAMS};

pub use ctx::{SbqDoorbell, SbqEvent};

/// Version of this ABI; the Dart layer refuses a library with another.
pub const SBQ_ABI_VERSION: u32 = 4;

/// Success.
pub const SBQ_OK: i64 = 0;
/// Nothing can be done now; an event follows (READABLE, WRITABLE or OPENED).
pub const SBQ_WOULD_BLOCK: i64 = 0;
/// `sbq_stream_read`: the peer finished its direction and everything was read.
pub const SBQ_FIN: i64 = -1;
/// The stream direction was finished, reset or stopped by this side already.
pub const SBQ_ERR_CLOSED: i64 = -2;
/// The connection has ended (for a stream of a WebTransport session: or the session).
pub const SBQ_ERR_CONNECTION: i64 = -3;
/// Unknown (or released) handle.
pub const SBQ_ERR_HANDLE: i64 = -4;
/// Invalid argument (malformed list, empty buffer, code above 2^62 - 1, bad UTF-8, ...).
pub const SBQ_ERR_ARG: i64 = -5;
/// TLS configuration rejected (certificate, key, ALPN).
pub const SBQ_ERR_TLS: i64 = -6;
/// Socket or address error.
pub const SBQ_ERR_IO: i64 = -7;
/// Not available in this state (handshake not complete, no exporter, buffer too small).
pub const SBQ_ERR_STATE: i64 = -8;
/// `sbq_init` was not called, or the runtime could not start.
pub const SBQ_ERR_INIT: i64 = -9;
/// The peer reset (read) or stopped (write) a WebTransport stream with a code outside the
/// WebTransport application range: the direction ended without an application code.
pub const SBQ_NO_CODE: i64 = -10;
/// `sbq_stream_finish` on a WebTransport stream whose header could not be written yet (no
/// credit): nothing was done; call again after the WRITABLE that follows.
pub const SBQ_RETRY: i64 = -11;
/// Results at or below `-SBQ_CODE_BASE` carry an application error code.
pub const SBQ_CODE_BASE: i64 = 16;

/// A listener accepted a raw QUIC connection, handshake complete. handle = connection,
/// a = listener.
pub const SBQ_EV_INCOMING: i32 = 1;
/// An outgoing connection completed its handshake, or a WebTransport session received its 2xx
/// response. handle = connection or session.
pub const SBQ_EV_CONNECTED: i32 = 2;
/// A connection ended, or its handshake failed. handle = connection, a = `SBQ_CLOSE_*`,
/// b = the error code (the application code for the `SBQ_CLOSE_APP_*` kinds); the reason is
/// read with `sbq_conn_close_reason`. Operations on the connection and its streams fail with
/// `SBQ_ERR_CONNECTION` from then on; release them.
pub const SBQ_EV_CLOSED: i32 = 3;
/// The peer opened a bidirectional stream. handle = stream, a = connection or session.
pub const SBQ_EV_STREAM: i32 = 4;
/// A stream `sbq_stream_open` waited for is open. handle = stream, a = connection.
pub const SBQ_EV_OPENED: i32 = 5;
/// A read that returned `SBQ_WOULD_BLOCK` may succeed now. handle = stream.
pub const SBQ_EV_READABLE: i32 = 6;
/// A write that returned `SBQ_WOULD_BLOCK` may succeed now. handle = stream.
pub const SBQ_EV_WRITABLE: i32 = 7;
/// The peer sent STOP_SENDING; the send direction was reset with the same code.
/// handle = stream, a = code (on a WebTransport stream the application code, -1 for none).
pub const SBQ_EV_STOPPED: i32 = 8;
/// Every byte of the finished send direction was acknowledged (or the reset this side sent
/// was). handle = stream.
pub const SBQ_EV_FINISHED_ACKED: i32 = 9;
/// A WebTransport request reached a listener: handle = session (pending), a = listener, b = the
/// draft version the client signalled (2 or 7). Read its fields with `sbq_wt_request`, and
/// answer with `sbq_wt_accept` (the session is live when it returns) or `sbq_wt_reject` (release
/// the handle then). A request not answered within the listener's handshake deadline (10 s
/// without one) is refused 503 and gets CLOSED (`SBQ_CLOSE_REFUSED`, b = 503).
pub const SBQ_EV_WT_REQUEST: i32 = 10;
/// The peer asked to drain a WebTransport session: WT_DRAIN_SESSION, or an HTTP/3 GOAWAY on its
/// connection. handle = session. At most once per session.
pub const SBQ_EV_DRAINING: i32 = 11;
/// The peer opened a unidirectional stream on a WebTransport session: handle = stream (receive
/// direction only), a = session.
pub const SBQ_EV_UNI_STREAM: i32 = 12;

/// The peer closed the connection with an application code (CONNECTION_CLOSE 0x1d).
pub const SBQ_CLOSE_APP_REMOTE: i64 = 1;
/// This side closed the connection (`sbq_conn_close`); code and reason are the ones given.
pub const SBQ_CLOSE_APP_LOCAL: i64 = 2;
/// The idle timeout expired, or the handshake did not complete within its deadline (the
/// configuration's `handshake_ms`, else the idle timeout).
pub const SBQ_CLOSE_TIMED_OUT: i64 = 3;
/// This side's stack detected a transport error; b = the transport error code.
pub const SBQ_CLOSE_TRANSPORT_LOCAL: i64 = 4;
/// The peer's stack closed with a transport error (CONNECTION_CLOSE 0x1c); b = its code.
pub const SBQ_CLOSE_TRANSPORT_REMOTE: i64 = 5;
/// A stateless reset.
pub const SBQ_CLOSE_RESET: i64 = 6;
/// The handshake failed because this side rejected the server's certificate.
pub const SBQ_CLOSE_CERT_REJECTED: i64 = 7;
/// The host could not be resolved, or no socket could be opened.
pub const SBQ_CLOSE_UNREACHABLE: i64 = 8;
/// Any other end (version mismatch, connection ids exhausted, a WebTransport protocol the client
/// did not offer, ...).
pub const SBQ_CLOSE_OTHER: i64 = 9;
/// A WebTransport session was refused: the server answered with a status other than 2xx, b = the
/// HTTP status (also in the reason, "HTTP status 404"); or a listener refused a request that was
/// not answered in time (b = 503).
pub const SBQ_CLOSE_REFUSED: i64 = 10;
/// The peer reset a WebTransport session's CONNECT stream (b = the HTTP/3 code), or ended it
/// without a response: the session is lost.
pub const SBQ_CLOSE_SESSION_RESET: i64 = 11;
/// This side's HTTP/3 layer ended the session or its connection, for the peer's protocol
/// violation: b = the HTTP/3 error code, the reason says what.
pub const SBQ_CLOSE_H3_LOCAL: i64 = 12;
/// The peer closed the QUIC connection under a WebTransport session: b = its HTTP/3 error code.
pub const SBQ_CLOSE_H3_REMOTE: i64 = 13;

/// `sbq_wt_request` fields: the request's `:authority`.
pub const SBQ_WT_AUTHORITY: i32 = 1;
/// The request's `:path` (with its query, as sent).
pub const SBQ_WT_PATH: i32 = 2;
/// The request's `Origin` (`SBQ_ERR_STATE` when it has none).
pub const SBQ_WT_ORIGIN: i32 = 3;
/// The protocols the client offered in `WT-Available-Protocols`, in its order, in the wire form
/// of an ALPN list (each preceded by its length byte; empty when none was offered, or the field
/// was malformed; protocols longer than 255 bytes are left out).
pub const SBQ_WT_PROTOCOLS: i32 = 4;

/// Certificate verification of a client: the platform's trust store.
pub const SBQ_VERIFY_PLATFORM: i32 = 0;
/// Certificate verification of a client: the SHA-256 of the certificate DER must be pinned.
pub const SBQ_VERIFY_PINNED: i32 = 1;
/// Certificate verification of a client: none (the handshake signature is still checked).
pub const SBQ_VERIFY_NONE: i32 = 2;

/// Connection statistics (`sbq_conn_stats`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SbqStats {
    pub rtt_us: u64,
    pub cwnd: u64,
    pub congestion_events: u64,
    pub lost_packets: u64,
    pub sent_packets: u64,
    pub udp_tx_bytes: u64,
    pub udp_rx_bytes: u64,
    pub udp_tx_datagrams: u64,
    pub udp_rx_datagrams: u64,
}

unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(p, n)
    }
}

unsafe fn text(p: *const u8, n: usize) -> Option<String> {
    std::str::from_utf8(bytes(p, n)).ok().map(str::to_owned)
}

/// Copies `src` into `out` (up to `cap` bytes); returns the full length of `src`.
unsafe fn copy_out(src: &[u8], out: *mut u8, cap: usize) -> i64 {
    if !out.is_null() {
        std::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len().min(cap));
    }
    src.len() as i64
}

fn fail(code: i64, msg: impl Into<String>) -> i64 {
    set_error(msg);
    code
}

fn code(v: u64) -> Option<quinn::VarInt> {
    quinn::VarInt::from_u64(v).ok()
}

/// The ABI version (`SBQ_ABI_VERSION`).
#[no_mangle]
pub extern "C" fn sbq_abi_version() -> u32 {
    SBQ_ABI_VERSION
}

/// Starts the runtime on the first call (with `worker_threads` tokio workers; later calls keep
/// the first value) and creates a context whose events are announced through `doorbell`.
/// Returns the context id, or 0 on failure.
#[no_mangle]
pub extern "C" fn sbq_init(doorbell: SbqDoorbell, worker_threads: u32) -> u64 {
    if let Err(e) = ctx::start(worker_threads) {
        set_error(e);
        return 0;
    }
    ctx::new_ctx(doorbell).id
}

/// Ends a context: closes its connections (code 0), WebTransport sessions and their HTTP/3
/// connections, and listeners, drops its streams and queued events. When it returns, the
/// doorbell will not be called again for this context. Not a leaf call: it waits for a doorbell
/// call in progress.
#[no_mangle]
pub extern "C" fn sbq_shutdown(ctx_id: u64) -> i32 {
    let Some(ctx) = lock(&CTXS).remove(&ctx_id) else {
        return SBQ_ERR_HANDLE as i32;
    };
    ctx.close();
    let listeners: Vec<_> = {
        let mut t = lock(&LISTENERS);
        let ids: Vec<u64> = t
            .iter()
            .filter(|(_, l)| l.ctx.id == ctx_id)
            .map(|(k, _)| *k)
            .collect();
        ids.iter().filter_map(|k| t.remove(k)).collect()
    };
    for l in listeners {
        l.close();
    }
    let conns: Vec<_> = {
        let mut t = lock(&CONNS);
        let ids: Vec<u64> = t
            .iter()
            .filter(|(_, c)| c.ctx.id == ctx_id)
            .map(|(k, _)| *k)
            .collect();
        ids.iter().filter_map(|k| t.remove(k)).collect()
    };
    for c in conns {
        c.release();
    }
    let h3s: Vec<_> = {
        let mut t = lock(&ctx::H3S);
        let ids: Vec<u64> = t
            .iter()
            .filter(|(_, h)| h.ctx.id == ctx_id)
            .map(|(k, _)| *k)
            .collect();
        ids.iter().filter_map(|k| t.remove(k)).collect()
    };
    for h in h3s {
        h.close(h3::err::H3_NO_ERROR, b"shutdown");
    }
    SBQ_OK as i32
}

/// Moves up to `cap` queued events of the context into `out`; returns how many. Call until it
/// returns less than `cap` after each doorbell.
#[no_mangle]
pub unsafe extern "C" fn sbq_poll(ctx_id: u64, out: *mut SbqEvent, cap: usize) -> usize {
    if out.is_null() || cap == 0 {
        return 0;
    }
    let Some(ctx) = get(&CTXS, ctx_id) else {
        return 0;
    };
    // Only the events handed out are written, each into its own slot of the caller's `cap`;
    // no slice of `cap` elements is formed, so any `cap` is honoured as given (a clamp would
    // return fewer than asked with events still queued, and the caller would stop polling
    // while no further doorbell comes).
    ctx.poll(cap, |i, ev| out.add(i).write(ev))
}

/// Copies the message of the last failure on the calling thread into `out` (up to `cap` bytes,
/// UTF-8); returns its full length.
#[no_mangle]
pub unsafe extern "C" fn sbq_last_error(out: *mut u8, cap: usize) -> i64 {
    copy_out(ctx::last_error().as_bytes(), out, cap)
}

/// SHA-256 of `len` bytes at `data` into the 32 bytes at `out`.
#[no_mangle]
pub unsafe extern "C" fn sbq_sha256(data: *const u8, len: usize, out: *mut u8) -> i32 {
    if out.is_null() {
        return SBQ_ERR_ARG as i32;
    }
    let h = config::sha256(bytes(data, len));
    std::ptr::copy_nonoverlapping(h.as_ptr(), out, 32);
    SBQ_OK as i32
}

/// Generates a self-signed ECDSA P-256 certificate for `subject` (UTF-8; common name and subject
/// alternative name), valid from five minutes ago for `validity_days` days. Writes the
/// certificate DER and the PKCS#8 key DER and their lengths. Returns `SBQ_OK`, or
/// `SBQ_ERR_STATE` when a buffer is too small (the lengths are set), or `SBQ_ERR_ARG`.
#[no_mangle]
pub unsafe extern "C" fn sbq_generate_self_signed(
    subject: *const u8,
    subject_len: usize,
    validity_days: u32,
    cert_out: *mut u8,
    cert_cap: usize,
    cert_len: *mut usize,
    key_out: *mut u8,
    key_cap: usize,
    key_len: *mut usize,
) -> i32 {
    let Some(subject) = text(subject, subject_len) else {
        return fail(SBQ_ERR_ARG, "subject is not UTF-8") as i32;
    };
    if cert_len.is_null() || key_len.is_null() {
        return fail(SBQ_ERR_ARG, "null length pointer") as i32;
    }
    match config::self_signed(&subject, validity_days) {
        Ok((cert, key)) => {
            *cert_len = cert.len();
            *key_len = key.len();
            if cert.len() > cert_cap
                || key.len() > key_cap
                || cert_out.is_null()
                || key_out.is_null()
            {
                return fail(SBQ_ERR_STATE, "buffer too small") as i32;
            }
            copy_out(&cert, cert_out, cert_cap);
            copy_out(&key, key_out, key_cap);
            SBQ_OK as i32
        }
        Err(e) => fail(SBQ_ERR_ARG, e) as i32,
    }
}

fn limits(
    max_bidi: u64,
    stream_window: u64,
    conn_window: u64,
    idle_ms: u64,
    keep_alive_ms: u64,
    handshake_ms: u64,
) -> Limits {
    Limits {
        max_bidi,
        stream_window,
        conn_window,
        idle_ms,
        keep_alive_ms,
        handshake_ms,
    }
}

/// Creates a client configuration. `alpn` is the ALPN list in wire form (each token preceded by
/// its length byte; a list that offers `h3` gives the connection HTTP/3's transport parameters:
/// 16 unidirectional streams and the datagram parameter); `verify` one of `SBQ_VERIFY_*`;
/// `pins` `pin_count` SHA-256 hashes of 32 bytes each (`SBQ_VERIFY_PINNED`); `max_bidi` the
/// bidirectional streams the server may open at once; windows in bytes; times in milliseconds,
/// 0 for none. `handshake_ms` bounds each handshake attempt of a connect (one per address
/// tried): CLOSED with `SBQ_CLOSE_TIMED_OUT` follows when none completed in time; with 0 the
/// idle timeout alone bounds the handshake, and with both 0 nothing does. 0-RTT is never used.
/// Returns the configuration handle (free it with `sbq_config_free`) or an error.
#[no_mangle]
pub unsafe extern "C" fn sbq_client_config(
    alpn: *const u8,
    alpn_len: usize,
    verify: i32,
    pins: *const u8,
    pin_count: usize,
    max_bidi: u64,
    stream_window: u64,
    conn_window: u64,
    idle_ms: u64,
    keep_alive_ms: u64,
    handshake_ms: u64,
) -> i64 {
    let alpn = match config::parse_alpn(bytes(alpn, alpn_len)) {
        Ok(a) => a,
        Err(e) => return fail(SBQ_ERR_ARG, e),
    };
    let verify = match verify {
        SBQ_VERIFY_PLATFORM => Verify::Platform,
        SBQ_VERIFY_NONE => Verify::None,
        SBQ_VERIFY_PINNED => {
            // The count is bounded before it is multiplied: a huge count would overflow the
            // length (panicking in a debug build) or claim a buffer far larger than any caller
            // has.
            if pin_count == 0 {
                return fail(SBQ_ERR_ARG, "no pinned hash");
            }
            if pin_count > 1024 {
                return fail(SBQ_ERR_ARG, "too many pinned hashes");
            }
            if pins.is_null() {
                return fail(SBQ_ERR_ARG, "no pinned hash");
            }
            let raw = bytes(pins, pin_count * 32);
            Verify::Pinned(
                raw.chunks_exact(32)
                    .map(|c| c.try_into().expect("32 bytes"))
                    .collect(),
            )
        }
        _ => return fail(SBQ_ERR_ARG, "unknown verify mode"),
    };
    let params = ClientParams {
        alpn,
        verify,
        limits: limits(
            max_bidi,
            stream_window,
            conn_window,
            idle_ms,
            keep_alive_ms,
            handshake_ms,
        ),
    };
    // Validate now, so that a bad configuration fails here and not in the connect task.
    if let Err(e) = config::client_config(&params, Arc::default()) {
        return fail(SBQ_ERR_TLS, e);
    }
    let h = ctx::next_handle();
    lock(&CONFIGS).insert(h, Arc::new(ConfigObj::Client(params)));
    h as i64
}

/// Creates a server configuration: ALPN list in wire form, the certificate DER (optionally
/// followed by the DER certificates of its chain), the private key DER (PKCS#8, SEC1 or
/// PKCS#1), and limits as for `sbq_client_config` (`max_bidi`: streams the client may open at
/// once). `handshake_ms` bounds the handshake of each connection the listener accepts: one not
/// complete by then is abandoned (closed) and never announced; 0 leaves it to the idle timeout,
/// and with both 0 a client that goes silent mid-handshake is kept until the listener closes.
/// TLS 1.3 only, no client authentication, no 0-RTT. A list that offers `h3` makes a listener of
/// WebTransport: its connections that negotiate `h3` run HTTP/3 (WT_REQUEST events instead of
/// INCOMING), with HTTP/3's transport parameters (16 unidirectional streams, the datagram
/// parameter, `max_bidi` + 1 bidirectional streams for the CONNECT stream), which then apply to
/// every connection of the listener; `handshake_ms` also bounds a request's wait for its answer.
#[no_mangle]
pub unsafe extern "C" fn sbq_server_config(
    alpn: *const u8,
    alpn_len: usize,
    cert: *const u8,
    cert_len: usize,
    key: *const u8,
    key_len: usize,
    max_bidi: u64,
    stream_window: u64,
    conn_window: u64,
    idle_ms: u64,
    keep_alive_ms: u64,
    handshake_ms: u64,
) -> i64 {
    let alpn = match config::parse_alpn(bytes(alpn, alpn_len)) {
        Ok(a) => a,
        Err(e) => return fail(SBQ_ERR_ARG, e),
    };
    let l = limits(
        max_bidi,
        stream_window,
        conn_window,
        idle_ms,
        keep_alive_ms,
        handshake_ms,
    );
    let alpn_copy = alpn.clone();
    match config::server_config(alpn, bytes(cert, cert_len), bytes(key, key_len), &l) {
        Ok(config) => {
            let h = ctx::next_handle();
            let params = ServerParams {
                config,
                handshake: l.handshake(),
                h3: config::offers_h3(&alpn_copy),
            };
            lock(&CONFIGS).insert(h, Arc::new(ConfigObj::Server(params)));
            h as i64
        }
        Err(e) => fail(SBQ_ERR_TLS, e),
    }
}

/// Frees a configuration; connections and listeners made with it are unaffected.
#[no_mangle]
pub extern "C" fn sbq_config_free(config: u64) -> i32 {
    match lock(&CONFIGS).remove(&config) {
        Some(_) => SBQ_OK as i32,
        None => SBQ_ERR_HANDLE as i32,
    }
}

/// Listens on `host` (an IP address literal, UTF-8; a name is `SBQ_ERR_ARG`, since resolving
/// it here could block: resolve it before) and `port` (0 for any) with a server configuration.
/// Returns the listener handle; INCOMING events follow (WT_REQUEST for HTTP/3).
#[no_mangle]
pub unsafe extern "C" fn sbq_listen(
    ctx_id: u64,
    config: u64,
    host: *const u8,
    host_len: usize,
    port: u16,
) -> i64 {
    let Some(ctx) = get(&CTXS, ctx_id) else {
        return fail(SBQ_ERR_INIT, "unknown context");
    };
    let Some(cfg) = get(&CONFIGS, config) else {
        return fail(SBQ_ERR_HANDLE, "unknown configuration");
    };
    let ConfigObj::Server(sp) = &*cfg else {
        return fail(SBQ_ERR_ARG, "not a server configuration");
    };
    let Some(host) = text(host, host_len) else {
        return fail(SBQ_ERR_ARG, "host is not UTF-8");
    };
    let addr: SocketAddr = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => return fail(SBQ_ERR_ARG, "listen requires an IP address literal"),
    };
    match conn::listen(&ctx, sp, addr) {
        Ok(h) => h as i64,
        Err(e) => fail(SBQ_ERR_IO, e),
    }
}

/// The local UDP port of a listener, or a negative error.
#[no_mangle]
pub extern "C" fn sbq_listener_port(listener: u64) -> i32 {
    match get(&LISTENERS, listener) {
        Some(l) => l
            .endpoint
            .local_addr()
            .map(|a| a.port() as i32)
            .unwrap_or(SBQ_ERR_IO as i32),
        None => SBQ_ERR_HANDLE as i32,
    }
}

/// Stops accepting and forgets the listener. Connections it accepted are unaffected and keep
/// its socket open until they end.
#[no_mangle]
pub extern "C" fn sbq_listener_close(listener: u64) -> i32 {
    let Some(l) = lock(&LISTENERS).remove(&listener) else {
        return SBQ_ERR_HANDLE as i32;
    };
    l.close();
    SBQ_OK as i32
}

/// Connects to `host` (UTF-8 name or address, resolved in the runtime) and `port`, sending
/// `server_name` (UTF-8) for SNI and verification, with a client configuration. Returns the
/// connection handle at once; CONNECTED or CLOSED follows (`SBQ_CLOSE_TIMED_OUT` once the
/// configuration's handshake deadline passed, or its idle timeout). The attempt is abandoned with
/// `sbq_conn_close` or `sbq_conn_release`.
#[no_mangle]
pub unsafe extern "C" fn sbq_connect(
    ctx_id: u64,
    config: u64,
    host: *const u8,
    host_len: usize,
    port: u16,
    server_name: *const u8,
    server_name_len: usize,
) -> i64 {
    let Some(ctx) = get(&CTXS, ctx_id) else {
        return fail(SBQ_ERR_INIT, "unknown context");
    };
    let Some(cfg) = get(&CONFIGS, config) else {
        return fail(SBQ_ERR_HANDLE, "unknown configuration");
    };
    let ConfigObj::Client(params) = &*cfg else {
        return fail(SBQ_ERR_ARG, "not a client configuration");
    };
    let (Some(host), Some(name)) = (text(host, host_len), text(server_name, server_name_len))
    else {
        return fail(SBQ_ERR_ARG, "host or server name is not UTF-8");
    };
    match conn::connect(&ctx, params, host, port, name) {
        Ok(h) => h as i64,
        Err(e) => fail(SBQ_ERR_TLS, e),
    }
}

/// Starts a WebTransport session: connects to `host` and `port` as `sbq_connect` does (the
/// configuration's ALPN list must offer `h3`), then sends the extended CONNECT for
/// `https://authority/path` (`authority` is the `:authority`, `host:port` without the default
/// port 443; `path` the `:path`), with `origin` as its `Origin` when not empty (browsers send
/// one, nodes need not), and offering `protocols` (wire form of an ALPN list, printable ASCII
/// each; empty for none) in `WT-Available-Protocols`. The request carries the draft-02 header
/// too, and SETTINGS advertise draft-02 and draft-07. Returns the session handle at once;
/// CONNECTED follows the server's 2xx (the selected protocol from `sbq_conn_protocol`, the
/// exporter from `sbq_conn_exporter`), or CLOSED: `SBQ_CLOSE_REFUSED` with the HTTP status for
/// another response, `SBQ_CLOSE_OTHER` for a protocol that was not offered, `SBQ_CLOSE_H3_LOCAL`
/// for a server without WebTransport, the kinds of `sbq_connect` for the QUIC handshake. The
/// configuration's handshake deadline bounds the QUIC handshake and again the HTTP/3 exchange
/// (`SBQ_CLOSE_TIMED_OUT`); a zero handshake deadline uses 10 seconds for HTTP/3.
/// The session uses its QUIC connection alone, which is closed when the
/// session ends.
#[no_mangle]
pub unsafe extern "C" fn sbq_connect_wt(
    ctx_id: u64,
    config: u64,
    host: *const u8,
    host_len: usize,
    port: u16,
    server_name: *const u8,
    server_name_len: usize,
    authority: *const u8,
    authority_len: usize,
    path: *const u8,
    path_len: usize,
    origin: *const u8,
    origin_len: usize,
    protocols: *const u8,
    protocols_len: usize,
) -> i64 {
    let Some(ctx) = get(&CTXS, ctx_id) else {
        return fail(SBQ_ERR_INIT, "unknown context");
    };
    let Some(cfg) = get(&CONFIGS, config) else {
        return fail(SBQ_ERR_HANDLE, "unknown configuration");
    };
    let ConfigObj::Client(params) = &*cfg else {
        return fail(SBQ_ERR_ARG, "not a client configuration");
    };
    if !params.h3() {
        return fail(SBQ_ERR_ARG, "the configuration does not offer h3");
    }
    let (Some(host), Some(name)) = (text(host, host_len), text(server_name, server_name_len))
    else {
        return fail(SBQ_ERR_ARG, "host or server name is not UTF-8");
    };
    let authority = bytes(authority, authority_len).to_vec();
    let path = bytes(path, path_len).to_vec();
    if authority.is_empty() || path.first() != Some(&b'/') {
        return fail(
            SBQ_ERR_ARG,
            "an authority and a path starting with / are required",
        );
    }
    let protocols = match config::parse_alpn(bytes(protocols, protocols_len)) {
        Ok(p) => p,
        Err(_) => return fail(SBQ_ERR_ARG, "malformed protocol list"),
    };
    let valid = |b: &[u8]| b.iter().all(|&c| (0x20..=0x7e).contains(&c));
    if !protocols.iter().all(|p| wt::is_sf_string(p))
        || !valid(&authority)
        || !valid(&path)
        || !valid(bytes(origin, origin_len))
    {
        return fail(SBQ_ERR_ARG, "fields must be printable ASCII");
    }
    let origin = bytes(origin, origin_len);
    let req = h3conn::ClientRequest {
        authority,
        path,
        origin: (!origin.is_empty()).then(|| origin.to_vec()),
        protocols,
    };
    match conn::connect_wt(&ctx, params, host, port, name, req) {
        Ok(h) => h as i64,
        Err(e) => fail(SBQ_ERR_TLS, e),
    }
}

/// Copies a field of a WebTransport request (`SBQ_WT_*`) into `out` (up to `cap` bytes); returns
/// its full length, `SBQ_ERR_STATE` when the request has no such field (no `Origin`) or the
/// session is not a server's, `SBQ_ERR_ARG` for an unknown field.
#[no_mangle]
pub unsafe extern "C" fn sbq_wt_request(session: u64, field: i32, out: *mut u8, cap: usize) -> i64 {
    let Some(c) = get(&CONNS, session) else {
        return SBQ_ERR_HANDLE;
    };
    match h3conn::request_field(&c, field) {
        Ok(v) => copy_out(&v, out, cap),
        Err(e) => e,
    }
}

/// Accepts a pending WebTransport request with the protocol `protocol` (one the client offered;
/// empty for none): the 2xx response goes out (with `WT-Protocol`, and the draft-02 header to a
/// draft-02 client), and the session is live when this returns `SBQ_OK`: streams the client
/// opened meanwhile follow as STREAM events. `SBQ_ERR_STATE` when it is not pending (answered,
/// or refused for lack of an answer), `SBQ_ERR_ARG` for a protocol not offered.
#[no_mangle]
pub unsafe extern "C" fn sbq_wt_accept(
    session: u64,
    protocol: *const u8,
    protocol_len: usize,
) -> i32 {
    let Some(c) = get(&CONNS, session) else {
        return SBQ_ERR_HANDLE as i32;
    };
    h3conn::accept(&c, bytes(protocol, protocol_len))
}

/// Refuses a pending WebTransport request with an HTTP status (300 to 599: 403 for an origin
/// not allowed, 404 for another path, 503 while shutting down, ...); then release the handle (no
/// CLOSED follows). The streams the client opened for it are refused with WT_SESSION_GONE.
#[no_mangle]
pub extern "C" fn sbq_wt_reject(session: u64, status: u32) -> i32 {
    let Some(c) = get(&CONNS, session) else {
        return SBQ_ERR_HANDLE as i32;
    };
    h3conn::reject(&c, status)
}

/// Sends WT_DRAIN_SESSION on a live WebTransport session (at most once; later calls do
/// nothing): the peer's DRAINING.
#[no_mangle]
pub extern "C" fn sbq_wt_drain(session: u64) -> i32 {
    let Some(c) = get(&CONNS, session) else {
        return SBQ_ERR_HANDLE as i32;
    };
    h3conn::drain(&c)
}

/// Closes a connection with an application error code (CONNECTION_CLOSE 0x1d) and a reason;
/// during the handshake, abandons it. CLOSED follows (`SBQ_CLOSE_APP_LOCAL`, unless the peer's
/// close arrived first). Data in flight is discarded.
///
/// A WebTransport session: `code` is a u32 (`SBQ_ERR_ARG` beyond) and the reason is cut to 1024
/// bytes at a character boundary (invalid UTF-8 is `SBQ_ERR_ARG`); a live session sends
/// WT_CLOSE_SESSION with them and FIN on its CONNECT stream, and its streams fail at once.
/// Once the peer's stack acknowledged the capsule and FIN, or three round trips passed without
/// that (within 0.2 to 2 s), the session's streams are reset and stopped with WT_SESSION_GONE
/// and CLOSED (`SBQ_CLOSE_APP_LOCAL`) is posted: an embedder may tear down its context then
/// without cutting the close short. The QUIC connection is closed once its last session has,
/// and the peer has closed the CONNECT stream (or the same wait passed). A client's session
/// still connecting is abandoned; a pending request is refused 503.
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_close(
    conn: u64,
    code: u64,
    reason: *const u8,
    reason_len: usize,
) -> i32 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE as i32;
    };
    if c.wt.is_some() {
        return h3conn::close(&c, code, bytes(reason, reason_len), true);
    }
    let Some(code) = self::code(code) else {
        return SBQ_ERR_ARG as i32;
    };
    c.close(code, bytes(reason, reason_len));
    SBQ_OK as i32
}

/// Forgets a connection and its streams; one still open is closed with code 0 first (a session:
/// WT_CLOSE_SESSION 0, no CLOSED event).
#[no_mangle]
pub extern "C" fn sbq_conn_release(conn: u64) -> i32 {
    let Some(c) = lock(&CONNS).remove(&conn) else {
        return SBQ_ERR_HANDLE as i32;
    };
    c.release();
    SBQ_OK as i32
}

/// Copies the reason of a connection's end into `out` (up to `cap` bytes): the peer's or this
/// side's reason phrase for an application close, a description otherwise. Returns its full
/// length, or `SBQ_ERR_STATE` while the connection is open.
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_close_reason(conn: u64, out: *mut u8, cap: usize) -> i64 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE;
    };
    let end = lock(&c.end).clone();
    match end {
        Some(info) => copy_out(&info.reason, out, cap),
        None => SBQ_ERR_STATE,
    }
}

/// RFC 8446 section 7.5 keying material exporter of the connection's TLS session: `out_len`
/// bytes for `label` and `context` (an empty context equals no context in TLS 1.3).
/// `SBQ_ERR_STATE` before the handshake completed; `SBQ_ERR_ARG` for a length the exporter
/// cannot produce (more than 255 times the hash length of the cipher suite).
///
/// A WebTransport session: the draft's per-session exporter, the TLS exporter with the label
/// `EXPORTER-WebTransport` and the context `session ID (u64, big endian) || len8 label || label
/// || len8 context || context`; `label` and `context` at most 255 bytes each. Available from
/// CONNECTED on a client, from WT_REQUEST on a server.
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_exporter(
    conn: u64,
    label: *const u8,
    label_len: usize,
    context: *const u8,
    context_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE as i32;
    };
    if out.is_null() || out_len == 0 {
        return SBQ_ERR_ARG as i32;
    }
    if c.wt.is_some() {
        let out = std::slice::from_raw_parts_mut(out, out_len);
        return h3conn::exporter(
            &c,
            bytes(label, label_len),
            bytes(context, context_len),
            out,
        );
    }
    let Some(qc) = c.connection() else {
        return SBQ_ERR_STATE as i32;
    };
    let out = std::slice::from_raw_parts_mut(out, out_len);
    match qc.export_keying_material(out, bytes(label, label_len), bytes(context, context_len)) {
        Ok(()) => SBQ_OK as i32,
        // The handshake is complete (`connection()` is set only then): the length is the
        // only thing left to refuse.
        Err(_) => fail(
            SBQ_ERR_ARG,
            format!("the exporter cannot produce {out_len} bytes"),
        ) as i32,
    }
}

/// SHA-256 of the DER encoding of the peer's end-entity certificate into the 32 bytes at `out`;
/// `SBQ_ERR_STATE` when the peer presented none (a client, to a server).
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_peer_cert_sha256(conn: u64, out: *mut u8) -> i32 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE as i32;
    };
    let Some(qc) = c.connection() else {
        return SBQ_ERR_STATE as i32;
    };
    let certs = qc.peer_identity().and_then(|i| {
        i.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .ok()
    });
    match certs.as_deref().and_then(|v| v.first()) {
        Some(cert) if !out.is_null() => {
            let h = config::sha256(cert.as_ref());
            std::ptr::copy_nonoverlapping(h.as_ptr(), out, 32);
            SBQ_OK as i32
        }
        Some(_) => SBQ_ERR_ARG as i32,
        None => SBQ_ERR_STATE as i32,
    }
}

/// Copies the negotiated ALPN protocol into `out` (up to `cap` bytes); returns its full length,
/// or `SBQ_ERR_STATE` when none was negotiated. A WebTransport session: the protocol selected
/// with `WT-Protocol` (length 0 when none), `SBQ_ERR_STATE` before the session is established.
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_protocol(conn: u64, out: *mut u8, cap: usize) -> i64 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE;
    };
    if c.wt.is_some() {
        return match h3conn::protocol(&c) {
            Some(p) => copy_out(&p, out, cap),
            None => SBQ_ERR_STATE,
        };
    }
    let Some(qc) = c.connection() else {
        return SBQ_ERR_STATE;
    };
    let proto = qc
        .handshake_data()
        .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol);
    match proto {
        Some(p) => copy_out(&p, out, cap),
        None => SBQ_ERR_STATE,
    }
}

/// Copies the peer's address (`ip:port`, IPv6 in brackets) into `out`; returns its length.
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_remote(conn: u64, out: *mut u8, cap: usize) -> i64 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE;
    };
    let Some(qc) = c.connection() else {
        return SBQ_ERR_STATE;
    };
    copy_out(qc.remote_address().to_string().as_bytes(), out, cap)
}

/// Changes how many bidirectional streams the peer may have open at once (MAX_STREAMS). On a
/// WebTransport session, the limit of its QUIC connection: `count` plus the CONNECT stream (the
/// sessions pooled on a connection share it).
#[no_mangle]
pub extern "C" fn sbq_conn_set_max_bidi(conn: u64, count: u64) -> i32 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE as i32;
    };
    let Some(qc) = c.connection() else {
        return SBQ_ERR_STATE as i32;
    };
    let count = if c.wt.is_some() {
        count.saturating_add(1)
    } else {
        count
    };
    let Some(n) = code(count) else {
        return SBQ_ERR_ARG as i32;
    };
    qc.set_max_concurrent_bi_streams(n);
    SBQ_OK as i32
}

/// Fills `out` with the connection's statistics.
#[no_mangle]
pub unsafe extern "C" fn sbq_conn_stats(conn: u64, out: *mut SbqStats) -> i32 {
    let Some(c) = get(&CONNS, conn) else {
        return SBQ_ERR_HANDLE as i32;
    };
    let Some(qc) = c.connection() else {
        return SBQ_ERR_STATE as i32;
    };
    if out.is_null() {
        return SBQ_ERR_ARG as i32;
    }
    let s = qc.stats();
    *out = SbqStats {
        rtt_us: s.path.rtt.as_micros() as u64,
        cwnd: s.path.cwnd,
        congestion_events: s.path.congestion_events,
        lost_packets: s.path.lost_packets,
        sent_packets: s.path.sent_packets,
        udp_tx_bytes: s.udp_tx.bytes,
        udp_rx_bytes: s.udp_rx.bytes,
        udp_tx_datagrams: s.udp_tx.datagrams,
        udp_rx_datagrams: s.udp_rx.datagrams,
    };
    SBQ_OK as i32
}

/// Opens a bidirectional stream: returns its handle if the peer's stream limit allows it now,
/// otherwise `SBQ_WOULD_BLOCK` and an OPENED event carries the stream once it does (one event
/// per blocked call). Nothing reaches the peer before the first write. `SBQ_ERR_STATE` during
/// the handshake; `SBQ_ERR_CONNECTION` once the connection has ended, also when its handshake
/// never completed. On a WebTransport session the stream carries the session's header;
/// `SBQ_ERR_STATE` before the session is live, `SBQ_ERR_CONNECTION` once the session or its
/// connection has ended.
#[no_mangle]
pub extern "C" fn sbq_stream_open(conn: u64) -> i64 {
    stream::open(conn)
}

/// Writes up to `len` (> 0) bytes; returns how many were accepted (the peer's flow control
/// credit bounds it), `SBQ_WOULD_BLOCK` (WRITABLE follows), the peer's STOP_SENDING code at or
/// below `-SBQ_CODE_BASE` (the direction has been reset with it; `SBQ_NO_CODE` on a WebTransport
/// stream for a code outside the application range), or an error (`SBQ_ERR_STATE` on a stream
/// without a send direction). On a stream of a WebTransport session this side opened, the stream
/// header goes first, ahead of the data and the FIN.
#[no_mangle]
pub unsafe extern "C" fn sbq_stream_write(stream: u64, data: *const u8, len: usize) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) => s.write(bytes(data, len)),
        None => SBQ_ERR_HANDLE,
    }
}

/// Reads up to `cap` (> 0) bytes into `buf`; returns how many, `SBQ_WOULD_BLOCK` (READABLE
/// follows), `SBQ_FIN`, the peer's reset code at or below `-SBQ_CODE_BASE` (`SBQ_NO_CODE` as for
/// writes), or an error.
/// Data not read stays in quinn and holds back the peer's flow control credit.
#[no_mangle]
pub unsafe extern "C" fn sbq_stream_read(stream: u64, buf: *mut u8, cap: usize) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) if !buf.is_null() => s.read(std::slice::from_raw_parts_mut(buf, cap)),
        Some(_) => SBQ_ERR_ARG,
        None => SBQ_ERR_HANDLE,
    }
}

/// Whether the peer reset the receive direction, without reading from it: the peer's reset code
/// at or below `-SBQ_CODE_BASE` (the direction has ended; reads return the same code),
/// `SBQ_WOULD_BLOCK` (a READABLE follows the next change of the direction: data, FIN or a reset;
/// call again then if no read is pending), `SBQ_FIN` when no reset can come any more (FIN was
/// read, or every byte was), `SBQ_ERR_CLOSED` after `sbq_stream_stop`, or an error. Lets an
/// embedder whose reader is paused observe an abort; quinn discards a reset direction's
/// unread data anyway.
#[no_mangle]
pub extern "C" fn sbq_stream_poll_reset(stream: u64) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) => s.poll_reset(),
        None => SBQ_ERR_HANDLE,
    }
}

/// Finishes the send direction (FIN after everything written). FINISHED_ACKED follows once the
/// peer acknowledged every byte. Returns `SBQ_OK`, the code of a STOP_SENDING received, or an
/// error; on a WebTransport stream whose header could not be written yet, `SBQ_RETRY`
/// (WRITABLE follows; call again).
#[no_mangle]
pub extern "C" fn sbq_stream_finish(stream: u64) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) => s.finish(),
        None => SBQ_ERR_HANDLE,
    }
}

/// Resets the send direction with `code` (RESET_STREAM); also after a finish, to abandon what is
/// not acknowledged yet. A no-op on a direction reset already. On a WebTransport stream `code` is
/// an application code (u32, mapped into the HTTP/3 space); `SBQ_ERR_ARG` beyond. Without
/// RESET_STREAM_AT (quinn has none) a reset may lose the stream header with the data, and the
/// peer then cannot tell which session the reset stream belonged to.
#[no_mangle]
pub extern "C" fn sbq_stream_reset(stream: u64, code: u64) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) => s.reset(code),
        None => SBQ_ERR_HANDLE,
    }
}

/// Asks the peer to stop sending with `code` (STOP_SENDING); the receive direction ends here at
/// once, and data still arriving is discarded. A no-op once the direction has ended. Codes as for
/// `sbq_stream_reset`.
#[no_mangle]
pub extern "C" fn sbq_stream_stop(stream: u64, code: u64) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) => s.stop(code),
        None => SBQ_ERR_HANDLE,
    }
}

/// Sets the send priority: higher first, strictly; round robin within a level. Initially 0.
#[no_mangle]
pub extern "C" fn sbq_stream_set_priority(stream: u64, priority: i32) -> i64 {
    match get(&STREAMS, stream) {
        Some(s) => s.set_priority(priority),
        None => SBQ_ERR_HANDLE,
    }
}

/// Forgets a stream. End both directions first (finish or reset; read to the end, or stop):
/// like quinn's drop, release finishes an open send direction and stops an unread receive
/// direction with code 0.
#[no_mangle]
pub extern "C" fn sbq_stream_release(stream: u64) -> i32 {
    stream::release(stream)
}
