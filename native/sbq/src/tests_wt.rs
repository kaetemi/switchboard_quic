/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

//! Self test of WebTransport sessions through the ABI, this shim at both ends, and against a
//! peer written on raw quinn streams in the test (HTTP/3 by hand) that does what the shim's own
//! client never would: optimistic streams, a dynamic table reference, oversized and malformed
//! frames and capsules, a second control stream, more sessions than allowed, plain GET requests.

use std::time::{Duration, Instant};

use quinn::VarInt;

use super::tests::{self_signed, until, write_one, Harness};
use super::*;
use crate::h3::{self, err, frame, setting};
use crate::wt::{self, app_to_h3};

const H3: &[u8] = b"\x02h3";
const PROTOCOLS: &[&str] = &["switchboard", "other"];

fn wire(list: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in list {
        out.push(p.len() as u8);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

impl Harness {
    /// A WebTransport listener on the loopback (ALPN h3); `handshake_ms` also bounds a request's
    /// wait for its answer.
    fn wt_server(&mut self, handshake_ms: u64) -> (u64, u16) {
        self.wt_server_with(handshake_ms, 16)
    }

    /// A WebTransport listener granting `max_bidi` streams (and one for a CONNECT stream).
    fn wt_server_with(&mut self, handshake_ms: u64, max_bidi: u64) -> (u64, u16) {
        let (cert, key) = self_signed("localhost");
        let cfg = unsafe {
            sbq_server_config(
                H3.as_ptr(),
                H3.len(),
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
                max_bidi,
                1 << 20,
                16 << 20,
                30_000,
                0,
                handshake_ms,
            )
        };
        assert!(cfg > 0, "server config: {}", ctx::last_error());
        let host = b"127.0.0.1";
        let l = unsafe { sbq_listen(self.ctx, cfg as u64, host.as_ptr(), host.len(), 0) };
        assert!(l > 0, "listen: {}", ctx::last_error());
        sbq_config_free(cfg as u64);
        (l as u64, sbq_listener_port(l as u64) as u16)
    }

    /// Starts a session to `https://localhost:port{path}`.
    fn wt_dial(&mut self, port: u16, path: &str, origin: &str, protocols: &[&str]) -> u64 {
        let cfg = unsafe {
            sbq_client_config(
                H3.as_ptr(),
                H3.len(),
                SBQ_VERIFY_NONE,
                std::ptr::null(),
                0,
                16,
                1 << 20,
                16 << 20,
                30_000,
                0,
                5_000,
            )
        };
        assert!(cfg > 0);
        let host = b"127.0.0.1";
        let name = b"localhost";
        let authority = format!("localhost:{port}");
        let protocols = wire(protocols);
        let s = unsafe {
            sbq_connect_wt(
                self.ctx,
                cfg as u64,
                host.as_ptr(),
                host.len(),
                port,
                name.as_ptr(),
                name.len(),
                authority.as_ptr(),
                authority.len(),
                path.as_ptr(),
                path.len(),
                origin.as_ptr(),
                origin.len(),
                protocols.as_ptr(),
                protocols.len(),
            )
        };
        assert!(s > 0, "connect_wt: {}", ctx::last_error());
        sbq_config_free(cfg as u64);
        s as u64
    }

    /// The next request at `listener`: (session, version).
    fn wt_request(&mut self, listener: u64) -> (u64, i64) {
        let e = self.wait("request", |e| {
            e.kind == SBQ_EV_WT_REQUEST && e.a == listener as i64
        });
        (e.handle, e.b)
    }

    /// A session accepted with "switchboard": (client, server).
    fn wt_pair(&mut self, listener: u64, port: u16) -> (u64, u64) {
        let c = self.wt_dial(port, "/sb", "", PROTOCOLS);
        let (s, _) = self.wt_request(listener);
        let p = b"switchboard";
        assert_eq!(unsafe { sbq_wt_accept(s, p.as_ptr(), p.len()) }, 0);
        self.wait("connected", |e| e.kind == SBQ_EV_CONNECTED && e.handle == c);
        (c, s)
    }

    fn closed(&mut self, h: u64) -> SbqEvent {
        self.wait("closed", |e| e.kind == SBQ_EV_CLOSED && e.handle == h)
    }

    /// The next stream the peer opened on `session`.
    fn stream_of(&mut self, session: u64) -> u64 {
        self.wait("stream", |e| {
            e.kind == SBQ_EV_STREAM && e.a == session as i64
        })
        .handle
    }
}

fn field(s: u64, f: i32) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 512];
    let n = unsafe { sbq_wt_request(s, f, buf.as_mut_ptr(), buf.len()) };
    (n >= 0).then(|| buf[..n as usize].to_vec())
}

fn text_of(h: u64, f: impl Fn(u64, *mut u8, usize) -> i64) -> Option<String> {
    let mut buf = vec![0u8; 2048];
    let n = f(h, buf.as_mut_ptr(), buf.len());
    (n >= 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

fn exporter(h: u64, label: &[u8], context: &[u8]) -> Result<[u8; 32], i32> {
    let mut out = [0u8; 32];
    let r = unsafe {
        sbq_conn_exporter(
            h,
            label.as_ptr(),
            label.len(),
            context.as_ptr(),
            context.len(),
            out.as_mut_ptr(),
            32,
        )
    };
    if r == 0 {
        Ok(out)
    } else {
        Err(r)
    }
}

fn reason_of(h: u64) -> String {
    text_of(h, |h, out, cap| unsafe {
        sbq_conn_close_reason(h, out, cap)
    })
    .expect("ended")
}

fn close(h: u64, code: u64, reason: &str) -> i32 {
    unsafe { sbq_conn_close(h, code, reason.as_ptr(), reason.len()) }
}

/// The QUIC connection under a session, from inside the crate.
fn quic_of(session: u64) -> quinn::Connection {
    let c = get(&CONNS, session).expect("a session");
    let h3 = c.wt.as_ref().unwrap().h3().expect("a connection");
    h3.conn.clone()
}

#[test]
fn a_session_accepted_with_its_protocol_streams_both_ways_and_the_exporter() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    let c = h.wt_dial(port, "/sb?x=1", "https://app.example", PROTOCOLS);
    // Not established yet: no protocol, no exporter, no stream.
    assert_eq!(
        text_of(c, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }),
        None
    );
    assert_eq!(sbq_stream_open(c), SBQ_ERR_STATE);
    let (s, version) = h.wt_request(l);
    // This side's client sends the draft-02 header: answered in draft-02.
    assert_eq!(version, 2);
    assert_eq!(
        field(s, SBQ_WT_AUTHORITY).unwrap(),
        format!("localhost:{port}").as_bytes()
    );
    assert_eq!(field(s, SBQ_WT_PATH).unwrap(), b"/sb?x=1");
    assert_eq!(field(s, SBQ_WT_ORIGIN).unwrap(), b"https://app.example");
    assert_eq!(field(s, SBQ_WT_PROTOCOLS).unwrap(), wire(PROTOCOLS));
    assert_eq!(field(s, 99), None);
    // The server's exporter exists before the answer: the session ID is known.
    let label = b"switchboard-ident";
    let early = exporter(s, label, b"").unwrap();
    // A protocol the client did not offer is refused.
    let bad = b"nope";
    assert_eq!(
        unsafe { sbq_wt_accept(s, bad.as_ptr(), bad.len()) },
        SBQ_ERR_ARG as i32
    );
    let p = b"switchboard";
    assert_eq!(unsafe { sbq_wt_accept(s, p.as_ptr(), p.len()) }, 0);
    assert_eq!(
        unsafe { sbq_wt_accept(s, p.as_ptr(), p.len()) },
        SBQ_ERR_STATE as i32
    );
    assert_eq!(sbq_wt_reject(s, 404), SBQ_ERR_STATE as i32);
    h.wait("connected", |e| e.kind == SBQ_EV_CONNECTED && e.handle == c);
    assert_eq!(
        text_of(c, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }).unwrap(),
        "switchboard"
    );
    assert_eq!(
        text_of(s, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }).unwrap(),
        "switchboard"
    );
    assert_eq!(
        text_of(c, |h, o, n| unsafe { sbq_conn_remote(h, o, n) }).unwrap(),
        format!("127.0.0.1:{port}")
    );
    let mut hash = [0u8; 32];
    assert_eq!(
        unsafe { sbq_conn_peer_cert_sha256(c, hash.as_mut_ptr()) },
        0
    );

    // The exporter: equal at both ends, the draft's derivation over session ID 0, different
    // for another label or context, and for another session.
    let ec = exporter(c, label, b"").unwrap();
    assert_eq!(ec, early);
    assert_eq!(exporter(s, label, b"").unwrap(), ec);
    let mut manual = [0u8; 32];
    quic_of(c)
        .export_keying_material(
            &mut manual,
            wt::EXPORTER_LABEL,
            &wt::exporter_context(0, label, b"").unwrap(),
        )
        .unwrap();
    assert_eq!(manual, ec);
    assert_ne!(exporter(c, b"other", b"").unwrap(), ec);
    assert_ne!(exporter(c, label, &[1]).unwrap(), ec);
    assert_eq!(exporter(c, &[0; 256], b""), Err(SBQ_ERR_ARG as i32));
    let (c2, s2) = h.wt_pair(l, port);
    assert_eq!(
        exporter(c2, label, b"").unwrap(),
        exporter(s2, label, b"").unwrap()
    );
    assert_ne!(exporter(c2, label, b"").unwrap(), ec);

    // Streams: the client's, then the server's, with FIN both ways.
    let cs = sbq_stream_open(c) as u64;
    assert!(cs > 0);
    h.write_all(cs, b"hello");
    assert_eq!(sbq_stream_finish(cs), 0);
    let ss = h.stream_of(s);
    assert_eq!(h.read_all(ss), Ok(b"hello".to_vec()));
    h.write_all(ss, b"world");
    assert_eq!(sbq_stream_finish(ss), 0);
    assert_eq!(h.read_all(cs), Ok(b"world".to_vec()));
    h.wait("acked", |e| {
        e.kind == SBQ_EV_FINISHED_ACKED && e.handle == cs
    });
    let pushed = sbq_stream_open(s) as u64;
    assert!(pushed > 0);
    // A stream with nothing but FIN still carries its header.
    assert_eq!(sbq_stream_finish(pushed), 0);
    let got = h.stream_of(c);
    assert_eq!(h.read_all(got), Ok(Vec::new()));
    for x in [cs, ss, pushed, got] {
        assert_eq!(sbq_stream_release(x), 0);
    }
    // The stream limit counts the CONNECT stream on the server's side: 16 channels open at once
    // (on the second session, whose client has opened none yet).
    let streams: Vec<u64> = (0..16)
        .map(|_| {
            let x = sbq_stream_open(c2);
            assert!(x > 0, "{x}");
            assert_eq!(write_one(x as u64), 1);
            x as u64
        })
        .collect();
    assert_eq!(sbq_stream_open(c2), SBQ_WOULD_BLOCK);
    for x in streams {
        sbq_stream_reset(x, 0);
    }
}

#[test]
fn refusals_carry_their_status() {
    let mut h = Harness::new();
    // This bounds TLS, HTTP/3 and the unanswered request below. Allow a loaded runner or
    // an emulated debug build to handshake, while staying below the client's 5 s deadline.
    let (l, port) = h.wt_server(2_000);
    for status in [404u32, 403, 400] {
        let c = h.wt_dial(port, "/elsewhere", "https://evil.example", PROTOCOLS);
        let (s, _) = h.wt_request(l);
        assert_eq!(sbq_wt_reject(s, status), 0);
        assert_eq!(sbq_wt_reject(s, status), SBQ_ERR_STATE as i32);
        assert_eq!(sbq_conn_release(s), 0);
        let e = h.closed(c);
        assert_eq!((e.a, e.b), (SBQ_CLOSE_REFUSED, status as i64));
        assert_eq!(reason_of(c), format!("HTTP status {status}"));
        assert_eq!(sbq_conn_release(c), 0);
    }
    assert_eq!(sbq_wt_reject(12345, 404), SBQ_ERR_HANDLE as i32);
    // Not answered within the deadline: 503 at both ends.
    let c = h.wt_dial(port, "/sb", "", &[]);
    let (s, _) = h.wt_request(l);
    assert_eq!(field(s, SBQ_WT_PROTOCOLS).unwrap(), b"");
    assert_eq!(field(s, SBQ_WT_ORIGIN), None);
    let e = h.closed(s);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_REFUSED, 503));
    let e = h.closed(c);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_REFUSED, 503));
    let p = b"";
    assert_eq!(
        unsafe { sbq_wt_accept(s, p.as_ptr(), p.len()) },
        SBQ_ERR_STATE as i32
    );
    // Statuses outside 300 to 599 are not refusals.
    let _c = h.wt_dial(port, "/sb", "", &[]);
    let (s, _) = h.wt_request(l);
    assert_eq!(sbq_wt_reject(s, 200), SBQ_ERR_ARG as i32);
    assert_eq!(sbq_wt_reject(s, 600), SBQ_ERR_ARG as i32);
    // Accepted without a protocol: none selected.
    assert_eq!(unsafe { sbq_wt_accept(s, p.as_ptr(), 0) }, 0);
    assert_eq!(
        text_of(s, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }).unwrap(),
        ""
    );
}

#[test]
fn close_with_code_and_reason_both_ways() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    // The client closes: WT_CLOSE_SESSION, then the QUIC connection once the server closed the
    // CONNECT stream.
    let (c, s) = h.wt_pair(l, port);
    assert_eq!(
        unsafe { sbq_conn_close(c, 7, [0xff].as_ptr(), 1) },
        SBQ_ERR_ARG as i32
    );
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"x");
    let ss = h.stream_of(s);
    let reason = format!("bad record {}", "é".repeat(600));
    assert_eq!(close(c, 42, &reason), 0);
    let e = h.closed(c);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_LOCAL, 42));
    let e = h.closed(s);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 42));
    let got = reason_of(s);
    assert!(got.len() <= 1024 && reason.starts_with(&got) && got.starts_with("bad record é"));
    assert_eq!(sbq_stream_open(c), SBQ_ERR_CONNECTION);
    // Its streams were reset with WT_SESSION_GONE, which carries no application code, if that
    // arrived first; then they ended with the session.
    let mut b = [0u8; 8];
    let r = loop {
        let r = unsafe { sbq_stream_read(ss, b.as_mut_ptr(), 8) };
        if r != SBQ_WOULD_BLOCK && r != 1 {
            break r;
        }
        h.sleep();
    };
    assert!(r == SBQ_ERR_CONNECTION || r == SBQ_NO_CODE, "{r}");
    let quic = quic_of(c);
    until("the QUIC connection closed", || {
        quic.close_reason().is_some()
    });
    // A code beyond u32 is not a WebTransport code.
    let (c, s) = h.wt_pair(l, port);
    assert_eq!(close(c, 1 << 32, ""), SBQ_ERR_ARG as i32);
    // The server closes.
    assert_eq!(close(s, 7, "going away"), 0);
    let e = h.closed(c);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 7));
    assert_eq!(reason_of(c), "going away");
    let e = h.closed(s);
    assert_eq!(e.a, SBQ_CLOSE_APP_LOCAL);
    let quic = quic_of(s);
    until("the QUIC connection closed", || {
        quic.close_reason().is_some()
    });
    // Released without a close: code 0, seen by the peer as a close.
    let (c, s) = h.wt_pair(l, port);
    assert_eq!(sbq_conn_release(c), 0);
    let e = h.closed(s);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 0));
    // A client abandoning its connect.
    let c = h.wt_dial(port, "/sb", "", &[]);
    assert_eq!(close(c, 1, "never mind"), 0);
    let e = h.closed(c);
    assert_eq!(e.a, SBQ_CLOSE_APP_LOCAL);
}

#[test]
fn draining_both_ways() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    let (c, s) = h.wt_pair(l, port);
    assert_eq!(sbq_wt_drain(c), 0);
    assert_eq!(sbq_wt_drain(c), 0);
    h.wait("draining", |e| e.kind == SBQ_EV_DRAINING && e.handle == s);
    assert_eq!(sbq_wt_drain(s), 0);
    h.wait("draining", |e| e.kind == SBQ_EV_DRAINING && e.handle == c);
    // The session goes on.
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"still");
    assert_eq!(sbq_stream_finish(cs), 0);
    let ss = h.stream_of(s);
    assert_eq!(h.read_all(ss), Ok(b"still".to_vec()));
    // Once only.
    std::thread::sleep(Duration::from_millis(100));
    h.pump();
    assert!(!h.backlog.iter().any(|e| e.kind == SBQ_EV_DRAINING));
    assert_eq!(close(c, 0, ""), 0);
    h.closed(s);
    assert_eq!(sbq_wt_drain(s), SBQ_ERR_STATE as i32);
}

#[test]
fn stream_codes_are_webtransport_codes_both_ways() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    let (c, s) = h.wt_pair(l, port);
    // A reset with 42: the peer reads 42, and the wire carried the HTTP/3 code of 42.
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"abc");
    let ss = h.stream_of(s);
    assert_eq!(sbq_stream_reset(cs, 42), 0);
    assert_eq!(h.read_all(ss), Err(42));
    // A stop with 5: the writer's STOPPED and write carry 5.
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"y");
    let ss = h.stream_of(s);
    assert_eq!(sbq_stream_stop(ss, 5), 0);
    let e = h.wait("stopped", |e| e.kind == SBQ_EV_STOPPED && e.handle == cs);
    assert_eq!(e.a, 5);
    assert_eq!(write_one(cs), -(SBQ_CODE_BASE + 5));
    // The other way, the largest code.
    let ss = sbq_stream_open(s) as u64;
    h.write_all(ss, b"z");
    let cs = h.stream_of(c);
    assert_eq!(sbq_stream_reset(ss, u32::MAX as u64), 0);
    assert_eq!(h.read_all(cs), Err(u32::MAX as u64));
    // Codes beyond u32 are argument errors.
    let cs = sbq_stream_open(c) as u64;
    assert_eq!(sbq_stream_reset(cs, 1 << 32), SBQ_ERR_ARG);
    assert_eq!(sbq_stream_stop(cs, 1 << 32), SBQ_ERR_ARG);
}

// ---------------------------------------------------------------------------------------------
// A peer on raw quinn streams.

/// A client written by hand: its SETTINGS, its requests, its streams.
struct Raw {
    conn: quinn::Connection,
    control: Option<quinn::SendStream>,
    _endpoint: quinn::Endpoint,
}

const WT_SETTINGS: &[(u64, u64)] = &[
    (setting::H3_DATAGRAM, 1),
    (setting::H3_DATAGRAM_DRAFT, 1),
    (setting::ENABLE_WEBTRANSPORT_DRAFT02, 1),
    (setting::WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 1),
];

#[track_caller]
fn block<F: std::future::Future>(f: F) -> F::Output {
    ctx::rt()
        .block_on(async { tokio::time::timeout(Duration::from_secs(10), f).await })
        .expect("timed out")
}

fn request_fields(path: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (b":method".to_vec(), b"CONNECT".to_vec()),
        (b":protocol".to_vec(), b"webtransport".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"localhost".to_vec()),
        (b":path".to_vec(), path.to_vec()),
    ]
}

fn headers(fields: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let f: Vec<(&[u8], &[u8])> = fields
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    h3::frame(frame::HEADERS, &h3::encode_field_section(&f))
}

fn capsule_frame(capsule: &[u8]) -> Vec<u8> {
    h3::frame(frame::DATA, capsule)
}

impl Raw {
    /// Connects and sends SETTINGS (`settings`, then `extra` raw bytes on the control stream).
    fn connect(port: u16, settings: &[(u64, u64)], extra: &[u8]) -> Raw {
        let mut b = vec![0u8];
        h3::put_frame(&mut b, frame::SETTINGS, &h3::encode_settings(settings));
        b.extend_from_slice(extra);
        Self::start(port, &b, 1 << 20)
    }

    fn start(port: u16, control_bytes: &[u8], stream_window: u64) -> Raw {
        block(async {
            let params = config::ClientParams {
                alpn: vec![b"h3".to_vec()],
                verify: config::Verify::None,
                limits: config::Limits {
                    max_bidi: 64,
                    stream_window,
                    conn_window: 16 << 20,
                    idle_ms: 30_000,
                    keep_alive_ms: 0,
                    handshake_ms: 0,
                },
            };
            let cc = config::client_config(&params, Default::default()).unwrap();
            let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            let conn = endpoint
                .connect_with(cc, ([127, 0, 0, 1], port).into(), "localhost")
                .unwrap()
                .await
                .unwrap();
            let mut control = conn.open_uni().await.unwrap();
            control.write_all(control_bytes).await.unwrap();
            Raw {
                conn,
                control: Some(control),
                _endpoint: endpoint,
            }
        })
    }

    fn wt(port: u16) -> Raw {
        Raw::connect(port, WT_SETTINGS, &[])
    }

    /// Opens a bidirectional stream without writing on it.
    #[track_caller]
    fn open(&self) -> (quinn::SendStream, quinn::RecvStream, u64) {
        block(async {
            let (s, r) = self.conn.open_bi().await.unwrap();
            let id = VarInt::from(s.id()).into_inner();
            (s, r, id)
        })
    }

    /// Opens a request stream and writes `bytes` on it.
    #[track_caller]
    fn request(&self, bytes: &[u8]) -> (quinn::SendStream, quinn::RecvStream, u64) {
        block(async {
            let (mut s, r) = self.conn.open_bi().await.unwrap();
            s.write_all(bytes).await.unwrap();
            let id = VarInt::from(s.id()).into_inner();
            (s, r, id)
        })
    }

    /// The status of the response on `r`, or the code the stream was reset with.
    #[track_caller]
    fn status(r: &mut quinn::RecvStream) -> Result<u16, u64> {
        block(async {
            loop {
                let mut b = [0u8; 2];
                if let Err(e) = r.read_exact(&mut b).await {
                    return match e {
                        quinn::ReadExactError::ReadError(quinn::ReadError::Reset(c)) => {
                            Err(c.into_inner())
                        }
                        e => panic!("{e}"),
                    };
                }
                let (t, len) = (b[0] as u64, b[1] as usize);
                let mut payload = vec![0u8; len];
                r.read_exact(&mut payload).await.unwrap();
                if t != frame::HEADERS {
                    continue;
                }
                let fields = h3::decode_field_section(&payload, 4096).unwrap();
                let (_, v) = fields.iter().find(|(n, _)| n == b":status").unwrap();
                return Ok(std::str::from_utf8(v).unwrap().parse().unwrap());
            }
        })
    }

    /// Opens a WebTransport bidirectional stream of session `sid` and writes `body`.
    fn wt_stream(&self, sid: u64, body: &[u8]) -> (quinn::SendStream, quinn::RecvStream) {
        let mut b = Vec::new();
        h3::put_varint(&mut b, frame::WT_STREAM);
        h3::put_varint(&mut b, sid);
        b.extend_from_slice(body);
        let (s, r, _) = self.request(&b);
        (s, r)
    }

    /// How the connection ended (within 10 s).
    #[track_caller]
    fn closed(&self) -> quinn::ConnectionError {
        block(self.conn.closed())
    }
}

fn closed_with(e: quinn::ConnectionError) -> u64 {
    match e {
        quinn::ConnectionError::ApplicationClosed(a) => a.error_code.into_inner(),
        e => panic!("not an application close: {e}"),
    }
}

/// The stream reset code a raw stream ends with (None: FIN or STOP).
#[track_caller]
fn reset_code(r: &mut quinn::RecvStream) -> Option<u64> {
    block(async {
        let mut b = [0u8; 4096];
        loop {
            match r.read(&mut b).await {
                Ok(Some(_)) => {}
                Ok(None) => return None,
                Err(quinn::ReadError::Reset(c)) => return Some(c.into_inner()),
                Err(e) => panic!("{e}"),
            }
        }
    })
}

#[track_caller]
fn stopped_code(s: &quinn::SendStream) -> Option<u64> {
    block(s.stopped()).unwrap().map(VarInt::into_inner)
}

#[test]
fn a_hand_written_client_on_raw_quinn_streams() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(1_000);
    let raw = Raw::connect(
        port,
        // GREASE and unknown settings are ignored.
        &[
            (setting::H3_DATAGRAM, 1),
            (setting::ENABLE_WEBTRANSPORT_DRAFT02, 1),
            (setting::WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 4),
            (0x1f * 7 + 0x21, 99),
            (0x4242, 1),
        ],
        // An unknown frame on the control stream.
        &h3::frame(0x21 + 0x1f, b"grease"),
    );
    // The CONNECT stream is opened first (stream 0), and written after a stream of its session
    // that therefore arrives before it: held, and delivered once the session is accepted.
    let (mut cs, mut cr, sid) = raw.open();
    assert_eq!(sid, 0);
    let (mut early, mut early_r) = raw.wt_stream(0, b"early");
    let mut req = h3::frame(0x21, b"ignored before HEADERS");
    req.extend(headers(&request_fields(b"/sb")));
    // Capsules sent before the response are processed once the session is accepted: an
    // unknown capsule and a drain.
    let mut capsules = Vec::new();
    wt::put_capsule(&mut capsules, 0x17 + 0x29, b"grease");
    capsules.extend(wt::drain_capsule());
    req.extend(capsule_frame(&capsules));
    block(async { cs.write_all(&req).await.unwrap() });
    let (s, version) = h.wt_request(l);
    // Without the draft-02 header, and with draft-07 settings: draft-07.
    assert_eq!(version, 7);
    assert_eq!(unsafe { sbq_wt_accept(s, std::ptr::null(), 0) }, 0);
    assert_eq!(Raw::status(&mut cr), Ok(200));
    h.wait("draining", |e| e.kind == SBQ_EV_DRAINING && e.handle == s);
    let held = h.stream_of(s);
    let mut b = [0u8; 5];
    let n = unsafe { sbq_stream_read(held, b.as_mut_ptr(), 5) };
    assert!(n > 0);
    // A reset with a code outside the WebTransport range: no application code.
    block(async { early.reset(VarInt::from_u32(0x100)).unwrap() });
    let mut r = unsafe { sbq_stream_read(held, b.as_mut_ptr(), 5) };
    while r >= 0 {
        h.wait("readable", |e| {
            e.kind == SBQ_EV_READABLE && e.handle == held
        });
        r = unsafe { sbq_stream_read(held, b.as_mut_ptr(), 5) };
    }
    assert_eq!(r, SBQ_NO_CODE);
    // A STOP_SENDING outside the range: STOPPED with -1, writes SBQ_NO_CODE.
    assert_eq!(write_one(held), 1);
    block(async { early_r.stop(VarInt::from_u32(0x10c)).unwrap() });
    let e = h.wait("stopped", |e| e.kind == SBQ_EV_STOPPED && e.handle == held);
    assert_eq!(e.a, -1);
    assert_eq!(write_one(held), SBQ_NO_CODE);
    // A unidirectional stream: delivered as UNI_STREAM, refused with UNSUPPORTED (36).
    let mut uni = block(async {
        let mut u = raw.conn.open_uni().await.unwrap();
        let mut b = Vec::new();
        h3::put_varint(&mut b, h3::stream_type::WEBTRANSPORT);
        h3::put_varint(&mut b, sid);
        b.extend_from_slice(b"uni");
        u.write_all(&b).await.unwrap();
        u
    });
    let e = h.wait("uni", |e| e.kind == SBQ_EV_UNI_STREAM && e.a == s as i64);
    assert_eq!(write_one(e.handle), SBQ_ERR_STATE);
    assert_eq!(sbq_stream_stop(e.handle, 36), 0);
    assert_eq!(stopped_code(&uni), Some(app_to_h3(36)));
    let _ = uni.reset(VarInt::from_u32(0));
    // An unknown unidirectional stream type is refused with H3_STREAM_CREATION_ERROR.
    let reserved = block(async {
        let mut u = raw.conn.open_uni().await.unwrap();
        u.write_all(&[0x21]).await.unwrap();
        u
    });
    assert_eq!(stopped_code(&reserved), Some(err::H3_STREAM_CREATION_ERROR));
    // Stream 4 was a data stream, so it can never become a CONNECT session.
    let (_late, mut late_r) = raw.wt_stream(4, b"not a CONNECT");
    assert_eq!(reset_code(&mut late_r), Some(wt::err::WT_SESSION_GONE));
    // A future session is held, then refused once the deadline passed.
    let (_late, mut late_r) = raw.wt_stream(400, b"nobody");
    assert_eq!(
        reset_code(&mut late_r),
        Some(wt::err::WT_BUFFERED_STREAM_REJECTED)
    );
    // A GET: 404, and the stream finished.
    let mut get = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"localhost".to_vec()),
        (b":path".to_vec(), b"/".to_vec()),
    ];
    let (_gs, mut gr, _) = raw.request(&headers(&get));
    assert_eq!(Raw::status(&mut gr), Ok(404));
    assert_eq!(reset_code(&mut gr), None);
    // A malformed request (an uppercase name): reset with H3_MESSAGE_ERROR.
    get.push((b"X-Upper".to_vec(), b"1".to_vec()));
    let (_ms, mut mr, _) = raw.request(&headers(&get));
    assert_eq!(Raw::status(&mut mr), Err(err::H3_MESSAGE_ERROR));
    // An HTTP/3 GOAWAY from the client: the session is draining (once: it is already).
    // The session closes with a FIN without a capsule: code 0, by the peer.
    block(async { cs.finish().unwrap() });
    let e = h.closed(s);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 0));
    // The server closed its side of the CONNECT stream in turn, then the QUIC connection: its
    // only session is done.
    assert_eq!(reset_code(&mut cr), None);
    assert_eq!(closed_with(raw.closed()), err::H3_NO_ERROR);
    drop(raw.control);
}

#[test]
fn sessions_on_one_connection_goaway_reset_and_the_listener_closing() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server_with(5_000, 64);
    let raw = Raw::wt(port);
    // Up to 16 sessions on one connection; the 17th is rejected with H3_REQUEST_REJECTED.
    let mut sessions = Vec::new();
    for _ in 0..16 {
        let (s, r, sid) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        sessions.push((s, r, sid, session));
    }
    let (_s, mut r, _) = raw.request(&headers(&request_fields(b"/sb")));
    assert_eq!(Raw::status(&mut r), Err(err::H3_REQUEST_REJECTED));
    for (_, r, _, session) in sessions.iter_mut() {
        assert_eq!(unsafe { sbq_wt_accept(*session, std::ptr::null(), 0) }, 0);
        assert_eq!(Raw::status(r), Ok(200));
    }
    // Each session's exporter is its own.
    let a = exporter(sessions[0].3, b"switchboard-ident", b"").unwrap();
    let b = exporter(sessions[1].3, b"switchboard-ident", b"").unwrap();
    assert_ne!(a, b);
    let mut manual = [0u8; 32];
    raw.conn
        .export_keying_material(
            &mut manual,
            wt::EXPORTER_LABEL,
            &wt::exporter_context(sessions[1].2, b"switchboard-ident", b"").unwrap(),
        )
        .unwrap();
    assert_eq!(manual, b);
    // A reset CONNECT stream: the session is lost.
    let (s0, _, _, session0) = &mut sessions[0];
    block(async { s0.reset(VarInt::from_u32(0x10c)).unwrap() });
    let e = h.closed(*session0);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_SESSION_RESET, 0x10c));
    // A close capsule with a message over 1024 bytes: the session ends, the stream is reset
    // with H3_MESSAGE_ERROR.
    let (s1, r1, _, session1) = &mut sessions[1];
    let mut capsule = Vec::new();
    let mut payload = 7u32.to_be_bytes().to_vec();
    payload.extend(std::iter::repeat_n(b'x', 2000));
    wt::put_capsule(&mut capsule, wt::capsule::WT_CLOSE_SESSION, &payload);
    block(async { s1.write_all(&capsule_frame(&capsule)).await.unwrap() });
    let e = h.closed(*session1);
    assert_eq!(
        (e.a, e.b),
        (SBQ_CLOSE_H3_LOCAL, err::H3_MESSAGE_ERROR as i64)
    );
    assert_eq!(reset_code(r1), Some(err::H3_MESSAGE_ERROR));
    // A close capsule split across DATA frames and behind GREASE frames still closes.
    let (s2, _, _, session2) = &mut sessions[2];
    let close = wt::close_capsule(9, b"split");
    let mut b = h3::frame(frame::DATA, &close[..3]);
    b.extend(h3::frame(0x21, b"grease"));
    b.extend(h3::frame(frame::DATA, &close[3..]));
    block(async { s2.write_all(&b).await.unwrap() });
    let e = h.closed(*session2);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 9));
    assert_eq!(reason_of(*session2), "split");
    // The listener closes: new requests on the open connection get 503.
    assert_eq!(sbq_listener_close(l), 0);
    let (_s, mut r, _) = raw.request(&headers(&request_fields(b"/sb")));
    assert_eq!(Raw::status(&mut r), Ok(503));
    // An HTTP/3 GOAWAY from the client: every open session drains.
    let mut goaway = Vec::new();
    h3::put_frame(&mut goaway, frame::GOAWAY, &[0]);
    let mut raw = raw;
    let mut control = raw.control.take();
    block(async { control.as_mut().unwrap().write_all(&goaway).await.unwrap() });
    for (_, _, _, session) in &sessions[3..] {
        h.wait("draining", |e| {
            e.kind == SBQ_EV_DRAINING && e.handle == *session
        });
    }
    // The control stream ends: H3_CLOSED_CRITICAL_STREAM, and every session is lost with it.
    block(async { control.as_mut().unwrap().finish().unwrap() });
    assert_eq!(closed_with(raw.closed()), err::H3_CLOSED_CRITICAL_STREAM);
    for (_, _, _, session) in &sessions[3..] {
        let e = h.closed(*session);
        assert_eq!(
            (e.a, e.b),
            (SBQ_CLOSE_H3_LOCAL, err::H3_CLOSED_CRITICAL_STREAM as i64)
        );
    }
}

#[test]
fn protocol_violations_close_the_connection_with_their_code() {
    let mut h = Harness::new();
    // Room for more streams than the held ones.
    let (_, port) = h.wt_server_with(5_000, 64);
    let (_, idle_port) = h.wt_server(1_000);
    let violation = |settings: &[(u64, u64)], extra: &[u8], then: &dyn Fn(&Raw)| -> u64 {
        let raw = Raw::connect(port, settings, extra);
        then(&raw);
        closed_with(raw.closed())
    };
    let nothing = |_: &Raw| {};
    // A field section that refers to the dynamic table (RFC 9204 B.2).
    let dynamic = |raw: &Raw| {
        raw.request(&h3::frame(frame::HEADERS, &[0x03, 0x81, 0x10, 0x11]));
    };
    assert_eq!(
        violation(WT_SETTINGS, &[], &dynamic),
        err::QPACK_DECOMPRESSION_FAILED
    );
    // A duplicate setting.
    assert_eq!(
        violation(&[(0x33, 1), (0x33, 1)], &[], &nothing),
        err::H3_SETTINGS_ERROR
    );
    // A first frame that is not SETTINGS (the raw client's SETTINGS come after it).
    let raw = block(async {
        let params = config::ClientParams {
            alpn: vec![b"h3".to_vec()],
            verify: config::Verify::None,
            limits: config::Limits {
                max_bidi: 4,
                stream_window: 1 << 20,
                conn_window: 1 << 20,
                idle_ms: 30_000,
                keep_alive_ms: 0,
                handshake_ms: 0,
            },
        };
        let cc = config::client_config(&params, Default::default()).unwrap();
        let ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let conn = ep
            .connect_with(cc, ([127, 0, 0, 1], port).into(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let mut u = conn.open_uni().await.unwrap();
        let mut b = vec![0u8];
        h3::put_frame(&mut b, frame::GOAWAY, &[0]);
        u.write_all(&b).await.unwrap();
        (conn, ep, u)
    });
    assert_eq!(closed_with(block(raw.0.closed())), err::H3_MISSING_SETTINGS);
    // A second control stream.
    let second = |raw: &Raw| {
        block(async {
            let mut u = raw.conn.open_uni().await.unwrap();
            let mut b = vec![0u8];
            h3::put_frame(&mut b, frame::SETTINGS, &[]);
            u.write_all(&b).await.unwrap();
            std::mem::forget(u);
        })
    };
    assert_eq!(
        violation(WT_SETTINGS, &[], &second),
        err::H3_STREAM_CREATION_ERROR
    );
    // DATA on the control stream.
    assert_eq!(
        violation(WT_SETTINGS, &h3::frame(frame::DATA, b"x"), &nothing),
        err::H3_FRAME_UNEXPECTED
    );
    // A SETTINGS frame over 4 KiB.
    let many: Vec<(u64, u64)> = (0..1000).map(|i| (0x1000 + i, 0)).collect();
    assert_eq!(violation(&many, &[], &nothing), err::H3_EXCESSIVE_LOAD);
    // An encoder stream inserting into the table this side does not have.
    let encoder = |raw: &Raw| {
        block(async {
            let mut u = raw.conn.open_uni().await.unwrap();
            u.write_all(&[0x02, 0x3f, 0xbd, 0x01]).await.unwrap();
            std::mem::forget(u);
        })
    };
    assert_eq!(
        violation(WT_SETTINGS, &[], &encoder),
        err::QPACK_ENCODER_STREAM_ERROR
    );
    // A session ID that is not a client-initiated bidirectional stream.
    let bad_id = |raw: &Raw| {
        raw.wt_stream(2, b"x");
    };
    assert_eq!(violation(WT_SETTINGS, &[], &bad_id), err::H3_ID_ERROR);
    // DATA before HEADERS on a request.
    let data_first = |raw: &Raw| {
        raw.request(&h3::frame(frame::DATA, b"x"));
    };
    assert_eq!(
        violation(WT_SETTINGS, &[], &data_first),
        err::H3_FRAME_UNEXPECTED
    );
    // Stream-level refusals leave the connection up: a HEADERS frame over 16 KiB.
    let raw = Raw::wt(port);
    let mut big = Vec::new();
    h3::put_varint(&mut big, frame::HEADERS);
    h3::put_varint(&mut big, 20_000);
    big.extend(std::iter::repeat_n(0u8, 20_000));
    let (_s, mut r, _) = raw.request(&big);
    assert_eq!(Raw::status(&mut r), Err(err::H3_EXCESSIVE_LOAD));
    // A client whose SETTINGS lack WebTransport: its requests are malformed.
    let plain = Raw::connect(port, &[(0x33, 1)], &[]);
    let (_s, mut r, _) = plain.request(&headers(&request_fields(b"/sb")));
    assert_eq!(Raw::status(&mut r), Err(err::H3_MESSAGE_ERROR));
    // More streams held than allowed: the ones beyond 16 are refused at once.
    let streams: Vec<_> = (0..20).map(|i| raw.wt_stream(400, &[i])).collect();
    let refused = streams
        .into_iter()
        .filter_map(|(_s, mut r)| {
            block(async {
                let mut b = [0u8; 1];
                tokio::time::timeout(Duration::from_millis(300), r.read(&mut b))
                    .await
                    .ok()
            })
        })
        .filter(|x| {
            matches!(x, Err(quinn::ReadError::Reset(c)) if c.into_inner() == wt::err::WT_BUFFERED_STREAM_REJECTED)
        })
        .count();
    assert_eq!(refused, 4);
    // A connection with no session is closed after the request deadline.
    let idle = Raw::wt(idle_port);
    let started = Instant::now();
    assert_eq!(closed_with(idle.closed()), err::H3_NO_ERROR);
    assert!(started.elapsed() >= Duration::from_millis(900));
}

#[test]
fn a_server_without_webtransport_and_a_client_dialling_raw_quic() {
    let mut h = Harness::new();
    // A listener of raw QUIC: the WebTransport client's handshake fails (no common ALPN).
    let (_l, port, _) = h.server(16, 1 << 20, 30_000);
    let c = h.wt_dial(port, "/sb", "", &[]);
    let e = h.closed(c);
    assert_eq!(
        e.a,
        SBQ_CLOSE_TRANSPORT_LOCAL
            .max(e.a)
            .min(SBQ_CLOSE_TRANSPORT_REMOTE)
    );
    // A configuration without h3 cannot dial WebTransport.
    let cfg = unsafe {
        sbq_client_config(
            b"\x0bswitchboard".as_ptr(),
            12,
            SBQ_VERIFY_NONE,
            std::ptr::null(),
            0,
            16,
            1 << 20,
            16 << 20,
            30_000,
            0,
            0,
        )
    };
    let x = b"x";
    let path = b"/sb";
    let r = unsafe {
        sbq_connect_wt(
            h.ctx,
            cfg as u64,
            x.as_ptr(),
            1,
            1,
            x.as_ptr(),
            1,
            x.as_ptr(),
            1,
            path.as_ptr(),
            3,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(r, SBQ_ERR_ARG);
    sbq_config_free(cfg as u64);
    // An HTTP/3 server whose SETTINGS lack WebTransport: closed with WT_REQUIREMENTS_NOT_MET.
    let (cert, key) = self_signed("localhost");
    let sc = config::server_config(
        vec![b"h3".to_vec()],
        &cert,
        &key,
        &config::Limits {
            max_bidi: 4,
            stream_window: 1 << 20,
            conn_window: 1 << 20,
            idle_ms: 30_000,
            keep_alive_ms: 0,
            handshake_ms: 0,
        },
    )
    .unwrap();
    let endpoint = {
        let _g = ctx::rt().enter();
        quinn::Endpoint::server(sc, "127.0.0.1:0".parse().unwrap()).unwrap()
    };
    let port = endpoint.local_addr().unwrap().port();
    let server = ctx::rt().spawn(async move {
        let conn = endpoint.accept().await.unwrap().await.unwrap();
        let mut u = conn.open_uni().await.unwrap();
        let mut b = vec![0u8];
        h3::put_frame(&mut b, frame::SETTINGS, &h3::encode_settings(&[(0x33, 1)]));
        u.write_all(&b).await.unwrap();
        let e = conn.closed().await;
        drop(u);
        e
    });
    let c = h.wt_dial(port, "/sb", "", &[]);
    let e = h.closed(c);
    assert_eq!(
        (e.a, e.b),
        (SBQ_CLOSE_H3_LOCAL, wt::err::WT_REQUIREMENTS_NOT_MET as i64)
    );
    let e = block(server).unwrap();
    assert_eq!(closed_with(e), wt::err::WT_REQUIREMENTS_NOT_MET);
}

#[test]
fn a_mixed_listener_serves_raw_quic_and_webtransport_on_one_port() {
    let mut h = Harness::new();
    let alpn = b"\x02h3\x0bswitchboard";
    let (cert, key) = self_signed("localhost");
    let cfg = unsafe {
        sbq_server_config(
            alpn.as_ptr(),
            alpn.len(),
            cert.as_ptr(),
            cert.len(),
            key.as_ptr(),
            key.len(),
            16,
            1 << 20,
            16 << 20,
            30_000,
            0,
            5_000,
        )
    };
    let host = b"127.0.0.1";
    let l = unsafe { sbq_listen(h.ctx, cfg as u64, host.as_ptr(), host.len(), 0) } as u64;
    sbq_config_free(cfg as u64);
    let port = sbq_listener_port(l) as u16;
    let (c, s) = h.wt_pair(l, port);
    assert_eq!(
        text_of(s, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }).unwrap(),
        "switchboard"
    );
    let raw = h.dial(port, SBQ_VERIFY_NONE, &[], 30_000);
    h.wait("connected", |e| {
        e.kind == SBQ_EV_CONNECTED && e.handle == raw
    });
    let incoming = h
        .wait("incoming", |e| e.kind == SBQ_EV_INCOMING && e.a == l as i64)
        .handle;
    assert_eq!(
        text_of(incoming, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }).unwrap(),
        "switchboard"
    );
    assert_eq!(
        text_of(raw, |h, o, n| unsafe { sbq_conn_protocol(h, o, n) }).unwrap(),
        "switchboard"
    );
    let _ = c;
}

#[test]
fn shutdown_ends_sessions_and_their_connections() {
    let mut server = Harness::new();
    let mut client = Harness::new();
    let (l, port) = server.wt_server(5_000);
    let c = client.wt_dial(port, "/sb", "", &[]);
    let (s, _) = server.wt_request(l);
    assert_eq!(unsafe { sbq_wt_accept(s, std::ptr::null(), 0) }, 0);
    client.wait("connected", |e| e.kind == SBQ_EV_CONNECTED && e.handle == c);
    let quic = quic_of(c);
    assert_eq!(sbq_shutdown(client.ctx), 0);
    let e = server.closed(s);
    assert!(
        e.a == SBQ_CLOSE_APP_REMOTE || e.a == SBQ_CLOSE_H3_REMOTE,
        "{e:?}"
    );
    until("the QUIC connection closed", || {
        quic.close_reason().is_some()
    });
}

#[test]
fn the_stream_limit_of_a_session() {
    // 2 streams for the client's channels (and one for its CONNECT stream): a third waits until
    // one of them ended both ways.
    let mut h = Harness::new();
    let (l, port) = h.wt_server_with(5_000, 2);
    let (c, s) = h.wt_pair(l, port);
    let s1 = sbq_stream_open(c) as u64;
    let s2 = sbq_stream_open(c) as u64;
    assert!(s1 > 0 && s2 > 0);
    h.write_all(s1, b"1");
    h.write_all(s2, b"2");
    assert_eq!(sbq_stream_open(c), SBQ_WOULD_BLOCK);
    assert_eq!(sbq_stream_finish(s1), 0);
    // The session's streams may be announced out of their order: each one's header is read on
    // its own.
    let (a, b) = (h.stream_of(s), h.stream_of(s));
    let mut first = [0u8; 1];
    let mut byte = |x: u64| loop {
        let n = unsafe { sbq_stream_read(x, first.as_mut_ptr(), 1) };
        if n == 1 {
            return first[0];
        }
        assert_eq!(n, SBQ_WOULD_BLOCK);
        h.wait("readable", |e| e.kind == SBQ_EV_READABLE && e.handle == x);
    };
    let r1 = if byte(a) == b'1' { a } else { b };
    if r1 == b {
        byte(b);
    }
    assert_eq!(h.read_all(r1), Ok(Vec::new()));
    assert_eq!(sbq_stream_finish(r1), 0);
    assert_eq!(h.read_all(s1), Ok(Vec::new()));
    let e = h.wait("opened", |e| e.kind == SBQ_EV_OPENED && e.a == c as i64);
    h.write_all(e.handle, b"3");
    assert_eq!(sbq_stream_finish(e.handle), 0);
    let r3 = h.stream_of(s);
    assert_eq!(h.read_all(r3), Ok(b"3".to_vec()));
}

/// Seconds since 1970 of a UTCTime `YYMMDDHHMMSSZ` (years 2000 to 2049).
fn utc_time(t: &[u8]) -> i64 {
    let n = |i: usize| i64::from(t[i] - b'0') * 10 + i64::from(t[i + 1] - b'0');
    let (y, m, d) = (2000 + n(0), n(2), n(4));
    // Days from the civil date (H. Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + n(6) * 3600 + n(8) * 60 + n(10)
}

#[test]
fn a_self_signed_certificate_a_browser_accepts_for_its_hash() {
    // The W3C API's serverCertificateHashes: X.509v3, an ECDSA P-256 key, a validity period
    // that is current and at most 14 days long.
    let (cert, _key) = self_signed("127.0.0.1");
    let find = |pattern: &[u8]| cert.windows(pattern.len()).position(|w| w == pattern);
    // version [0] INTEGER 2 (v3)
    assert!(find(&[0xa0, 0x03, 0x02, 0x01, 0x02]).is_some());
    // id-ecPublicKey and prime256v1
    assert!(find(&[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]).is_some());
    assert!(find(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]).is_some());
    // subjectAltName with iPAddress 127.0.0.1.
    assert!(find(&[0x06, 0x03, 0x55, 0x1d, 0x11]).is_some());
    assert!(find(&[0x87, 0x04, 127, 0, 0, 1]).is_some());
    // The validity: two UTCTimes.
    let at = find(&[0x17, 0x0d]).expect("notBefore");
    let not_before = utc_time(&cert[at + 2..at + 15]);
    let at2 = at + 15 + find_from(&cert[at + 15..], &[0x17, 0x0d]).expect("notAfter");
    let not_after = utc_time(&cert[at2 + 2..at2 + 15]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert_eq!(not_after - not_before, 14 * 86400);
    assert!(not_before <= now && now < not_after);
    assert!(now - not_before <= 6 * 60, "{}", now - not_before);
}

fn find_from(b: &[u8], pattern: &[u8]) -> Option<usize> {
    b.windows(pattern.len()).position(|w| w == pattern)
}

#[test]
fn truncated_frames_are_connection_errors_at_every_boundary() {
    let mut h = Harness::new();
    let (_, port) = h.wt_server(5_000);
    // Unknown frame type and length use all eight bytes; partial varints and payloads must
    // produce H3_FRAME_ERROR rather than a clean FIN, session reset, or critical-stream error.
    let mut frame = Vec::new();
    h3::put_varint(&mut frame, 1 << 40);
    frame.extend_from_slice(&[0xc0, 0, 0, 0, 0, 0, 0, 4]);
    frame.extend_from_slice(b"abcd");
    for end in 1..frame.len() {
        let raw = Raw::wt(port);
        let (mut send, _recv, _) = raw.request(&frame[..end]);
        block(async { send.finish().unwrap() });
        assert_eq!(
            closed_with(raw.closed()),
            err::H3_FRAME_ERROR,
            "request {end}"
        );
    }
    let mut settings = vec![0];
    h3::put_frame(
        &mut settings,
        frame::SETTINGS,
        &h3::encode_settings(WT_SETTINGS),
    );
    for end in 2..settings.len() {
        let mut raw = Raw::start(port, &settings[..end], 1 << 20);
        block(async { raw.control.as_mut().unwrap().finish().unwrap() });
        assert_eq!(
            closed_with(raw.closed()),
            err::H3_FRAME_ERROR,
            "control {end}"
        );
    }
}

#[test]
fn connect_capsules_and_trailers_are_validated() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    // Capsule truncations at DATA boundaries are message errors; incomplete DATA itself is
    // a frame error and affects the connection. GREASE capsules and empty DATA remain legal.
    let capsule = wt::close_capsule(7, b"hello");
    for end in 1..capsule.len() {
        let raw = Raw::wt(port);
        let (mut send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
        assert_eq!(Raw::status(&mut recv), Ok(200));
        block(async {
            send.write_all(&capsule_frame(&capsule[..end]))
                .await
                .unwrap();
            send.finish().unwrap();
        });
        let e = h.closed(session);
        assert_eq!(
            (e.a, e.b),
            (SBQ_CLOSE_H3_LOCAL, err::H3_MESSAGE_ERROR as i64),
            "capsule {end}"
        );
    }
    for (payload, expected, connection) in [
        (
            h3::frame(frame::HEADERS, &[0, 0x80]),
            err::QPACK_DECOMPRESSION_FAILED,
            true,
        ),
        (
            h3::frame(
                frame::HEADERS,
                &h3::encode_field_section(&[(b":status", b"200")]),
            ),
            err::H3_MESSAGE_ERROR,
            false,
        ),
        (
            [
                h3::frame(frame::HEADERS, &[0, 0]),
                h3::frame(frame::DATA, &[]),
            ]
            .concat(),
            err::H3_FRAME_UNEXPECTED,
            true,
        ),
        (
            [
                h3::frame(frame::HEADERS, &[0, 0]),
                h3::frame(frame::HEADERS, &[0, 0]),
            ]
            .concat(),
            err::H3_FRAME_UNEXPECTED,
            true,
        ),
        (vec![0, 4, 0x68], err::H3_FRAME_ERROR, true),
        (
            {
                let mut c = Vec::new();
                wt::put_capsule(&mut c, wt::capsule::WT_DRAIN_SESSION, b"x");
                capsule_frame(&c)
            },
            err::H3_MESSAGE_ERROR,
            false,
        ),
        (
            {
                let mut c = Vec::new();
                wt::put_capsule(&mut c, wt::capsule::WT_CLOSE_SESSION, &[0, 0, 0, 0, 0xff]);
                capsule_frame(&c)
            },
            err::H3_MESSAGE_ERROR,
            false,
        ),
    ] {
        let raw = Raw::wt(port);
        let (mut send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
        assert_eq!(Raw::status(&mut recv), Ok(200));
        block(async {
            send.write_all(&payload).await.unwrap();
            send.finish().unwrap();
        });
        let e = h.closed(session);
        assert_eq!((e.a, e.b), (SBQ_CLOSE_H3_LOCAL, expected as i64));
        if connection {
            assert_eq!(closed_with(raw.closed()), expected);
        }
    }
}

#[test]
fn data_after_a_close_capsule_resets_connect() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    for tail in [
        wt::close_capsule(9, b"second"),
        wt::drain_capsule(),
        vec![0x17, 0],
    ] {
        let raw = Raw::wt(port);
        let (mut send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
        assert_eq!(Raw::status(&mut recv), Ok(200));
        let mut c = wt::close_capsule(7, b"first");
        c.extend(tail);
        block(async {
            send.write_all(&capsule_frame(&c)).await.unwrap();
            send.finish().unwrap();
        });
        assert_eq!(h.closed(session).b, 7); // First close metadata wins.
        assert_eq!(reset_code(&mut recv), Some(err::H3_MESSAGE_ERROR));
    }
}

#[test]
fn held_stream_timeout_and_missing_settings_are_bounded() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(250);
    let raw = Raw::wt(port);
    let (_send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
    let (session, _) = h.wt_request(l);
    assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
    assert_eq!(Raw::status(&mut recv), Ok(200));
    let (_send, mut held) = raw.wt_stream(400, b"held");
    assert_eq!(
        reset_code(&mut held),
        Some(wt::err::WT_BUFFERED_STREAM_REJECTED)
    );
    assert!(raw.conn.close_reason().is_none());
    let silent = Raw::start(port, &[], 1 << 20);
    let (_send, _recv, _) = silent.request(&headers(&request_fields(b"/sb")));
    let start = Instant::now();
    assert_eq!(closed_with(silent.closed()), err::H3_NO_ERROR);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn a_typeless_peer_stream_outlives_the_deadline() {
    // quiche (Chrome) sends the type of a QPACK stream with its first instruction, and opening a
    // later stream opens the earlier ones, typeless: stopping one would end the connection.
    let mut h = Harness::new();
    let (l, port) = h.wt_server(250);
    let raw = Raw::wt(port);
    let (_send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
    let (session, _) = h.wt_request(l);
    assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
    assert_eq!(Raw::status(&mut recv), Ok(200));
    let (mut encoder, _decoder) = block(async {
        let encoder = raw.conn.open_uni().await.unwrap();
        let mut decoder = raw.conn.open_uni().await.unwrap();
        decoder
            .write_all(&[h3::stream_type::QPACK_DECODER as u8])
            .await
            .unwrap();
        (encoder, decoder)
    });
    std::thread::sleep(Duration::from_millis(750));
    let stopped = ctx::rt().block_on(async {
        tokio::time::timeout(Duration::from_millis(200), encoder.stopped()).await
    });
    assert!(stopped.is_err(), "the typeless stream was stopped");
    assert!(raw.conn.close_reason().is_none());
    block(async {
        encoder
            .write_all(&[h3::stream_type::QPACK_ENCODER as u8])
            .await
            .unwrap()
    });
    std::thread::sleep(Duration::from_millis(100));
    assert!(raw.conn.close_reason().is_none());
}

#[test]
fn a_server_leaves_the_connection_close_to_the_client_for_the_close_wait() {
    // Chrome reports a session closed only after it sent its FIN in answer to the close, and a
    // connection close that arrives first fails the session ("Connection lost." to the page): a
    // server closes the QUIC connection itself only after the close wait (three round trips, at
    // least 200 ms), however soon both sides closed the CONNECT stream.
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    let raw = Raw::wt(port);
    let (mut cs, mut cr, _) = raw.request(&headers(&request_fields(b"/sb")));
    let (s, _) = h.wt_request(l);
    assert_eq!(unsafe { sbq_wt_accept(s, std::ptr::null(), 0) }, 0);
    assert_eq!(Raw::status(&mut cr), Ok(200));
    let started = Instant::now();
    assert_eq!(close(s, 9, "bye"), 0);
    // The capsule and FIN arrive, and the client answers with its FIN at once.
    assert_eq!(reset_code(&mut cr), None);
    block(async { cs.finish().unwrap() });
    let e = h.closed(s);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_LOCAL, 9));
    std::thread::sleep(Duration::from_millis(100));
    let early = raw.conn.close_reason();
    if started.elapsed() < Duration::from_millis(200) {
        assert!(early.is_none(), "closed before the close wait: {early:?}");
    }
    // A client that does not close it: the server does, after the close wait.
    assert_eq!(closed_with(raw.closed()), err::H3_NO_ERROR);
    assert!(started.elapsed() >= Duration::from_millis(200));
}

#[test]
fn closing_one_pooled_session_releases_its_streams_and_tasks_without_peer_fin() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    for window in [64, 1 << 20] {
        let mut settings = vec![0];
        h3::put_frame(
            &mut settings,
            frame::SETTINGS,
            &h3::encode_settings(WT_SETTINGS),
        );
        let raw = Raw::start(port, &settings, window);
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let (send, mut recv, sid) = raw.request(&headers(&request_fields(b"/sb")));
            let (session, _) = h.wt_request(l);
            assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
            assert_eq!(Raw::status(&mut recv), Ok(200));
            sessions.push((send, recv, sid, session));
        }
        let (_send, mut recv) = raw.wt_stream(sessions[0].2, b"data");
        let stream = h.stream_of(sessions[0].3);
        let object = ctx::get(&ctx::STREAMS, stream).unwrap();
        let weak = std::sync::Arc::downgrade(&object);
        drop(object);
        assert_eq!(close(sessions[0].3, 7, &"x".repeat(1024)), 0);
        assert_eq!(
            unsafe { sbq_stream_write(stream, b"x".as_ptr(), 1) },
            SBQ_ERR_CONNECTION
        );
        assert_eq!(sbq_conn_release(sessions[0].3), 0);
        assert_eq!(reset_code(&mut recv), Some(wt::err::WT_SESSION_GONE));
        until("deferred streams released", || weak.upgrade().is_none());
        // No FIN on the peer's first CONNECT. A surviving session keeps the connection up.
        std::thread::sleep(Duration::from_millis(350));
        assert!(raw.conn.close_reason().is_none());
        let (_send, _recv) = raw.wt_stream(sessions[1].2, b"still live");
        h.stream_of(sessions[1].3);
    }
}

#[test]
fn draft02_and_draft07_server_requirements_and_goaway() {
    let mut h = Harness::new();
    for mode in 0..8 {
        let (cert, key) = self_signed("localhost");
        let sc = config::server_config(
            vec![b"h3".to_vec()],
            &cert,
            &key,
            &config::Limits {
                max_bidi: 4,
                stream_window: 1 << 20,
                conn_window: 1 << 20,
                idle_ms: 30_000,
                keep_alive_ms: 0,
                handshake_ms: 0,
            },
        )
        .unwrap();
        let endpoint = {
            let _g = ctx::rt().enter();
            quinn::Endpoint::server(sc, "127.0.0.1:0".parse().unwrap()).unwrap()
        };
        let port = endpoint.local_addr().unwrap().port();
        let server = ctx::rt().spawn(async move {
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let mut control = conn.open_uni().await.unwrap();
            let mut settings = vec![(setting::H3_DATAGRAM, 1)];
            if mode < 2 {
                settings.push((setting::ENABLE_WEBTRANSPORT_DRAFT02, 1));
            } else {
                settings.push((setting::WEBTRANSPORT_MAX_SESSIONS_DRAFT07, 1));
            }
            if mode >= 3 {
                settings.push((setting::ENABLE_CONNECT_PROTOCOL, 1));
            }
            let mut start = vec![0];
            h3::put_frame(&mut start, frame::SETTINGS, &h3::encode_settings(&settings));
            if mode == 4 {
                h3::put_frame(&mut start, frame::GOAWAY, &[0]);
            }
            control.write_all(&start).await.unwrap();
            let mut request = None;
            if ![2, 4].contains(&mode) {
                let (mut send, recv) = conn.accept_bi().await.unwrap();
                if mode >= 6 {
                    let b = if mode == 6 {
                        vec![1, 3, 0]
                    } else {
                        vec![0x40, 0x21, 4, 0]
                    };
                    send.write_all(&b).await.unwrap();
                    send.finish().unwrap();
                } else if mode == 5 {
                    control
                        .write_all(&h3::frame(frame::GOAWAY, &[0]))
                        .await
                        .unwrap();
                } else {
                    let mut fields: Vec<(&[u8], &[u8])> = vec![(b":status", b"200")];
                    if mode == 0 {
                        fields.push((b"sec-webtransport-http3-draft", b"draft02"));
                    }
                    send.write_all(&h3::frame(
                        frame::HEADERS,
                        &h3::encode_field_section(&fields),
                    ))
                    .await
                    .unwrap();
                }
                request = Some((send, recv));
            }
            let ended = conn.closed().await;
            drop(request);
            drop(control);
            ended
        });
        let client = h.wt_dial(port, "/sb", "", &[]);
        if [0, 3].contains(&mode) {
            h.wait("connected to supported draft", |e| {
                e.handle == client && e.kind == SBQ_EV_CONNECTED
            });
            assert_eq!(close(client, 0, ""), 0);
        } else {
            let e = h.closed(client);
            let expected = if mode >= 6 {
                (SBQ_CLOSE_H3_LOCAL, err::H3_FRAME_ERROR as i64)
            } else if mode >= 4 {
                (SBQ_CLOSE_H3_REMOTE, err::H3_REQUEST_REJECTED as i64)
            } else {
                (SBQ_CLOSE_H3_LOCAL, wt::err::WT_REQUIREMENTS_NOT_MET as i64)
            };
            assert_eq!((e.a, e.b), expected, "mode {mode}");
        }
        block(server).unwrap();
        sbq_conn_release(client);
    }
}

#[test]
fn pending_handles_survive_listener_close_and_release() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    let client = h.wt_dial(port, "/sb", "", &[]);
    let (session, _) = h.wt_request(l);
    assert_eq!(sbq_listener_close(l), 0);
    assert_eq!(
        unsafe { sbq_wt_accept(session, std::ptr::null(), 0) },
        SBQ_ERR_STATE as i32
    );
    assert_eq!(h.closed(client).b, 503);
    assert!(field(session, SBQ_WT_PATH).is_some());
    assert_eq!(sbq_conn_release(session), 0);
    assert_eq!(
        unsafe { sbq_wt_request(session, SBQ_WT_PATH, std::ptr::null_mut(), 0) },
        SBQ_ERR_HANDLE
    );

    let (l, port) = h.wt_server(5_000);
    let client = h.wt_dial(port, "/sb", "", &[]);
    let (session, _) = h.wt_request(l);
    assert_eq!(sbq_conn_release(session), 0);
    assert_eq!(h.closed(client).b, 503);
}

#[test]
fn unreleased_expired_requests_remain_within_the_handle_bound() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server_with(150, 64);
    let raw = Raw::wt(port);
    let (_send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
    let (live, _) = h.wt_request(l);
    assert_eq!(unsafe { sbq_wt_accept(live, std::ptr::null(), 0) }, 0);
    assert_eq!(Raw::status(&mut recv), Ok(200));
    let mut requests = Vec::new();
    for _ in 1..h3conn::MAX_SESSIONS {
        let (send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        assert_eq!(h.closed(session).b, 503);
        assert_eq!(Raw::status(&mut recv), Ok(503));
        requests.push((send, recv, session));
    }
    let (_send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
    assert_eq!(Raw::status(&mut recv), Err(err::H3_REQUEST_REJECTED));
    for (_, _, session) in requests {
        sbq_conn_release(session);
    }
    let (_send, _recv, _) = raw.request(&headers(&request_fields(b"/sb")));
    h.wt_request(l); // Releasing the handles restores the resource grant.
}

#[test]
fn old_closed_sessions_are_not_mistaken_for_future_sessions() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server_with(5_000, 128);
    let raw = Raw::wt(port);
    let (_keep_send, mut keep_recv, keep_sid) = raw.request(&headers(&request_fields(b"/sb")));
    let (keep, _) = h.wt_request(l);
    assert_eq!(unsafe { sbq_wt_accept(keep, std::ptr::null(), 0) }, 0);
    assert_eq!(Raw::status(&mut keep_recv), Ok(200));
    let mut oldest = 0;
    for i in 0..70 {
        let (_send, mut recv, sid) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        if i == 0 {
            oldest = sid;
        }
        assert_eq!(sbq_wt_reject(session, 404), 0);
        assert_eq!(Raw::status(&mut recv), Ok(404));
        sbq_conn_release(session);
    }
    let (_send, mut recv) = raw.wt_stream(oldest, b"late");
    assert_eq!(reset_code(&mut recv), Some(wt::err::WT_SESSION_GONE));
    // A late stream of the live session, older than every refused one, is still its own.
    let (_send, _recv) = raw.wt_stream(keep_sid, b"late but live");
    h.stream_of(keep);
    // A future CONNECT ID is still bufferable, even beyond every accepted peer stream.
    let (_send, _recv) = raw.wt_stream(4_000, b"future");
    assert!(raw.conn.close_reason().is_none());
}

/// A UDP relay to the listener on `port`, on the loopback; what the client sends is dropped
/// while `drop_up` is set. Returns the relay's port and its task.
fn relay(
    port: u16,
    drop_up: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let sock = block(tokio::net::UdpSocket::bind("127.0.0.1:0")).unwrap();
    let local = sock.local_addr().unwrap().port();
    let server: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    let task = ctx::rt().spawn(async move {
        let mut client = None;
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            if from == server {
                if let Some(c) = client {
                    let _ = sock.send_to(&buf[..n], c).await;
                }
            } else {
                client = Some(from);
                if !drop_up.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = sock.send_to(&buf[..n], server).await;
                }
            }
        }
    });
    (local, task)
}

#[test]
fn a_close_whose_fin_is_never_acknowledged_reports_closed_and_resets_nothing() {
    let mut h = Harness::new();
    let (l, port) = h.wt_server(5_000);
    let drop_up = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (relay_port, relay_task) = relay(port, drop_up.clone());
    let raw = Raw::wt(relay_port);
    // Two sessions: the second keeps the QUIC connection up once the first has closed.
    let mut sessions = Vec::new();
    for _ in 0..2 {
        let (send, mut recv, _) = raw.request(&headers(&request_fields(b"/sb")));
        let (session, _) = h.wt_request(l);
        assert_eq!(unsafe { sbq_wt_accept(session, std::ptr::null(), 0) }, 0);
        assert_eq!(Raw::status(&mut recv), Ok(200));
        sessions.push((send, recv, session));
    }
    // From here no acknowledgement of the client reaches the server.
    drop_up.store(true, std::sync::atomic::Ordering::Relaxed);
    let start = Instant::now();
    assert_eq!(close(sessions[0].2, 9, "bye"), 0);
    // CLOSED waits for the acknowledgement, and without one comes with the close wait.
    let e = h.closed(sessions[0].2);
    let waited = start.elapsed();
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_LOCAL, 9));
    assert!(
        waited >= Duration::from_millis(150) && waited < Duration::from_secs(3),
        "{waited:?}"
    );
    std::thread::sleep(Duration::from_millis(200));
    // The capsule and FIN reached the client; no reset after them took them back (quinn
    // discards a stream's unread data when a reset arrives).
    let recv = &mut sessions[0].1;
    let got = block(recv.read_to_end(4096)).expect("the CONNECT stream ends with FIN");
    assert_eq!(got, capsule_frame(&wt::close_capsule(9, b"bye")));
    relay_task.abort();
}
