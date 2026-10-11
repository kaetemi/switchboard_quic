/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

//! Self test of the ABI, through the extern "C" functions as an embedder calls them: a
//! doorbell, `sbq_poll`, handles and result codes. Each test has its own context.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::*;

static RANG: Mutex<u64> = Mutex::new(0);
static RANG_CV: Condvar = Condvar::new();

extern "C" fn doorbell(_ctx: u64) {
    *RANG.lock().unwrap() += 1;
    RANG_CV.notify_all();
}

const ALPN: &[u8] = b"\x0bswitchboard";

struct Harness {
    ctx: u64,
    backlog: Vec<SbqEvent>,
}

impl Harness {
    fn new() -> Self {
        let ctx = sbq_init(doorbell, 2);
        assert!(ctx > 0);
        Harness {
            ctx,
            backlog: Vec::new(),
        }
    }

    fn pump(&mut self) {
        let mut buf = [SbqEvent::default(); 16];
        loop {
            let n = unsafe { sbq_poll(self.ctx, buf.as_mut_ptr(), buf.len()) };
            self.backlog.extend_from_slice(&buf[..n]);
            if n < buf.len() {
                break;
            }
        }
    }

    fn sleep(&self) {
        let g = RANG.lock().unwrap();
        let _ = RANG_CV.wait_timeout(g, Duration::from_millis(10)).unwrap();
    }

    /// Waits (up to 10 s) for an event matching `pred` and removes it from the backlog.
    fn wait(&mut self, what: &str, pred: impl Fn(&SbqEvent) -> bool) -> SbqEvent {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            self.pump();
            if let Some(i) = self.backlog.iter().position(&pred) {
                return self.backlog.remove(i);
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; backlog {:?}",
                self.backlog
            );
            self.sleep();
        }
    }

    fn server(&mut self, max_bidi: u64, window: u64, idle_ms: u64) -> (u64, u16, [u8; 32]) {
        let (cert, key) = self_signed("localhost");
        let mut hash = [0u8; 32];
        unsafe { sbq_sha256(cert.as_ptr(), cert.len(), hash.as_mut_ptr()) };
        let cfg = unsafe {
            sbq_server_config(
                ALPN.as_ptr(),
                ALPN.len(),
                cert.as_ptr(),
                cert.len(),
                key.as_ptr(),
                key.len(),
                max_bidi,
                window,
                16 << 20,
                idle_ms,
                0,
            )
        };
        assert!(cfg > 0, "server config: {}", ctx::last_error());
        let host = b"127.0.0.1";
        let l = unsafe { sbq_listen(self.ctx, cfg as u64, host.as_ptr(), host.len(), 0) };
        assert!(l > 0, "listen: {}", ctx::last_error());
        assert_eq!(sbq_config_free(cfg as u64), 0);
        let port = sbq_listener_port(l as u64);
        assert!(port > 0);
        (l as u64, port as u16, hash)
    }

    /// Starts a connection; returns its handle (CONNECTED or CLOSED follows).
    fn dial(&mut self, port: u16, verify: i32, pins: &[[u8; 32]], idle_ms: u64) -> u64 {
        let flat: Vec<u8> = pins.iter().flatten().copied().collect();
        let cfg = unsafe {
            sbq_client_config(
                ALPN.as_ptr(),
                ALPN.len(),
                verify,
                flat.as_ptr(),
                pins.len(),
                16,
                1 << 20,
                16 << 20,
                idle_ms,
                0,
            )
        };
        assert!(cfg > 0, "client config: {}", ctx::last_error());
        let host = b"127.0.0.1";
        let name = b"localhost";
        let c = unsafe {
            sbq_connect(
                self.ctx,
                cfg as u64,
                host.as_ptr(),
                host.len(),
                port,
                name.as_ptr(),
                name.len(),
            )
        };
        assert!(c > 0);
        sbq_config_free(cfg as u64);
        c as u64
    }

    /// A connected pair: (client connection, server connection).
    fn pair(&mut self, listener: u64, port: u16) -> (u64, u64) {
        let c = self.dial(port, SBQ_VERIFY_NONE, &[], 30_000);
        self.wait("connected", |e| e.kind == SBQ_EV_CONNECTED && e.handle == c);
        let s = self
            .wait("incoming", |e| {
                e.kind == SBQ_EV_INCOMING && e.a == listener as i64
            })
            .handle;
        (c, s)
    }

    fn write_all(&mut self, stream: u64, data: &[u8]) {
        let mut off = 0;
        while off < data.len() {
            let n = unsafe { sbq_stream_write(stream, data[off..].as_ptr(), data.len() - off) };
            assert!(n >= 0, "write: {n}");
            if n == 0 {
                self.wait("writable", |e| {
                    e.kind == SBQ_EV_WRITABLE && e.handle == stream
                });
            }
            off += n as usize;
        }
    }

    /// Reads until FIN; returns the data, or the reset code as Err.
    fn read_all(&mut self, stream: u64) -> Result<Vec<u8>, u64> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 65536];
        loop {
            let n = unsafe { sbq_stream_read(stream, buf.as_mut_ptr(), buf.len()) };
            if n > 0 {
                out.extend_from_slice(&buf[..n as usize]);
            } else if n == SBQ_WOULD_BLOCK {
                self.wait("readable", |e| {
                    e.kind == SBQ_EV_READABLE && e.handle == stream
                });
            } else if n == SBQ_FIN {
                return Ok(out);
            } else {
                assert!(n <= -SBQ_CODE_BASE, "read: {n}");
                return Err((-n - SBQ_CODE_BASE) as u64);
            }
        }
    }

    fn close_reason(&self, conn: u64) -> String {
        let mut buf = [0u8; 256];
        let n = unsafe { sbq_conn_close_reason(conn, buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 0);
        String::from_utf8_lossy(&buf[..n as usize]).into_owned()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        sbq_shutdown(self.ctx);
    }
}

fn self_signed(subject: &str) -> (Vec<u8>, Vec<u8>) {
    let mut cert = vec![0u8; 4096];
    let mut key = vec![0u8; 4096];
    let (mut cl, mut kl) = (0usize, 0usize);
    let r = unsafe {
        sbq_generate_self_signed(
            subject.as_ptr(),
            subject.len(),
            14,
            cert.as_mut_ptr(),
            cert.len(),
            &mut cl,
            key.as_mut_ptr(),
            key.len(),
            &mut kl,
        )
    };
    assert_eq!(r, 0);
    cert.truncate(cl);
    key.truncate(kl);
    (cert, key)
}

fn exporter(conn: u64) -> [u8; 32] {
    let label = b"EXPORTER-Channel-Binding";
    let mut out = [0u8; 32];
    let r = unsafe {
        sbq_conn_exporter(
            conn,
            label.as_ptr(),
            label.len(),
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
            32,
        )
    };
    assert_eq!(r, 0);
    out
}

fn write_one(h: u64) -> i64 {
    let b = [0u8; 1];
    unsafe { sbq_stream_write(h, b.as_ptr(), 1) }
}

#[test]
fn config_errors() {
    let _h = Harness::new();
    let bad = b"\x05abc";
    let none = std::ptr::null();
    let r = unsafe {
        sbq_client_config(
            bad.as_ptr(),
            bad.len(),
            SBQ_VERIFY_NONE,
            none,
            0,
            1,
            1,
            1,
            0,
            0,
        )
    };
    assert_eq!(r, SBQ_ERR_ARG);
    let r = unsafe {
        sbq_client_config(
            ALPN.as_ptr(),
            ALPN.len(),
            SBQ_VERIFY_PINNED,
            none,
            0,
            1,
            1,
            1,
            0,
            0,
        )
    };
    assert_eq!(r, SBQ_ERR_ARG);
    let junk = [1u8, 2, 3];
    let r = unsafe {
        sbq_server_config(
            ALPN.as_ptr(),
            ALPN.len(),
            junk.as_ptr(),
            3,
            junk.as_ptr(),
            3,
            1,
            1,
            1,
            0,
            0,
        )
    };
    assert_eq!(r, SBQ_ERR_TLS);
    let mut msg = [0u8; 256];
    let n = unsafe { sbq_last_error(msg.as_mut_ptr(), msg.len()) };
    assert!(n > 0);
    assert_eq!(write_one(12345), SBQ_ERR_HANDLE);
    assert_eq!(sbq_config_free(12345), SBQ_ERR_HANDLE as i32);
    assert_eq!(sbq_abi_version(), SBQ_ABI_VERSION);
}

#[test]
fn self_signed_certificate() {
    let (cert, key) = self_signed("127.0.0.1");
    assert_eq!(cert[0], 0x30);
    assert!(!key.is_empty());
    let mut small = [0u8; 8];
    let mut key_buf = [0u8; 8];
    let (mut cl, mut kl) = (0usize, 0usize);
    let subject = b"x";
    let r = unsafe {
        sbq_generate_self_signed(
            subject.as_ptr(),
            1,
            14,
            small.as_mut_ptr(),
            8,
            &mut cl,
            key_buf.as_mut_ptr(),
            8,
            &mut kl,
        )
    };
    assert_eq!(r, SBQ_ERR_STATE as i32);
    assert!(cl > 8 && kl > 8);
    // Chains split on DER boundaries.
    let mut two = cert.clone();
    two.extend_from_slice(&cert);
    assert_eq!(config::split_der_chain(&two).unwrap().len(), 2);
    assert!(config::split_der_chain(&cert[..cert.len() - 1]).is_err());
}

#[test]
fn handshake_exporter_and_identity() {
    let mut h = Harness::new();
    let (l, port, hash) = h.server(16, 1 << 20, 30_000);
    let (c, s) = h.pair(l, port);

    let mut buf = [0u8; 64];
    let n = unsafe { sbq_conn_protocol(c, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(&buf[..n as usize], b"switchboard");
    let n = unsafe { sbq_conn_protocol(s, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(&buf[..n as usize], b"switchboard");
    let n = unsafe { sbq_conn_remote(c, buf.as_mut_ptr(), buf.len()) };
    assert_eq!(
        String::from_utf8_lossy(&buf[..n as usize]),
        format!("127.0.0.1:{port}")
    );

    let mut peer = [0u8; 32];
    assert_eq!(
        unsafe { sbq_conn_peer_cert_sha256(c, peer.as_mut_ptr()) },
        0
    );
    assert_eq!(peer, hash);
    assert_eq!(
        unsafe { sbq_conn_peer_cert_sha256(s, peer.as_mut_ptr()) },
        SBQ_ERR_STATE as i32
    );

    assert_eq!(exporter(c), exporter(s));
    let (c2, s2) = h.pair(l, port);
    assert_eq!(exporter(c2), exporter(s2));
    assert_ne!(exporter(c), exporter(c2));

    let mut stats = SbqStats::default();
    assert_eq!(unsafe { sbq_conn_stats(c, &mut stats) }, 0);
    assert!(stats.udp_tx_bytes > 0 && stats.sent_packets > 0);
    assert_eq!(sbq_conn_set_max_bidi(s, 4), 0);
    assert_eq!(sbq_listener_close(l), 0);
    assert_eq!(sbq_listener_close(l), SBQ_ERR_HANDLE as i32);
    // Accepted connections outlive their listener.
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"after");
    assert_eq!(sbq_stream_finish(cs), 0);
    let ss = h
        .wait("stream", |e| e.kind == SBQ_EV_STREAM && e.a == s as i64)
        .handle;
    assert_eq!(h.read_all(ss), Ok(b"after".to_vec()));
}

#[test]
fn certificate_verification() {
    let mut h = Harness::new();
    let (_l, port, hash) = h.server(16, 1 << 20, 30_000);

    let ok = h.dial(port, SBQ_VERIFY_PINNED, &[[7u8; 32], hash], 30_000);
    h.wait("pinned connect", |e| {
        e.kind == SBQ_EV_CONNECTED && e.handle == ok
    });

    let wrong = h.dial(port, SBQ_VERIFY_PINNED, &[[7u8; 32]], 30_000);
    let e = h.wait("pin rejection", |e| {
        e.kind == SBQ_EV_CLOSED && e.handle == wrong
    });
    assert_eq!(e.a, SBQ_CLOSE_CERT_REJECTED);

    let platform = h.dial(port, SBQ_VERIFY_PLATFORM, &[], 30_000);
    let e = h.wait("platform rejection", |e| {
        e.kind == SBQ_EV_CLOSED && e.handle == platform
    });
    assert_eq!(e.a, SBQ_CLOSE_CERT_REJECTED);
    assert_eq!(sbq_conn_release(wrong), 0);
    assert_eq!(sbq_conn_release(wrong), SBQ_ERR_HANDLE as i32);
}

#[test]
fn streams_fin_reset_stop() {
    let mut h = Harness::new();
    let (l, port, _) = h.server(16, 1 << 20, 30_000);
    let (c, s) = h.pair(l, port);

    // Data both ways with FIN; the finish is acknowledged.
    let cs = sbq_stream_open(c) as u64;
    assert!(cs > 0);
    assert_eq!(sbq_stream_set_priority(cs, 2), 0);
    h.write_all(cs, b"hello");
    assert_eq!(sbq_stream_finish(cs), 0);
    assert_eq!(sbq_stream_finish(cs), SBQ_ERR_CLOSED);
    let ss = h
        .wait("stream", |e| e.kind == SBQ_EV_STREAM && e.a == s as i64)
        .handle;
    assert_eq!(h.read_all(ss), Ok(b"hello".to_vec()));
    assert_eq!(h.read_all(ss), Ok(Vec::new()));
    h.write_all(ss, b"world");
    assert_eq!(sbq_stream_finish(ss), 0);
    assert_eq!(h.read_all(cs), Ok(b"world".to_vec()));
    h.wait("acked", |e| {
        e.kind == SBQ_EV_FINISHED_ACKED && e.handle == cs
    });
    h.wait("acked", |e| {
        e.kind == SBQ_EV_FINISHED_ACKED && e.handle == ss
    });
    assert_eq!(sbq_stream_release(cs), 0);
    assert_eq!(sbq_stream_release(ss), 0);
    assert_eq!(sbq_stream_release(ss), SBQ_ERR_HANDLE as i32);

    // A reset with a code reaches the reader.
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"x");
    let ss = h
        .wait("stream", |e| e.kind == SBQ_EV_STREAM && e.a == s as i64)
        .handle;
    assert_eq!(sbq_stream_reset(cs, 9), 0);
    assert_eq!(sbq_stream_reset(cs, 9), 0);
    assert_eq!(write_one(cs), SBQ_ERR_CLOSED);
    assert_eq!(h.read_all(ss), Err(9));
    assert_eq!(h.read_all(ss), Err(9));

    // STOP_SENDING: the writer sees the code, and its direction is reset with it.
    let cs = sbq_stream_open(c) as u64;
    h.write_all(cs, b"y");
    let ss = h
        .wait("stream", |e| e.kind == SBQ_EV_STREAM && e.a == s as i64)
        .handle;
    assert_eq!(sbq_stream_stop(ss, 7), 0);
    let e = h.wait("stopped", |e| e.kind == SBQ_EV_STOPPED && e.handle == cs);
    assert_eq!(e.a, 7);
    assert_eq!(write_one(cs), -(SBQ_CODE_BASE + 7));
    assert_eq!(sbq_stream_finish(cs), -(SBQ_CODE_BASE + 7));
    let mut b = [0u8; 4];
    assert_eq!(
        unsafe { sbq_stream_read(ss, b.as_mut_ptr(), 4) },
        SBQ_ERR_CLOSED
    );
    // The other direction still works.
    h.write_all(ss, b"z");
    assert_eq!(sbq_stream_finish(ss), 0);
    assert_eq!(h.read_all(cs), Ok(b"z".to_vec()));
}

#[test]
fn close_codes_and_idle_timeout() {
    let mut h = Harness::new();
    let (l, port, _) = h.server(16, 1 << 20, 30_000);
    let (c, s) = h.pair(l, port);
    let reason = b"bad record";
    assert_eq!(
        unsafe { sbq_conn_close(c, 32, reason.as_ptr(), reason.len()) },
        0
    );
    let e = h.wait("server closed", |e| {
        e.kind == SBQ_EV_CLOSED && e.handle == s
    });
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 32));
    assert_eq!(h.close_reason(s), "bad record");
    let e = h.wait("client closed", |e| {
        e.kind == SBQ_EV_CLOSED && e.handle == c
    });
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_LOCAL, 32));
    assert_eq!(h.close_reason(c), "bad record");
    assert_eq!(sbq_stream_open(c), SBQ_ERR_CONNECTION);

    // Short idle timeout, no keep-alive: both ends time out.
    let (l2, port2, _) = h.server(16, 1 << 20, 300);
    let c = h.dial(port2, SBQ_VERIFY_NONE, &[], 300);
    h.wait("connected", |e| e.kind == SBQ_EV_CONNECTED && e.handle == c);
    let s = h
        .wait("incoming", |e| {
            e.kind == SBQ_EV_INCOMING && e.a == l2 as i64
        })
        .handle;
    let e = h.wait("idle client", |e| e.kind == SBQ_EV_CLOSED && e.handle == c);
    assert_eq!(e.a, SBQ_CLOSE_TIMED_OUT);
    let e = h.wait("idle server", |e| e.kind == SBQ_EV_CLOSED && e.handle == s);
    assert_eq!(e.a, SBQ_CLOSE_TIMED_OUT);

    // Nothing listens: the handshake times out (its timeout is the idle timeout).
    let dead = h.dial(9, SBQ_VERIFY_NONE, &[], 300);
    let e = h.wait("unreachable", |e| {
        e.kind == SBQ_EV_CLOSED && e.handle == dead
    });
    assert!(
        e.a == SBQ_CLOSE_TIMED_OUT || e.a == SBQ_CLOSE_UNREACHABLE,
        "{e:?}"
    );
}

#[test]
fn stream_limit_and_backpressure() {
    let mut h = Harness::new();
    let (l, port, _) = h.server(1, 65536, 30_000);
    let (c, s) = h.pair(l, port);

    let first = sbq_stream_open(c) as u64;
    assert!(first > 0);
    assert_eq!(sbq_stream_open(c), SBQ_WOULD_BLOCK);

    // Backpressure: the peer grants 64 KiB and reads nothing.
    let big = vec![0x5au8; 256 << 10];
    let mut off = 0;
    loop {
        let n = unsafe { sbq_stream_write(first, big[off..].as_ptr(), big.len() - off) };
        assert!(n >= 0);
        if n == 0 {
            break;
        }
        off += n as usize;
    }
    assert_eq!(off, 65536, "accepted {off}");
    let ss = h
        .wait("stream", |e| e.kind == SBQ_EV_STREAM && e.a == s as i64)
        .handle;
    // Reading returns credit; the writer becomes writable and completes.
    let mut buf = vec![0u8; 65536];
    let mut got = 0;
    let mut writable = false;
    while off < big.len() || got < big.len() {
        if off < big.len() && writable {
            let n = unsafe { sbq_stream_write(first, big[off..].as_ptr(), big.len() - off) };
            assert!(n >= 0);
            off += n as usize;
            writable = n > 0;
        }
        let n = unsafe { sbq_stream_read(ss, buf.as_mut_ptr(), buf.len()) };
        assert!(n >= 0);
        got += n as usize;
        h.pump();
        if h.backlog
            .iter()
            .any(|e| e.kind == SBQ_EV_WRITABLE && e.handle == first)
        {
            h.backlog
                .retain(|e| !(e.kind == SBQ_EV_WRITABLE && e.handle == first));
            writable = true;
        }
        if n == 0 && !writable {
            h.sleep();
        }
    }
    assert_eq!(got, big.len());

    // Ending the first stream in both directions frees the slot: OPENED follows.
    assert_eq!(sbq_stream_finish(first), 0);
    assert_eq!(h.read_all(ss), Ok(Vec::new()));
    assert_eq!(sbq_stream_finish(ss), 0);
    let e = h.wait("opened", |e| e.kind == SBQ_EV_OPENED && e.a == c as i64);
    assert!(e.handle > 0);
}

#[test]
fn shutdown_closes_connections() {
    let mut server = Harness::new();
    let mut client = Harness::new();
    let (l, port, _) = server.server(16, 1 << 20, 30_000);
    let c = client.dial(port, SBQ_VERIFY_NONE, &[], 30_000);
    client.wait("connected", |e| e.kind == SBQ_EV_CONNECTED && e.handle == c);
    let s = server
        .wait("incoming", |e| e.kind == SBQ_EV_INCOMING && e.a == l as i64)
        .handle;
    assert_eq!(sbq_shutdown(client.ctx), 0);
    let e = server.wait("closed", |e| e.kind == SBQ_EV_CLOSED && e.handle == s);
    assert_eq!((e.a, e.b), (SBQ_CLOSE_APP_REMOTE, 0));
    assert_eq!(sbq_conn_release(c), SBQ_ERR_HANDLE as i32);
    assert_eq!(sbq_shutdown(client.ctx), SBQ_ERR_HANDLE as i32);
}

#[test]
fn dial_falls_back_to_the_other_family() {
    let mut h = Harness::new();
    let (l, port, _) = h.server(16, 1 << 20, 30_000);
    let params = config::ClientParams {
        alpn: vec![b"switchboard".to_vec()],
        verify: config::Verify::None,
        limits: config::Limits {
            max_bidi: 4,
            stream_window: 1 << 20,
            conn_window: 16 << 20,
            idle_ms: 30_000,
            keep_alive_ms: 0,
        },
    };
    let cc = config::client_config(&params, Default::default()).unwrap();
    // The preferred address (IPv6 loopback) has no listener; the IPv4 one does.
    let addrs: Vec<std::net::SocketAddr> = vec![
        format!("[::1]:{port}").parse().unwrap(),
        format!("127.0.0.1:{port}").parse().unwrap(),
    ];
    let started = Instant::now();
    let conn = ctx::rt().block_on(conn::dial_addrs(cc, &addrs, "localhost"));
    assert!(conn.is_ok(), "dial failed");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(conn.ok().unwrap().remote_address(), addrs[1]);
    h.wait("incoming", |e| e.kind == SBQ_EV_INCOMING && e.a == l as i64);
}
