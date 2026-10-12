/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GPT-6 Astra <noreply@openai.com>
*/

//! Listeners and connections: the tasks that accept, connect, watch for peer streams and for
//! the end of a connection, and post the matching events. A connection object is either a raw
//! QUIC connection or a WebTransport session (`wt`), whose HTTP/3 connection `h3conn` runs.

use std::collections::HashSet;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{Connection, ConnectionError, Endpoint, VarInt};
use tokio::task::{AbortHandle, JoinSet};

use crate::config::{client_config, ClientParams, ServerParams};
use crate::ctx::{lock, next_handle, rt, Ctx, CONNS, LISTENERS, STREAMS};
use crate::h3conn::{self, ClientRequest, H3Conn, WtSession, H3_ALPN};
use crate::stream::{self, NewStream};
use crate::*;

/// How a connection ended, as its CLOSED event and `sbq_conn_close_reason` report it.
#[derive(Clone, Debug)]
pub struct CloseInfo {
    pub kind: i64,
    pub code: u64,
    pub reason: Vec<u8>,
}

pub struct ConnObj {
    pub ctx: Arc<Ctx>,
    pub handle: u64,
    /// Set once the handshake completed.
    pub conn: Mutex<Option<Connection>>,
    /// The close this side asked for, reported when quinn says "locally closed".
    pub local_close: Mutex<Option<(u64, Vec<u8>)>>,
    pub end: Mutex<Option<CloseInfo>>,
    pub tasks: Mutex<Vec<AbortHandle>>,
    /// The client's certificate verifier rejected the server's certificate.
    pub rejected: Arc<AtomicBool>,
    /// The connection's streams in the stream table; None once released, so that a stream an
    /// accept or open task completes afterwards is dropped instead of registered.
    pub streams: Mutex<Option<HashSet<u64>>>,
    /// Some for a WebTransport session: `conn` is then its HTTP/3 connection once the session
    /// exists, and the session's own state is here.
    pub wt: Option<WtSession>,
}

impl ConnObj {
    fn with(
        ctx: Arc<Ctx>,
        conn: Option<Connection>,
        rejected: Arc<AtomicBool>,
        wt: Option<WtSession>,
    ) -> Arc<Self> {
        Arc::new(ConnObj {
            ctx,
            handle: next_handle(),
            conn: Mutex::new(conn),
            local_close: Mutex::new(None),
            end: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            rejected,
            streams: Mutex::new(Some(HashSet::new())),
            wt,
        })
    }

    fn new(ctx: Arc<Ctx>, conn: Option<Connection>, rejected: Arc<AtomicBool>) -> Arc<Self> {
        Self::with(ctx, conn, rejected, None)
    }

    /// A WebTransport session, not yet in the table.
    pub fn new_session(ctx: Arc<Ctx>, wt: WtSession, conn: Option<Connection>) -> Arc<Self> {
        Self::with(ctx, conn, Arc::new(AtomicBool::new(false)), Some(wt))
    }

    /// Where a new stream goes: the QUIC connection, and the stream header of a WebTransport
    /// session. `SBQ_ERR_STATE` before the connection or session is established,
    /// `SBQ_ERR_CONNECTION` once it has ended.
    pub fn stream_target(&self) -> Result<(Connection, Option<Vec<u8>>), i64> {
        let ended = lock(&self.end).is_some();
        if let Some(wt) = self.wt.as_ref() {
            if ended {
                return Err(SBQ_ERR_CONNECTION);
            }
            let header = wt.stream_header().ok_or(SBQ_ERR_STATE)?;
            let h3 = wt.h3().ok_or(SBQ_ERR_STATE)?;
            return Ok((h3.conn.clone(), Some(header)));
        }
        // Ended first: a connection whose handshake never completed has no `Connection` either,
        // and after CLOSED it fails as an ended one does, not as one still in its handshake.
        if ended {
            return Err(SBQ_ERR_CONNECTION);
        }
        match self.connection() {
            Some(c) => Ok((c, None)),
            None => Err(SBQ_ERR_STATE),
        }
    }

    pub fn connection(&self) -> Option<Connection> {
        lock(&self.conn).clone()
    }

    pub fn add_task(&self, h: AbortHandle) {
        let mut t = lock(&self.tasks);
        t.retain(|h| !h.is_finished());
        t.push(h);
    }

    /// Records the end once and posts CLOSED.
    pub fn finish(&self, info: CloseInfo) {
        {
            let mut end = lock(&self.end);
            if end.is_some() {
                return;
            }
            *end = Some(info.clone());
        }
        self.ctx
            .post(SBQ_EV_CLOSED, self.handle, info.kind, info.code as i64);
    }

    fn close_info(&self, e: &ConnectionError) -> CloseInfo {
        let (kind, code, reason) = match e {
            ConnectionError::ApplicationClosed(a) => (
                SBQ_CLOSE_APP_REMOTE,
                a.error_code.into_inner(),
                a.reason.to_vec(),
            ),
            ConnectionError::LocallyClosed => {
                let (code, reason) = lock(&self.local_close).clone().unwrap_or_default();
                (SBQ_CLOSE_APP_LOCAL, code, reason)
            }
            ConnectionError::TimedOut => (SBQ_CLOSE_TIMED_OUT, 0, b"timed out".to_vec()),
            ConnectionError::Reset => (SBQ_CLOSE_RESET, 0, b"stateless reset".to_vec()),
            ConnectionError::TransportError(t) if self.rejected.load(Ordering::Relaxed) => (
                SBQ_CLOSE_CERT_REJECTED,
                u64::from(t.code),
                t.to_string().into_bytes(),
            ),
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

    /// Closes the connection with an application code, or abandons the handshake.
    pub fn close(&self, code: quinn::VarInt, reason: &[u8]) {
        {
            let mut lc = lock(&self.local_close);
            if lc.is_none() {
                *lc = Some((code.into_inner(), reason.to_vec()));
            }
        }
        match self.connection() {
            Some(c) => c.close(code, reason),
            None => {
                for t in lock(&self.tasks).drain(..) {
                    t.abort();
                }
                self.finish(CloseInfo {
                    kind: SBQ_CLOSE_APP_LOCAL,
                    code: code.into_inner(),
                    reason: reason.to_vec(),
                });
            }
        }
    }

    /// Forgets the connection: closes it with code 0 if it is still open, stops its tasks and
    /// drops its streams. A WebTransport session is closed (WT_CLOSE_SESSION 0, quietly); its
    /// QUIC connection is left to its HTTP/3 layer, which may carry other sessions.
    pub fn release(self: &Arc<Self>) {
        if self.wt.is_some() {
            h3conn::release(self);
            lock(&self.conn).take();
        } else {
            // Recorded first, as `close` does: a dial task whose handshake completes
            // concurrently (an abort only takes effect at its next await) then closes the
            // connection itself instead of keeping it alive with no handle (see `connect`).
            {
                let mut lc = lock(&self.local_close);
                if lc.is_none() {
                    *lc = Some((0, Vec::new()));
                }
            }
            if let Some(c) = lock(&self.conn).take() {
                if c.close_reason().is_none() {
                    c.close(0u32.into(), b"");
                }
            }
        }
        for t in lock(&self.tasks).drain(..) {
            t.abort();
        }
        let streams = lock(&self.streams).take().unwrap_or_default();
        // Dropped after the table lock is released: dropping a stream takes quinn's lock.
        let _removed: Vec<_> = {
            let mut table = lock(&STREAMS);
            streams.iter().filter_map(|s| table.remove(s)).collect()
        };
    }
}

/// Starts the tasks of an established connection: peer-opened bidirectional streams, and the
/// end of the connection.
fn watch(obj: &Arc<ConnObj>, conn: Connection) {
    let o = obj.clone();
    let c = conn.clone();
    let accept = rt().spawn(async move {
        while let Ok((s, r)) = c.accept_bi().await {
            if let Err(s) = stream::insert(&o, NewStream::raw(s, r), Some(SBQ_EV_STREAM)) {
                s.abort();
                break;
            }
        }
    });
    let o = obj.clone();
    let closed = rt().spawn(async move {
        let e = conn.closed().await;
        o.finish(o.close_info(&e));
    });
    obj.add_task(accept.abort_handle());
    obj.add_task(closed.abort_handle());
}

pub struct ListenerObj {
    pub ctx: Arc<Ctx>,
    pub endpoint: Endpoint,
    pub task: Mutex<Option<AbortHandle>>,
    /// Set by `close`: the HTTP/3 connections it accepted answer new WebTransport requests 503.
    pub closed: Arc<AtomicBool>,
}

impl ListenerObj {
    /// Stops accepting. Connections already accepted keep the socket until they end.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.endpoint.set_server_config(None);
        if let Some(t) = lock(&self.task).take() {
            t.abort();
        }
    }
}

/// The ALPN protocol a connection negotiated.
pub fn negotiated_alpn(conn: &Connection) -> Option<Vec<u8>> {
    conn.handshake_data()
        .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol)
}

/// The output of `f`, or None when `deadline` passed first (`f` is dropped then).
async fn within<F: Future>(deadline: Option<Duration>, f: F) -> Option<F::Output> {
    match deadline {
        Some(d) => tokio::time::timeout(d, f).await.ok(),
        None => Some(f.await),
    }
}

/// Completes the handshake of an incoming connection within `deadline` and announces it, or,
/// for one that negotiated `h3` on a listener that serves it, starts its HTTP/3 layer, whose
/// WebTransport requests are announced instead. A handshake that fails or runs out of time is
/// dropped, which closes it in quinn (the endpoint forgets it once the close has drained);
/// nothing of it reached a table.
async fn handshake(
    inc: quinn::Incoming,
    ctx: Arc<Ctx>,
    listener: u64,
    deadline: Option<Duration>,
    h3: Option<Arc<AtomicBool>>,
) {
    let Ok(connecting) = inc.accept() else { return };
    if let Some(Ok(conn)) = within(deadline, connecting).await {
        if let Some(closed) = h3 {
            if negotiated_alpn(&conn).as_deref() == Some(H3_ALPN) {
                H3Conn::start(ctx, conn, false, listener, Some(closed), deadline);
                return;
            }
        }
        let obj = ConnObj::new(ctx, Some(conn.clone()), Arc::new(AtomicBool::new(false)));
        lock(&CONNS).insert(obj.handle, obj.clone());
        // `sbq_shutdown` closes the context before it sweeps the table: a handshake that completes
        // during the sweep either is in the table for it, or sees the context closed here.
        if obj.ctx.is_closed() {
            if let Some(o) = lock(&CONNS).remove(&obj.handle) {
                o.release();
            }
            return;
        }
        obj.ctx
            .post(SBQ_EV_INCOMING, obj.handle, listener as i64, 0);
        watch(&obj, conn);
    }
}

/// The UDP socket of a listener. A socket on an IPv6 address is made dual-stack where the
/// platform allows it (IPV6_V6ONLY off), as quinn makes its client sockets: Linux and macOS
/// default to dual-stack, Windows to IPv6 only, where a listener on `::` would not hear IPv4
/// clients. Where the option cannot be changed, the socket keeps the platform's default.
fn bind_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

pub fn listen(ctx: &Arc<Ctx>, sp: &ServerParams, addr: SocketAddr) -> Result<u64, String> {
    let _g = rt().enter();
    let endpoint = bind_udp(addr)
        .and_then(|socket| {
            Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(sp.config.clone()),
                socket,
                Arc::new(quinn::TokioRuntime),
            )
        })
        .map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    let h = next_handle();
    let closed = Arc::new(AtomicBool::new(false));
    let obj = Arc::new(ListenerObj {
        ctx: ctx.clone(),
        endpoint: endpoint.clone(),
        task: Mutex::new(None),
        closed: closed.clone(),
    });
    let ctx = ctx.clone();
    let deadline = sp.handshake;
    let h3 = sp.h3.then_some(closed);
    let task = rt().spawn(async move {
        let mut handshakes = JoinSet::new();
        loop {
            tokio::select! {
                inc = endpoint.accept() => match inc {
                    Some(inc) => {
                        handshakes.spawn(handshake(inc, ctx.clone(), h, deadline, h3.clone()));
                    }
                    None => break,
                },
                Some(_) = handshakes.join_next(), if !handshakes.is_empty() => {}
            }
        }
    });
    *lock(&obj.task) = Some(task.abort_handle());
    lock(&LISTENERS).insert(h, obj);
    Ok(h)
}

/// One client endpoint (UDP socket) per address family, shared by every outgoing connection.
fn client_endpoint(v6: bool) -> std::io::Result<Endpoint> {
    static V4: Mutex<Option<Endpoint>> = Mutex::new(None);
    static V6: Mutex<Option<Endpoint>> = Mutex::new(None);
    let mut slot = lock(if v6 { &V6 } else { &V4 });
    if let Some(e) = slot.as_ref() {
        return Ok(e.clone());
    }
    let _g = rt().enter();
    let bind: SocketAddr = if v6 { "[::]:0" } else { "0.0.0.0:0" }
        .parse()
        .expect("literal");
    let e = Endpoint::client(bind)?;
    *slot = Some(e.clone());
    Ok(e)
}

/// Why one connection attempt failed.
pub(crate) enum Failure {
    Conn(ConnectionError),
    Info(CloseInfo),
}

impl Failure {
    fn info(self, o: &ConnObj) -> CloseInfo {
        match self {
            Failure::Conn(e) => o.close_info(&e),
            Failure::Info(i) => i,
        }
    }

    /// Of two failures, the one that says more: anything beats a timeout.
    fn pick(first: Failure, second: Failure) -> Failure {
        match first {
            Failure::Conn(ConnectionError::TimedOut) => second,
            _ => first,
        }
    }
}

fn unreachable(msg: String) -> Failure {
    Failure::Info(CloseInfo {
        kind: SBQ_CLOSE_UNREACHABLE,
        code: 0,
        reason: msg.into_bytes(),
    })
}

/// One handshake with `addr`, within `deadline` if given. Running out of time is a timeout, as
/// quinn reports a handshake its idle timeout ended, so that `Failure::pick` prefers any other
/// failure; the `Connecting` dropped with the timeout closes the attempt in quinn.
async fn attempt(
    cc: quinn::ClientConfig,
    addr: SocketAddr,
    server_name: &str,
    deadline: Option<Duration>,
) -> Result<Connection, Failure> {
    let endpoint = client_endpoint(addr.is_ipv6())
        .map_err(|e| unreachable(format!("cannot open a socket: {e}")))?;
    let connecting = endpoint.connect_with(cc, addr, server_name).map_err(|e| {
        Failure::Info(CloseInfo {
            kind: SBQ_CLOSE_OTHER,
            code: 0,
            reason: e.to_string().into_bytes(),
        })
    })?;
    within(deadline, connecting)
        .await
        .unwrap_or(Err(ConnectionError::TimedOut))
        .map_err(Failure::Conn)
}

/// How long the first address has to itself before the first address of the other family is
/// tried alongside it (a light form of RFC 8305's Happy Eyeballs: a dual-stack name whose
/// preferred address has no listener does not cost a whole handshake timeout).
const SECOND_FAMILY_DELAY: Duration = Duration::from_millis(250);

/// Resolves `host` and completes a handshake with the first of its addresses that answers, each
/// attempt within `deadline`.
async fn dial(
    cc: quinn::ClientConfig,
    host: &str,
    port: u16,
    server_name: &str,
    deadline: Option<Duration>,
) -> Result<Connection, Failure> {
    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
        Ok(a) => a.collect(),
        Err(e) => return Err(unreachable(format!("cannot resolve {host}: {e}"))),
    };
    if addrs.is_empty() {
        return Err(unreachable(format!("no address for {host}")));
    }
    dial_addrs(cc, &addrs, server_name, deadline).await
}

/// Tries the first address, and after `SECOND_FAMILY_DELAY` also the first address of the other
/// family; the first handshake to complete wins and the other attempt is dropped (closed). Each
/// attempt has `deadline` to itself, so a dual-stack dial ends within about the deadline plus
/// `SECOND_FAMILY_DELAY`.
pub(crate) async fn dial_addrs(
    cc: quinn::ClientConfig,
    addrs: &[SocketAddr],
    server_name: &str,
    deadline: Option<Duration>,
) -> Result<Connection, Failure> {
    let first = addrs[0];
    let Some(&second) = addrs.iter().find(|a| a.is_ipv6() != first.is_ipv6()) else {
        return attempt(cc, first, server_name, deadline).await;
    };
    let a = attempt(cc.clone(), first, server_name, deadline);
    tokio::pin!(a);
    tokio::select! {
        r = &mut a => match r {
            Ok(c) => Ok(c),
            Err(e1) => attempt(cc, second, server_name, deadline)
                .await
                .map_err(|e2| Failure::pick(e1, e2)),
        },
        _ = tokio::time::sleep(SECOND_FAMILY_DELAY) => {
            let b = attempt(cc, second, server_name, deadline);
            tokio::pin!(b);
            tokio::select! {
                r = &mut a => match r {
                    Ok(c) => Ok(c),
                    Err(e1) => b.await.map_err(|e2| Failure::pick(e1, e2)),
                },
                r = &mut b => match r {
                    Ok(c) => Ok(c),
                    Err(e2) => a.await.map_err(|e1| Failure::pick(e1, e2)),
                },
            }
        }
    }
}

pub fn connect(
    ctx: &Arc<Ctx>,
    params: &ClientParams,
    host: String,
    port: u16,
    server_name: String,
) -> Result<u64, String> {
    let rejected = Arc::new(AtomicBool::new(false));
    let cc = client_config(params, rejected.clone())?;
    let deadline = params.limits.handshake();
    let obj = ConnObj::new(ctx.clone(), None, rejected);
    let h = obj.handle;
    lock(&CONNS).insert(h, obj.clone());
    let o = obj.clone();
    let task = rt().spawn(async move {
        match dial(cc, &host, port, &server_name, deadline).await {
            Ok(conn) => {
                {
                    let mut slot = lock(&o.conn);
                    // A close asked for during the handshake (which reported CLOSED already), or
                    // a release: either recorded `local_close` before looking at the slot.
                    if let Some((code, reason)) = lock(&o.local_close).clone() {
                        conn.close(quinn::VarInt::from_u64(code).unwrap_or_default(), &reason);
                        return;
                    }
                    *slot = Some(conn.clone());
                }
                o.ctx.post(SBQ_EV_CONNECTED, h, 0, 0);
                watch(&o, conn);
            }
            Err(f) => o.finish(f.info(&o)),
        }
    });
    obj.add_task(task.abort_handle());
    Ok(h)
}

/// Starts a WebTransport session: dials `host:port`, runs HTTP/3 over the connection and sends
/// the extended CONNECT of `req`. CONNECTED follows the server's 2xx, CLOSED anything else. The
/// configuration's handshake deadline bounds the QUIC handshake (each attempt), and again the
/// HTTP/3 exchange (the server's SETTINGS and its response).
pub fn connect_wt(
    ctx: &Arc<Ctx>,
    params: &ClientParams,
    host: String,
    port: u16,
    server_name: String,
    req: ClientRequest,
) -> Result<u64, String> {
    let rejected = Arc::new(AtomicBool::new(false));
    let cc = client_config(params, rejected.clone())?;
    let deadline = params.limits.handshake();
    let obj = ConnObj::with(ctx.clone(), None, rejected, Some(WtSession::client()));
    let h = obj.handle;
    lock(&CONNS).insert(h, obj.clone());
    let o = obj.clone();
    let task = rt().spawn(async move {
        let conn = match dial(cc, &host, port, &server_name, deadline).await {
            Ok(conn) => conn,
            Err(f) => {
                let info = f.info(&o);
                return h3conn::connect_failed(&o, None, info);
            }
        };
        let wt = o.wt.as_ref().expect("a session");
        let h3 = {
            let mut slot = lock(&wt.h3);
            // A close or a release during the handshake recorded `local_close` before it looked
            // at the slot.
            if lock(&o.local_close).is_some() {
                conn.close(VarInt::from_u32(0x10c), b"");
                return;
            }
            let h3 = H3Conn::start(o.ctx.clone(), conn, true, 0, None, deadline);
            *slot = Some(h3.clone());
            h3
        };
        let r = within(
            Some(deadline.unwrap_or(h3conn::DEFAULT_REQUEST_TIMEOUT)),
            h3conn::client_session(&o, &h3, req),
        )
        .await;
        match r {
            Some(Ok(())) => {}
            Some(Err(info)) => h3conn::connect_failed(&o, Some(&h3), info),
            None => h3conn::connect_failed(
                &o,
                Some(&h3),
                CloseInfo {
                    kind: SBQ_CLOSE_TIMED_OUT,
                    code: 0,
                    reason: b"timed out".to_vec(),
                },
            ),
        }
    });
    obj.add_task(task.abort_handle());
    Ok(h)
}
