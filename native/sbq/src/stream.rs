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

//! Streams: non-blocking reads and writes polled with wakers that post READABLE and WRITABLE, a
//! non-consuming check for the peer's reset (whose waker is the read's), and a task per stream that
//! reports STOP_SENDING or the acknowledged end.
//!
//! A stream of a WebTransport session differs in three ways: the stream header this side owes the
//! peer (signal and session ID) is written ahead of the first byte of data or the FIN; error codes
//! are WebTransport application codes (u32) mapped into the HTTP/3 space on the wire, and a code
//! outside that space is reported as `SBQ_NO_CODE`; and a peer's unidirectional stream has no send
//! direction.

use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use quinn::{ReadError, RecvStream, SendStream, VarInt, WriteError};

use crate::conn::ConnObj;
use crate::ctx::{lock, next_handle, rt, Ctx, EvWaker, CONNS, STREAMS};
use crate::wt;
use crate::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendState {
    Open,
    Finished,
    Reset,
    /// The peer sent STOP_SENDING; the direction was reset with the same code.
    Stopped(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecvState {
    Open,
    Fin,
    Reset(u64),
    /// This side sent STOP_SENDING.
    Stopped,
}

struct Inner {
    /// None for a peer's unidirectional stream.
    send: Option<SendStream>,
    recv: RecvStream,
    send_state: SendState,
    recv_state: RecvState,
    /// The stream header still to be written ahead of the data (a WebTransport stream this side
    /// opened; empty otherwise).
    prefix: Vec<u8>,
    /// The stream's WebTransport session ended: its directions were reset and stopped with
    /// WT_SESSION_GONE, and reads and writes fail as on an ended connection.
    gone: bool,
}

pub struct StreamObj {
    pub conn: u64,
    /// The stream belongs to a WebTransport session: codes are mapped.
    wt: bool,
    inner: Mutex<Inner>,
    read_waker: Waker,
    write_waker: Waker,
}

/// Encodes an application error code as a negative result.
pub fn code_result(code: u64) -> i64 {
    -(SBQ_CODE_BASE + code as i64)
}

/// The outcome of writing the stream header ahead of the data.
enum Prefix {
    Done,
    Blocked,
    Failed(i64),
}

impl StreamObj {
    /// The wire code for an application code given by the embedder: unchanged on raw QUIC, mapped
    /// into the HTTP/3 space on WebTransport (where codes are u32). None when out of range.
    fn wire_code(&self, code: u64) -> Option<VarInt> {
        if self.wt {
            let code = u32::try_from(code).ok()?;
            VarInt::from_u64(wt::app_to_h3(code)).ok()
        } else {
            VarInt::from_u64(code).ok()
        }
    }

    /// A peer's wire code as a result: the application code, or `SBQ_NO_CODE` for a WebTransport
    /// code outside the application range.
    fn code_out(&self, wire: u64) -> i64 {
        if !self.wt {
            return code_result(wire);
        }
        match wt::h3_to_app(wire) {
            Some(c) => code_result(u64::from(c)),
            None => SBQ_NO_CODE,
        }
    }

    /// A peer's wire code for an event: the application code, or -1 for none.
    fn code_event(&self, wire: u64) -> i64 {
        if !self.wt {
            return wire as i64;
        }
        wt::h3_to_app(wire).map_or(-1, i64::from)
    }

    /// STOP_SENDING arrived: reset the direction with the same code (RFC 9000 section 3.5; quinn
    /// leaves it to the application), also when it is finished but not acknowledged yet, which
    /// ends the retransmission of data the peer discards.
    fn peer_stopped(&self, code: VarInt) {
        let mut g = lock(&self.inner);
        if matches!(g.send_state, SendState::Open | SendState::Finished) {
            if let Some(send) = g.send.as_mut() {
                let _ = send.reset(code);
            }
            g.send_state = SendState::Stopped(code.into_inner());
        }
    }

    /// This side closed the stream's session: reads and writes fail at once, as on an ended
    /// connection, while the wire resets wait for `session_gone` (once the close has reached
    /// the peer).
    pub fn session_ended(&self) {
        lock(&self.inner).gone = true;
    }

    /// The session ended: reset the send direction and stop the receive direction with
    /// WT_SESSION_GONE, as the WebTransport draft requires of every stream of the session.
    pub fn session_gone(&self) {
        let code = VarInt::from_u64(wt::err::WT_SESSION_GONE).expect("in range");
        let mut g = lock(&self.inner);
        g.gone = true;
        if matches!(g.send_state, SendState::Open | SendState::Finished) {
            if let Some(send) = g.send.as_mut() {
                let _ = send.reset(code);
                g.send_state = SendState::Reset;
            }
        }
        if g.recv_state == RecvState::Open {
            let _ = g.recv.stop(code);
            g.recv_state = RecvState::Stopped;
        }
    }

    /// The result of a failed write of the send direction (data or header).
    fn write_failed(&self, g: &mut Inner, e: WriteError) -> i64 {
        match e {
            WriteError::Stopped(c) => {
                if let Some(send) = g.send.as_mut() {
                    let _ = send.reset(c);
                }
                g.send_state = SendState::Stopped(c.into_inner());
                self.code_out(c.into_inner())
            }
            WriteError::ConnectionLost(_) => SBQ_ERR_CONNECTION,
            _ => SBQ_ERR_CLOSED,
        }
    }

    /// Writes what is left of the stream header.
    fn flush_prefix(&self, g: &mut Inner) -> Prefix {
        while !g.prefix.is_empty() {
            let Some(send) = g.send.as_mut() else {
                return Prefix::Failed(SBQ_ERR_STATE);
            };
            let mut cx = Context::from_waker(&self.write_waker);
            match Pin::new(send).poll_write(&mut cx, &g.prefix) {
                Poll::Ready(Ok(0)) => return Prefix::Failed(SBQ_ERR_CLOSED),
                Poll::Ready(Ok(n)) => {
                    g.prefix.drain(..n);
                    // A short successful write does not arm quinn's waker. Poll the remaining
                    // prefix (at most 16 bytes in total) until it is done or actually Pending.
                }
                Poll::Pending => return Prefix::Blocked,
                Poll::Ready(Err(e)) => return Prefix::Failed(self.write_failed(g, e)),
            }
        }
        Prefix::Done
    }

    pub fn write(&self, data: &[u8]) -> i64 {
        if data.is_empty() {
            return SBQ_ERR_ARG;
        }
        let mut g = lock(&self.inner);
        if g.send.is_none() {
            return SBQ_ERR_STATE;
        }
        if g.gone {
            return SBQ_ERR_CONNECTION;
        }
        match g.send_state {
            SendState::Open => {}
            SendState::Stopped(c) => return self.code_out(c),
            SendState::Finished | SendState::Reset => return SBQ_ERR_CLOSED,
        }
        match self.flush_prefix(&mut g) {
            Prefix::Done => {}
            Prefix::Blocked => return SBQ_WOULD_BLOCK,
            Prefix::Failed(r) => return r,
        }
        let mut cx = Context::from_waker(&self.write_waker);
        let send = g.send.as_mut().expect("checked");
        match Pin::new(send).poll_write(&mut cx, data) {
            Poll::Ready(Ok(n)) => n as i64,
            Poll::Pending => SBQ_WOULD_BLOCK,
            Poll::Ready(Err(e)) => self.write_failed(&mut g, e),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> i64 {
        if buf.is_empty() {
            return SBQ_ERR_ARG;
        }
        let mut g = lock(&self.inner);
        if g.gone {
            return SBQ_ERR_CONNECTION;
        }
        match g.recv_state {
            RecvState::Open => {}
            RecvState::Fin => return SBQ_FIN,
            RecvState::Reset(c) => return self.code_out(c),
            RecvState::Stopped => return SBQ_ERR_CLOSED,
        }
        let mut cx = Context::from_waker(&self.read_waker);
        match g.recv.poll_read(&mut cx, buf) {
            Poll::Ready(Ok(0)) => {
                g.recv_state = RecvState::Fin;
                SBQ_FIN
            }
            Poll::Ready(Ok(n)) => n as i64,
            Poll::Pending => SBQ_WOULD_BLOCK,
            Poll::Ready(Err(ReadError::Reset(c))) => {
                g.recv_state = RecvState::Reset(c.into_inner());
                self.code_out(c.into_inner())
            }
            Poll::Ready(Err(ReadError::ConnectionLost(_))) => SBQ_ERR_CONNECTION,
            Poll::Ready(Err(_)) => SBQ_ERR_CLOSED,
        }
    }

    /// Whether the peer reset the receive direction, without reading: the code (and the direction
    /// ends with it, as a read would have reported it), `SBQ_WOULD_BLOCK` with the read waker
    /// registered (quinn wakes it for a reset as for data and FIN, so a READABLE follows the next
    /// change, possibly a spurious one), or `SBQ_FIN` when no reset can come any more (FIN read,
    /// or quinn has forgotten the direction after its last byte was read).
    pub fn poll_reset(&self) -> i64 {
        let mut g = lock(&self.inner);
        if g.gone {
            return SBQ_ERR_CONNECTION;
        }
        match g.recv_state {
            RecvState::Open => {}
            RecvState::Fin => return SBQ_FIN,
            RecvState::Reset(c) => return self.code_out(c),
            RecvState::Stopped => return SBQ_ERR_CLOSED,
        }
        let polled = {
            let mut cx = Context::from_waker(&self.read_waker);
            let mut fut = pin!(g.recv.received_reset());
            fut.as_mut().poll(&mut cx)
        };
        match polled {
            Poll::Ready(Ok(Some(c))) => {
                // quinn discards the direction once the reset is observed; reads report it from
                // here on.
                g.recv_state = RecvState::Reset(c.into_inner());
                self.code_out(c.into_inner())
            }
            Poll::Ready(Ok(None)) => SBQ_FIN,
            Poll::Pending => SBQ_WOULD_BLOCK,
            Poll::Ready(Err(quinn::ResetError::ConnectionLost(_))) => SBQ_ERR_CONNECTION,
            Poll::Ready(Err(_)) => SBQ_ERR_CLOSED,
        }
    }

    pub fn finish(&self) -> i64 {
        let mut g = lock(&self.inner);
        if g.send.is_none() {
            return SBQ_ERR_STATE;
        }
        if g.gone {
            return SBQ_ERR_CONNECTION;
        }
        match g.send_state {
            // quinn's finish reports a STOP_SENDING that raced in as Ok and leaves the code to
            // the stopped() task above, so only "already ended" can be seen here.
            SendState::Open => {
                match self.flush_prefix(&mut g) {
                    Prefix::Done => {}
                    Prefix::Blocked => return SBQ_RETRY,
                    Prefix::Failed(r) => return r,
                }
                match g.send.as_mut().expect("checked").finish() {
                    Ok(()) => {
                        g.send_state = SendState::Finished;
                        SBQ_OK
                    }
                    Err(_) => SBQ_ERR_CONNECTION,
                }
            }
            SendState::Stopped(c) => self.code_out(c),
            SendState::Finished | SendState::Reset => SBQ_ERR_CLOSED,
        }
    }

    /// Resets the send direction with the embedder's `code` (mapped on WebTransport).
    pub fn reset(&self, code: u64) -> i64 {
        let Some(code) = self.wire_code(code) else {
            return SBQ_ERR_ARG;
        };
        let mut g = lock(&self.inner);
        match g.send_state {
            SendState::Open | SendState::Finished => {
                let Some(send) = g.send.as_mut() else {
                    return SBQ_ERR_STATE;
                };
                let _ = send.reset(code);
                g.send_state = SendState::Reset;
                SBQ_OK
            }
            // Reset already, by the peer's STOP_SENDING or an earlier call.
            SendState::Stopped(_) | SendState::Reset => SBQ_OK,
        }
    }

    /// Stops the receive direction with the embedder's `code` (mapped on WebTransport).
    pub fn stop(&self, code: u64) -> i64 {
        let Some(code) = self.wire_code(code) else {
            return SBQ_ERR_ARG;
        };
        let mut g = lock(&self.inner);
        if g.recv_state == RecvState::Open {
            let _ = g.recv.stop(code);
            g.recv_state = RecvState::Stopped;
        }
        SBQ_OK
    }

    pub fn set_priority(&self, priority: i32) -> i64 {
        let g = lock(&self.inner);
        let Some(send) = g.send.as_ref() else {
            return SBQ_ERR_STATE;
        };
        match send.set_priority(priority) {
            Ok(()) => SBQ_OK,
            Err(_) => SBQ_ERR_CLOSED,
        }
    }
}

impl Drop for StreamObj {
    fn drop(&mut self) {
        let mut g = lock(&self.inner);
        let code =
            VarInt::from_u64(if self.wt { wt::err::WT_SESSION_GONE } else { 0 }).expect("in range");
        if g.send_state == SendState::Open {
            if let Some(send) = g.send.as_mut() {
                let _ = send.reset(code);
            }
        }
        if g.recv_state == RecvState::Open {
            let _ = g.recv.stop(code);
        }
    }
}

/// A stream to register: its directions, whether it belongs to a WebTransport session, and the
/// stream header still to write.
pub struct NewStream {
    pub send: Option<SendStream>,
    pub recv: RecvStream,
    pub wt: bool,
    pub prefix: Vec<u8>,
}

impl NewStream {
    pub fn abort(mut self) {
        let code =
            VarInt::from_u64(if self.wt { wt::err::WT_SESSION_GONE } else { 0 }).expect("in range");
        if let Some(send) = self.send.as_mut() {
            let _ = send.reset(code);
        }
        let _ = self.recv.stop(code);
    }

    pub fn raw(send: SendStream, recv: RecvStream) -> Self {
        NewStream {
            send: Some(send),
            recv,
            wt: false,
            prefix: Vec::new(),
        }
    }
}

/// Registers a new stream of `conn`, posts `announce` (STREAM, UNI_STREAM or OPENED, with the
/// connection or session) if given, and only then starts its STOP_SENDING / acknowledgement
/// task, so that the embedder learns the handle before any event of the stream. Gives the
/// stream back when the connection was released meanwhile.
pub fn insert(conn: &Arc<ConnObj>, s: NewStream, announce: Option<i32>) -> Result<u64, NewStream> {
    // Same lock order as session close: phase first, then the stream set. Once close takes
    // its snapshot, no optimistic delivery or pending open can escape the deferred resets.
    let phase = conn.wt.as_ref().map(|wt| lock(&wt.st));
    if phase
        .as_ref()
        .is_some_and(|st| st.phase != crate::h3conn::Phase::Live)
    {
        return Err(s);
    }
    let mut ids = lock(&conn.streams);
    let Some(set) = ids.as_mut() else {
        return Err(s);
    };
    let h = next_handle();
    let ctx: Arc<Ctx> = conn.ctx.clone();
    let stopped = s.send.as_ref().map(|send| send.stopped());
    let waker = |kind| {
        Waker::from(Arc::new(EvWaker {
            ctx: ctx.clone(),
            kind,
            handle: h,
        }))
    };
    let wt = s.wt;
    let obj = Arc::new(StreamObj {
        conn: conn.handle,
        wt,
        inner: Mutex::new(Inner {
            send: s.send,
            recv: s.recv,
            send_state: SendState::Open,
            recv_state: RecvState::Open,
            prefix: s.prefix,
            gone: false,
        }),
        read_waker: waker(SBQ_EV_READABLE),
        write_waker: waker(SBQ_EV_WRITABLE),
    });
    let weak = Arc::downgrade(&obj);
    // Lock order: the connection's stream set, then the stream table (`ConnObj::release` and
    // `release` below take them one at a time).
    lock(&STREAMS).insert(h, obj);
    set.insert(h);
    drop(ids);
    drop(phase);
    if let Some(kind) = announce {
        ctx.post(kind, h, conn.handle as i64, 0);
    }
    if let Some(stopped) = stopped {
        rt().spawn(async move {
            match stopped.await {
                Ok(Some(code)) => {
                    let mut reported = code.into_inner() as i64;
                    if let Some(obj) = weak.upgrade() {
                        obj.peer_stopped(code);
                        reported = obj.code_event(code.into_inner());
                    }
                    ctx.post(SBQ_EV_STOPPED, h, reported, 0);
                }
                Ok(None) => ctx.post(SBQ_EV_FINISHED_ACKED, h, 0, 0),
                Err(_) => {}
            }
        });
    }
    Ok(h)
}

/// Opens a bidirectional stream now if the peer's stream limit allows it; otherwise waits for
/// credit in a task that posts OPENED, and returns SBQ_WOULD_BLOCK.
pub fn open(conn_h: u64) -> i64 {
    let Some(obj) = crate::ctx::get(&CONNS, conn_h) else {
        return SBQ_ERR_HANDLE;
    };
    // The QUIC connection, and the stream header of a WebTransport session.
    let (conn, header) = match obj.stream_target() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let wt = header.is_some();
    let new = move |s, r| NewStream {
        send: Some(s),
        recv: r,
        wt,
        prefix: header.clone().unwrap_or_default(),
    };
    {
        let mut fut = pin!(conn.open_bi());
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok((s, r))) => {
                return insert(&obj, new(s, r), None).map_or_else(
                    |s| {
                        s.abort();
                        SBQ_ERR_CONNECTION
                    },
                    |h| h as i64,
                )
            }
            Poll::Ready(Err(_)) => return SBQ_ERR_CONNECTION,
            Poll::Pending => {}
        }
    }
    let o = obj.clone();
    let task = rt().spawn(async move {
        if let Ok((s, r)) = conn.open_bi().await {
            if let Err(s) = insert(&o, new(s, r), Some(SBQ_EV_OPENED)) {
                s.abort();
            }
        }
    });
    obj.add_task(task.abort_handle());
    SBQ_WOULD_BLOCK
}

/// Forgets a stream. Its directions should have ended (or been reset / stopped) first.
/// As a final safeguard, dropping an open direction explicitly aborts it (WT_SESSION_GONE
/// for WebTransport, 0 for raw QUIC); a finished send direction keeps its FIN.
pub fn release(h: u64) -> i32 {
    let Some(obj) = lock(&STREAMS).remove(&h) else {
        return SBQ_ERR_HANDLE as i32;
    };
    if let Some(conn) = crate::ctx::get(&CONNS, obj.conn) {
        if let Some(set) = lock(&conn.streams).as_mut() {
            set.remove(&h);
        }
    }
    drop(obj);
    SBQ_OK as i32
}
