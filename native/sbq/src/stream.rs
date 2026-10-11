/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
  GLM 5.3 Flash <noreply@z.ai>
*/

//! Bidirectional streams: non-blocking reads and writes polled with wakers that post READABLE and
//! WRITABLE, and a task per stream that reports STOP_SENDING or the acknowledged end.

use std::future::Future;
use std::pin::{pin, Pin};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use quinn::{ReadError, RecvStream, SendStream, VarInt, WriteError};

use crate::conn::ConnObj;
use crate::ctx::{lock, next_handle, rt, Ctx, EvWaker, CONNS, STREAMS};
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
    send: SendStream,
    recv: RecvStream,
    send_state: SendState,
    recv_state: RecvState,
}

pub struct StreamObj {
    pub conn: u64,
    inner: Mutex<Inner>,
    read_waker: Waker,
    write_waker: Waker,
}

/// Encodes an application error code as a negative result.
pub fn code_result(code: u64) -> i64 {
    -(SBQ_CODE_BASE + code as i64)
}

impl StreamObj {
    /// STOP_SENDING arrived: reset the direction with the same code (RFC 9000 section 3.5; quinn
    /// leaves it to the application).
    fn peer_stopped(&self, code: VarInt) {
        let mut g = lock(&self.inner);
        if g.send_state == SendState::Open {
            let _ = g.send.reset(code);
            g.send_state = SendState::Stopped(code.into_inner());
        }
    }

    pub fn write(&self, data: &[u8]) -> i64 {
        if data.is_empty() {
            return SBQ_ERR_ARG;
        }
        let mut g = lock(&self.inner);
        match g.send_state {
            SendState::Open => {}
            SendState::Stopped(c) => return code_result(c),
            SendState::Finished | SendState::Reset => return SBQ_ERR_CLOSED,
        }
        let mut cx = Context::from_waker(&self.write_waker);
        match Pin::new(&mut g.send).poll_write(&mut cx, data) {
            Poll::Ready(Ok(n)) => n as i64,
            Poll::Pending => SBQ_WOULD_BLOCK,
            Poll::Ready(Err(WriteError::Stopped(c))) => {
                let _ = g.send.reset(c);
                g.send_state = SendState::Stopped(c.into_inner());
                code_result(c.into_inner())
            }
            Poll::Ready(Err(WriteError::ConnectionLost(_))) => SBQ_ERR_CONNECTION,
            Poll::Ready(Err(_)) => SBQ_ERR_CLOSED,
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> i64 {
        if buf.is_empty() {
            return SBQ_ERR_ARG;
        }
        let mut g = lock(&self.inner);
        match g.recv_state {
            RecvState::Open => {}
            RecvState::Fin => return SBQ_FIN,
            RecvState::Reset(c) => return code_result(c),
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
                code_result(c.into_inner())
            }
            Poll::Ready(Err(ReadError::ConnectionLost(_))) => SBQ_ERR_CONNECTION,
            Poll::Ready(Err(_)) => SBQ_ERR_CLOSED,
        }
    }

    pub fn finish(&self) -> i64 {
        let mut g = lock(&self.inner);
        match g.send_state {
            // quinn's finish reports a STOP_SENDING that raced in as Ok and leaves the code to
            // the stopped() task above, so only "already ended" can be seen here.
            SendState::Open => match g.send.finish() {
                Ok(()) => {
                    g.send_state = SendState::Finished;
                    SBQ_OK
                }
                Err(_) => SBQ_ERR_CONNECTION,
            },
            SendState::Stopped(c) => code_result(c),
            SendState::Finished | SendState::Reset => SBQ_ERR_CLOSED,
        }
    }

    pub fn reset(&self, code: VarInt) -> i64 {
        let mut g = lock(&self.inner);
        match g.send_state {
            SendState::Open | SendState::Finished => {
                let _ = g.send.reset(code);
                g.send_state = SendState::Reset;
                SBQ_OK
            }
            // Reset already, by the peer's STOP_SENDING or an earlier call.
            SendState::Stopped(_) | SendState::Reset => SBQ_OK,
        }
    }

    pub fn stop(&self, code: VarInt) -> i64 {
        let mut g = lock(&self.inner);
        if g.recv_state == RecvState::Open {
            let _ = g.recv.stop(code);
            g.recv_state = RecvState::Stopped;
        }
        SBQ_OK
    }

    pub fn set_priority(&self, priority: i32) -> i64 {
        let g = lock(&self.inner);
        match g.send.set_priority(priority) {
            Ok(()) => SBQ_OK,
            Err(_) => SBQ_ERR_CLOSED,
        }
    }
}

/// Registers a new stream of `conn` and starts its STOP_SENDING / acknowledgement task.
pub fn insert(conn: &Arc<ConnObj>, send: SendStream, recv: RecvStream) -> u64 {
    let h = next_handle();
    let ctx: Arc<Ctx> = conn.ctx.clone();
    let stopped = send.stopped();
    let waker = |kind| {
        Waker::from(Arc::new(EvWaker {
            ctx: ctx.clone(),
            kind,
            handle: h,
        }))
    };
    let obj = Arc::new(StreamObj {
        conn: conn.handle,
        inner: Mutex::new(Inner {
            send,
            recv,
            send_state: SendState::Open,
            recv_state: RecvState::Open,
        }),
        read_waker: waker(SBQ_EV_READABLE),
        write_waker: waker(SBQ_EV_WRITABLE),
    });
    let weak = Arc::downgrade(&obj);
    lock(&STREAMS).insert(h, obj);
    lock(&conn.streams).insert(h);
    rt().spawn(async move {
        match stopped.await {
            Ok(Some(code)) => {
                if let Some(obj) = weak.upgrade() {
                    obj.peer_stopped(code);
                }
                ctx.post(SBQ_EV_STOPPED, h, code.into_inner() as i64, 0);
            }
            Ok(None) => ctx.post(SBQ_EV_FINISHED_ACKED, h, 0, 0),
            Err(_) => {}
        }
    });
    h
}

/// Opens a bidirectional stream now if the peer's stream limit allows it; otherwise waits for
/// credit in a task that posts OPENED, and returns SBQ_WOULD_BLOCK.
pub fn open(conn_h: u64) -> i64 {
    let Some(obj) = crate::ctx::get(&CONNS, conn_h) else {
        return SBQ_ERR_HANDLE;
    };
    let Some(conn) = obj.connection() else {
        return SBQ_ERR_STATE;
    };
    {
        let mut fut = pin!(conn.open_bi());
        match fut.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(Ok((s, r))) => return insert(&obj, s, r) as i64,
            Poll::Ready(Err(_)) => return SBQ_ERR_CONNECTION,
            Poll::Pending => {}
        }
    }
    let o = obj.clone();
    let task = rt().spawn(async move {
        if let Ok((s, r)) = conn.open_bi().await {
            let sh = insert(&o, s, r);
            o.ctx.post(SBQ_EV_OPENED, sh, o.handle as i64, 0);
        }
    });
    obj.add_task(task.abort_handle());
    SBQ_WOULD_BLOCK
}

/// Forgets a stream. Its directions should have ended (or been reset / stopped) first: as with
/// quinn's own drop, an open send side is finished and an unread receive side stopped with 0.
pub fn release(h: u64) -> i32 {
    let Some(obj) = lock(&STREAMS).remove(&h) else {
        return SBQ_ERR_HANDLE as i32;
    };
    if let Some(conn) = crate::ctx::get(&CONNS, obj.conn) {
        lock(&conn.streams).remove(&h);
    }
    drop(obj);
    SBQ_OK as i32
}
