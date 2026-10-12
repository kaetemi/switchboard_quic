/*
Polyverse Switchboard
Microservice Network Architecture
Copyright (C) 2018-2026  Jan BOON (Kaetemi)
Authors:
  Jan Boon <jan.boon@kaetemi.be>
  Claude Opus 5.5 <noreply@anthropic.com>
*/

//! The process-wide runtime, the per-caller contexts with their event queues, the notifier
//! thread that rings their doorbells, and the handle tables.
//!
//! Locking rules, which keep the shim free of the deadlock the evaluation found (a callback into
//! Dart from inside a quinn waker, which runs with the connection lock held, while the Dart thread
//! waited for that lock inside a leaf call):
//! * a waker only takes a context's queue lock, which is a leaf lock;
//! * only the notifier thread calls into the embedder (the doorbell), and it holds no lock but
//!   the context's doorbell lock while it does;
//! * the doorbell lock is taken by nothing else but `sbq_shutdown`, which must therefore not be a
//!   leaf call on the Dart side.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, LazyLock, Mutex, MutexGuard, OnceLock, Weak};
use std::task::Wake;

use crate::config::ConfigObj;
use crate::conn::{ConnObj, ListenerObj};
use crate::h3conn::H3Conn;
use crate::stream::StreamObj;

/// The doorbell: called from the notifier thread, with the context id, when the context's event
/// queue went from empty to non-empty. The embedder answers with `sbq_poll` until it returns fewer
/// events than it asked for (the queue is then empty, and the next event rings again). Never
/// called again for a context once `sbq_shutdown` returned.
pub type SbqDoorbell = extern "C" fn(ctx: u64);

/// One event, as `sbq_poll` delivers it. The meaning of `handle`, `a` and `b` depends on `kind`
/// (see the `SBQ_EV_*` constants).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SbqEvent {
    pub kind: i32,
    pub reserved: i32,
    pub handle: u64,
    pub a: i64,
    pub b: i64,
}

/// Locks a mutex, ignoring poisoning (a panic aborts in release builds anyway).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct Queue {
    events: VecDeque<SbqEvent>,
    /// A doorbell is due or delivered and the queue has not been drained since.
    rung: bool,
    closed: bool,
}

/// One caller of the shim (on the Dart side, one isolate): its own event queue and doorbell.
/// Every listener and connection belongs to the context that created it.
pub struct Ctx {
    pub id: u64,
    queue: Mutex<Queue>,
    bell: Mutex<Option<SbqDoorbell>>,
}

impl Ctx {
    /// Queues an event; rings the doorbell (through the notifier thread) if it is not rung yet.
    pub fn post(self: &Arc<Self>, kind: i32, handle: u64, a: i64, b: i64) {
        let ring = {
            let mut q = lock(&self.queue);
            if q.closed {
                return;
            }
            q.events.push_back(SbqEvent {
                kind,
                reserved: 0,
                handle,
                a,
                b,
            });
            !std::mem::replace(&mut q.rung, true)
        };
        if ring {
            notifier().ring(self.clone());
        }
    }

    /// Hands up to `cap` events to `put` (with their index), oldest first; returns how many. Fewer
    /// than `cap` means the queue is empty now, and the next post rings the doorbell again.
    pub fn poll(&self, cap: usize, mut put: impl FnMut(usize, SbqEvent)) -> usize {
        let mut q = lock(&self.queue);
        let n = cap.min(q.events.len());
        for (i, ev) in q.events.drain(..n).enumerate() {
            put(i, ev);
        }
        if q.events.is_empty() {
            q.rung = false;
        }
        n
    }

    /// Whether `sbq_shutdown` closed the context.
    pub fn is_closed(&self) -> bool {
        lock(&self.queue).closed
    }

    /// Stops event delivery: drops queued events, and returns once no doorbell call for this
    /// context is in progress.
    pub fn close(&self) {
        {
            let mut q = lock(&self.queue);
            q.closed = true;
            q.events.clear();
        }
        *lock(&self.bell) = None;
    }
}

struct Notifier {
    ring: Mutex<VecDeque<Weak<Ctx>>>,
    cv: Condvar,
}

impl Notifier {
    fn ring(&self, ctx: Arc<Ctx>) {
        lock(&self.ring).push_back(Arc::downgrade(&ctx));
        self.cv.notify_one();
    }

    fn run(&self) {
        loop {
            let batch: Vec<Weak<Ctx>> = {
                let mut g = lock(&self.ring);
                while g.is_empty() {
                    g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
                }
                g.drain(..).collect()
            };
            for ctx in batch.iter().filter_map(Weak::upgrade) {
                let bell = lock(&ctx.bell);
                if let Some(cb) = *bell {
                    cb(ctx.id);
                }
            }
        }
    }
}

fn notifier() -> &'static Notifier {
    static N: OnceLock<&'static Notifier> = OnceLock::new();
    N.get_or_init(|| {
        let n: &'static Notifier = Box::leak(Box::new(Notifier {
            ring: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("sbq-notify".into())
            .spawn(move || n.run())
            .expect("cannot start the sbq notifier thread");
        n
    })
}

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static INIT: Mutex<()> = Mutex::new(());
static NEXT: AtomicU64 = AtomicU64::new(1);

/// Starts the runtime (first call only; later calls keep the first thread count) and the
/// notifier thread.
pub fn start(worker_threads: u32) -> Result<(), String> {
    let _g = lock(&INIT);
    if RUNTIME.get().is_none() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads.clamp(1, 64) as usize)
            .thread_name("sbq")
            .enable_all()
            .build()
            .map_err(|e| format!("cannot start the runtime: {e}"))?;
        let _ = RUNTIME.set(rt);
    }
    notifier();
    Ok(())
}

pub fn rt() -> &'static tokio::runtime::Runtime {
    RUNTIME.get().expect("sbq_init was not called")
}

/// A fresh handle: unique across every kind of object for the life of the process, never 0.
pub fn next_handle() -> u64 {
    NEXT.fetch_add(1, Ordering::Relaxed)
}

pub fn new_ctx(bell: SbqDoorbell) -> Arc<Ctx> {
    let ctx = Arc::new(Ctx {
        id: next_handle(),
        queue: Mutex::new(Queue {
            events: VecDeque::new(),
            rung: false,
            closed: false,
        }),
        bell: Mutex::new(Some(bell)),
    });
    lock(&CTXS).insert(ctx.id, ctx.clone());
    ctx
}

pub type Table<T> = LazyLock<Mutex<HashMap<u64, Arc<T>>>>;

pub(crate) static CTXS: Table<Ctx> = LazyLock::new(Default::default);
pub(crate) static CONFIGS: Table<ConfigObj> = LazyLock::new(Default::default);
pub(crate) static LISTENERS: Table<ListenerObj> = LazyLock::new(Default::default);
pub(crate) static CONNS: Table<ConnObj> = LazyLock::new(Default::default);
pub(crate) static STREAMS: Table<StreamObj> = LazyLock::new(Default::default);
/// The HTTP/3 connections, by an id of their own (not a handle of the ABI): what
/// `sbq_shutdown` closes besides the handles.
pub(crate) static H3S: Table<H3Conn> = LazyLock::new(Default::default);

pub fn get<T>(table: &Table<T>, h: u64) -> Option<Arc<T>> {
    lock(table).get(&h).cloned()
}

/// A waker that turns a quinn readiness notification into an event of its context.
pub struct EvWaker {
    pub ctx: Arc<Ctx>,
    pub kind: i32,
    pub handle: u64,
}

impl Wake for EvWaker {
    fn wake(self: Arc<Self>) {
        self.ctx.post(self.kind, self.handle, 0, 0)
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.ctx.post(self.kind, self.handle, 0, 0)
    }
}

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Records the message `sbq_last_error` returns on this thread.
pub fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
}

pub fn last_error() -> String {
    LAST_ERROR.with(|e| e.borrow().clone())
}
