// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! `worker_threads` host coordinator (B10).
//!
//! Workers are **process-isolated** - each `new Worker(path, opts)` in
//! the parent JS spawns a child `burn run --internal-worker <path>`
//! subprocess. IPC is length-prefixed JSON over the child's stdin /
//! stdout pipes (4-byte big-endian length, max 16 MiB per frame).
//!
//! ## Why processes, not threads
//!
//! * Kernel-level isolation: a worker crash / OOM doesn't take down
//!   the parent.
//! * Capability inheritance is **explicit**: the parent serializes its
//!   *current runtime* `Manifold` into `--allow-*` flags and the child
//!   `clap` parser builds an identical (or narrower) one. A bug in the
//!   codec can only narrow capabilities, never widen them
//!   ([`crate::manifold_codec`]).
//! * No `SharedArrayBuffer` / `Atomics` surface - the WASM linear-
//!   memory model can't share, so we don't pretend to.
//!
//! ## Hardening
//!
//! * **Depth cap** via `BURN_WORKER_DEPTH` (mirrors `BURN_SHIM_DEPTH`).
//!   Default ceiling 8 - fork-bomb defense.
//! * **Concurrency cap** via [`WorkerConfig::max_concurrent`] (default
//!   32) - bounded resource use per parent.
//! * **Frame-size cap** at 16 MiB - DoS defense against a hostile child
//!   sending a huge `JSON.stringify(...)`.
//! * **Linux**: child sets `PR_SET_PDEATHSIG = SIGKILL` so the kernel
//!   reaps it if the parent crashes (defense against orphaned workers).
//! * **All-OS**: parent's `Drop` closes child stdin and joins waiter
//!   threads, so any survivors are reaped even on abrupt parent exit.
//! * **Path validation**: the spawn path is canonicalised and checked
//!   against the parent's `Manifold::fs` allow-list before `Command`
//!   ever runs.
//! * **Worker ids** are a monotonic counter from 1, never the host PID.

use afterburner_core::Manifold;
use kovan_channel::flavors::bounded::{
    Receiver as BoundedRx, Sender as BoundedTx, channel as bounded_channel,
};
use kovan_map::HopscotchMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
// The byte-frame IPC pipes (parent->child stdin, child->parent stdout) use
// `std::sync::mpsc`, not the lock-free kovan unbounded channel. Their writer
// thread does one blocking `recv()` and then sleeps until the *next* frame -
// the classic "send one frame, pause, send another later" pattern. kovan's
// unbounded `recv` parks on a fresh per-iteration `Signal` but never removes a
// signal it registered on a non-parking iteration, so the queue accrues stale
// signals; a later `send` can `pop_front()` a stale one and notify nobody,
// stranding the parked writer (a `cluster.disconnect()` terminate frame that
// the worker then never sees -> the worker never exits). `std::sync::mpsc`'s
// blocking `recv` has no such lost-wakeup, and these single-consumer command
// queues gain nothing from a lock-free structure: one dedicated thread does
// blocking pipe I/O, so the std channel is both correct and the right tool.
use std::sync::mpsc::{
    Receiver as UnboundedRx, Sender as UnboundedTx, channel as unbounded_channel,
};
use std::thread;
use std::time::Duration;

pub type WorkerId = i32;

mod frame {
    pub const INIT: &str = "init";
    pub const MSG: &str = "msg";
    pub const ONLINE: &str = "online";
    pub const ERROR: &str = "error";
    pub const TERMINATE: &str = "terminate";
    pub const CLOSE_PORT: &str = "close-port";
    // `exit` is a parent-side synthetic event - never appears on the
    // wire - so it has no constant here. The reader pump emits
    // `WorkerEvent::Exit` directly from the waiter thread.
}

pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub const WORKER_DEPTH_ENV: &str = "BURN_WORKER_DEPTH";
pub const WORKER_DEPTH_LIMIT: u32 = 8;

pub mod errors {
    pub const E_NO_DAEMON: i32 = -1;
    pub const E_PERMISSION: i32 = -2;
    pub const E_DEPTH: i32 = -3;
    pub const E_CONCURRENCY: i32 = -4;
    pub const E_PATH: i32 = -5;
    pub const E_SPAWN: i32 = -6;
    pub const E_FRAME_TOO_LARGE: i32 = -7;
    pub const E_NO_PARENT: i32 = -8;
    pub const E_BAD_ID: i32 = -9;
    pub const E_OTHER: i32 = -10;
    pub const E_EVAL_DISABLED: i32 = -11;
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub max_concurrent: usize,
    pub max_frame_bytes: usize,
    pub terminate_grace: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 32,
            max_frame_bytes: MAX_FRAME_BYTES,
            terminate_grace: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone)]
pub enum WorkerEvent {
    Online {
        worker_id: WorkerId,
    },
    Message {
        worker_id: WorkerId,
        payload: String,
    },
    Error {
        worker_id: WorkerId,
        message: String,
        stack: String,
    },
    Exit {
        worker_id: WorkerId,
        code: i32,
    },
    TerminateRequested,
    ParentMessage {
        payload: String,
    },
}

/// Parent-side per-worker handle. Both fields are `Clone`, so this
/// satisfies `HopscotchMap<WorkerId, WorkerHandle>`'s `V: Clone` bound:
/// the lock-free map returns owned clones from `get`/`remove`,
/// which is fine because both `mpsc::Sender` and `Arc` are cheap to
/// clone (an atomic increment plus, for the sender, an extra channel
/// reference).
///
/// The actual `Child` lives inside the waiter thread so it can call
/// `wait()` without contending with the spawn path. Threads are
/// detached - they exit naturally when their channels close (writer
/// when stdin_tx is dropped; reader when the child closes stdout;
/// waiter after `Child::wait`). The OS reaps any survivors when the
/// parent process exits.
#[derive(Clone)]
struct WorkerHandle {
    stdin_tx: UnboundedTx<Vec<u8>>,
    kill: Arc<KillHandle>,
}

struct KillHandle {
    /// Set when the spawn finishes. The waiter thread populates this
    /// from the OS-level child handle (Unix: pid; Windows: HANDLE).
    pid: AtomicI32,
}

impl KillHandle {
    fn new() -> Self {
        Self {
            pid: AtomicI32::new(0),
        }
    }

    fn set(&self, pid: i32) {
        self.pid.store(pid, Ordering::Release);
    }

    /// SIGKILL the child if we know its pid. No-op when pid is 0
    /// (waiter not yet established) or on platforms where signal
    /// delivery isn't trivially expressible.
    #[cfg(unix)]
    fn force_kill(&self) {
        let pid = self.pid.load(Ordering::Acquire);
        if pid > 0 {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
    }

    #[cfg(not(unix))]
    fn force_kill(&self) {
        // Windows fallback uses Child::kill via the waiter - no
        // standalone PID handle needed. The waiter sees stdin close
        // and gives up.
    }
}

struct ParentState {
    next_id: AtomicI32,
    /// Wait-free reads (`get`); lock-free writes (`insert`/`remove`)
    /// per kovan_map's HopscotchMap design - no Mutex anywhere on the
    /// daemon hot path.
    active: HopscotchMap<WorkerId, WorkerHandle>,
    alive: AtomicUsize,
}

struct ChildState {
    thread_id: WorkerId,
    worker_data: String,
    /// Single-producer, single-consumer queue feeding a dedicated
    /// stdout-writer thread. Avoids any user-level lock on stdout -
    /// the writer thread is the only entity that touches the pipe.
    stdout_tx: UnboundedTx<Vec<u8>>,
    parent_closed: Arc<AtomicBool>,
}

enum Role {
    Parent(ParentState),
    Child(ChildState),
}

pub struct DaemonWorkers {
    role: Role,
    config: WorkerConfig,
    /// Bounded channel for events surfaced to the daemon event loop.
    /// Bounded so chatty workers / unhandled errors apply backpressure
    /// to the reader threads (their `send` blocks until the loop
    /// drains). All four channel ops on kovan are lock-free.
    events_tx: BoundedTx<WorkerEvent>,
    events_rx: BoundedRx<WorkerEvent>,
    manifold: Manifold,
    burn_exe: PathBuf,
}

impl std::fmt::Debug for DaemonWorkers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaemonWorkers")
            .field(
                "role",
                &match &self.role {
                    Role::Parent(_) => "parent",
                    Role::Child(_) => "child",
                },
            )
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DaemonWorkers {
    pub fn new_parent(manifold: Manifold, config: WorkerConfig) -> Arc<Self> {
        let (tx, rx) = bounded_channel::<WorkerEvent>(1024);
        Arc::new(Self {
            role: Role::Parent(ParentState {
                next_id: AtomicI32::new(1),
                active: HopscotchMap::new(),
                alive: AtomicUsize::new(0),
            }),
            config,
            events_tx: tx,
            events_rx: rx,
            manifold,
            burn_exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("burn")),
        })
    }

    pub fn new_child(
        manifold: Manifold,
        config: WorkerConfig,
    ) -> Result<Arc<Self>, ChildInitError> {
        let (events_tx, events_rx) = bounded_channel::<WorkerEvent>(1024);
        let init = read_init_frame_from_stdin(config.max_frame_bytes)?;
        let parent_closed = Arc::new(AtomicBool::new(false));

        // Stdin pump (parent → child events). Detached - exits when
        // stdin closes.
        {
            let tx = events_tx.clone();
            let max = config.max_frame_bytes;
            let closed = Arc::clone(&parent_closed);
            thread::Builder::new()
                .name("burn-worker-stdin".into())
                .spawn(move || child_stdin_pump(tx, max, closed))
                .map_err(|e| ChildInitError::Spawn(e.to_string()))?;
        }

        // Stdout writer thread (child → parent frames). Single
        // consumer of the queue; writes are serialized through this
        // thread, so no user-level lock on stdout is needed.
        let (stdout_tx, stdout_rx) = unbounded_channel::<Vec<u8>>();
        thread::Builder::new()
            .name("burn-worker-stdout".into())
            .spawn(move || child_stdout_writer(stdout_rx))
            .map_err(|e| ChildInitError::Spawn(e.to_string()))?;

        Ok(Arc::new(Self {
            role: Role::Child(ChildState {
                thread_id: init.thread_id,
                worker_data: init.worker_data,
                stdout_tx,
                parent_closed,
            }),
            config,
            events_tx,
            events_rx,
            manifold,
            burn_exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("burn")),
        }))
    }

    pub fn is_main_thread(&self) -> bool {
        matches!(self.role, Role::Parent(_))
    }

    pub fn thread_id(&self) -> WorkerId {
        match &self.role {
            Role::Parent(_) => 0,
            Role::Child(c) => c.thread_id,
        }
    }

    pub fn worker_data(&self) -> &str {
        match &self.role {
            Role::Parent(_) => "",
            Role::Child(c) => &c.worker_data,
        }
    }

    pub fn try_recv_event(&self) -> Option<WorkerEvent> {
        // kovan_channel try_recv is &self / lock-free.
        self.events_rx.try_recv()
    }

    pub fn has_alive_workers(&self) -> bool {
        match &self.role {
            Role::Parent(p) => p.alive.load(Ordering::Acquire) > 0,
            Role::Child(_) => false,
        }
    }

    pub fn signal_parent_closed(&self) {
        if let Role::Child(c) = &self.role {
            c.parent_closed.store(true, Ordering::Release);
        }
    }

    pub fn parent_closed_signaled(&self) -> bool {
        match &self.role {
            Role::Parent(_) => false,
            Role::Child(c) => c.parent_closed.load(Ordering::Acquire),
        }
    }

    /// Called from the daemon event loop after dispatching `Exit` to
    /// JS: remove the handle from the lock-free map and decrement the
    /// counter so subsequent spawns don't see a phantom alive worker.
    pub fn mark_reaped(&self, worker_id: WorkerId) {
        if let Role::Parent(p) = &self.role
            && p.active.remove(&worker_id).is_some()
        {
            // Dropping the WorkerHandle drops the stdin sender clone
            // - once all senders are gone, the writer thread exits.
            // The waiter thread already exited (it's what posted the
            // Exit event we're processing now). The kill handle drops
            // last; harmless because the child is already gone.
            p.alive.fetch_sub(1, Ordering::Release);
        }
    }

    pub fn spawn_worker(
        &self,
        script_path: &str,
        worker_data_json: &str,
        last_error: &mut String,
    ) -> i32 {
        self.spawn_worker_with_env(script_path, worker_data_json, "", last_error)
    }

    /// Same as [`Self::spawn_worker`] but additionally injects the
    /// JSON-encoded `{key:val,...}` env map into the spawned child's
    /// environment. Reserved env vars used by burn itself
    /// (`BURN_WORKER_DEPTH`, `BURN_QUIET`) are filtered out - caller-
    /// supplied values for those would break the depth-cap and
    /// quiet-mode guarantees. Used by the `cluster` polyfill to set
    /// `BURN_CLUSTER_REUSEPORT=1` on every forked worker so its
    /// daemon listeners bind via `SO_REUSEPORT`.
    pub fn spawn_worker_with_env(
        &self,
        script_path: &str,
        worker_data_json: &str,
        env_json: &str,
        last_error: &mut String,
    ) -> i32 {
        let parent = match &self.role {
            Role::Parent(p) => p,
            Role::Child(_) => {
                *last_error =
                    "worker_threads: nested workers from inside a worker are not supported".into();
                return errors::E_NO_PARENT;
            }
        };

        let depth = current_worker_depth();
        if depth >= WORKER_DEPTH_LIMIT {
            *last_error = format!(
                "worker_threads: depth limit reached ({WORKER_DEPTH_ENV}={depth}, limit={WORKER_DEPTH_LIMIT})"
            );
            return errors::E_DEPTH;
        }

        if parent.alive.load(Ordering::Acquire) >= self.config.max_concurrent {
            *last_error = format!(
                "worker_threads: concurrency cap reached ({} alive)",
                parent.alive.load(Ordering::Relaxed)
            );
            return errors::E_CONCURRENCY;
        }

        let canonical = match canonicalise_for_read(script_path, &self.manifold) {
            Ok(p) => p,
            Err(why) => {
                *last_error = format!("worker_threads: {why}");
                return errors::E_PATH;
            }
        };

        let id = parent.next_id.fetch_add(1, Ordering::Relaxed);
        let cli_args = crate::manifold_codec::manifold_to_cli_args(&self.manifold);
        let mut cmd = Command::new(&self.burn_exe);
        for arg in &cli_args {
            cmd.arg(arg);
        }
        cmd.arg("--quiet");
        cmd.arg("run");
        cmd.arg("--internal-worker");
        cmd.arg("--worker-thread-id");
        cmd.arg(id.to_string());
        cmd.arg(canonical.as_os_str());
        cmd.env(WORKER_DEPTH_ENV, (depth + 1).to_string());
        cmd.env("BURN_QUIET", "1");
        if !env_json.is_empty() {
            apply_env_overrides(&mut cmd, env_json);
        }
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());

        #[cfg(target_os = "linux")]
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                let res = libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
                if res != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                *last_error = format!("worker_threads: spawn: {e}");
                return errors::E_SPAWN;
            }
        };

        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");

        let kill = Arc::new(KillHandle::new());
        kill.set(child.id() as i32);

        // Unbounded so the JS host import never blocks waiting for a
        // slow / hostile worker. Frame-size cap is the DoS guard.
        let (stdin_tx, stdin_rx) = unbounded_channel::<Vec<u8>>();

        // Writer thread - drains the queue onto the child's stdin
        // pipe. Detached (no JoinHandle stored): exits when stdin_tx
        // is dropped or the pipe closes. The OS reaps any survivors
        // when the parent process exits.
        thread::Builder::new()
            .name(format!("burn-worker-{id}-writer"))
            .spawn(move || parent_writer_pump(stdin, stdin_rx))
            .expect("spawn writer thread");

        // Reader thread - child→parent events. `events_tx.send` is
        // bounded; backpressure is intentional so a chatty worker
        // doesn't outpace the daemon event loop.
        let evt_tx = self.events_tx.clone();
        let max_frame = self.config.max_frame_bytes;
        thread::Builder::new()
            .name(format!("burn-worker-{id}-reader"))
            .spawn(move || parent_reader_pump(id, stdout, evt_tx, max_frame))
            .expect("spawn reader thread");

        // Waiter thread - owns the Child, observes its exit, posts
        // an Exit event.
        let evt_tx2 = self.events_tx.clone();
        thread::Builder::new()
            .name(format!("burn-worker-{id}-waiter"))
            .spawn(move || waiter_pump(id, child, evt_tx2))
            .expect("spawn waiter thread");

        let init_frame = serde_json::json!({
            "type": frame::INIT,
            "thread_id": id,
            "worker_data": worker_data_json,
        });
        // `send` is non-blocking; it only fails if the writer thread we
        // just spawned has already exited (it has not), so the error is
        // unreachable here and ignored.
        let _ = stdin_tx.send(serde_json::to_vec(&init_frame).unwrap_or_default());

        // HopscotchMap insert is lock-free.
        parent.active.insert(id, WorkerHandle { stdin_tx, kill });
        parent.alive.fetch_add(1, Ordering::Release);

        id
    }

    pub fn post_message_to_worker(
        &self,
        worker_id: WorkerId,
        payload_json: &str,
        last_error: &mut String,
    ) -> i32 {
        let parent = match &self.role {
            Role::Parent(p) => p,
            Role::Child(_) => return errors::E_NO_PARENT,
        };
        if payload_json.len() > self.config.max_frame_bytes {
            *last_error = format!(
                "worker_threads: message exceeds {} bytes",
                self.config.max_frame_bytes
            );
            return errors::E_FRAME_TOO_LARGE;
        }
        // HopscotchMap::get returns an owned clone - the lookup is
        // wait-free.
        let Some(handle) = parent.active.get(&worker_id) else {
            *last_error = format!("worker_threads: unknown worker id {worker_id}");
            return errors::E_BAD_ID;
        };
        let env = serde_json::json!({"type": frame::MSG, "payload_json": payload_json});
        let _ = handle
            .stdin_tx
            .send(serde_json::to_vec(&env).unwrap_or_default());
        0
    }

    /// `force=true` sends SIGKILL after the graceful frame; `force=false`
    /// just delivers the terminate frame and lets the child shut down.
    pub fn terminate_worker(&self, worker_id: WorkerId, force: bool) -> i32 {
        let Role::Parent(parent) = &self.role else {
            return errors::E_NO_PARENT;
        };
        let Some(handle) = parent.active.get(&worker_id) else {
            return errors::E_BAD_ID;
        };
        let frame = serde_json::json!({"type": frame::TERMINATE});
        let _ = handle
            .stdin_tx
            .send(serde_json::to_vec(&frame).unwrap_or_default());
        if force {
            handle.kill.force_kill();
        }
        0
    }

    pub fn post_to_parent(&self, payload_json: &str, last_error: &mut String) -> i32 {
        let Role::Child(child) = &self.role else {
            return errors::E_NO_PARENT;
        };
        if payload_json.len() > self.config.max_frame_bytes {
            *last_error = format!(
                "worker_threads: message exceeds {} bytes",
                self.config.max_frame_bytes
            );
            return errors::E_FRAME_TOO_LARGE;
        }
        let env = serde_json::json!({"type": frame::MSG, "payload_json": payload_json});
        let _ = child
            .stdout_tx
            .send(serde_json::to_vec(&env).unwrap_or_default());
        0
    }

    pub fn post_online_to_parent(&self, _last_error: &mut String) -> i32 {
        let Role::Child(child) = &self.role else {
            return errors::E_NO_PARENT;
        };
        let env = serde_json::json!({"type": frame::ONLINE});
        let _ = child
            .stdout_tx
            .send(serde_json::to_vec(&env).unwrap_or_default());
        0
    }

    pub fn post_error_to_parent(
        &self,
        message: &str,
        stack: &str,
        _last_error: &mut String,
    ) -> i32 {
        let Role::Child(child) = &self.role else {
            return errors::E_NO_PARENT;
        };
        let env = serde_json::json!({
            "type": frame::ERROR,
            "message": message,
            "stack": stack,
        });
        let _ = child
            .stdout_tx
            .send(serde_json::to_vec(&env).unwrap_or_default());
        0
    }
}

impl Drop for DaemonWorkers {
    /// Best-effort cleanup. We don't join the worker threads (none of
    /// them are stored as `JoinHandle`s - they're detached). Force-
    /// killing every still-alive child via the kill handle gives the
    /// OS something to reap; the writer / reader threads exit on
    /// their own when the pipes close.
    fn drop(&mut self) {
        if let Role::Parent(parent) = &self.role {
            // Snapshot ids by iterating the lock-free map.
            let ids: Vec<WorkerId> = parent.active.iter().map(|(id, _)| id).collect();
            for id in ids {
                if let Some(handle) = parent.active.remove(&id) {
                    let term = serde_json::json!({"type": frame::TERMINATE});
                    let _ = handle
                        .stdin_tx
                        .send(serde_json::to_vec(&term).unwrap_or_default());
                    handle.kill.force_kill();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

#[derive(Debug)]
pub enum ChildInitError {
    Eof,
    InvalidFrame(String),
    Spawn(String),
    Io(std::io::Error),
}

impl std::fmt::Display for ChildInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Eof => write!(f, "worker child: parent closed stdin before init"),
            Self::InvalidFrame(s) => write!(f, "worker child: invalid init frame: {s}"),
            Self::Spawn(s) => write!(f, "worker child: thread spawn: {s}"),
            Self::Io(e) => write!(f, "worker child: io: {e}"),
        }
    }
}
impl std::error::Error for ChildInitError {}

struct InitPayload {
    thread_id: WorkerId,
    worker_data: String,
}

fn read_init_frame_from_stdin(max_bytes: usize) -> Result<InitPayload, ChildInitError> {
    let mut stdin = std::io::stdin().lock();
    let bytes = read_frame(&mut stdin, max_bytes).map_err(map_io)?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| ChildInitError::InvalidFrame(e.to_string()))?;
    let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
    if ty != frame::INIT {
        return Err(ChildInitError::InvalidFrame(format!(
            "expected type=init, got type={ty}"
        )));
    }
    let thread_id = v
        .get("thread_id")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| ChildInitError::InvalidFrame("missing thread_id".into()))?
        as WorkerId;
    let worker_data = v
        .get("worker_data")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    Ok(InitPayload {
        thread_id,
        worker_data,
    })
}

fn map_io(e: FrameReadError) -> ChildInitError {
    match e {
        FrameReadError::Eof => ChildInitError::Eof,
        FrameReadError::TooLarge(n) => {
            ChildInitError::InvalidFrame(format!("frame too large: {n} bytes"))
        }
        FrameReadError::Truncated => ChildInitError::InvalidFrame("truncated frame body".into()),
        FrameReadError::Io(io) => ChildInitError::Io(io),
    }
}

#[derive(Debug)]
enum FrameReadError {
    Eof,
    TooLarge(usize),
    Truncated,
    Io(std::io::Error),
}

impl From<std::io::Error> for FrameReadError {
    fn from(e: std::io::Error) -> Self {
        FrameReadError::Io(e)
    }
}

/// Read one length-prefixed frame: `[u32 BE length][N bytes]`. Reject
/// anything bigger than `max_bytes`.
fn read_frame<R: Read>(r: &mut R, max_bytes: usize) -> Result<Vec<u8>, FrameReadError> {
    let mut len_buf = [0u8; 4];
    let read = read_some_or_eof(r, &mut len_buf)?;
    if read == 0 {
        return Err(FrameReadError::Eof);
    }
    if read != 4 {
        return Err(FrameReadError::Truncated);
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_bytes {
        return Err(FrameReadError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    let body = read_some_or_eof(r, &mut buf)?;
    if body != len {
        return Err(FrameReadError::Truncated);
    }
    Ok(buf)
}

/// Returns the number of bytes filled before EOF/error. 0 means "EOF
/// before any byte was read" - distinct from a partial fill (which
/// represents truncation when it isn't 0 or buf.len()).
fn read_some_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Ok(filled),
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u32;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

fn parent_writer_pump(mut stdin: std::process::ChildStdin, rx: UnboundedRx<Vec<u8>>) {
    // `recv()` returns `Err` only once every `Sender` clone has dropped,
    // i.e. the worker handle is gone and no more frames can arrive.
    while let Ok(bytes) = rx.recv() {
        if write_frame(&mut stdin, &bytes).is_err() {
            break;
        }
    }
    let _ = stdin.flush();
}

/// Child-side stdout writer thread. Exits when the queue's senders all
/// drop (i.e. the worker is shutting down).
fn child_stdout_writer(rx: UnboundedRx<Vec<u8>>) {
    let mut out = std::io::stdout().lock();
    while let Ok(bytes) = rx.recv() {
        if write_frame(&mut out, &bytes).is_err() {
            break;
        }
    }
    let _ = out.flush();
}

fn parent_reader_pump(
    worker_id: WorkerId,
    mut stdout: std::process::ChildStdout,
    tx: BoundedTx<WorkerEvent>,
    max_frame_bytes: usize,
) {
    loop {
        let bytes = match read_frame(&mut stdout, max_frame_bytes) {
            Ok(b) => b,
            Err(_) => return,
        };
        let v: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return,
        };
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let evt = match ty {
            frame::ONLINE => WorkerEvent::Online { worker_id },
            frame::MSG => {
                let payload = v
                    .get("payload_json")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                WorkerEvent::Message { worker_id, payload }
            }
            frame::ERROR => {
                let message = v
                    .get("message")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let stack = v
                    .get("stack")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                WorkerEvent::Error {
                    worker_id,
                    message,
                    stack,
                }
            }
            _ => continue,
        };
        // bounded `send` blocks if the daemon event loop is slow -
        // intentional backpressure so we don't drop messages.
        tx.send(evt);
    }
}

fn waiter_pump(id: WorkerId, mut child: Child, tx: BoundedTx<WorkerEvent>) {
    let code = match child.wait() {
        Ok(status) => status.code().unwrap_or(-1),
        Err(_) => -1,
    };
    tx.send(WorkerEvent::Exit {
        worker_id: id,
        code,
    });
}

fn child_stdin_pump(
    tx: BoundedTx<WorkerEvent>,
    max_frame_bytes: usize,
    parent_closed: Arc<AtomicBool>,
) {
    let mut stdin = std::io::stdin().lock();
    loop {
        let bytes = match read_frame(&mut stdin, max_frame_bytes) {
            Ok(b) => b,
            Err(_) => {
                parent_closed.store(true, Ordering::Release);
                return;
            }
        };
        let v: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let evt = match ty {
            frame::MSG => {
                let payload = v
                    .get("payload_json")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                WorkerEvent::ParentMessage { payload }
            }
            frame::TERMINATE => WorkerEvent::TerminateRequested,
            frame::CLOSE_PORT => {
                parent_closed.store(true, Ordering::Release);
                continue;
            }
            _ => continue,
        };
        tx.send(evt);
    }
}

fn canonicalise_for_read(path: &str, m: &Manifold) -> Result<PathBuf, String> {
    use afterburner_core::FsAccess;

    let requested = PathBuf::from(path);
    let absolute = if requested.is_absolute() {
        requested
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cwd: {e}"))?
            .join(&requested)
    };
    let canonical = absolute
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {e}", absolute.display()))?;

    let roots: &[PathBuf] = match &m.fs {
        FsAccess::None => {
            return Err(format!(
                "worker script {} blocked: fs access not granted",
                canonical.display()
            ));
        }
        FsAccess::ReadOnly(r) | FsAccess::ReadWrite(r) => r,
    };
    if roots.is_empty() {
        return Ok(canonical);
    }
    for root in roots {
        let root_canon = root.canonicalize().unwrap_or_else(|_| root.clone());
        if canonical.starts_with(&root_canon) {
            return Ok(canonical);
        }
    }
    Err(format!(
        "worker script {} outside fs allow-list",
        canonical.display()
    ))
}

fn current_worker_depth() -> u32 {
    std::env::var(WORKER_DEPTH_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Merge the JSON env map into `cmd`. Reserved keys are skipped:
/// `BURN_WORKER_DEPTH` (depth-cap defense) and `BURN_QUIET`
/// (silent-mode contract) - letting JS override these would break
/// the security envelope.
fn apply_env_overrides(cmd: &mut Command, env_json: &str) {
    const RESERVED: &[&str] = &[WORKER_DEPTH_ENV, "BURN_QUIET"];
    let v: serde_json::Value = match serde_json::from_str(env_json) {
        Ok(v) => v,
        Err(_) => return,
    };
    let map = match v.as_object() {
        Some(m) => m,
        None => return,
    };
    for (k, val) in map {
        if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(k)) {
            continue;
        }
        let s = match val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Null => continue,
            _ => continue,
        };
        cmd.env(k, s);
    }
}

impl DaemonWorkers {
    /// OS pid of a spawned worker, or `0` if the id is unknown
    /// or the kill handle hasn't been populated yet.
    pub fn worker_pid(&self, worker_id: WorkerId) -> i32 {
        match &self.role {
            Role::Parent(p) => p
                .active
                .get(&worker_id)
                .map(|h| h.kill.pid.load(Ordering::Acquire))
                .unwrap_or(0),
            Role::Child(_) => 0,
        }
    }
}
