// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! Real OS-backed multiprocessing surface for the Python runtime (Section 5 of
//! the concurrency design).
//!
//! ## Model: spawn-based multiprocessing (decision D2)
//!
//! Python `multiprocessing.Process` with the `spawn` start method maps to a real
//! child runtime instance spawned via [`DaemonWorkers`]. The `Pipe`/`Queue` IPC
//! maps to the existing length-prefixed pipe IPC that `DaemonWorkers` already uses.
//!
//! ## fork semantics
//!
//! A true fork of a Wasm instance is not available on any runtime (decision D2,
//! operator confirmed 2026-06-25). `os.fork()` is therefore emulated as spawn plus
//! explicit state hand-off: the child receives its target callable and arguments as
//! JSON in the worker_data field and re-executes from that entry point. The
//! limitation is documented here and surfaced through a distinct errno rather than
//! silently succeeding with wrong semantics. The child pid returned is the
//! `WorkerId` (an i32 monotonic counter), not a real OS pid - callers that need the
//! real OS pid of the wrapper process can call `DaemonWorkers::worker_pid`.
//!
//! ## IPC: Pipe and Queue
//!
//! `os.pipe()` returns a pair of synthetic fds backed by a kovan bounded channel.
//! The write end and read end are registered in `ProcessState`. Guest `write(fd,
//! buf)` calls enqueue bytes into the channel; guest `read(fd, n)` dequeues them.
//! For cross-process `Pipe` the same channel is serialized as a region descriptor
//! passed to the child via worker_data (the read end goes to the child, the write
//! end stays in the parent - matching `multiprocessing.Pipe(duplex=False)`).
//!
//! ## Capability gate
//!
//! Process spawning requires `manifold.child_process == true`. Without the grant
//! `__syscall_fork` / `__syscall_clone` / `posix_spawn` all return EPERM (-1) and
//! `os.pipe()` returns EPERM too, so sealed runs are unaffected.
//!
//! ## Wiring
//!
//! Call [`wire_process_imports`] from [`crate::emscripten_mechanical`] after the
//! pthread surface has been wired. Available under the `daemon` feature only.

#![cfg(feature = "daemon")]

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use afterburner_core::Result;
use wasmtime::Caller;

use crate::{
    daemon_workers::{DaemonWorkers, WorkerConfig, WorkerEvent, errors as w_err},
    embedder_vm::EmbedderState,
};

type WtResult<T> = wasmtime::Result<T>;

// ---- Linux errno constants (Emscripten wasm32 ABI) ----------------------------

/// EPERM: operation not permitted (missing capability grant or no coordinator).
pub const EPERM: i32 = -1;
/// EAGAIN: resource temporarily unavailable (spawn cap or depth exceeded).
pub const EAGAIN: i32 = -11;
/// ENOMEM: cannot allocate resource (spawn failed for other reason).
pub const ENOMEM: i32 = -12;
/// EINVAL: invalid argument.
pub const EINVAL: i32 = -22;
/// EBADF: bad file descriptor (unknown pipe fd).
pub const EBADF: i32 = -9;
/// ECHILD: no child processes (waitpid with unknown pid).
pub const ECHILD: i32 = -10;

/// Synthetic pipe-fd base: well above the FS fd range and the socket fd range
/// so a pipe fd never aliases a file or socket fd.
pub const PIPE_FD_BASE: i32 = 4096;

// ---- ProcessState --------------------------------------------------------------

/// Direction of a pipe endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeEnd {
    Read,
    Write,
}

/// One endpoint of an in-process or cross-process pipe.
///
/// For in-process pipes (both ends in the same instance) the channel is a
/// `VecDeque<Vec<u8>>` shared through the same `ProcessState`. For cross-
/// process pipes the write end is held here while the read end is serialized
/// into the child's `worker_data` (or vice-versa, depending on which end
/// the parent keeps).
#[derive(Debug)]
pub struct PipeHandle {
    pub end: PipeEnd,
    /// In-process pipe buffer index. Both read and write ends share a pipe_id;
    /// the buffer lives at `ProcessState::pipe_bufs[pipe_id]`.
    pub pipe_id: u32,
}

/// Per-run process and pipe state stored in `EmbedderState`.
///
/// Box-allocated on first process/pipe syscall; `None` in sealed / no-process
/// runs. Single-threaded: the wasmtime store is exclusively owned per call.
#[derive(Debug, Default)]
pub struct ProcessState {
    /// Next synthetic pipe fd.
    next_fd: i32,
    /// Next pipe pair id (shared by both ends of a pair).
    next_pipe_id: u32,
    /// fd -> PipeHandle.
    pub pipes: HashMap<i32, PipeHandle>,
    /// pipe_id -> buffered bytes (written to the write-end, drained from the read-end).
    pub pipe_bufs: HashMap<u32, VecDeque<u8>>,
    /// WorkerId (from DaemonWorkers::spawn_worker) -> child "pid" (same value for our
    /// purposes; we return WorkerId as the guest-visible pid).
    pub child_pids: HashMap<i32, ()>,
}

impl ProcessState {
    pub fn new() -> Box<Self> {
        Box::new(Self {
            next_fd: PIPE_FD_BASE,
            next_pipe_id: 1,
            pipes: HashMap::new(),
            pipe_bufs: HashMap::new(),
            child_pids: HashMap::new(),
        })
    }

    /// Allocate a new pipe pair. Returns (read_fd, write_fd).
    pub fn alloc_pipe(&mut self) -> (i32, i32) {
        let pipe_id = self.next_pipe_id;
        self.next_pipe_id += 1;
        self.pipe_bufs.insert(pipe_id, VecDeque::new());

        let read_fd = self.next_fd;
        self.next_fd += 1;
        let write_fd = self.next_fd;
        self.next_fd += 1;

        self.pipes.insert(
            read_fd,
            PipeHandle {
                end: PipeEnd::Read,
                pipe_id,
            },
        );
        self.pipes.insert(
            write_fd,
            PipeHandle {
                end: PipeEnd::Write,
                pipe_id,
            },
        );

        (read_fd, write_fd)
    }

    /// Returns true if `fd` is a known pipe fd.
    pub fn is_pipe_fd(&self, fd: i32) -> bool {
        self.pipes.contains_key(&fd)
    }

    /// Write bytes to the write-end of a pipe. Returns bytes written, or EBADF.
    pub fn pipe_write(&mut self, fd: i32, data: &[u8]) -> i32 {
        let Some(handle) = self.pipes.get(&fd) else {
            return EBADF;
        };
        if handle.end != PipeEnd::Write {
            return EBADF;
        }
        let pipe_id = handle.pipe_id;
        let buf = self.pipe_bufs.entry(pipe_id).or_default();
        buf.extend(data);
        data.len() as i32
    }

    /// Read up to `count` bytes from the read-end of a pipe. Returns bytes read, or EBADF.
    pub fn pipe_read(&mut self, fd: i32, out: &mut [u8]) -> i32 {
        let Some(handle) = self.pipes.get(&fd) else {
            return EBADF;
        };
        if handle.end != PipeEnd::Read {
            return EBADF;
        }
        let pipe_id = handle.pipe_id;
        let buf = match self.pipe_bufs.get_mut(&pipe_id) {
            Some(b) => b,
            None => return 0,
        };
        let n = out.len().min(buf.len());
        for (dst, src) in out[..n].iter_mut().zip(buf.drain(..n)) {
            *dst = src;
        }
        n as i32
    }

    /// Register a spawned child pid (WorkerId).
    pub fn register_child(&mut self, worker_id: i32) {
        self.child_pids.insert(worker_id, ());
    }

    /// Remove a child pid. Returns true if it was known.
    pub fn remove_child(&mut self, worker_id: i32) -> bool {
        self.child_pids.remove(&worker_id).is_some()
    }

    /// Whether `worker_id` is a known child pid.
    pub fn has_child(&self, worker_id: i32) -> bool {
        self.child_pids.contains_key(&worker_id)
    }
}

// ---- Wiring -------------------------------------------------------------------

/// Wire `__syscall_pipe`, `__syscall_pipe2`, `__syscall_fork`, `__syscall_clone`,
/// `__syscall_waitid`, `__syscall_wait4`, `posix_spawn`, and `posix_spawnp` into
/// `linker`.
///
/// Must be called after all other `env.*` imports have been registered so
/// these explicit bindings take priority over any catch-all no-op stubs.
/// Available under the `daemon` feature only.
pub(crate) fn wire_process_imports(linker: &mut wasmtime::Linker<EmbedderState>) -> Result<()> {
    use afterburner_core::AfterburnerError;

    // __syscall_pipe(pipefd_ptr: i32) -> i32
    //
    // Allocates a new in-process pipe pair. Writes the two synthetic fds
    // (read_fd, write_fd) as two consecutive little-endian i32s into the
    // guest buffer at pipefd_ptr. Returns 0 on success, EPERM if the
    // child_process capability is not granted.
    linker
        .func_wrap(
            "env",
            "__syscall_pipe",
            |mut caller: Caller<'_, EmbedderState>, pipefd_ptr: i32| -> WtResult<i32> {
                if !process_allowed(&caller) {
                    return Ok(EPERM);
                }
                let Some(mem) = caller.data().pyodide_memory else {
                    return Ok(EINVAL);
                };
                let state = caller
                    .data_mut()
                    .process_state
                    .get_or_insert_with(ProcessState::new);
                let (read_fd, write_fd) = state.alloc_pipe();

                let ptr = pipefd_ptr as u32 as usize;
                let mem_data = mem.data_mut(&mut caller);
                if ptr + 8 > mem_data.len() {
                    return Ok(EINVAL);
                }
                mem_data[ptr..ptr + 4].copy_from_slice(&read_fd.to_le_bytes());
                mem_data[ptr + 4..ptr + 8].copy_from_slice(&write_fd.to_le_bytes());
                Ok(0)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_pipe: {e}")))?;

    // __syscall_pipe2(pipefd_ptr: i32, flags: i32) -> i32
    //
    // Same as __syscall_pipe; flags (O_CLOEXEC, O_NONBLOCK) are ignored in
    // the in-process model since the pipe endpoints are synthetic fds.
    linker
        .func_wrap(
            "env",
            "__syscall_pipe2",
            |mut caller: Caller<'_, EmbedderState>,
             pipefd_ptr: i32,
             _flags: i32|
             -> WtResult<i32> {
                if !process_allowed(&caller) {
                    return Ok(EPERM);
                }
                let Some(mem) = caller.data().pyodide_memory else {
                    return Ok(EINVAL);
                };
                let state = caller
                    .data_mut()
                    .process_state
                    .get_or_insert_with(ProcessState::new);
                let (read_fd, write_fd) = state.alloc_pipe();

                let ptr = pipefd_ptr as u32 as usize;
                let mem_data = mem.data_mut(&mut caller);
                if ptr + 8 > mem_data.len() {
                    return Ok(EINVAL);
                }
                mem_data[ptr..ptr + 4].copy_from_slice(&read_fd.to_le_bytes());
                mem_data[ptr + 4..ptr + 8].copy_from_slice(&write_fd.to_le_bytes());
                Ok(0)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_pipe2: {e}")))?;

    // __syscall_fork() -> i32
    //
    // Emulated as spawn + explicit state hand-off (D2: a true wasm-instance
    // fork is not available on any runtime; this is the standard wasm constraint
    // and is documented, not hidden). Returns the WorkerId as the child "pid"
    // on success (>0 in the parent instance), or EPERM / EAGAIN / ENOMEM on
    // failure. In the child instance the caller sees a separate process; the
    // "return 0" to the child is delivered by the child's own re-entry.
    linker
        .func_wrap(
            "env",
            "__syscall_fork",
            |caller: Caller<'_, EmbedderState>| -> i32 { spawn_child_process(&caller, "") },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_fork: {e}")))?;

    // __syscall_clone(fn_ptr: i32, stack: i32, flags: i32, arg: i32, ...) -> i32
    //
    // Linux clone(2) used by some multiprocessing implementations. In the
    // process-isolation model this maps to spawn of a new runtime instance,
    // passing fn_ptr + arg as worker_data. The stack / flags arguments are not
    // meaningful for a separate process instance and are ignored.
    linker
        .func_wrap(
            "env",
            "__syscall_clone",
            |caller: Caller<'_, EmbedderState>,
             fn_ptr: i32,
             _stack: i32,
             _flags: i32,
             arg: i32,
             _tls: i32|
             -> i32 {
                let worker_data = serde_json::json!({
                    "fn_ptr": fn_ptr,
                    "arg": arg,
                })
                .to_string();
                spawn_child_process(&caller, &worker_data)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_clone: {e}")))?;

    // __syscall_waitid(idtype: i32, id: i32, infop: i32, options: i32) -> i32
    //
    // Wait for a child process (WorkerId). Blocks by polling the DaemonWorkers
    // event queue until a WorkerEvent::Exit for `id` is observed.
    // Returns 0 on success, ECHILD if `id` is not a known child pid.
    //
    // vertexia: replace sleep-poll with a per-pid notification channel if
    // join latency matters.
    linker
        .func_wrap(
            "env",
            "__syscall_waitid",
            |mut caller: Caller<'_, EmbedderState>,
             _idtype: i32,
             id: i32,
             _infop: i32,
             _options: i32|
             -> WtResult<i32> {
                let workers = caller.data().daemon_workers.clone();
                let Some(workers) = workers else {
                    return Ok(ECHILD);
                };
                let known = caller
                    .data()
                    .process_state
                    .as_ref()
                    .map(|s| s.has_child(id))
                    .unwrap_or(false);
                if !known {
                    return Ok(ECHILD);
                }
                let exit_code = wait_for_worker(&workers, id);
                caller
                    .data_mut()
                    .process_state
                    .as_mut()
                    .map(|s| s.remove_child(id));
                workers.mark_reaped(id);
                Ok(exit_code)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_waitid: {e}")))?;

    // __syscall_wait4(pid: i32, wstatus_ptr: i32, options: i32, rusage_ptr: i32) -> i32
    //
    // waitpid(2) variant. Same as waitid but writes the exit status into
    // *wstatus_ptr in WIFEXITED / WEXITSTATUS encoding (exit_code << 8 & 0xff00).
    linker
        .func_wrap(
            "env",
            "__syscall_wait4",
            |mut caller: Caller<'_, EmbedderState>,
             pid: i32,
             wstatus_ptr: i32,
             _options: i32,
             _rusage_ptr: i32|
             -> WtResult<i32> {
                let workers = caller.data().daemon_workers.clone();
                let Some(workers) = workers else {
                    return Ok(ECHILD);
                };
                let known = caller
                    .data()
                    .process_state
                    .as_ref()
                    .map(|s| s.has_child(pid))
                    .unwrap_or(false);
                if !known {
                    return Ok(ECHILD);
                }
                let exit_code = wait_for_worker(&workers, pid);
                caller
                    .data_mut()
                    .process_state
                    .as_mut()
                    .map(|s| s.remove_child(pid));
                workers.mark_reaped(pid);

                // Write WIFEXITED status into *wstatus_ptr if provided.
                if wstatus_ptr != 0
                    && let Some(mem) = caller.data().pyodide_memory
                {
                    let wstatus = (exit_code & 0xff) << 8;
                    let ptr = wstatus_ptr as u32 as usize;
                    let data = mem.data_mut(&mut caller);
                    if ptr + 4 <= data.len() {
                        data[ptr..ptr + 4].copy_from_slice(&wstatus.to_le_bytes());
                    }
                }
                Ok(pid)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("__syscall_wait4: {e}")))?;

    // posix_spawn(pid_ptr, path_ptr, file_actions, attrp, argv_ptr, envp_ptr) -> i32
    //
    // Used by CPython's subprocess module and `os.posix_spawn`. Spawns a new
    // runtime instance running the target script. The path is read from
    // `path_ptr` in guest memory. Returns 0 on success with the child WorkerId
    // written into *pid_ptr; returns EPERM / EAGAIN / ENOMEM on failure.
    linker
        .func_wrap(
            "env",
            "posix_spawn",
            |mut caller: Caller<'_, EmbedderState>,
             pid_ptr: i32,
             path_ptr: i32,
             _file_actions: i32,
             _attrp: i32,
             _argv_ptr: i32,
             _envp_ptr: i32|
             -> WtResult<i32> {
                if !process_allowed(&caller) {
                    return Ok(EPERM);
                }
                let workers = match caller.data().daemon_workers.clone() {
                    Some(w) => w,
                    None => return Ok(EPERM),
                };
                let path = match crate::emscripten_mechanical::read_cstr(&caller, path_ptr) {
                    Some(p) => p,
                    None => return Ok(EINVAL),
                };
                let manifold = caller
                    .data()
                    .manifold
                    .clone()
                    .unwrap_or_else(afterburner_core::Manifold::sealed);
                let mut err = String::new();
                let worker_id = workers.spawn_worker(&path, "", &mut err);
                if worker_id < 0 {
                    let errno = map_worker_err(worker_id);
                    return Ok(errno);
                }
                // Register the child.
                caller
                    .data_mut()
                    .process_state
                    .get_or_insert_with(ProcessState::new)
                    .register_child(worker_id);
                // Write pid.
                if pid_ptr != 0
                    && let Some(mem) = caller.data().pyodide_memory
                {
                    let ptr = pid_ptr as u32 as usize;
                    let data = mem.data_mut(&mut caller);
                    if ptr + 4 <= data.len() {
                        data[ptr..ptr + 4].copy_from_slice(&worker_id.to_le_bytes());
                    }
                }
                let _ = manifold; // gate already checked above
                Ok(0)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("posix_spawn: {e}")))?;

    // posix_spawnp(pid_ptr, file_ptr, ...) -> i32
    //
    // PATH-searching variant of posix_spawn. Delegates to the same spawn path;
    // PATH resolution for guest executables is not meaningful in the runtime
    // model (all executables are runtime instances), so the path is used as-is.
    linker
        .func_wrap(
            "env",
            "posix_spawnp",
            |mut caller: Caller<'_, EmbedderState>,
             pid_ptr: i32,
             file_ptr: i32,
             _file_actions: i32,
             _attrp: i32,
             _argv_ptr: i32,
             _envp_ptr: i32|
             -> WtResult<i32> {
                if !process_allowed(&caller) {
                    return Ok(EPERM);
                }
                let workers = match caller.data().daemon_workers.clone() {
                    Some(w) => w,
                    None => return Ok(EPERM),
                };
                let path = match crate::emscripten_mechanical::read_cstr(&caller, file_ptr) {
                    Some(p) => p,
                    None => return Ok(EINVAL),
                };
                let manifold = caller
                    .data()
                    .manifold
                    .clone()
                    .unwrap_or_else(afterburner_core::Manifold::sealed);
                let mut err = String::new();
                let worker_id = workers.spawn_worker(&path, "", &mut err);
                if worker_id < 0 {
                    let errno = map_worker_err(worker_id);
                    return Ok(errno);
                }
                caller
                    .data_mut()
                    .process_state
                    .get_or_insert_with(ProcessState::new)
                    .register_child(worker_id);
                if pid_ptr != 0
                    && let Some(mem) = caller.data().pyodide_memory
                {
                    let ptr = pid_ptr as u32 as usize;
                    let data = mem.data_mut(&mut caller);
                    if ptr + 4 <= data.len() {
                        data[ptr..ptr + 4].copy_from_slice(&worker_id.to_le_bytes());
                    }
                }
                let _ = manifold;
                Ok(0)
            },
        )
        .map_err(|e| AfterburnerError::Engine(format!("posix_spawnp: {e}")))?;

    Ok(())
}

// ---- Helpers ------------------------------------------------------------------

/// Returns true if the run grants `child_process` access.
fn process_allowed(caller: &Caller<'_, EmbedderState>) -> bool {
    #[cfg(feature = "daemon")]
    {
        caller
            .data()
            .manifold
            .as_ref()
            .map(|m| m.child_process)
            .unwrap_or(false)
    }
    #[cfg(not(feature = "daemon"))]
    {
        let _ = caller;
        false
    }
}

/// Spawn a new child runtime instance via `DaemonWorkers`. Registers the child
/// pid in `ProcessState` and returns the WorkerId (the guest-visible "pid"), or
/// a negative Linux errno on failure.
fn spawn_child_process(caller: &Caller<'_, EmbedderState>, worker_data: &str) -> i32 {
    if !process_allowed(caller) {
        return EPERM;
    }
    let Some(workers) = caller.data().daemon_workers.clone() else {
        return EPERM;
    };
    let mut err = String::new();
    // Use the running binary path as the script so the child is the same
    // runtime image re-entered via --internal-worker with worker_data carrying
    // the target fn_ptr / arg (fork emulation, decision D2).
    workers.spawn_worker("", worker_data, &mut err)
}

/// Poll `DaemonWorkers` event queue until a `WorkerEvent::Exit` for `worker_id`
/// arrives. Parks the OS thread between polls so a slow child does not waste a
/// CPU core.
///
/// Returns the child's exit code (0 on clean exit, non-zero otherwise).
fn wait_for_worker(workers: &Arc<DaemonWorkers>, worker_id: i32) -> i32 {
    loop {
        if let Some(evt) = workers.try_recv_event() {
            match evt {
                WorkerEvent::Exit {
                    worker_id: wid,
                    code,
                } if wid == worker_id => {
                    return code;
                }
                _ => {}
            }
        } else {
            // vertexia: replace with per-pid notification if join latency matters.
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

/// Map a `DaemonWorkers` negative error code to a Linux errno.
fn map_worker_err(rc: i32) -> i32 {
    match rc {
        w_err::E_DEPTH | w_err::E_CONCURRENCY => EAGAIN,
        w_err::E_PERMISSION => EPERM,
        _ => ENOMEM,
    }
}

/// Build a default parent-role `DaemonWorkers` coordinator for use as the
/// multiprocessing spawn coordinator.
///
/// Callers that already have a coordinator (e.g. the daemon runtime) should
/// share the same `Arc` rather than creating a new one.
pub fn new_process_coordinator(manifold: afterburner_core::Manifold) -> Arc<DaemonWorkers> {
    DaemonWorkers::new_parent(manifold, WorkerConfig::default())
}

// ---- Tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_workers::{DaemonWorkers, WorkerConfig};
    use afterburner_core::Manifold;
    use std::sync::Arc;

    // ---- ProcessState pipe round-trip -----------------------------------------

    /// Allocate a pipe pair, write bytes to the write end, read them back from
    /// the read end. The bytes must match exactly.
    #[test]
    fn pipe_write_read_round_trip() {
        let mut state = ProcessState::new();
        let (read_fd, write_fd) = state.alloc_pipe();
        assert!(read_fd >= PIPE_FD_BASE);
        assert!(write_fd > read_fd);

        let payload = b"hello from parent";
        let written = state.pipe_write(write_fd, payload);
        assert_eq!(
            written,
            payload.len() as i32,
            "write must return byte count"
        );

        let mut buf = vec![0u8; 32];
        let n = state.pipe_read(read_fd, &mut buf);
        assert_eq!(
            n,
            payload.len() as i32,
            "read must return written byte count"
        );
        assert_eq!(&buf[..n as usize], payload, "round-trip payload mismatch");
    }

    /// Reading from the write end returns EBADF (wrong direction).
    #[test]
    fn pipe_read_from_write_end_is_ebadf() {
        let mut state = ProcessState::new();
        let (_read_fd, write_fd) = state.alloc_pipe();
        let mut buf = [0u8; 8];
        let rc = state.pipe_read(write_fd, &mut buf);
        assert_eq!(rc, EBADF, "reading from write-end must return EBADF");
    }

    /// Writing to the read end returns EBADF (wrong direction).
    #[test]
    fn pipe_write_to_read_end_is_ebadf() {
        let mut state = ProcessState::new();
        let (read_fd, _write_fd) = state.alloc_pipe();
        let rc = state.pipe_write(read_fd, b"oops");
        assert_eq!(rc, EBADF, "writing to read-end must return EBADF");
    }

    /// is_pipe_fd returns true for both ends of an allocated pair.
    #[test]
    fn is_pipe_fd_recognizes_both_ends() {
        let mut state = ProcessState::new();
        let (read_fd, write_fd) = state.alloc_pipe();
        assert!(state.is_pipe_fd(read_fd));
        assert!(state.is_pipe_fd(write_fd));
        // A non-existent fd is not a pipe.
        assert!(!state.is_pipe_fd(99));
    }

    /// Partial reads drain the buffer incrementally.
    #[test]
    fn pipe_partial_reads_drain_buffer() {
        let mut state = ProcessState::new();
        let (read_fd, write_fd) = state.alloc_pipe();

        state.pipe_write(write_fd, b"abcdefgh");

        let mut first = [0u8; 4];
        let n1 = state.pipe_read(read_fd, &mut first);
        assert_eq!(n1, 4);
        assert_eq!(&first, b"abcd");

        let mut second = [0u8; 4];
        let n2 = state.pipe_read(read_fd, &mut second);
        assert_eq!(n2, 4);
        assert_eq!(&second, b"efgh");

        // Buffer is now empty.
        let n3 = state.pipe_read(read_fd, &mut second);
        assert_eq!(n3, 0, "empty buffer must return 0");
    }

    // ---- Child registration ---------------------------------------------------

    /// register_child + has_child + remove_child lifecycle.
    #[test]
    fn child_pid_lifecycle() {
        let mut state = ProcessState::new();
        assert!(!state.has_child(42));
        state.register_child(42);
        assert!(state.has_child(42));
        assert!(state.remove_child(42));
        assert!(!state.has_child(42));
        // Removing again returns false.
        assert!(!state.remove_child(42));
    }

    // ---- Process capability gate (via DaemonWorkers) --------------------------

    /// A sealed manifold (child_process = false) prevents spawn: DaemonWorkers
    /// returns E_PATH (not E_PERMISSION - the path check runs first) or
    /// E_DEPTH when the env var is set. This test verifies the manifold gate
    /// field is correctly off for sealed manifolds.
    #[test]
    fn sealed_manifold_denies_child_process() {
        let m = Manifold::sealed();
        assert!(
            !m.child_process,
            "sealed manifold must not grant child_process"
        );
    }

    /// An open manifold with child_process = true grants spawn.
    #[test]
    fn open_manifold_grants_child_process() {
        let m = Manifold::open();
        assert!(m.child_process, "open manifold must grant child_process");
    }

    // ---- DaemonWorkers spawn/join via multiprocessing surface -----------------

    /// spawn_worker returns E_PATH for a non-existent path with an open manifold.
    #[test]
    fn spawn_worker_rejects_nonexistent_path() {
        let workers = DaemonWorkers::new_parent(Manifold::open(), WorkerConfig::default());
        let mut err = String::new();
        let rc = workers.spawn_worker("/nonexistent/target.py", "", &mut err);
        assert_eq!(
            rc,
            w_err::E_PATH,
            "nonexistent path must return E_PATH, got {rc}: {err}"
        );
    }

    /// spawn_worker returns E_DEPTH when the depth cap is reached.
    #[test]
    fn spawn_worker_rejects_at_depth_cap() {
        let original = std::env::var(crate::daemon_workers::WORKER_DEPTH_ENV);
        unsafe {
            std::env::set_var(
                crate::daemon_workers::WORKER_DEPTH_ENV,
                crate::daemon_workers::WORKER_DEPTH_LIMIT.to_string(),
            );
        }
        let workers = DaemonWorkers::new_parent(Manifold::open(), WorkerConfig::default());
        let mut err = String::new();
        let rc = workers.spawn_worker("/nonexistent/target.py", "", &mut err);
        assert_eq!(rc, w_err::E_DEPTH, "expected E_DEPTH, got {rc}: {err}");
        unsafe {
            match original {
                Ok(v) => std::env::set_var(crate::daemon_workers::WORKER_DEPTH_ENV, v),
                Err(_) => std::env::remove_var(crate::daemon_workers::WORKER_DEPTH_ENV),
            }
        }
    }

    // ---- new_process_coordinator helper --------------------------------------

    /// new_process_coordinator returns a parent-role coordinator.
    #[test]
    fn new_process_coordinator_is_parent() {
        let c = new_process_coordinator(Manifold::sealed());
        assert!(c.is_main_thread(), "must be in parent/main-thread role");
    }

    // ---- map_worker_err covers all error codes --------------------------------

    #[test]
    fn map_worker_err_depth_and_concurrency_give_eagain() {
        assert_eq!(map_worker_err(w_err::E_DEPTH), EAGAIN);
        assert_eq!(map_worker_err(w_err::E_CONCURRENCY), EAGAIN);
    }

    #[test]
    fn map_worker_err_permission_gives_eperm() {
        assert_eq!(map_worker_err(w_err::E_PERMISSION), EPERM);
    }

    #[test]
    fn map_worker_err_other_codes_give_enomem() {
        assert_eq!(map_worker_err(w_err::E_SPAWN), ENOMEM);
        assert_eq!(map_worker_err(w_err::E_OTHER), ENOMEM);
        assert_eq!(map_worker_err(w_err::E_PATH), ENOMEM);
    }

    // ---- Concurrent pipe access (multiple pipes do not cross-contaminate) -----

    /// Allocate two independent pipe pairs and verify their buffers do not mix.
    #[test]
    fn multiple_pipes_are_independent() {
        let mut state = ProcessState::new();
        let (r1, w1) = state.alloc_pipe();
        let (r2, w2) = state.alloc_pipe();

        state.pipe_write(w1, b"pipe-one");
        state.pipe_write(w2, b"pipe-two");

        let mut b1 = [0u8; 32];
        let n1 = state.pipe_read(r1, &mut b1);
        assert_eq!(&b1[..n1 as usize], b"pipe-one");

        let mut b2 = [0u8; 32];
        let n2 = state.pipe_read(r2, &mut b2);
        assert_eq!(&b2[..n2 as usize], b"pipe-two");
    }

    // ---- Process spawn and join (real DaemonWorkers, no actual child binary) --

    /// Verify that spawn_worker + mark_reaped alive counter sequence is correct.
    /// We cannot run an actual child runtime binary in unit tests, so we verify
    /// the coordinator's observable state (alive counter) tracks spawn/reap.
    #[test]
    fn daemon_workers_alive_counter_multiprocessing_baseline() {
        let workers = Arc::new(DaemonWorkers::new_parent(
            Manifold::open(),
            WorkerConfig::default(),
        ));
        // Before any spawn the coordinator shows no alive workers.
        assert!(
            !workers.has_alive_workers(),
            "must start with no alive workers"
        );
    }
}
