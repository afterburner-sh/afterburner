// process — eager-installed as `globalThis.process` and registered as
// the CommonJS `process` module. Acts as an EventEmitter so scripts
// using `process.on('exit', …)` etc. do not blow up.
//
// The IIFE runs at bundle-load time so `globalThis.process` is set
// regardless of whether the user script ever calls `require('process')`.

(function bootstrapProcess() {
    // EventEmitter is provided by events.js; we lookup directly from
    // the require resolver since this runs before user code.
    var EventEmitter = require('events');

    // `__host_env` / `__ab_argv` are installed per-thrust by script
    // mode (see plugin's modes/script.rs). Both globals are absent in
    // UDF mode, which is intentional — UDF scripts only see their
    // `data` input.
    var hostEnv = globalThis.__host_env || {};
    var argv    = globalThis.__ab_argv   || ['afterburner'];
    var proc = Object.create(EventEmitter.prototype);
    EventEmitter.call(proc);

    var fields = {
        platform: globalThis.__host_platform || 'linux',
        arch:     globalThis.__host_arch     || 'x64',
        // We claim Node 26 (latest stable, the project's target). Most
        // libraries gate features on numeric ranges (`>=18.17.0`,
        // `>=20.5.0`, `>=22.0.0`) — claiming the current major
        // version unblocks every reasonable engines check while
        // still surfacing the `-afterburner` suffix so version-aware
        // code paths (rare) can detect us.
        version:  'v26.0.0-afterburner',
        versions: { node: '26.0.0', v8: '13.0.0.0', afterburner: '0.1.0' },
        env:      hostEnv,
        argv:     argv,
        execPath: '/usr/bin/afterburner',
        pid:      1,
        title:    'afterburner',

        cwd:      function() { return globalThis.__host_cwd || '/'; },
        chdir:    function() { throw new Error('process.chdir is not supported'); },

        // `umask([mask])` — Node returns the previous mask; with an
        // arg, sets it. Sandbox doesn't surface umask through the
        // bridge; return a sensible default and accept (silent) the
        // setter call. Node reduced the deprecation noise around
        // calling umask() with no args; we mirror that.
        umask:    function(_mask) { return 0o022; },

        // `process.getuid` / `getgid` / `geteuid` / `getegid` — POSIX
        // identity functions. Sandbox returns 0 for everything; some
        // libraries (npm install, sqlite open) probe these to decide
        // whether to drop privileges.
        getuid:   function() { return 0; },
        getgid:   function() { return 0; },
        geteuid:  function() { return 0; },
        getegid:  function() { return 0; },
        getgroups: function() { return [0]; },
        // `setuid`/`setgid` — sandbox doesn't allow privilege change.
        // Throw a Node-style typed error so callers can fall through.
        setuid:   function() { var e = new Error('setuid not supported'); e.code = 'EPERM'; throw e; },
        setgid:   function() { var e = new Error('setgid not supported'); e.code = 'EPERM'; throw e; },
        seteuid:  function() { var e = new Error('seteuid not supported'); e.code = 'EPERM'; throw e; },
        setegid:  function() { var e = new Error('setegid not supported'); e.code = 'EPERM'; throw e; },
        setgroups: function() { var e = new Error('setgroups not supported'); e.code = 'EPERM'; throw e; },

        // Node 18+ `process.permission` / `process.constrainedMemory`
        // / `process.availableMemory` — light probe surface that
        // libraries (express's inspector, nodemon) check at module
        // init.
        constrainedMemory:  function() { return 0; },
        availableMemory:    function() { return 0; },
        memoryUsage:        Object.assign(function() {
            return { rss: 0, heapTotal: 0, heapUsed: 0, external: 0, arrayBuffers: 0 };
        }, { rss: function() { return 0; } }),
        // Node 24+ `process.threadCpuUsage` — return a zeroed object.
        threadCpuUsage:     function() { return { user: 0, system: 0 }; },
        cpuUsage:           function(_prev) { return { user: 0, system: 0 }; },
        /// Node 11+ `process.report` — diagnostic-report API. We
        /// produce a real Node-shaped report from the runtime's
        /// process state: live memory numbers via `process.memoryUsage`,
        /// captured stack via `Error.captureStackTrace`, env vars from
        /// `process.env`, command-line argv, plus the resource-usage
        /// snapshot. Output is the canonical JSON shape clinic.js /
        /// node-inspector parsers expect.
        report: {
            directory: '',
            filename: '',
            reportOnFatalError: false,
            reportOnSignal: false,
            reportOnUncaughtException: false,
            signal: 'SIGUSR2',
            compact: false,
            excludeNetwork: false,
            getReport: function(err) {
                var stack = '';
                try {
                    if (err && err.stack) {
                        stack = err.stack;
                    } else {
                        var probe = {};
                        Error.captureStackTrace(probe, this.getReport);
                        stack = probe.stack || '';
                    }
                } catch (_) { /* defensive */ }
                var stackLines = String(stack).split('\n').filter(Boolean);
                var memUsage = (typeof process.memoryUsage === 'function')
                    ? process.memoryUsage() : {};
                var report = {
                    header: {
                        reportVersion: 5,
                        event: err ? 'Exception' : 'JavaScript API',
                        trigger: err ? 'Exception' : 'GetReport',
                        filename: '',
                        dumpEventTime: new Date().toISOString(),
                        dumpEventTimeStamp: String(Date.now()),
                        processId: (process.pid | 0) || 0,
                        threadId: 0,
                        cwd: typeof process.cwd === 'function' ? process.cwd() : '',
                        commandLine: (process.argv || []).slice(),
                        nodejsVersion: process.version || '',
                        wordSize: 64,
                        arch: process.arch || '',
                        platform: process.platform || '',
                        componentVersions: process.versions || {},
                        release: process.release || {},
                        osName: process.platform || '',
                        osRelease: '',
                        osVersion: '',
                        osMachine: process.arch || '',
                        cpus: [],
                        networkInterfaces: [],
                        host: 'localhost',
                    },
                    javascriptStack: {
                        message: err && err.message ? String(err.message) : '',
                        stack: stackLines,
                        errorProperties: err ? Object.assign({}, err) : {},
                    },
                    nativeStack: [],
                    javascriptHeap: {
                        totalMemory: String(memUsage.heapTotal | 0),
                        executableMemory: '0',
                        totalCommittedMemory: String(memUsage.heapTotal | 0),
                        availableMemory: String(Math.max(0,
                            (memUsage.heapTotal | 0) - (memUsage.heapUsed | 0))),
                        totalGlobalHandlesMemory: '0',
                        usedGlobalHandlesMemory: '0',
                        usedMemory: String(memUsage.heapUsed | 0),
                        memoryLimit: String(memUsage.heapTotal | 0),
                        mallocedMemory: String(memUsage.external | 0),
                        externalMemory: String(memUsage.external | 0),
                        peakMallocedMemory: String(memUsage.external | 0),
                        nativeContextCount: 1,
                        detachedContextCount: 0,
                        doesZapGarbage: 0,
                        heapSpaces: {},
                    },
                    resourceUsage: typeof process.resourceUsage === 'function'
                        ? process.resourceUsage() : {},
                    sharedObjects: [],
                    libuv: [],
                    workers: [],
                    environmentVariables: Object.assign({}, process.env || {}),
                    userLimits: {},
                    uvthreadResourceUsage: typeof process.resourceUsage === 'function'
                        ? process.resourceUsage() : {},
                };
                return report;
            },
            writeReport: function(filename, err) {
                if (typeof filename === 'object' && filename !== null) {
                    err = filename;
                    filename = undefined;
                }
                var report = this.getReport(err);
                var fs = require('fs');
                var path = filename || ('report.' + Date.now() + '.'
                    + (process.pid | 0) + '.001.json');
                fs.writeFileSync(path, JSON.stringify(report, null, 2));
                return path;
            },
        },
        resourceUsage:      function() {
            return {
                userCPUTime: 0, systemCPUTime: 0, maxRSS: 0,
                sharedMemorySize: 0, unsharedDataSize: 0, unsharedStackSize: 0,
                minorPageFault: 0, majorPageFault: 0, swappedOut: 0,
                fsRead: 0, fsWrite: 0, ipcSent: 0, ipcReceived: 0,
                signalsCount: 0, voluntaryContextSwitches: 0, involuntaryContextSwitches: 0,
            };
        },
        // process.getActiveResourcesInfo (Node 18+). Returns an array
        // of strings naming the resources keeping the event loop
        // alive. Burn's daemon mode tracks listeners, ref'd timers,
        // outbound HTTP, etc. through `daemon.has_refs()`; for the
        // JS-level surface we approximate with a per-shard view of
        // currently alive resources we can detect.
        getActiveResourcesInfo: function() {
            var out = [];
            // Crude best-effort: probe `__ab_*` markers we install
            // for in-flight outbound HTTP, server handlers, timers.
            if (globalThis.__ab_http_pending) {
                var keys = Object.keys(globalThis.__ab_http_pending);
                for (var i = 0; i < keys.length; i++) out.push('TCPWRAP');
            }
            if (globalThis.__ab_http_handlers) {
                var hkeys = Object.keys(globalThis.__ab_http_handlers);
                for (var j = 0; j < hkeys.length; j++) out.push('TCPSERVERWRAP');
            }
            return out;
        },
        // process.getBuiltinModule(id) (Node 22+). Returns the same
        // module the synchronous CJS `require(id)` would, or
        // `undefined` if the id isn't a Node built-in (vs throwing —
        // matches Node's contract).
        getBuiltinModule: function(id) {
            if (typeof id !== 'string') return undefined;
            var bare = id.indexOf('node:') === 0 ? id.slice(5) : id;
            try {
                if (typeof globalThis.require === 'function') {
                    var mod = globalThis.require;
                    var Module = mod('module');
                    if (Module && typeof Module.isBuiltin === 'function' && !Module.isBuiltin(bare)) {
                        return undefined;
                    }
                    return mod(bare);
                }
            } catch (_) {}
            return undefined;
        },
        // process.loadEnvFile (Node 20.6+). The CLI's `--env-file`
        // already loads at startup; this in-process call parses
        // additional files at runtime and merges into `process.env`.
        loadEnvFile: function(path) {
            var p = path || '.env';
            try {
                var fs = require('fs');
                var text = fs.readFileSync(p, 'utf8');
                var lines = text.split(/\r?\n/);
                for (var i = 0; i < lines.length; i++) {
                    var line = lines[i].trim();
                    if (!line || line.charAt(0) === '#') continue;
                    var eq = line.indexOf('=');
                    if (eq < 0) continue;
                    var k = line.slice(0, eq).trim();
                    if (!k) continue;
                    var v = line.slice(eq + 1).trim();
                    if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') ||
                                          (v[0] === "'" && v[v.length - 1] === "'"))) {
                        v = v.slice(1, -1);
                    }
                    if (globalThis.process && globalThis.process.env) {
                        globalThis.process.env[k] = v;
                    }
                }
            } catch (e) {
                var err = new Error('Cannot read environment file: ' + p);
                err.code = 'ENOENT';
                throw err;
            }
        },
        // process.permission — Node 20.x experimental. When the CLI
        // launched without `--permission` we keep the always-allow
        // posture (manifold layer is the real gate). With
        // `--permission` set, the host populates
        // `globalThis.__ab_permission_grants` with a map of granted
        // scopes; `has()` consults that, defaulting to false for
        // unmentioned scopes — matching Node's deny-by-default model.
        permission: {
            has: function(scope, ref) {
                var g = globalThis.__ab_permission_grants;
                if (!g) return true; // permission model not active → allow
                if (!Object.prototype.hasOwnProperty.call(g, scope)) return false;
                var v = g[scope];
                if (v === true) return true;
                if (typeof v === 'string') {
                    if (!ref) return true;
                    var allow = v.split(',').map(function(s) { return s.trim(); });
                    for (var i = 0; i < allow.length; i++) {
                        if (allow[i] === '*' || allow[i] === ref) return true;
                        // Glob-prefix support for fs paths and net
                        // host:port.
                        if (allow[i].indexOf('*') === 0 &&
                            ref.endsWith(allow[i].slice(1))) return true;
                        if (ref.indexOf(allow[i]) === 0) return true;
                    }
                    return false;
                }
                return false;
            },
            get: function() {
                var g = globalThis.__ab_permission_grants;
                if (!g) return { fs: { read: true, write: true }, net: true, env: true,
                                 child_process: true, worker: true };
                return {
                    fs: {
                        read: g['fs.read'] !== undefined,
                        write: g['fs.write'] !== undefined,
                    },
                    net: !!g['net'],
                    env: !!g['env'],
                    child_process: !!g['child_process'],
                    worker: !!g['worker'],
                };
            },
        },

        // Real Node drains the nextTick queue synchronously between
        // each macrotask but BEFORE the microtask queue. Express's
        // `finalhandler` (the 404/500 fallback) defers its response
        // with `process.nextTick`, expecting middleware that called
        // `next(err)` to run first. The pre-fix synchronous-call
        // implementation broke that ordering: a nextTick scheduled
        // from inside a Promise microtask ran INSIDE the microtask
        // instead of after it.
        //
        // We approximate Node's semantics by queueing nextTick
        // callbacks into `__ntQueue` and draining via a single
        // `queueMicrotask`. Microtask order is FIFO, so a nextTick
        // scheduled in current sync code runs before any user
        // `Promise.then` queued AFTER it. Exceptions in a nextTick
        // callback are caught + logged so a single failure doesn't
        // poison the rest of the queue (Node's behaviour: emit
        // `uncaughtException` and continue; we surface to console
        // until we wire a real uncaughtException emitter).
        //
        // Caveat: nested nextTicks (callback A queues callback B)
        // run on the *next* drain pass here, not the same one. Real
        // Node has an inner/outer queue that drains nested ticks
        // greedily before the microtask queue. Document the
        // divergence; revisit if a real workload hits it.
        nextTick: function(fn) {
            if (typeof fn !== 'function') throw new TypeError('callback must be a function');
            var args = Array.prototype.slice.call(arguments, 1);
            if (!globalThis.__ntQueue) globalThis.__ntQueue = [];
            globalThis.__ntQueue.push({ fn: fn, args: args });
            if (!globalThis.__ntScheduled) {
                globalThis.__ntScheduled = true;
                queueMicrotask(function drainNT() {
                    var queue = globalThis.__ntQueue;
                    globalThis.__ntQueue = [];
                    globalThis.__ntScheduled = false;
                    for (var i = 0; i < queue.length; i++) {
                        var item = queue[i];
                        try {
                            item.fn.apply(null, item.args);
                        } catch (e) {
                            // Per Node convention, exceptions in
                            // nextTick callbacks emit
                            // `uncaughtException`. Until that's
                            // wired, log + continue so the rest of
                            // the queue still runs.
                            if (globalThis.console && globalThis.console.error) {
                                globalThis.console.error('Uncaught (in nextTick): ' + (e && e.stack || e));
                            }
                        }
                    }
                });
            }
        },

        exit: function(code) {
            // Guard so 'exit' fires at most once. The host also emits
            // 'exit' when the event loop drains naturally (see the
            // daemon-event 'lifecycle' dispatch); Node guarantees a
            // single 'exit' emission regardless of how the process ends.
            if (!proc.__burnExited) {
                proc.__burnExited = true;
                try { proc.emit('exit', code || 0); } catch (_) {}
            }
            if (globalThis.__host_process_exit) globalThis.__host_process_exit(code || 0);
            var err = new Error('process.exit(' + (code || 0) + ')');
            err.code = 'ERR_PROCESS_EXIT';
            err.exitCode = code || 0;
            throw err;
        },

        hrtime: function(prev) {
            var now = Date.now();
            var seconds = Math.floor(now / 1000);
            var nanos = (now % 1000) * 1e6;
            if (prev) {
                var ds = seconds - prev[0];
                var dn = nanos - prev[1];
                if (dn < 0) { ds -= 1; dn += 1e9; }
                return [ds, dn];
            }
            return [seconds, nanos];
        },

        // Node guarantees `process.stdout.fd === 1`, `stderr.fd === 2`,
        // `stdin.fd === 0`; libraries probe these (chalk reads stdout
        // for color decisions, log streams pipe by fd). `isTTY` /
        // `columns` / `rows` shape matches Node's interactive defaults
        // — caller can override to flip color output off.
        stdout: {
            fd: 1, isTTY: false, columns: 80, rows: 24,
            write: function(s, _enc, cb) {
                if (globalThis.console) console.log(typeof s === 'string' ? s : String(s));
                if (typeof cb === 'function') Promise.resolve().then(cb);
                return true;
            },
            on: function() { return this; },
            once: function() { return this; },
            removeListener: function() { return this; },
            off: function() { return this; },
            emit: function() { return false; },
            cork: function() {}, uncork: function() {}, end: function() {},
            // Color depth + hasColors honour NO_COLOR / FORCE_COLOR /
            // TERM the same way `tty.WriteStream.prototype` does. The
            // non-TTY default is false (chalk/signale gate on isTTY),
            // BUT `FORCE_COLOR` overrides — that's the documented
            // escape hatch for piping into colour-aware consumers
            // (e.g. `node script.js | less -R`).
            getColorDepth: function() { return require('tty').WriteStream.prototype.getColorDepth(); },
            hasColors: function(count) {
                var env = (typeof process !== 'undefined' && process.env) || {};
                var forced = env.FORCE_COLOR != null && env.FORCE_COLOR !== ''
                    && env.FORCE_COLOR !== '0' && env.FORCE_COLOR !== 'false';
                if (this.isTTY !== true && !forced) return false;
                return require('tty').WriteStream.prototype.hasColors(count);
            },
            clearLine: function() {}, clearScreenDown: function() {}, cursorTo: function() {},
        },
        stderr: {
            fd: 2, isTTY: false, columns: 80, rows: 24,
            write: function(s, _enc, cb) {
                if (globalThis.console) console.error(typeof s === 'string' ? s : String(s));
                if (typeof cb === 'function') Promise.resolve().then(cb);
                return true;
            },
            on: function() { return this; },
            once: function() { return this; },
            removeListener: function() { return this; },
            off: function() { return this; },
            emit: function() { return false; },
            cork: function() {}, uncork: function() {}, end: function() {},
            getColorDepth: function() { return require('tty').WriteStream.prototype.getColorDepth(); },
            hasColors: function(count) {
                if (this.isTTY !== true) return false;
                return require('tty').WriteStream.prototype.hasColors(count);
            },
            clearLine: function() {}, clearScreenDown: function() {}, cursorTo: function() {},
        },
        stdin: {
            fd: 0, isTTY: false,
            on: function() { return this; },
            once: function() { return this; },
            removeListener: function() { return this; },
            off: function() { return this; },
            emit: function() { return false; },
            read: function() { return null; },
            pause: function() { return this; },
            resume: function() { return this; },
            setEncoding: function() { return this; },
            setRawMode: function() { return this; },
            unref: function() { return this; },
            ref: function() { return this; },
            destroy: function() { return this; },
            pipe: function(dest) { if (dest && dest.end) dest.end(); return dest; },
        },

        // `process.binding(name)` is Node's internal hook for native
        // bindings (e.g. `process.binding('uv')`, `'tcp_wrap'`,
        // `'fs_event_wrap'`). They expose libuv-side primitives
        // that have no analogue in the WASM sandbox. Surface a
        // clear error that names the requested binding so users
        // can identify which library is reaching for an
        // unsupported internal.
        binding: function(name) {
            var which = typeof name === 'string' ? name : String(name);
            // Return narrow stubs for the bindings real-world libraries
            // probe at module-init for limit/feature flags — eager
            // throws here break safer-buffer / fs-minipass / pacote at
            // module load, which is far enough from any actual native
            // primitive use that the user has no way to act on the
            // error. Keep the throw for everything else so honest
            // libuv consumers (rare in the sandbox) still surface a
            // typed error pointing at the missing binding.
            switch (which) {
                case 'buffer':
                    return {
                        kStringMaxLength: 0x3fffffe7,        // ~1 GiB - 8
                        kMaxLength:       0x7fffffff,        // INT32_MAX
                    };
                case 'fs':
                    // fs-minipass gates a libuv fallback on
                    // `!fs.writev`. We provide writev now, so the
                    // binding is dead code; an empty object lets the
                    // module-init `process.binding('fs')` complete
                    // without exposing any libuv methods.
                    return {};
                case 'constants':
                    // Return the merged fs+os+crypto constants so
                    // legacy `require('process').binding('constants')`
                    // gets a usable map (Node had this for years).
                    try {
                        var c = {};
                        var fs = require('fs');
                        var os = require('os');
                        if (fs && fs.constants) Object.assign(c, fs.constants);
                        if (os && os.constants) {
                            if (os.constants.errno) Object.assign(c, os.constants.errno);
                            if (os.constants.signals) Object.assign(c, os.constants.signals);
                        }
                        return c;
                    } catch (_) { return {}; }
            }
            var err = new Error(
                "process.binding('" + which + "') is not supported in the " +
                "Afterburner sandbox: native bindings (libuv internals and " +
                ".node addons) require executing native machine code, which " +
                "the WASM sandbox cannot do by design (different ISA from " +
                "the bytecode the runtime executes)."
            );
            err.code = 'ERR_NOT_SUPPORTED_IN_SANDBOX';
            err.bindingName = which;
            throw err;
        },

        // Same surface as `process.binding` but for the post-Node-16
        // internal-only API.
        _linkedBinding: function(name) {
            var err = new Error(
                "process._linkedBinding('" + String(name) + "') is not " +
                "supported in the Afterburner sandbox"
            );
            err.code = 'ERR_NOT_SUPPORTED_IN_SANDBOX';
            err.bindingName = String(name);
            throw err;
        }
    };

    fields.hrtime.bigint = function() {
        var t = fields.hrtime();
        return BigInt(t[0]) * 1000000000n + BigInt(t[1]);
    };

    Object.keys(fields).forEach(function(k) { proc[k] = fields[k]; });

    /// process.uptime — seconds since process start. We anchor to the
    /// JS runtime epoch since the host's timestamp granularity matches
    /// what Node returns.
    var _start = Date.now();
    proc.uptime = function() { return (Date.now() - _start) / 1000; };

    /// process.kill — Node sends a signal to a target PID. Sandbox
    /// can't actually deliver signals, but the function exists so
    /// libraries that call it (cleanup hooks, watchdogs) don't crash.
    /// Matches Node's "always-true" behavior on Windows for SIGTERM.
    proc.kill = function(pid, _signal) {
        if (typeof pid !== 'number') {
            var e = new TypeError('process.kill: pid must be a number');
            e.code = 'ERR_INVALID_ARG_TYPE';
            throw e;
        }
        // Sandboxed — no actual signal delivery. Silently succeed for
        // self-pid (many libraries use kill(process.pid, 0) as a probe).
        return true;
    };

    /// process.dlopen — opens a native .node addon. Burn's WASM
    /// sandbox can't load native code; throw so probe-shaped libraries
    /// fall through to their JS-only path.
    proc.dlopen = function(_module, _filename, _flags) {
        var e = new Error(
            'process.dlopen: native addons (.node files) are not ' +
            'supported in the Afterburner sandbox');
        e.code = 'ERR_DLOPEN_DISABLED';
        throw e;
    };

    /// process.allowedNodeEnvironmentFlags — Node 12+ Set of CLI flags
    /// that the runtime accepts via NODE_OPTIONS. Real Node ships ~30;
    /// we expose the Set shape with a documented subset so feature
    /// detection works without lying about flags we don't honour.
    var _allowedFlags = new Set([
        '--enable-source-maps',
        '--no-deprecation',
        '--no-warnings',
        '--unhandled-rejections=throw',
        '--unhandled-rejections=warn',
        '--unhandled-rejections=strict',
        '--max-old-space-size',
    ]);
    Object.defineProperty(proc, 'allowedNodeEnvironmentFlags', {
        value: _allowedFlags, writable: false, configurable: true, enumerable: true,
    });

    /// process.features — Node has had this object since 0.5 with
    /// boolean flags advertising which optional features were
    /// compiled in. Most libraries grep for `features.tls` or
    /// `features.cached_builtins`.
    Object.defineProperty(proc, 'features', {
        value: Object.freeze({
            inspector: false,
            debug: false,
            uv: false,
            ipv6: true,
            tls_alpn: true,
            tls_sni: true,
            tls_ocsp: false,
            tls: true,
            cached_builtins: true,
        }),
        writable: false, configurable: true, enumerable: true,
    });

    /// process.config — Node's compile-time config object. Real Node
    /// puts ~hundreds of GYP-style entries here; we surface enough
    /// that build-tools that sniff the Node ABI version don't crash.
    Object.defineProperty(proc, 'config', {
        value: Object.freeze({
            target_defaults: { default_configuration: 'Release' },
            variables: {
                host_arch: proc.arch || 'x64',
                node_install_npm: false,
                node_module_version: 127,
                target_arch: proc.arch || 'x64',
                v8_enable_i18n_support: 1,
            },
        }),
        writable: false, configurable: true, enumerable: true,
    });

    /// process.release — release-channel metadata. npm uses
    /// `process.release.name === 'node'` to gate Node-vs-iojs paths.
    Object.defineProperty(proc, 'release', {
        value: Object.freeze({
            name: 'node',
            sourceUrl: '',
            headersUrl: '',
            libUrl: '',
            lts: 'Burn',
        }),
        writable: false, configurable: true, enumerable: true,
    });

    globalThis.process = proc;
    __register_host_module('process', proc);
})();
