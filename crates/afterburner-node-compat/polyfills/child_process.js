// child_process — sync subset (execSync / spawnSync), backed by
// `__host_child_process_exec_sync` on both the native (rquickjs) path
// and the WASM-sandbox path. Argv crosses the host import boundary as
// a JSON-encoded array string so the wire shape stays primitive
// (host_imports work in (ptr, len) pairs, no array marshalling).
//
// Sync methods only: burn does not drive async child_process events.

__register_module('child_process', function(module, exports, require) {

    function ensureHost() {
        var fn = globalThis.__host_child_process_exec_sync;
        if (typeof fn !== 'function') {
            var err = new Error("Permission denied: child_process is not available in this sandbox");
            err.code = 'EACCES';
            throw err;
        }
        return fn;
    }

    function parseResult(raw) {
        if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
            var err = new Error("child_process: " + raw.slice('__HOST_ERR__:'.length));
            err.code = 'EACCES';
            throw err;
        }
        return JSON.parse(raw);
    }

    function callHost(cmd, argv) {
        // Always serialize argv as JSON for both native and wasm paths
        // — the wasm host import only accepts scalar args, and keeping
        // the wire identical means a single `parseResult` works for
        // both backends.
        var argvJson = JSON.stringify((argv || []).map(String));
        return ensureHost()(String(cmd), argvJson);
    }

    exports.execSync = function(command, options) {
        // Node's `execSync` takes a whole command string; we split on
        // whitespace for the simple shim.
        var parts = String(command).split(/\s+/).filter(Boolean);
        if (parts.length === 0) throw new Error("child_process.execSync: empty command");
        var argv = parts.slice(1);
        var raw = callHost(parts[0], argv);
        var result = parseResult(raw);
        if (result.status !== 0) {
            var err = new Error("Command failed: " + command + "\n" + result.stderr);
            err.status = result.status;
            err.stdout = result.stdout;
            err.stderr = result.stderr;
            throw err;
        }
        return result.stdout;
    };

    exports.spawnSync = function(command, args, options) {
        args = args || [];
        var raw = callHost(command, args);
        return parseResult(raw);
    };

    /// `child_process.execFileSync(file, args, options)` — Node's
    /// quoting-safe twin of execSync. Doesn't run a shell, takes the
    /// argv vector directly. We delegate to the same host fn as
    /// spawnSync. Throws on non-zero exit per Node semantics.
    exports.execFileSync = function(file, args, options) {
        args = args || [];
        var raw = callHost(String(file), args);
        var result = parseResult(raw);
        if (result.status !== 0) {
            var err = new Error("Command failed: " + file + " " + args.join(' ') +
                "\n" + result.stderr);
            err.status = result.status;
            err.stdout = result.stdout;
            err.stderr = result.stderr;
            err.pid = result.pid;
            throw err;
        }
        // execFileSync returns the stdout buffer (or string if encoding set).
        var enc = options && options.encoding;
        if (enc && enc !== 'buffer') {
            return String(result.stdout);
        }
        var Buffer = require('buffer').Buffer;
        return Buffer.from(String(result.stdout || ''), 'utf8');
    };

    // ---- Async-style child_process wrappers ------------------------
    //
    // The host backend is synchronous; the async wrappers run the
    // child inline and dispatch events / callbacks on a microtask so
    // the canonical Node patterns (`.on('exit', …)`, `exec(cmd, cb)`)
    // work as expected. Real concurrent subprocess execution would
    // need a nuclei-backed coordinator like the outbound HTTP path.
    var EventEmitter = require('events');

    function _bufferOf(text) {
        var Buffer = require('buffer').Buffer;
        return Buffer.from(String(text || ''), 'utf8');
    }

    function _makeStream(text) {
        var s = Object.create(EventEmitter.prototype);
        EventEmitter.call(s);
        s.readable = true;
        s.setEncoding = function(enc) { s._enc = enc; return s; };
        s.pipe = function(dest) {
            Promise.resolve().then(function() {
                var chunk = _bufferOf(text);
                if (s._enc === 'utf8' || s._enc === 'utf-8') chunk = chunk.toString('utf8');
                if (dest && typeof dest.write === 'function') dest.write(chunk);
                if (dest && typeof dest.end === 'function') dest.end();
            });
            return dest;
        };
        Promise.resolve().then(function() {
            if (text != null && text.length) {
                var chunk = _bufferOf(text);
                if (s._enc === 'utf8' || s._enc === 'utf-8') chunk = chunk.toString('utf8');
                s.emit('data', chunk);
            }
            s.emit('end');
            s.emit('close');
        });
        return s;
    }

    function _makeChildProcess(result, cmd, args) {
        var ee = Object.create(EventEmitter.prototype);
        EventEmitter.call(ee);
        ee.pid = (result && result.pid) || 0;
        ee.exitCode = (result && result.status) !== undefined ? result.status : 0;
        ee.signalCode = null;
        ee.killed = false;
        ee.spawnfile = String(cmd);
        ee.spawnargs = [String(cmd)].concat((args || []).map(String));
        ee.stdout = _makeStream(result && result.stdout);
        ee.stderr = _makeStream(result && result.stderr);
        var stdin = Object.create(EventEmitter.prototype);
        EventEmitter.call(stdin);
        stdin.write = function() { return true; };
        stdin.end = function() {};
        stdin.writable = true;
        ee.stdin = stdin;
        ee.kill = function(_signal) { ee.killed = true; return true; };
        ee.send = function() { return false; };
        ee.disconnect = function() {};
        ee.ref = function() {};
        ee.unref = function() {};
        Promise.resolve().then(function() {
            ee.emit('spawn');
            ee.emit('exit', ee.exitCode, ee.signalCode);
            ee.emit('close', ee.exitCode, ee.signalCode);
        });
        return ee;
    }

    exports.spawn = function spawn(command, args, options) {
        if (Array.isArray(args)) {
            // good
        } else if (args && typeof args === 'object') {
            options = args; args = [];
        } else {
            args = args || [];
        }
        var result;
        try {
            var raw = callHost(command, args);
            result = parseResult(raw);
        } catch (e) {
            // Surface error via the canonical async error event.
            var ee = _makeChildProcess({ status: 1 }, command, args);
            Promise.resolve().then(function() { ee.emit('error', e); });
            return ee;
        }
        return _makeChildProcess(result, command, args);
    };

    exports.execFile = function execFile(file, args, options, cb) {
        if (typeof args === 'function') { cb = args; args = []; options = undefined; }
        if (typeof options === 'function') { cb = options; options = undefined; }
        args = args || [];
        var child;
        try {
            var raw = callHost(file, args);
            var result = parseResult(raw);
            child = _makeChildProcess(result, file, args);
            if (typeof cb === 'function') {
                Promise.resolve().then(function() {
                    var enc = (options && options.encoding) || 'utf8';
                    var stdout = enc === 'buffer' ? _bufferOf(result.stdout) : String(result.stdout || '');
                    var stderr = enc === 'buffer' ? _bufferOf(result.stderr) : String(result.stderr || '');
                    if (result.status !== 0) {
                        var err = new Error('Command failed: ' + file);
                        err.code = result.status;
                        err.stdout = stdout;
                        err.stderr = stderr;
                        cb(err, stdout, stderr);
                    } else {
                        cb(null, stdout, stderr);
                    }
                });
            }
        } catch (e) {
            if (typeof cb === 'function') {
                Promise.resolve().then(function() { cb(e, '', ''); });
            }
            child = _makeChildProcess({ status: 1 }, file, args);
        }
        return child;
    };

    exports.exec = function exec(command, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        var parts = String(command).split(/\s+/).filter(Boolean);
        if (parts.length === 0) {
            if (cb) Promise.resolve().then(function() { cb(new Error('empty command'), '', ''); });
            return _makeChildProcess({ status: 1 }, command, []);
        }
        return exports.execFile(parts[0], parts.slice(1), options, cb);
    };

    /// fork(modulePath, args, opts) — run another module under burn.
    /// The IPC channel that real Node provides isn't implemented:
    /// the spawned child runs without parent ↔ child message passing.
    /// Use `worker_threads` for in-process IPC instead.
    exports.fork = function fork(modulePath, args, _options) {
        args = args || [];
        var burn = (typeof process !== 'undefined' && process.argv && process.argv[0]) || 'burn';
        var argv = [String(modulePath)].concat((args || []).map(String));
        var raw, result;
        try {
            raw = callHost(burn, argv);
            result = parseResult(raw);
        } catch (e) {
            result = { status: 1, stdout: '', stderr: String((e && e.message) || e) };
        }
        return _makeChildProcess(result, burn, argv);
    };

    // ChildProcess class — surface-only, real instances come back
    // from spawn() / fork() / exec(). Some libraries probe
    // `cp.ChildProcess` at module init.
    exports.ChildProcess = function ChildProcess() {
        EventEmitter.call(this);
    };
    exports.ChildProcess.prototype = Object.create(EventEmitter.prototype);
    exports.ChildProcess.prototype.constructor = exports.ChildProcess;
});
