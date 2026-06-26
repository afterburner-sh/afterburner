// net — raw TCP + AF_UNIX polyfill (B7).
//
// `Socket` is the JS-side facade for a host-owned `tokio::TcpStream`
// or `tokio::net::UnixStream`. Operations cross into Rust via
// `__host_net_*` imports (TCP) or `__host_unix_*` imports (AF_UNIX);
// inbound bytes / lifecycle events arrive via the daemon-event
// dispatcher as `{kind:"net-..."}` or `{kind:"unix-..."}` envelopes.
// The dispatcher routes them through `__ab_net_handlers[conn_id]`,
// `__ab_net_server_handlers[server_id]`, `__ab_unix_handlers[conn_id]`,
// or `__ab_unix_server_handlers[server_id]`.
//
// API coverage (minimum-viable for real DB drivers):
//
//   net.connect / net.createConnection
//     ({port, host}[, listener])       -- TCP
//     (port[, host][, listener])       -- TCP
//     ({path}[, listener])             -- Unix-domain
//   socket.{write, end, destroy, setNoDelay, setKeepAlive, setTimeout,
//           address, remoteAddress, remotePort, localAddress, localPort,
//           bytesRead, bytesWritten, destroyed, connecting, readable,
//           writable, pause, resume, on('data'|'end'|'close'|'error'|
//           'connect'|'drain'|'timeout')}
//   net.createServer([options][, connectionListener])
//   server.{listen, close, address, getConnections,
//            on('listening'|'connection'|'close'|'error')}
//   net.{isIP, isIPv4, isIPv6}
//
// Unix-domain sockets: supported via AF_UNIX over __host_unix_* imports.
//
// Deferred (will throw a clear error if used):
//   - net.BlockList
//   - socket.setEncoding (callers should decode bytes themselves)
//   - allowHalfOpen option on Server (always allowed by default)

(function bootstrapNetGlobals() {
    if (!globalThis.__ab_net_handlers) globalThis.__ab_net_handlers = {};
    if (!globalThis.__ab_net_server_handlers) globalThis.__ab_net_server_handlers = {};
    if (!globalThis.__ab_unix_handlers) globalThis.__ab_unix_handlers = {};
    if (!globalThis.__ab_unix_server_handlers) globalThis.__ab_unix_server_handlers = {};
})();

__register_module('net', function(module, exports, require) {
    var EventEmitter = require('events').EventEmitter;
    var Buffer = require('buffer').Buffer;

    // ----- error mapping --------------------------------------------

    function mapHostErrorCode(rc) {
        switch (rc) {
            case -1: return 'ENO_DAEMON';
            case -2: return 'EACCES';
            case -3: return 'ENOTFOUND';
            case -4: return 'EINVAL';
            case -5: return 'EINVAL';
            case -6: return 'EINVAL';
            default: return 'EOTHER';
        }
    }

    function makeError(rc, prefix) {
        var detail = '';
        if (typeof globalThis.__host_last_error === 'function') {
            detail = globalThis.__host_last_error();
        }
        var code = mapHostErrorCode(rc);
        var e = new Error(prefix + ': ' + (detail || ('rc=' + rc)));
        e.code = code;
        return e;
    }

    // ----- Socket ----------------------------------------------------

    function Socket(opts) {
        if (!(this instanceof Socket)) return new Socket(opts);
        EventEmitter.call(this);
        opts = opts || {};

        // Internal state
        this._connId = 0;            // 0 until TCP connect / accept binds it
        this._unixConnId = 0;        // 0 unless this is a Unix-domain socket
        this._connecting = false;
        this._destroyed = false;
        // Separate from `_destroyed` so the host's terminal Close event
        // can still emit `'close'` after a user-initiated destroy(). The
        // destroy path flips `_destroyed` synchronously to make
        // `socket.destroyed === true` observable from inside the
        // 'close' listener (Node-compat).
        this._closeEmitted = false;
        this._readable = true;
        this._writable = true;
        this._encoding = null;       // null = emit Buffer; set via setEncoding
        this._wantsDrain = false;    // true after write() returned false
        this._pendingHWM = 64 * 1024;
        this.bytesRead = 0;
        this.bytesWritten = 0;
        this.remoteAddress = undefined;
        this.remotePort = undefined;
        this.remoteFamily = undefined;
        this.localAddress = undefined;
        this.localPort = undefined;

        this._timeoutMs = 0;
        this._timeoutHandle = null;

        // Ready-state mirrors Node's. Set as connect/end/close fire.
        this.readyState = 'opening';
    }
    Socket.prototype = Object.create(EventEmitter.prototype);
    Socket.prototype.constructor = Socket;

    // Internal: bind a host-allocated conn_id to this socket and
    // register so daemon-event dispatch can find us.
    Socket.prototype._attach = function(connId) {
        if (this._connId) {
            // Should never happen unless a caller reuses a Socket.
            throw new Error('net.Socket already attached to conn ' + this._connId);
        }
        this._connId = connId | 0;
        globalThis.__ab_net_handlers[this._connId] = this;
    };

    // Internal: bind a host-allocated unix conn_id.
    Socket.prototype._attachUnix = function(connId) {
        this._unixConnId = connId | 0;
        globalThis.__ab_unix_handlers[this._unixConnId] = this;
    };

    Socket.prototype._dispatchConnect = function(local, remote) {
        this._connecting = false;
        this.readyState = 'open';
        this.localAddress = local && local.address;
        this.localPort = local && local.port;
        this.remoteAddress = remote && remote.address;
        this.remotePort = remote && remote.port;
        this.remoteFamily = remote && remote.family;
        this._resetTimeout();
        try { this.emit('connect'); } catch (_) {}
        try { this.emit('ready'); } catch (_) {}
    };

    Socket.prototype._dispatchData = function(payloadB64) {
        if (this._destroyed || !this._readable) return;
        this._resetTimeout();
        var bytes;
        try {
            bytes = Buffer.from(payloadB64, 'base64');
        } catch (_) {
            return;
        }
        this.bytesRead += bytes.length;
        // Honour `setEncoding`: when an encoding has been set, decode
        // the chunk before emitting and the 'data' listener gets a
        // string. Otherwise pass the Buffer through.
        var chunk = this._encoding
            ? bytes.toString(this._encoding)
            : bytes;
        try { this.emit('data', chunk); } catch (_) {}
    };

    Socket.prototype._dispatchEnd = function() {
        if (!this._readable) return;
        this._readable = false;
        this.readyState = this._writable ? 'writeOnly' : 'closed';
        try { this.emit('end'); } catch (_) {}
    };

    Socket.prototype._dispatchDrain = function() {
        if (!this._wantsDrain) return;
        this._wantsDrain = false;
        try { this.emit('drain'); } catch (_) {}
    };

    Socket.prototype._dispatchError = function(message, code) {
        var e = new Error(message || 'net error');
        e.code = code || 'EOTHER';
        try { this.emit('error', e); } catch (_) {}
    };

    Socket.prototype._dispatchClose = function(hadError) {
        if (this._closeEmitted) return;
        this._closeEmitted = true;
        this._destroyed = true;
        this._readable = false;
        this._writable = false;
        this.readyState = 'closed';
        this._clearTimeout();
        try { this.emit('close', !!hadError); } catch (_) {}
        if (this._connId) {
            delete globalThis.__ab_net_handlers[this._connId];
        }
        if (this._unixConnId) {
            delete globalThis.__ab_unix_handlers[this._unixConnId];
        }
    };

    Socket.prototype.connect = function() {
        // connect(port, host?, cb?) | connect({port, host}, cb?)
        // connect({path}, cb?)  -- AF_UNIX
        var args = Array.prototype.slice.call(arguments);
        var opts;
        var cb;
        if (args.length && typeof args[args.length - 1] === 'function') {
            cb = args.pop();
        }
        if (args.length === 1 && typeof args[0] === 'object' && args[0]) {
            opts = args[0];
        } else {
            opts = { port: args[0], host: args[1] };
        }

        // Path-based = Unix-domain socket.
        if (opts.path) {
            this._connecting = true;
            this.readyState = 'opening';
            var rc = globalThis.__host_unix_connect(String(opts.path));
            var self = this;
            if (rc < 0) {
                var err = makeError(rc, 'net.connect (unix)');
                Promise.resolve().then(function() {
                    self._connecting = false;
                    self._destroyed = true;
                    self.readyState = 'closed';
                    try { self.emit('error', err); } catch (_) {}
                    try { self.emit('close', true); } catch (_) {}
                });
                return this;
            }
            this._attachUnix(rc);
            if (cb) this.once('connect', cb);
            return this;
        }

        var port = opts.port | 0;
        var host = opts.host || '127.0.0.1';
        if (!port || port < 1 || port > 65535) {
            throw new RangeError('net.connect: port out of range: ' + opts.port);
        }
        this._connecting = true;
        this.readyState = 'opening';
        var rc2 = globalThis.__host_net_connect(String(host), port);
        if (rc2 < 0) {
            var err2 = makeError(rc2, 'net.connect');
            // Defer the error event to a microtask so handlers added
            // after connect() (the typical pattern) still fire.
            var self2 = this;
            Promise.resolve().then(function() {
                self2._connecting = false;
                self2._destroyed = true;
                self2.readyState = 'closed';
                try { self2.emit('error', err2); } catch (_) {}
                try { self2.emit('close', true); } catch (_) {}
            });
            return this;
        }
        this._attach(rc2);
        if (cb) this.once('connect', cb);
        return this;
    };

    Socket.prototype.write = function(data, encoding, cb) {
        if (this._destroyed || !this._writable) {
            if (cb) Promise.resolve().then(function() { cb(new Error('not writable')); });
            return false;
        }
        if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }

        var b64;
        if (Buffer.isBuffer(data)) {
            b64 = data.toString('base64');
        } else if (typeof data === 'string') {
            b64 = Buffer.from(data, encoding || 'utf8').toString('base64');
        } else if (data instanceof Uint8Array) {
            b64 = Buffer.from(data).toString('base64');
        } else {
            var t = typeof data;
            throw new TypeError('net.Socket.write: unsupported chunk type ' + t);
        }

        // bytesWritten counts the raw bytes, not the base64 string.
        var n = Buffer.isBuffer(data) ? data.length :
                (typeof data === 'string' ? Buffer.byteLength(data, encoding || 'utf8') :
                 (data && data.length) || 0);

        var rc;
        if (this._unixConnId) {
            rc = globalThis.__host_unix_write(this._unixConnId, b64);
        } else {
            rc = globalThis.__host_net_write(this._connId, b64);
        }
        if (rc < 0) {
            var err = makeError(rc, 'net.write');
            if (cb) cb(err);
            try { this.emit('error', err); } catch (_) {}
            return false;
        }
        this.bytesWritten += n;
        this._resetTimeout();
        if (cb) Promise.resolve().then(cb);

        var pending;
        if (this._unixConnId) {
            pending = globalThis.__host_unix_pending(this._unixConnId) | 0;
        } else {
            pending = globalThis.__host_net_pending(this._connId) | 0;
        }
        if (pending >= this._pendingHWM) {
            this._wantsDrain = true;
            return false;
        }
        return true;
    };

    Socket.prototype.end = function(data, encoding, cb) {
        if (typeof data === 'function') { cb = data; data = undefined; encoding = undefined; }
        else if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
        if (data !== undefined && data !== null) {
            this.write(data, encoding);
        }
        this._writable = false;
        if (!this._destroyed) {
            if (this._unixConnId) {
                globalThis.__host_unix_end(this._unixConnId);
            } else if (this._connId) {
                globalThis.__host_net_end(this._connId);
            }
        }
        if (cb) this.once('close', cb);
        return this;
    };

    Socket.prototype.destroy = function(err) {
        if (this._destroyed) return this;
        this._destroyed = true;
        this._readable = false;
        this._writable = false;
        if (this._unixConnId) {
            globalThis.__host_unix_destroy(this._unixConnId);
        } else if (this._connId) {
            globalThis.__host_net_destroy(this._connId);
        }
        if (err) {
            try { this.emit('error', err); } catch (_) {}
        }
        return this;
    };

    Socket.prototype.setNoDelay = function(enable) {
        if (this._connId) {
            globalThis.__host_net_set_no_delay(this._connId, enable === false ? 0 : 1);
        }
        return this;
    };

    Socket.prototype.setKeepAlive = function(enable, initialDelay) {
        if (this._connId) {
            globalThis.__host_net_set_keep_alive(
                this._connId,
                enable ? 1 : 0,
                (initialDelay | 0) || 0
            );
        }
        return this;
    };

    Socket.prototype.setTimeout = function(timeout, cb) {
        this._timeoutMs = timeout | 0;
        if (cb) this.on('timeout', cb);
        this._resetTimeout();
        return this;
    };

    Socket.prototype._resetTimeout = function() {
        this._clearTimeout();
        if (this._timeoutMs > 0) {
            var self = this;
            this._timeoutHandle = setTimeout(function() {
                try { self.emit('timeout'); } catch (_) {}
            }, this._timeoutMs);
        }
    };

    Socket.prototype._clearTimeout = function() {
        if (this._timeoutHandle) {
            clearTimeout(this._timeoutHandle);
            this._timeoutHandle = null;
        }
    };

    Socket.prototype.address = function() {
        if (!this.localAddress) return {};
        return {
            address: this.localAddress,
            family: this.remoteFamily ||
                    (String(this.localAddress || '').indexOf(':') >= 0 ? 'IPv6' : 'IPv4'),
            port: this.localPort,
        };
    };

    Socket.prototype.pause = function() {
        // Backpressure on the read side isn't wired in this minimum
        // subset — host always pumps. This is a no-op so callers that
        // call .pause() defensively don't crash.
        return this;
    };
    Socket.prototype.resume = function() { return this; };
    Socket.prototype.ref = function() { return this; };
    Socket.prototype.unref = function() { return this; };
    Socket.prototype.setEncoding = function(encoding) {
        // Buffer.toString validates the encoding name; preserving null
        // / undefined to "reset to Buffer" matches Node's contract.
        if (encoding == null) {
            this._encoding = null;
            return this;
        }
        // Sniff support up front so the first chunk doesn't surprise
        // user code at runtime.
        Buffer.from('').toString(encoding);
        this._encoding = encoding;
        return this;
    };

    Object.defineProperty(Socket.prototype, 'destroyed', {
        get: function() { return this._destroyed; },
    });
    Object.defineProperty(Socket.prototype, 'connecting', {
        get: function() { return this._connecting; },
    });
    Object.defineProperty(Socket.prototype, 'readable', {
        get: function() { return this._readable; },
    });
    Object.defineProperty(Socket.prototype, 'writable', {
        get: function() { return this._writable; },
    });
    Object.defineProperty(Socket.prototype, 'pending', {
        get: function() {
            if (this._unixConnId) {
                return globalThis.__host_unix_pending(this._unixConnId) | 0;
            }
            if (!this._connId) return 0;
            return globalThis.__host_net_pending(this._connId) | 0;
        },
    });

    // ----- Server ----------------------------------------------------

    function Server(opts, connectionListener) {
        if (!(this instanceof Server)) return new Server(opts, connectionListener);
        EventEmitter.call(this);
        if (typeof opts === 'function') {
            connectionListener = opts;
            opts = {};
        }
        this._serverId = 0;
        this._listening = false;
        this._closed = false;
        this._port = 0;
        this._host = '';
        this._path = null;           // non-null for Unix-domain servers
        this._connections = new Set();
        if (connectionListener) this.on('connection', connectionListener);
    }
    Server.prototype = Object.create(EventEmitter.prototype);
    Server.prototype.constructor = Server;

    Server.prototype.listen = function() {
        // listen(port[, host][, backlog][, cb])
        // listen({port, host, backlog}[, cb])
        // listen({path}[, cb])  -- Unix-domain
        // listen(cb) — port 0
        var args = Array.prototype.slice.call(arguments);
        var cb;
        if (args.length && typeof args[args.length - 1] === 'function') {
            cb = args.pop();
        }
        var opts;
        if (args.length === 1 && typeof args[0] === 'object' && args[0]) {
            opts = args[0];
        } else if (args.length === 0) {
            opts = { port: 0 };
        } else {
            opts = { port: args[0], host: args[1] };
        }

        // Path-based = Unix-domain server.
        if (opts.path) {
            var upath = String(opts.path);
            var urc = globalThis.__host_unix_listen(upath);
            if (urc < 0) {
                var uerr = makeError(urc, 'net.listen (unix)');
                var uself = this;
                Promise.resolve().then(function() {
                    try { uself.emit('error', uerr); } catch (_) {}
                });
                return this;
            }
            this._serverId = urc | 0;
            this._path = upath;
            globalThis.__ab_unix_server_handlers[this._serverId] = this;
            if (cb) this.once('listening', cb);
            return this;
        }

        var port = opts.port | 0;
        var host = opts.host || '0.0.0.0';
        if (port < 0 || port > 65535) {
            throw new RangeError('net.listen: port out of range: ' + opts.port);
        }
        var rc = globalThis.__host_net_listen(String(host), port);
        if (rc < 0) {
            var err = makeError(rc, 'net.listen');
            var self = this;
            Promise.resolve().then(function() {
                try { self.emit('error', err); } catch (_) {}
            });
            return this;
        }
        this._serverId = rc | 0;
        this._port = port;
        this._host = host;
        globalThis.__ab_net_server_handlers[this._serverId] = this;
        if (cb) this.once('listening', cb);
        return this;
    };

    Server.prototype.address = function() {
        if (!this._listening) return null;
        if (this._path) {
            return { address: this._path, family: 'Unix', port: 0 };
        }
        return {
            address: this._host,
            family: this._host.indexOf(':') >= 0 ? 'IPv6' : 'IPv4',
            port: this._port,
        };
    };

    Server.prototype.close = function(cb) {
        if (this._closed) {
            if (cb) Promise.resolve().then(function() { cb(); });
            return this;
        }
        this._closed = true;
        if (this._serverId) {
            if (this._path) {
                globalThis.__host_unix_close_server(this._serverId);
                delete globalThis.__ab_unix_server_handlers[this._serverId];
            } else {
                globalThis.__host_net_close_server(this._serverId);
                delete globalThis.__ab_net_server_handlers[this._serverId];
            }
        }
        var self = this;
        Promise.resolve().then(function() {
            self._listening = false;
            try { self.emit('close'); } catch (_) {}
            if (cb) cb();
        });
        return this;
    };

    Server.prototype.getConnections = function(cb) {
        var n = this._connections.size;
        Promise.resolve().then(function() { cb(null, n); });
        return this;
    };

    Server.prototype.ref = function() { return this; };
    Server.prototype.unref = function() { return this; };

    Server.prototype._dispatchListening = function(port) {
        this._listening = true;
        this._port = (port | 0) || this._port;
        try { this.emit('listening'); } catch (_) {}
    };

    Server.prototype._dispatchConnection = function(connId, local, remote) {
        var sock = new Socket();
        sock._attach(connId | 0);
        sock._connecting = false;
        sock.readyState = 'open';
        sock.localAddress = local && local.address;
        sock.localPort = local && local.port;
        sock.remoteAddress = remote && remote.address;
        sock.remotePort = remote && remote.port;
        sock.remoteFamily = remote && remote.family;
        var self = this;
        this._connections.add(sock);
        sock.once('close', function() { self._connections.delete(sock); });
        try { this.emit('connection', sock); } catch (_) {}
    };

    Server.prototype._dispatchUnixConnection = function(connId) {
        var sock = new Socket();
        sock._attachUnix(connId | 0);
        sock._connecting = false;
        sock.readyState = 'open';
        var self = this;
        this._connections.add(sock);
        sock.once('close', function() { self._connections.delete(sock); });
        try { this.emit('connection', sock); } catch (_) {}
    };

    Server.prototype._dispatchServerError = function(message) {
        var err = new Error(message || 'net.Server error');
        err.code = 'EOTHER';
        try { this.emit('error', err); } catch (_) {}
    };

    Object.defineProperty(Server.prototype, 'listening', {
        get: function() { return this._listening; },
    });

    // ----- Top-level helpers -----------------------------------------

    function connect() {
        var s = new Socket();
        return s.connect.apply(s, arguments);
    }

    function createServer(opts, listener) {
        return new Server(opts, listener);
    }

    function isIPv4(s) {
        if (typeof s !== 'string') return false;
        var parts = s.split('.');
        if (parts.length !== 4) return false;
        for (var i = 0; i < 4; i++) {
            var p = parts[i];
            if (!/^\d+$/.test(p)) return false;
            var n = parseInt(p, 10);
            if (n < 0 || n > 255) return false;
            if (p.length > 1 && p[0] === '0') return false;
        }
        return true;
    }

    function isIPv6(s) {
        if (typeof s !== 'string' || s.length === 0) return false;
        // Reject obvious junk before letting the regex chew on it.
        if (s.indexOf(' ') >= 0) return false;
        // Permissive match — covers full, compressed (`::`), and
        // IPv4-mapped (`::ffff:1.2.3.4`) forms. Doesn't enforce the
        // single-`::` rule rigorously but that's good enough for the
        // standard library's `isIP` contract.
        var ipv4Tail = '(?:\\d{1,3}\\.){3}\\d{1,3}';
        var hex = '[0-9a-fA-F]{1,4}';
        var regex = new RegExp(
            '^(?:' +
                '(?:' + hex + ':){7}' + hex +                              // 8 groups
                '|(?:' + hex + ':){1,7}:' +                                // ::-prefix
                '|(?:' + hex + ':){1,6}:' + hex +
                '|(?:' + hex + ':){1,5}(?::' + hex + '){1,2}' +
                '|(?:' + hex + ':){1,4}(?::' + hex + '){1,3}' +
                '|(?:' + hex + ':){1,3}(?::' + hex + '){1,4}' +
                '|(?:' + hex + ':){1,2}(?::' + hex + '){1,5}' +
                '|' + hex + ':(?::' + hex + '){1,6}' +
                '|:(?::' + hex + '){1,7}' +
                '|::' +
                '|(?:' + hex + ':){6}' + ipv4Tail +
                '|::(?:' + hex + ':){0,5}' + ipv4Tail +
            ')$'
        );
        return regex.test(s);
    }

    function isIP(s) {
        if (isIPv4(s)) return 4;
        if (isIPv6(s)) return 6;
        return 0;
    }

    // ---- net.BlockList (Node 15+) -----------------------------
    //
    // A list of IP rules with `addAddress` / `addRange` / `addSubnet`
    // and a `check(addr)` that returns true if the address matches.
    // Pure-JS — used by Node apps to gate accepted connections.
    function _ipv4ToInt(s) {
        var p = s.split('.');
        if (p.length !== 4) return -1;
        var n = 0;
        for (var i = 0; i < 4; i++) {
            var b = parseInt(p[i], 10);
            if (!(b >= 0 && b <= 255)) return -1;
            n = (n * 256) + b;
        }
        return n;
    }
    function BlockList() {
        if (!(this instanceof BlockList)) return new BlockList();
        this._rules = [];
    }
    BlockList.prototype.addAddress = function(address, family) {
        family = family || 'ipv4';
        this._rules.push({ kind: 'address', address: String(address), family: family });
    };
    BlockList.prototype.addRange = function(start, end, family) {
        family = family || 'ipv4';
        this._rules.push({ kind: 'range', start: String(start), end: String(end), family: family });
    };
    BlockList.prototype.addSubnet = function(network, prefix, family) {
        family = family || 'ipv4';
        this._rules.push({ kind: 'subnet', network: String(network), prefix: prefix | 0, family: family });
    };
    BlockList.prototype.check = function(address, family) {
        family = family || (isIPv6(address) ? 'ipv6' : 'ipv4');
        var addrStr = String(address);
        for (var i = 0; i < this._rules.length; i++) {
            var r = this._rules[i];
            if (r.family !== family) continue;
            if (r.kind === 'address' && r.address === addrStr) return true;
            if (family === 'ipv4') {
                var n = _ipv4ToInt(addrStr);
                if (n < 0) continue;
                if (r.kind === 'range') {
                    var lo = _ipv4ToInt(r.start), hi = _ipv4ToInt(r.end);
                    if (lo >= 0 && hi >= 0 && n >= lo && n <= hi) return true;
                } else if (r.kind === 'subnet') {
                    var net = _ipv4ToInt(r.network);
                    if (net < 0 || r.prefix < 0 || r.prefix > 32) continue;
                    var mask = r.prefix === 0 ? 0 : (~0 << (32 - r.prefix)) >>> 0;
                    if ((n & mask) === (net & mask)) return true;
                }
            }
            // IPv6 subnet/range matching is string-prefix only here.
            // Real workloads rarely use BlockList for IPv6; expand
            // when a concrete need surfaces.
        }
        return false;
    };
    Object.defineProperty(BlockList.prototype, 'rules', {
        get: function() {
            return this._rules.map(function(r) {
                if (r.kind === 'address') return 'Address: ' + r.family.toUpperCase() + ' ' + r.address;
                if (r.kind === 'range') return 'Range: ' + r.family.toUpperCase() + ' ' + r.start + '-' + r.end;
                return 'Subnet: ' + r.family.toUpperCase() + ' ' + r.network + '/' + r.prefix;
            });
        },
    });

    // ---- net.SocketAddress (Node 15+) -------------------------
    //
    // Immutable address record. In Node it's a transferable across
    // workers; here it's a value-object with the same shape.
    function SocketAddress(options) {
        if (!(this instanceof SocketAddress)) return new SocketAddress(options);
        options = options || {};
        Object.defineProperty(this, 'address', { value: String(options.address || '127.0.0.1'), enumerable: true });
        Object.defineProperty(this, 'port', { value: (options.port | 0) || 0, enumerable: true });
        Object.defineProperty(this, 'family', { value: String(options.family || 'ipv4').toLowerCase(), enumerable: true });
        Object.defineProperty(this, 'flowlabel', { value: (options.flowlabel | 0) || 0, enumerable: true });
    }
    SocketAddress.parse = function(input) {
        if (typeof input !== 'string') return undefined;
        var s = input.trim();
        if (s[0] === '[') {
            var rb = s.indexOf(']');
            if (rb < 0) return undefined;
            var addr = s.slice(1, rb);
            var rest = s.slice(rb + 1);
            var port = rest[0] === ':' ? parseInt(rest.slice(1), 10) : 0;
            return new SocketAddress({ address: addr, port: port, family: 'ipv6' });
        }
        if (isIPv6(s)) return new SocketAddress({ address: s, family: 'ipv6' });
        var c = s.lastIndexOf(':');
        if (c >= 0) {
            return new SocketAddress({ address: s.slice(0, c), port: parseInt(s.slice(c + 1), 10) || 0 });
        }
        return new SocketAddress({ address: s });
    };

    exports.Socket = Socket;
    exports.Server = Server;
    exports.createConnection = connect;
    exports.connect = connect;
    exports.createServer = createServer;
    exports.isIP = isIP;
    exports.isIPv4 = isIPv4;
    exports.isIPv6 = isIPv6;
    exports.BlockList = BlockList;
    exports.SocketAddress = SocketAddress;
});
