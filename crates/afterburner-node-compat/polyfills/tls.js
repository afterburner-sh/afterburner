// tls — raw TLS polyfill (B7).
//
// Layered on top of the same daemon-event plumbing as `net.js`: a JS
// `TLSSocket` is the façade, the host owns the `tokio_rustls`
// `TlsStream`, and lifecycle events arrive as `{kind: "tls-..."}`
// envelopes routed through `__ab_tls_handlers` and
// `__ab_tls_server_handlers`.
//
// API coverage (minimum-viable for real DB / API drivers):
//
//   tls.connect(opts[, listener])
//     opts: {host, port, servername?, rejectUnauthorized?, ca?,
//            ALPNProtocols?}
//   tls.connect(port, host[, opts][, listener])
//   socket.{write, end, destroy, on('secureConnect'|'data'|'end'|
//           'close'|'error'|'drain'), authorized, authorizationError,
//           getProtocol, alpnProtocol, encrypted}
//   tls.createServer(opts[, connectionListener])
//     opts: {cert, key} — PEM strings
//   server.{listen, close, address, on('listening'|'secureConnection'|
//           'close'|'error')}
//
// Deferred (will throw a clear error if used):
//   - PSK
//   - tls.checkServerIdentity hook (rustls handles standard hostname
//     verification automatically when rejectUnauthorized is true)
//   - DTLS / OpenSSL-specific knobs (secureProtocol, ciphers list,
//     ECDH curve picks)
//
// SNI multi-cert routing is supported via tls.createSecureContext
// + Server#addContext / { serverContexts: { '*.example.com': ctx } }.

(function bootstrapTlsGlobals() {
    if (!globalThis.__ab_tls_handlers) globalThis.__ab_tls_handlers = {};
    if (!globalThis.__ab_tls_server_handlers) globalThis.__ab_tls_server_handlers = {};
})();

__register_module('tls', function(module, exports, require) {
    var EventEmitter = require('events').EventEmitter;
    var Buffer = require('buffer').Buffer;
    var net = require('net');

    // ----- error mapping --------------------------------------------

    function mapHostErrorCode(rc) {
        switch (rc) {
            case -1: return 'ENO_DAEMON';
            case -2: return 'EACCES';
            case -3: return 'ENOTFOUND';
            case -4: return 'EINVAL';
            case -5: return 'EINVAL';
            case -6: return 'EINVAL';
            case -7: return 'ERR_TLS_INVALID_CERT';
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

    // ----- TLSSocket -------------------------------------------------
    //
    // Shaped like `net.Socket` but the connection it stands in for
    // is a TLS stream. We don't extend `net.Socket` — the polyfill
    // owns a dedicated host id space (__host_tls_*), so re-using
    // net.Socket would risk crossed wires on the registry side.

    function TLSSocket(opts) {
        if (!(this instanceof TLSSocket)) return new TLSSocket(opts);
        EventEmitter.call(this);
        opts = opts || {};

        this._connId = 0;
        this._connecting = false;
        this._destroyed = false;
        this._closeEmitted = false;
        this._readable = true;
        this._writable = true;
        this._encoding = null;        // null = emit Buffer; set via setEncoding
        this._wantsDrain = false;
        this._pendingHWM = 64 * 1024;
        this.bytesRead = 0;
        this.bytesWritten = 0;
        this.encrypted = true;
        this.authorized = false;
        this.authorizationError = null;
        this.alpnProtocol = null;
        this._protocol = null;
        this.remoteAddress = undefined;
        this.remotePort = undefined;
        this.remoteFamily = undefined;
        this.localAddress = undefined;
        this.localPort = undefined;
        this.readyState = 'opening';
    }
    TLSSocket.prototype = Object.create(EventEmitter.prototype);
    TLSSocket.prototype.constructor = TLSSocket;

    TLSSocket.prototype._attach = function(connId) {
        if (this._connId) {
            throw new Error('tls.TLSSocket already attached to conn ' + this._connId);
        }
        this._connId = connId | 0;
        globalThis.__ab_tls_handlers[this._connId] = this;
    };

    TLSSocket.prototype._dispatchSecureConnect = function(
        local, remote, alpn, protocol, authorized, cipher, certChainB64
    ) {
        this._connecting = false;
        this.readyState = 'open';
        this.localAddress = local && local.address;
        this.localPort = local && local.port;
        this.remoteAddress = remote && remote.address;
        this.remotePort = remote && remote.port;
        this.remoteFamily = remote && remote.family;
        this.alpnProtocol = alpn || null;
        this._protocol = protocol || null;
        this._cipher = cipher || null;
        this._peerCertChainB64 = Array.isArray(certChainB64) ? certChainB64 : [];
        this.authorized = !!authorized;
        if (!this.authorized) {
            this.authorizationError = new Error(
                'TLS verification skipped (rejectUnauthorized: false)'
            );
            this.authorizationError.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
        }
        try { this.emit('secureConnect'); } catch (_) {}
        // Node fires 'connect' before 'secureConnect' for the legacy
        // path; we collapse them into one and emit both for callers
        // that listen only to 'connect'.
        try { this.emit('connect'); } catch (_) {}
        try { this.emit('ready'); } catch (_) {}
    };

    TLSSocket.prototype._dispatchData = function(payloadB64) {
        if (this._destroyed || !this._readable) return;
        var bytes;
        try { bytes = Buffer.from(payloadB64, 'base64'); }
        catch (_) { return; }
        this.bytesRead += bytes.length;
        // Honour `setEncoding`: emit decoded string when an encoding is
        // configured; Buffer otherwise.
        var chunk = this._encoding ? bytes.toString(this._encoding) : bytes;
        try { this.emit('data', chunk); } catch (_) {}
    };

    TLSSocket.prototype._dispatchEnd = function() {
        if (!this._readable) return;
        this._readable = false;
        this.readyState = this._writable ? 'writeOnly' : 'closed';
        try { this.emit('end'); } catch (_) {}
    };

    TLSSocket.prototype._dispatchDrain = function() {
        if (!this._wantsDrain) return;
        this._wantsDrain = false;
        try { this.emit('drain'); } catch (_) {}
    };

    TLSSocket.prototype._dispatchError = function(message, code) {
        var e = new Error(message || 'tls error');
        e.code = code || 'EOTHER';
        try { this.emit('error', e); } catch (_) {}
    };

    TLSSocket.prototype._dispatchClose = function(hadError) {
        if (this._closeEmitted) return;
        this._closeEmitted = true;
        this._destroyed = true;
        this._readable = false;
        this._writable = false;
        this.readyState = 'closed';
        try { this.emit('close', !!hadError); } catch (_) {}
        if (this._connId) {
            delete globalThis.__ab_tls_handlers[this._connId];
        }
    };

    TLSSocket.prototype.connect = function(opts) {
        var port = opts.port | 0;
        var host = opts.host || '127.0.0.1';
        if (!port || port < 1 || port > 65535) {
            throw new RangeError('tls.connect: port out of range: ' + opts.port);
        }
        // `rejectUnauthorized` defaults to true (Node-compat). Only an
        // explicit `false` opts out.
        var hostOpts = {
            rejectUnauthorized: opts.rejectUnauthorized === false ? false : true,
            servername: typeof opts.servername === 'string' ? opts.servername : '',
            alpn: Array.isArray(opts.ALPNProtocols)
                ? opts.ALPNProtocols.map(function(p) { return String(p); })
                : [],
            ca: typeof opts.ca === 'string' ? opts.ca :
                Buffer.isBuffer(opts.ca) ? opts.ca.toString('utf8') : '',
            // mTLS: pass client cert + key when the caller supplies them.
            cert: typeof opts.cert === 'string' ? opts.cert :
                  Buffer.isBuffer(opts.cert) ? opts.cert.toString('utf8') : '',
            key: typeof opts.key === 'string' ? opts.key :
                 Buffer.isBuffer(opts.key) ? opts.key.toString('utf8') : ''
        };
        this._connecting = true;
        this.readyState = 'opening';
        var rc = globalThis.__host_tls_connect(
            String(host),
            port,
            JSON.stringify(hostOpts)
        );
        if (rc < 0) {
            var err = makeError(rc, 'tls.connect');
            var self = this;
            Promise.resolve().then(function() {
                self._connecting = false;
                self._destroyed = true;
                self.readyState = 'closed';
                try { self.emit('error', err); } catch (_) {}
                try { self.emit('close', true); } catch (_) {}
            });
            return this;
        }
        this._attach(rc);
        return this;
    };

    TLSSocket.prototype.write = function(data, encoding, cb) {
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
            throw new TypeError('tls.TLSSocket.write: unsupported chunk type ' + typeof data);
        }

        var rc = globalThis.__host_tls_write(this._connId, b64);
        if (rc < 0) {
            var err = makeError(rc, 'tls.write');
            if (cb) cb(err);
            try { this.emit('error', err); } catch (_) {}
            return false;
        }
        var n = Buffer.isBuffer(data) ? data.length :
                (typeof data === 'string' ? Buffer.byteLength(data, encoding || 'utf8') :
                 (data && data.length) || 0);
        this.bytesWritten += n;
        if (cb) Promise.resolve().then(cb);

        var pending = globalThis.__host_tls_pending(this._connId) | 0;
        if (pending >= this._pendingHWM) {
            this._wantsDrain = true;
            return false;
        }
        return true;
    };

    TLSSocket.prototype.end = function(data, encoding, cb) {
        if (typeof data === 'function') { cb = data; data = undefined; encoding = undefined; }
        else if (typeof encoding === 'function') { cb = encoding; encoding = undefined; }
        if (data !== undefined && data !== null) {
            this.write(data, encoding);
        }
        this._writable = false;
        if (this._connId && !this._destroyed) {
            globalThis.__host_tls_end(this._connId);
        }
        if (cb) this.once('close', cb);
        return this;
    };

    TLSSocket.prototype.destroy = function(err) {
        if (this._destroyed) return this;
        this._destroyed = true;
        this._readable = false;
        this._writable = false;
        if (this._connId) {
            globalThis.__host_tls_destroy(this._connId);
        }
        if (err) {
            try { this.emit('error', err); } catch (_) {}
        }
        return this;
    };

    // setNoDelay / setKeepAlive aren't surfaced — tls owns the
    // underlying TcpStream and applying them after the handshake is
    // a niche use case. Accept-and-no-op stubs to match Node's lax
    // duck-typing.
    TLSSocket.prototype.setNoDelay = function() { return this; };
    TLSSocket.prototype.setKeepAlive = function() { return this; };
    TLSSocket.prototype.setTimeout = function() { return this; };
    TLSSocket.prototype.pause = function() { return this; };
    TLSSocket.prototype.resume = function() { return this; };
    TLSSocket.prototype.ref = function() { return this; };
    TLSSocket.prototype.unref = function() { return this; };
    TLSSocket.prototype.setEncoding = function(encoding) {
        if (encoding == null) {
            this._encoding = null;
            return this;
        }
        Buffer.from('').toString(encoding);
        this._encoding = encoding;
        return this;
    };

    TLSSocket.prototype.address = function() {
        if (!this.localAddress) return {};
        return {
            address: this.localAddress,
            family: this.remoteFamily ||
                    (String(this.localAddress || '').indexOf(':') >= 0 ? 'IPv6' : 'IPv4'),
            port: this.localPort,
        };
    };

    TLSSocket.prototype.getProtocol = function() {
        return this._protocol;
    };

    TLSSocket.prototype.getCipher = function() {
        // The IANA cipher-suite name comes from rustls'
        // `negotiated_cipher_suite()` and is the same string Node's
        // `getCipher()` returns for `name` / `standardName`.
        var name = this._cipher || 'unknown';
        return {
            name: name,
            standardName: name,
            version: this._protocol || '',
        };
    };

    /// Return the leaf peer certificate, shaped close enough to Node
    /// for the common assertions:
    ///   { raw: Buffer, fingerprint256: '...' }
    /// Subject/issuer parsing requires full ASN.1 decoding; the
    /// minimum subset doesn't include it — callers needing those
    /// fields can parse `raw` themselves.
    TLSSocket.prototype.getPeerCertificate = function(detailed) {
        var chain = this._peerCertChainB64 || [];
        if (chain.length === 0) return {};
        var raw = Buffer.from(chain[0], 'base64');
        var cert = {
            raw: raw,
            fingerprint256: sha256Fingerprint(raw),
            subject: {},
            issuer: {},
            valid_from: '',
            valid_to: '',
        };
        if (detailed && chain.length > 1) {
            cert.issuerCertificate = (function makeIssuer(rest) {
                if (rest.length === 0) return undefined;
                var rawIssuer = Buffer.from(rest[0], 'base64');
                return {
                    raw: rawIssuer,
                    fingerprint256: sha256Fingerprint(rawIssuer),
                    subject: {},
                    issuer: {},
                    issuerCertificate: makeIssuer(rest.slice(1)),
                };
            })(chain.slice(1));
        }
        return cert;
    };

    /// Return the entire leaf-first peer certificate chain as an
    /// array of `{raw, fingerprint256}` objects. Convenient when
    /// callers need to walk every cert; mirrors Node's `getPeerX509Certificate()`
    /// shape.
    TLSSocket.prototype.getPeerCertChain = function() {
        var chain = this._peerCertChainB64 || [];
        return chain.map(function(b64) {
            var raw = Buffer.from(b64, 'base64');
            return { raw: raw, fingerprint256: sha256Fingerprint(raw) };
        });
    };

    function sha256Fingerprint(buf) {
        // Node returns colon-separated uppercase hex (`AA:BB:...`).
        // We prefer this format because real-world certificate
        // pinning code matches it byte-for-byte.
        try {
            var crypto = require('crypto');
            var hash = crypto.createHash('sha256').update(buf).digest('hex');
            var out = [];
            for (var i = 0; i < hash.length; i += 2) {
                out.push(hash.slice(i, i + 2).toUpperCase());
            }
            return out.join(':');
        } catch (_) {
            return '';
        }
    }

    Object.defineProperty(TLSSocket.prototype, 'destroyed', {
        get: function() { return this._destroyed; },
    });
    Object.defineProperty(TLSSocket.prototype, 'connecting', {
        get: function() { return this._connecting; },
    });
    Object.defineProperty(TLSSocket.prototype, 'readable', {
        get: function() { return this._readable; },
    });
    Object.defineProperty(TLSSocket.prototype, 'writable', {
        get: function() { return this._writable; },
    });
    Object.defineProperty(TLSSocket.prototype, 'pending', {
        get: function() {
            if (!this._connId) return 0;
            return globalThis.__host_tls_pending(this._connId) | 0;
        },
    });

    // ----- Server ----------------------------------------------------

    function _pemFromOpt(v) {
        if (typeof v === 'string') return v;
        if (Buffer.isBuffer(v)) return v.toString('utf8');
        if (Array.isArray(v) && v.length && (typeof v[0] === 'string' || Buffer.isBuffer(v[0]))) {
            return _pemFromOpt(v[0]);
        }
        return '';
    }

    function createSecureContext(opts) {
        opts = opts || {};
        var cert = _pemFromOpt(opts.cert);
        var key = _pemFromOpt(opts.key);
        if (!cert || !key) {
            throw new Error('tls.createSecureContext: `cert` and `key` (PEM) are required');
        }
        return { context: { __isSecureContext: true, cert: cert, key: key } };
    }

    function Server(opts, secureConnectionListener) {
        if (!(this instanceof Server)) return new Server(opts, secureConnectionListener);
        EventEmitter.call(this);
        if (typeof opts === 'function') {
            secureConnectionListener = opts;
            opts = {};
        }
        opts = opts || {};
        this._cert = _pemFromOpt(opts.cert);
        this._key = _pemFromOpt(opts.key);
        if (!this._cert || !this._key) {
            throw new Error('tls.createServer: `cert` and `key` (PEM) are required');
        }
        // mTLS server options: request + verify the client cert when
        // `requestCert` is true. `ca` supplies the PEM of the CA used
        // to verify the client cert; defaults to empty (no client auth).
        this._requestCert = opts.requestCert === true;
        this._clientCaPem = typeof opts.ca === 'string' ? opts.ca :
                            Buffer.isBuffer(opts.ca) ? opts.ca.toString('utf8') : '';
        this._sniContexts = Object.create(null);
        if (opts.serverContexts && typeof opts.serverContexts === 'object') {
            for (var sn in opts.serverContexts) {
                if (Object.prototype.hasOwnProperty.call(opts.serverContexts, sn)) {
                    var sc = opts.serverContexts[sn];
                    var c, k;
                    if (sc && sc.context && sc.context.__isSecureContext) {
                        c = sc.context.cert; k = sc.context.key;
                    } else if (sc && typeof sc === 'object') {
                        c = _pemFromOpt(sc.cert); k = _pemFromOpt(sc.key);
                    }
                    if (c && k) this._sniContexts[String(sn)] = { cert: c, key: k };
                }
            }
        }
        this._serverId = 0;
        this._listening = false;
        this._closed = false;
        this._port = 0;
        this._host = '';
        this._connections = new Set();
        if (secureConnectionListener) this.on('secureConnection', secureConnectionListener);
    }
    Server.prototype = Object.create(EventEmitter.prototype);
    Server.prototype.constructor = Server;

    Server.prototype.addContext = function(servername, context) {
        if (typeof servername !== 'string' || !servername) {
            throw new TypeError('tls.Server#addContext: servername must be a non-empty string');
        }
        var c, k;
        if (context && context.context && context.context.__isSecureContext) {
            c = context.context.cert; k = context.context.key;
        } else if (context && typeof context === 'object') {
            c = _pemFromOpt(context.cert); k = _pemFromOpt(context.key);
        }
        if (!c || !k) {
            throw new Error('tls.Server#addContext: context must include cert and key');
        }
        this._sniContexts[servername] = { cert: c, key: k };
        return this;
    };

    Server.prototype.listen = function() {
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
        var port = opts.port | 0;
        var host = opts.host || '0.0.0.0';
        if (port < 0 || port > 65535) {
            throw new RangeError('tls.listen: port out of range: ' + opts.port);
        }
        var sniArr = [];
        for (var sn in this._sniContexts) {
            if (Object.prototype.hasOwnProperty.call(this._sniContexts, sn)) {
                sniArr.push({
                    servername: sn,
                    cert: this._sniContexts[sn].cert,
                    key: this._sniContexts[sn].key,
                });
            }
        }
        var sniJson = sniArr.length ? JSON.stringify(sniArr) : '';
        // mTLS listen options: requestCert + client CA PEM.
        var listenOpts = JSON.stringify({
            requestCert: this._requestCert,
            ca: this._clientCaPem
        });
        var rc = globalThis.__host_tls_listen(
            String(host), port, this._cert, this._key, sniJson, listenOpts
        );
        if (rc < 0) {
            var err = makeError(rc, 'tls.listen');
            var self = this;
            Promise.resolve().then(function() {
                try { self.emit('error', err); } catch (_) {}
            });
            return this;
        }
        this._serverId = rc | 0;
        this._port = port;
        this._host = host;
        globalThis.__ab_tls_server_handlers[this._serverId] = this;
        if (cb) this.once('listening', cb);
        return this;
    };

    Server.prototype.address = function() {
        if (!this._listening) return null;
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
            globalThis.__host_tls_close_server(this._serverId);
            delete globalThis.__ab_tls_server_handlers[this._serverId];
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

    Server.prototype._dispatchConnection = function(
        connId, local, remote, alpn, protocol, cipher, certChainB64
    ) {
        var sock = new TLSSocket();
        sock._attach(connId | 0);
        sock._connecting = false;
        sock.readyState = 'open';
        sock.localAddress = local && local.address;
        sock.localPort = local && local.port;
        sock.remoteAddress = remote && remote.address;
        sock.remotePort = remote && remote.port;
        sock.remoteFamily = remote && remote.family;
        sock.alpnProtocol = alpn || null;
        sock._protocol = protocol || null;
        sock._cipher = cipher || null;
        sock._peerCertChainB64 = Array.isArray(certChainB64) ? certChainB64 : [];
        // When the server requested a client cert (mTLS) and the chain
        // is non-empty, the handshake succeeded: the client is authorized.
        // Without requestCert (one-way TLS) the chain is empty and
        // authorized stays false (Node's default for server-side sockets).
        sock.authorized = sock._peerCertChainB64.length > 0;
        var self = this;
        this._connections.add(sock);
        sock.once('close', function() { self._connections.delete(sock); });
        try { this.emit('secureConnection', sock); } catch (_) {}
        // Node also emits 'connection' (the legacy raw-TCP-layer event)
        // — keep that for callers that just listen to 'connection'.
        try { this.emit('connection', sock); } catch (_) {}
    };

    Server.prototype._dispatchServerError = function(message) {
        var err = new Error(message || 'tls.Server error');
        err.code = 'EOTHER';
        try { this.emit('error', err); } catch (_) {}
    };

    Object.defineProperty(Server.prototype, 'listening', {
        get: function() { return this._listening; },
    });

    // ----- Top-level helpers -----------------------------------------

    function connect() {
        var args = Array.prototype.slice.call(arguments);
        var cb;
        if (args.length && typeof args[args.length - 1] === 'function') {
            cb = args.pop();
        }
        var opts;
        if (args.length === 1 && typeof args[0] === 'object' && args[0]) {
            opts = args[0];
        } else if (args.length >= 2 && typeof args[1] === 'string') {
            // (port, host[, opts])
            opts = Object.assign({}, args[2] || {}, { port: args[0], host: args[1] });
        } else {
            opts = { port: args[0] };
        }
        var s = new TLSSocket();
        if (cb) s.once('secureConnect', cb);
        return s.connect(opts);
    }

    function createServer(opts, listener) {
        return new Server(opts, listener);
    }

    exports.TLSSocket = TLSSocket;
    exports.Server = Server;
    exports.connect = connect;
    exports.createServer = createServer;
    exports.createSecureContext = createSecureContext;
    exports.SecureContext = function SecureContext() {};
    // Re-export net's IP helpers so callers can do `tls.isIP`.
    exports.isIP = net.isIP;
    exports.isIPv4 = net.isIPv4;
    exports.isIPv6 = net.isIPv6;
    // Stable defaults — Node exposes these but burn doesn't gate on them.
    exports.DEFAULT_MIN_VERSION = 'TLSv1.2';
    exports.DEFAULT_MAX_VERSION = 'TLSv1.3';
    /// `tls.DEFAULT_ECDH_CURVE` (Node 8+) — preferred curve list. We
    /// don't gate on this; Node defaults to 'auto'.
    exports.DEFAULT_ECDH_CURVE = 'auto';
    /// `tls.DEFAULT_CIPHERS` — Node's default OpenSSL cipher string.
    /// We surface the canonical Node 18+ default for libraries that
    /// echo it back (axios bundle reporting, oncall debugging).
    exports.DEFAULT_CIPHERS = [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'DHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-SHA256',
        'DHE-RSA-AES128-SHA256',
        'ECDHE-RSA-AES256-SHA384',
        'DHE-RSA-AES256-SHA384',
        'ECDHE-RSA-AES256-SHA256',
        'DHE-RSA-AES256-SHA256',
        'HIGH',
        '!aNULL',
        '!eNULL',
        '!EXPORT',
        '!DES',
        '!RC4',
        '!MD5',
        '!PSK',
        '!SRP',
        '!CAMELLIA',
    ].join(':');
    /// Renegotiation guards — Node has had these since 0.6 to defend
    /// against CVE-2009-3555. We surface the values and accept them as
    /// configured but our TCP/TLS layer doesn't expose renegotiation,
    /// so they're informational.
    exports.CLIENT_RENEG_LIMIT = 3;
    exports.CLIENT_RENEG_WINDOW = 600;

    /// tls.checkServerIdentity(hostname, cert) — verify a peer
    /// certificate matches the requested hostname. Real impl walks
    /// `cert.subjectaltname` for `DNS:` entries and compares against
    /// the hostname (with leading-`*` wildcards collapsed). Returns
    /// `undefined` on match, an `Error` instance on mismatch.
    exports.checkServerIdentity = function(hostname, cert) {
        if (!cert) {
            var err = new Error('tls.checkServerIdentity: cert is required');
            err.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
            return err;
        }
        var host = String(hostname || '').toLowerCase();
        var altNames = [];
        if (typeof cert.subjectaltname === 'string') {
            // Parse "DNS:foo, DNS:bar, IP Address:1.2.3.4" pairs.
            var parts = cert.subjectaltname.split(/,\s*/);
            for (var i = 0; i < parts.length; i++) {
                var p = parts[i].split(':');
                if (p.length === 2 && p[0].trim().toLowerCase() === 'dns') {
                    altNames.push(p[1].trim().toLowerCase());
                }
            }
        }
        if (cert.subject && typeof cert.subject.CN === 'string' && altNames.length === 0) {
            altNames.push(String(cert.subject.CN).toLowerCase());
        }
        for (var j = 0; j < altNames.length; j++) {
            var name = altNames[j];
            if (name === host) return undefined;
            // Wildcard match: `*.example.com` matches `foo.example.com`
            // but NOT `foo.bar.example.com` (single label).
            if (name.indexOf('*.') === 0) {
                var suffix = name.slice(1); // ".example.com"
                if (host.length > suffix.length && host.endsWith(suffix)) {
                    var labelEnd = host.length - suffix.length;
                    if (host.indexOf('.', 0) >= labelEnd || host.indexOf('.', 0) === labelEnd) {
                        return undefined;
                    }
                    if (host.indexOf('.') === labelEnd) return undefined;
                }
            }
        }
        var error = new Error("Hostname/IP does not match certificate's altnames: Host: "
            + host + ". is not in the cert's altnames: " + altNames.join(', '));
        error.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
        error.host = host;
        error.cert = cert;
        return error;
    };

    // ---- tls.rootCertificates / getCACertificates (Node 12 / 24) ----
    //
    // The host TLS layer (rustls / webpki-roots) owns the actual root
    // store; we don't surface PEM strings out of it (that crosses the
    // sandbox boundary for what's effectively read-only metadata).
    // The arrays are populated lazily on first access and cached.
    var _rootCerts = null;
    Object.defineProperty(exports, 'rootCertificates', {
        configurable: true,
        enumerable: true,
        get: function() {
            if (_rootCerts === null) {
                if (typeof globalThis.__host_tls_root_certificates === 'function') {
                    var raw = globalThis.__host_tls_root_certificates();
                    _rootCerts = (typeof raw === 'string' && raw.length) ? raw.split('\n--CERT--\n') : [];
                } else {
                    _rootCerts = [];
                }
            }
            return _rootCerts.slice();
        },
    });
    exports.getCACertificates = function getCACertificates(type) {
        // type: 'default' | 'system' | 'bundled' | 'extra'.
        // We only have the bundled webpki roots; surface them under
        // every requested type for compatibility.
        type = type || 'default';
        return exports.rootCertificates;
    };
});
