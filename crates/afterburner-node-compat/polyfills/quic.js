// node:quic — Node 24's experimental QUIC + HTTP/3 module. Backed by
// the host's `daemon_http3` coordinator (quinn + h3-quinn). Each
// listening endpoint runs a real QUIC stack over UDP with TLS-1.3
// and the `h3` ALPN; incoming requests dispatch through the same
// envelope path as `http.createServer`, so user code sees the same
// `(req, res)` shape.

__register_module('quic', function(module, exports, require) {
    var EventEmitter = require('events').EventEmitter;
    var http = require('http');

    function _err(code, msg) {
        var e = new Error(msg);
        e.code = code;
        return e;
    }

    /// `QuicEndpoint` — a UDP-bound QUIC listener. Wraps an
    /// underlying http.Server so the request/response surface is the
    /// same one Node code uses elsewhere. The key behavioural diff:
    /// the listener speaks H3 wire format (no H1 fallback — QUIC is
    /// HTTP/3-only).
    function QuicEndpoint(options) {
        if (!(this instanceof QuicEndpoint)) {
            throw new TypeError('QuicEndpoint must be constructed with `new`');
        }
        EventEmitter.call(this);
        options = options || {};
        var addr = options.address || {};
        this._port = (addr.port | 0) || 0;
        this._host = addr.host || '127.0.0.1';
        this._cert = options.cert;
        this._key  = options.key;
        this._closed = false;
        this._serverId = -1;
        this._sessions = [];
        // Inner http.Server reused for the request/response dispatch.
        // The H3 daemon pushes incoming requests to the same event
        // channel that http.createServer's listeners consume.
        this._inner = http.createServer();
        var self = this;
        this._inner.on('listening', function() {
            self.emit('listening');
        });
        this._inner.on('close', function() { self.emit('close'); });
        this._inner.on('error', function(e) { self.emit('error', e); });
    }
    QuicEndpoint.prototype = Object.create(EventEmitter.prototype);
    QuicEndpoint.prototype.constructor = QuicEndpoint;

    /// `endpoint.listen(options, sessionHandler)` — bind the QUIC
    /// listener and start serving. `sessionHandler` is called once per
    /// accepted QUIC session; we synthesise a Session object that
    /// emits `'stream'` for each request so user code can speak the
    /// stream-shape API directly.
    QuicEndpoint.prototype.listen = function(options, sessionHandler) {
        if (typeof options === 'function') {
            sessionHandler = options;
            options = undefined;
        }
        options = options || {};
        if (this._closed) throw _err('ERR_QUIC_CLOSED', 'endpoint closed');

        var cert = options.cert || this._cert;
        var key  = options.key  || this._key;
        if (!cert || !key) {
            throw _err('ERR_QUIC_TLS_REQUIRED',
                'QuicEndpoint.listen requires `cert` and `key` (PEM, TLS-1.3)');
        }
        var port = (options.port != null ? options.port : this._port) | 0;

        if (typeof globalThis.__host_http3_listen !== 'function') {
            throw _err('ERR_QUIC_NO_DAEMON',
                'QUIC requires daemon mode (build with --features http3 and run via burn CLI)');
        }

        var self = this;
        // Wire the user's session/stream handler against the inner
        // http.Server's `'request'` event FIRST. This ensures the
        // handler is attached before either TCP or UDP starts
        // accepting requests.
        if (typeof sessionHandler === 'function') {
            this._inner.on('request', function(req, res) {
                var session = new EventEmitter();
                session.endpoint = self;
                session.closed = false;
                session.close = function() { session.closed = true; };
                self._sessions.push(session);
                self.emit('session', session);
                sessionHandler(session);
                var stream = new EventEmitter();
                stream.id = (QuicEndpoint._streamCounter =
                    (QuicEndpoint._streamCounter || 1) + 4);
                stream.req = req;
                stream.res = res;
                stream.write = function(chunk, enc, cb) { return res.write(chunk, enc, cb); };
                stream.end   = function(chunk, enc, cb) { return res.end(chunk, enc, cb); };
                stream.respond = function(headers) {
                    var st = (headers && headers[':status']) || 200;
                    var send = {};
                    if (headers) {
                        Object.keys(headers).forEach(function(k) {
                            if (k.charAt(0) !== ':') send[k] = headers[k];
                        });
                    }
                    res.writeHead(st, send);
                };
                req.on('data', function(chunk) { stream.emit('data', chunk); });
                req.on('end',  function() { stream.emit('end'); });
                req.on('error', function(e) { stream.emit('error', e); });
                session.emit('stream', stream);
                if (self.listenerCount('stream') > 0) self.emit('stream', stream, session);
            });
        }

        // Bind TCP first so the JS handler chain has a real
        // server_id from the HTTP listener. The H3 listener piggybacks
        // on that server_id so incoming UDP/H3 requests dispatch to
        // the same handler.
        this._inner.listen(port, function() {
            var sid = self._inner._serverId;
            if (typeof sid !== 'number' || sid <= 0) {
                self.emit('error', _err('ERR_QUIC_LISTEN',
                    'QuicEndpoint.listen: HTTP listener has no server_id'));
                return;
            }
            self._serverId = sid;
            var h3id = globalThis.__host_http3_listen(
                port, sid, String(cert), String(key));
            if (typeof h3id === 'number' && h3id < 0) {
                var msg = h3id === -1 ? 'no daemon attached'
                        : h3id === -2 ? 'EADDRINUSE (UDP)'
                        : h3id === -4 ? 'permission denied (manifold listen)'
                        : 'h3 listen error';
                self.emit('error', _err('ERR_QUIC_LISTEN',
                    'QuicEndpoint.listen: ' + msg));
            }
        });
        return this;
    };

    QuicEndpoint.prototype.close = function(cb) {
        this._closed = true;
        if (this._serverId > 0 && typeof globalThis.__host_http_close === 'function') {
            try { globalThis.__host_http_close(this._serverId); } catch (_) {}
        }
        if (typeof cb === 'function') Promise.resolve().then(cb);
        return this;
    };

    QuicEndpoint.prototype.address = function() {
        if (this._serverId <= 0) return null;
        return { address: this._host, family: 'IPv4', port: this._port };
    };

    /// `quic.connect(addr, _options)` — client-side QUIC over HTTP/3.
    /// Returns a Session whose `request(headers, body)` issues a real
    /// outbound H3 request via the host's quinn client + h3 client
    /// stack. Each `request` round-trips synchronously from the JS
    /// side (the host runs `block_on` against the daemon's tokio
    /// runtime).
    function connect(addr, _options) {
        if (typeof globalThis.__host_http3_request !== 'function') {
            throw _err('ERR_QUIC_NO_DAEMON',
                'quic.connect: outbound h3 needs the daemon runtime '
                + '(build with --features http3)');
        }
        var session = new EventEmitter();
        session.addr = addr;
        session.closed = false;
        session.close = function() { session.closed = true; };
        /// `session.request(headers, body)` — minimal H3 client
        /// request shape. Returns a Promise resolving to
        /// `{status, headers, body}` (Buffer) — matches what an h3
        /// client would yield for a single-stream request.
        session.request = function(headers, body) {
            headers = headers || {};
            var method = headers[':method'] || 'GET';
            var path = headers[':path'] || '/';
            var scheme = headers[':scheme'] || 'https';
            var authority = headers[':authority']
                || (typeof addr === 'string' ? addr : (addr && addr.address));
            var url = scheme + '://' + authority + path;
            var Buf = globalThis.Buffer || require('buffer').Buffer;
            var bodyBytes = body == null ? new Uint8Array(0)
                : (typeof body === 'string' ? Buf.from(body, 'utf8')
                : Buf.isBuffer(body) ? body
                : new Uint8Array(body));
            var bodyB64 = Buf.from(bodyBytes).toString('base64');
            var raw = globalThis.__host_http3_request(url, String(method), bodyB64);
            if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
                return Promise.reject(_err('ERR_QUIC_REQUEST',
                    'quic.connect.request: ' + raw.slice('__HOST_ERR__:'.length)));
            }
            try {
                var parsed = JSON.parse(raw);
                var bodyOut = parsed.body_b64
                    ? Buf.from(parsed.body_b64, 'base64')
                    : Buf.alloc(0);
                return Promise.resolve({
                    status: parsed.status,
                    headers: parsed.headers || {},
                    body: bodyOut,
                });
            } catch (e) {
                return Promise.reject(_err('ERR_QUIC_REQUEST',
                    'quic.connect.request: bad host response: ' + e.message));
            }
        };
        Promise.resolve().then(function() { session.emit('connect'); });
        return session;
    }

    exports.QuicEndpoint = QuicEndpoint;
    exports.connect = connect;
    /// Constants pinned to RFC 9000 / 9114 values so apps that destructure
    /// them at module-init don't choke.
    exports.constants = {
        // QUIC transport error codes — RFC 9000 §20.1.
        QUIC_NO_ERROR: 0,
        QUIC_INTERNAL_ERROR: 1,
        QUIC_CONNECTION_REFUSED: 2,
        QUIC_FLOW_CONTROL_ERROR: 3,
        QUIC_STREAM_LIMIT_ERROR: 4,
        QUIC_STREAM_STATE_ERROR: 5,
        QUIC_FINAL_SIZE_ERROR: 6,
        QUIC_FRAME_ENCODING_ERROR: 7,
        QUIC_TRANSPORT_PARAMETER_ERROR: 8,
        QUIC_CONNECTION_ID_LIMIT_ERROR: 9,
        QUIC_PROTOCOL_VIOLATION: 10,
        QUIC_INVALID_TOKEN: 11,
        QUIC_APPLICATION_ERROR: 12,
        QUIC_CRYPTO_BUFFER_EXCEEDED: 13,
        QUIC_KEY_UPDATE_ERROR: 14,
        QUIC_AEAD_LIMIT_REACHED: 15,
        QUIC_NO_VIABLE_PATH: 16,
        // HTTP/3 frame types — RFC 9114 §11.
        H3_DATA: 0x00,
        H3_HEADERS: 0x01,
        H3_CANCEL_PUSH: 0x03,
        H3_SETTINGS: 0x04,
        H3_PUSH_PROMISE: 0x05,
        H3_GOAWAY: 0x07,
    };
});
