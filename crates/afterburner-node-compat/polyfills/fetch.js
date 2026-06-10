// fetch / Request / Response / Headers — Web API, synchronous under
// the hood (our http host is sync) but Promise-wrapped to match the
// standard interface.

(function installFetch() {
    if (typeof globalThis.fetch === 'function') return;

    function Headers(init) {
        this._m = Object.create(null);
        if (!init) return;
        if (init instanceof Headers) {
            for (var k in init._m) this._m[k] = init._m[k];
            return;
        }
        if (Array.isArray(init)) {
            for (var i = 0; i < init.length; i++) this.set(init[i][0], init[i][1]);
            return;
        }
        var keys = Object.keys(init);
        for (var j = 0; j < keys.length; j++) this.set(keys[j], init[keys[j]]);
    }
    Headers.prototype.get = function(k)       { return this._m[String(k).toLowerCase()] || null; };
    Headers.prototype.has = function(k)       { return String(k).toLowerCase() in this._m; };
    Headers.prototype.set = function(k, v)    { this._m[String(k).toLowerCase()] = String(v); };
    Headers.prototype.append = function(k, v) {
        var key = String(k).toLowerCase();
        this._m[key] = (this._m[key] ? this._m[key] + ', ' : '') + String(v);
    };
    Headers.prototype['delete'] = function(k) { delete this._m[String(k).toLowerCase()]; };
    Headers.prototype.forEach = function(cb)  {
        var keys = Object.keys(this._m);
        for (var i = 0; i < keys.length; i++) cb(this._m[keys[i]], keys[i], this);
    };
    Headers.prototype.entries = function() {
        var keys = Object.keys(this._m);
        var self = this;
        var i = 0;
        return { next: function() {
            if (i >= keys.length) return { done: true };
            var k = keys[i++];
            return { value: [k, self._m[k]], done: false };
        } };
    };
    Headers.prototype.keys = function() {
        var keys = Object.keys(this._m);
        var i = 0;
        return { next: function() {
            if (i >= keys.length) return { done: true };
            return { value: keys[i++], done: false };
        } };
    };
    Headers.prototype.values = function() {
        var keys = Object.keys(this._m);
        var self = this;
        var i = 0;
        return { next: function() {
            if (i >= keys.length) return { done: true };
            return { value: self._m[keys[i++]], done: false };
        } };
    };
    Headers.prototype[Symbol.iterator] = Headers.prototype.entries;
    /// Headers.prototype.getSetCookie — Node 19+. Returns each
    /// Set-Cookie header as a separate array entry. Our internal
    /// storage joins same-name headers with `, `; Set-Cookie is
    /// the one header where that join is wrong per spec, but we
    /// recover by splitting on the canonical separator.
    Headers.prototype.getSetCookie = function() {
        var raw = this._m['set-cookie'];
        if (!raw) return [];
        // Split on `, ` only when the next chunk looks like a new
        // cookie name (matches `[A-Za-z0-9!#$%&'*+\-.^_`|~]+=`).
        // Single-cookie value may contain `, ` inside `Expires=...`
        // weekday names — naive split would corrupt those.
        var parts = [];
        var cur = '';
        var i = 0;
        while (i < raw.length) {
            if (raw[i] === ',' && raw[i + 1] === ' ') {
                // Lookahead: does what's next look like NAME= ?
                var j = i + 2;
                var k = j;
                while (k < raw.length && /[A-Za-z0-9!#$%&'*+\-.^_`|~]/.test(raw[k])) k++;
                if (k > j && raw[k] === '=') {
                    parts.push(cur);
                    cur = '';
                    i = j;
                    continue;
                }
            }
            cur += raw[i++];
        }
        if (cur) parts.push(cur);
        return parts;
    };

    function Request(url, init) {
        init = init || {};
        // If a Request instance is passed in, copy its fields then
        // overlay the init (matching the spec's `new Request(req,
        // {...})` cloning shape).
        if (url && typeof url === 'object' && url instanceof Request) {
            this.url = url.url;
            this.method = url.method;
            this.headers = new Headers(url.headers);
            this.body = url.body;
            this._bodyBytes = url._bodyBytes || null;
            this.signal = url.signal;
            this.redirect = url.redirect;
            this.cache = url.cache;
            this.credentials = url.credentials;
            this.mode = url.mode;
            this.referrer = url.referrer;
            this.referrerPolicy = url.referrerPolicy;
            this.integrity = url.integrity;
            this.keepalive = url.keepalive;
        } else {
            this.url = String(url);
            this.method = 'GET';
            this.headers = new Headers();
            this.body = null;
            this._bodyBytes = null;
            this.signal = null;
            this.redirect = 'follow';
            this.cache = 'default';
            this.credentials = 'same-origin';
            this.mode = 'cors';
            this.referrer = '';
            this.referrerPolicy = '';
            this.integrity = '';
            this.keepalive = false;
        }
        // Apply init overlays on top.
        if (init.method) this.method = String(init.method).toUpperCase();
        if (init.headers) this.headers = new Headers(init.headers);
        if (init.body != null) {
            // Binary BodyInit (ArrayBuffer / TypedArray / Buffer) must NOT
            // be stringified — `String(uint8array)` yields "0,97,115,…".
            // Keep the exact bytes; the send path frames them as base64
            // for the host, which decodes and sends the original bytes.
            var _b = init.body;
            if (typeof ArrayBuffer !== 'undefined' && _b instanceof ArrayBuffer) {
                this._bodyBytes = new Uint8Array(_b.slice(0));
                this.body = null;
            } else if (typeof ArrayBuffer !== 'undefined' && ArrayBuffer.isView(_b)) {
                this._bodyBytes = new Uint8Array(
                    _b.buffer.slice(_b.byteOffset, _b.byteOffset + _b.byteLength));
                this.body = null;
            } else {
                this._bodyBytes = null;
                this.body = String(_b);
            }
        }
        if (init.signal !== undefined) this.signal = init.signal;
        if (init.redirect) this.redirect = init.redirect;
        if (init.cache) this.cache = init.cache;
        if (init.credentials) this.credentials = init.credentials;
        if (init.mode) this.mode = init.mode;
        if (init.referrer != null) this.referrer = String(init.referrer);
        if (init.referrerPolicy) this.referrerPolicy = init.referrerPolicy;
        if (init.integrity) this.integrity = init.integrity;
        if (init.keepalive !== undefined) this.keepalive = !!init.keepalive;
    }
    Request.prototype.clone = function() { return new Request(this); };
    Request.prototype.text = function() {
        if (this._bodyBytes) {
            var Buffer = require('buffer').Buffer;
            return Promise.resolve(Buffer.from(this._bodyBytes).toString('utf8'));
        }
        return Promise.resolve(this.body != null ? String(this.body) : '');
    };
    Request.prototype.json = function() {
        return this.text().then(function(s) { return JSON.parse(s); });
    };
    Request.prototype.arrayBuffer = function() {
        if (this._bodyBytes) {
            return Promise.resolve(this._bodyBytes.buffer.slice(
                this._bodyBytes.byteOffset,
                this._bodyBytes.byteOffset + this._bodyBytes.byteLength));
        }
        var Buffer = require('buffer').Buffer;
        var s = this.body != null ? String(this.body) : '';
        return Promise.resolve(Buffer.from(s, 'utf8').buffer);
    };
    Request.prototype.bytes = function() {
        return this.arrayBuffer().then(function(ab) { return new Uint8Array(ab); });
    };
    Request.prototype.blob = function() {
        var ct = (this.headers && this.headers.get && this.headers.get('content-type')) || '';
        return this.arrayBuffer().then(function(ab) { return new Blob([ab], { type: ct }); });
    };

    function Response(body, init) {
        init = init || {};
        // Body storage: prefer `_bodyB64` (authoritative raw bytes)
        // for any binary input, fall back to `_bodyText` for strings.
        // `String(uint8array)` yields `"0,97,115,…"` and corrupts
        // downstream binary consumers (e.g. `WebAssembly.instantiateStreaming(new Response(bytes))`),
        // so detect ArrayBuffer / TypedArray / Buffer up-front and
        // base64-encode the raw bytes.
        this._bodyText = '';
        this._bodyB64 = init.bodyB64 || null;
        if (body != null && this._bodyB64 === null) {
            var Buf = globalThis.Buffer || require('buffer').Buffer;
            if (body instanceof ArrayBuffer) {
                this._bodyB64 = Buf.from(new Uint8Array(body)).toString('base64');
            } else if (ArrayBuffer.isView(body)) {
                // Uint8Array / DataView / other typed arrays — copy the
                // underlying bytes (respecting byteOffset / length).
                var u8 = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
                this._bodyB64 = Buf.from(u8).toString('base64');
            } else if (Buf.isBuffer && Buf.isBuffer(body)) {
                this._bodyB64 = body.toString('base64');
            } else {
                this._bodyText = String(body);
            }
        }
        this.status = init.status !== undefined ? init.status : 200;
        this.statusText = init.statusText || '';
        this.ok = this.status >= 200 && this.status < 300;
        this.headers = new Headers(init.headers);
        this.url = init.url || '';
        this.bodyUsed = false;
    }
    Response.prototype.text = function() {
        if (this.bodyUsed) return Promise.reject(new TypeError('Body already consumed'));
        this.bodyUsed = true;
        // Decode base64 → utf8 when binary bytes are authoritative so
        // text() sees proper decoded characters rather than the lossy
        // roundtrip.
        if (this._bodyB64 !== null) {
            var Buffer = require('buffer').Buffer;
            return Promise.resolve(Buffer.from(this._bodyB64, 'base64').toString('utf8'));
        }
        return Promise.resolve(this._bodyText);
    };
    Response.prototype.json = function() {
        return this.text().then(function(s) { return JSON.parse(s); });
    };
    Response.prototype.arrayBuffer = function() {
        if (this.bodyUsed) return Promise.reject(new TypeError('Body already consumed'));
        this.bodyUsed = true;
        var Buffer = require('buffer').Buffer;
        // `bodyB64` roundtrips binary losslessly; fall back to utf8
        // encode of the text view when the host didn't provide it.
        if (this._bodyB64 !== null) {
            var buf = Buffer.from(this._bodyB64, 'base64');
            return Promise.resolve(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length));
        }
        return Promise.resolve(Buffer.from(this._bodyText, 'utf8').buffer);
    };
    /// `Response.prototype.bytes()` — Node 22+ shortcut that returns
    /// a Uint8Array view of the body. Avoids the arrayBuffer ↔ view
    /// round-trip dance for the common "give me bytes" case.
    Response.prototype.bytes = function() {
        return this.arrayBuffer().then(function(ab) { return new Uint8Array(ab); });
    };
    Response.prototype.blob = function() {
        var ct = (this.headers && this.headers.get && this.headers.get('content-type')) || '';
        return this.arrayBuffer().then(function(ab) {
            return new Blob([ab], { type: ct });
        });
    };
    Response.prototype.formData = function() {
        var ct = (this.headers && this.headers.get && this.headers.get('content-type')) || '';
        if (ct.indexOf('application/x-www-form-urlencoded') === -1 &&
            ct.indexOf('multipart/form-data') === -1) {
            return Promise.reject(new TypeError(
                'Response.formData: Content-Type is not application/x-www-form-urlencoded or multipart/form-data'));
        }
        return this.text().then(function(s) {
            var fd = new FormData();
            var sp = new URLSearchParams(s);
            sp.forEach(function(v, k) { fd.append(k, v); });
            return fd;
        });
    };
    Response.prototype.clone = function() {
        var r = new Response(this._bodyText, {
            status: this.status,
            statusText: this.statusText,
            headers: this.headers,
            url: this.url,
            bodyB64: this._bodyB64,
        });
        return r;
    };
    /// Response.json(data, init) — Node 18.0+. Serialises `data` and
    /// returns a Response with `Content-Type: application/json`.
    Response.json = function(data, init) {
        init = init || {};
        var headers = new Headers(init.headers || {});
        if (!headers.has('content-type')) {
            headers.set('content-type', 'application/json');
        }
        return new Response(JSON.stringify(data), {
            status: init.status,
            statusText: init.statusText,
            headers: headers,
            url: init.url,
        });
    };
    /// Response.error() — Node 18.0+. Synthesises a network-error
    /// response: status 0, empty body, type 'error'.
    Response.error = function() {
        var r = new Response('', { status: 0, statusText: '' });
        r.type = 'error';
        return r;
    };
    /// Response.redirect(url, status) — Node 18.0+. Returns a Response
    /// with the URL in `Location:` and the given redirect status.
    Response.redirect = function(url, status) {
        status = status || 302;
        if (status < 300 || status >= 400) {
            throw new RangeError('Response.redirect: invalid status ' + status);
        }
        return new Response('', {
            status: status,
            headers: { Location: String(url) },
        });
    };

    function fetch(input, init) {
        var req = input instanceof Request ? input : new Request(input, init);
        if (req.signal && req.signal.aborted) {
            return Promise.reject(req.signal.reason || new Error('Aborted'));
        }
        // Resolve `blob:burn/...` URLs against the local blob URL
        // registry (populated by `URL.createObjectURL(blob)`). No
        // network capability needed since the bytes are already
        // in-memory.
        if (req.url && req.url.indexOf('blob:') === 0
            && typeof globalThis.__ab_resolve_blob_url === 'function') {
            var blob = globalThis.__ab_resolve_blob_url(req.url);
            if (!blob) {
                return Promise.reject(new TypeError(
                    'fetch: blob URL ' + req.url + ' has been revoked or never existed'
                ));
            }
            return blob.arrayBuffer().then(function(buf) {
                var bytes = new Uint8Array(buf);
                var b64;
                try {
                    var Buf = globalThis.Buffer || require('buffer').Buffer;
                    b64 = Buf.from(bytes).toString('base64');
                } catch (_) { b64 = null; }
                var resp = new Response('', {
                    status: 200,
                    url: req.url,
                    bodyB64: b64,
                });
                if (blob.type) {
                    resp.headers.set('content-type', blob.type);
                }
                return resp;
            });
        }
        if (typeof globalThis.__host_http_request !== 'function') {
            return Promise.reject(new Error('fetch: net capability not granted'));
        }
        var raw;
        if (typeof globalThis.__host_http_request_v2 === 'function') {
            // v2: request headers travel with the request (the legacy
            // import drops them) and the body — string or binary — is
            // base64-framed so the host sends the exact original bytes.
            var BufB = globalThis.Buffer || require('buffer').Buffer;
            var bodyB64 = '';
            if (req._bodyBytes && req._bodyBytes.length) {
                bodyB64 = BufB.from(req._bodyBytes).toString('base64');
            } else if (req.body != null && req.body !== '') {
                bodyB64 = BufB.from(String(req.body), 'utf8').toString('base64');
            }
            raw = globalThis.__host_http_request_v2(
                req.method, req.url, JSON.stringify(req.headers._m), bodyB64);
        } else if (req._bodyBytes && req._bodyBytes.length) {
            return Promise.reject(new Error(
                'fetch: this host does not support binary request bodies'));
        } else {
            raw = globalThis.__host_http_request(req.method, req.url, req.body);
        }
        var parsed;
        try { parsed = JSON.parse(raw); }
        catch (e) { return Promise.reject(new Error('fetch: malformed host response: ' + e.message)); }
        if (typeof parsed.body === 'string' && parsed.body.indexOf('__HOST_ERR__:') === 0) {
            return Promise.reject(new Error('fetch: ' + parsed.body.slice('__HOST_ERR__:'.length)));
        }
        var resp = new Response(parsed.body, {
            status: parsed.status,
            url: req.url,
            bodyB64: parsed.body_b64 || null,
        });
        return Promise.resolve(resp);
    }

    globalThis.fetch = fetch;
    globalThis.Headers = Headers;
    globalThis.Request = Request;
    globalThis.Response = Response;
})();
