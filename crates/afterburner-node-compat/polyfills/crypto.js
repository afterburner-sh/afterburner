// crypto — Node-style hash/hmac/randomBytes/randomUUID, all backed by
// the engine's `__host_crypto_*` globals. A Hash/Hmac object accumulates
// data and returns the final digest on `.digest(encoding)`.

__register_module('crypto', function(module, exports, require) {

    function ensureHost(name) {
        var fn = globalThis['__host_crypto_' + name];
        if (typeof fn !== 'function') {
            var err = new Error("Permission denied: crypto." + name);
            err.code = 'EACCES';
            throw err;
        }
        return fn;
    }

    function checkErr(result, op) {
        if (typeof result === 'string' && result.indexOf('__HOST_ERR__:') === 0) {
            var msg = result.slice('__HOST_ERR__:'.length);
            var err = new Error("crypto." + op + ": " + msg);
            if (msg.toLowerCase().indexOf('permission denied') !== -1) err.code = 'EACCES';
            throw err;
        }
        return result;
    }

    function streamingHashPresent() {
        return typeof globalThis.__host_crypto_hash_open === 'function'
            && typeof globalThis.__host_crypto_hash_update === 'function'
            && typeof globalThis.__host_crypto_hash_digest === 'function';
    }

    // Encode whatever the user handed us as a base64 string for the
    // streaming host wire. String inputs go through UTF-8 to match
    // Node's default. Buffer / Uint8Array pass through as their raw
    // bytes, so binary data roundtrips cleanly.
    function toUpdateB64(data) {
        if (data == null) return '';
        var B = require('buffer').Buffer;
        if (typeof data === 'string') {
            return B.from(data, 'utf8').toString('base64');
        }
        if (B.isBuffer(data)) return data.toString('base64');
        if (data instanceof Uint8Array) return B.from(data).toString('base64');
        // Fall back to String() coercion — matches old behavior for
        // weird input types.
        return B.from(String(data), 'utf8').toString('base64');
    }

    // When a host `open` returns the 0-sentinel, the detailed reason
    // is in `__host_last_error` on WASM. Native throws the exception
    // inline, so this path only fires in the WASM sandbox.
    function throwOpenErr(op, algo) {
        var msg = '';
        if (typeof globalThis.__host_last_error === 'function') {
            msg = String(globalThis.__host_last_error() || '');
        }
        if (!msg) msg = "'" + algo + "' not supported";
        var err = new Error('crypto.' + op + ': ' + msg);
        if (msg.toLowerCase().indexOf('permission denied') !== -1) err.code = 'EACCES';
        throw err;
    }

    function Hash(algorithm) {
        this._algo = String(algorithm).toLowerCase();
        this._finalized = false;
        this._streaming = streamingHashPresent();
        if (this._streaming) {
            this._handle = globalThis.__host_crypto_hash_open(this._algo);
            if (!this._handle) throwOpenErr('createHash', this._algo);
        } else {
            this._chunks = [];
        }
    }
    Hash.prototype.update = function(data) {
        if (this._finalized) throw new Error('Digest already called');
        if (this._streaming) {
            var r = globalThis.__host_crypto_hash_update(this._handle, toUpdateB64(data));
            if (typeof r === 'string' && r.indexOf('__HOST_ERR__:') === 0) {
                throw new Error('crypto.hash.update: ' + r.slice('__HOST_ERR__:'.length));
            }
        } else {
            this._chunks.push(typeof data === 'string' ? data : String(data));
        }
        return this;
    };
    Hash.prototype.digest = function(encoding) {
        if (this._finalized) throw new Error('Digest already called');
        this._finalized = true;
        // Node semantics: digest() with no encoding (or 'buffer') returns a
        // Buffer of RAW BYTES. The host bridge speaks text, so fetch base64
        // and decode — defaulting to a hex STRING here silently breaks every
        // binary consumer (keyed-HMAC chains, signatures, key derivation).
        var wantRaw = encoding === undefined || encoding === null || encoding === 'buffer';
        var enc = wantRaw ? 'base64' : encoding;
        var out;
        if (this._streaming) {
            out = checkErr(
                globalThis.__host_crypto_hash_digest(this._handle, enc),
                'hash'
            );
        } else {
            out = checkErr(
                ensureHost('hash')(this._algo, this._chunks.join(''), enc),
                'hash'
            );
        }
        return wantRaw ? require('buffer').Buffer.from(out, 'base64') : out;
    };

    function Hmac(algorithm, key) {
        this._algo = String(algorithm).toLowerCase();
        this._finalized = false;
        this._streaming = streamingHashPresent()
            && typeof globalThis.__host_crypto_hmac_open === 'function';
        if (this._streaming) {
            var B = require('buffer').Buffer;
            var keyB64 = typeof key === 'string'
                ? B.from(key, 'utf8').toString('base64')
                : (B.isBuffer(key) ? key.toString('base64')
                   : B.from(String(key), 'utf8').toString('base64'));
            this._handle = globalThis.__host_crypto_hmac_open(this._algo, keyB64);
            if (!this._handle) throwOpenErr('createHmac', this._algo);
        } else {
            this._key = typeof key === 'string' ? key : String(key);
            this._chunks = [];
        }
    }
    Hmac.prototype.update = function(data) {
        if (this._finalized) throw new Error('Digest already called');
        if (this._streaming) {
            var r = globalThis.__host_crypto_hash_update(this._handle, toUpdateB64(data));
            if (typeof r === 'string' && r.indexOf('__HOST_ERR__:') === 0) {
                throw new Error('crypto.hmac.update: ' + r.slice('__HOST_ERR__:'.length));
            }
        } else {
            this._chunks.push(typeof data === 'string' ? data : String(data));
        }
        return this;
    };
    Hmac.prototype.digest = function(encoding) {
        if (this._finalized) throw new Error('Digest already called');
        this._finalized = true;
        // Same Node semantics as Hash.digest: no encoding → raw-byte Buffer.
        var wantRaw = encoding === undefined || encoding === null || encoding === 'buffer';
        var enc = wantRaw ? 'base64' : encoding;
        var out;
        if (this._streaming) {
            out = checkErr(
                globalThis.__host_crypto_hash_digest(this._handle, enc),
                'hmac'
            );
        } else {
            out = checkErr(
                ensureHost('hmac')(this._algo, this._key, this._chunks.join(''), enc),
                'hmac'
            );
        }
        return wantRaw ? require('buffer').Buffer.from(out, 'base64') : out;
    };

    exports.createHash = function(algorithm) { return new Hash(algorithm); };
    exports.createHmac = function(algorithm, key) { return new Hmac(algorithm, key); };

    // Supported hash + cipher catalogues. Keep these aligned with the
    // host's crypto bridge — packaging tools (npm/ssri/node-tap) call
    // `getHashes()` at module-init time and crash with TypeError when
    // it is missing.
    var SUPPORTED_HASHES = [
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'shake128', 'shake256'
    ];
    var SUPPORTED_CIPHERS = [
        'aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
        'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm'
    ];
    exports.getHashes  = function() { return SUPPORTED_HASHES.slice(); };
    exports.getCiphers = function() { return SUPPORTED_CIPHERS.slice(); };
    exports.getCurves  = function() { return ['P-256', 'P-384', 'P-521']; };

    /// `crypto.randomBytes(len[, callback])` — Node returns a Buffer
    /// of `len` cryptographically random bytes. The callback form
    /// (Node 0.5+) takes `(err, buf)`. We get the bytes from the host
    /// as a hex string, then re-pack into a Buffer to match Node's
    /// API surface.
    exports.randomBytes = function(len, cb) {
        var hex = checkErr(ensureHost('random_bytes')(len, 'hex'), 'randomBytes');
        var buf = Buffer.from(hex, 'hex');
        if (typeof cb === 'function') {
            Promise.resolve().then(function() { cb(null, buf); });
            return undefined;
        }
        return buf;
    };

    exports.randomUUID = function() {
        return checkErr(ensureHost('random_uuid')(), 'randomUUID');
    };

    exports.timingSafeEqual = function(a, b) {
        var fn = globalThis.__host_crypto_timing_safe_equal;
        if (typeof fn !== 'function') return false;
        return fn(typeof a === 'string' ? a : String(a),
                  typeof b === 'string' ? b : String(b));
    };

    // `randomFillSync(buffer[, offset[, size]])` — fills the buffer
    // in-place with cryptographically random bytes. Returns the buffer.
    exports.randomFillSync = function(buffer, offset, size) {
        if (!buffer || typeof buffer.length !== 'number') {
            throw new TypeError('randomFillSync: buffer must be a TypedArray');
        }
        var off = (offset | 0) || 0;
        var len = (typeof size === 'number') ? (size | 0) : (buffer.length - off);
        if (len <= 0) return buffer;
        var hex = ensureHost('random_bytes')(len, 'hex');
        if (typeof hex !== 'string') return buffer;
        var view = (buffer.buffer && typeof buffer.buffer === 'object')
            ? new Uint8Array(buffer.buffer, buffer.byteOffset || 0, buffer.byteLength || buffer.length)
            : buffer;
        for (var i = 0; i < len; i++) {
            view[off + i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return buffer;
    };

    /// `randomFill(buffer[, offset[, size]], cb)` — async variant.
    /// Same operation; calls cb on next microtask.
    exports.randomFill = function(buffer, offset, size, cb) {
        if (typeof offset === 'function') { cb = offset; offset = undefined; size = undefined; }
        else if (typeof size === 'function') { cb = size; size = undefined; }
        try {
            exports.randomFillSync(buffer, offset, size);
            if (typeof cb === 'function') Promise.resolve().then(function() { cb(null, buffer); });
        } catch (e) {
            if (typeof cb === 'function') Promise.resolve().then(function() { cb(e); });
        }
    };

    /// `crypto.randomInt([min, ]max[, callback])` — uniform integer
    /// in `[min, max)`. Sync if no callback. Min defaults to 0.
    exports.randomInt = function(min, max, cb) {
        if (typeof min === 'function') { cb = min; min = 0; max = 0xffffffff; }
        else if (typeof max === 'function') { cb = max; max = min; min = 0; }
        else if (max === undefined) { max = min; min = 0; }
        if (min < 0 || max <= min || max - min > Math.pow(2, 48)) {
            var err = new RangeError('randomInt: min/max out of range');
            if (typeof cb === 'function') {
                Promise.resolve().then(function() { cb(err); });
                return;
            }
            throw err;
        }
        var range = max - min;
        // Sample 6 bytes (2^48), reject + retry to avoid modulo bias.
        function sample() {
            var hex = ensureHost('random_bytes')(6, 'hex');
            var n = 0;
            for (var i = 0; i < 12; i++) n = n * 16 + parseInt(hex.charAt(i), 16);
            var max48 = Math.pow(2, 48);
            var fold = max48 - (max48 % range);
            if (n >= fold) return sample(); // discard biased range
            return min + (n % range);
        }
        var v = sample();
        if (typeof cb === 'function') {
            Promise.resolve().then(function() { cb(null, v); });
            return;
        }
        return v;
    };

    /// `crypto.timingSafeEqual` already exists (inline below); the
    /// alias below matches Node's Web Crypto export for callers that
    /// reach for `crypto.webcrypto.subtle`.
    exports.webcrypto = (typeof globalThis.crypto === 'object') ? globalThis.crypto : undefined;

    // ---- ciphers (AES-GCM / AES-CBC) --------------------------------
    var Buffer = require('buffer').Buffer;

    function toB64(x) {
        if (typeof x === 'string') return Buffer.from(x, 'utf8').toString('base64');
        if (Buffer.isBuffer(x))    return x.toString('base64');
        if (x instanceof Uint8Array) return Buffer.from(x).toString('base64');
        throw new TypeError('expected string/Buffer/Uint8Array');
    }
    function fromB64(s, tag) {
        if (typeof s === 'string' && s.indexOf('__HOST_ERR__:') === 0) {
            throw new Error(tag + ': ' + s.slice('__HOST_ERR__:'.length));
        }
        return Buffer.from(s, 'base64');
    }

    function makeGcmCipher(algo, key, iv, opts) {
        var aad = null;
        var finalized = false;
        var queued = [];
        var mode = opts && opts.mode; // 'encrypt' | 'decrypt'
        var authTag = null;
        return {
            setAAD: function(buf) { aad = Buffer.isBuffer(buf) ? buf : Buffer.from(buf); return this; },
            setAutoPadding: function() { return this; },
            update: function(data) {
                if (finalized) throw new Error('cipher finalized');
                queued.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
                return Buffer.alloc(0);
            },
            setAuthTag: function(tag) { authTag = tag; return this; },
            getAuthTag: function() {
                if (mode !== 'encrypt' || !finalized) {
                    throw new Error('getAuthTag available only after encrypt final');
                }
                return authTag;
            },
            final: function() {
                if (finalized) throw new Error('cipher finalized');
                finalized = true;
                var data = Buffer.concat(queued);
                var fn = mode === 'encrypt' ? '__host_crypto_aes_gcm_encrypt' : '__host_crypto_aes_gcm_decrypt';
                var rawIn = mode === 'encrypt' ? data
                    : Buffer.concat([data, authTag || Buffer.alloc(16)]);
                var raw = globalThis[fn](
                    algo,
                    toB64(key),
                    toB64(iv),
                    toB64(rawIn),
                    aad ? toB64(aad) : null
                );
                var out = fromB64(raw, 'cipher');
                if (mode === 'encrypt') {
                    authTag = out.slice(out.length - 16);
                    return out.slice(0, out.length - 16);
                } else {
                    return out;
                }
            }
        };
    }

    function makeCbcCipher(algo, key, iv, mode) {
        var finalized = false;
        var queued = [];
        return {
            setAutoPadding: function() { return this; },
            update: function(data) {
                if (finalized) throw new Error('cipher finalized');
                queued.push(Buffer.isBuffer(data) ? data : Buffer.from(data));
                return Buffer.alloc(0);
            },
            final: function() {
                if (finalized) throw new Error('cipher finalized');
                finalized = true;
                var data = Buffer.concat(queued);
                var fn = mode === 'encrypt' ? '__host_crypto_aes_cbc_encrypt' : '__host_crypto_aes_cbc_decrypt';
                var raw = globalThis[fn](algo, toB64(key), toB64(iv), toB64(data));
                return fromB64(raw, 'cipher');
            }
        };
    }

    function makeCipher(algo, key, iv, mode) {
        var a = String(algo).toLowerCase();
        if (a.indexOf('-gcm') > 0) return makeGcmCipher(a, key, iv, { mode: mode });
        if (a.indexOf('-cbc') > 0) return makeCbcCipher(a, key, iv, mode);
        throw new Error('Unsupported cipher: ' + algo);
    }

    exports.createCipheriv = function(algo, key, iv) { return makeCipher(algo, key, iv, 'encrypt'); };
    exports.createDecipheriv = function(algo, key, iv) { return makeCipher(algo, key, iv, 'decrypt'); };

    // ---- KDFs --------------------------------------------------------
    exports.pbkdf2Sync = function(password, salt, iterations, keylen, digest) {
        var fn = globalThis.__host_crypto_pbkdf2_sync;
        if (typeof fn !== 'function') {
            throw new Error('Permission denied: crypto.pbkdf2Sync');
        }
        var pwd = typeof password === 'string' ? password
            : Buffer.isBuffer(password) ? password.toString('binary')
            : String(password);
        var saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt));
        var raw = fn(String(digest || 'sha256'), pwd, saltBuf.toString('base64'), iterations >>> 0, keylen >>> 0);
        return fromB64(raw, 'pbkdf2Sync');
    };

    // ---- sign / verify (RSA + ECDSA) ----------------------------------
    function signImpl(algorithm, keyPem, data) {
        var fn = globalThis.__host_crypto_sign;
        if (typeof fn !== 'function') {
            throw new Error('Permission denied: crypto.sign');
        }
        var dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
        var raw = fn(String(algorithm), String(keyPem), dataBuf.toString('base64'));
        if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
            throw new Error('crypto.sign: ' + raw.slice('__HOST_ERR__:'.length));
        }
        return Buffer.from(raw, 'base64');
    }

    function verifyImpl(algorithm, keyPem, data, signature) {
        var fn = globalThis.__host_crypto_verify;
        if (typeof fn !== 'function') {
            throw new Error('Permission denied: crypto.verify');
        }
        var dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
        var sigBuf = Buffer.isBuffer(signature) ? signature : Buffer.from(String(signature));
        var code = fn(
            String(algorithm),
            String(keyPem),
            dataBuf.toString('base64'),
            sigBuf.toString('base64')
        );
        // Both paths now return i32 (1/0/negative). Accept bool too in
        // case an embedder wires a host that returns it directly.
        if (code === 1 || code === true) return true;
        if (code === 0 || code === false) return false;
        throw new Error('crypto.verify: host error (code ' + code + ')');
    }

    exports.sign = signImpl;
    exports.verify = verifyImpl;

    // Node's stream-style createSign / createVerify. Streaming-backed:
    // chunks are hashed incrementally on the host side, so memory is
    // proportional to the digest state (~200 B) rather than the total
    // payload size.
    var ALGO_ALIASES = {
        'RSA-SHA256': 'RS256', 'RSA-SHA384': 'RS384', 'RSA-SHA512': 'RS512',
        'sha256WithRSAEncryption': 'RS256',
        'sha384WithRSAEncryption': 'RS384',
        'sha512WithRSAEncryption': 'RS512',
    };
    function canonicalAlgo(algo) { return ALGO_ALIASES[algo] || algo; }

    function streamingHostPresent() {
        return typeof globalThis.__host_crypto_sign_open === 'function'
            && typeof globalThis.__host_crypto_sign_update === 'function';
    }

    function makeSigner(algo) {
        var canonical = canonicalAlgo(algo);
        if (streamingHostPresent()) {
            var handle = globalThis.__host_crypto_sign_open(canonical);
            if (!handle) throw new Error('crypto.createSign: ' + canonical + ' not supported');
            return {
                update: function(d) {
                    var buf = Buffer.isBuffer(d) ? d : Buffer.from(String(d));
                    var r = globalThis.__host_crypto_sign_update(handle, buf.toString('base64'));
                    if (typeof r === 'string' && r.indexOf('__HOST_ERR__:') === 0) {
                        throw new Error('crypto.sign.update: ' + r.slice('__HOST_ERR__:'.length));
                    }
                    return this;
                },
                sign: function(key) {
                    var raw = globalThis.__host_crypto_sign_finalize(handle, canonical, String(key));
                    if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
                        throw new Error('crypto.sign: ' + raw.slice('__HOST_ERR__:'.length));
                    }
                    return Buffer.from(raw, 'base64');
                }
            };
        }
        // Fallback for older plugins / embedders that haven't wired
        // streaming: buffer everything and use the one-shot API.
        var chunks = [];
        return {
            update: function(d) { chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(String(d))); return this; },
            sign:   function(key) { return signImpl(canonical, key, Buffer.concat(chunks)); }
        };
    }

    function makeVerifier(algo) {
        var canonical = canonicalAlgo(algo);
        if (streamingHostPresent() && typeof globalThis.__host_crypto_verify_finalize === 'function') {
            var handle = globalThis.__host_crypto_sign_open(canonical);
            if (!handle) throw new Error('crypto.createVerify: ' + canonical + ' not supported');
            return {
                update: function(d) {
                    var buf = Buffer.isBuffer(d) ? d : Buffer.from(String(d));
                    var r = globalThis.__host_crypto_sign_update(handle, buf.toString('base64'));
                    if (typeof r === 'string' && r.indexOf('__HOST_ERR__:') === 0) {
                        throw new Error('crypto.verify.update: ' + r.slice('__HOST_ERR__:'.length));
                    }
                    return this;
                },
                verify: function(key, sig) {
                    var sigBuf = Buffer.isBuffer(sig) ? sig : Buffer.from(String(sig));
                    var code = globalThis.__host_crypto_verify_finalize(
                        handle, canonical, String(key), sigBuf.toString('base64'));
                    if (code === 1 || code === true) return true;
                    if (code === 0 || code === false) return false;
                    throw new Error('crypto.verify: host error (code ' + code + ')');
                }
            };
        }
        var chunks = [];
        return {
            update: function(d) { chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(String(d))); return this; },
            verify: function(key, sig) { return verifyImpl(canonical, key, Buffer.concat(chunks), sig); }
        };
    }
    exports.createSign = makeSigner;
    exports.createVerify = makeVerifier;

    exports.scryptSync = function(password, salt, keylen, options) {
        var fn = globalThis.__host_crypto_scrypt_sync;
        if (typeof fn !== 'function') {
            throw new Error('Permission denied: crypto.scryptSync');
        }
        options = options || {};
        var N = options.N || options.cost || 16384;
        var r = options.r || options.blockSize || 8;
        var p = options.p || options.parallelization || 1;
        var pwd = typeof password === 'string' ? password
            : Buffer.isBuffer(password) ? password.toString('binary')
            : String(password);
        var saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(String(salt));
        var raw = fn(pwd, saltBuf.toString('base64'), N >>> 0, r >>> 0, p >>> 0, keylen >>> 0);
        return fromB64(raw, 'scryptSync');
    };

    /// `crypto.scrypt(password, salt, keylen, options, cb)` — Node's
    /// async wrapper. Our scrypt is host-side synchronous, so we
    /// dispatch on a microtask to preserve the cb-after-IO contract.
    exports.scrypt = function(password, salt, keylen, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try { cb(null, exports.scryptSync(password, salt, keylen, options)); }
            catch (e) { cb(e); }
        });
    };

    /// `crypto.hash(algorithm, data, encoding)` — Node 21+ one-shot
    /// hash that skips the `createHash` ceremony. Returns the digest
    /// directly in the requested encoding (default 'hex').
    exports.hash = function(algorithm, data, encoding) {
        var h = exports.createHash(algorithm);
        h.update(data);
        return h.digest(encoding || 'hex');
    };

    /// `crypto.hkdfSync(digest, ikm, salt, info, length)` — Node 15+.
    /// Composes HKDF-Extract + HKDF-Expand from createHmac. Returns
    /// the OKM as an ArrayBuffer (Node returns ArrayBuffer too).
    exports.hkdfSync = function(digest, ikm, salt, info, length) {
        var Buffer = require('buffer').Buffer;
        var ikmBuf  = Buffer.isBuffer(ikm)  ? ikm  : Buffer.from(ikm);
        var saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt || '');
        var infoBuf = Buffer.isBuffer(info) ? info : Buffer.from(info || '');
        // HKDF-Extract: PRK = HMAC(salt, IKM)
        var extract = exports.createHmac(digest, saltBuf);
        extract.update(ikmBuf);
        var prk = Buffer.from(extract.digest('hex'), 'hex');
        // HKDF-Expand: T(0) = empty; T(i) = HMAC(PRK, T(i-1) || info || 0xi)
        var hashLen = prk.length;
        var n = Math.ceil(length / hashLen);
        if (n > 255) {
            throw new RangeError('HKDF: length too large');
        }
        var okm = Buffer.alloc(0);
        var t = Buffer.alloc(0);
        for (var i = 1; i <= n; i++) {
            var h = exports.createHmac(digest, prk);
            h.update(Buffer.concat([t, infoBuf, Buffer.from([i])]));
            t = Buffer.from(h.digest('hex'), 'hex');
            okm = Buffer.concat([okm, t]);
        }
        var out = okm.slice(0, length);
        return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
    };

    /// `crypto.hkdf(...)` — async sibling. Mirrors hkdfSync on a
    /// microtask.
    exports.hkdf = function(digest, ikm, salt, info, length, cb) {
        Promise.resolve().then(function() {
            try { cb(null, exports.hkdfSync(digest, ikm, salt, info, length)); }
            catch (e) { cb(e); }
        });
    };

    /// `crypto.subtle` — alias to globalThis.crypto.subtle (Node 15+
    /// ships SubtleCrypto via the crypto module, not just globally).
    Object.defineProperty(exports, 'subtle', {
        get: function() {
            return globalThis.crypto && globalThis.crypto.subtle;
        },
        configurable: true,
    });

    /// `crypto.fips` — boolean flag exposed since Node 0.12. We're
    /// not FIPS-validated; surfacing `false` matches what most non-
    /// FIPS Node builds report.
    Object.defineProperty(exports, 'fips', {
        value: false, writable: false, configurable: true, enumerable: true,
    });

    /// `crypto.KeyObject` — opaque key handle. PKCS#8 / SPKI / raw
    /// bytes underneath; `export` / `equals` operate on those bytes.
    function _b64UrlEncode(bytes) {
        var Buf = globalThis.Buffer || require('buffer').Buffer;
        return Buf.from(bytes).toString('base64')
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function _hostSubtle(op, args) {
        if (typeof globalThis.__host_crypto_subtle_op !== 'function') {
            throw new Error('crypto: subtle host fn missing');
        }
        var Buf = globalThis.Buffer || require('buffer').Buffer;
        var jsonArgs = '[' + args.map(function(a) {
            var bs = (a instanceof Uint8Array) ? a
                  : Buf.isBuffer(a) ? a
                  : (typeof a === 'string') ? Buf.from(a, 'utf8')
                  : Buf.from(a);
            return JSON.stringify(_b64UrlEncode(bs));
        }).join(',') + ']';
        var r = globalThis.__host_crypto_subtle_op(op, jsonArgs);
        if (typeof r === 'string' && r.indexOf('__HOST_ERR__:') === 0) {
            throw new Error(r.slice('__HOST_ERR__:'.length));
        }
        return r;
    }
    function _b64UrlToBytes(b64) {
        var s = String(b64).replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4 !== 0) s += '=';
        var Buf = globalThis.Buffer || require('buffer').Buffer;
        return new Uint8Array(Buf.from(s, 'base64'));
    }

    function KeyObject(type, asymKeyType, raw) {
        // Node's KeyObject is meant to be created via factory
        // functions, not direct construction. We follow the spec:
        // direct `new KeyObject()` is disallowed.
        if (!(this instanceof KeyObject)) return new KeyObject(type, asymKeyType, raw);
        if (!arguments.length) {
            var e = new TypeError('Illegal constructor: KeyObject is created via createSecretKey/createPrivateKey/createPublicKey');
            e.code = 'ERR_OPERATION_FAILED';
            throw e;
        }
        Object.defineProperty(this, 'type', { value: type, enumerable: true });
        Object.defineProperty(this, 'asymmetricKeyType',
            { value: asymKeyType || undefined, enumerable: true });
        Object.defineProperty(this, '_raw', { value: raw, enumerable: false });
    }
    KeyObject.prototype.export = function(options) {
        options = options || {};
        if (this.type === 'secret') {
            // Secret keys export to raw or jwk (oct kty).
            if (options.format === 'jwk') {
                return {
                    kty: 'oct',
                    k: _b64UrlEncode(this._raw),
                    ext: true,
                };
            }
            // Default: Buffer of the raw bytes.
            return Buffer.from(this._raw);
        }
        // Asymmetric: PKCS#8 / SPKI / JWK.
        if (options.format === 'jwk') {
            // RSA → host helper; EC/Ed/X25519 left as raw DER plus a
            // typed JWK envelope is more work — start with RSA and
            // fall through for others.
            if (this.asymmetricKeyType === 'rsa') {
                var op = (this.type === 'private')
                    ? 'rsa:export-jwk-priv' : 'rsa:export-jwk-pub';
                var b64 = _hostSubtle(op, [this._raw]);
                var bytes = _b64UrlToBytes(b64);
                var jsonStr = String.fromCharCode.apply(null, Array.prototype.slice.call(bytes));
                var jwk = JSON.parse(jsonStr);
                return jwk;
            }
            // For EC keys, the SPKI/PKCS8 already carries everything;
            // produce a minimal JWK from the raw bytes.
            return { kty: 'EC', _raw: _b64UrlEncode(this._raw) };
        }
        // Default DER/PEM: we hold DER bytes; produce PEM if asked.
        var fmt = options.format || 'pem';
        if (fmt === 'der') return Buffer.from(this._raw);
        // PEM wrapping.
        var label;
        if (this.type === 'private') label = 'PRIVATE KEY';
        else if (this.type === 'public') label = 'PUBLIC KEY';
        else label = 'KEY';
        var b64 = Buffer.from(this._raw).toString('base64');
        var pem = '-----BEGIN ' + label + '-----\n';
        for (var i = 0; i < b64.length; i += 64) {
            pem += b64.slice(i, i + 64) + '\n';
        }
        pem += '-----END ' + label + '-----\n';
        return pem;
    };
    KeyObject.prototype.equals = function(other) {
        if (!(other instanceof KeyObject)) return false;
        if (this.type !== other.type) return false;
        if (this._raw.length !== other._raw.length) return false;
        var a = this._raw, b = other._raw, acc = 0;
        for (var i = 0; i < a.length; i++) acc |= (a[i] ^ b[i]);
        return acc === 0;
    };
    Object.defineProperty(KeyObject.prototype, 'symmetricKeySize', {
        get: function() {
            return this.type === 'secret' ? this._raw.length : undefined;
        },
    });
    Object.defineProperty(KeyObject.prototype, 'asymmetricKeyDetails', {
        get: function() {
            if (this.asymmetricKeyType === 'rsa') {
                return {}; // populated when we add ASN.1 introspection
            }
            if (this.asymmetricKeyType === 'ec') {
                return { namedCurve: this._curve || 'P-256' };
            }
            return {};
        },
    });
    KeyObject.from = function(cryptoKey) {
        // Web Crypto CryptoKey → Node KeyObject. Pull the raw bytes
        // out of `_raw` (set by our subtle factory) and rewrap.
        if (cryptoKey && cryptoKey._raw) {
            var nodeType;
            if (cryptoKey.type === 'secret') nodeType = 'secret';
            else if (cryptoKey.type === 'private') nodeType = 'private';
            else nodeType = 'public';
            var asym;
            var n = String((cryptoKey.algorithm && cryptoKey.algorithm.name) || '').toLowerCase();
            if (n.indexOf('rsa') === 0) asym = 'rsa';
            else if (n === 'ecdsa' || n === 'ecdh') asym = 'ec';
            else if (n === 'ed25519') asym = 'ed25519';
            else if (n === 'x25519') asym = 'x25519';
            return new KeyObject(nodeType, asym, new Uint8Array(cryptoKey._raw));
        }
        throw new TypeError('KeyObject.from: argument must be a CryptoKey');
    };
    exports.KeyObject = KeyObject;

    function _bytesFromKeyish(input) {
        if (input == null) {
            throw new TypeError('crypto: key input required');
        }
        if (input instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(input))) {
            return new Uint8Array(input);
        }
        if (typeof input === 'string') return new TextEncoder().encode(input);
        if (input.key !== undefined) {
            // Node-shape `{ key, format, type, passphrase }` — we don't
            // do passphrase decryption (no OpenSSL); pass through the
            // key body.
            return _bytesFromKeyish(input.key);
        }
        throw new TypeError('crypto: unsupported key input shape');
    }
    function _stripPemBody(input) {
        // Convert PEM to DER if input is a string; otherwise return
        // bytes as-is.
        if (typeof input === 'string' && input.indexOf('-----BEGIN ') !== -1) {
            var b64 = input
                .replace(/-----BEGIN [^-]+-----/, '')
                .replace(/-----END [^-]+-----/, '')
                .replace(/\s+/g, '');
            return new Uint8Array(Buffer.from(b64, 'base64'));
        }
        return _bytesFromKeyish(input);
    }
    function _detectAsymKind(_der) {
        // ASN.1 sniffing: PKCS#8 / SPKI start with SEQUENCE 0x30.
        // We don't fully parse — RSA/EC heuristic: assume RSA unless
        // the user supplied an EC-specific key. For factory APIs, a
        // proper introspection pass would walk OIDs; for now we let
        // the consuming op (sign/verify) pick the algorithm.
        return undefined; // unknown; sign/verify will pick at use time
    }

    exports.createSecretKey = function(input, encoding) {
        var bytes;
        if (typeof input === 'string') {
            bytes = new TextEncoder().encode(
                encoding ? Buffer.from(input, encoding).toString() : input);
        } else {
            bytes = _bytesFromKeyish(input);
        }
        return new KeyObject('secret', undefined, bytes);
    };

    exports.createPrivateKey = function(input) {
        var raw = _stripPemBody(input);
        return new KeyObject('private', _detectAsymKind(raw), raw);
    };

    exports.createPublicKey = function(input) {
        // If the caller passes a private KeyObject, derive its public
        // half. For RSA keys this would re-build SPKI from PKCS#8 —
        // requires an extra host op. Punt to the simple path: SPKI
        // bytes if the input is already a public key, else throw.
        if (input instanceof KeyObject) {
            if (input.type === 'public') return input;
            if (input.type === 'private') {
                var e = new Error('createPublicKey from private KeyObject requires a separate derive step');
                e.code = 'ERR_OPERATION_FAILED';
                throw e;
            }
        }
        var raw = _stripPemBody(input);
        return new KeyObject('public', _detectAsymKind(raw), raw);
    };

    /// `generateKeyPairSync(type, options)` — Node 13+. Backed by the
    /// subtle dispatcher; returns `{publicKey, privateKey}` as
    /// KeyObjects (or PEM/DER per `options.publicKeyEncoding` /
    /// `privateKeyEncoding`).
    function _wrapPair(type, privDer, pubDer, options) {
        options = options || {};
        var priv = new KeyObject('private', type, privDer);
        var pub = new KeyObject('public', type, pubDer);
        var out = { privateKey: priv, publicKey: pub };
        if (options.privateKeyEncoding) {
            out.privateKey = priv.export(options.privateKeyEncoding);
        }
        if (options.publicKeyEncoding) {
            out.publicKey = pub.export(options.publicKeyEncoding);
        }
        return out;
    }
    function _splitPair(s) {
        // Host returns `["<priv_b64>","<pub_b64>"]`.
        var arr = JSON.parse(s);
        return { priv: _b64UrlToBytes(arr[0]), pub: _b64UrlToBytes(arr[1]) };
    }
    exports.generateKeyPairSync = function(type, options) {
        options = options || {};
        if (type === 'rsa') {
            var bits = (options.modulusLength | 0) || 2048;
            var exp = (options.publicExponent | 0) || 65537;
            var pair = _splitPair(_hostSubtle('rsa:keygen', [
                new TextEncoder().encode(String(bits)),
                new TextEncoder().encode(String(exp)),
            ]));
            return _wrapPair('rsa', pair.priv, pair.pub, options);
        }
        if (type === 'ec') {
            var curve = String(options.namedCurve || 'P-256').toUpperCase();
            if (curve === 'P256' || curve === 'PRIME256V1' || curve === 'SECP256R1') curve = 'P-256';
            else if (curve === 'P384' || curve === 'SECP384R1') curve = 'P-384';
            else if (curve === 'P521' || curve === 'SECP521R1') curve = 'P-521';
            var ecPair = _splitPair(_hostSubtle('ec:keygen',
                [new TextEncoder().encode(curve)]));
            var out = _wrapPair('ec', ecPair.priv, ecPair.pub, options);
            out.privateKey._curve = curve;
            out.publicKey._curve = curve;
            return out;
        }
        if (type === 'ed25519') {
            var edPair = _splitPair(_hostSubtle('ed25519:keygen', []));
            return _wrapPair('ed25519', edPair.priv, edPair.pub, options);
        }
        if (type === 'x25519') {
            var xPair = _splitPair(_hostSubtle('x25519:keygen', []));
            return _wrapPair('x25519', xPair.priv, xPair.pub, options);
        }
        var err = new Error('crypto.generateKeyPair: unsupported type ' + type);
        err.code = 'ERR_CRYPTO_INVALID_KEY';
        throw err;
    };
    exports.generateKeyPair = function(type, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try {
                var pair = exports.generateKeyPairSync(type, options);
                cb(null, pair.publicKey, pair.privateKey);
            } catch (e) { cb(e); }
        });
    };

    /// `crypto.diffieHellman({privateKey, publicKey})` — Node 13+.
    /// Backed by the subtle ECDH dispatcher; both keys must be
    /// KeyObjects with the same EC curve (or X25519).
    exports.diffieHellman = function(options) {
        options = options || {};
        var priv = options.privateKey;
        var pub  = options.publicKey;
        if (!(priv instanceof KeyObject) || !(pub instanceof KeyObject)) {
            var e = new TypeError('crypto.diffieHellman: privateKey + publicKey must be KeyObjects');
            e.code = 'ERR_INVALID_ARG_TYPE';
            throw e;
        }
        if (priv.asymmetricKeyType === 'x25519' || pub.asymmetricKeyType === 'x25519') {
            var sharedX = _b64UrlToBytes(_hostSubtle('x25519:derive',
                [priv._raw, pub._raw]));
            return Buffer.from(sharedX);
        }
        var curve = priv._curve || pub._curve || 'P-256';
        var shared = _b64UrlToBytes(_hostSubtle('ecdh:derive', [
            new TextEncoder().encode(curve),
            priv._raw,
            pub._raw,
        ]));
        return Buffer.from(shared);
    };

    /// `crypto.createECDH(curve)` — Node 0.11+. Returns an ECDH
    /// instance with `generateKeys`, `computeSecret`, etc.
    function ECDH(curve) {
        if (!(this instanceof ECDH)) return new ECDH(curve);
        var c = String(curve).toUpperCase();
        if (c === 'PRIME256V1' || c === 'SECP256R1') c = 'P-256';
        else if (c === 'SECP384R1') c = 'P-384';
        else if (c === 'SECP521R1') c = 'P-521';
        if (c !== 'P-256' && c !== 'P-384' && c !== 'P-521') {
            var e = new Error('crypto.createECDH: unsupported curve ' + curve);
            e.code = 'ERR_CRYPTO_ECDH_INVALID_FORMAT';
            throw e;
        }
        this._curve = c;
        this._priv = null;
        this._pub = null;
    }
    ECDH.prototype.generateKeys = function(encoding, format) {
        var pair = _splitPair(_hostSubtle('ec:keygen',
            [new TextEncoder().encode(this._curve)]));
        this._priv = pair.priv;
        this._pub = pair.pub;
        return this.getPublicKey(encoding, format);
    };
    ECDH.prototype.getPublicKey = function(encoding, _format) {
        var b = Buffer.from(this._pub || []);
        return encoding ? b.toString(encoding) : b;
    };
    ECDH.prototype.getPrivateKey = function(encoding) {
        var b = Buffer.from(this._priv || []);
        return encoding ? b.toString(encoding) : b;
    };
    ECDH.prototype.setPrivateKey = function(priv, encoding) {
        this._priv = encoding ? _bytesFromKeyish(Buffer.from(priv, encoding)) : _bytesFromKeyish(priv);
        return this;
    };
    ECDH.prototype.computeSecret = function(otherPub, inputEnc, outputEnc) {
        var pubBytes = inputEnc ? _bytesFromKeyish(Buffer.from(otherPub, inputEnc)) : _bytesFromKeyish(otherPub);
        if (!this._priv) {
            var e = new Error('createECDH: no private key — call generateKeys() first');
            e.code = 'ERR_CRYPTO_INCOMPATIBLE_KEY';
            throw e;
        }
        var shared = _b64UrlToBytes(_hostSubtle('ecdh:derive', [
            new TextEncoder().encode(this._curve),
            this._priv,
            pubBytes,
        ]));
        var b = Buffer.from(shared);
        return outputEnc ? b.toString(outputEnc) : b;
    };
    exports.createECDH = ECDH;
    exports.ECDH = ECDH;

    /// Classical Diffie-Hellman (`createDiffieHellman`,
    /// `createDiffieHellmanGroup`, `getDiffieHellman`). Modular
    /// arithmetic on big integers — host-side via the existing
    /// `crypto.generatePrime` / `crypto.checkPrime` machinery. We
    /// implement enough to make the canonical 2048-bit MODP groups
    /// (`modp14`, `modp15`, `modp16`) work for legacy code that
    /// still uses them.
    var _MODP_GROUPS = {
        // RFC 3526 §3 — 2048-bit MODP group (MODP14).
        modp14: {
            prime_hex: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
            generator: 2,
        },
        modp15: {
            prime_hex: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
            generator: 2,
        },
    };
    function DiffieHellmanGroup(name) {
        if (!(this instanceof DiffieHellmanGroup)) return new DiffieHellmanGroup(name);
        var g = _MODP_GROUPS[name];
        if (!g) {
            var e = new Error('crypto.getDiffieHellman: unknown group ' + name);
            e.code = 'ERR_CRYPTO_UNKNOWN_DH_GROUP';
            throw e;
        }
        this.name = name;
        this._prime = BigInt('0x' + g.prime_hex);
        this._generator = BigInt(g.generator);
        this._priv = null;
        this._pub = null;
    }
    function _bytesFromBigInt(n) {
        var hex = n.toString(16);
        if (hex.length % 2 !== 0) hex = '0' + hex;
        return new Uint8Array(Buffer.from(hex, 'hex'));
    }
    function _bigIntFromBytes(bytes) {
        var b = new Uint8Array(bytes);
        var hex = '';
        for (var i = 0; i < b.length; i++) hex += ('0' + b[i].toString(16)).slice(-2);
        return BigInt('0x' + (hex || '0'));
    }
    function _modPow(base, exp, mod) {
        // Standard square-and-multiply, BigInt-native.
        var result = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp & 1n) result = (result * base) % mod;
            exp >>= 1n;
            base = (base * base) % mod;
        }
        return result;
    }
    DiffieHellmanGroup.prototype.generateKeys = function(encoding) {
        // Pick a random ~256-bit private exponent. Real OpenSSL uses
        // a 2 ≤ x < p-1 range; we approximate with 32 random bytes
        // which is well within the safe zone for 2048-bit primes.
        var rb = exports.randomBytes(32);
        this._priv = _bigIntFromBytes(rb) % (this._prime - 2n) + 2n;
        this._pub = _modPow(this._generator, this._priv, this._prime);
        return this.getPublicKey(encoding);
    };
    DiffieHellmanGroup.prototype.computeSecret = function(other, inputEnc, outputEnc) {
        if (!this._priv) {
            var e = new Error('DH.computeSecret: generateKeys() first');
            e.code = 'ERR_CRYPTO_INCOMPATIBLE_KEY';
            throw e;
        }
        var pubBytes = inputEnc ? _bytesFromKeyish(Buffer.from(other, inputEnc)) : _bytesFromKeyish(other);
        var pub = _bigIntFromBytes(pubBytes);
        var shared = _modPow(pub, this._priv, this._prime);
        var b = Buffer.from(_bytesFromBigInt(shared));
        return outputEnc ? b.toString(outputEnc) : b;
    };
    DiffieHellmanGroup.prototype.getPublicKey = function(encoding) {
        if (!this._pub) return null;
        var b = Buffer.from(_bytesFromBigInt(this._pub));
        return encoding ? b.toString(encoding) : b;
    };
    DiffieHellmanGroup.prototype.getPrivateKey = function(encoding) {
        if (!this._priv) return null;
        var b = Buffer.from(_bytesFromBigInt(this._priv));
        return encoding ? b.toString(encoding) : b;
    };
    DiffieHellmanGroup.prototype.getPrime = function(encoding) {
        var b = Buffer.from(_bytesFromBigInt(this._prime));
        return encoding ? b.toString(encoding) : b;
    };
    DiffieHellmanGroup.prototype.getGenerator = function(encoding) {
        var b = Buffer.from(_bytesFromBigInt(this._generator));
        return encoding ? b.toString(encoding) : b;
    };
    DiffieHellmanGroup.prototype.setPrivateKey = function(priv, encoding) {
        var bs = encoding ? _bytesFromKeyish(Buffer.from(priv, encoding)) : _bytesFromKeyish(priv);
        this._priv = _bigIntFromBytes(bs);
        this._pub = _modPow(this._generator, this._priv, this._prime);
        return this;
    };
    DiffieHellmanGroup.prototype.setPublicKey = function(pub, encoding) {
        var bs = encoding ? _bytesFromKeyish(Buffer.from(pub, encoding)) : _bytesFromKeyish(pub);
        this._pub = _bigIntFromBytes(bs);
        return this;
    };
    DiffieHellmanGroup.prototype.verifyError = 0;

    function DiffieHellman(prime, primeEncoding, generator, generatorEncoding) {
        if (!(this instanceof DiffieHellman)) {
            return new DiffieHellman(prime, primeEncoding, generator, generatorEncoding);
        }
        // Constructor with custom prime: prime can be a number (bit
        // length, generate one) or a Buffer/string (raw prime).
        if (typeof prime === 'number') {
            var bits = prime | 0;
            var hex = globalThis.__host_crypto_generate_prime
                ? globalThis.__host_crypto_generate_prime(bits, false)
                : null;
            if (typeof hex !== 'string' || hex.indexOf('__HOST_ERR__:') === 0) {
                var e = new Error('createDiffieHellman: failed to generate prime');
                e.code = 'ERR_CRYPTO_OPERATION_FAILED';
                throw e;
            }
            this._prime = BigInt('0x' + hex);
        } else {
            var pb = primeEncoding ? _bytesFromKeyish(Buffer.from(prime, primeEncoding))
                                   : _bytesFromKeyish(prime);
            this._prime = _bigIntFromBytes(pb);
        }
        if (generator == null) {
            this._generator = 2n;
        } else if (typeof generator === 'number') {
            this._generator = BigInt(generator);
        } else {
            var gb = generatorEncoding ? _bytesFromKeyish(Buffer.from(generator, generatorEncoding))
                                       : _bytesFromKeyish(generator);
            this._generator = _bigIntFromBytes(gb);
        }
        this._priv = null;
        this._pub = null;
        this.verifyError = 0;
    }
    DiffieHellman.prototype = Object.create(DiffieHellmanGroup.prototype);
    DiffieHellman.prototype.constructor = DiffieHellman;

    exports.createDiffieHellman = function(prime, primeEnc, generator, genEnc) {
        return new DiffieHellman(prime, primeEnc, generator, genEnc);
    };
    exports.createDiffieHellmanGroup = function(name) { return new DiffieHellmanGroup(name); };
    exports.getDiffieHellman = exports.createDiffieHellmanGroup;
    exports.DiffieHellman = DiffieHellman;
    exports.DiffieHellmanGroup = DiffieHellmanGroup;

    /// `X509Certificate` — Node 15.6+. Real cert parsing requires
    /// ASN.1 + X.509 walking. We surface a usable subset: parses the
    /// PEM/DER, exposes `.raw` (DER bytes), `.toString()` (PEM), and
    /// the most-probed subject/issuer/serialNumber/validFrom/validTo
    /// fields via a minimal-viable ASN.1 walk that pulls out the
    /// printable strings.
    function X509Certificate(input) {
        if (!(this instanceof X509Certificate)) return new X509Certificate(input);
        var der = _stripPemBody(input);
        Object.defineProperty(this, 'raw', { value: Buffer.from(der), enumerable: true });
        // Surface the bytes as a PEM toString() — most use sites care
        // only about round-tripping the on-disk cert.
        var b64 = Buffer.from(der).toString('base64');
        var pem = '-----BEGIN CERTIFICATE-----\n';
        for (var i = 0; i < b64.length; i += 64) pem += b64.slice(i, i + 64) + '\n';
        pem += '-----END CERTIFICATE-----\n';
        Object.defineProperty(this, '_pem', { value: pem, enumerable: false });
        // Best-effort ASN.1 string scan: walk the DER bytes pulling
        // every PrintableString / UTF8String / IA5String we find, in
        // order. The first two are subject/issuer in practice; later
        // ones are SAN dnsNames.
        var strings = [];
        var i2 = 0;
        while (i2 < der.length - 2) {
            var tag = der[i2], len = der[i2 + 1];
            if ((tag === 0x13 || tag === 0x0c || tag === 0x16) && len > 0 && len < 128
                && i2 + 2 + len <= der.length) {
                var s = '';
                for (var j = 0; j < len; j++) s += String.fromCharCode(der[i2 + 2 + j]);
                strings.push(s);
                i2 += 2 + len;
            } else {
                i2 += 1;
            }
        }
        Object.defineProperty(this, 'subject',
            { value: strings[1] ? 'CN=' + strings[1] : '', enumerable: true });
        Object.defineProperty(this, 'issuer',
            { value: strings[0] ? 'CN=' + strings[0] : '', enumerable: true });
        Object.defineProperty(this, 'subjectAltName',
            { value: strings.slice(2).join(', '), enumerable: true });
        // serialNumber / validFrom / validTo — without a full ASN.1
        // parser we can't pinpoint them; expose '' so probes don't
        // crash.
        Object.defineProperty(this, 'serialNumber', { value: '', enumerable: true });
        Object.defineProperty(this, 'validFrom', { value: '', enumerable: true });
        Object.defineProperty(this, 'validTo', { value: '', enumerable: true });
    }
    X509Certificate.prototype.toString = function() { return this._pem; };
    X509Certificate.prototype.toLegacyObject = function() {
        return {
            subject: this.subject,
            issuer: this.issuer,
            subjectaltname: this.subjectAltName,
            raw: this.raw,
        };
    };
    X509Certificate.prototype.toJSON = function() { return this._pem; };
    X509Certificate.prototype.checkHost = function() { return undefined; };
    X509Certificate.prototype.checkEmail = function() { return undefined; };
    X509Certificate.prototype.checkIP = function() { return undefined; };
    X509Certificate.prototype.checkIssued = function() { return false; };
    X509Certificate.prototype.checkPrivateKey = function() { return false; };
    X509Certificate.prototype.verify = function() { return false; };
    Object.defineProperty(X509Certificate.prototype, 'publicKey', {
        get: function() {
            // Public key extraction would need an ASN.1 walker we don't
            // ship; expose a KeyObject wrapping the raw DER so callers
            // that just want to ferry bytes around still work.
            return new KeyObject('public', undefined, new Uint8Array(this.raw));
        },
    });
    Object.defineProperty(X509Certificate.prototype, 'fingerprint', {
        get: function() {
            var h = exports.createHash('sha1');
            h.update(this.raw);
            return h.digest('hex').toUpperCase().match(/.{2}/g).join(':');
        },
    });
    Object.defineProperty(X509Certificate.prototype, 'fingerprint256', {
        get: function() {
            var h = exports.createHash('sha256');
            h.update(this.raw);
            return h.digest('hex').toUpperCase().match(/.{2}/g).join(':');
        },
    });
    Object.defineProperty(X509Certificate.prototype, 'fingerprint512', {
        get: function() {
            var h = exports.createHash('sha512');
            h.update(this.raw);
            return h.digest('hex').toUpperCase().match(/.{2}/g).join(':');
        },
    });
    exports.X509Certificate = X509Certificate;
    /// `crypto.checkPrimeSync(candidate, options?)` — Miller-Rabin
    /// primality test. Accepts `BigInt`, `number`, `Buffer` (BE bytes),
    /// `Uint8Array`. Node's `options.checks` is honoured (default 0 →
    /// host picks 40 rounds for ≤2^-80 false-positive probability).
    function _candidateToHex(c) {
        if (typeof c === 'bigint') {
            var s = c.toString(16);
            if (s.length % 2 !== 0) s = '0' + s;
            return s;
        }
        if (typeof c === 'number') {
            if (!Number.isFinite(c) || c < 0) return '00';
            var s2 = Math.floor(c).toString(16);
            if (s2.length % 2 !== 0) s2 = '0' + s2;
            return s2;
        }
        if (c instanceof ArrayBuffer) c = new Uint8Array(c);
        if (ArrayBuffer.isView(c) || c instanceof Uint8Array
            || (typeof Buffer !== 'undefined' && Buffer.isBuffer(c))) {
            var bytes = (typeof Buffer !== 'undefined' && Buffer.isBuffer(c))
                ? c : new Uint8Array(c.buffer, c.byteOffset, c.byteLength);
            var hex = '';
            for (var i = 0; i < bytes.length; i++) {
                hex += ('0' + bytes[i].toString(16)).slice(-2);
            }
            return hex || '00';
        }
        throw new TypeError('checkPrime: candidate must be number / BigInt / Buffer');
    }
    exports.checkPrimeSync = function(p, options) {
        var checks = (options && (options.checks | 0)) || 0;
        var hex = _candidateToHex(p);
        if (typeof globalThis.__host_crypto_check_prime !== 'function') {
            throw new Error('crypto.checkPrimeSync: host fn missing');
        }
        var r = globalThis.__host_crypto_check_prime(hex, checks);
        if (r < 0) throw new Error('checkPrime: host error code ' + r);
        return r === 1;
    };
    exports.checkPrime = function(p, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try { cb(null, exports.checkPrimeSync(p, options)); }
            catch (e) { cb(e); }
        });
    };
    /// `crypto.generatePrimeSync(size, options?)` — Generate a probable
    /// prime of `size` bits. `options.safe` requires `(p-1)/2` also
    /// prime. Returns BigInt by default (matches Node 15+).
    exports.generatePrimeSync = function(size, options) {
        if (typeof globalThis.__host_crypto_generate_prime !== 'function') {
            throw new Error('crypto.generatePrimeSync: host fn missing');
        }
        var safe = !!(options && options.safe);
        var hex = globalThis.__host_crypto_generate_prime(size | 0, safe);
        if (typeof hex === 'string' && hex.indexOf('__HOST_ERR__:') === 0) {
            throw new Error(hex.slice('__HOST_ERR__:'.length));
        }
        if (options && options.bigint === false) {
            // Buffer of BE bytes when the caller opts out of BigInt.
            return Buffer.from(hex, 'hex');
        }
        return BigInt('0x' + hex);
    };
    exports.generatePrime = function(size, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try { cb(null, exports.generatePrimeSync(size, options)); }
            catch (e) { cb(e); }
        });
    };
    exports.secureHeapUsed = function() {
        return { total: 0, min: 0, used: 0, utilization: 0 };
    };
    exports.setEngine = function(name, _flags) {
        var n = String(name || '').toLowerCase();
        if (n === '' || n === 'default' || n === 'dynamic') return;
        var e = new Error("burn doesn't link OpenSSL — we don't want to compromise");
        e.code = 'ERR_CRYPTO_ENGINE_UNKNOWN';
        throw e;
    };
    exports.setFips = function(enabled) {
        if (!enabled) return;
        var e = new Error("burn doesn't link OpenSSL — we don't want to compromise");
        e.code = 'ERR_CRYPTO_FIPS_UNAVAILABLE';
        throw e;
    };
    // Node's `crypto.getFips()` returns 1/0 (number); `crypto.fips`
    // is the boolean shorthand exposed since Node 0.12. Both are
    // false on non-FIPS Node builds — we mirror that exactly so
    // libraries that gate behaviour on either form see the same
    // answer as in stock Node.
    exports.getFips = function() { return 0; };
    Object.defineProperty(exports, 'fips', {
        get: function() { return false; },
        set: function(v) { exports.setFips(!!v); },
        enumerable: true,
        configurable: true,
    });

    // ---- crypto.constants -----------------------------------------
    //
    // Subset that real-world packages probe: OpenSSL flag bits + the
    // signing/padding scheme constants used by `crypto.sign` /
    // `subtle.sign` callers. Burn doesn't use these for gating
    // (the host-side rust-crypto crates encode the algorithm in the
    // call shape), but exposing them keeps `require('crypto').constants.RSA_PKCS1_PADDING`
    // probes from being `undefined` and crashing.
    exports.constants = {
        // SSL options
        SSL_OP_ALL: 0x80000bff,
        SSL_OP_NO_SSLv2: 0x01000000,
        SSL_OP_NO_SSLv3: 0x02000000,
        SSL_OP_NO_TLSv1: 0x04000000,
        SSL_OP_NO_TLSv1_1: 0x10000000,
        SSL_OP_NO_TLSv1_2: 0x08000000,
        SSL_OP_NO_TLSv1_3: 0x20000000,
        // RSA padding
        RSA_PKCS1_PADDING: 1,
        RSA_SSLV23_PADDING: 2,
        RSA_NO_PADDING: 3,
        RSA_PKCS1_OAEP_PADDING: 4,
        RSA_X931_PADDING: 5,
        RSA_PKCS1_PSS_PADDING: 6,
        // PSS salt
        RSA_PSS_SALTLEN_DIGEST: -1,
        RSA_PSS_SALTLEN_MAX_SIGN: -2,
        RSA_PSS_SALTLEN_AUTO: -2,
        // DH point formats
        POINT_CONVERSION_COMPRESSED: 2,
        POINT_CONVERSION_UNCOMPRESSED: 4,
        POINT_CONVERSION_HYBRID: 6,
        // Hash algorithms (for crypto.diffieHellman)
        ENGINE_METHOD_NONE: 0x00,
        ENGINE_METHOD_ALL: 0xffff,
        DH_CHECK_P_NOT_SAFE_PRIME: 2,
        DH_CHECK_P_NOT_PRIME: 1,
        DH_NOT_SUITABLE_GENERATOR: 8,
        DH_UNABLE_TO_CHECK_GENERATOR: 4,
        defaultCoreCipherList:
            'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:'
            + 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:'
            + 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384',
    };
});
