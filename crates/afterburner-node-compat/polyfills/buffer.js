// buffer — a `Buffer` class backed by `Uint8Array`, covering the
// slice of the API that scripts normally touch. UCS-2 / UTF-16 are
// intentionally omitted — callers who need them can fall back to
// TextDecoder directly.

__register_module('buffer', function(module, exports, require) {

    // ---- encoding helpers -------------------------------------------------

    var HEX = '0123456789abcdef';

    function utf8Encode(str) {
        // QuickJS exposes TextEncoder globally; prefer it when available.
        if (typeof TextEncoder === 'function') {
            return new TextEncoder().encode(str);
        }
        // Fallback — correct for BMP, good enough for ASCII-heavy payloads.
        var out = [];
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 0x80)       out.push(c);
            else if (c < 0x800) out.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
            else                out.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
        }
        return new Uint8Array(out);
    }

    function utf8Decode(bytes) {
        if (typeof TextDecoder === 'function') {
            return new TextDecoder('utf-8').decode(bytes);
        }
        var out = '';
        for (var i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
        return out;
    }

    function hexEncode(bytes) {
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
            var b = bytes[i];
            out += HEX[(b >> 4) & 0x0F] + HEX[b & 0x0F];
        }
        return out;
    }

    function hexDecode(str) {
        str = String(str);
        if (str.length % 2) str = str.slice(0, str.length - 1);
        var bytes = new Uint8Array(str.length / 2);
        for (var i = 0; i < bytes.length; i++) {
            bytes[i] = parseInt(str.substr(i * 2, 2), 16) & 0xFF;
        }
        return bytes;
    }

    var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var B64_INV = (function() {
        var a = new Int8Array(256).fill(-1);
        for (var i = 0; i < 64; i++) a[B64.charCodeAt(i)] = i;
        a['='.charCodeAt(0)] = 0;
        return a;
    })();

    // Host-native base64 bridges (raw-byte framing). Present whenever
    // the runtime installs the codec globals; the interpreter-side
    // implementations below stay as the fallback for other embeddings
    // and for inputs the host's stricter decoder rejects.
    var hostB64Encode = typeof __host_b64_encode === 'function' ? __host_b64_encode : null;
    var hostB64Decode = typeof __host_b64_decode === 'function' ? __host_b64_decode : null;

    function b64Encode(bytes) {
        if (hostB64Encode && bytes.length > 0) {
            try { return hostB64Encode(bytes); } catch (_) { /* fall back */ }
        }
        return b64EncodeJs(bytes);
    }

    function b64Decode(str) {
        str = String(str);
        if (hostB64Decode) {
            // First attempt: the raw input. Covers canonical payloads
            // (padded or not) without an O(n) sanitize pass.
            try { return hostB64Decode(str); } catch (_) { /* sanitize */ }
            // Second attempt: strip characters outside the standard
            // alphabet (whitespace, line breaks, data-URL noise) the
            // same way the interpreter path does, then retry.
            var clean = str.replace(/[^A-Za-z0-9+/=]/g, '');
            try { return hostB64Decode(clean); } catch (_) { /* fall back */ }
        }
        return b64DecodeJs(str);
    }

    function b64EncodeJs(bytes) {
        // Bulk-encode by chunk into an array, join once at the end.
        // QuickJS's `+=` string concat creates a fresh string per
        // step which goes quadratic on multi-KB inputs (50 KB took
        // ~800ms; 315 KB hung). Joining a small array of pre-
        // encoded segments collapses that to ~one alloc per chunk.
        // Chunk size 768 bytes = 1024 base64 chars per segment;
        // picked to keep the temporary char arrays cache-friendly
        // while bounding the array overhead.
        var n = bytes.length;
        if (n === 0) return '';
        var chunks = [];
        var i = 0;
        var CHUNK = 768;
        for (; i + CHUNK <= n; i += CHUNK) {
            var seg = '';
            for (var j = i; j < i + CHUNK; j += 3) {
                var v = (bytes[j] << 16) | (bytes[j+1] << 8) | bytes[j+2];
                seg += B64[(v >> 18) & 63] + B64[(v >> 12) & 63] + B64[(v >> 6) & 63] + B64[v & 63];
            }
            chunks.push(seg);
        }
        var tail = '';
        for (; i + 3 <= n; i += 3) {
            var v2 = (bytes[i] << 16) | (bytes[i+1] << 8) | bytes[i+2];
            tail += B64[(v2 >> 18) & 63] + B64[(v2 >> 12) & 63] + B64[(v2 >> 6) & 63] + B64[v2 & 63];
        }
        var rem = n - i;
        if (rem === 1) {
            var n1 = bytes[i] << 16;
            tail += B64[(n1 >> 18) & 63] + B64[(n1 >> 12) & 63] + '==';
        } else if (rem === 2) {
            var n2 = (bytes[i] << 16) | (bytes[i+1] << 8);
            tail += B64[(n2 >> 18) & 63] + B64[(n2 >> 12) & 63] + B64[(n2 >> 6) & 63] + '=';
        }
        if (tail) chunks.push(tail);
        return chunks.join('');
    }

    function b64DecodeJs(str) {
        str = String(str).replace(/[^A-Za-z0-9+/=]/g, '');
        var pad = 0;
        if (str.charAt(str.length - 1) === '=') pad++;
        if (str.charAt(str.length - 2) === '=') pad++;
        var out = new Uint8Array(Math.floor(str.length * 3 / 4) - pad);
        var o = 0;
        for (var i = 0; i < str.length; i += 4) {
            var n = (B64_INV[str.charCodeAt(i)]   << 18) |
                    (B64_INV[str.charCodeAt(i+1)] << 12) |
                    (B64_INV[str.charCodeAt(i+2)] << 6)  |
                    (B64_INV[str.charCodeAt(i+3)]);
            if (o < out.length) out[o++] = (n >> 16) & 0xFF;
            if (o < out.length) out[o++] = (n >> 8) & 0xFF;
            if (o < out.length) out[o++] = n & 0xFF;
        }
        return out;
    }

    // ---- Buffer class -----------------------------------------------------

    function Buffer(arg, encodingOrLength) {
        if (typeof arg === 'number') {
            var u = new Uint8Array(arg);
            makeBuffer(u);
            return u;
        }
        if (typeof arg === 'string') return Buffer.from(arg, encodingOrLength);
        if (arg instanceof Uint8Array) {
            makeBuffer(arg);
            return arg;
        }
        if (Array.isArray(arg)) return Buffer.from(arg);
        throw new TypeError('unsupported Buffer argument');
    }

    function makeBuffer(u8) {
        u8.__isBuffer = true;
        u8.toString = function(encoding, start, end) {
            encoding = (encoding || 'utf8').toLowerCase();
            var slice = (start !== undefined || end !== undefined) ? u8.subarray(start || 0, end) : u8;
            if (encoding === 'utf8' || encoding === 'utf-8') return utf8Decode(slice);
            if (encoding === 'hex')                          return hexEncode(slice);
            if (encoding === 'base64')                       return b64Encode(slice);
            if (encoding === 'ascii' || encoding === 'binary' || encoding === 'latin1') {
                var s = '';
                for (var i = 0; i < slice.length; i++) s += String.fromCharCode(slice[i]);
                return s;
            }
            throw new Error('Unknown encoding: ' + encoding);
        };
        u8.slice = function(start, end) {
            var s = Uint8Array.prototype.subarray.call(u8, start, end);
            makeBuffer(s);
            return s;
        };
        // `subarray` MUST return a Buffer (not a bare Uint8Array) so the
        // returned view still has Buffer methods — most importantly
        // `toString(encoding)`. Node's `Buffer.subarray` returns a
        // Buffer; without this override `buf.subarray(a,b).toString('utf8')`
        // falls back to TypedArray's comma-joined `toString` and yields
        // "104,105,…" instead of the decoded text. The `tar` package
        // decodes every header field via `subarray().toString('utf8')`,
        // so the bare-Uint8Array form made every checksum/path parse
        // garbage and broke `npm install` tarball extraction.
        u8.subarray = function(start, end) {
            var s = Uint8Array.prototype.subarray.call(u8, start, end);
            makeBuffer(s);
            return s;
        };
        u8.equals = function(other) {
            if (!other || other.length !== u8.length) return false;
            for (var i = 0; i < u8.length; i++) if (u8[i] !== other[i]) return false;
            return true;
        };
        u8.compare = function(other, targetStart, targetEnd, sourceStart, sourceEnd) {
            var a = u8.subarray(sourceStart || 0, sourceEnd !== undefined ? sourceEnd : u8.length);
            var b = other.subarray(targetStart || 0, targetEnd !== undefined ? targetEnd : other.length);
            var len = Math.min(a.length, b.length);
            for (var i = 0; i < len; i++) {
                if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
            }
            return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
        };
        u8.indexOf = function(value, byteOffset, encoding) {
            var needle;
            if (typeof value === 'number') {
                for (var i = byteOffset || 0; i < u8.length; i++) if (u8[i] === (value & 0xff)) return i;
                return -1;
            }
            if (typeof value === 'string') needle = Buffer.from(value, encoding || 'utf8');
            else if (value instanceof Uint8Array) needle = value;
            else throw new TypeError('Buffer.indexOf: unsupported value');
            outer: for (var j = byteOffset || 0; j <= u8.length - needle.length; j++) {
                for (var k = 0; k < needle.length; k++) if (u8[j + k] !== needle[k]) continue outer;
                return j;
            }
            return -1;
        };
        u8.includes = function(value, byteOffset, encoding) {
            return u8.indexOf(value, byteOffset, encoding) !== -1;
        };
        u8.copy = function(target, targetStart, sourceStart, sourceEnd) {
            targetStart = targetStart || 0;
            sourceStart = sourceStart || 0;
            sourceEnd = sourceEnd !== undefined ? sourceEnd : u8.length;
            var n = Math.min(sourceEnd - sourceStart, target.length - targetStart);
            for (var i = 0; i < n; i++) target[targetStart + i] = u8[sourceStart + i];
            return n;
        };
        u8.write = function(str, offset, length, encoding) {
            offset = offset || 0;
            if (typeof length === 'string') { encoding = length; length = undefined; }
            var bytes = Buffer.from(str, encoding || 'utf8');
            var n = Math.min(length !== undefined ? length : bytes.length, u8.length - offset);
            for (var i = 0; i < n; i++) u8[offset + i] = bytes[i];
            return n;
        };
        // Numeric readers (little-endian + big-endian, unsigned + signed).
        u8.readUInt8 = function(o) { return u8[o || 0]; };
        u8.readInt8  = function(o) { var v = u8[o || 0]; return v > 127 ? v - 256 : v; };
        u8.readUInt16LE = function(o) { o = o || 0; return u8[o] | (u8[o + 1] << 8); };
        u8.readUInt16BE = function(o) { o = o || 0; return (u8[o] << 8) | u8[o + 1]; };
        u8.readInt16LE  = function(o) { var v = u8.readUInt16LE(o); return v > 32767 ? v - 65536 : v; };
        u8.readInt16BE  = function(o) { var v = u8.readUInt16BE(o); return v > 32767 ? v - 65536 : v; };
        u8.readUInt32LE = function(o) { o = o || 0;
            return (u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16)) + (u8[o + 3] * 0x1000000); };
        u8.readUInt32BE = function(o) { o = o || 0;
            return (u8[o] * 0x1000000) + ((u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3]); };
        u8.readInt32LE  = function(o) { o = o || 0;
            return u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24); };
        u8.readInt32BE  = function(o) { o = o || 0;
            return (u8[o] << 24) | (u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3]; };

        u8.writeUInt8 = function(v, o) { u8[o || 0] = v & 0xff; return (o || 0) + 1; };
        u8.writeInt8  = u8.writeUInt8;
        u8.writeUInt16LE = function(v, o) { o = o || 0; u8[o] = v & 0xff; u8[o + 1] = (v >>> 8) & 0xff; return o + 2; };
        u8.writeUInt16BE = function(v, o) { o = o || 0; u8[o] = (v >>> 8) & 0xff; u8[o + 1] = v & 0xff; return o + 2; };
        u8.writeInt16LE  = u8.writeUInt16LE;
        u8.writeInt16BE  = u8.writeUInt16BE;
        u8.writeUInt32LE = function(v, o) { o = o || 0;
            u8[o] = v & 0xff; u8[o + 1] = (v >>> 8) & 0xff;
            u8[o + 2] = (v >>> 16) & 0xff; u8[o + 3] = (v >>> 24) & 0xff;
            return o + 4;
        };
        u8.writeUInt32BE = function(v, o) { o = o || 0;
            u8[o] = (v >>> 24) & 0xff; u8[o + 1] = (v >>> 16) & 0xff;
            u8[o + 2] = (v >>> 8) & 0xff; u8[o + 3] = v & 0xff;
            return o + 4;
        };
        u8.writeInt32LE = u8.writeUInt32LE;
        u8.writeInt32BE = u8.writeUInt32BE;
        return u8;
    }

    Buffer.from = function(source, encoding) {
        if (typeof source === 'string') {
            encoding = (encoding || 'utf8').toLowerCase();
            if (encoding === 'utf8' || encoding === 'utf-8') return makeBuffer(utf8Encode(source));
            if (encoding === 'hex')                          return makeBuffer(hexDecode(source));
            if (encoding === 'base64')                       return makeBuffer(b64Decode(source));
            if (encoding === 'ascii' || encoding === 'binary' || encoding === 'latin1') {
                var u = new Uint8Array(source.length);
                for (var i = 0; i < source.length; i++) u[i] = source.charCodeAt(i) & 0xFF;
                return makeBuffer(u);
            }
            throw new Error('Unknown encoding: ' + encoding);
        }
        if (source instanceof ArrayBuffer) return makeBuffer(new Uint8Array(source));
        if (source instanceof Uint8Array || Array.isArray(source)) {
            var copy = new Uint8Array(source.length);
            copy.set(source);
            return makeBuffer(copy);
        }
        throw new TypeError('Buffer.from: unsupported source');
    };

    Buffer.alloc = function(size, fill) {
        var u = new Uint8Array(size);
        if (fill !== undefined && fill !== 0) {
            var byteFill = typeof fill === 'number' ? fill : fill.charCodeAt ? fill.charCodeAt(0) : 0;
            u.fill(byteFill & 0xFF);
        }
        return makeBuffer(u);
    };

    Buffer.allocUnsafe = Buffer.alloc;
    Buffer.allocUnsafeSlow = Buffer.alloc;

    // Default pool size matches Node's 8 KiB. We don't pool slabs
    // under the hood — each `Buffer.alloc` is a fresh `Uint8Array` —
    // but expose the field so libraries that probe / write to it
    // don't trip.
    Buffer.poolSize = 8 * 1024;

    /// Buffer.copyBytesFrom(view, offset?, length?) — Node 19+.
    /// Copies bytes from a TypedArray view (Uint8Array, DataView,
    /// etc.) into a fresh Buffer. Honors offset + length in
    /// elements (NOT bytes) for non-1-byte typed arrays, matching
    /// Node's contract.
    Buffer.copyBytesFrom = function(view, offset, length) {
        if (view == null || typeof view.byteLength !== 'number') {
            throw new TypeError('Buffer.copyBytesFrom: view must be a TypedArray');
        }
        var byteOffset = view.byteOffset || 0;
        var bpe = view.BYTES_PER_ELEMENT || 1;
        offset = offset === undefined ? 0 : (offset | 0);
        length = length === undefined ? (view.length - offset) : (length | 0);
        if (offset < 0 || length < 0 || offset + length > view.length) {
            throw new RangeError('Buffer.copyBytesFrom: offset/length out of range');
        }
        var srcOffset = byteOffset + offset * bpe;
        var srcLen = length * bpe;
        var src = new Uint8Array(view.buffer, srcOffset, srcLen);
        var out = new Uint8Array(srcLen);
        out.set(src);
        return makeBuffer(out);
    };

    Buffer.concat = function(list, totalLength) {
        if (!Array.isArray(list)) throw new TypeError('list argument must be an Array');
        if (list.length === 0) return Buffer.alloc(0);
        if (totalLength === undefined) {
            totalLength = 0;
            for (var i = 0; i < list.length; i++) totalLength += list[i].length;
        }
        var out = new Uint8Array(totalLength);
        var offset = 0;
        for (var j = 0; j < list.length; j++) {
            var buf = list[j];
            var take = Math.min(buf.length, totalLength - offset);
            out.set(buf.subarray(0, take), offset);
            offset += take;
        }
        return makeBuffer(out);
    };

    Buffer.isBuffer = function(x) {
        return !!(x && x.__isBuffer === true);
    };

    Buffer.byteLength = function(str, encoding) {
        if (typeof str !== 'string') return str.length || 0;
        encoding = (encoding || 'utf8').toLowerCase();
        if (encoding === 'hex')    return Math.floor(str.length / 2);
        if (encoding === 'base64') return Math.floor(str.replace(/=/g, '').length * 3 / 4);
        return utf8Encode(str).length;
    };

    /// Buffer.compare(a, b) — static byte-wise comparator. Returns
    /// -1 / 0 / 1 like a memcmp; useful for sorted-by-bytes
    /// containers (Map keys, sorted indexes).
    Buffer.compare = function(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
            throw new TypeError('Buffer.compare: both arguments must be Buffer');
        }
        var n = Math.min(a.length, b.length);
        for (var i = 0; i < n; i++) {
            if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
        }
        if (a.length === b.length) return 0;
        return a.length < b.length ? -1 : 1;
    };

    /// Buffer.isEncoding(name) — true if `name` is a known encoding.
    Buffer.isEncoding = function(encoding) {
        if (typeof encoding !== 'string') return false;
        switch (encoding.toLowerCase()) {
            case 'utf8': case 'utf-8':
            case 'utf16le': case 'utf-16le': case 'ucs2': case 'ucs-2':
            case 'latin1': case 'binary':
            case 'ascii':
            case 'base64': case 'base64url':
            case 'hex':
                return true;
            default:
                return false;
        }
    };

    /// Buffer.prototype.swap16 / swap32 / swap64 — byte-swap pairs
    /// of bytes in-place. Throws if length isn't a multiple of the
    /// swap unit. Returns `this` so calls chain.
    function _swap(self, unit) {
        if ((self.length % unit) !== 0) {
            throw new RangeError('Buffer.swap' + (unit * 8) + ': length must be multiple of ' + unit);
        }
        for (var i = 0; i < self.length; i += unit) {
            for (var j = 0; j < unit / 2; j++) {
                var tmp = self[i + j];
                self[i + j] = self[i + unit - 1 - j];
                self[i + unit - 1 - j] = tmp;
            }
        }
        return self;
    }
    function _installSwapMethods(proto) {
        if (!proto) return;
        if (typeof proto.swap16 !== 'function') {
            proto.swap16 = function() { return _swap(this, 2); };
        }
        if (typeof proto.swap32 !== 'function') {
            proto.swap32 = function() { return _swap(this, 4); };
        }
        if (typeof proto.swap64 !== 'function') {
            proto.swap64 = function() { return _swap(this, 8); };
        }
    }
    // makeBuffer either returns a fresh Uint8Array with `__isBuffer`
    // tagged or extends prototypes; `swap*` lives on the per-buffer
    // augmentation. Install on the canonical Uint8Array prototype
    // since Buffers ARE Uint8Arrays under the hood.
    _installSwapMethods(Uint8Array.prototype);

    exports.Buffer = Buffer;
    exports.kMaxLength = 0x7fffffff;
    exports.INSPECT_MAX_BYTES = 50;

    /// buffer.constants — module-level Node 8.2+ surface. Real apps
    /// (sharp, fast-glob, node-canvas) probe these at module init.
    exports.constants = {
        MAX_LENGTH: 0x7fffffff,
        MAX_STRING_LENGTH: 0x1fffffe8,
    };

    /// buffer.atob / buffer.btoa — Node re-exports the Web globals
    /// here for convenience (some libraries import from buffer
    /// instead of relying on the global).
    exports.atob = function(input) {
        return Buffer.from(String(input), 'base64').toString('binary');
    };
    exports.btoa = function(input) {
        return Buffer.from(String(input), 'binary').toString('base64');
    };

    /// buffer.transcode — re-encode a Buffer between two single-byte
    /// or UTF encodings. Uses TextDecoder + TextEncoder for the
    /// common cross-encoding paths; falls back to identity copy
    /// when source and target encodings match.
    exports.transcode = function(source, fromEnc, toEnc) {
        if (!Buffer.isBuffer(source)) {
            throw new TypeError('buffer.transcode: source must be a Buffer');
        }
        var from = String(fromEnc || '').toLowerCase();
        var to = String(toEnc || '').toLowerCase();
        if (from === to) return Buffer.from(source);
        // Use the canonical TextDecoder/TextEncoder pair for any pair
        // that involves utf-* on at least one side.
        var dec = new TextDecoder(from === 'utf16le' ? 'utf-16le' : (from || 'utf-8'));
        var str = dec.decode(source);
        if (to === 'utf-8' || to === 'utf8') {
            return Buffer.from(new TextEncoder().encode(str));
        }
        if (to === 'utf16le' || to === 'utf-16le') {
            // Manual UTF-16LE encode.
            var out = Buffer.alloc(str.length * 2);
            for (var i = 0; i < str.length; i++) {
                var c = str.charCodeAt(i);
                out[i * 2]     = c & 0xff;
                out[i * 2 + 1] = (c >> 8) & 0xff;
            }
            return out;
        }
        if (to === 'latin1' || to === 'binary') {
            var out2 = Buffer.alloc(str.length);
            for (var j = 0; j < str.length; j++) {
                out2[j] = str.charCodeAt(j) & 0xff;
            }
            return out2;
        }
        if (to === 'ascii') {
            var out3 = Buffer.alloc(str.length);
            for (var k = 0; k < str.length; k++) {
                out3[k] = str.charCodeAt(k) & 0x7f;
            }
            return out3;
        }
        throw new Error('buffer.transcode: unsupported target encoding: ' + to);
    };

    /// buffer.resolveObjectURL — returns the Blob registered to a
    /// `blob:` URL via URL.createObjectURL. Burn doesn't support
    /// createObjectURL (no DOM), so this always returns undefined.
    exports.resolveObjectURL = function() { return undefined; };

    /// `buffer.isUtf8(input)` / `buffer.isAscii(input)` — Node 19.4+
    /// validators that check whether a Buffer / TypedArray / ArrayBuffer
    /// holds well-formed UTF-8 or 7-bit ASCII bytes. We accept the same
    /// argument shape as Node and walk the underlying byte view.
    function _coerceToBytes(input, fnName) {
        if (input == null) {
            var e = new TypeError(
                fnName + ': argument must be a Buffer, TypedArray, DataView or ArrayBuffer');
            e.code = 'ERR_INVALID_ARG_TYPE';
            throw e;
        }
        if (input instanceof ArrayBuffer) return new Uint8Array(input);
        if (ArrayBuffer.isView(input)) {
            return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
        }
        var e2 = new TypeError(
            fnName + ': argument must be a Buffer, TypedArray, DataView or ArrayBuffer');
        e2.code = 'ERR_INVALID_ARG_TYPE';
        throw e2;
    }

    exports.isUtf8 = function isUtf8(input) {
        var bytes = _coerceToBytes(input, 'isUtf8');
        var i = 0, n = bytes.length;
        while (i < n) {
            var b = bytes[i];
            if (b < 0x80) { i += 1; continue; }
            var trailing;
            if ((b & 0xe0) === 0xc0) { trailing = 1; if (b < 0xc2) return false; }
            else if ((b & 0xf0) === 0xe0) { trailing = 2; }
            else if ((b & 0xf8) === 0xf0) { trailing = 3; if (b > 0xf4) return false; }
            else return false;
            if (i + trailing >= n) return false;
            // Overlong / surrogate / out-of-range filters per RFC 3629.
            if (trailing === 2 && b === 0xe0 && bytes[i + 1] < 0xa0) return false;
            if (trailing === 2 && b === 0xed && bytes[i + 1] >= 0xa0) return false;
            if (trailing === 3 && b === 0xf0 && bytes[i + 1] < 0x90) return false;
            if (trailing === 3 && b === 0xf4 && bytes[i + 1] >= 0x90) return false;
            for (var j = 1; j <= trailing; j++) {
                if ((bytes[i + j] & 0xc0) !== 0x80) return false;
            }
            i += 1 + trailing;
        }
        return true;
    };

    exports.isAscii = function isAscii(input) {
        var bytes = _coerceToBytes(input, 'isAscii');
        for (var i = 0; i < bytes.length; i++) {
            if (bytes[i] > 0x7f) return false;
        }
        return true;
    };

    /// buffer.SlowBuffer — alias for `Buffer.allocUnsafeSlow` per
    /// Node's documented re-export.
    exports.SlowBuffer = function SlowBuffer(size) {
        return Buffer.allocUnsafeSlow(size);
    };

    /// buffer.Blob / buffer.File — re-exports of the Web globals
    /// for callers that import from `node:buffer` instead of using
    /// the globals directly.
    if (typeof globalThis.Blob === 'function') exports.Blob = globalThis.Blob;
    if (typeof globalThis.File === 'function') exports.File = globalThis.File;
});
