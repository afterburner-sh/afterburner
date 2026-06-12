// stream — Node 20 LTS streams (Readable, Writable, Duplex,
// Transform, PassThrough, pipeline, finished, compose, addAbortSignal).
// Pure JS — no host calls. Backpressure modeled with a highWaterMark
// + pending-byte counter; the actual wire-level pause/resume is
// observable through `.write()` returning false and a `'drain'` event
// firing after the pending count crosses back below HWM.

__register_module('stream', function(module, exports, require) {

    var EventEmitter = require('events');

    var DEFAULT_HWM = 16 * 1024;

    // --- Readable ---------------------------------------------------------
    //
    // Two consumption modes:
    //   * Flowing: listening for 'data' (and 'end') gets the chunks pushed
    //     synchronously as `.push(chunk)` runs.
    //   * Paused: `.read()` (no listener) buffers internally; pull when
    //     the consumer asks. We start paused; transition to flowing on
    //     the first 'data' listener.

    function Readable(opts) {
        if (!(this instanceof Readable)) return new Readable(opts);
        EventEmitter.call(this);
        this._events = this._events || Object.create(null);
        opts = opts || {};
        this._readable = true;
        this._ended = false;
        this._destroyed = false;
        this._buffer = [];
        this._highWaterMark = opts.highWaterMark || DEFAULT_HWM;
        this._read = (opts.read || function() {}).bind(this);
        this._flowing = null; // null = unset, true = flowing, false = paused
        var self = this;
        // Auto-flow on first data listener. The pump is deferred a
        // microtask so the listener is attached before _read() pushes.
        this.on('newListener', function(name) {
            if (name === 'data' && self._flowing === null) {
                self._flowing = true;
                queueMicrotask(function() { self._pump(); });
            }
        });
    }
    Readable.prototype = Object.create(EventEmitter.prototype);
    Readable.prototype.constructor = Readable;

    Readable.prototype.push = function(chunk) {
        if (chunk === null) {
            this._ended = true;
            // Flush buffered chunks before 'end'.
            this._drainBuffer();
            this.emit('end');
            this.emit('close');
            return false;
        }
        if (this._destroyed) return false;
        if (this._flowing) {
            this.emit('data', chunk);
            // Keep pulling: Node re-invokes _read() as the consumer keeps
            // up. Deferred so a synchronous multi-push _read never recurses.
            var self = this;
            queueMicrotask(function() { self._pump(); });
        } else {
            this._buffer.push(chunk);
            this.emit('readable');
        }
        return true;
    };
    // Ask the underlying source (`_read`, set via `new Readable({read})`
    // or assigned by subclasses) for more data. Re-entrancy-guarded; a
    // source that pushes nothing simply stops the flow until the next
    // explicit resume()/read().
    Readable.prototype._pump = function() {
        if (this._pumping || this._ended || this._destroyed) return;
        if (typeof this._read !== 'function') return;
        this._pumping = true;
        try {
            this._read(this._highWaterMark);
        } catch (e) {
            this.emit('error', e);
        }
        this._pumping = false;
    };
    Readable.prototype._drainBuffer = function() {
        while (this._buffer.length && this._flowing !== false) {
            this.emit('data', this._buffer.shift());
        }
    };
    Readable.prototype.read = function() {
        if (this._buffer.length === 0) {
            // Paused-mode pull: give the source a chance to fill the
            // buffer synchronously (Node calls _read here too).
            this._pump();
        }
        if (this._buffer.length === 0) return null;
        return this._buffer.shift();
    };
    Readable.prototype.pause = function() {
        this._flowing = false;
        return this;
    };
    // setEncoding(enc): emit strings instead of Buffers. Body collectors
    // (fastify's content-type parser, raw-body) call this before reading.
    Readable.prototype.setEncoding = function(enc) {
        this._encoding = enc || 'utf8';
        var self = this;
        if (!this._encodingWrapped) {
            this._encodingWrapped = true;
            var origEmit = this.emit;
            this.emit = function(name, chunk) {
                if (name === 'data' && self._encoding && chunk != null && typeof chunk !== 'string') {
                    var args = Array.prototype.slice.call(arguments);
                    args[1] = (typeof Buffer !== 'undefined' && Buffer.isBuffer(chunk))
                        ? chunk.toString(self._encoding)
                        : String(chunk);
                    return origEmit.apply(this, args);
                }
                return origEmit.apply(this, arguments);
            };
        }
        return this;
    };
    Readable.prototype.resume = function() {
        this._flowing = true;
        this._drainBuffer();
        this._pump();
        return this;
    };
    Readable.prototype.pipe = function(dest, opts) {
        opts = opts || {};
        var self = this;
        var ended = false;
        var endDest = opts.end !== false;
        this.on('data', function(chunk) {
            var ok = dest.write(chunk);
            if (!ok) self.pause();
        });
        dest.on && dest.on('drain', function() { self.resume(); });
        this.on('end', function() {
            if (ended) return;
            ended = true;
            if (endDest && typeof dest.end === 'function') dest.end();
        });
        this.on('error', function(err) {
            if (typeof dest.destroy === 'function') dest.destroy(err);
        });
        return dest;
    };
    Readable.prototype.unpipe = function(_dest) {
        // We don't track multiple pipe targets — pause() effectively
        // halts the pipe. Fine for the common single-pipe case.
        this.pause();
        return this;
    };
    Readable.prototype.destroy = function(err) {
        if (this._destroyed) return this;
        this._destroyed = true;
        this._readable = false;
        if (err) this.errored = err;
        var self = this;
        Promise.resolve().then(function() {
            if (err) self.emit('error', err);
            self.emit('close');
        });
        return this;
    };
    Object.defineProperty(Readable.prototype, 'readable', {
        get: function() { return this._readable && !this._ended && !this._destroyed; },
    });
    Object.defineProperty(Readable.prototype, 'destroyed', {
        get: function() { return this._destroyed; },
    });
    Object.defineProperty(Readable.prototype, 'readableEnded', {
        get: function() { return this._ended; },
    });

    // Async-iterator interop. Node makes Readable async-iterable.
    Readable.prototype[Symbol.asyncIterator] = function() {
        var self = this;
        var pending = [];
        var resolvers = [];
        var ended = false;
        var error = null;

        self.on('data', function(chunk) {
            if (resolvers.length) {
                var r = resolvers.shift();
                r({ value: chunk, done: false });
            } else {
                pending.push(chunk);
            }
        });
        self.on('end', function() {
            ended = true;
            while (resolvers.length) {
                resolvers.shift()({ value: undefined, done: true });
            }
        });
        self.on('error', function(e) {
            error = e;
            while (resolvers.length) {
                var r = resolvers.shift();
                r(Promise.reject(e));
            }
        });

        return {
            next: function() {
                if (error) return Promise.reject(error);
                if (pending.length) {
                    return Promise.resolve({ value: pending.shift(), done: false });
                }
                if (ended) {
                    return Promise.resolve({ value: undefined, done: true });
                }
                return new Promise(function(resolve) { resolvers.push(resolve); });
            },
            return: function() {
                self.destroy();
                return Promise.resolve({ value: undefined, done: true });
            },
        };
    };

    Readable.from = function(iterable, opts) {
        var r = new Readable(opts);
        // Sync iterable (Array, generator) — feed synchronously after a
        // microtask tick so listeners can attach.
        if (iterable && typeof iterable[Symbol.iterator] === 'function'
            && typeof iterable[Symbol.asyncIterator] !== 'function') {
            Promise.resolve().then(function() {
                try {
                    for (var v of iterable) r.push(v);
                    r.push(null);
                } catch (e) { r.destroy(e); }
            });
            return r;
        }
        // Async iterable.
        if (iterable && typeof iterable[Symbol.asyncIterator] === 'function') {
            (async function() {
                try {
                    for await (var v of iterable) r.push(v);
                    r.push(null);
                } catch (e) { r.destroy(e); }
            })();
            return r;
        }
        // Single value fallback — wrap in a one-element array.
        Promise.resolve().then(function() {
            r.push(iterable);
            r.push(null);
        });
        return r;
    };

    // --- Writable ---------------------------------------------------------
    function Writable(opts) {
        if (!(this instanceof Writable)) return new Writable(opts);
        EventEmitter.call(this);
        this._events = this._events || Object.create(null);
        opts = opts || {};
        this._writable = true;
        this._destroyed = false;
        this._ended = false;
        this._finished = false;
        this._highWaterMark = opts.highWaterMark || DEFAULT_HWM;
        this._pending = 0;
        this._writeFn = (opts.write || function(_c, _e, cb) { cb && cb(); }).bind(this);
        this._writevFn = opts.writev ? opts.writev.bind(this) : null;
        this._finalFn = opts.final ? opts.final.bind(this) : null;
    }
    Writable.prototype = Object.create(EventEmitter.prototype);
    Writable.prototype.constructor = Writable;

    Writable.prototype.write = function(chunk, encoding, cb) {
        if (typeof encoding === 'function') { cb = encoding; encoding = null; }
        if (this._destroyed || this._ended) {
            var err = new Error('write after end');
            err.code = 'ERR_STREAM_WRITE_AFTER_END';
            if (cb) Promise.resolve().then(function() { cb(err); });
            this.emit('error', err);
            return false;
        }
        var self = this;
        var size = chunkSize(chunk);
        this._pending += size;
        var underWater = this._pending < this._highWaterMark;
        this._writeFn(chunk, encoding, function(err) {
            self._pending -= size;
            if (err) {
                self.emit('error', err);
            } else if (self._pending < self._highWaterMark
                       && self._pending + size >= self._highWaterMark) {
                // Crossed back below HWM — fire 'drain'.
                self.emit('drain');
            }
            if (cb) cb(err);
        });
        return underWater;
    };
    Writable.prototype.end = function(chunk, encoding, cb) {
        if (typeof chunk === 'function') { cb = chunk; chunk = undefined; }
        if (typeof encoding === 'function') { cb = encoding; encoding = null; }
        if (chunk !== undefined && chunk !== null) this.write(chunk, encoding);
        if (this._ended) { if (cb) Promise.resolve().then(cb); return this; }
        this._ended = true;
        var self = this;
        var finish = function(err) {
            if (err) { self.emit('error', err); if (cb) cb(err); return; }
            self._finished = true;
            self.emit('finish');
            self.emit('close');
            if (cb) cb();
        };
        // Defer to a microtask so listeners attached AFTER end() (the
        // canonical Node pattern: `ws.end(chunk); ws.on('finish', …);`)
        // still observe the event. `_finalFn` and the synchronous-
        // write fast path otherwise fire 'finish' before the listener
        // is attached.
        Promise.resolve().then(function() {
            if (self._finalFn) self._finalFn(finish);
            else finish();
        });
        return this;
    };
    Writable.prototype.destroy = function(err) {
        if (this._destroyed) return this;
        this._destroyed = true;
        this._writable = false;
        if (err) this.errored = err;
        var self = this;
        Promise.resolve().then(function() {
            if (err) self.emit('error', err);
            self.emit('close');
        });
        return this;
    };
    Writable.prototype.cork = function() {};
    Writable.prototype.uncork = function() {};
    Writable.prototype.setDefaultEncoding = function() { return this; };
    Object.defineProperty(Writable.prototype, 'writable', {
        get: function() {
            return this._writable && !this._destroyed && !this._ended;
        },
    });
    Object.defineProperty(Writable.prototype, 'destroyed', {
        get: function() { return this._destroyed; },
    });
    Object.defineProperty(Writable.prototype, 'writableEnded', {
        get: function() { return this._ended; },
    });
    Object.defineProperty(Writable.prototype, 'writableFinished', {
        get: function() { return this._finished; },
    });
    Object.defineProperty(Writable.prototype, 'writableLength', {
        get: function() { return this._pending; },
    });

    function chunkSize(chunk) {
        if (chunk == null) return 0;
        if (typeof chunk === 'string') return chunk.length;
        if (chunk.length !== undefined) return chunk.length;
        return 1;
    }

    // --- Duplex (separate read + write halves) ----------------------------
    //
    // Real Duplex: read() and write() track distinct buffers + states.
    // Different from Transform, which couples them via the user
    // _transform fn.
    function Duplex(opts) {
        if (!(this instanceof Duplex)) return new Duplex(opts);
        Readable.call(this, opts);
        // Re-init Writable's state without overwriting the Readable
        // properties we just set.
        opts = opts || {};
        this._writable = true;
        this._writableEnded = false;
        this._finished = false;
        this._pending = 0;
        this._writeFn = (opts.write || function(_c, _e, cb) { cb && cb(); }).bind(this);
        this._finalFn = opts.final ? opts.final.bind(this) : null;
    }
    Duplex.prototype = Object.create(Readable.prototype);
    Duplex.prototype.constructor = Duplex;

    Duplex.prototype.write = function(chunk, encoding, cb) {
        if (typeof encoding === 'function') { cb = encoding; encoding = null; }
        if (this._destroyed || this._writableEnded) {
            var err = new Error('write after end');
            err.code = 'ERR_STREAM_WRITE_AFTER_END';
            if (cb) Promise.resolve().then(function() { cb(err); });
            return false;
        }
        var self = this;
        var size = chunkSize(chunk);
        this._pending += size;
        var underWater = this._pending < this._highWaterMark;
        this._writeFn(chunk, encoding, function(err) {
            self._pending -= size;
            if (err) self.emit('error', err);
            else if (self._pending < self._highWaterMark
                     && self._pending + size >= self._highWaterMark) {
                self.emit('drain');
            }
            if (cb) cb(err);
        });
        return underWater;
    };
    Duplex.prototype.end = Writable.prototype.end;

    // --- Transform (write transforms into push) ---------------------------
    function Transform(opts) {
        if (!(this instanceof Transform)) return new Transform(opts);
        Readable.call(this, opts);
        opts = opts || {};
        this._writable = true;
        this._writableEnded = false;
        this._transform = (opts.transform || function(c, e, cb) { cb(null, c); }).bind(this);
        this._flush = opts.flush ? opts.flush.bind(this) : null;
    }
    Transform.prototype = Object.create(Readable.prototype);
    Transform.prototype.constructor = Transform;
    Transform.prototype.write = function(chunk, encoding, cb) {
        if (typeof encoding === 'function') { cb = encoding; encoding = null; }
        if (this._destroyed) {
            if (cb) cb(new Error('Transform destroyed'));
            return false;
        }
        var self = this;
        this._transform(chunk, encoding, function(err, out) {
            if (err) { self.emit('error', err); if (cb) cb(err); return; }
            if (out !== undefined && out !== null) self.push(out);
            if (cb) cb();
        });
        return true;
    };
    Transform.prototype.end = function(chunk, encoding, cb) {
        if (typeof chunk === 'function') { cb = chunk; chunk = undefined; }
        if (typeof encoding === 'function') { cb = encoding; encoding = null; }
        var self = this;
        var doFlush = function() {
            if (self._flush) {
                self._flush(function(err, out) {
                    if (err) { self.emit('error', err); if (cb) cb(err); return; }
                    if (out !== undefined && out !== null) self.push(out);
                    self.push(null);
                    if (cb) cb();
                });
            } else {
                self.push(null);
                if (cb) cb();
            }
        };
        if (chunk !== undefined && chunk !== null) {
            this.write(chunk, encoding, function() { doFlush(); });
        } else {
            doFlush();
        }
        return this;
    };

    // --- PassThrough ------------------------------------------------------
    function PassThrough(opts) {
        if (!(this instanceof PassThrough)) return new PassThrough(opts);
        Transform.call(this, Object.assign({}, opts, {
            transform: function(c, e, cb) { cb(null, c); },
        }));
    }
    PassThrough.prototype = Object.create(Transform.prototype);
    PassThrough.prototype.constructor = PassThrough;

    // --- pipeline ---------------------------------------------------------
    //
    // Node 20 supports several stage shapes:
    //   * stream object (Readable / Writable / Duplex / Transform)
    //   * iterable / async iterable (becomes a Readable)
    //   * async generator function `(prev) => ...` (becomes a Transform)
    //
    // This polyfill handles streams + iterables; generator-fn stages
    // get wrapped with a Readable.from(asyncFn(prev)) bridge.
    function pipeline() {
        var args = Array.prototype.slice.call(arguments);
        var cb = typeof args[args.length - 1] === 'function' ? args.pop() : null;
        if (args.length < 2) {
            var err = new Error('pipeline needs at least 2 streams');
            if (cb) cb(err);
            else throw err;
            return null;
        }
        var stages = args.map(function(s, i) {
            if (s && typeof s.pipe === 'function') return s;          // Readable / Duplex
            // Writables don't have `.pipe` but accept piped data.
            if (s && typeof s.write === 'function' && typeof s.end === 'function') return s;
            // Iterable / async iterable / generator fn.
            if (typeof s === 'function') {
                // Generator function — call with previous stream.
                return s; // resolved in the loop below with prev
            }
            if (s && (typeof s[Symbol.iterator] === 'function'
                || typeof s[Symbol.asyncIterator] === 'function')) {
                return Readable.from(s);
            }
            throw new Error('pipeline: stage ' + i + ' is not a stream / iterable / function');
        });

        var prev = stages[0];
        if (typeof prev === 'function') {
            // First stage can't be a function (no upstream).
            var e = new Error('pipeline: first stage cannot be a function');
            if (cb) cb(e); else throw e;
            return null;
        }
        for (var i = 1; i < stages.length; i++) {
            var stage = stages[i];
            if (typeof stage === 'function') {
                // Wrap as Readable.from(stage(prev))
                stage = Readable.from(stage(prev));
            }
            prev = prev.pipe(stage);
        }
        var settled = false;
        prev.on('finish', function() {
            if (settled) return;
            settled = true;
            if (cb) cb(null);
        });
        prev.on('end', function() {
            if (settled) return;
            settled = true;
            if (cb) cb(null);
        });
        prev.on('error', function(err) {
            if (settled) return;
            settled = true;
            if (cb) cb(err);
        });
        return prev;
    }

    // --- finished ---------------------------------------------------------
    function finished(stream, opts, cb) {
        if (typeof opts === 'function') { cb = opts; opts = {}; }
        opts = opts || {};
        var settled = false;
        var done = function(err) {
            if (settled) return;
            settled = true;
            if (cb) cb(err || null);
        };
        if (stream.on) {
            stream.on('end', function() { done(); });
            stream.on('finish', function() { done(); });
            stream.on('close', function() { done(); });
            stream.on('error', function(e) { done(e); });
        }
    }

    // --- compose (Node 20+) -----------------------------------------------
    //
    // Returns a Duplex whose readable side is the last stage's output
    // and whose writable side feeds the first stage. Implemented by
    // running the pipeline and exposing a façade.
    function compose() {
        var args = Array.prototype.slice.call(arguments);
        if (args.length === 0) {
            throw new Error('compose: need at least one stream');
        }
        var first = args[0];
        for (var i = 1; i < args.length; i++) first = first.pipe(args[i]);
        // The composed object proxies write to the first arg, end to
        // the first arg, and forwards 'data'/'end' from the last.
        var head = args[0];
        var tail = args[args.length - 1];
        var d = new Duplex({
            write: function(chunk, encoding, cb) {
                head.write(chunk, encoding);
                if (cb) cb();
            },
            final: function(cb) { head.end(); cb(); },
        });
        tail.on('data', function(c) { d.push(c); });
        tail.on('end', function() { d.push(null); });
        tail.on('error', function(e) { d.emit('error', e); });
        return d;
    }

    // --- addAbortSignal ---------------------------------------------------
    //
    // When the signal aborts, destroy the stream with an AbortError.
    function addAbortSignal(signal, stream) {
        if (!signal) return stream;
        if (signal.aborted) {
            stream.destroy(new Error('AbortError'));
            return stream;
        }
        var listener = function() {
            stream.destroy(new Error('AbortError'));
        };
        signal.addEventListener && signal.addEventListener('abort', listener);
        return stream;
    }

    // Legacy `Stream` base class — Node's `require('stream')` returns
    // a *callable* function (the legacy `Stream` constructor) with the
    // modern subclasses + helpers attached as own properties. Real npm
    // packages depend on the dual shape: `send/index.js` does
    // `util.inherits(SendStream, Stream)`, which fails our explicit
    // `superCtor must be a function` guard if `Stream` is a plain
    // object. Keep the existing `exports` namespace populated for
    // call-sites that use `require('stream').Readable` etc.; swap
    // `module.exports` to the constructor.
    function Stream() {
        EventEmitter.call(this);
    }
    Stream.prototype = Object.create(EventEmitter.prototype);
    Stream.prototype.constructor = Stream;
    Stream.prototype.pipe = Readable.prototype.pipe;

    // ---- Node ↔ Web Streams bridge (Node 17+) ---------------------
    // `Readable.toWeb(node)` / `Readable.fromWeb(web)` etc. real
    // libs (undici, node-fetch shims, web-streams-polyfill consumers)
    // depend on these even when only one side is in active use.
    Readable.toWeb = function(nodeReadable, _opts) {
        if (typeof globalThis.ReadableStream !== 'function') {
            throw new Error('Readable.toWeb: ReadableStream unavailable');
        }
        return new globalThis.ReadableStream({
            start: function(controller) {
                nodeReadable.on('data', function(chunk) {
                    controller.enqueue(chunk);
                });
                nodeReadable.on('end', function() {
                    try { controller.close(); } catch (_) {}
                });
                nodeReadable.on('error', function(err) {
                    try { controller.error(err); } catch (_) {}
                });
            },
            cancel: function() {
                if (typeof nodeReadable.destroy === 'function') {
                    try { nodeReadable.destroy(); } catch (_) {}
                }
            },
        });
    };
    Readable.fromWeb = function(webReadable, _opts) {
        // Wrap a Web ReadableStream as a Node Readable. We pull
        // chunks via `.getReader()` and emit them as `data` events;
        // EOF closes the reader and fires `end`.
        var reader = webReadable.getReader();
        var node = Readable.from((async function* () {
            while (true) {
                var step = await reader.read();
                if (step.done) return;
                yield step.value;
            }
        })());
        return node;
    };
    /// `Writable.toWeb(node)` — wrap a Node Writable so it behaves
    /// like a WHATWG WritableStream. The web stream's `write(chunk)`
    /// pushes into the node stream and resolves on `'drain'` /
    /// completion; `close()` calls `node.end()`; `abort()` calls
    /// `node.destroy(reason)`.
    Writable.toWeb = function(nodeWritable) {
        if (typeof WritableStream !== 'function') {
            throw new Error('Writable.toWeb: WritableStream global unavailable');
        }
        return new WritableStream({
            write: function(chunk) {
                return new Promise(function(resolve, reject) {
                    var ok = nodeWritable.write(chunk, function(err) {
                        if (err) reject(err);
                    });
                    if (ok) {
                        Promise.resolve().then(resolve);
                    } else {
                        nodeWritable.once('drain', resolve);
                        nodeWritable.once('error', reject);
                    }
                });
            },
            close: function() {
                return new Promise(function(resolve, reject) {
                    nodeWritable.end(function() { resolve(); });
                    nodeWritable.once('error', reject);
                });
            },
            abort: function(reason) {
                return new Promise(function(resolve) {
                    try { nodeWritable.destroy(reason); } catch (_) {}
                    Promise.resolve().then(resolve);
                });
            },
        });
    };

    /// `Writable.fromWeb(web)` — wrap a WHATWG WritableStream as a
    /// Node Writable. Each `_write` call grabs a writer and forwards
    /// the chunk; `_final` closes; `_destroy` aborts.
    Writable.fromWeb = function(webWritable) {
        // Lock the writer once at construction so the same handle is
        // reused across writes — getWriter() throws on double-lock.
        var writer = webWritable.getWriter();
        var node = new Writable({
            write: function(chunk, enc, cb) {
                try {
                    // Coerce strings so the WritableStream sees a
                    // Uint8Array regardless of the Node-side encoding.
                    var data;
                    if (typeof chunk === 'string') {
                        data = new TextEncoder().encode(chunk);
                    } else if (chunk && chunk.buffer && chunk.byteLength != null) {
                        data = chunk;
                    } else {
                        data = new Uint8Array(chunk);
                    }
                    var p = writer.write(data);
                    if (p && typeof p.then === 'function') {
                        p.then(function() { cb(); }, cb);
                    } else {
                        cb();
                    }
                } catch (e) { cb(e); }
            },
            final: function(cb) {
                try {
                    var p = writer.close();
                    if (p && typeof p.then === 'function') {
                        p.then(function() { cb(); }, cb);
                    } else {
                        cb();
                    }
                } catch (e) { cb(e); }
            },
            destroy: function(err, cb) {
                try {
                    var p = writer.abort(err);
                    if (p && typeof p.then === 'function') {
                        p.then(function() { cb(err); }, function() { cb(err); });
                    } else {
                        cb(err);
                    }
                } catch (_) { cb(err); }
            },
        });
        return node;
    };

    /// stream.duplexPair — Node 22+. Returns `[a, b]` two Duplex
    /// streams cross-connected: writes to `a` appear on reads from
    /// `b` and vice versa. Useful for in-process protocol simulations.
    function duplexPair() {
        var a = new PassThrough();
        var b = new PassThrough();
        a.pipe(b);
        b.pipe(a);
        return [a, b];
    }

    /// `stream.isDisturbed` / `isErrored` / `isReadable` — Node 16+
    /// static probes used by undici and friends to decide whether a
    /// stream has been touched. We expose them as best-effort
    /// duck-typed checks against our internal flags so consumers don't
    /// crash on probe.
    function isDisturbed(s) {
        if (s == null) return false;
        return !!(s._readableState && (s._readableState.dataEmitted ||
            s._readableState.endEmitted || s._readableState.errored ||
            s._readableState.destroyed)) ||
            !!(s._writableState && (s._writableState.errored ||
                s._writableState.destroyed)) ||
            !!s._disturbed;
    }
    function isErrored(s) {
        if (s == null) return false;
        return !!(s.errored || (s._readableState && s._readableState.errored) ||
            (s._writableState && s._writableState.errored));
    }
    function isReadable(s) {
        if (s == null || typeof s.read !== 'function') return false;
        var rs = s._readableState;
        if (!rs) return true;
        return !rs.endEmitted && !rs.errored && !rs.destroyed;
    }
    /// `stream.getDefaultHighWaterMark(objectMode)` / `set` — Node 19.9+
    /// runtime knobs for default buffering. We track them in module
    /// state; the streams we already have are constructed before this
    /// is mutated, so the value is consultative for code that probes
    /// the runtime configuration.
    var _hwm = { byte: 16384, object: 16 };
    function getDefaultHighWaterMark(objectMode) {
        return objectMode ? _hwm.object : _hwm.byte;
    }
    function setDefaultHighWaterMark(objectMode, value) {
        var v = (value | 0);
        if (v <= 0) {
            var err = new RangeError(
                'highWaterMark must be a positive integer');
            err.code = 'ERR_OUT_OF_RANGE';
            throw err;
        }
        if (objectMode) _hwm.object = v; else _hwm.byte = v;
    }

    exports.Readable       = Readable;
    exports.Writable       = Writable;
    exports.Duplex         = Duplex;
    exports.Transform      = Transform;
    exports.PassThrough    = PassThrough;
    exports.pipeline       = pipeline;
    exports.finished       = finished;
    exports.compose        = compose;
    exports.addAbortSignal = addAbortSignal;
    exports.duplexPair     = duplexPair;
    exports.isDisturbed    = isDisturbed;
    exports.isErrored      = isErrored;
    exports.isReadable     = isReadable;
    exports.getDefaultHighWaterMark = getDefaultHighWaterMark;
    exports.setDefaultHighWaterMark = setDefaultHighWaterMark;
    exports.Stream         = Stream;
    /// stream.promises — Node 15+ Promise-shaped wrappers for
    /// pipeline / finished. Same names as `require('stream/promises')`.
    exports.promises = {
        pipeline: function() {
            var args = Array.prototype.slice.call(arguments);
            return new Promise(function(resolve, reject) {
                args.push(function(err) { if (err) reject(err); else resolve(); });
                pipeline.apply(null, args);
            });
        },
        finished: function(stream, opts) {
            return new Promise(function(resolve, reject) {
                finished(stream, opts || {}, function(err) {
                    if (err) reject(err); else resolve();
                });
            });
        },
    };

    Stream.Readable        = Readable;
    Stream.Writable        = Writable;
    Stream.Duplex          = Duplex;
    Stream.Transform       = Transform;
    Stream.PassThrough     = PassThrough;
    Stream.pipeline        = pipeline;
    Stream.finished        = finished;
    Stream.compose         = compose;
    Stream.addAbortSignal  = addAbortSignal;
    Stream.duplexPair      = duplexPair;
    Stream.isDisturbed     = isDisturbed;
    Stream.isErrored       = isErrored;
    Stream.isReadable      = isReadable;
    Stream.getDefaultHighWaterMark = getDefaultHighWaterMark;
    Stream.setDefaultHighWaterMark = setDefaultHighWaterMark;
    Stream.promises        = exports.promises;
    Stream.Stream          = Stream;

    module.exports = Stream;
});
