// Small Web-API polyfills that most Node.js scripts now assume. Wired
// as globals, not modules, to match the browser/Node semantics.

(function installWebCompat() {
    // structuredClone — ES2022. QuickJS-NG typically has it; fall back
    // to a type-preserving deep-copy. Pure JSON round-trip flattens
    // Date / Map / Set / TypedArray / Buffer so we walk the graph by
    // hand for those, and fall back to JSON for plain objects.
    if (typeof globalThis.structuredClone !== 'function') {
        globalThis.structuredClone = function(value, _opts) {
            return _structuredCloneInner(value, new Map());
        };
        function _structuredCloneInner(v, seen) {
            if (v === null || typeof v !== 'object') return v;
            if (seen.has(v)) return seen.get(v);
            // Date
            if (v instanceof Date) { var d = new Date(v.getTime()); seen.set(v, d); return d; }
            // RegExp
            if (v instanceof RegExp) { var re = new RegExp(v.source, v.flags); seen.set(v, re); return re; }
            // ArrayBuffer
            if (v instanceof ArrayBuffer) {
                var ab = new ArrayBuffer(v.byteLength);
                new Uint8Array(ab).set(new Uint8Array(v));
                seen.set(v, ab);
                return ab;
            }
            // Typed arrays (preserves the constructor + offset/length)
            if (ArrayBuffer.isView(v) && !(v instanceof DataView)) {
                var TC = v.constructor;
                var copy = new TC(v.length);
                copy.set(v);
                seen.set(v, copy);
                return copy;
            }
            if (v instanceof DataView) {
                var ab2 = new ArrayBuffer(v.byteLength);
                new Uint8Array(ab2).set(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
                var dv = new DataView(ab2);
                seen.set(v, dv);
                return dv;
            }
            // Map
            if (v instanceof Map) {
                var mm = new Map();
                seen.set(v, mm);
                v.forEach(function(val, key) {
                    mm.set(_structuredCloneInner(key, seen), _structuredCloneInner(val, seen));
                });
                return mm;
            }
            // Set
            if (v instanceof Set) {
                var ss = new Set();
                seen.set(v, ss);
                v.forEach(function(val) { ss.add(_structuredCloneInner(val, seen)); });
                return ss;
            }
            // Error
            if (v instanceof Error) {
                var EC = v.constructor;
                var er = new EC(v.message);
                if (v.stack) er.stack = v.stack;
                seen.set(v, er);
                return er;
            }
            // Array
            if (Array.isArray(v)) {
                var ar = new Array(v.length);
                seen.set(v, ar);
                for (var i = 0; i < v.length; i++) ar[i] = _structuredCloneInner(v[i], seen);
                return ar;
            }
            // Plain object: walk keys.
            var out = {};
            seen.set(v, out);
            var keys = Object.keys(v);
            for (var k = 0; k < keys.length; k++) {
                out[keys[k]] = _structuredCloneInner(v[keys[k]], seen);
            }
            return out;
        }
    }

    // ---- Intl stubs (JS engine doesn't ship full ICU) ---------------
    //
    // Real Intl needs ICU, which QuickJS doesn't bundle. Most
    // libraries probe `typeof Intl !== 'undefined'` then call into
    // `Intl.NumberFormat` / `Intl.DateTimeFormat` / `Intl.Collator`.
    // We surface the constructors with English-only behavior so the
    // probe + canonical formatting paths work; non-English locales
    // fall back to ASCII formatting (caller can detect via
    // `resolvedOptions().locale === 'en-US'`).
    if (typeof globalThis.Intl !== 'object' || globalThis.Intl === null) {
        var IntlObj = {};
        function _toString(v) { return v == null ? '' : String(v); }

        function NumberFormat(locales, options) {
            if (!(this instanceof NumberFormat)) return new NumberFormat(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        NumberFormat.prototype.format = function(n) {
            n = Number(n);
            if (!isFinite(n)) {
                if (isNaN(n)) return 'NaN';
                return n > 0 ? '∞' : '-∞';
            }
            var opts = this._opts;
            // minimumFractionDigits / maximumFractionDigits.
            var min = opts.minimumFractionDigits;
            var max = opts.maximumFractionDigits;
            var fixed = (typeof max === 'number') ? max
                      : (typeof min === 'number') ? min
                      : undefined;
            var s = (typeof fixed === 'number') ? n.toFixed(fixed) : String(n);
            if (typeof min === 'number') {
                var dot = s.indexOf('.');
                var have = dot < 0 ? 0 : s.length - dot - 1;
                if (have < min) {
                    if (dot < 0) s += '.';
                    while (have < min) { s += '0'; have++; }
                }
            }
            // Group separators.
            if (opts.useGrouping !== false) {
                var sign = '';
                if (s.charAt(0) === '-') { sign = '-'; s = s.slice(1); }
                var dotIdx = s.indexOf('.');
                var int = dotIdx < 0 ? s : s.slice(0, dotIdx);
                var frac = dotIdx < 0 ? '' : s.slice(dotIdx);
                int = int.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
                s = sign + int + frac;
            }
            // Style: percent / currency.
            if (opts.style === 'percent') s = (Number(n) * 100) + '%';
            else if (opts.style === 'currency' && opts.currency) {
                s = opts.currency + ' ' + s;
            }
            return s;
        };
        NumberFormat.prototype.formatToParts = function(n) {
            return [{ type: 'integer', value: this.format(n) }];
        };
        NumberFormat.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, numberingSystem: 'latn' }, this._opts);
        };
        NumberFormat.supportedLocalesOf = function(locales) {
            return Array.isArray(locales) ? locales.slice() : [locales].filter(Boolean);
        };
        IntlObj.NumberFormat = NumberFormat;

        function DateTimeFormat(locales, options) {
            if (!(this instanceof DateTimeFormat)) return new DateTimeFormat(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        DateTimeFormat.prototype.format = function(d) {
            var date = (d instanceof Date) ? d : new Date(d);
            // Default: locale-style date+time.
            return date.toLocaleString
                ? date.toLocaleString(this._locale)
                : date.toString();
        };
        DateTimeFormat.prototype.formatToParts = function(d) {
            return [{ type: 'literal', value: this.format(d) }];
        };
        DateTimeFormat.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, calendar: 'gregory',
                                   timeZone: 'UTC', numberingSystem: 'latn' }, this._opts);
        };
        DateTimeFormat.supportedLocalesOf = NumberFormat.supportedLocalesOf;
        IntlObj.DateTimeFormat = DateTimeFormat;

        function Collator(locales, options) {
            if (!(this instanceof Collator)) return new Collator(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        Collator.prototype.compare = function(a, b) {
            a = _toString(a); b = _toString(b);
            if (this._opts.sensitivity === 'base') {
                a = a.toLowerCase(); b = b.toLowerCase();
            }
            if (this._opts.numeric) {
                return a.localeCompare(b, undefined, { numeric: true });
            }
            return a < b ? -1 : a > b ? 1 : 0;
        };
        Collator.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, sensitivity: 'variant',
                                   numeric: false, caseFirst: 'false' }, this._opts);
        };
        Collator.supportedLocalesOf = NumberFormat.supportedLocalesOf;
        IntlObj.Collator = Collator;

        function PluralRules(locales, options) {
            if (!(this instanceof PluralRules)) return new PluralRules(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        PluralRules.prototype.select = function(n) {
            // English-only: 1 → one, anything else → other.
            return n === 1 ? 'one' : 'other';
        };
        PluralRules.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, type: 'cardinal',
                                   pluralCategories: ['one', 'other'] }, this._opts);
        };
        PluralRules.supportedLocalesOf = NumberFormat.supportedLocalesOf;
        IntlObj.PluralRules = PluralRules;

        function ListFormat(locales, options) {
            if (!(this instanceof ListFormat)) return new ListFormat(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        ListFormat.prototype.format = function(arr) {
            arr = Array.from(arr || []).map(_toString);
            if (arr.length === 0) return '';
            if (arr.length === 1) return arr[0];
            if (arr.length === 2) return arr[0] + ' and ' + arr[1];
            return arr.slice(0, -1).join(', ') + ', and ' + arr[arr.length - 1];
        };
        ListFormat.prototype.formatToParts = function(arr) {
            return [{ type: 'literal', value: this.format(arr) }];
        };
        ListFormat.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, type: 'conjunction', style: 'long' }, this._opts);
        };
        ListFormat.supportedLocalesOf = NumberFormat.supportedLocalesOf;
        IntlObj.ListFormat = ListFormat;

        function RelativeTimeFormat(locales, options) {
            if (!(this instanceof RelativeTimeFormat)) return new RelativeTimeFormat(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        RelativeTimeFormat.prototype.format = function(value, unit) {
            if (value === 0) return 'this ' + unit;
            var abs = Math.abs(value);
            var u = unit + (abs === 1 ? '' : 's');
            return value > 0
                ? 'in ' + abs + ' ' + u
                : abs + ' ' + u + ' ago';
        };
        RelativeTimeFormat.prototype.formatToParts = function(value, unit) {
            return [{ type: 'literal', value: this.format(value, unit) }];
        };
        RelativeTimeFormat.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, style: 'long', numeric: 'always' }, this._opts);
        };
        RelativeTimeFormat.supportedLocalesOf = NumberFormat.supportedLocalesOf;
        IntlObj.RelativeTimeFormat = RelativeTimeFormat;

        function Segmenter(locales, options) {
            if (!(this instanceof Segmenter)) return new Segmenter(locales, options);
            this._opts = options || {};
            this._locale = Array.isArray(locales) ? (locales[0] || 'en-US') : (locales || 'en-US');
        }
        Segmenter.prototype.segment = function(input) {
            var s = _toString(input);
            var granularity = (this._opts && this._opts.granularity) || 'grapheme';
            var segments;
            if (granularity === 'word') {
                segments = s.match(/\S+|\s+/g) || [];
            } else if (granularity === 'sentence') {
                segments = s.match(/[^.!?]+[.!?]?/g) || [s];
            } else {
                // grapheme: code-point chunks (close enough for ASCII).
                segments = Array.from(s);
            }
            var idx = 0;
            return {
                [Symbol.iterator]: function() {
                    var i = 0;
                    return { next: function() {
                        if (i >= segments.length) return { done: true };
                        var seg = segments[i];
                        var ent = { segment: seg, index: idx, input: s };
                        idx += seg.length;
                        i++;
                        return { value: ent, done: false };
                    } };
                },
            };
        };
        Segmenter.prototype.resolvedOptions = function() {
            return Object.assign({ locale: this._locale, granularity: 'grapheme' }, this._opts);
        };
        Segmenter.supportedLocalesOf = NumberFormat.supportedLocalesOf;
        IntlObj.Segmenter = Segmenter;

        IntlObj.getCanonicalLocales = function(locales) {
            if (!locales) return [];
            return (Array.isArray(locales) ? locales : [locales]).map(_toString);
        };

        globalThis.Intl = IntlObj;
    }

    // ---- AsyncIterator global (Stage 3 / Node 22+) ----------------
    //
    // QuickJS provides `Iterator` natively but not `AsyncIterator`,
    // even though TC39 has it as a global constructor with a method
    // bag (map/filter/take/drop/toArray/forEach/some/every/find).
    // We synthesise it from the well-known
    // `%AsyncIteratorPrototype%` (every async generator inherits
    // from it) so `class X extends AsyncIterator { ... }` and
    // feature-detect probes work.
    if (typeof globalThis.AsyncIterator === 'undefined') {
        var asyncGenFn = (async function*() {})();
        var asyncIteratorProto = Object.getPrototypeOf(
            Object.getPrototypeOf(asyncGenFn));
        var AsyncIteratorCtor = function AsyncIterator() {
            if (new.target === AsyncIteratorCtor) {
                throw new TypeError(
                    'AsyncIterator is not a constructor; subclass it instead');
            }
        };
        AsyncIteratorCtor.prototype = asyncIteratorProto;
        AsyncIteratorCtor.from = function from(iterable) {
            if (iterable && typeof iterable[Symbol.asyncIterator] === 'function') {
                return iterable[Symbol.asyncIterator]();
            }
            if (iterable && typeof iterable[Symbol.iterator] === 'function') {
                var it = iterable[Symbol.iterator]();
                return (async function*() {
                    var step = it.next();
                    while (!step.done) { yield step.value; step = it.next(); }
                })();
            }
            throw new TypeError(
                'AsyncIterator.from: argument must be iterable or async iterable');
        };
        Object.defineProperty(globalThis, 'AsyncIterator', {
            value: AsyncIteratorCtor, writable: true, configurable: true,
        });
    }

    // ---- Iterator Helpers (Stage 3 / Node 22+) ---------------------
    //
    // ES2025 Iterator Helpers extend the `Iterator` global with
    // `from(iter)` static, plus `Iterator.prototype.{map, filter, take,
    // drop, reduce, toArray, forEach, every, some, find, flatMap}`.
    // We install the constructor if the engine doesn't ship one (QuickJS
    // is the realistic case) and patch the prototype every time so
    // older engine builds get the helpers too.
    (function installIteratorHelpers() {
        var IterCtor = globalThis.Iterator;
        if (typeof IterCtor !== 'function') {
            // Synthesize a prototype that any iterator object's
            // `Symbol.iterator` chain can hang off. The Stage 3 spec
            // uses `%IteratorPrototype%` — we materialise it from
            // a generator's prototype (every iterator engine ships
            // shares this object).
            var genProto = Object.getPrototypeOf(
                Object.getPrototypeOf((function*(){})())
            );
            IterCtor = function Iterator() {
                throw new TypeError('Iterator: not constructable');
            };
            IterCtor.prototype = genProto;
            try {
                Object.defineProperty(globalThis, 'Iterator', {
                    value: IterCtor, writable: true, configurable: true,
                });
            } catch (_) {}
        }
        var proto = IterCtor.prototype;
        if (!proto) return;

        function _wrap(generator) {
            // Wrap a generator in a fresh iterator object whose
            // prototype is the Iterator prototype so chained helpers
            // resolve correctly.
            var out = generator;
            try { Object.setPrototypeOf(out, proto); } catch (_) {}
            return out;
        }

        function _iterOf(value) {
            // Accept iterators (return them as-is) and iterables
            // (call Symbol.iterator). Matches the spec's
            // `GetIteratorFlattenable`.
            if (value == null) {
                throw new TypeError('Iterator.from: argument is nullish');
            }
            if (typeof value.next === 'function') return value;
            var it = value[Symbol.iterator];
            if (typeof it === 'function') return it.call(value);
            throw new TypeError('Iterator.from: argument is not iterable');
        }

        if (typeof IterCtor.from !== 'function') {
            IterCtor.from = function from(iterable) {
                var it = _iterOf(iterable);
                return _wrap((function*() {
                    var step = it.next();
                    while (!step.done) { yield step.value; step = it.next(); }
                })());
            };
        }

        function define(name, fn) {
            if (typeof proto[name] === 'function') return;
            try {
                Object.defineProperty(proto, name, {
                    value: fn, writable: true, configurable: true,
                });
            } catch (_) {}
        }

        define('map', function map(mapper) {
            if (typeof mapper !== 'function') {
                throw new TypeError('Iterator.map: mapper must be a function');
            }
            var src = this;
            return _wrap((function*() {
                var i = 0;
                var step = src.next();
                while (!step.done) {
                    yield mapper(step.value, i++);
                    step = src.next();
                }
            })());
        });

        define('filter', function filter(pred) {
            if (typeof pred !== 'function') {
                throw new TypeError('Iterator.filter: predicate must be a function');
            }
            var src = this;
            return _wrap((function*() {
                var i = 0;
                var step = src.next();
                while (!step.done) {
                    if (pred(step.value, i++)) yield step.value;
                    step = src.next();
                }
            })());
        });

        define('take', function take(limit) {
            limit = Number(limit);
            if (!Number.isFinite(limit) || limit < 0) {
                throw new RangeError('Iterator.take: limit must be a non-negative number');
            }
            limit = Math.floor(limit);
            var src = this;
            return _wrap((function*() {
                var n = 0;
                while (n < limit) {
                    var step = src.next();
                    if (step.done) return;
                    yield step.value;
                    n++;
                }
            })());
        });

        define('drop', function drop(limit) {
            limit = Number(limit);
            if (!Number.isFinite(limit) || limit < 0) {
                throw new RangeError('Iterator.drop: limit must be a non-negative number');
            }
            limit = Math.floor(limit);
            var src = this;
            return _wrap((function*() {
                var n = 0;
                var step = src.next();
                while (!step.done) {
                    if (n >= limit) yield step.value;
                    n++;
                    step = src.next();
                }
            })());
        });

        define('reduce', function reduce(reducer, initialValue) {
            if (typeof reducer !== 'function') {
                throw new TypeError('Iterator.reduce: reducer must be a function');
            }
            var acc;
            var i = 0;
            var step = this.next();
            if (arguments.length < 2) {
                if (step.done) {
                    throw new TypeError(
                        'Iterator.reduce: empty iterator with no initial value');
                }
                acc = step.value;
                step = this.next();
                i = 1;
            } else {
                acc = initialValue;
            }
            while (!step.done) {
                acc = reducer(acc, step.value, i++);
                step = this.next();
            }
            return acc;
        });

        define('toArray', function toArray() {
            var out = [];
            var step = this.next();
            while (!step.done) {
                out.push(step.value);
                step = this.next();
            }
            return out;
        });

        define('forEach', function forEach(fn) {
            if (typeof fn !== 'function') {
                throw new TypeError('Iterator.forEach: argument must be a function');
            }
            var i = 0;
            var step = this.next();
            while (!step.done) {
                fn(step.value, i++);
                step = this.next();
            }
        });

        define('every', function every(pred) {
            if (typeof pred !== 'function') {
                throw new TypeError('Iterator.every: predicate must be a function');
            }
            var i = 0;
            var step = this.next();
            while (!step.done) {
                if (!pred(step.value, i++)) return false;
                step = this.next();
            }
            return true;
        });

        define('some', function some(pred) {
            if (typeof pred !== 'function') {
                throw new TypeError('Iterator.some: predicate must be a function');
            }
            var i = 0;
            var step = this.next();
            while (!step.done) {
                if (pred(step.value, i++)) return true;
                step = this.next();
            }
            return false;
        });

        define('find', function find(pred) {
            if (typeof pred !== 'function') {
                throw new TypeError('Iterator.find: predicate must be a function');
            }
            var i = 0;
            var step = this.next();
            while (!step.done) {
                if (pred(step.value, i++)) return step.value;
                step = this.next();
            }
            return undefined;
        });

        define('flatMap', function flatMap(mapper) {
            if (typeof mapper !== 'function') {
                throw new TypeError('Iterator.flatMap: mapper must be a function');
            }
            var src = this;
            return _wrap((function*() {
                var i = 0;
                var step = src.next();
                while (!step.done) {
                    var sub = mapper(step.value, i++);
                    var inner = _iterOf(sub);
                    var s2 = inner.next();
                    while (!s2.done) { yield s2.value; s2 = inner.next(); }
                    step = src.next();
                }
            })());
        });
    })();

    // ---- JSON.rawJSON / isRawJSON (Stage 4, Node 21+) -------------
    //
    // `JSON.rawJSON(text)` returns a value that JSON.stringify
    // inlines verbatim — useful for embedding precomputed JSON
    // (BigInt strings, large arrays) without parse → stringify
    // re-encoding. We tag with a private symbol so `isRawJSON`
    // recognises the value, and provide `toJSON` so naive
    // serialisers (JSON.stringify without a replacer) still emit a
    // valid representation.
    if (typeof JSON.rawJSON !== 'function') {
        var RAW_JSON_TAG = Symbol.for('JSON.rawJSON.tag');
        Object.defineProperty(JSON, 'rawJSON', {
            value: function rawJSON(text) {
                var s = String(text);
                // Validate input is parseable JSON per spec.
                JSON.parse(s);
                var out = Object.create(null);
                Object.defineProperty(out, RAW_JSON_TAG, { value: true });
                Object.defineProperty(out, 'rawJSON', { value: s, enumerable: true });
                Object.defineProperty(out, 'toJSON', {
                    value: function() { return JSON.parse(s); },
                });
                return out;
            },
            writable: true, configurable: true,
        });
        Object.defineProperty(JSON, 'isRawJSON', {
            value: function isRawJSON(v) {
                return !!(v && typeof v === 'object' && v[RAW_JSON_TAG] === true);
            },
            writable: true, configurable: true,
        });
    }

    // ---- Symbol.dispose / Symbol.asyncDispose (Node 20+) ------------

    // performance.now — no monotonic clock inside the sandbox, but
    // Date.now gives us something non-decreasing for most practical
    // purposes. Hrtime-style scripts won't crash.
    if (typeof globalThis.performance !== 'object' || typeof globalThis.performance.now !== 'function') {
        globalThis.performance = globalThis.performance || {};
        globalThis.performance.now = function() { return Date.now(); };
    }
    // Fill the rest of the User Timing Level 3 surface (Node 16+).
    // `performance.mark/measure` keep an in-process buffer so libraries
    // that probe `getEntries*` work even though our `performance.now`
    // resolution is millisecond-grade. Real-time performance work
    // benefits from `perf_hooks` directly; these globals satisfy
    // structural probes.
    if (typeof globalThis.performance.timeOrigin !== 'number') {
        Object.defineProperty(globalThis.performance, 'timeOrigin', {
            value: Date.now(), enumerable: true, writable: false, configurable: false,
        });
    }
    if (!globalThis.performance._entries) globalThis.performance._entries = [];
    if (typeof globalThis.performance.mark !== 'function') {
        globalThis.performance.mark = function(name, options) {
            var entry = {
                name: String(name),
                entryType: 'mark',
                startTime: (options && typeof options.startTime === 'number')
                    ? options.startTime : globalThis.performance.now(),
                duration: 0,
                detail: options && options.detail,
            };
            globalThis.performance._entries.push(entry);
            return entry;
        };
    }
    if (typeof globalThis.performance.measure !== 'function') {
        globalThis.performance.measure = function(name, startMarkOrOpts, endMark) {
            var startTime = 0;
            var endTime = globalThis.performance.now();
            var detail;
            if (typeof startMarkOrOpts === 'string') {
                var startE = globalThis.performance._entries.find(function(e) {
                    return e.name === startMarkOrOpts && e.entryType === 'mark';
                });
                if (startE) startTime = startE.startTime;
            } else if (startMarkOrOpts && typeof startMarkOrOpts === 'object') {
                if (typeof startMarkOrOpts.start === 'number') startTime = startMarkOrOpts.start;
                if (typeof startMarkOrOpts.end === 'number') endTime = startMarkOrOpts.end;
                if (typeof startMarkOrOpts.duration === 'number') {
                    endTime = startTime + startMarkOrOpts.duration;
                }
                detail = startMarkOrOpts.detail;
            }
            if (typeof endMark === 'string') {
                var endE = globalThis.performance._entries.find(function(e) {
                    return e.name === endMark && e.entryType === 'mark';
                });
                if (endE) endTime = endE.startTime;
            }
            var entry = {
                name: String(name),
                entryType: 'measure',
                startTime: startTime,
                duration: endTime - startTime,
                detail: detail,
            };
            globalThis.performance._entries.push(entry);
            return entry;
        };
    }
    if (typeof globalThis.performance.clearMarks !== 'function') {
        globalThis.performance.clearMarks = function(name) {
            globalThis.performance._entries = globalThis.performance._entries.filter(function(e) {
                if (e.entryType !== 'mark') return true;
                return name !== undefined && e.name !== name;
            });
        };
    }
    if (typeof globalThis.performance.clearMeasures !== 'function') {
        globalThis.performance.clearMeasures = function(name) {
            globalThis.performance._entries = globalThis.performance._entries.filter(function(e) {
                if (e.entryType !== 'measure') return true;
                return name !== undefined && e.name !== name;
            });
        };
    }
    if (typeof globalThis.performance.getEntries !== 'function') {
        globalThis.performance.getEntries = function() {
            return globalThis.performance._entries.slice();
        };
    }
    if (typeof globalThis.performance.getEntriesByName !== 'function') {
        globalThis.performance.getEntriesByName = function(name, type) {
            return globalThis.performance._entries.filter(function(e) {
                if (e.name !== name) return false;
                if (type !== undefined && e.entryType !== type) return false;
                return true;
            });
        };
    }
    if (typeof globalThis.performance.getEntriesByType !== 'function') {
        globalThis.performance.getEntriesByType = function(type) {
            return globalThis.performance._entries.filter(function(e) { return e.entryType === type; });
        };
    }

    // ---- PerformanceObserver / PerformanceEntry classes -----------
    //
    // These let libraries subscribe to mark/measure events. The
    // observer fires synchronously after each mark/measure when its
    // observed entryTypes match.
    if (typeof globalThis.PerformanceEntry !== 'function') {
        function PerformanceEntry() {
            this.name = '';
            this.entryType = '';
            this.startTime = 0;
            this.duration = 0;
        }
        globalThis.PerformanceEntry = PerformanceEntry;
        globalThis.PerformanceMark = function PerformanceMark() {
            PerformanceEntry.call(this);
            this.entryType = 'mark';
        };
        globalThis.PerformanceMark.prototype = Object.create(PerformanceEntry.prototype);
        globalThis.PerformanceMeasure = function PerformanceMeasure() {
            PerformanceEntry.call(this);
            this.entryType = 'measure';
        };
        globalThis.PerformanceMeasure.prototype = Object.create(PerformanceEntry.prototype);
        function PerformanceObserverEntryList(entries) { this._entries = entries.slice(); }
        PerformanceObserverEntryList.prototype.getEntries = function() {
            return this._entries.slice();
        };
        PerformanceObserverEntryList.prototype.getEntriesByName = function(name, type) {
            return this._entries.filter(function(e) {
                return e.name === name && (type === undefined || e.entryType === type);
            });
        };
        PerformanceObserverEntryList.prototype.getEntriesByType = function(type) {
            return this._entries.filter(function(e) { return e.entryType === type; });
        };
        globalThis.PerformanceObserverEntryList = PerformanceObserverEntryList;
        function PerformanceObserver(callback) {
            this._callback = callback;
            this._types = [];
            this._buffered = false;
            this._cursor = globalThis.performance._entries.length;
        }
        if (!globalThis.performance._observers) globalThis.performance._observers = [];
        PerformanceObserver.prototype.observe = function(options) {
            var types = (options && options.entryTypes) || (options && options.type ? [options.type] : []);
            this._types = types.slice();
            this._buffered = !!(options && options.buffered);
            globalThis.performance._observers.push(this);
            // If buffered, replay pre-existing entries.
            if (this._buffered) {
                var self = this;
                var matching = globalThis.performance._entries.filter(function(e) {
                    return self._types.indexOf(e.entryType) >= 0;
                });
                if (matching.length) {
                    var list = new PerformanceObserverEntryList(matching);
                    Promise.resolve().then(function() { self._callback(list, self); });
                }
            }
        };
        PerformanceObserver.prototype.disconnect = function() {
            var idx = globalThis.performance._observers.indexOf(this);
            if (idx >= 0) globalThis.performance._observers.splice(idx, 1);
        };
        PerformanceObserver.prototype.takeRecords = function() {
            var since = globalThis.performance._entries.slice(this._cursor);
            this._cursor = globalThis.performance._entries.length;
            return since;
        };
        PerformanceObserver.supportedEntryTypes = ['mark', 'measure', 'resource', 'navigation'];
        globalThis.PerformanceObserver = PerformanceObserver;

        // Hook mark/measure to fan out to observers.
        var _origMark = globalThis.performance.mark;
        globalThis.performance.mark = function() {
            var entry = _origMark.apply(globalThis.performance, arguments);
            _fanout(entry);
            return entry;
        };
        var _origMeasure = globalThis.performance.measure;
        globalThis.performance.measure = function() {
            var entry = _origMeasure.apply(globalThis.performance, arguments);
            _fanout(entry);
            return entry;
        };
        function _fanout(entry) {
            var observers = globalThis.performance._observers;
            if (!observers || observers.length === 0) return;
            for (var i = 0; i < observers.length; i++) {
                var obs = observers[i];
                if (obs._types.indexOf(entry.entryType) < 0) continue;
                (function(o) {
                    Promise.resolve().then(function() {
                        var list = new PerformanceObserverEntryList([entry]);
                        try { o._callback(list, o); } catch (_) {}
                    });
                })(obs);
            }
        }
    }

    // `queueMicrotask` — schedule a microtask. QuickJS supports
    // Promise.then which gives us the microtask queue for free.
    if (typeof globalThis.queueMicrotask !== 'function') {
        globalThis.queueMicrotask = function(fn) {
            if (typeof fn !== 'function') throw new TypeError('callback must be a function');
            Promise.resolve().then(fn);
        };
    }

    // `TextEncoder` / `TextDecoder` — Web globals. Javy ships them when
    // built with `text_encoding(true)` (our WASM plugin does); native
    // rquickjs doesn't. Real npm packages (Express deps, undici, etc.)
    // probe these at module-load time and crash with `ReferenceError`
    // without them.
    //
    // Implementation note: do NOT route through `Buffer.toString` /
    // `Buffer.from(str, 'utf8')` here. Buffer's UTF-8 codec routes
    // back through these globals in some plenum paths, producing an
    // infinite recursion. The pure-JS encoder/decoder below is
    // self-contained and handles BMP + surrogate-paired astral
    // codepoints. Replacement char (`�`) for malformed sequences
    // when not in `fatal` mode (matches WHATWG spec).
    if (typeof globalThis.TextEncoder !== 'function') {
        globalThis.TextEncoder = function TextEncoder() {
            this.encoding = 'utf-8';
        };
        globalThis.TextEncoder.prototype.encode = function(input) {
            var s = input === undefined ? '' : String(input);
            // Worst case: 4 bytes per code unit (surrogate pair → 4-byte UTF-8).
            var out = new Uint8Array(s.length * 4);
            var n = 0;
            for (var i = 0; i < s.length; i++) {
                var c = s.charCodeAt(i);
                if (c >= 0xD800 && c <= 0xDBFF && i + 1 < s.length) {
                    var c2 = s.charCodeAt(i + 1);
                    if (c2 >= 0xDC00 && c2 <= 0xDFFF) {
                        var cp = 0x10000 + (((c & 0x3FF) << 10) | (c2 & 0x3FF));
                        out[n++] = 0xF0 | (cp >> 18);
                        out[n++] = 0x80 | ((cp >> 12) & 0x3F);
                        out[n++] = 0x80 | ((cp >> 6) & 0x3F);
                        out[n++] = 0x80 | (cp & 0x3F);
                        i++;
                        continue;
                    }
                }
                if (c < 0x80) {
                    out[n++] = c;
                } else if (c < 0x800) {
                    out[n++] = 0xC0 | (c >> 6);
                    out[n++] = 0x80 | (c & 0x3F);
                } else {
                    out[n++] = 0xE0 | (c >> 12);
                    out[n++] = 0x80 | ((c >> 6) & 0x3F);
                    out[n++] = 0x80 | (c & 0x3F);
                }
            }
            return out.slice(0, n);
        };
        globalThis.TextEncoder.prototype.encodeInto = function(source, dest) {
            var encoded = this.encode(source);
            var n = Math.min(encoded.length, dest.length);
            for (var i = 0; i < n; i++) dest[i] = encoded[i];
            return { read: source.length, written: n };
        };
    }
    if (typeof globalThis.TextDecoder !== 'function') {
        globalThis.TextDecoder = function TextDecoder(label, options) {
            var enc = (label || 'utf-8').toLowerCase();
            if (enc === 'utf8') enc = 'utf-8';
            this.encoding = enc;
            this.fatal = !!(options && options.fatal);
            this.ignoreBOM = !!(options && options.ignoreBOM);
        };
        globalThis.TextDecoder.prototype.decode = function(input, _options) {
            if (input === undefined) return '';
            var bytes;
            if (input instanceof Uint8Array) {
                bytes = input;
            } else if (input instanceof ArrayBuffer) {
                bytes = new Uint8Array(input);
            } else if (input && typeof input.byteLength === 'number') {
                bytes = new Uint8Array(
                    input.buffer || input,
                    input.byteOffset || 0,
                    input.byteLength
                );
            } else {
                return '';
            }
            // Pure-JS UTF-8 decode. Doesn't route through Buffer to
            // avoid recursion when Buffer's own codec calls back here.
            var s = '';
            var i = 0;
            while (i < bytes.length) {
                var b1 = bytes[i++];
                if (b1 < 0x80) {
                    s += String.fromCharCode(b1);
                } else if (b1 < 0xC0) {
                    s += '�';
                } else if (b1 < 0xE0) {
                    var b2 = bytes[i++] || 0;
                    s += String.fromCharCode(((b1 & 0x1F) << 6) | (b2 & 0x3F));
                } else if (b1 < 0xF0) {
                    var b2c = bytes[i++] || 0;
                    var b3 = bytes[i++] || 0;
                    s += String.fromCharCode(
                        ((b1 & 0x0F) << 12) | ((b2c & 0x3F) << 6) | (b3 & 0x3F)
                    );
                } else {
                    var b2d = bytes[i++] || 0;
                    var b3d = bytes[i++] || 0;
                    var b4 = bytes[i++] || 0;
                    var cp =
                        ((b1 & 0x07) << 18) |
                        ((b2d & 0x3F) << 12) |
                        ((b3d & 0x3F) << 6) |
                        (b4 & 0x3F);
                    cp -= 0x10000;
                    s += String.fromCharCode(
                        0xD800 + (cp >> 10),
                        0xDC00 + (cp & 0x3FF)
                    );
                }
            }
            return s;
        };
    }

    // Tolerant `TextDecoder`: the native (javy) decoder accepts ONLY the
    // exact label 'utf-8' and throws on the labels real-world code passes -
    // emscripten builds (h3-js, sql.js, ...) do `new TextDecoder('utf8')`
    // (no dash) for narrow strings and `new TextDecoder('utf-16le')` for
    // wide strings. Wrap whatever decoder we have so every common label
    // works: utf-8 aliases delegate to the fast native decoder; utf-16 and
    // latin1 decode in pure JS. Replaces the decoder unconditionally, since
    // even when a native one exists it is the too-strict one.
    (function () {
        var NativeTD = globalThis.TextDecoder;
        function normLabel(label) {
            var e = String(label == null ? 'utf-8' : label).toLowerCase().trim();
            if (e === '' || e === 'utf8' || e === 'utf-8' || e === 'unicode-1-1-utf-8' ||
                e === 'unicode11utf8' || e === 'unicode20utf8' || e === 'x-unicode20utf8') return 'utf-8';
            if (e === 'utf-16le' || e === 'utf-16' || e === 'ucs-2' || e === 'ucs2' ||
                e === 'unicode' || e === 'csunicode') return 'utf-16le';
            if (e === 'utf-16be' || e === 'unicodefffe') return 'utf-16be';
            if (e === 'latin1' || e === 'iso-8859-1' || e === 'iso8859-1' || e === 'l1' ||
                e === 'ascii' || e === 'us-ascii' || e === 'windows-1252' || e === 'cp1252' ||
                e === 'binary') return 'latin1';
            return null;
        }
        function toBytes(input) {
            if (input === undefined || input === null) return new Uint8Array(0);
            if (input instanceof Uint8Array) return input;
            if (input instanceof ArrayBuffer) return new Uint8Array(input);
            if (typeof input.byteLength === 'number') {
                return new Uint8Array(input.buffer || input, input.byteOffset || 0, input.byteLength);
            }
            return new Uint8Array(0);
        }
        function decodeUtf8Js(bytes) {
            var s = '', i = 0;
            while (i < bytes.length) {
                var b1 = bytes[i++];
                if (b1 < 0x80) { s += String.fromCharCode(b1); }
                else if (b1 < 0xC0) { s += '�'; }
                else if (b1 < 0xE0) { s += String.fromCharCode(((b1 & 0x1F) << 6) | (bytes[i++] & 0x3F)); }
                else if (b1 < 0xF0) {
                    var c2 = bytes[i++] & 0x3F, c3 = bytes[i++] & 0x3F;
                    s += String.fromCharCode(((b1 & 0x0F) << 12) | (c2 << 6) | c3);
                } else {
                    var d2 = bytes[i++] & 0x3F, d3 = bytes[i++] & 0x3F, d4 = bytes[i++] & 0x3F;
                    var cp = (((b1 & 0x07) << 18) | (d2 << 12) | (d3 << 6) | d4) - 0x10000;
                    s += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
                }
            }
            return s;
        }
        function decodeUtf16(bytes, le) {
            var s = '', n = bytes.length & ~1;
            for (var i = 0; i < n; i += 2) {
                s += String.fromCharCode(le ? (bytes[i] | (bytes[i + 1] << 8))
                                            : ((bytes[i] << 8) | bytes[i + 1]));
            }
            return s;
        }
        function decodeLatin1(bytes) {
            var s = '';
            for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
            return s;
        }
        function TolerantTextDecoder(label, options) {
            if (!(this instanceof TolerantTextDecoder)) return new TolerantTextDecoder(label, options);
            var enc = normLabel(label);
            if (enc === null) throw new RangeError("Failed to construct 'TextDecoder': the encoding label provided ('" + label + "') is invalid.");
            this._enc = enc;
            this.encoding = enc === 'latin1' ? 'windows-1252' : enc;
            this.fatal = !!(options && options.fatal);
            this.ignoreBOM = !!(options && options.ignoreBOM);
            this._native = null;
            if (enc === 'utf-8' && typeof NativeTD === 'function' && NativeTD !== TolerantTextDecoder) {
                try { this._native = new NativeTD('utf-8'); } catch (_) { this._native = null; }
            }
        }
        TolerantTextDecoder.prototype.decode = function (input, opts) {
            if (input === undefined) return '';
            var bytes = toBytes(input);
            if (this._enc === 'utf-8') {
                if (this._native) { try { return this._native.decode(bytes, opts); } catch (_) { /* fall through */ } }
                return decodeUtf8Js(bytes);
            }
            if (this._enc === 'utf-16le') return decodeUtf16(bytes, true);
            if (this._enc === 'utf-16be') return decodeUtf16(bytes, false);
            return decodeLatin1(bytes);
        };
        globalThis.TextDecoder = TolerantTextDecoder;
    })();

    // `btoa` / `atob` — base64 encoders. QuickJS doesn't ship these.
    if (typeof globalThis.btoa !== 'function') {
        globalThis.btoa = function(str) {
            var Buffer = require('buffer').Buffer;
            return Buffer.from(String(str), 'binary').toString('base64');
        };
    }
    if (typeof globalThis.atob !== 'function') {
        globalThis.atob = function(b64) {
            var Buffer = require('buffer').Buffer;
            return Buffer.from(String(b64), 'base64').toString('binary');
        };
    }

    // Node 20 LTS globals exposed without `require`:
    //   * `Buffer`           — global since v0.x.
    //   * `global`           — alias to globalThis since v12.
    //   * `URL` / `URLSearchParams` — global since v10.
    if (typeof globalThis.Buffer !== 'function') {
        globalThis.Buffer = require('buffer').Buffer;
    }
    if (typeof globalThis.global !== 'object') {
        globalThis.global = globalThis;
    }

    // ----- EventTarget / Event / CustomEvent ------------------------
    // Node 15 made these globals; nearly every modern web-API
    // building block (AbortSignal, MessagePort, the streams family)
    // either extends EventTarget or fires Events through it. Anything
    // that does `class X extends EventTarget {}` falls over without
    // a real constructor, even when the extending code never actually
    // dispatches an event.
    if (typeof globalThis.Event !== 'function') {
        var Event = function Event(type, init) {
            init = init || {};
            this.type = String(type);
            this.bubbles = !!init.bubbles;
            this.cancelable = !!init.cancelable;
            this.composed = !!init.composed;
            this.defaultPrevented = false;
            this.timeStamp = Date.now();
            this.target = null;
            this.currentTarget = null;
            this.eventPhase = 0;
            this.isTrusted = false;
            this._propagationStopped = false;
            this._immediatePropagationStopped = false;
        };
        Event.prototype.preventDefault = function() {
            if (this.cancelable) this.defaultPrevented = true;
        };
        Event.prototype.stopPropagation = function() { this._propagationStopped = true; };
        Event.prototype.stopImmediatePropagation = function() {
            this._propagationStopped = true;
            this._immediatePropagationStopped = true;
        };
        Event.prototype.composedPath = function() { return []; };
        Event.NONE = 0; Event.CAPTURING_PHASE = 1; Event.AT_TARGET = 2; Event.BUBBLING_PHASE = 3;
        globalThis.Event = Event;
    }
    if (typeof globalThis.CustomEvent !== 'function') {
        globalThis.CustomEvent = function CustomEvent(type, init) {
            globalThis.Event.call(this, type, init);
            this.detail = init && 'detail' in init ? init.detail : null;
        };
        globalThis.CustomEvent.prototype = Object.create(globalThis.Event.prototype);
        globalThis.CustomEvent.prototype.constructor = globalThis.CustomEvent;
    }
    if (typeof globalThis.EventTarget !== 'function') {
        var EventTarget = function EventTarget() { this._listeners = {}; };
        EventTarget.prototype.addEventListener = function(type, listener, _options) {
            if (!this._listeners) this._listeners = {};
            (this._listeners[type] = this._listeners[type] || []).push(listener);
        };
        EventTarget.prototype.removeEventListener = function(type, listener) {
            if (!this._listeners || !this._listeners[type]) return;
            var arr = this._listeners[type];
            for (var i = arr.length - 1; i >= 0; i--) {
                if (arr[i] === listener) arr.splice(i, 1);
            }
        };
        EventTarget.prototype.dispatchEvent = function(event) {
            if (!event || typeof event.type !== 'string') {
                throw new TypeError('dispatchEvent: argument must be an Event');
            }
            event.target = this;
            event.currentTarget = this;
            event.eventPhase = 2; // AT_TARGET
            var arr = (this._listeners && this._listeners[event.type]) || [];
            for (var i = 0; i < arr.length; i++) {
                if (event._immediatePropagationStopped) break;
                try {
                    var fn = arr[i];
                    if (typeof fn === 'function') fn.call(this, event);
                    else if (fn && typeof fn.handleEvent === 'function') fn.handleEvent(event);
                } catch (e) {
                    // Swallow per Web spec — an exceptional handler
                    // shouldn't prevent siblings from firing. Surface
                    // via the runtime's error reporting path.
                    if (typeof globalThis.queueMicrotask === 'function') {
                        globalThis.queueMicrotask(function() { throw e; });
                    }
                }
            }
            event.eventPhase = 0;
            return !event.defaultPrevented;
        };
        globalThis.EventTarget = EventTarget;
    }

    // ----- DOMException ---------------------------------------------
    // Used by AbortController.abort() (DOMException 'AbortError'),
    // various Streams APIs, and Cache/IndexedDB shims. Most callers
    // construct it as `new DOMException(message, name)` and read
    // `.name` to discriminate error types.
    if (typeof globalThis.DOMException !== 'function') {
        var DOMException = function DOMException(message, name) {
            this.message = message === undefined ? '' : String(message);
            this.name = name === undefined ? 'Error' : String(name);
            // .code: legacy numeric. 0 if name doesn't map.
            var legacy = {
                IndexSizeError: 1, HierarchyRequestError: 3, WrongDocumentError: 4,
                InvalidCharacterError: 5, NoModificationAllowedError: 7,
                NotFoundError: 8, NotSupportedError: 9, InUseAttributeError: 10,
                InvalidStateError: 11, SyntaxError: 12, InvalidModificationError: 13,
                NamespaceError: 14, InvalidAccessError: 15, SecurityError: 18,
                NetworkError: 19, AbortError: 20, URLMismatchError: 21,
                QuotaExceededError: 22, TimeoutError: 23, InvalidNodeTypeError: 24,
                DataCloneError: 25,
            };
            this.code = legacy[this.name] || 0;
            // Stack trace via Error to make it inspectable.
            try { Error.captureStackTrace(this, DOMException); }
            catch (_) { this.stack = (new Error(this.message)).stack; }
        };
        DOMException.prototype = Object.create(Error.prototype);
        DOMException.prototype.constructor = DOMException;
        DOMException.prototype.toString = function() { return this.name + ': ' + this.message; };
        // Static legacy code constants on the constructor.
        var codes = ['INDEX_SIZE_ERR','DOMSTRING_SIZE_ERR','HIERARCHY_REQUEST_ERR','WRONG_DOCUMENT_ERR','INVALID_CHARACTER_ERR','NO_DATA_ALLOWED_ERR','NO_MODIFICATION_ALLOWED_ERR','NOT_FOUND_ERR','NOT_SUPPORTED_ERR','INUSE_ATTRIBUTE_ERR','INVALID_STATE_ERR','SYNTAX_ERR','INVALID_MODIFICATION_ERR','NAMESPACE_ERR','INVALID_ACCESS_ERR','VALIDATION_ERR','TYPE_MISMATCH_ERR','SECURITY_ERR','NETWORK_ERR','ABORT_ERR','URL_MISMATCH_ERR','QUOTA_EXCEEDED_ERR','TIMEOUT_ERR','INVALID_NODE_TYPE_ERR','DATA_CLONE_ERR'];
        for (var ci = 0; ci < codes.length; ci++) DOMException[codes[ci]] = ci + 1;
        globalThis.DOMException = DOMException;
    }

    // ----- Blob / File / FormData -----------------------------------
    // Node 18+ globals. node-fetch / undici-style clients construct
    // Blobs to wrap response bodies; multer / form-data libraries
    // build FormData. Buffer-backed implementations — covers the API
    // shape; binary streaming is best-effort sync.
    if (typeof globalThis.Blob !== 'function') {
        var Blob = function Blob(parts, options) {
            options = options || {};
            this.type = options.type ? String(options.type).toLowerCase() : '';
            var arr = parts || [];
            // Coerce each part to bytes.
            var Buf = (typeof globalThis.Buffer === 'function') ? globalThis.Buffer : null;
            var pieces = [];
            for (var i = 0; i < arr.length; i++) {
                var p = arr[i];
                if (Buf && Buf.isBuffer && Buf.isBuffer(p)) pieces.push(p);
                else if (p instanceof Uint8Array) pieces.push(Buf ? Buf.from(p) : p);
                else if (p instanceof ArrayBuffer) pieces.push(Buf ? Buf.from(new Uint8Array(p)) : new Uint8Array(p));
                else if (typeof p === 'string') pieces.push(Buf ? Buf.from(p, 'utf8') : new globalThis.TextEncoder().encode(p));
                else if (p && typeof p.arrayBuffer === 'function') {
                    // Nested Blob — sync access to its internal bytes.
                    pieces.push(Buf ? Buf.from(p._bytes || []) : (p._bytes || new Uint8Array(0)));
                } else {
                    var s = String(p);
                    pieces.push(Buf ? Buf.from(s, 'utf8') : new globalThis.TextEncoder().encode(s));
                }
            }
            // Concatenate.
            var total = 0;
            for (var j = 0; j < pieces.length; j++) total += pieces[j].length;
            var out = Buf ? Buf.alloc(total) : new Uint8Array(total);
            var off = 0;
            for (var k = 0; k < pieces.length; k++) {
                if (Buf) pieces[k].copy(out, off);
                else out.set(pieces[k], off);
                off += pieces[k].length;
            }
            this._bytes = out;
            this.size = total;
        };
        Blob.prototype.arrayBuffer = function() {
            var b = this._bytes;
            return Promise.resolve(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength));
        };
        Blob.prototype.text = function() {
            return Promise.resolve(new globalThis.TextDecoder().decode(this._bytes));
        };
        Blob.prototype.bytes = function() {
            return Promise.resolve(new Uint8Array(this._bytes.buffer, this._bytes.byteOffset, this._bytes.byteLength));
        };
        Blob.prototype.slice = function(start, end, type) {
            var s = (start === undefined) ? 0 : (start | 0);
            var e = (end === undefined) ? this.size : (end | 0);
            if (s < 0) s = Math.max(this.size + s, 0);
            if (e < 0) e = Math.max(this.size + e, 0);
            s = Math.min(s, this.size); e = Math.min(e, this.size);
            var sub = this._bytes.slice(s, e);
            var out = Object.create(Blob.prototype);
            out._bytes = sub; out.size = sub.length;
            out.type = type ? String(type).toLowerCase() : '';
            return out;
        };
        Blob.prototype.stream = function() {
            // Best-effort: a stream-shaped object with one chunk.
            var bytes = this._bytes;
            var done = false;
            return {
                getReader: function() {
                    return {
                        read: function() {
                            if (done) return Promise.resolve({ value: undefined, done: true });
                            done = true;
                            return Promise.resolve({ value: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength), done: false });
                        },
                        cancel: function() { done = true; return Promise.resolve(); },
                        releaseLock: function() {},
                    };
                },
                [Symbol.asyncIterator]: function() {
                    return {
                        next: function() {
                            if (done) return Promise.resolve({ value: undefined, done: true });
                            done = true;
                            return Promise.resolve({ value: bytes, done: false });
                        },
                    };
                },
            };
        };
        globalThis.Blob = Blob;
    }
    if (typeof globalThis.File !== 'function') {
        globalThis.File = function File(parts, name, options) {
            globalThis.Blob.call(this, parts, options);
            this.name = String(name);
            this.lastModified = (options && typeof options.lastModified === 'number') ? options.lastModified : Date.now();
            this.webkitRelativePath = '';
        };
        globalThis.File.prototype = Object.create(globalThis.Blob.prototype);
        globalThis.File.prototype.constructor = globalThis.File;
    }

    // ----- FileReader (Web API, Node 23+ global) ---------------------
    //
    // The Web API for asynchronous Blob/File reading. Most uses today
    // call `readAsText` / `readAsArrayBuffer` / `readAsDataURL` and
    // listen for `loadend` / `load`. We synthesise it on top of the
    // Blob's `text()` / `arrayBuffer()` Promises so existing code
    // (image upload widgets, file picker handlers) works.
    if (typeof globalThis.FileReader !== 'function') {
        function FileReader() {
            // EventTarget-shaped emitter for on{load,loadend,error,...}.
            this._listeners = Object.create(null);
            this.readyState = 0; // EMPTY
            this.result = null;
            this.error = null;
            this.onload = null; this.onloadend = null; this.onloadstart = null;
            this.onerror = null; this.onabort = null; this.onprogress = null;
        }
        FileReader.EMPTY = 0; FileReader.LOADING = 1; FileReader.DONE = 2;
        FileReader.prototype.EMPTY = 0;
        FileReader.prototype.LOADING = 1;
        FileReader.prototype.DONE = 2;
        FileReader.prototype.addEventListener = function(name, fn) {
            (this._listeners[name] = this._listeners[name] || []).push(fn);
        };
        FileReader.prototype.removeEventListener = function(name, fn) {
            var list = this._listeners[name];
            if (!list) return;
            this._listeners[name] = list.filter(function(f) { return f !== fn; });
        };
        FileReader.prototype._fire = function(name, ev) {
            var on = this['on' + name];
            if (typeof on === 'function') { try { on.call(this, ev); } catch (_) {} }
            var list = this._listeners[name] || [];
            for (var i = 0; i < list.length; i++) {
                try { list[i].call(this, ev); } catch (_) {}
            }
        };
        FileReader.prototype._read = function(blob, kind) {
            var self = this;
            self.readyState = 1; // LOADING
            self._fire('loadstart', { type: 'loadstart' });
            var p;
            if (kind === 'text') p = blob.text().then(function(t) { return t; });
            else if (kind === 'arrayBuffer') p = blob.arrayBuffer();
            else if (kind === 'dataURL') {
                p = blob.arrayBuffer().then(function(ab) {
                    var bytes = new Uint8Array(ab);
                    var bin = '';
                    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
                    return 'data:' + (blob.type || '') + ';base64,' + btoa(bin);
                });
            } else if (kind === 'binaryString') {
                p = blob.arrayBuffer().then(function(ab) {
                    var bytes = new Uint8Array(ab);
                    var s = '';
                    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
                    return s;
                });
            }
            p.then(function(value) {
                self.result = value;
                self.readyState = 2;
                self._fire('load', { type: 'load' });
                self._fire('loadend', { type: 'loadend' });
            }, function(err) {
                self.error = err;
                self.readyState = 2;
                self._fire('error', { type: 'error', error: err });
                self._fire('loadend', { type: 'loadend' });
            });
        };
        FileReader.prototype.readAsText = function(blob) { this._read(blob, 'text'); };
        FileReader.prototype.readAsArrayBuffer = function(blob) { this._read(blob, 'arrayBuffer'); };
        FileReader.prototype.readAsDataURL = function(blob) { this._read(blob, 'dataURL'); };
        FileReader.prototype.readAsBinaryString = function(blob) {
            this._read(blob, 'binaryString');
        };
        FileReader.prototype.abort = function() {
            if (this.readyState === 1) {
                this.readyState = 2;
                this._fire('abort', { type: 'abort' });
                this._fire('loadend', { type: 'loadend' });
            }
        };
        Object.defineProperty(globalThis, 'FileReader', {
            value: FileReader, writable: true, configurable: true,
        });
    }
    if (typeof globalThis.FormData !== 'function') {
        globalThis.FormData = function FormData() {
            this._entries = [];
        };
        var FP = globalThis.FormData.prototype;
        FP.append = function(key, value, filename) {
            this._entries.push([String(key), value, filename]);
        };
        FP.set = function(key, value, filename) {
            this._entries = this._entries.filter(function(e) { return e[0] !== String(key); });
            this._entries.push([String(key), value, filename]);
        };
        FP.delete = function(key) {
            this._entries = this._entries.filter(function(e) { return e[0] !== String(key); });
        };
        FP.has = function(key) {
            return this._entries.some(function(e) { return e[0] === String(key); });
        };
        FP.get = function(key) {
            for (var i = 0; i < this._entries.length; i++)
                if (this._entries[i][0] === String(key)) return this._entries[i][1];
            return null;
        };
        FP.getAll = function(key) {
            return this._entries.filter(function(e) { return e[0] === String(key); }).map(function(e) { return e[1]; });
        };
        FP.entries = function() {
            var arr = this._entries.map(function(e) { return [e[0], e[1]]; });
            var idx = 0;
            return {
                next: function() {
                    if (idx >= arr.length) return { value: undefined, done: true };
                    return { value: arr[idx++], done: false };
                },
                [Symbol.iterator]: function() { return this; },
            };
        };
        FP.keys = function() {
            var arr = this._entries.map(function(e) { return e[0]; });
            var idx = 0;
            return { next: function() { return idx < arr.length ? { value: arr[idx++], done: false } : { value: undefined, done: true }; }, [Symbol.iterator]: function() { return this; } };
        };
        FP.values = function() {
            var arr = this._entries.map(function(e) { return e[1]; });
            var idx = 0;
            return { next: function() { return idx < arr.length ? { value: arr[idx++], done: false } : { value: undefined, done: true }; }, [Symbol.iterator]: function() { return this; } };
        };
        FP.forEach = function(cb, thisArg) {
            for (var i = 0; i < this._entries.length; i++) cb.call(thisArg, this._entries[i][1], this._entries[i][0], this);
        };
        FP[Symbol.iterator] = FP.entries;
    }

    // ----- MessageChannel / MessagePort / MessageEvent ---------------
    // Same-realm message passing. Worker code uses the API surface
    // even when the actual cross-thread mechanism is provided by the
    // worker_threads polyfill — we expose a same-realm impl so user
    // code that does `new MessageChannel()` doesn't crash.
    if (typeof globalThis.MessageEvent !== 'function') {
        globalThis.MessageEvent = function MessageEvent(type, init) {
            globalThis.Event.call(this, type, init);
            init = init || {};
            this.data = init.data === undefined ? null : init.data;
            this.origin = init.origin || '';
            this.lastEventId = init.lastEventId || '';
            this.source = init.source || null;
            this.ports = init.ports || [];
        };
        globalThis.MessageEvent.prototype = Object.create(globalThis.Event.prototype);
        globalThis.MessageEvent.prototype.constructor = globalThis.MessageEvent;
    }
    if (typeof globalThis.MessagePort !== 'function') {
        var MessagePort = function MessagePort() {
            globalThis.EventTarget.call(this);
            this._other = null;
            this._started = false;
            this._queued = [];
            this._onmessage = null;
        };
        MessagePort.prototype = Object.create(globalThis.EventTarget.prototype);
        MessagePort.prototype.constructor = MessagePort;
        Object.defineProperty(MessagePort.prototype, 'onmessage', {
            get: function() { return this._onmessage; },
            set: function(fn) {
                this._onmessage = fn;
                this.start();
            },
        });
        MessagePort.prototype.postMessage = function(data, transferList) {
            var other = this._other;
            if (!other) return;
            var ev = new globalThis.MessageEvent('message', { data: data, ports: transferList || [] });
            if (other._started || other._onmessage) {
                if (typeof globalThis.queueMicrotask === 'function') {
                    globalThis.queueMicrotask(function() {
                        if (typeof other._onmessage === 'function') other._onmessage(ev);
                        other.dispatchEvent(ev);
                    });
                } else {
                    Promise.resolve().then(function() {
                        if (typeof other._onmessage === 'function') other._onmessage(ev);
                        other.dispatchEvent(ev);
                    });
                }
            } else {
                other._queued.push(ev);
            }
        };
        MessagePort.prototype.start = function() {
            if (this._started) return;
            this._started = true;
            var self = this;
            for (var i = 0; i < this._queued.length; i++) {
                (function(ev) {
                    Promise.resolve().then(function() {
                        if (typeof self._onmessage === 'function') self._onmessage(ev);
                        self.dispatchEvent(ev);
                    });
                })(this._queued[i]);
            }
            this._queued.length = 0;
        };
        MessagePort.prototype.close = function() {
            this._other = null;
            this._onmessage = null;
        };
        globalThis.MessagePort = MessagePort;
    }
    if (typeof globalThis.MessageChannel !== 'function') {
        globalThis.MessageChannel = function MessageChannel() {
            this.port1 = new globalThis.MessagePort();
            this.port2 = new globalThis.MessagePort();
            this.port1._other = this.port2;
            this.port2._other = this.port1;
        };
    }
    if (typeof globalThis.BroadcastChannel !== 'function') {
        // Sandbox is single-realm, so a BroadcastChannel just delivers
        // messages to other channels with the same name in this same
        // process. Useful for in-process module-coordination patterns.
        if (!globalThis.__ab_bc_registry) globalThis.__ab_bc_registry = {};
        var BroadcastChannel = function BroadcastChannel(name) {
            globalThis.EventTarget.call(this);
            this.name = String(name);
            this._closed = false;
            this._onmessage = null;
            var reg = globalThis.__ab_bc_registry;
            (reg[this.name] = reg[this.name] || []).push(this);
        };
        BroadcastChannel.prototype = Object.create(globalThis.EventTarget.prototype);
        BroadcastChannel.prototype.constructor = BroadcastChannel;
        Object.defineProperty(BroadcastChannel.prototype, 'onmessage', {
            get: function() { return this._onmessage; },
            set: function(v) { this._onmessage = v; },
        });
        BroadcastChannel.prototype.postMessage = function(data) {
            if (this._closed) return;
            var ev = new globalThis.MessageEvent('message', { data: data });
            var peers = (globalThis.__ab_bc_registry[this.name] || []).filter(function(c) { return c !== this; }, this);
            var self = this;
            peers.forEach(function(peer) {
                if (peer._closed) return;
                Promise.resolve().then(function() {
                    if (typeof peer._onmessage === 'function') peer._onmessage(ev);
                    peer.dispatchEvent(ev);
                });
            });
        };
        BroadcastChannel.prototype.close = function() {
            this._closed = true;
            var reg = globalThis.__ab_bc_registry;
            if (reg[this.name]) {
                reg[this.name] = reg[this.name].filter(function(c) { return c !== this; }, this);
            }
        };
        globalThis.BroadcastChannel = BroadcastChannel;
    }

    // ----- Web Crypto (globalThis.crypto) ---------------------------
    // Modern crypto is via the SubtleCrypto WebCrypto API. Most uses
    // we see in Node code are `crypto.randomUUID()`,
    // `crypto.getRandomValues()`, `crypto.subtle.digest()`. Lazy-load
    // node:crypto on first call so module-init time doesn't reach
    // into the host bridge before host imports are wired (Wizer
    // pre-init runs the bundle without our custom wasm imports
    // bound; eager require here trips the linker).
    if (typeof globalThis.crypto !== 'object' || !globalThis.crypto || typeof globalThis.crypto.randomUUID !== 'function') {
        var webCrypto = globalThis.crypto || {};
        function _hexToBytes(hex) {
            var out = new Uint8Array(hex.length / 2);
            for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i*2, 2), 16);
            return out;
        }
        webCrypto.randomUUID = function() {
            try {
                var nc = require('crypto');
                if (typeof nc.randomUUID === 'function') return nc.randomUUID();
            } catch (_) {}
            var r = '';
            for (var i = 0; i < 32; i++) {
                if (i === 8 || i === 12 || i === 16 || i === 20) r += '-';
                r += Math.floor(Math.random() * 16).toString(16);
            }
            return r;
        };
        webCrypto.getRandomValues = function(typed) {
            if (!typed || typeof typed.length !== 'number') {
                throw new TypeError('getRandomValues: typed-array required');
            }
            var n = typed.byteLength || typed.length;
            try {
                var nc = require('crypto');
                if (nc && nc.randomBytes) {
                    var hex = nc.randomBytes(n);
                    var bytes = (typeof hex === 'string') ? _hexToBytes(hex) : hex;
                    var view = new Uint8Array(typed.buffer || typed, typed.byteOffset || 0, n);
                    for (var i = 0; i < n; i++) view[i] = bytes[i];
                    return typed;
                }
            } catch (_) {}
            var view2 = new Uint8Array(typed.buffer || typed, typed.byteOffset || 0, n);
            for (var j = 0; j < n; j++) view2[j] = Math.floor(Math.random() * 256);
            return typed;
        };
        // ---- SubtleCrypto -------------------------------------
        //
        // Web Crypto subset wired on top of node:crypto host fns.
        //
        // Algorithms shipped:
        //   AES-GCM      encrypt / decrypt / generateKey / importKey
        //                / exportKey
        //   AES-CBC      encrypt / decrypt / generateKey / importKey
        //                / exportKey
        //   AES-CTR      encrypt / decrypt (via AES-CBC host fn with
        //                CTR-mode wrapper TBD; falls back to error)
        //   HMAC         sign / verify / generateKey / importKey /
        //                exportKey (SHA-1/256/384/512)
        //   PBKDF2       deriveBits / deriveKey
        //   HKDF         deriveBits / deriveKey (HMAC-based)
        //   SHA-1/256/384/512  digest
        //
        // CryptoKey is an opaque-ish JS object holding the raw key
        // bytes plus algorithm metadata — extractable=true returns
        // the bytes via exportKey, false returns an error per the
        // spec.
        function _toBytes(input) {
            if (input == null) return new Uint8Array(0);
            if (input instanceof ArrayBuffer) return new Uint8Array(input);
            if (ArrayBuffer.isView(input)) {
                return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
            }
            if (typeof input === 'string') {
                var enc = new TextEncoder();
                return enc.encode(input);
            }
            return new Uint8Array(input);
        }
        function _bufToB64(bytes) {
            // Avoid require('buffer') here since this function runs
            // before module loading is fully wired during early
            // global install.
            var Buf = globalThis.Buffer || (require('buffer') && require('buffer').Buffer);
            return Buf.from(bytes).toString('base64');
        }
        function _b64ToBuf(b64) {
            var Buf = globalThis.Buffer || (require('buffer') && require('buffer').Buffer);
            return new Uint8Array(Buf.from(b64, 'base64'));
        }
        function _algoName(a) {
            return (typeof a === 'string') ? a.toLowerCase()
                 : (a && a.name) ? String(a.name).toLowerCase()
                 : '';
        }
        function _hashName(h) {
            var s = (typeof h === 'string') ? h : (h && h.name) || '';
            return s.toLowerCase().replace('-', '');
        }
        function _aesCipherName(keyBytes, mode) {
            var bits = keyBytes.length * 8;
            return 'aes-' + bits + '-' + mode;
        }
        function _makeCryptoKey(algorithm, raw, type, extractable, usages) {
            var key = Object.create(null);
            Object.defineProperty(key, 'algorithm', { value: algorithm, enumerable: true });
            Object.defineProperty(key, 'type', { value: type, enumerable: true });
            Object.defineProperty(key, 'extractable', { value: !!extractable, enumerable: true });
            Object.defineProperty(key, 'usages', { value: usages.slice(), enumerable: true });
            // _raw is non-enumerable so JSON.stringify(key) doesn't leak
            // the secret. Spec-wise CryptoKey is opaque; we keep parity.
            Object.defineProperty(key, '_raw', { value: raw, enumerable: false });
            return key;
        }

        var subtle = {
            digest: function(algo, data) {
                var nodeAlgo = _hashName(algo);
                try {
                    var nc = require('crypto');
                    var hash = nc.createHash(nodeAlgo);
                    hash.update(_toBytes(data));
                    var hex = hash.digest('hex');
                    return Promise.resolve(_hexToBytes(hex).buffer);
                } catch (e) { return Promise.reject(e); }
            },

            encrypt: function(algorithm, key, data) {
                return new Promise(function(resolve, reject) {
                    try {
                        var name = _algoName(algorithm);
                        var nc = require('crypto');
                        if (name === 'aes-gcm') {
                            var iv = _toBytes(algorithm.iv);
                            var aad = algorithm.additionalData ? _toBytes(algorithm.additionalData) : null;
                            var tagLen = (algorithm.tagLength | 0) || 128;
                            var c = nc.createCipheriv(_aesCipherName(key._raw, 'gcm'),
                                                      Buffer.from(key._raw),
                                                      Buffer.from(iv));
                            if (aad) c.setAAD(Buffer.from(aad));
                            c.update(Buffer.from(_toBytes(data)));
                            var ct = c.final();
                            var tag = c.getAuthTag().slice(0, tagLen / 8);
                            var out = new Uint8Array(ct.length + tag.length);
                            out.set(ct, 0);
                            out.set(tag, ct.length);
                            resolve(out.buffer);
                            return;
                        }
                        if (name === 'aes-cbc') {
                            var iv2 = _toBytes(algorithm.iv);
                            var c2 = nc.createCipheriv(_aesCipherName(key._raw, 'cbc'),
                                                       Buffer.from(key._raw),
                                                       Buffer.from(iv2));
                            c2.update(Buffer.from(_toBytes(data)));
                            var out2 = c2.final();
                            resolve(new Uint8Array(out2).buffer);
                            return;
                        }
                        reject(new Error('SubtleCrypto.encrypt: unsupported algorithm: ' + name));
                    } catch (e) { reject(e); }
                });
            },

            decrypt: function(algorithm, key, data) {
                return new Promise(function(resolve, reject) {
                    try {
                        var name = _algoName(algorithm);
                        var nc = require('crypto');
                        var input = _toBytes(data);
                        if (name === 'aes-gcm') {
                            var iv = _toBytes(algorithm.iv);
                            var aad = algorithm.additionalData ? _toBytes(algorithm.additionalData) : null;
                            var tagLen = (algorithm.tagLength | 0) || 128;
                            var tagBytes = tagLen / 8;
                            if (input.length < tagBytes) return reject(new Error('aes-gcm: ciphertext shorter than tag'));
                            var ct = input.slice(0, input.length - tagBytes);
                            var tag = input.slice(input.length - tagBytes);
                            var d = nc.createDecipheriv(_aesCipherName(key._raw, 'gcm'),
                                                        Buffer.from(key._raw),
                                                        Buffer.from(iv));
                            if (aad) d.setAAD(Buffer.from(aad));
                            d.setAuthTag(Buffer.from(tag));
                            d.update(Buffer.from(ct));
                            var pt = d.final();
                            resolve(new Uint8Array(pt).buffer);
                            return;
                        }
                        if (name === 'aes-cbc') {
                            var iv2 = _toBytes(algorithm.iv);
                            var d2 = nc.createDecipheriv(_aesCipherName(key._raw, 'cbc'),
                                                         Buffer.from(key._raw),
                                                         Buffer.from(iv2));
                            d2.update(Buffer.from(input));
                            var pt2 = d2.final();
                            resolve(new Uint8Array(pt2).buffer);
                            return;
                        }
                        reject(new Error('SubtleCrypto.decrypt: unsupported algorithm: ' + name));
                    } catch (e) { reject(e); }
                });
            },

            sign: function(algorithm, key, data) {
                return new Promise(function(resolve, reject) {
                    try {
                        var name = _algoName(algorithm);
                        var nc = require('crypto');
                        if (name === 'hmac') {
                            var hashName = _hashName(key.algorithm && key.algorithm.hash);
                            var h = nc.createHmac(hashName, Buffer.from(key._raw));
                            h.update(Buffer.from(_toBytes(data)));
                            var hex = h.digest('hex');
                            resolve(_hexToBytes(hex).buffer);
                            return;
                        }
                        reject(new Error('SubtleCrypto.sign: unsupported algorithm: ' + name));
                    } catch (e) { reject(e); }
                });
            },

            verify: function(algorithm, key, signature, data) {
                return new Promise(function(resolve, reject) {
                    var self = this;
                    var p = subtle.sign(algorithm, key, data);
                    p.then(function(expected) {
                        var sig = new Uint8Array(_toBytes(signature));
                        var exp = new Uint8Array(expected);
                        if (sig.length !== exp.length) { resolve(false); return; }
                        var ok = 0;
                        for (var i = 0; i < sig.length; i++) ok |= (sig[i] ^ exp[i]);
                        resolve(ok === 0);
                    }, reject);
                });
            },

            generateKey: function(algorithm, extractable, usages) {
                return new Promise(function(resolve, reject) {
                    try {
                        var name = _algoName(algorithm);
                        var len = (algorithm.length | 0) || 256;
                        var raw = new Uint8Array(len / 8);
                        webCrypto.getRandomValues(raw);
                        if (name === 'aes-gcm' || name === 'aes-cbc' || name === 'aes-ctr') {
                            resolve(_makeCryptoKey({ name: name.toUpperCase(), length: len },
                                                   raw, 'secret', extractable, usages));
                            return;
                        }
                        if (name === 'hmac') {
                            var hashName = _hashName(algorithm.hash);
                            // HMAC default key length matches block size of hash.
                            var blockBits = (hashName === 'sha512' || hashName === 'sha384') ? 1024 : 512;
                            var hmacLen = algorithm.length || blockBits;
                            var hraw = new Uint8Array(hmacLen / 8);
                            webCrypto.getRandomValues(hraw);
                            resolve(_makeCryptoKey({ name: 'HMAC',
                                                     hash: { name: hashName.toUpperCase().replace(/^SHA/, 'SHA-') },
                                                     length: hmacLen },
                                                   hraw, 'secret', extractable, usages));
                            return;
                        }
                        reject(new Error('SubtleCrypto.generateKey: unsupported algorithm: ' + name));
                    } catch (e) { reject(e); }
                });
            },

            importKey: function(format, keyData, algorithm, extractable, usages) {
                return new Promise(function(resolve, reject) {
                    try {
                        var name = _algoName(algorithm);
                        if (format === 'raw') {
                            var raw = _toBytes(keyData);
                            if (name === 'aes-gcm' || name === 'aes-cbc' || name === 'aes-ctr') {
                                resolve(_makeCryptoKey({ name: name.toUpperCase(), length: raw.length * 8 },
                                                       raw, 'secret', extractable, usages));
                                return;
                            }
                            if (name === 'hmac') {
                                var hashName = _hashName(algorithm.hash);
                                resolve(_makeCryptoKey({ name: 'HMAC',
                                                         hash: { name: hashName.toUpperCase().replace(/^SHA/, 'SHA-') },
                                                         length: raw.length * 8 },
                                                       raw, 'secret', extractable, usages));
                                return;
                            }
                            if (name === 'pbkdf2' || name === 'hkdf') {
                                resolve(_makeCryptoKey({ name: name.toUpperCase() },
                                                       raw, 'secret', extractable, usages));
                                return;
                            }
                        }
                        if (format === 'jwk' && keyData && keyData.k) {
                            var raw2 = _toBytes(_b64UrlDecode(keyData.k));
                            if (name === 'aes-gcm' || name === 'aes-cbc') {
                                resolve(_makeCryptoKey({ name: name.toUpperCase(), length: raw2.length * 8 },
                                                       raw2, 'secret', extractable, usages));
                                return;
                            }
                            if (name === 'hmac') {
                                var hashName2 = _hashName(algorithm.hash);
                                resolve(_makeCryptoKey({ name: 'HMAC',
                                                         hash: { name: hashName2.toUpperCase().replace(/^SHA/, 'SHA-') },
                                                         length: raw2.length * 8 },
                                                       raw2, 'secret', extractable, usages));
                                return;
                            }
                        }
                        reject(new Error('SubtleCrypto.importKey: unsupported format/algorithm: '
                                         + format + '/' + name));
                    } catch (e) { reject(e); }
                });
            },

            exportKey: function(format, key) {
                return new Promise(function(resolve, reject) {
                    try {
                        if (!key.extractable) {
                            return reject(new Error('SubtleCrypto.exportKey: key not extractable'));
                        }
                        if (format === 'raw') {
                            resolve(new Uint8Array(key._raw).buffer);
                            return;
                        }
                        if (format === 'jwk') {
                            var algoName = (key.algorithm && key.algorithm.name) || '';
                            var jwk = {
                                kty: 'oct',
                                k: _b64UrlEncode(key._raw),
                                alg: algoName,
                                ext: true,
                                key_ops: key.usages.slice(),
                            };
                            resolve(jwk);
                            return;
                        }
                        reject(new Error('SubtleCrypto.exportKey: unsupported format: ' + format));
                    } catch (e) { reject(e); }
                });
            },

            deriveBits: function(algorithm, baseKey, length) {
                return new Promise(function(resolve, reject) {
                    try {
                        var name = _algoName(algorithm);
                        var nc = require('crypto');
                        if (name === 'pbkdf2') {
                            var hashName = _hashName(algorithm.hash);
                            var salt = _toBytes(algorithm.salt);
                            var iters = algorithm.iterations | 0;
                            var bytes = length / 8;
                            var raw = nc.pbkdf2Sync(
                                Buffer.from(baseKey._raw),
                                Buffer.from(salt),
                                iters,
                                bytes,
                                hashName);
                            resolve(new Uint8Array(raw).buffer);
                            return;
                        }
                        if (name === 'hkdf') {
                            // RFC 5869 HKDF on top of HMAC. The Hmac
                            // wrapper's `digest()` returns a hex string
                            // by default; pass the raw form via
                            // `digest('hex')` and convert with
                            // `Buffer.from(hex, 'hex')` so we get bytes.
                            var hash = _hashName(algorithm.hash);
                            var ikm = baseKey._raw;
                            var salt2 = algorithm.salt ? _toBytes(algorithm.salt) : new Uint8Array(0);
                            var info = algorithm.info ? _toBytes(algorithm.info) : new Uint8Array(0);
                            var extract = nc.createHmac(hash, Buffer.from(salt2));
                            extract.update(Buffer.from(ikm));
                            var prk = Buffer.from(extract.digest('hex'), 'hex');
                            var bytesNeeded = length / 8;
                            var hashLen = prk.length;
                            var n = Math.ceil(bytesNeeded / hashLen);
                            var t = Buffer.alloc(0);
                            var okm = Buffer.alloc(0);
                            for (var i = 1; i <= n; i++) {
                                var h = nc.createHmac(hash, prk);
                                h.update(t);
                                h.update(Buffer.from(info));
                                h.update(Buffer.from([i]));
                                t = Buffer.from(h.digest('hex'), 'hex');
                                okm = Buffer.concat([okm, t]);
                            }
                            resolve(new Uint8Array(okm.slice(0, bytesNeeded)).buffer);
                            return;
                        }
                        reject(new Error('SubtleCrypto.deriveBits: unsupported algorithm: ' + name));
                    } catch (e) { reject(e); }
                });
            },

            deriveKey: function(algorithm, baseKey, derivedKeyAlgorithm, extractable, usages) {
                return subtle.deriveBits(algorithm, baseKey,
                    (derivedKeyAlgorithm.length | 0) || 256
                ).then(function(buf) {
                    return subtle.importKey('raw', buf, derivedKeyAlgorithm, extractable, usages);
                });
            },

            wrapKey: function(format, key, wrappingKey, wrapAlgorithm) {
                return subtle.exportKey(format, key).then(function(raw) {
                    return subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
                });
            },

            unwrapKey: function(format, wrapped, unwrappingKey, unwrapAlgorithm,
                                unwrappedKeyAlgorithm, extractable, usages) {
                return subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrapped).then(function(raw) {
                    return subtle.importKey(format, raw, unwrappedKeyAlgorithm, extractable, usages);
                });
            },
        };
        function _b64UrlEncode(bytes) {
            return _bufToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }
        function _b64UrlDecode(str) {
            var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4 !== 0) s += '=';
            return _b64ToBuf(s);
        }
        webCrypto.subtle = webCrypto.subtle || subtle;
        globalThis.crypto = webCrypto;

        // ----- CryptoKey / SubtleCrypto / Crypto globals --------------
        //
        // Node 17+ exposes the WebCrypto class globals (so library
        // code can `instanceof CryptoKey` after import-key). Our keys
        // are plain objects with a `type`, `algorithm`, `extractable`,
        // `usages` shape; the global is a brand-check class that accepts
        // them via its own ctor pattern.
        if (typeof globalThis.CryptoKey !== 'function') {
            function CryptoKey() {
                throw new TypeError(
                    'Illegal constructor: CryptoKey is not constructable directly');
            }
            // Mark our internal keys as instances via prototype tagging.
            CryptoKey.prototype = Object.create(Object.prototype);
            Object.defineProperty(CryptoKey.prototype, Symbol.toStringTag, {
                value: 'CryptoKey', configurable: true,
            });
            Object.defineProperty(globalThis, 'CryptoKey', {
                value: CryptoKey, writable: true, configurable: true,
            });
        }
        if (typeof globalThis.SubtleCrypto !== 'function') {
            function SubtleCrypto() {
                throw new TypeError(
                    'Illegal constructor: SubtleCrypto is not constructable directly');
            }
            SubtleCrypto.prototype = Object.create(Object.prototype);
            Object.defineProperty(SubtleCrypto.prototype, Symbol.toStringTag, {
                value: 'SubtleCrypto', configurable: true,
            });
            Object.defineProperty(globalThis, 'SubtleCrypto', {
                value: SubtleCrypto, writable: true, configurable: true,
            });
        }
        if (typeof globalThis.Crypto !== 'function') {
            function Crypto() {
                throw new TypeError(
                    'Illegal constructor: Crypto is not constructable directly');
            }
            Crypto.prototype = Object.create(Object.prototype);
            Object.defineProperty(Crypto.prototype, Symbol.toStringTag, {
                value: 'Crypto', configurable: true,
            });
            Object.defineProperty(globalThis, 'Crypto', {
                value: Crypto, writable: true, configurable: true,
            });
        }
    }

    // ----- navigator (Node 22+) -------------------------------------
    if (typeof globalThis.navigator !== 'object' || !globalThis.navigator) {
        globalThis.navigator = {
            userAgent: 'Node.js/26.0.0 (Afterburner)',
            language: 'en-US',
            languages: ['en-US'],
            hardwareConcurrency: 1,
            platform: globalThis.process && globalThis.process.platform || 'linux',
            onLine: true,
        };
    }

    // ----- Streams Web globals --------------------------------------
    // The polyfill bundle registers `stream/web` as a require target
    // but Node 18+ also exposes the constructors as globals. Bring
    // them onto globalThis so undici / web-streams-polyfill probes
    // see them.
    try {
        var sw = require('stream/web');
        ['ReadableStream','WritableStream','TransformStream',
         'ByteLengthQueuingStrategy','CountQueuingStrategy',
         'ReadableStreamDefaultReader','ReadableStreamBYOBReader',
         'WritableStreamDefaultWriter','TransformStreamDefaultController'
        ].forEach(function(name) {
            if (sw[name] && !globalThis[name]) globalThis[name] = sw[name];
        });
    } catch (_) {}

    // ----- TextEncoderStream / TextDecoderStream --------------------
    // TransformStream subclasses that pump chunks through encode/decode.
    // Defer until ReadableStream is available so we can compose.
    if (typeof globalThis.TextEncoderStream !== 'function' && typeof globalThis.TransformStream === 'function') {
        var TES = function TextEncoderStream() {
            var enc = new globalThis.TextEncoder();
            globalThis.TransformStream.call(this, {
                transform: function(chunk, controller) {
                    controller.enqueue(enc.encode(String(chunk)));
                },
            });
            this.encoding = enc.encoding;
        };
        TES.prototype = Object.create(globalThis.TransformStream && globalThis.TransformStream.prototype || Object.prototype);
        globalThis.TextEncoderStream = TES;
    }
    if (typeof globalThis.TextDecoderStream !== 'function' && typeof globalThis.TransformStream === 'function') {
        var TDS = function TextDecoderStream(label, options) {
            var dec = new globalThis.TextDecoder(label, options);
            globalThis.TransformStream.call(this, {
                transform: function(chunk, controller) {
                    controller.enqueue(dec.decode(chunk));
                },
            });
            this.encoding = dec.encoding;
        };
        TDS.prototype = Object.create(globalThis.TransformStream && globalThis.TransformStream.prototype || Object.prototype);
        globalThis.TextDecoderStream = TDS;
    }

    // ----- CompressionStream / DecompressionStream ------------------
    //
    // Node 17+ / WHATWG Compression Streams. Each instance is a
    // TransformStream that pipes chunks through a sync zlib codec.
    // Supported formats: `gzip` / `deflate` / `deflate-raw`.
    // `Reflect.construct` is the only path that produces a real
    // TransformStream subclass under QuickJS — `.call(this, …)` on
    // class constructors throws a TypeError.
    function _makeCompressFn(format) {
        return function(chunk, controller) {
            try {
                var nz = require('zlib');
                var Buf = globalThis.Buffer;
                var buf = Buf && Buf.from ? Buf.from(chunk) : chunk;
                var syncFn = (format === 'gzip') ? nz.gzipSync
                           : (format === 'deflate') ? nz.deflateSync
                           : (format === 'deflate-raw') ? nz.deflateRawSync
                           : (format === 'zstd') ? nz.zstdCompressSync
                           : null;
                if (!syncFn) {
                    controller.error(new TypeError(
                        "CompressionStream: unknown format '" + format + "'"));
                    return;
                }
                controller.enqueue(syncFn(buf));
            } catch (e) { controller.error(e); }
        };
    }
    function _makeDecompressFn(format) {
        return function(chunk, controller) {
            try {
                var nz = require('zlib');
                var Buf = globalThis.Buffer;
                var buf = Buf && Buf.from ? Buf.from(chunk) : chunk;
                var syncFn = (format === 'gzip') ? nz.gunzipSync
                           : (format === 'deflate') ? nz.inflateSync
                           : (format === 'deflate-raw') ? nz.inflateRawSync
                           : (format === 'zstd') ? nz.zstdDecompressSync
                           : null;
                if (!syncFn) {
                    controller.error(new TypeError(
                        "DecompressionStream: unknown format '" + format + "'"));
                    return;
                }
                controller.enqueue(syncFn(buf));
            } catch (e) { controller.error(e); }
        };
    }
    if (typeof globalThis.CompressionStream !== 'function'
        && typeof globalThis.TransformStream === 'function') {
        globalThis.CompressionStream = function CompressionStream(format) {
            return Reflect.construct(globalThis.TransformStream,
                [{ transform: _makeCompressFn(format) }],
                CompressionStream);
        };
        globalThis.CompressionStream.prototype =
            Object.create(globalThis.TransformStream.prototype);
        globalThis.CompressionStream.prototype.constructor = globalThis.CompressionStream;
    }
    if (typeof globalThis.DecompressionStream !== 'function'
        && typeof globalThis.TransformStream === 'function') {
        globalThis.DecompressionStream = function DecompressionStream(format) {
            return Reflect.construct(globalThis.TransformStream,
                [{ transform: _makeDecompressFn(format) }],
                DecompressionStream);
        };
        globalThis.DecompressionStream.prototype =
            Object.create(globalThis.TransformStream.prototype);
        globalThis.DecompressionStream.prototype.constructor = globalThis.DecompressionStream;
    }
    if (typeof globalThis.URL !== 'function') {
        var urlMod = require('url');
        if (typeof urlMod.URL === 'function') {
            globalThis.URL = urlMod.URL;
            globalThis.URLSearchParams = urlMod.URLSearchParams;
        } else {
            // Regex-based parser with proper RFC 3986 reference
            // resolution for the 2-arg form. Covers WHATWG-shape
            // properties (`protocol`/`host`/`pathname`/`search`/
            // `searchParams`) plus the redirect-following cases
            // node-fetch / minipass-fetch / pacote depend on:
            //   * `new URL('/p', 'https://h.com/x')`   → `https://h.com/p`
            //   * `new URL('p', 'https://h.com/x/y')`  → `https://h.com/x/p`
            //   * `new URL('https://o.com/p', 'https://h.com/x')` → `https://o.com/p`
            //   * `new URL('?q=1', 'https://h.com/x')` → `https://h.com/x?q=1`
            // Without these, every redirect-followed download breaks
            // with empty-host options and the upstream HTTP client
            // synthesises a malformed `https:///path` URL.
            function _parseAbs(s) {
                var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)([^?#]*)?(\?[^#]*)?(#.*)?$/.exec(s);
                if (!m) return null;
                return { protocol: m[1] + ':', authority: m[2] || '', path: m[3] || '', query: m[4] || '', fragment: m[5] || '' };
            }
            function _normalizePath(p) {
                // RFC 3986 §5.2.4 — remove `.` and `..` segments.
                if (!p) return '';
                var leading = p.charAt(0) === '/';
                var trailing = p.charAt(p.length - 1) === '/';
                var parts = p.split('/').filter(function(s) { return s.length > 0; });
                var stack = [];
                for (var i = 0; i < parts.length; i++) {
                    var seg = parts[i];
                    if (seg === '.') continue;
                    if (seg === '..') { if (stack.length) stack.pop(); continue; }
                    stack.push(seg);
                }
                return (leading ? '/' : '') + stack.join('/') + (trailing && stack.length ? '/' : '');
            }
            globalThis.URL = function URL(href, base) {
                var input = String(href);
                var parsed = _parseAbs(input);
                if (!parsed && base) {
                    // Reference resolution per RFC 3986 §5.3.
                    var b = _parseAbs(String(base));
                    if (b) {
                        // Same-document fragment.
                        if (input.charAt(0) === '#') {
                            input = (b.protocol + '//' + b.authority + b.path + b.query + input);
                        } else if (input.charAt(0) === '?') {
                            input = (b.protocol + '//' + b.authority + b.path + input);
                        } else if (input.charAt(0) === '/') {
                            // Absolute path on the base authority.
                            input = (b.protocol + '//' + b.authority + input);
                        } else {
                            // Path-relative against the base directory.
                            var basePath = b.path || '/';
                            // Strip the last segment.
                            var slash = basePath.lastIndexOf('/');
                            var baseDir = slash >= 0 ? basePath.slice(0, slash + 1) : '/';
                            input = (b.protocol + '//' + b.authority + _normalizePath(baseDir + input));
                        }
                        parsed = _parseAbs(input);
                    }
                }
                var protocol = parsed ? parsed.protocol : '';
                var host = parsed ? parsed.authority : '';
                var path = parsed ? (parsed.path || '/') : input;
                var query = parsed ? parsed.query : '';
                var fragment = parsed ? parsed.fragment : '';
                // Username / password split off the authority.
                var username = '', password = '';
                var atIdx = host.indexOf('@');
                if (atIdx >= 0) {
                    var userinfo = host.slice(0, atIdx);
                    host = host.slice(atIdx + 1);
                    var colonIdx = userinfo.indexOf(':');
                    if (colonIdx >= 0) {
                        username = userinfo.slice(0, colonIdx);
                        password = userinfo.slice(colonIdx + 1);
                    } else {
                        username = userinfo;
                    }
                }
                var hp = host.split(':');
                var hostname = hp[0] || '';
                var port = hp.length > 1 ? hp[1] : '';
                this.protocol = protocol;
                this.host = host;
                this.hostname = hostname;
                this.port = port;
                this.pathname = _normalizePath(path);
                if (this.pathname === '' && host) this.pathname = '/';
                this.search = query;
                this.hash = fragment;
                this.username = username;
                this.password = password;
                this.origin = protocol + (host ? '//' + host : '');
                this.href = protocol + '//' + (username ? username + (password ? ':' + password : '') + '@' : '') + host + this.pathname + this.search + this.hash;
                this.searchParams = new globalThis.URLSearchParams(this.search.slice(1));
            };
            globalThis.URL.prototype.toString = function() { return this.href; };
            globalThis.URL.prototype.toJSON  = function() { return this.href; };
            globalThis.URL.canParse = function(href, base) {
                try { new globalThis.URL(href, base); return true; }
                catch (_) { return false; }
            };
            globalThis.URL.parse = function(href, base) {
                try { return new globalThis.URL(href, base); }
                catch (_) { return null; }
            };
            // ----- URL.createObjectURL / revokeObjectURL (Node 20+) -----
            //
            // Maps a Blob / File to a `blob:burn/<uuid>` URL. The
            // mapping lives in a global registry; `fetch(blob:burn/...)`
            // (and other consumers via `globalThis.__ab_resolve_blob_url`)
            // can resolve back to the original Blob's bytes.
            // `revokeObjectURL` drops the registry entry.
            if (!globalThis.__ab_blob_url_registry) {
                globalThis.__ab_blob_url_registry = Object.create(null);
            }
            var _blobUrlReg = globalThis.__ab_blob_url_registry;
            var _blobUrlSeq = 0;
            globalThis.URL.createObjectURL = function(blob) {
                if (!blob || typeof blob.arrayBuffer !== 'function') {
                    throw new TypeError(
                        'URL.createObjectURL: argument must be a Blob / File'
                    );
                }
                // Deterministic id space — counter + pid keeps URLs
                // unique within a single process; `fetch` consumers
                // look this up by exact string match.
                var pid = (typeof process !== 'undefined' && process.pid) | 0;
                var id = 'burn-' + pid + '-' + (++_blobUrlSeq);
                var url = 'blob:burn/' + id;
                _blobUrlReg[url] = blob;
                return url;
            };
            globalThis.URL.revokeObjectURL = function(url) {
                if (typeof url === 'string') delete _blobUrlReg[url];
            };
            // Exposed for the fetch polyfill — given a `blob:burn/...`
            // URL, return the underlying Blob or undefined.
            globalThis.__ab_resolve_blob_url = function(url) {
                return _blobUrlReg[url];
            };

            globalThis.URLSearchParams = function URLSearchParams(init) {
                this._pairs = [];
                var self = this;
                if (typeof init === 'string') {
                    var s = init.replace(/^\?/, '');
                    if (s) s.split('&').forEach(function(p) {
                        var eq = p.indexOf('=');
                        var k = eq < 0 ? p : p.slice(0, eq);
                        var v = eq < 0 ? '' : p.slice(eq + 1);
                        self._pairs.push([decodeURIComponent(k), decodeURIComponent(v)]);
                    });
                } else if (init && typeof init === 'object') {
                    Object.keys(init).forEach(function(k) {
                        self._pairs.push([k, String(init[k])]);
                    });
                }
            };
            var P = globalThis.URLSearchParams.prototype;
            P.get = function(k) {
                for (var i = 0; i < this._pairs.length; i++)
                    if (this._pairs[i][0] === k) return this._pairs[i][1];
                return null;
            };
            P.getAll = function(k) {
                return this._pairs.filter(function(p) { return p[0] === k; })
                                  .map(function(p) { return p[1]; });
            };
            P.has = function(k) {
                return this._pairs.some(function(p) { return p[0] === k; });
            };
            P.set = function(k, v) {
                this._pairs = this._pairs.filter(function(p) { return p[0] !== k; });
                this._pairs.push([k, String(v)]);
            };
            P.append = function(k, v) { this._pairs.push([k, String(v)]); };
            P.delete = function(k) {
                this._pairs = this._pairs.filter(function(p) { return p[0] !== k; });
            };
            P.toString = function() {
                return this._pairs.map(function(p) {
                    return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1]);
                }).join('&');
            };
        }
    }

    // ============================================================
    // ES2024 / ES2023 globals.
    //
    // The runtime's QuickJS may add these natively in a future build;
    // every install is gated on `!has(...)` so the polyfill is a
    // no-op once the engine catches up. Idempotent + safe.
    // ============================================================

    // ---- `self` / `addEventListener` on globalThis (Web shim) -------
    //
    // Browser / Worker code routinely references `self` as the global
    // and `addEventListener` as a top-level binding. Node 22+ ships
    // both; without them, polyfills like `whatwg-url`, `web-streams-
    // polyfill`, and undici crash at module init with
    // "self is not defined".
    if (typeof globalThis.self === 'undefined') {
        globalThis.self = globalThis;
    }
    if (typeof globalThis.addEventListener !== 'function'
        && typeof globalThis.EventTarget === 'function') {
        try {
            var _gtTarget = new globalThis.EventTarget();
            globalThis.addEventListener =
                _gtTarget.addEventListener.bind(_gtTarget);
            globalThis.removeEventListener =
                _gtTarget.removeEventListener.bind(_gtTarget);
            globalThis.dispatchEvent =
                _gtTarget.dispatchEvent.bind(_gtTarget);
        } catch (_) {
            globalThis.addEventListener = function() {};
            globalThis.removeEventListener = function() {};
            globalThis.dispatchEvent = function() { return true; };
        }
    }

    // ---- Event subclasses (Node 22+) -------------------------------
    //
    // `ProgressEvent` / `CloseEvent` / `ErrorEvent` are common
    // Web-API constructors that real apps reach for in fetch-style
    // upload progress code, WebSocket close handling, and error
    // bubbling from worker threads. Lightweight subclasses of Event
    // with the canonical extra fields.
    if (typeof globalThis.ProgressEvent !== 'function' && typeof globalThis.Event === 'function') {
        globalThis.ProgressEvent = function ProgressEvent(type, init) {
            init = init || {};
            globalThis.Event.call(this, type, init);
            this.lengthComputable = !!init.lengthComputable;
            this.loaded = init.loaded || 0;
            this.total = init.total || 0;
        };
        globalThis.ProgressEvent.prototype =
            Object.create(globalThis.Event.prototype);
        globalThis.ProgressEvent.prototype.constructor = globalThis.ProgressEvent;
    }
    if (typeof globalThis.CloseEvent !== 'function' && typeof globalThis.Event === 'function') {
        globalThis.CloseEvent = function CloseEvent(type, init) {
            init = init || {};
            globalThis.Event.call(this, type, init);
            this.code = init.code || 0;
            this.reason = init.reason || '';
            this.wasClean = !!init.wasClean;
        };
        globalThis.CloseEvent.prototype =
            Object.create(globalThis.Event.prototype);
        globalThis.CloseEvent.prototype.constructor = globalThis.CloseEvent;
    }
    if (typeof globalThis.ErrorEvent !== 'function' && typeof globalThis.Event === 'function') {
        globalThis.ErrorEvent = function ErrorEvent(type, init) {
            init = init || {};
            globalThis.Event.call(this, type, init);
            this.message = init.message || '';
            this.filename = init.filename || '';
            this.lineno = init.lineno || 0;
            this.colno = init.colno || 0;
            this.error = init.error || null;
        };
        globalThis.ErrorEvent.prototype =
            Object.create(globalThis.Event.prototype);
        globalThis.ErrorEvent.prototype.constructor = globalThis.ErrorEvent;
    }

    // ============================================================
    // Web Streams (WHATWG) — minimum viable implementation.
    //
    // QuickJS / Javy don't ship the streams spec natively. This
    // polyfill covers the common consumers: undici body iteration,
    // CompressionStream, fetch().body, Readable.toWeb/fromWeb. It's
    // pull-based (the canonical algorithm); the controller API
    // matches WHATWG so user code that constructs streams works.
    //
    // Out of scope for now: BYOB readers (byte streams pull into
    // user-provided buffers), tee() (split into two readers),
    // queuing strategies beyond size+highWaterMark defaults. Real
    // workloads that need those grow later.
    // ============================================================
    if (typeof globalThis.ReadableStream !== 'function'
        || (function() {
            // Detect "stub" ReadableStream by attempting a no-op
            // construction; Javy's stub throws on call.
            try { new globalThis.ReadableStream({}); return false; } catch (_) { return true; }
        })()) {

        function _resolvedPromise(v) { return Promise.resolve(v); }

        function ReadableStreamDefaultController(stream) {
            this._stream = stream;
        }
        ReadableStreamDefaultController.prototype.enqueue = function(chunk) {
            var s = this._stream;
            if (s._state !== 'readable') return;
            s._queue.push(chunk);
            s._processQueue();
        };
        ReadableStreamDefaultController.prototype.close = function() {
            var s = this._stream;
            if (s._state !== 'readable') return;
            s._closeRequested = true;
            s._processQueue();
        };
        ReadableStreamDefaultController.prototype.error = function(err) {
            var s = this._stream;
            if (s._state !== 'readable') return;
            s._error = err;
            s._state = 'errored';
            s._flushReaders();
        };
        Object.defineProperty(ReadableStreamDefaultController.prototype, 'desiredSize', {
            get: function() {
                var s = this._stream;
                if (s._state === 'errored') return null;
                if (s._state === 'closed') return 0;
                return Math.max(0, (s._highWaterMark | 0) - s._queue.length);
            },
        });

        function ReadableStream(underlyingSource, strategy) {
            if (!(this instanceof ReadableStream)) {
                throw new TypeError('ReadableStream is a constructor');
            }
            underlyingSource = underlyingSource || {};
            strategy = strategy || {};
            this._source = underlyingSource;
            this._highWaterMark = (strategy && strategy.highWaterMark) || 1;
            this._queue = [];
            this._state = 'readable';
            this._closeRequested = false;
            this._error = null;
            this._readerLocked = false;
            this._waiters = []; // pending read() resolvers
            var controller = new ReadableStreamDefaultController(this);
            this._controller = controller;
            try {
                if (typeof underlyingSource.start === 'function') {
                    var ret = underlyingSource.start(controller);
                    if (ret && typeof ret.then === 'function') {
                        var self = this;
                        ret.catch(function(e) { controller.error(e); });
                    }
                }
            } catch (e) { controller.error(e); }
        }

        ReadableStream.prototype._pull = function() {
            var s = this;
            if (s._pulling) return;
            if (typeof s._source.pull !== 'function') return;
            if (s._queue.length >= s._highWaterMark) return;
            s._pulling = true;
            try {
                var ret = s._source.pull(s._controller);
                Promise.resolve(ret).then(function() {
                    s._pulling = false;
                    s._processQueue();
                }, function(e) {
                    s._pulling = false;
                    s._controller.error(e);
                });
            } catch (e) {
                s._pulling = false;
                s._controller.error(e);
            }
        };
        ReadableStream.prototype._processQueue = function() {
            // Drain pending readers from the queue.
            while (this._waiters.length && this._queue.length) {
                var resolve = this._waiters.shift();
                resolve({ value: this._queue.shift(), done: false });
            }
            // If close was requested and queue is empty, close.
            if (this._closeRequested && this._queue.length === 0) {
                this._state = 'closed';
                this._flushReaders();
                return;
            }
            // Need more data?
            if (this._queue.length < this._highWaterMark) this._pull();
        };
        ReadableStream.prototype._flushReaders = function() {
            while (this._waiters.length) {
                var resolve = this._waiters.shift();
                if (this._state === 'errored') {
                    resolve(Promise.reject(this._error));
                } else {
                    resolve({ value: undefined, done: true });
                }
            }
        };
        ReadableStream.prototype.getReader = function(_opts) {
            if (this._readerLocked) {
                throw new TypeError('ReadableStream is already locked');
            }
            this._readerLocked = true;
            return new ReadableStreamDefaultReader(this);
        };
        ReadableStream.prototype.cancel = function(reason) {
            if (this._state !== 'readable') return Promise.resolve();
            this._state = 'closed';
            this._queue = [];
            this._flushReaders();
            try {
                if (typeof this._source.cancel === 'function') {
                    return Promise.resolve(this._source.cancel(reason));
                }
            } catch (_) {}
            return Promise.resolve();
        };
        ReadableStream.prototype.pipeTo = function(dest, _opts) {
            var src = this;
            return (async function() {
                var reader = src.getReader();
                var writer = dest.getWriter();
                try {
                    while (true) {
                        var step = await reader.read();
                        if (step.done) break;
                        await writer.write(step.value);
                    }
                    await writer.close();
                } catch (e) {
                    try { await writer.abort(e); } catch (_) {}
                    throw e;
                } finally {
                    reader.releaseLock();
                    writer.releaseLock();
                }
            })();
        };
        ReadableStream.prototype.pipeThrough = function(transform, opts) {
            this.pipeTo(transform.writable, opts).catch(function(_) {});
            return transform.readable;
        };
        ReadableStream.prototype[Symbol.asyncIterator] = function() {
            var reader = this.getReader();
            return {
                next: function() { return reader.read(); },
                return: function(v) { reader.releaseLock(); return Promise.resolve({ value: v, done: true }); },
                [Symbol.asyncIterator]: function() { return this; },
            };
        };
        Object.defineProperty(ReadableStream.prototype, 'locked', {
            get: function() { return this._readerLocked; },
        });

        // Static `ReadableStream.from(iterable)` — Node 22+ /
        // Web 2024.
        ReadableStream.from = function(iterable) {
            var it;
            if (iterable && typeof iterable[Symbol.asyncIterator] === 'function') {
                it = iterable[Symbol.asyncIterator]();
            } else if (iterable && typeof iterable[Symbol.iterator] === 'function') {
                it = iterable[Symbol.iterator]();
            } else {
                throw new TypeError('ReadableStream.from: argument is not iterable');
            }
            return new ReadableStream({
                async pull(controller) {
                    var step = await it.next();
                    if (step.done) controller.close();
                    else controller.enqueue(step.value);
                },
            });
        };

        function ReadableStreamDefaultReader(stream) {
            this._stream = stream;
        }
        ReadableStreamDefaultReader.prototype.read = function() {
            var s = this._stream;
            if (!s) return Promise.resolve({ value: undefined, done: true });
            if (s._state === 'errored') return Promise.reject(s._error);
            if (s._queue.length) {
                return _resolvedPromise({ value: s._queue.shift(), done: false }).then(function(v) {
                    if (s._state === 'readable') s._processQueue();
                    return v;
                });
            }
            if (s._state === 'closed') {
                return _resolvedPromise({ value: undefined, done: true });
            }
            // Wait for next enqueue.
            var self = this;
            return new Promise(function(resolve) {
                s._waiters.push(resolve);
                s._pull();
            });
        };
        ReadableStreamDefaultReader.prototype.releaseLock = function() {
            if (!this._stream) return;
            this._stream._readerLocked = false;
            this._stream = null;
        };
        ReadableStreamDefaultReader.prototype.cancel = function(reason) {
            if (!this._stream) return Promise.resolve();
            return this._stream.cancel(reason);
        };
        Object.defineProperty(ReadableStreamDefaultReader.prototype, 'closed', {
            get: function() {
                var s = this._stream;
                if (!s) return Promise.resolve();
                if (s._state === 'closed') return Promise.resolve();
                if (s._state === 'errored') return Promise.reject(s._error);
                return new Promise(function(resolve, reject) {
                    var orig = s._flushReaders;
                    s._flushReaders = function() {
                        orig.call(s);
                        if (s._state === 'errored') reject(s._error);
                        else resolve();
                    };
                });
            },
        });

        function WritableStreamDefaultController(stream) { this._stream = stream; }
        WritableStreamDefaultController.prototype.error = function(err) {
            this._stream._error = err;
            this._stream._state = 'errored';
        };

        function WritableStream(underlyingSink, strategy) {
            if (!(this instanceof WritableStream)) {
                throw new TypeError('WritableStream is a constructor');
            }
            underlyingSink = underlyingSink || {};
            this._sink = underlyingSink;
            this._highWaterMark = (strategy && strategy.highWaterMark) || 1;
            this._queue = [];
            this._state = 'writable';
            this._error = null;
            this._writerLocked = false;
            var controller = new WritableStreamDefaultController(this);
            this._controller = controller;
            try {
                if (typeof underlyingSink.start === 'function') {
                    var ret = underlyingSink.start(controller);
                    Promise.resolve(ret).catch(function(e) { controller.error(e); });
                }
            } catch (e) { controller.error(e); }
        }
        WritableStream.prototype.getWriter = function() {
            if (this._writerLocked) throw new TypeError('WritableStream is locked');
            this._writerLocked = true;
            return new WritableStreamDefaultWriter(this);
        };
        WritableStream.prototype.abort = function(reason) {
            this._state = 'errored';
            this._error = reason;
            try {
                if (typeof this._sink.abort === 'function') {
                    return Promise.resolve(this._sink.abort(reason));
                }
            } catch (_) {}
            return Promise.resolve();
        };
        WritableStream.prototype.close = function() {
            if (this._state !== 'writable') return Promise.resolve();
            var self = this;
            this._state = 'closed';
            try {
                if (typeof this._sink.close === 'function') {
                    return Promise.resolve(this._sink.close());
                }
            } catch (e) {
                self._error = e;
                self._state = 'errored';
                return Promise.reject(e);
            }
            return Promise.resolve();
        };
        Object.defineProperty(WritableStream.prototype, 'locked', {
            get: function() { return this._writerLocked; },
        });

        function WritableStreamDefaultWriter(stream) { this._stream = stream; }
        WritableStreamDefaultWriter.prototype.write = function(chunk) {
            var s = this._stream;
            if (!s) return Promise.reject(new TypeError('writer released'));
            if (s._state === 'errored') return Promise.reject(s._error);
            if (s._state !== 'writable') return Promise.reject(new TypeError('stream closed'));
            if (typeof s._sink.write !== 'function') return Promise.resolve();
            try {
                var ret = s._sink.write(chunk, s._controller);
                return Promise.resolve(ret);
            } catch (e) {
                s._error = e;
                s._state = 'errored';
                return Promise.reject(e);
            }
        };
        WritableStreamDefaultWriter.prototype.close = function() {
            return this._stream ? this._stream.close() : Promise.resolve();
        };
        WritableStreamDefaultWriter.prototype.abort = function(reason) {
            return this._stream ? this._stream.abort(reason) : Promise.resolve();
        };
        WritableStreamDefaultWriter.prototype.releaseLock = function() {
            if (!this._stream) return;
            this._stream._writerLocked = false;
            this._stream = null;
        };
        Object.defineProperty(WritableStreamDefaultWriter.prototype, 'desiredSize', {
            get: function() {
                var s = this._stream;
                if (!s) return null;
                if (s._state === 'errored') return null;
                if (s._state === 'closed') return 0;
                return s._highWaterMark - s._queue.length;
            },
        });

        function TransformStream(transformer, writableStrategy, readableStrategy) {
            if (!(this instanceof TransformStream)) {
                throw new TypeError('TransformStream is a constructor');
            }
            transformer = transformer || {};
            var readableSide;
            var readableController;
            var transformFn = transformer.transform || function(chunk, c) { c.enqueue(chunk); };
            var flushFn = transformer.flush || function(_c) {};
            var writable = new WritableStream({
                async write(chunk) {
                    await Promise.resolve(transformFn(chunk, readableController));
                },
                async close() {
                    try { await Promise.resolve(flushFn(readableController)); } catch (_) {}
                    readableController.close();
                },
                abort(reason) { readableController.error(reason); },
            }, writableStrategy);
            readableSide = new ReadableStream({
                start(c) { readableController = c; },
            }, readableStrategy);
            // Run the transformer's start hook with a tiny shim
            // controller that delegates to the readable side.
            var shimController = {
                enqueue: function(chunk) { readableController.enqueue(chunk); },
                error: function(err) { readableController.error(err); },
                terminate: function() { readableController.close(); },
            };
            try {
                if (typeof transformer.start === 'function') {
                    Promise.resolve(transformer.start(shimController)).catch(function(_) {});
                }
            } catch (_) {}
            this.readable = readableSide;
            this.writable = writable;
        }

        function ByteLengthQueuingStrategy(opts) {
            this.highWaterMark = (opts && opts.highWaterMark) || 1;
            this.size = function(chunk) { return chunk && chunk.byteLength != null ? chunk.byteLength : 1; };
        }
        function CountQueuingStrategy(opts) {
            this.highWaterMark = (opts && opts.highWaterMark) || 1;
            this.size = function() { return 1; };
        }

        globalThis.ReadableStream = ReadableStream;
        globalThis.ReadableStreamDefaultReader = ReadableStreamDefaultReader;
        globalThis.ReadableStreamDefaultController = ReadableStreamDefaultController;
        globalThis.WritableStream = WritableStream;
        globalThis.WritableStreamDefaultWriter = WritableStreamDefaultWriter;
        globalThis.WritableStreamDefaultController = WritableStreamDefaultController;
        globalThis.TransformStream = TransformStream;
        globalThis.ByteLengthQueuingStrategy = ByteLengthQueuingStrategy;
        globalThis.CountQueuingStrategy = CountQueuingStrategy;

        // Re-link CompressionStream / DecompressionStream / TextEncoderStream
        // / TextDecoderStream classes that were installed earlier in
        // this same IIFE against the now-stub TransformStream. Their
        // prototypes were chained to the stub; we re-chain them to the
        // working TransformStream.prototype so `instanceof TransformStream`
        // checks pass and `Reflect.construct` works.
        function _relinkPrototype(Cls) {
            if (typeof Cls === 'function') {
                Cls.prototype = Object.create(TransformStream.prototype);
                Cls.prototype.constructor = Cls;
            }
        }
        _relinkPrototype(globalThis.CompressionStream);
        _relinkPrototype(globalThis.DecompressionStream);
        _relinkPrototype(globalThis.TextEncoderStream);
        _relinkPrototype(globalThis.TextDecoderStream);
    }

    // ---- SharedArrayBuffer (cross-process via mmap) ---------------
    //
    // Real OS-shared memory backed by `__host_sab_alloc` (memfd on
    // Linux). The JS surface mimics ArrayBuffer's shape so existing
    // typed-array code works; reads / writes hop through host imports
    // so cross-process coherence is honoured.
    if (typeof globalThis.__ab_sab_registry !== 'object') {
        globalThis.__ab_sab_registry = Object.create(null);
    }
    var _sabRegistry = globalThis.__ab_sab_registry;

    /// Build a `SharedArrayBuffer`-shaped object backed by an
    /// mmap region. We can't subclass `ArrayBuffer` (the engine's
    /// internal slots aren't accessible from JS), so the strategy
    /// is: allocate a regular ArrayBuffer of the same byteLength,
    /// bolt the SAB metadata onto it as non-enumerable properties,
    /// register it in the SAB registry. Typed-array views over the
    /// returned ArrayBuffer index through the standard JS heap;
    /// `Atomics.{load,store,wait,notify}` detect the registered
    /// region via the registry and route atomic ops to the host so
    /// cross-process coherence holds.
    function _SAB(byteLengthOrAttach) {
        if (!(this instanceof _SAB)) return new _SAB(byteLengthOrAttach);
        var byteLength;
        var regionId;
        if (typeof byteLengthOrAttach === 'object' && byteLengthOrAttach !== null
            && byteLengthOrAttach.__ab_sab_attach) {
            var attach = byteLengthOrAttach;
            regionId = globalThis.__host_sab_open(attach.descriptor, attach.byteLength);
            if (regionId < 0) {
                throw new Error('SharedArrayBuffer attach: rc=' + regionId);
            }
            byteLength = attach.byteLength;
        } else {
            byteLength = (byteLengthOrAttach | 0) >>> 0;
            if (byteLength === 0) {
                throw new RangeError('SharedArrayBuffer: byteLength must be > 0');
            }
            regionId = globalThis.__host_sab_alloc(byteLength);
            if (regionId < 0) {
                throw new Error('SharedArrayBuffer: alloc failed (rc=' + regionId + ')');
            }
        }
        // The buffer the user gets IS a real ArrayBuffer so
        // `new Int32Array(sab)` works without monkey-patching the
        // typed-array constructor. Atomics.* detect this is a SAB
        // shadow via the registry keyed by buffer identity.
        var buf = new ArrayBuffer(byteLength);
        Object.defineProperty(buf, '_regionId', {
            value: regionId,
            enumerable: false,
            writable: false,
        });
        Object.defineProperty(buf, '_descriptor', {
            value: globalThis.__host_sab_descriptor(regionId) || '',
            enumerable: false,
            writable: false,
        });
        Object.defineProperty(buf, '_isSharedArrayBuffer', {
            value: true,
            enumerable: false,
            writable: false,
        });
        _sabRegistry[regionId] = buf;
        return buf;
    }

    // Replace globalThis.SharedArrayBuffer with our shadow. Old code
    // that captured the original is the rare case — the global is
    // re-checked at every constructor call here.
    if (typeof globalThis.__host_sab_alloc === 'function') {
        globalThis.SharedArrayBuffer = _SAB;
    }

    function _sabFromView(view) {
        // Map a typed-array view over a SharedArrayBuffer to its
        // underlying region. Returns the buffer if it carries our
        // `_regionId` brand, null otherwise.
        var buf = view && view.buffer;
        if (!buf) return null;
        if (typeof buf._regionId === 'number') return buf;
        return null;
    }

    function _viewByteOffset(view, idx) {
        var bytesPerElement = view.BYTES_PER_ELEMENT || 1;
        return (view.byteOffset | 0) + ((idx | 0) * bytesPerElement);
    }

    // ---- Atomics (cross-process via __host_sab_*) -----------------
    //
    // For typed-array views over a `SharedArrayBuffer`, each Atomics
    // op routes through the host so the bytes the kernel sees are
    // exactly the slot the futex / wake operates on. Over a regular
    // (non-shared) `ArrayBuffer`, ops fall back to single-realm
    // semantics — there's no cross-process coherence to enforce.
    // Atomics ops simplify to their non-atomic equivalents because
    // there's no other thread to race with; the wait/notify
    // primitives raise — single-threaded code that calls `wait()`
    // would deadlock anyway, so a typed error beats a hang.
    if (typeof globalThis.Atomics === 'undefined') {
        function _ta(view) {
            if (!ArrayBuffer.isView(view)) {
                throw new TypeError('Atomics: argument is not a TypedArray');
            }
            return view;
        }
        globalThis.Atomics = {
            load: function(view, idx) {
                _ta(view);
                var sab = _sabFromView(view);
                if (sab) {
                    var w = view.BYTES_PER_ELEMENT === 8 ? 8 : 4;
                    var v = globalThis.__host_sab_atomic_load(
                        sab._regionId, _viewByteOffset(view, idx), w);
                    view[idx] = v;
                    return v;
                }
                return view[idx];
            },
            store: function(view, idx, value) {
                _ta(view);
                var sab = _sabFromView(view);
                if (sab) {
                    var w = view.BYTES_PER_ELEMENT === 8 ? 8 : 4;
                    globalThis.__host_sab_atomic_store(
                        sab._regionId, _viewByteOffset(view, idx), value, w);
                }
                view[idx] = value;
                return value;
            },
            add: function(view, idx, value) {
                _ta(view);
                var sab = _sabFromView(view);
                if (sab) {
                    var w = view.BYTES_PER_ELEMENT === 8 ? 8 : 4;
                    var off = _viewByteOffset(view, idx);
                    while (true) {
                        var cur = globalThis.__host_sab_atomic_load(sab._regionId, off, w);
                        var got = globalThis.__host_sab_atomic_cas(
                            sab._regionId, off, cur, cur + value, w);
                        if (got === cur) {
                            view[idx] = cur + value;
                            return cur;
                        }
                    }
                }
                var v = view[idx]; view[idx] = v + value; return v;
            },
            sub: function(view, idx, value) {
                _ta(view);
                var sab = _sabFromView(view);
                if (sab) {
                    var w = view.BYTES_PER_ELEMENT === 8 ? 8 : 4;
                    var off = _viewByteOffset(view, idx);
                    while (true) {
                        var cur = globalThis.__host_sab_atomic_load(sab._regionId, off, w);
                        var got = globalThis.__host_sab_atomic_cas(
                            sab._regionId, off, cur, cur - value, w);
                        if (got === cur) {
                            view[idx] = cur - value;
                            return cur;
                        }
                    }
                }
                var v = view[idx]; view[idx] = v - value; return v;
            },
            and: function(view, idx, value) {
                var v = _ta(view)[idx]; view[idx] = v & value; return v;
            },
            or: function(view, idx, value) {
                var v = _ta(view)[idx]; view[idx] = v | value; return v;
            },
            xor: function(view, idx, value) {
                var v = _ta(view)[idx]; view[idx] = v ^ value; return v;
            },
            exchange: function(view, idx, value) {
                _ta(view);
                var sab = _sabFromView(view);
                if (sab) {
                    var w = view.BYTES_PER_ELEMENT === 8 ? 8 : 4;
                    var off = _viewByteOffset(view, idx);
                    while (true) {
                        var cur = globalThis.__host_sab_atomic_load(sab._regionId, off, w);
                        var got = globalThis.__host_sab_atomic_cas(
                            sab._regionId, off, cur, value, w);
                        if (got === cur) {
                            view[idx] = value;
                            return cur;
                        }
                    }
                }
                var v = view[idx]; view[idx] = value; return v;
            },
            compareExchange: function(view, idx, expected, replacement) {
                _ta(view);
                var sab = _sabFromView(view);
                if (sab) {
                    var w = view.BYTES_PER_ELEMENT === 8 ? 8 : 4;
                    var got = globalThis.__host_sab_atomic_cas(
                        sab._regionId, _viewByteOffset(view, idx),
                        expected, replacement, w);
                    if (got === expected) view[idx] = replacement;
                    return got;
                }
                var v = view[idx];
                if (v === expected) view[idx] = replacement;
                return v;
            },
            isLockFree: function(_size) { return true; },
            wait: function(view, idx, value, timeout) {
                // Cross-process semantics when the view is over a
                // SharedArrayBuffer: route through the host's
                // futex / WaitOnAddress equivalent. Single-realm SAB
                // (or non-shared backing) falls through to a typed
                // error since blocking sync would deadlock the realm.
                _ta(view);
                var sab = _sabFromView(view);
                if (!sab) {
                    throw new TypeError(
                        'Atomics.wait: requires a SharedArrayBuffer-backed typed-array view'
                    );
                }
                var byteOffset = _viewByteOffset(view, idx);
                var to = (typeof timeout === 'number' && isFinite(timeout) && timeout >= 0)
                    ? (timeout | 0) : -1;
                var rc = globalThis.__host_sab_wait(sab._regionId, byteOffset, value | 0, to);
                if (rc === 0) return 'ok';
                if (rc === 1) return 'not-equal';
                if (rc === 2) return 'timed-out';
                throw new Error('Atomics.wait: rc=' + rc);
            },
            notify: function(view, idx, count) {
                _ta(view);
                if (count === undefined || count === null) count = Infinity;
                var sab = _sabFromView(view);
                if (sab) {
                    // Cross-process wake via the host's
                    // wake_one / wake_all primitive.
                    var byteOffset = _viewByteOffset(view, idx);
                    var n = count === Infinity ? -1 : (count | 0);
                    var rc = globalThis.__host_sab_notify(sab._regionId, byteOffset, n);
                    if (rc < 0) {
                        // ERR_OUT_OF_BOUNDS / ERR_BAD_ID surface as 0
                        // woken (matches spec — invalid args don't wake).
                        return 0;
                    }
                    // Single-realm waitAsync waiters parked on this
                    // same address still need a wake, but a process-
                    // level futex notify already covered them via
                    // their wait_async() path that's polling the same
                    // bytes. We additionally fire JS-side waiters for
                    // the local realm.
                    var key = _atomicsKey(view, idx);
                    var queue = _atomicsWaiters[key];
                    if (queue && queue.length > 0) {
                        var jsCount = count === Infinity ? queue.length : count;
                        var woken = 0;
                        while (woken < jsCount && queue.length > 0) {
                            var w = queue.shift();
                            if (w._timer) try { clearTimeout(w._timer); } catch (_) {}
                            if (!w._settled) { w._settled = true; w._resolve('ok'); }
                            woken++;
                        }
                        if (queue.length === 0) delete _atomicsWaiters[key];
                    }
                    return rc;
                }
                // Non-SAB path — single-realm waiter queue only.
                var key = _atomicsKey(view, idx);
                var queue = _atomicsWaiters[key];
                if (!queue || queue.length === 0) return 0;
                var n = 0;
                while (n < count && queue.length > 0) {
                    var w = queue.shift();
                    if (w._timer) {
                        try { clearTimeout(w._timer); } catch (_) {}
                    }
                    if (!w._settled) {
                        w._settled = true;
                        w._resolve('ok');
                    }
                    n++;
                }
                if (queue.length === 0) delete _atomicsWaiters[key];
                return n;
            },
            waitAsync: function(view, idx, value, timeout) {
                // Spec: if the slot already differs from `value`, return
                // synchronously with `not-equal`. Only enqueue the
                // waiter when the slot still matches.
                var actual = _ta(view)[idx];
                if (actual !== value) {
                    return { async: false, value: 'not-equal' };
                }
                var key = _atomicsKey(view, idx);
                var waiter = { _settled: false, _resolve: null, _timer: null };
                var p = new Promise(function(resolve) { waiter._resolve = resolve; });
                if (!_atomicsWaiters[key]) _atomicsWaiters[key] = [];
                _atomicsWaiters[key].push(waiter);
                if (typeof timeout === 'number' && timeout >= 0 && isFinite(timeout)) {
                    waiter._timer = setTimeout(function() {
                        if (waiter._settled) return;
                        var queue = _atomicsWaiters[key];
                        if (queue) {
                            var i = queue.indexOf(waiter);
                            if (i >= 0) queue.splice(i, 1);
                            if (queue.length === 0) delete _atomicsWaiters[key];
                        }
                        waiter._settled = true;
                        waiter._resolve('timed-out');
                    }, timeout);
                }
                return { async: true, value: p };
            },
        };

        // Per-(buffer, byte-offset) waiter queue. Keyed by the
        // underlying ArrayBuffer's identity (via WeakMap-assigned id)
        // joined with the byte offset of the view slot. Multiple
        // typed-array views over the same buffer with the same idx
        // map to the same key so a `notify(view2, idx)` wakes a
        // `waitAsync(view1, idx)` provided their offsets coincide
        // — that's exactly Atomics' wire contract.
        var _atomicsWaiters = Object.create(null);
        var _atomicsBufId = new WeakMap();
        var _atomicsNextBufId = 1;
        function _atomicsKey(view, idx) {
            var buf = view.buffer;
            var bufId = _atomicsBufId.get(buf);
            if (bufId === undefined) {
                bufId = _atomicsNextBufId++;
                _atomicsBufId.set(buf, bufId);
            }
            // Byte-offset normalises across views of different
            // element widths (Int32Array, BigInt64Array) so callers
            // synchronising via different views over the same buffer
            // see each other's waiters.
            var byteIdx = (view.byteOffset | 0) + (idx | 0) * view.BYTES_PER_ELEMENT;
            return bufId + ':' + byteIdx;
        }
    }

    // ---- Uint8Array base64 / hex (Stage 3 / Node 22+) -------------
    //
    // `arr.toBase64({alphabet?, omitPadding?})` /
    // `arr.toHex()` / `Uint8Array.fromBase64(s, opts?)` /
    // `Uint8Array.fromHex(s)`. Reuse Buffer for the actual codec
    // since Buffer is already wired through QuickJS's optimised
    // base64 path; the wrappers normalise the spec-shape options.
    if (typeof Uint8Array.prototype.toBase64 !== 'function') {
        Object.defineProperty(Uint8Array.prototype, 'toBase64', {
            value: function toBase64(options) {
                var Buf = globalThis.Buffer || require('buffer').Buffer;
                var s = Buf.from(this).toString('base64');
                var alphabet = (options && options.alphabet) || 'base64';
                if (alphabet === 'base64url') {
                    s = s.replace(/\+/g, '-').replace(/\//g, '_');
                }
                if (options && options.omitPadding) s = s.replace(/=+$/, '');
                return s;
            },
            writable: true, configurable: true,
        });
    }
    if (typeof Uint8Array.prototype.toHex !== 'function') {
        Object.defineProperty(Uint8Array.prototype, 'toHex', {
            value: function toHex() {
                var out = '';
                for (var i = 0; i < this.length; i++) {
                    var b = this[i];
                    if (b < 16) out += '0';
                    out += b.toString(16);
                }
                return out;
            },
            writable: true, configurable: true,
        });
    }
    if (typeof Uint8Array.fromBase64 !== 'function') {
        Object.defineProperty(Uint8Array, 'fromBase64', {
            value: function fromBase64(input, options) {
                var s = String(input);
                var alphabet = (options && options.alphabet) || 'base64';
                if (alphabet === 'base64url') {
                    s = s.replace(/-/g, '+').replace(/_/g, '/');
                    while (s.length % 4 !== 0) s += '=';
                }
                var Buf = globalThis.Buffer || require('buffer').Buffer;
                return new Uint8Array(Buf.from(s, 'base64'));
            },
            writable: true, configurable: true,
        });
    }
    if (typeof Uint8Array.fromHex !== 'function') {
        Object.defineProperty(Uint8Array, 'fromHex', {
            value: function fromHex(input) {
                var s = String(input);
                if (s.length % 2 !== 0) {
                    throw new SyntaxError('Uint8Array.fromHex: odd-length string');
                }
                var out = new Uint8Array(s.length / 2);
                for (var i = 0; i < out.length; i++) {
                    var hi = parseInt(s[i * 2], 16);
                    var lo = parseInt(s[i * 2 + 1], 16);
                    if (Number.isNaN(hi) || Number.isNaN(lo)) {
                        throw new SyntaxError('Uint8Array.fromHex: non-hex char');
                    }
                    out[i] = (hi << 4) | lo;
                }
                return out;
            },
            writable: true, configurable: true,
        });
    }

    // ---- Symbol.dispose / Symbol.asyncDispose (Node 20+) ------------
    // Installed FIRST because DisposableStack and AsyncDisposableStack
    // below register prototype methods keyed on these symbols. Spec
    // says they're well-known shared Symbols; idempotent if QuickJS
    // already added them.
    if (typeof Symbol.dispose === 'undefined') {
        Object.defineProperty(Symbol, 'dispose', {
            value: Symbol.for('Symbol.dispose'),
            writable: false, configurable: false, enumerable: false,
        });
    }
    if (typeof Symbol.asyncDispose === 'undefined') {
        Object.defineProperty(Symbol, 'asyncDispose', {
            value: Symbol.for('Symbol.asyncDispose'),
            writable: false, configurable: false, enumerable: false,
        });
    }

    // ---- reportError (Node 18+) -----------------------------------
    //
    // Browser/Node spec: dispatch the error as if it bubbled to the
    // global error handler. We surface it on stderr so it's visible
    // and dispatch an `error` event for any registered listeners.
    if (typeof globalThis.reportError !== 'function') {
        globalThis.reportError = function(err) {
            try {
                if (typeof globalThis.dispatchEvent === 'function'
                    && typeof globalThis.ErrorEvent === 'function') {
                    var ev = new globalThis.ErrorEvent('error', {
                        message: err && err.message ? err.message : String(err),
                        error: err,
                    });
                    globalThis.dispatchEvent(ev);
                }
            } catch (_) {}
            try {
                if (globalThis.console && typeof globalThis.console.error === 'function') {
                    globalThis.console.error(err);
                }
            } catch (_) {}
        };
    }

    // ---- scheduler API (Node 22+, Web stable since 2024) -----------
    //
    // `scheduler.wait(delay, opts)` → Promise that resolves after
    // `delay` ms (rejects if `opts.signal` aborts).
    // `scheduler.postTask(fn, opts)` → schedules a microtask-ish
    // callback and returns a Promise of its return value.
    if (typeof globalThis.scheduler !== 'object' || !globalThis.scheduler) {
        globalThis.scheduler = {
            wait: function(delay, opts) {
                var ms = delay | 0;
                var signal = opts && opts.signal;
                return new Promise(function(resolve, reject) {
                    if (signal && signal.aborted) {
                        return reject(signal.reason || new Error('Aborted'));
                    }
                    var t = setTimeout(function() { resolve(); }, ms);
                    if (signal) {
                        signal.addEventListener('abort', function() {
                            clearTimeout(t);
                            reject(signal.reason || new Error('Aborted'));
                        }, { once: true });
                    }
                });
            },
            postTask: function(fn, opts) {
                var signal = opts && opts.signal;
                if (signal && signal.aborted) {
                    return Promise.reject(signal.reason || new Error('Aborted'));
                }
                return new Promise(function(resolve, reject) {
                    queueMicrotask(function() {
                        if (signal && signal.aborted) {
                            return reject(signal.reason || new Error('Aborted'));
                        }
                        try { resolve(fn()); } catch (e) { reject(e); }
                    });
                });
            },
            yield: function() { return new Promise(function(r) { queueMicrotask(r); }); },
        };
    }

    // ---- DisposableStack / AsyncDisposableStack (Node 22+) --------
    //
    // TC39 explicit-resource-management aggregator: `using stack =
    // new DisposableStack();` then `stack.use(disposable)` registers
    // cleanups, `stack.dispose()` runs them in LIFO order.
    if (typeof globalThis.DisposableStack !== 'function') {
        function DisposableStack() {
            this._stack = [];
            this._disposed = false;
        }
        DisposableStack.prototype.use = function(value) {
            if (this._disposed) throw new ReferenceError('DisposableStack is disposed');
            if (value != null && typeof value[Symbol.dispose] === 'function') {
                this._stack.push(function() { value[Symbol.dispose](); });
            }
            return value;
        };
        DisposableStack.prototype.adopt = function(value, onDispose) {
            if (this._disposed) throw new ReferenceError('DisposableStack is disposed');
            this._stack.push(function() { onDispose(value); });
            return value;
        };
        DisposableStack.prototype.defer = function(onDispose) {
            if (this._disposed) throw new ReferenceError('DisposableStack is disposed');
            this._stack.push(onDispose);
        };
        DisposableStack.prototype.move = function() {
            if (this._disposed) throw new ReferenceError('DisposableStack is disposed');
            var fresh = new DisposableStack();
            fresh._stack = this._stack;
            this._stack = [];
            this._disposed = true;
            return fresh;
        };
        DisposableStack.prototype.dispose = function() {
            if (this._disposed) return;
            this._disposed = true;
            while (this._stack.length) {
                var fn = this._stack.pop();
                try { fn(); } catch (_) {}
            }
        };
        DisposableStack.prototype[Symbol.dispose] = DisposableStack.prototype.dispose;
        Object.defineProperty(DisposableStack.prototype, 'disposed', {
            get: function() { return this._disposed; },
        });
        globalThis.DisposableStack = DisposableStack;
    }
    if (typeof globalThis.AsyncDisposableStack !== 'function') {
        function AsyncDisposableStack() {
            this._stack = [];
            this._disposed = false;
        }
        AsyncDisposableStack.prototype.use = function(value) {
            if (this._disposed) throw new ReferenceError('AsyncDisposableStack is disposed');
            if (value != null) {
                if (typeof value[Symbol.asyncDispose] === 'function') {
                    this._stack.push(function() { return value[Symbol.asyncDispose](); });
                } else if (typeof value[Symbol.dispose] === 'function') {
                    this._stack.push(function() { return value[Symbol.dispose](); });
                }
            }
            return value;
        };
        AsyncDisposableStack.prototype.adopt = function(value, onDispose) {
            if (this._disposed) throw new ReferenceError('AsyncDisposableStack is disposed');
            this._stack.push(function() { return onDispose(value); });
            return value;
        };
        AsyncDisposableStack.prototype.defer = function(onDispose) {
            if (this._disposed) throw new ReferenceError('AsyncDisposableStack is disposed');
            this._stack.push(onDispose);
        };
        AsyncDisposableStack.prototype.move = function() {
            if (this._disposed) throw new ReferenceError('AsyncDisposableStack is disposed');
            var fresh = new AsyncDisposableStack();
            fresh._stack = this._stack;
            this._stack = [];
            this._disposed = true;
            return fresh;
        };
        AsyncDisposableStack.prototype.disposeAsync = async function() {
            if (this._disposed) return;
            this._disposed = true;
            while (this._stack.length) {
                var fn = this._stack.pop();
                try { await fn(); } catch (_) {}
            }
        };
        AsyncDisposableStack.prototype[Symbol.asyncDispose] = AsyncDisposableStack.prototype.disposeAsync;
        Object.defineProperty(AsyncDisposableStack.prototype, 'disposed', {
            get: function() { return this._disposed; },
        });
        globalThis.AsyncDisposableStack = AsyncDisposableStack;
    }

    // ---- Promise.withResolvers (Stage 4, Node 22) -------------------
    if (typeof Promise.withResolvers !== 'function') {
        Object.defineProperty(Promise, 'withResolvers', {
            value: function withResolvers() {
                var resolve, reject;
                var promise = new this(function(res, rej) { resolve = res; reject = rej; });
                return { promise: promise, resolve: resolve, reject: reject };
            },
            writable: true, configurable: true,
        });
    }

    // ---- Promise.try (Stage 3, Node 22+) ----------------------------
    // Run a sync callback, wrap return / throw into a Promise. Lets
    // callers fold sync-or-async producers into one Promise chain
    // without an extra `try / catch` ceremony.
    if (typeof Promise.try !== 'function') {
        Object.defineProperty(Promise, 'try', {
            value: function tryFn(fn /*, ...args */) {
                var args = Array.prototype.slice.call(arguments, 1);
                return new this(function(resolve) {
                    resolve(typeof fn === 'function' ? fn.apply(undefined, args) : fn);
                });
            },
            writable: true, configurable: true,
        });
    }

    // ---- Object.groupBy / Map.groupBy (ES2024) ----------------------
    if (typeof Object.groupBy !== 'function') {
        Object.defineProperty(Object, 'groupBy', {
            value: function groupBy(items, keyFn) {
                var out = Object.create(null);
                var i = 0;
                for (var it of items) {
                    var k = keyFn(it, i++);
                    var key = (typeof k === 'symbol') ? k : String(k);
                    if (!Object.prototype.hasOwnProperty.call(out, key)) out[key] = [];
                    out[key].push(it);
                }
                return out;
            },
            writable: true, configurable: true,
        });
    }
    if (typeof Map.groupBy !== 'function') {
        Object.defineProperty(Map, 'groupBy', {
            value: function groupBy(items, keyFn) {
                var out = new Map();
                var i = 0;
                for (var it of items) {
                    var k = keyFn(it, i++);
                    var arr = out.get(k);
                    if (!arr) { arr = []; out.set(k, arr); }
                    arr.push(it);
                }
                return out;
            },
            writable: true, configurable: true,
        });
    }

    // ---- Set.prototype set-theoretic methods (ES2024, Node 22) -----
    //
    // The spec is precise about argument shape: every method takes a
    // "set-like" — an object with `size`, `has`, and `keys` — *not*
    // necessarily a `Set` instance. The polyfill matches that contract
    // so the polyfill behaves like the native methods if a script
    // passes e.g. a Map or a custom collection.
    function _setLikeOf(other, name) {
        if (other == null || typeof other !== 'object' && typeof other !== 'function') {
            throw new TypeError('Set.prototype.' + name + ': argument is not set-like');
        }
        var size = other.size;
        if (typeof size !== 'number') {
            throw new TypeError('Set.prototype.' + name + ': argument is not set-like (size)');
        }
        if (typeof other.has !== 'function' || typeof other.keys !== 'function') {
            throw new TypeError('Set.prototype.' + name + ': argument is not set-like (has/keys)');
        }
        return { size: size, has: other.has.bind(other), keys: other.keys.bind(other) };
    }
    function _installSetMethod(name, impl) {
        if (typeof Set.prototype[name] === 'function') return;
        Object.defineProperty(Set.prototype, name, {
            value: impl, writable: true, configurable: true,
        });
    }
    _installSetMethod('intersection', function intersection(other) {
        var s = _setLikeOf(other, 'intersection');
        var result = new Set();
        // Iterate the smaller of (this, other) for O(min(n, m)).
        if (this.size <= s.size) {
            for (var v of this) if (s.has(v)) result.add(v);
        } else {
            var it = s.keys();
            for (var step = it.next(); !step.done; step = it.next()) {
                if (this.has(step.value)) result.add(step.value);
            }
        }
        return result;
    });
    _installSetMethod('union', function union(other) {
        var s = _setLikeOf(other, 'union');
        var result = new Set(this);
        var it = s.keys();
        for (var step = it.next(); !step.done; step = it.next()) {
            result.add(step.value);
        }
        return result;
    });
    _installSetMethod('difference', function difference(other) {
        var s = _setLikeOf(other, 'difference');
        var result = new Set();
        for (var v of this) if (!s.has(v)) result.add(v);
        return result;
    });
    _installSetMethod('symmetricDifference', function symmetricDifference(other) {
        var s = _setLikeOf(other, 'symmetricDifference');
        var result = new Set();
        for (var v of this) if (!s.has(v)) result.add(v);
        var it = s.keys();
        for (var step = it.next(); !step.done; step = it.next()) {
            if (!this.has(step.value)) result.add(step.value);
        }
        return result;
    });
    _installSetMethod('isSubsetOf', function isSubsetOf(other) {
        var s = _setLikeOf(other, 'isSubsetOf');
        if (this.size > s.size) return false;
        for (var v of this) if (!s.has(v)) return false;
        return true;
    });
    _installSetMethod('isSupersetOf', function isSupersetOf(other) {
        var s = _setLikeOf(other, 'isSupersetOf');
        if (this.size < s.size) return false;
        var it = s.keys();
        for (var step = it.next(); !step.done; step = it.next()) {
            if (!this.has(step.value)) return false;
        }
        return true;
    });
    _installSetMethod('isDisjointFrom', function isDisjointFrom(other) {
        var s = _setLikeOf(other, 'isDisjointFrom');
        if (this.size <= s.size) {
            for (var v of this) if (s.has(v)) return false;
        } else {
            var it = s.keys();
            for (var step = it.next(); !step.done; step = it.next()) {
                if (this.has(step.value)) return false;
            }
        }
        return true;
    });

    // ============================================================
    // URLPattern — WHATWG URL Pattern Standard.
    //
    // Supports the canonical shape used by routing libraries:
    //   new URLPattern({ pathname: '/users/:id' })
    //   new URLPattern('https://*.example.com/:path*')
    //   pattern.test(input) / pattern.exec(input)
    //
    // The matcher converts each component pattern into a RegExp with
    // named groups and a small wildcard grammar:
    //
    //   :name        capture (one segment, no `/`)
    //   :name(re)    capture with custom inline regex
    //   *            wildcard (zero-or-more anything)
    //   {x}          group
    //   {x}?         optional group
    //
    // Not implemented: pattern modifiers `?`/`+` after capture
    // groups (rare in practice). Real URL Pattern Standard supports
    // them — extend if a real workload surfaces.
    // ============================================================
    // ============================================================
    // WebSocket client (RFC 6455).
    //
    // Builds on top of `net.connect` / `tls.connect` so no new
    // Rust host fns are needed. Performs the HTTP/1.1 Upgrade
    // handshake (verifies `Sec-WebSocket-Accept`), then frames
    // text / binary / close / ping / pong per the spec. Client
    // → server frames are masked with a random 4-byte key.
    //
    // Surface matches WHATWG WebSocket: constructor(url[, protocols]),
    // `.send(data)` for string / ArrayBuffer / TypedArray / Blob,
    // `.close(code?, reason?)`, `readyState` (0..3),
    // `addEventListener`, on{open,message,error,close} setters,
    // `binaryType` ('blob' | 'arraybuffer'). Subprotocol negotiation
    // through the `protocols` argument; `extensions` left empty.
    // ============================================================
    if (typeof globalThis.WebSocket !== 'function') {
        var WS_CONNECTING = 0, WS_OPEN = 1, WS_CLOSING = 2, WS_CLOSED = 3;
        var WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

        function _ws_random16() {
            var arr = new Uint8Array(16);
            globalThis.crypto.getRandomValues(arr);
            return arr;
        }
        function _ws_b64(bytes) {
            // node:buffer is available in our polyfill bundle.
            var Buf = globalThis.Buffer || (require('buffer') && require('buffer').Buffer);
            return Buf.from(bytes).toString('base64');
        }
        function _ws_sha1_b64(input) {
            // SHA-1 + base64 — used to verify Sec-WebSocket-Accept.
            var nc = require('crypto');
            var h = nc.createHash('sha1');
            h.update(input);
            var hex = h.digest('hex');
            var bytes = new Uint8Array(hex.length / 2);
            for (var i = 0; i < bytes.length; i++) {
                bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
            }
            return _ws_b64(bytes);
        }
        function _ws_parseUrl(url) {
            // Reuse globalThis.URL — we just need scheme/host/port/path.
            var u = new URL(url);
            var secure = u.protocol === 'wss:' || u.protocol === 'https:';
            var port = u.port ? parseInt(u.port, 10) : (secure ? 443 : 80);
            return { secure: secure, host: u.hostname, port: port,
                     path: u.pathname + (u.search || '') };
        }

        function _ws_buildHandshake(parsed, key, protocols) {
            var lines = [
                'GET ' + parsed.path + ' HTTP/1.1',
                'Host: ' + parsed.host + (parsed.port !== (parsed.secure ? 443 : 80)
                    ? ':' + parsed.port : ''),
                'Upgrade: websocket',
                'Connection: Upgrade',
                'Sec-WebSocket-Key: ' + key,
                'Sec-WebSocket-Version: 13',
            ];
            if (protocols && protocols.length) {
                var list = Array.isArray(protocols) ? protocols : [protocols];
                lines.push('Sec-WebSocket-Protocol: ' + list.join(', '));
            }
            return lines.join('\r\n') + '\r\n\r\n';
        }

        function _ws_encodeFrame(opcode, payload) {
            // RFC 6455 §5.2. Client→server frames are masked.
            var Buf = globalThis.Buffer || require('buffer').Buffer;
            var data = (typeof payload === 'string') ? Buf.from(payload, 'utf8')
                     : Buf.isBuffer(payload) ? payload
                     : Buf.from(payload);
            var len = data.length;
            var hdr;
            var maskOffset;
            if (len < 126) {
                hdr = Buf.alloc(2 + 4);
                hdr[0] = 0x80 | (opcode & 0x0F); // FIN=1
                hdr[1] = 0x80 | len; // MASK=1, len
                maskOffset = 2;
            } else if (len < 65536) {
                hdr = Buf.alloc(4 + 4);
                hdr[0] = 0x80 | (opcode & 0x0F);
                hdr[1] = 0x80 | 126;
                hdr[2] = (len >> 8) & 0xFF;
                hdr[3] = len & 0xFF;
                maskOffset = 4;
            } else {
                hdr = Buf.alloc(10 + 4);
                hdr[0] = 0x80 | (opcode & 0x0F);
                hdr[1] = 0x80 | 127;
                // 64-bit length, big-endian. JS ints are 53-bit safe; cap
                // at 2^31-1 here. Real-world payloads above 2 GiB hit
                // memory caps anyway.
                hdr.writeUInt32BE(0, 2);
                hdr.writeUInt32BE(len, 6);
                maskOffset = 10;
            }
            var mask = new Uint8Array(4);
            globalThis.crypto.getRandomValues(mask);
            hdr[maskOffset]     = mask[0];
            hdr[maskOffset + 1] = mask[1];
            hdr[maskOffset + 2] = mask[2];
            hdr[maskOffset + 3] = mask[3];
            var masked = Buf.alloc(len);
            for (var i = 0; i < len; i++) masked[i] = data[i] ^ mask[i % 4];
            return Buf.concat([hdr, masked]);
        }

        function _ws_decodeFrames(buffer) {
            // Returns { frames: [{opcode, payload, fin}], rest: Buffer }
            // server→client frames are NOT masked.
            var frames = [];
            var p = 0;
            while (p + 2 <= buffer.length) {
                var b1 = buffer[p];
                var b2 = buffer[p + 1];
                var fin = (b1 & 0x80) !== 0;
                var opcode = b1 & 0x0F;
                var masked = (b2 & 0x80) !== 0;
                var len = b2 & 0x7F;
                var hdrLen = 2;
                if (len === 126) {
                    if (buffer.length < p + 4) break;
                    len = buffer.readUInt16BE(p + 2);
                    hdrLen = 4;
                } else if (len === 127) {
                    if (buffer.length < p + 10) break;
                    // Top 32 bits ignored — see encode comment.
                    len = buffer.readUInt32BE(p + 6);
                    hdrLen = 10;
                }
                var maskKey = null;
                if (masked) {
                    if (buffer.length < p + hdrLen + 4) break;
                    maskKey = buffer.slice(p + hdrLen, p + hdrLen + 4);
                    hdrLen += 4;
                }
                if (buffer.length < p + hdrLen + len) break;
                var payload = buffer.slice(p + hdrLen, p + hdrLen + len);
                if (masked) {
                    var unmasked = globalThis.Buffer.alloc(len);
                    for (var i = 0; i < len; i++) unmasked[i] = payload[i] ^ maskKey[i % 4];
                    payload = unmasked;
                }
                frames.push({ opcode: opcode, payload: payload, fin: fin });
                p += hdrLen + len;
            }
            return { frames: frames, rest: buffer.slice(p) };
        }

        function WebSocket(url, protocols) {
            if (!(this instanceof WebSocket)) {
                throw new TypeError('WebSocket is a constructor');
            }
            this.url = String(url);
            this.readyState = WS_CONNECTING;
            this.binaryType = 'blob';
            this.bufferedAmount = 0;
            this.extensions = '';
            this.protocol = '';
            this.onopen = null;
            this.onmessage = null;
            this.onerror = null;
            this.onclose = null;
            this._listeners = Object.create(null);
            this._handshakeBuf = globalThis.Buffer.alloc(0);
            this._frameBuf = globalThis.Buffer.alloc(0);
            this._handshakeDone = false;
            this._fragments = [];
            this._fragmentOpcode = 0;

            var parsed = _ws_parseUrl(this.url);
            var key = _ws_b64(_ws_random16());
            this._handshakeKey = key;
            this._expectedAccept = _ws_sha1_b64(key + WS_GUID);

            var connectMod = parsed.secure ? 'tls' : 'net';
            var sock;
            try {
                var mod = require(connectMod);
                sock = mod.connect({
                    host: parsed.host,
                    port: parsed.port,
                    servername: parsed.host,
                });
            } catch (e) {
                this._fireError(e);
                this._setReadyState(WS_CLOSED);
                return;
            }
            this._sock = sock;

            var self = this;
            sock.once('connect', function() {
                try {
                    sock.write(_ws_buildHandshake(parsed, key, protocols));
                } catch (e) { self._fireError(e); }
            });
            // TLS sockets fire 'secureConnect' after the TLS handshake;
            // both shapes work here because net's connect→data flow
            // matches.
            sock.once('secureConnect', function() {
                try {
                    sock.write(_ws_buildHandshake(parsed, key, protocols));
                } catch (e) { self._fireError(e); }
            });
            sock.on('data', function(chunk) {
                if (!self._handshakeDone) {
                    self._handshakeBuf = globalThis.Buffer.concat([self._handshakeBuf, chunk]);
                    var idx = self._handshakeBuf.indexOf('\r\n\r\n');
                    if (idx < 0) return;
                    var head = self._handshakeBuf.slice(0, idx).toString('utf8');
                    var rest = self._handshakeBuf.slice(idx + 4);
                    self._handshakeBuf = globalThis.Buffer.alloc(0);
                    if (!self._verifyHandshake(head)) return;
                    self._handshakeDone = true;
                    self._setReadyState(WS_OPEN);
                    self._fire('open', {});
                    if (rest.length) self._handleData(rest);
                    return;
                }
                self._handleData(chunk);
            });
            sock.on('error', function(e) {
                self._fireError(e);
                self._setReadyState(WS_CLOSED);
                self._fire('close', { code: 1006, reason: '', wasClean: false });
            });
            sock.on('close', function() {
                if (self.readyState !== WS_CLOSED) {
                    self._setReadyState(WS_CLOSED);
                    self._fire('close', { code: 1006, reason: '', wasClean: false });
                }
            });
        }
        WebSocket.CONNECTING = WS_CONNECTING;
        WebSocket.OPEN = WS_OPEN;
        WebSocket.CLOSING = WS_CLOSING;
        WebSocket.CLOSED = WS_CLOSED;
        WebSocket.prototype.CONNECTING = WS_CONNECTING;
        WebSocket.prototype.OPEN = WS_OPEN;
        WebSocket.prototype.CLOSING = WS_CLOSING;
        WebSocket.prototype.CLOSED = WS_CLOSED;

        WebSocket.prototype._setReadyState = function(s) { this.readyState = s; };
        WebSocket.prototype._fireError = function(err) {
            var e = (err && err.message) ? err : new Error(String(err || 'WebSocket error'));
            this._fire('error', { error: e, message: e.message });
        };
        WebSocket.prototype._fire = function(type, detail) {
            var ev = Object.assign({ type: type, target: this }, detail || {});
            var prop = 'on' + type;
            try { if (typeof this[prop] === 'function') this[prop](ev); } catch (_) {}
            var arr = this._listeners[type];
            if (arr) {
                for (var i = 0; i < arr.length; i++) {
                    try { arr[i](ev); } catch (_) {}
                }
            }
        };
        WebSocket.prototype._verifyHandshake = function(head) {
            var lines = head.split('\r\n');
            var status = lines[0] || '';
            if (status.indexOf(' 101 ') === -1) {
                this._fireError(new Error('WebSocket handshake failed: ' + status));
                this._setReadyState(WS_CLOSED);
                this._fire('close', { code: 1006, reason: '', wasClean: false });
                return false;
            }
            var accept = '';
            var protocol = '';
            for (var i = 1; i < lines.length; i++) {
                var c = lines[i].indexOf(':');
                if (c < 0) continue;
                var name = lines[i].slice(0, c).trim().toLowerCase();
                var value = lines[i].slice(c + 1).trim();
                if (name === 'sec-websocket-accept') accept = value;
                else if (name === 'sec-websocket-protocol') protocol = value;
            }
            if (accept !== this._expectedAccept) {
                this._fireError(new Error('WebSocket handshake: bad Sec-WebSocket-Accept'));
                this._setReadyState(WS_CLOSED);
                this._fire('close', { code: 1006, reason: '', wasClean: false });
                return false;
            }
            this.protocol = protocol;
            return true;
        };
        WebSocket.prototype._handleData = function(chunk) {
            this._frameBuf = globalThis.Buffer.concat([this._frameBuf, chunk]);
            var dec = _ws_decodeFrames(this._frameBuf);
            this._frameBuf = dec.rest;
            for (var i = 0; i < dec.frames.length; i++) this._handleFrame(dec.frames[i]);
        };
        WebSocket.prototype._handleFrame = function(frame) {
            switch (frame.opcode) {
                case 0x0: // continuation
                    this._fragments.push(frame.payload);
                    if (frame.fin) {
                        var full = globalThis.Buffer.concat(this._fragments);
                        this._fragments = [];
                        this._dispatchMessage(this._fragmentOpcode, full);
                    }
                    break;
                case 0x1: // text
                case 0x2: // binary
                    if (frame.fin) {
                        this._dispatchMessage(frame.opcode, frame.payload);
                    } else {
                        this._fragments = [frame.payload];
                        this._fragmentOpcode = frame.opcode;
                    }
                    break;
                case 0x8: // close
                    var code = frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : 1005;
                    var reason = frame.payload.length > 2
                        ? frame.payload.slice(2).toString('utf8') : '';
                    this._setReadyState(WS_CLOSING);
                    try { this._sock.write(_ws_encodeFrame(0x8, frame.payload)); } catch (_) {}
                    try { this._sock.end(); } catch (_) {}
                    this._setReadyState(WS_CLOSED);
                    this._fire('close', { code: code, reason: reason, wasClean: true });
                    break;
                case 0x9: // ping → respond with pong, same payload
                    try { this._sock.write(_ws_encodeFrame(0xA, frame.payload)); } catch (_) {}
                    break;
                case 0xA: // pong → ignore
                    break;
                default:
                    // Unknown opcode → fail the connection per spec.
                    this._fireError(new Error('WebSocket: unknown opcode ' + frame.opcode));
                    try { this._sock.end(); } catch (_) {}
                    break;
            }
        };
        WebSocket.prototype._dispatchMessage = function(opcode, payload) {
            var data;
            if (opcode === 0x1) {
                data = payload.toString('utf8');
            } else if (this.binaryType === 'arraybuffer') {
                var ab = new ArrayBuffer(payload.length);
                new Uint8Array(ab).set(payload);
                data = ab;
            } else {
                // 'blob' default — surface as Buffer (Blob exists but the
                // canonical browser shape is opaque; node's `ws` package
                // surfaces Buffer here too).
                data = payload;
            }
            this._fire('message', { data: data });
        };
        WebSocket.prototype.send = function(data) {
            if (this.readyState !== WS_OPEN) {
                throw new Error('WebSocket is not open: readyState ' + this.readyState);
            }
            var opcode = (typeof data === 'string') ? 0x1 : 0x2;
            var Buf = globalThis.Buffer;
            var payload;
            if (typeof data === 'string') {
                payload = Buf.from(data, 'utf8');
            } else if (data instanceof ArrayBuffer) {
                payload = Buf.from(new Uint8Array(data));
            } else if (ArrayBuffer.isView(data)) {
                payload = Buf.from(data.buffer, data.byteOffset, data.byteLength);
            } else if (Buf.isBuffer(data)) {
                payload = data;
            } else {
                payload = Buf.from(String(data), 'utf8');
            }
            try { this._sock.write(_ws_encodeFrame(opcode, payload)); }
            catch (e) { this._fireError(e); }
        };
        WebSocket.prototype.close = function(code, reason) {
            if (this.readyState >= WS_CLOSING) return;
            this._setReadyState(WS_CLOSING);
            var Buf = globalThis.Buffer;
            var payload = Buf.alloc(0);
            if (typeof code === 'number') {
                var rb = reason ? Buf.from(String(reason), 'utf8') : Buf.alloc(0);
                payload = Buf.alloc(2 + rb.length);
                payload.writeUInt16BE(code, 0);
                if (rb.length) rb.copy(payload, 2);
            }
            try { this._sock.write(_ws_encodeFrame(0x8, payload)); } catch (_) {}
            try { this._sock.end(); } catch (_) {}
        };
        WebSocket.prototype.addEventListener = function(type, listener) {
            if (typeof listener !== 'function') return;
            if (!this._listeners[type]) this._listeners[type] = [];
            this._listeners[type].push(listener);
        };
        WebSocket.prototype.removeEventListener = function(type, listener) {
            var arr = this._listeners[type];
            if (!arr) return;
            var idx = arr.indexOf(listener);
            if (idx >= 0) arr.splice(idx, 1);
        };
        WebSocket.prototype.dispatchEvent = function(event) {
            if (event && typeof event.type === 'string') this._fire(event.type, event);
            return true;
        };

        globalThis.WebSocket = WebSocket;
    }

    // ============================================================
    // EventSource (Server-Sent Events client).
    //
    // RFC 6202 / WHATWG. Built on `fetch`. Our fetch buffers the
    // whole response body (no streaming), so this implementation is
    // best-effort: it issues a request, parses every `data:` event
    // out of the returned body in one pass, fires `message` events,
    // and reconnects per the `retry:` directive (or 3s default).
    // Works perfectly for finite SSE responses where the server
    // sends N events then closes; longer-lived infinite streams
    // would benefit from streaming HTTP responses (separate feature).
    // ============================================================
    if (typeof globalThis.EventSource !== 'function') {
        var ES_CONNECTING = 0, ES_OPEN = 1, ES_CLOSED = 2;
        function EventSource(url, init) {
            if (!(this instanceof EventSource)) {
                throw new TypeError('EventSource is a constructor');
            }
            this.url = String(url);
            this.readyState = ES_CONNECTING;
            this.withCredentials = !!(init && init.withCredentials);
            this.onopen = null;
            this.onmessage = null;
            this.onerror = null;
            this._listeners = Object.create(null);
            this._lastEventId = '';
            this._retryMs = 3000;
            this._closed = false;
            this._connect();
        }
        EventSource.CONNECTING = ES_CONNECTING;
        EventSource.OPEN = ES_OPEN;
        EventSource.CLOSED = ES_CLOSED;
        EventSource.prototype.CONNECTING = ES_CONNECTING;
        EventSource.prototype.OPEN = ES_OPEN;
        EventSource.prototype.CLOSED = ES_CLOSED;

        EventSource.prototype._fire = function(type, detail) {
            var ev = Object.assign({ type: type, target: this }, detail || {});
            var prop = 'on' + type;
            try { if (typeof this[prop] === 'function') this[prop](ev); } catch (_) {}
            var arr = this._listeners[type];
            if (arr) for (var i = 0; i < arr.length; i++) {
                try { arr[i](ev); } catch (_) {}
            }
        };
        EventSource.prototype.addEventListener = function(type, listener) {
            if (typeof listener !== 'function') return;
            if (!this._listeners[type]) this._listeners[type] = [];
            this._listeners[type].push(listener);
        };
        EventSource.prototype.removeEventListener = function(type, listener) {
            var arr = this._listeners[type];
            if (!arr) return;
            var idx = arr.indexOf(listener);
            if (idx >= 0) arr.splice(idx, 1);
        };
        EventSource.prototype.dispatchEvent = function(event) {
            if (event && typeof event.type === 'string') this._fire(event.type, event);
            return true;
        };
        EventSource.prototype.close = function() {
            this._closed = true;
            this.readyState = ES_CLOSED;
        };

        EventSource.prototype._connect = function() {
            if (this._closed) return;
            var self = this;
            var headers = { 'Accept': 'text/event-stream' };
            if (this._lastEventId) headers['Last-Event-ID'] = this._lastEventId;
            // Use the global fetch installed at the top of the
            // bundle. Buffered body comes back as text — we parse
            // the whole stream at once.
            globalThis.fetch(this.url, { headers: headers }).then(function(resp) {
                if (self._closed) return;
                if (!resp.ok) {
                    self._fire('error', { message: 'EventSource HTTP ' + resp.status });
                    self._scheduleReconnect();
                    return;
                }
                self.readyState = ES_OPEN;
                self._fire('open', {});
                return resp.text().then(function(body) {
                    self._parse(body);
                    self._scheduleReconnect();
                });
            }).catch(function(e) {
                if (self._closed) return;
                self._fire('error', { message: e && e.message });
                self._scheduleReconnect();
            });
        };

        EventSource.prototype._scheduleReconnect = function() {
            if (this._closed) return;
            var self = this;
            this.readyState = ES_CONNECTING;
            setTimeout(function() { self._connect(); }, this._retryMs);
        };

        EventSource.prototype._parse = function(body) {
            // Split into events on blank lines (\n\n or \r\n\r\n).
            // Each event is a sequence of `field: value` lines.
            var events = String(body).split(/\r?\n\r?\n/);
            for (var i = 0; i < events.length; i++) {
                var raw = events[i];
                if (!raw) continue;
                var lines = raw.split(/\r?\n/);
                var name = 'message';
                var data = '';
                var id = null;
                for (var j = 0; j < lines.length; j++) {
                    var line = lines[j];
                    if (!line || line.charAt(0) === ':') continue;
                    var c = line.indexOf(':');
                    var field = c < 0 ? line : line.slice(0, c);
                    var value = c < 0 ? '' : line.slice(c + 1);
                    if (value.charAt(0) === ' ') value = value.slice(1);
                    if (field === 'event') name = value;
                    else if (field === 'data') data += (data ? '\n' : '') + value;
                    else if (field === 'id') id = value;
                    else if (field === 'retry') {
                        var n = parseInt(value, 10);
                        if (!isNaN(n) && n > 0) this._retryMs = n;
                    }
                }
                if (id !== null) this._lastEventId = id;
                if (data === '' && lines.length === 1 && lines[0] === '') continue;
                this._fire(name, { data: data, lastEventId: this._lastEventId, origin: this.url });
            }
        };
        globalThis.EventSource = EventSource;
    }

    if (typeof globalThis.URLPattern !== 'function') {
        var COMPONENTS = ['protocol', 'username', 'password', 'hostname', 'port',
                          'pathname', 'search', 'hash'];

        function compileURLPattern(pat, isPath) {
            // Empty pattern → match anything.
            if (pat === undefined || pat === null || pat === '') {
                return { regex: /^.*$/, names: [] };
            }
            var src = String(pat);
            var out = '^';
            var names = [];
            var i = 0;
            while (i < src.length) {
                var c = src[i];
                if (c === '\\') {
                    // Escape: copy the next char raw.
                    if (i + 1 < src.length) {
                        out += '\\' + src[i + 1];
                        i += 2;
                    } else {
                        out += '\\\\';
                        i += 1;
                    }
                    continue;
                }
                if (c === ':' && /[A-Za-z_$]/.test(src[i + 1] || '')) {
                    // Capture group `:name` or `:name(regex)`.
                    var j = i + 1;
                    while (j < src.length && /[A-Za-z0-9_$]/.test(src[j])) j++;
                    var name = src.slice(i + 1, j);
                    var re;
                    if (src[j] === '(') {
                        var depth = 1, k = j + 1;
                        while (k < src.length && depth > 0) {
                            if (src[k] === '\\') { k += 2; continue; }
                            if (src[k] === '(') depth++;
                            else if (src[k] === ')') depth--;
                            if (depth > 0) k++;
                        }
                        re = src.slice(j + 1, k);
                        j = k + 1; // past `)`
                    } else {
                        re = isPath ? '[^/]+' : '[^/]+';
                    }
                    names.push(name);
                    out += '(' + re + ')';
                    i = j;
                    continue;
                }
                if (c === '*') {
                    out += '.*';
                    i += 1;
                    continue;
                }
                // Regex metacharacters get escaped so the literal text
                // matches itself, not as a metacharacter.
                if ('.^$+?()[]{}|'.indexOf(c) !== -1) {
                    out += '\\' + c;
                } else {
                    out += c;
                }
                i += 1;
            }
            out += '$';
            return { regex: new RegExp(out), names: names };
        }

        function URLPattern(input, baseURL) {
            if (!(this instanceof URLPattern)) {
                throw new TypeError('URLPattern is a constructor');
            }
            var spec = {};
            if (typeof input === 'string') {
                // Parse as URL pattern string. Use the first absolute
                // separator to split off scheme + host + path; we
                // rely on the URL parser for the easy split, then
                // assign each piece's pattern.
                try {
                    // The URL parser doesn't accept `:name` syntax in
                    // the path — temporarily encode `:` so URL parses,
                    // then decode.
                    var encoded = input.replace(/:([A-Za-z_$][A-Za-z0-9_$]*)/g, '__AB_URLP_$1__');
                    var u = new URL(encoded, baseURL || 'http://x.invalid/');
                    var dec = function(s) { return s.replace(/__AB_URLP_([A-Za-z0-9_$]+)__/g, ':$1'); };
                    spec.protocol = dec(u.protocol.replace(/:$/, ''));
                    spec.hostname = dec(u.hostname);
                    spec.port = dec(u.port);
                    spec.pathname = dec(u.pathname);
                    spec.search = dec(u.search.replace(/^\?/, ''));
                    spec.hash = dec(u.hash.replace(/^#/, ''));
                } catch (_) {
                    spec.pathname = input;
                }
            } else if (input && typeof input === 'object') {
                for (var k = 0; k < COMPONENTS.length; k++) {
                    if (input[COMPONENTS[k]] !== undefined) {
                        spec[COMPONENTS[k]] = String(input[COMPONENTS[k]]);
                    }
                }
            } else {
                throw new TypeError('URLPattern: input must be a string or object');
            }
            this._compiled = {};
            for (var n = 0; n < COMPONENTS.length; n++) {
                var name = COMPONENTS[n];
                this._compiled[name] = compileURLPattern(spec[name], name === 'pathname');
            }
        }

        function _exec(self, input) {
            var u;
            try {
                if (typeof input === 'string') u = new URL(input);
                else if (input && typeof input === 'object') {
                    // input shape: { pathname, search, ... } or full URL
                    u = {
                        protocol: (input.protocol || '').replace(/:$/, ''),
                        username: input.username || '',
                        password: input.password || '',
                        hostname: input.hostname || '',
                        port: input.port || '',
                        pathname: input.pathname || '',
                        search: (input.search || '').replace(/^\?/, ''),
                        hash: (input.hash || '').replace(/^#/, ''),
                    };
                } else {
                    return null;
                }
            } catch (_) { return null; }

            var inputs = {
                protocol: (u.protocol || '').replace(/:$/, ''),
                username: u.username || '',
                password: u.password || '',
                hostname: u.hostname || '',
                port: u.port || '',
                pathname: u.pathname || '',
                search: (u.search || '').replace(/^\?/, ''),
                hash: (u.hash || '').replace(/^#/, ''),
            };
            var result = { inputs: [input] };
            for (var i = 0; i < COMPONENTS.length; i++) {
                var name = COMPONENTS[i];
                var c = self._compiled[name];
                var m = c.regex.exec(inputs[name]);
                if (!m) return null;
                var groups = {};
                for (var g = 0; g < c.names.length; g++) {
                    groups[c.names[g]] = m[g + 1];
                }
                result[name] = { input: inputs[name], groups: groups };
            }
            return result;
        }

        URLPattern.prototype.test = function(input) { return _exec(this, input) !== null; };
        URLPattern.prototype.exec = function(input) { return _exec(this, input); };
        // Spec accessors (return the source pattern strings). Best-
        // effort: we don't reconstruct the original `:name` form, just
        // return a compiled regex source so `console.log(p.pathname)`
        // is at least informative.
        for (var ci = 0; ci < COMPONENTS.length; ci++) {
            (function(name) {
                Object.defineProperty(URLPattern.prototype, name, {
                    get: function() { return this._compiled[name].regex.source; },
                    configurable: true,
                });
            })(COMPONENTS[ci]);
        }

        globalThis.URLPattern = URLPattern;
    }
})();
