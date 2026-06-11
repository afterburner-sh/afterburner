// The plenum.js require() resolver.
//
// Bare names and `node:*` resolve through the factory map installed
// by `__register_module` — that covers every Node stdlib module the
// plenum bundle ships. B6 extends this with:
//
//   * Filesystem resolution for `./`, `../`, `/` paths
//     (`require('./lib')`, `require('../util')`, `require('/abs')`).
//   * `node_modules` walk for bare names not in the stdlib factory
//     map (`require('express')` starts at the caller's `__dirname`
//     and walks up looking for `node_modules/express`).
//   * `package.json "main"` + `index.js` / `index.json` resolution
//     matching Node's CommonJS semantics.
//   * Per-module `require` closures so `./sibling` inside a loaded
//     file resolves relative to THAT file's dir, not the entry
//     script's — same as Node.
//   * `.json` file support: `require('./config.json')` returns the
//     parsed object, no need to JSON.parse by hand.
//   * `require.cache` keyed by absolute resolved path.
//   * `require.resolve(name)` → the absolute path that `require`
//     would load, without actually loading it.
//
// Filesystem lookups go through `__host_fs_*`; if the active
// Manifold denies fs access, filesystem-backed requires throw a
// clean EACCES naming the denied path ("permission denied reading
// '<path>' …") — distinguishable from a genuinely absent file, which
// stays the Node-shaped MODULE_NOT_FOUND. See `moduleNotFound` below
// for how the boolean `exists` probe (which collapses denied and
// absent to `false`) is disambiguated on the failure path.
//
// Resolution bases (Node-equivalent, all file-relative):
//   * Modules loaded through require() get a scoped require rooted at
//     THEIR OWN directory (`makeRequire(dirname(absPath))`), so
//     `require('./sibling')` inside a loaded file resolves next to
//     that file — never against the process CWD.
//   * The entry script's require is rooted at `dirname(argv[1])` for
//     `burn run file.js` (argv[1] is canonicalized absolute).
//   * Only `-e` / stdin eval mode (argv[1] === '[eval]') falls back
//     to the host CWD — there is no requiring file to be relative to.

(function plenumRequire() {
    var factories = Object.create(null);
    // Cache is shared across all per-module requires and keyed by the
    // resolved identifier: stdlib names (e.g. "path"), or absolute
    // filesystem paths (e.g. "/home/me/server.js").
    var cache = Object.create(null);

    function stripNodePrefix(name) {
        return typeof name === 'string' && name.indexOf('node:') === 0
            ? name.slice(5)
            : name;
    }

    function loadStdlib(mod) {
        var cached = cache[mod];
        if (cached !== undefined) return cached;
        var factory = factories[mod];
        if (typeof factory !== 'function') return undefined;
        var m = { exports: {} };
        // Install before invoking so cyclic requires see a partial
        // exports object rather than triggering an infinite loop.
        cache[mod] = m.exports;
        factory(m, m.exports, globalThis.require);
        // Factories may replace `module.exports` wholesale
        // (e.g. `module.exports = EventEmitter`). Pick up the final
        // binding before handing it out.
        cache[mod] = m.exports;
        return m.exports;
    }

    // ---- fs + path helpers (internal, do not depend on polyfills) ----------
    //
    // The require resolver can be reached before the `path` module's
    // factory has run on the first user invocation, so we inline the
    // sliver of path logic we need. Only POSIX-style separators —
    // Windows hosts normalize to forward slashes in `__host_cwd`.

    // fs host functions have two failure shapes depending on the
    // backend: the WASI path returns a string prefixed with
    // `__HOST_ERR__:`, and the native (rquickjs) path throws
    // directly. A failure that is a manifold PERMISSION DENIAL is
    // surfaced as an EACCES error naming the path — silently
    // collapsing it to "module not found" sent operators chasing
    // phantom missing files when the truth was an ungranted fs
    // capability. Every other failure (genuinely absent file,
    // I/O error) still reads as "not found" to the resolver.

    function isDenialDetail(msg) {
        return typeof msg === 'string'
            && msg.toLowerCase().indexOf('permission denied') !== -1;
    }

    function permissionDeniedError(path) {
        var e = new Error(
            "permission denied reading '" + path + "' (fs capability not " +
            "granted to the active manifold; grant fs read access, e.g. " +
            "--allow-fs=<dir> / --allow-fs-read=<dir> on the CLI)");
        e.code = 'EACCES';
        e.path = String(path);
        return e;
    }

    function fsExists(p) {
        if (vfsMap()) {
            if (vfsRead(String(p)) !== null || vfsIsDir(String(p))) return true;
            if (vfsPath(String(p))) return false; // virtual root: miss = absent
        }
        // NOTE: the boolean host probe cannot distinguish "absent"
        // from "denied" — denials are recovered on the resolution
        // failure path via `fsReadDenied` (see `moduleNotFound`).
        var fn = globalThis.__host_fs_exists_sync;
        if (typeof fn !== 'function') return false;
        try { return !!fn(String(p)); } catch (_) { return false; }
    }

    function fsRead(p) {
        if (vfsMap()) {
            var vv = vfsRead(String(p));
            if (vv !== null) return vv;
            if (vfsPath(String(p))) return null; // never ask the host for /afb/…
        }
        var fn = globalThis.__host_fs_read_file_sync;
        if (typeof fn !== 'function') return null;
        try {
            // The host bridge always sends bytes as base64 (binary-safe
            // wire format — see `polyfills/fs.js` for the full
            // contract). Decode to a UTF-8 string here; require()
            // never reads non-text files.
            var b64 = fn(String(p), 'base64');
            if (typeof b64 === 'string' && b64.indexOf('__HOST_ERR__:') === 0) {
                if (isDenialDetail(b64.slice('__HOST_ERR__:'.length))) {
                    throw permissionDeniedError(p);
                }
                return null;
            }
            // We can't `require('buffer')` from inside require.js
            // (circular bootstrap), so decode base64 inline. The
            // implementation matches `Buffer.from(b64, 'base64')` →
            // UTF-8 decode but without crossing the module boundary.
            return base64ToUtf8(b64);
        } catch (e) {
            if (e && e.code === 'EACCES') throw e;
            // Native (rquickjs) backend throws directly — recognise
            // its denial message shape too.
            if (e && isDenialDetail(e.message)) throw permissionDeniedError(p);
            return null;
        }
    }

    // One real read attempt against `p`, purely to learn whether the
    // failure is a manifold denial. Used only on the resolution
    // FAILURE path (zero extra host calls on successful requires).
    function fsReadDenied(p) {
        if (vfsPath(String(p))) return false; // vfs misses are absent, not denied
        var fn = globalThis.__host_fs_read_file_sync;
        if (typeof fn !== 'function') return false;
        try {
            var out = fn(String(p), 'base64');
            return typeof out === 'string'
                && out.indexOf('__HOST_ERR__:') === 0
                && isDenialDetail(out.slice('__HOST_ERR__:'.length));
        } catch (e) {
            return !!(e && (e.code === 'EACCES' || isDenialDetail(e.message)));
        }
    }

    // Build the resolution-failure error. The `exists` probes collapse
    // "denied" and "absent" to false, so before reporting Node's
    // MODULE_NOT_FOUND we make one real read attempt at the primary
    // candidate: a manifold denial becomes EACCES naming the path.
    // The MODULE_NOT_FOUND message carries the resolved base so a
    // failed relative require shows WHICH directory it resolved
    // against (CWD-vs-requiring-file misdiagnosis killer).
    //
    // `resolvedBase` is only passed for RELATIVE/ABSOLUTE specifiers
    // — the user named a concrete file, so "denied" vs "absent" is a
    // meaningful, actionable distinction there. Bare names (`null`
    // base) keep the plain Node-shaped message: the node_modules walk
    // spans many directories, the package may genuinely not be
    // installed, and the default-sealed embedding (UDF mode) would
    // otherwise report every missing package as a permission problem.
    function moduleNotFound(name, resolvedBase) {
        if (resolvedBase && fsReadDenied(resolvedBase)) {
            return permissionDeniedError(resolvedBase);
        }
        var e = new Error("Cannot find module '" + name + "'"
            + (resolvedBase && resolvedBase !== name
                ? " (resolved against '" + resolvedBase + "')"
                : ''));
        e.code = 'MODULE_NOT_FOUND';
        return e;
    }

    // Tiny inlined base64→UTF-8 decoder. Used only by the require
    // resolver's source loader; cleaner than calling out to
    // `Buffer` (which lives in a module we may be in the middle of
    // bootstrapping). globalThis.atob produces a "binary string"
    // (each char = one byte, ≤255), then we re-decode as UTF-8.
    var B64_INV = (function() {
        var alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        var inv = new Int16Array(256);
        for (var i = 0; i < 256; i++) inv[i] = -1;
        for (var j = 0; j < alphabet.length; j++) inv[alphabet.charCodeAt(j)] = j;
        return inv;
    })();

    function base64ToUtf8(s) {
        // Strip padding for length math.
        var clean = s.replace(/=+$/, '');
        var bytesLen = Math.floor(clean.length * 3 / 4);
        var bytes = new Uint8Array(bytesLen);
        var bi = 0;
        for (var i = 0; i + 4 <= clean.length; i += 4) {
            var n = (B64_INV[clean.charCodeAt(i)]   << 18) |
                    (B64_INV[clean.charCodeAt(i+1)] << 12) |
                    (B64_INV[clean.charCodeAt(i+2)] << 6)  |
                    (B64_INV[clean.charCodeAt(i+3)]);
            bytes[bi++] = (n >> 16) & 0xff;
            bytes[bi++] = (n >> 8)  & 0xff;
            bytes[bi++] = n & 0xff;
        }
        var rem = clean.length - i;
        if (rem === 2) {
            var n2 = (B64_INV[clean.charCodeAt(i)]   << 18) |
                     (B64_INV[clean.charCodeAt(i+1)] << 12);
            bytes[bi++] = (n2 >> 16) & 0xff;
        } else if (rem === 3) {
            var n3 = (B64_INV[clean.charCodeAt(i)]   << 18) |
                     (B64_INV[clean.charCodeAt(i+1)] << 12) |
                     (B64_INV[clean.charCodeAt(i+2)] << 6);
            bytes[bi++] = (n3 >> 16) & 0xff;
            bytes[bi++] = (n3 >> 8)  & 0xff;
        }
        if (typeof TextDecoder === 'function') {
            return new TextDecoder('utf-8').decode(bytes.subarray(0, bi));
        }
        // Fallback — correct for ASCII; user source under burn is JS
        // which is overwhelmingly ASCII / latin-1 friendly. Non-ASCII
        // identifiers would require the TextDecoder path above
        // (always present in QuickJS post-Phase E).
        var out = '';
        for (var k = 0; k < bi; k++) out += String.fromCharCode(bytes[k]);
        return out;
    }

    function fsIsDir(p) {
        if (vfsMap()) {
            if (vfsIsDir(String(p))) return true;
            if (vfsPath(String(p))) return false;
        }
        var fn = globalThis.__host_fs_stat_sync;
        if (typeof fn !== 'function') return false;
        try {
            var raw = fn(String(p));
            if (typeof raw !== 'string' || raw.indexOf('__HOST_ERR__:') === 0) return false;
            return JSON.parse(raw).isDirectory === true;
        } catch (_) {
            return false;
        }
    }

    // ---- virtual package filesystem -----------------------------
    //
    // A composed .afb module (multi-file package, vendored
    // node_modules, digest-pinned dependency packages) delivers its
    // whole file tree as DATA inside the compiled source:
    //   globalThis.__afb_files = { '/afb/source/main.js': '…', … }
    //   globalThis.__afb_links = { 'ns/name': '/afb/deps/ns/name/source/main.js' }
    // The probes below consult that map FIRST, so the entire Node
    // resolution algorithm (exports maps, extension ladder, caching,
    // circular semantics) runs unchanged over virtual paths — and a
    // '/afb/…' path NEVER reaches the host fs bridge: a vfs miss is
    // "absent", not a manifold question. Real-fs behavior (and its
    // manifold gating) is byte-for-byte unchanged for every other
    // path; network access from vendored code is not touched by any
    // of this — it still goes through the host net gates.
    var vfsDirCache = null;
    function vfsMap() {
        var m = globalThis.__afb_files;
        return (m && typeof m === 'object') ? m : null;
    }
    function vfsPath(p) {
        return typeof p === 'string' && p.indexOf('/afb/') === 0;
    }
    function vfsRead(p) {
        var m = vfsMap();
        if (!m) return null;
        var v = m[p];
        return typeof v === 'string' ? v : null;
    }
    function vfsIsDir(p) {
        var m = vfsMap();
        if (!m) return false;
        if (vfsDirCache === null) {
            // Built once per instance: every ancestor dir of every
            // virtual file. Keeps the node_modules walk O(1) per
            // probe even for thousand-file vendored packages.
            vfsDirCache = {};
            for (var k in m) {
                var d = dirname(k);
                while (d && d !== '/' && !vfsDirCache[d]) {
                    vfsDirCache[d] = true;
                    d = dirname(d);
                }
            }
        }
        var key = p.charAt(p.length - 1) === '/' ? p.slice(0, -1) : p;
        return vfsDirCache[key] === true;
    }

    function dirname(p) {
        if (!p || p === '/') return '/';
        var trimmed = p.charAt(p.length - 1) === '/' ? p.slice(0, -1) : p;
        var i = trimmed.lastIndexOf('/');
        if (i < 0) return '.';
        if (i === 0) return '/';
        return trimmed.slice(0, i);
    }

    function normalize(p) {
        var absolute = p.charAt(0) === '/';
        var parts = p.split('/');
        var out = [];
        for (var i = 0; i < parts.length; i++) {
            var seg = parts[i];
            if (seg === '' || seg === '.') continue;
            if (seg === '..') {
                if (out.length > 0 && out[out.length - 1] !== '..') {
                    out.pop();
                } else if (!absolute) {
                    out.push('..');
                }
            } else {
                out.push(seg);
            }
        }
        var joined = out.join('/');
        return absolute ? '/' + joined : (joined || '.');
    }

    function resolveJoin(base, rel) {
        if (rel.charAt(0) === '/') return normalize(rel);
        return normalize(base + '/' + rel);
    }

    function isRelativeOrAbsolute(name) {
        if (typeof name !== 'string' || name.length === 0) return false;
        var c0 = name.charAt(0);
        if (c0 === '/') return true;
        if (c0 !== '.') return false;
        var c1 = name.charAt(1);
        return c1 === '/' || (c1 === '.' && name.charAt(2) === '/') || name.length === 1 || name === '..';
    }

    // Given a candidate absolute path, try the Node CJS resolution
    // ladder. Extensions tried (in order): exact, .js, .json, .mjs,
    // .cjs, .ts, .mts, .cts. TS/ESM extensions are opt-in — the
    // loader asks the host to transpile them before running. If the
    // host has no transpile hook (built without `ts`), loading a
    // .ts/.mjs surfaces a clean error instead of a JS parse failure.
    var EXTENSION_LADDER = ['.js', '.json', '.mjs', '.cjs', '.ts', '.mts', '.cts'];

    function resolveCandidate(candidate) {
        if (fsExists(candidate) && !fsIsDir(candidate)) return candidate;
        for (var i = 0; i < EXTENSION_LADDER.length; i++) {
            var p = candidate + EXTENSION_LADDER[i];
            if (fsExists(p)) return p;
        }
        if (fsIsDir(candidate)) {
            var pkg = candidate + '/package.json';
            if (fsExists(pkg)) {
                var data = fsRead(pkg);
                if (typeof data === 'string') {
                    try {
                        var parsed = JSON.parse(data);
                        var main = parsed && typeof parsed.main === 'string' ? parsed.main : null;
                        if (main) {
                            var mainAbs = resolveJoin(candidate, main);
                            var resolved = resolveCandidate(mainAbs);
                            if (resolved) return resolved;
                        }
                    } catch (_) { /* malformed package.json falls through to index */ }
                }
            }
            // Directory fallback — match the extension order above.
            for (var j = 0; j < EXTENSION_LADDER.length; j++) {
                var idx = candidate + '/index' + EXTENSION_LADDER[j];
                if (fsExists(idx)) return idx;
            }
        }
        return null;
    }

    // Transpile if the extension or contents need it. TS / `.mts` /
    // `.mjs` always go through the host transpile hook. Plain `.js`
    // files are scanned for ESM syntax — if found, they are routed
    // through the same hook so `import` / `export` lower to
    // CommonJS. ESM-only npm packages (chalk, ora, etc., which set
    // `"type": "module"` and ship .js files) reach us via this
    // path; without it `require('chalk')` would parse-fail at
    // `import` keywords. The fast string-scan keeps plain CJS
    // modules off the oxc parse path.
    function maybeTranspile(source, absPath) {
        var lower = absPath.toLowerCase();
        var explicit = lower.slice(-3) === '.ts'
                    || lower.slice(-4) === '.mts'
                    || lower.slice(-4) === '.cts'
                    || lower.slice(-4) === '.mjs';
        var needs = explicit;
        if (!needs && (lower.slice(-3) === '.js' || lower.slice(-4) === '.cjs')) {
            // Cheap pre-check: top-of-line `import …` / `export …` /
            // `import.meta` are the markers that warrant a real
            // lowering pass. Mid-line `import` (in strings, comments,
            // member access) is fine — oxc would no-op those — but we
            // skip the parse to keep CJS imports cheap.
            needs = /(^|\n)\s*(import\s|import\(|export\s|export\{)/.test(source)
                 || source.indexOf('import.meta') >= 0;
        }
        if (!needs) return source;
        var fn = globalThis.__host_ts_transpile;
        if (typeof fn !== 'function') {
            // Only TS files hard-require the hook. `.js` callers fall
            // back to the unmodified source and let the CJS parser
            // surface its own error if it actually contained ESM —
            // matches the no-`ts`-feature flow on the CLI side.
            if (!explicit) return source;
            var e = new Error("Loading '" + absPath + "' requires the `ts` cargo feature");
            e.code = 'ERR_UNSUPPORTED_EXTENSION';
            throw e;
        }
        var out = fn(source, absPath);
        if (typeof out === 'string' && out.indexOf('__HOST_ERR__:') === 0) {
            var err = new Error("Transpile failed for '" + absPath + "': " + out.slice('__HOST_ERR__:'.length));
            err.code = 'ERR_TRANSPILE_FAILED';
            throw err;
        }
        return out;
    }

    // Subpath imports (`#name`) — Node's mechanism for a package to
    // reference its own internal modules without exposing them to
    // consumers. We walk up from `fromDir` for the nearest
    // `package.json`, look up its `imports` field, and resolve the
    // matched entry relative to that package's root. Conditional
    // exports collapse to `node` → `default` (we don't support
    // `import` vs `require` discrimination since we have a single
    // require-shaped resolver). Returns the absolute path or null.
    function resolveSubpathImport(name, fromDir) {
        var dir = fromDir;
        if (typeof dir !== 'string' || dir.length === 0) dir = '/';
        for (var i = 0; i < 64; i++) {
            var pkgPath = dir + '/package.json';
            if (fsExists(pkgPath)) {
                var raw = fsRead(pkgPath);
                if (typeof raw === 'string') {
                    var pkg;
                    try { pkg = JSON.parse(raw); } catch (_) { pkg = null; }
                    if (pkg && pkg.imports && typeof pkg.imports === 'object') {
                        var entry = pkg.imports[name];
                        if (entry === undefined) {
                            // Pattern subpath imports like
                            // `#feature/*` would land here in Node.
                            // We don't support patterns yet — fall
                            // through to upper package.json.
                        } else {
                            var relative = pickConditional(entry);
                            if (typeof relative === 'string') {
                                var abs = resolveJoin(dir, relative);
                                var r = resolveCandidate(abs);
                                if (r) return r;
                            }
                        }
                    }
                }
            }
            var parent = dirname(dir);
            if (parent === dir) break;
            dir = parent;
        }
        return null;
    }

    // Conditional-exports resolver: pick `node` then `default` then
    // the first string entry. Strings are returned as-is.
    function pickConditional(entry) {
        if (typeof entry === 'string') return entry;
        if (!entry || typeof entry !== 'object') return null;
        // CJS-lens condition priority. `require`/`node` MUST win over
        // `import`: dual-build packages (e.g. glob → import:esm,
        // require:commonjs) ship a CommonJS build our `require()` can
        // load directly, whereas the `import` build is ESM that often
        // won't parse as-is. Crucially we resolve by this fixed
        // priority rather than package.json key order — otherwise a
        // package that lists `import` before `require` (glob does)
        // would pick the ESM build. `import` is the last resort (it
        // would need transpiling). Each condition may be a string or a
        // nested condition object, so recurse.
        var order = ['node', 'require', 'default', 'import'];
        for (var i = 0; i < order.length; i++) {
            var v = entry[order[i]];
            if (typeof v === 'string') return v;
            if (v && typeof v === 'object') {
                var nested = pickConditional(v);
                if (nested) return nested;
            }
        }
        // Custom/unknown conditions as a last resort — but never
        // `types` (a `.d.ts` pointer, not a runtime target).
        for (var k in entry) {
            if (k === 'types' || order.indexOf(k) !== -1) continue;
            if (typeof entry[k] === 'string') return entry[k];
            if (entry[k] && typeof entry[k] === 'object') {
                var n2 = pickConditional(entry[k]);
                if (n2) return n2;
            }
        }
        return null;
    }

    // Split a bare specifier into the package name and an optional
    // subpath. Scoped packages (`@scope/name/sub`) keep the first two
    // segments as the package name.
    function splitPackageSpecifier(name) {
        if (name.charAt(0) === '@') {
            var parts = name.split('/');
            return { pkg: parts.slice(0, 2).join('/'), sub: parts.slice(2).join('/') };
        }
        var idx = name.indexOf('/');
        if (idx === -1) return { pkg: name, sub: '' };
        return { pkg: name.slice(0, idx), sub: name.slice(idx + 1) };
    }

    // Pattern-subpath exports: `"./foo/*": "./dist/foo/*.js"`. Match
    // `key` against the `*`-bearing export keys and substitute the
    // captured segment into the (conditional-resolved) target.
    function matchExportsPattern(exp, key) {
        for (var pat in exp) {
            var star = pat.indexOf('*');
            if (star === -1) continue;
            var prefix = pat.slice(0, star);
            var suffix = pat.slice(star + 1);
            if (key.length >= prefix.length + suffix.length
                && key.slice(0, prefix.length) === prefix
                && (suffix === '' || key.slice(key.length - suffix.length) === suffix)) {
                var mid = key.slice(prefix.length, key.length - suffix.length);
                var tgt = pickConditional(exp[pat]);
                if (typeof tgt === 'string') return tgt.split('*').join(mid);
            }
        }
        return null;
    }

    // Resolve a package + subpath through the package.json `exports`
    // field — the modern, authoritative map and the ONLY way to reach
    // subpath exports like `@scope/pkg/sub` whose target lives where
    // `main`/index can't see (e.g. `@sigstore/protobuf-specs/rekor/v2`
    // → `./dist/rekor/v2/index.js`). Returns an absolute path or null
    // (null falls back to legacy main/index resolution).
    function resolveViaExports(pkgRoot, sub) {
        var pkgJson = pkgRoot + '/package.json';
        if (!fsExists(pkgJson)) return null;
        var raw = fsRead(pkgJson);
        if (typeof raw !== 'string') return null;
        var pkg;
        try { pkg = JSON.parse(raw); } catch (_) { return null; }
        if (!pkg || pkg.exports === undefined || pkg.exports === null) return null;
        var exp = pkg.exports;
        var key = sub ? ('./' + sub) : '.';
        var target = null;
        if (typeof exp === 'string') {
            // String shorthand describes the `.` entry only.
            if (key === '.') target = exp;
        } else if (typeof exp === 'object') {
            // If no key looks like a subpath (`.`/`./…`), the object is
            // a bare condition map for `.` (e.g. `{ require, import }`).
            var hasSubpathKeys = false;
            for (var k in exp) {
                if (k === '.' || k.charAt(0) === '.') { hasSubpathKeys = true; break; }
            }
            if (!hasSubpathKeys) {
                if (key === '.') target = pickConditional(exp);
            } else if (Object.prototype.hasOwnProperty.call(exp, key)) {
                target = pickConditional(exp[key]);
            } else {
                target = matchExportsPattern(exp, key);
            }
        }
        if (typeof target !== 'string') return null;
        var abs = resolveJoin(pkgRoot, target);
        return resolveCandidate(abs) || (fsExists(abs) && !fsIsDir(abs) ? abs : null);
    }

    // Walk up `fromDir` looking for `node_modules/<pkg>`. Consults the
    // package's `exports` map first (authoritative for subpaths), then
    // falls back to legacy main/index + filesystem-join resolution.
    // Returns the absolute resolved file path, or null.
    function resolvePackage(name, fromDir) {
        var dir = fromDir;
        // Guard against pathological inputs (empty dir, etc.).
        if (typeof dir !== 'string' || dir.length === 0) dir = '/';
        var spec = splitPackageSpecifier(name);
        // Safety bound: 64 parent walks is far more than any real tree.
        for (var i = 0; i < 64; i++) {
            var pkgRoot = dir + '/node_modules/' + spec.pkg;
            if (fsIsDir(pkgRoot)) {
                var viaExports = resolveViaExports(pkgRoot, spec.sub);
                if (viaExports) return viaExports;
                // Legacy: bare name → main/index; subpath → join onto
                // the package root and resolve (covers packages with no
                // `exports` and deep imports they still permit).
                var cand = spec.sub ? (pkgRoot + '/' + spec.sub) : pkgRoot;
                var r = resolveCandidate(cand);
                if (r) return r;
            }
            var parent = dirname(dir);
            if (parent === dir) break;
            dir = parent;
        }
        return null;
    }

    // Cache stores `module` records, not bare `module.exports`. This
    // mirrors Node's `require.cache` shape (`{ [path]: Module }` —
    // `Module.exports` resolved at read-time) and is the ONLY way
    // circular requires work correctly: when `a.js` partially loads
    // and requires `b.js`, which requires `a.js` back, `b.js` must
    // see the LATEST `a.js` exports object — including any
    // `module.exports = NewClass` reassignment that happened between
    // the cache install and the cycle re-entry. Caching the bare
    // `module.exports` snapshot misses every such reassignment and
    // hands cycles a stale empty object, which surfaces in user code
    // as `parent class must be constructor` or
    // `Cannot read property 'X' of undefined`.
    function getCached(path) {
        var rec = cache[path];
        if (rec === undefined) return undefined;
        // JSON modules are cached as the parsed value directly; only
        // module records have an `exports` property + `loaded` flag.
        if (rec && typeof rec === 'object' && Object.prototype.hasOwnProperty.call(rec, 'exports')
            && Object.prototype.hasOwnProperty.call(rec, 'filename')) {
            return rec.exports;
        }
        return rec;
    }

    function loadAbsoluteFile(absPath, scopedRequire) {
        var cached = getCached(absPath);
        if (cached !== undefined) return cached;
        // A manifold denial throws EACCES from fsRead directly; a
        // null here means the file vanished between the exists probe
        // and the read (or an I/O error) — report it as not found.
        var source = fsRead(absPath);
        if (source === null) {
            throw moduleNotFound(absPath, absPath);
        }
        if (absPath.slice(-5) === '.json') {
            var parsed = JSON.parse(source);
            cache[absPath] = parsed;
            return parsed;
        }
        // B8/B9: .ts/.mts/.cts/.mjs files go through the host's
        // oxc-based transpiler before landing in the CJS wrapper.
        // Plain .js / .cjs pass through untouched.
        source = maybeTranspile(source, absPath);
        // Node strips a leading hashbang before handing source to V8;
        // QuickJS rejects `#!`. Replace with `//` so line numbers
        // stay aligned with the on-disk file. Also drops a UTF-8 BOM
        // if one is present (which would otherwise reach the Function
        // constructor and parse-fail the same way).
        if (source.charCodeAt(0) === 0xFEFF) {
            source = source.slice(1);
        }
        if (source.charCodeAt(0) === 0x23 /* # */ &&
            source.charCodeAt(1) === 0x21 /* ! */) {
            source = '//' + source.slice(2);
        }
        // Dynamic `import(spec)` has no module loader registered in
        // QuickJS, so the bare expression throws "could not load
        // module 'X'" the moment it runs. Rewrite to a require-based
        // shim BEFORE the source reaches the Function constructor.
        // This keeps the npm / corepack / yarn dispatch chain
        // (which uses `await import('chalk')`) functional under our
        // CJS-shaped require resolver. The shim resolves to a
        // namespace-shaped object (matches Node's CJS-from-ESM
        // interop). The pattern is conservative — only `import(`
        // followed by a non-`.` (excludes `import.meta` /
        // `imports.foo`) and not preceded by an identifier char
        // (excludes `aimport(`). Strings/comments containing
        // `import(` are a known false-positive but vanishingly rare
        // in distributed npm packages.
        if (source.indexOf('import(') >= 0 || source.indexOf('import (') >= 0) {
            // Capture the closure-scoped `require` as the FIRST arg so
            // the import resolves relative to *this* file's dir, not
            // the entry script's. Async dynamic imports inside class
            // methods would otherwise lose the active-require frame
            // by the time they fire.
            source = source.replace(
                /([^A-Za-z0-9_$]|^)import(\s*)\(/g,
                '$1globalThis.__ab_dyn_import$2(require,'
            );
        }
        // Node CJS wrapper — `module.exports` / `exports` are the
        // user-visible outputs; `require` is the scoped copy; the two
        // `__filename` / `__dirname` bindings match Node.
        var modObj = { exports: {}, filename: absPath, loaded: false };
        var dir = dirname(absPath);
        // Compile first so a parse error can name the module. QuickJS
        // SyntaxErrors carry no source context; without the path, a
        // failed dependency surfaces as a bare "Unexpected token …"
        // with no hint which file is at fault.
        var fn;
        try {
            fn = new Function(
                'module', 'exports', 'require', '__filename', '__dirname',
                source
            );
        } catch (compileErr) {
            if (compileErr && typeof compileErr.message === 'string'
                && compileErr.message.indexOf(absPath) === -1) {
                compileErr.message += ' (while compiling ' + absPath + ')';
            }
            throw compileErr;
        }
        // Install the MODULE record (not the exports snapshot) before
        // invoking the user body. Cycles look up `cache[absPath]` and
        // pull `.exports` at access time — so any
        // `module.exports = NewClass` reassignment inside the user
        // body is visible to a re-entrant require immediately.
        cache[absPath] = modObj;
        // Stash the current scoped require before running the user body
        // so dynamic `import(...)` (rewritten to `__ab_dyn_import`)
        // walks `node_modules` from the importing file's dir. JS is
        // single-threaded so the save/restore is race-free; nested
        // requires nest their saves naturally.
        var prevActive = globalThis.__ab_active_require;
        globalThis.__ab_active_require = scopedRequire;
        try {
            fn(modObj, modObj.exports, scopedRequire, absPath, dir);
        } catch (e) {
            // Broken module — evict so a retry can re-run the factory
            // cleanly.
            delete cache[absPath];
            throw e;
        } finally {
            globalThis.__ab_active_require = prevActive;
        }
        modObj.loaded = true;
        return modObj.exports;
    }

    // Construct a `require` closure scoped to `fromDir`. This is what
    // user modules see as their local `require` — `./sibling` resolves
    // relative to `fromDir`, bare names resolve via stdlib then
    // `fromDir`-rooted `node_modules` walk.
    function makeRequire(fromDir) {
        function resolveOnly(name) {
            if (typeof name !== 'string') {
                throw new TypeError('require.resolve(name) expects a string');
            }
            var stripped = stripNodePrefix(name);
            // Pre-registered modules return their registration name
            // as the "resolved identifier" — no path materializes.
            if (factories[stripped] || cache[stripped] !== undefined) {
                return stripped;
            }
            if (isRelativeOrAbsolute(name)) {
                var base = name.charAt(0) === '/' ? name : resolveJoin(fromDir, name);
                var r = resolveCandidate(base);
                if (!r) throw moduleNotFound(name, base);
                return r;
            }
            var pkg = resolvePackage(name, fromDir);
            if (pkg) return pkg;
            throw moduleNotFound(name, null);
        }

        function req(name) {
            if (typeof name !== 'string') {
                throw new TypeError('require(name) expects a string');
            }
            // Pre-registered modules always win, regardless of name
            // shape. This matters for programmatic registration (e.g.
            // FlowEngine::load_bundle) that uses literal names like
            // './util' to key helper modules into the factory map —
            // those should short-circuit the filesystem lookup.
            var preregistered = loadStdlib(stripNodePrefix(name));
            if (preregistered !== undefined) return preregistered;

            // Subpath imports (`#name`) — Node looks up the closest
            // package.json's `imports` field and resolves the matched
            // entry relative to that package root. ESM-only npm
            // packages (chalk, ora) ship internal deps like
            // `#ansi-styles` via this mechanism.
            if (name.charAt(0) === '#') {
                var resolvedSubpath = resolveSubpathImport(name, fromDir);
                if (resolvedSubpath) {
                    return loadAbsoluteFile(resolvedSubpath, makeRequire(dirname(resolvedSubpath)));
                }
                var eImp = new Error("Cannot find module '" + name + "'");
                eImp.code = 'ERR_PACKAGE_IMPORT_NOT_DEFINED';
                throw eImp;
            }

            if (isRelativeOrAbsolute(name)) {
                var base = name.charAt(0) === '/' ? name : resolveJoin(fromDir, name);
                var r = resolveCandidate(base);
                if (!r) throw moduleNotFound(name, base);
                return loadAbsoluteFile(r, makeRequire(dirname(r)));
            }
            // Linked dependency packages (__afb_links): a composed
            // .afb maps each digest-pinned dependency coordinate to
            // that dependency's entry inside the virtual tree. Exact
            // names only — the dep's entry IS its API surface.
            var links = globalThis.__afb_links;
            if (links && typeof links === 'object' && typeof links[name] === 'string') {
                var linked = links[name];
                return loadAbsoluteFile(linked, makeRequire(dirname(linked)));
            }
            // Bare name — fall through to `node_modules` walk.
            var pkg = resolvePackage(name, fromDir);
            if (pkg) return loadAbsoluteFile(pkg, makeRequire(dirname(pkg)));
            throw moduleNotFound(name, null);
        }

        req.cache = cache;
        req.resolve = resolveOnly;
        return req;
    }

    function entryDir() {
        // For file-mode invocations (`burn run foo.js`), argv[1] is
        // the canonicalized absolute script path — its dirname is the
        // entry module's `__dirname`, matching Node's semantics where
        // `require('./sibling')` in the entry script resolves next to
        // the entry file, NOT next to the shell's cwd.
        var argv = globalThis.__ab_argv;
        if (argv && typeof argv[1] === 'string') {
            var label = argv[1];
            if (label.length > 0 && label.charAt(0) === '/'
                && label !== '[eval]' && label !== '[test]') {
                return dirname(label);
            }
        }
        // Eval mode (`-e CODE`, argv[1] = '[eval]') has no file of
        // its own, so we fall back to the shell's cwd — matches what
        // the user would expect when they type `burn -e 'require("./x")'`
        // in a project dir.
        var cwd = globalThis.__host_cwd;
        if (typeof cwd === 'string' && cwd.length > 0) return cwd;
        return '/';
    }

    // The entry-point require. Re-computed on each access so per-
    // invocation `__host_cwd` / `__ab_argv` updates are picked up
    // without a global reset.
    function installEntryRequire() {
        var req = makeRequire(entryDir());
        // Expose the factory-map registration helpers on the entry
        // require for debugging / tests.
        req.__plenum_modules_installed = function() {
            return Object.keys(factories).concat(Object.keys(cache));
        };
        // Node's `require.main` — descriptor for the script that
        // launched the process. For `burn run foo.js` it points at
        // foo.js; for `-e` and stdin modes it points at the
        // synthetic [eval] entry. The fields match Node's
        // Module-instance shape (id, filename, exports, paths,
        // children) closely enough for the canonical idiom
        // `require.main === module` to work in burn.
        var argv = globalThis.__ab_argv;
        var entry = (argv && typeof argv[1] === 'string') ? argv[1] : '[eval]';
        req.main = {
            id: entry,
            filename: entry,
            exports: {},
            loaded: false,
            paths: [entryDir()],
            children: [],
        };
        globalThis.require = req;
    }

    installEntryRequire();

    globalThis.__register_module = function(name, factory) {
        factories[stripNodePrefix(name)] = factory;
    };

    globalThis.__register_host_module = function(name, obj) {
        cache[stripNodePrefix(name)] = obj;
    };

    globalThis.__plenum_modules_installed = function() {
        return Object.keys(factories).concat(Object.keys(cache));
    };

    // Per-invocation hook: when the host updates `__host_cwd` via the
    // script envelope, the entry-point `require` should rebase its
    // starting dir. Called from the plugin's script/daemon-init
    // wrappers immediately after they set `__host_cwd`.
    globalThis.__plenum_refresh_entry_require = installEntryRequire;

    // File-relative require for `module.createRequire(filename)`:
    // resolve `id` exactly as a module living at `base` would —
    // relative specifiers and the node_modules walk start at
    // dirname(base), not at the entry script's dir.
    globalThis.__plenum_require_from = function(id, base) {
        return makeRequire(dirname(String(base)))(id);
    };

    // Dynamic-import shim. QuickJS has no registered module loader,
    // so bare `import('foo')` throws "could not load module" the
    // moment it runs — that breaks every npm-side dispatcher (npm
    // imports `chalk` / `supports-color`; corepack imports the proxy
    // agent; pnpm imports its own engine). At source-rewrite time
    // we replace `import(` with `globalThis.__ab_dyn_import(`; this
    // function returns a Promise resolving to the module's
    // namespace-shaped object, matching Node's CJS-from-ESM interop:
    // CJS modules whose `module.exports` is an object are returned
    // as-is; anything else is wrapped under `default`.
    globalThis.__ab_dyn_import = function(reqOrSpec, maybeSpec) {
        // Two-arg shape: rewriter passes `(require, spec)` so the
        // import resolves relative to the importing file's dir.
        // One-arg shape: entry-script eval / CLI code that's outside
        // a CJS wrapper — fall back to the entry require.
        var r;
        var spec;
        if (typeof maybeSpec !== 'undefined' && typeof reqOrSpec === 'function') {
            r = reqOrSpec;
            spec = maybeSpec;
        } else {
            r = globalThis.require;
            spec = reqOrSpec;
        }
        try {
            var mod = r(spec);
            // Already namespace-shaped (ESM-lowered files include
            // `__esModule: true` + named keys, plus `default`).
            if (mod && typeof mod === 'object' && mod.__esModule) {
                return Promise.resolve(mod);
            }
            // CJS fallback: synthesise a namespace with `default` set
            // to the require result. Spread the object's enumerable
            // keys so `import('cjs').namedExport` still works when
            // the CJS module exports a plain object.
            var ns = { default: mod };
            if (mod && typeof mod === 'object') {
                for (var k in mod) {
                    if (k === 'default') continue;
                    ns[k] = mod[k];
                }
            }
            return Promise.resolve(ns);
        } catch (e) {
            return Promise.reject(e);
        }
    };
})();
