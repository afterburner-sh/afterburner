// fs — thin glue over the __host_fs_* globals installed by the engine.
// Every method throws if the host global isn't present (meaning the
// engine didn't wire fs, usually because Manifold::fs == None).
//
// The WASM plugin signals host-side errors by returning a string that
// starts with "__HOST_ERR__:" — we check for that prefix and rethrow.

__register_module('fs', function(module, exports, require) {

    function requireHost(name) {
        var fn = globalThis['__host_fs_' + name];
        if (typeof fn !== 'function') {
            var err = new Error("Permission denied: fs." + name + " is not available");
            err.code = 'EACCES';
            throw err;
        }
        return fn;
    }

    // Map a host error message to the Node.js errno `code`. The host
    // surfaces raw `std::io::Error` text, which carries BOTH a human
    // phrase ("No such file or directory") and an "(os error N)"
    // suffix; we match either form. Getting `code` right is load-
    // bearing: cacache (npm's content-addressable cache) treats a
    // missing content file as a cache MISS only when
    // `err.code === 'ENOENT'` — otherwise it rethrows the failed
    // `stat` as fatal and the entire `npm install` aborts on a cold
    // cache. tar/mkdirp similarly branch on 'EEXIST'/'ENOTDIR'/etc.
    // The "(os error N)" forms are matched WITH their parens so that
    // "(os error 2)" can't accidentally match "(os error 20/21)".
    function hostErrCode(lower) {
        if (lower.indexOf('permission denied') !== -1 || lower.indexOf('(os error 13)') !== -1) return 'EACCES';
        if (lower.indexOf('operation not permitted') !== -1 || lower.indexOf('(os error 1)') !== -1) return 'EPERM';
        if (lower.indexOf('no such file or directory') !== -1 || lower.indexOf('not found') !== -1 || lower.indexOf('(os error 2)') !== -1) return 'ENOENT';
        if (lower.indexOf('file exists') !== -1 || lower.indexOf('already exists') !== -1 || lower.indexOf('(os error 17)') !== -1) return 'EEXIST';
        if (lower.indexOf('not a directory') !== -1 || lower.indexOf('(os error 20)') !== -1) return 'ENOTDIR';
        if (lower.indexOf('is a directory') !== -1 || lower.indexOf('(os error 21)') !== -1) return 'EISDIR';
        if (lower.indexOf('directory not empty') !== -1 || lower.indexOf('(os error 39)') !== -1) return 'ENOTEMPTY';
        return undefined;
    }
    var HOST_ERRNO = { EPERM: -1, ENOENT: -2, EACCES: -13, EEXIST: -17, ENOTDIR: -20, EISDIR: -21, ENOTEMPTY: -39 };

    function checkHostError(result, op) {
        if (typeof result === 'string' && result.indexOf('__HOST_ERR__:') === 0) {
            var msg = result.slice('__HOST_ERR__:'.length);
            var err = new Error("fs." + op + ": " + msg);
            var code = hostErrCode(msg.toLowerCase());
            if (code) {
                err.code = code;
                err.errno = HOST_ERRNO[code];
            }
            throw err;
        }
        return result;
    }

    // Match Node.js exactly: the host bridge always sends bytes as
    // base64 (binary-safe wire format). The polyfill decodes and
    // converts based on the caller's encoding choice.
    //
    //   fs.readFileSync(path)              → Buffer        (Node default)
    //   fs.readFileSync(path, 'utf8')      → string
    //   fs.readFileSync(path, {encoding})  → string
    //   fs.readFileSync(path, {encoding: null}) → Buffer
    var BufferLazy;
    function bufferModule() {
        if (!BufferLazy) BufferLazy = require('buffer').Buffer;
        return BufferLazy;
    }

    function pickEncoding(options) {
        if (typeof options === 'string') return options;
        if (options && typeof options === 'object') {
            // Node treats `encoding: null` as "give me a Buffer".
            return options.encoding === undefined ? undefined : options.encoding;
        }
        return undefined;
    }

    exports.readFileSync = function(path, options) {
        var encoding = pickEncoding(options);
        // The encoding hint goes to the host so native (rquickjs)
        // bindings can short-circuit if they want; the WASM path
        // ignores it and always returns base64. Either way the
        // decode below is the source of truth.
        var b64 = requireHost('read_file_sync')(String(path), 'base64');
        b64 = checkHostError(b64, 'readFileSync');
        var Buffer = bufferModule();
        var buf = Buffer.from(b64, 'base64');
        if (encoding == null) return buf;
        return buf.toString(encoding);
    };

    exports.writeFileSync = function(path, data, options) {
        var encoding = pickEncoding(options);
        var Buffer = bufferModule();
        var bytes;
        if (Buffer.isBuffer(data)) {
            bytes = data;
        } else if (data instanceof Uint8Array) {
            bytes = Buffer.from(data);
        } else if (typeof data === 'string') {
            bytes = Buffer.from(data, encoding || 'utf8');
        } else {
            throw new TypeError('fs.writeFileSync: data must be Buffer, Uint8Array, or string');
        }
        var b64 = bytes.toString('base64');
        // Pass 'base64' through as the encoding hint (the WASM bridge
        // reads bytes from memory either way; this just keeps the
        // 3-arg shape stable for the native binding).
        var out = requireHost('write_file_sync')(String(path), b64, 'base64');
        checkHostError(out, 'writeFileSync');
    };

    exports.existsSync = function(path) {
        var fn = globalThis.__host_fs_exists_sync;
        return typeof fn === 'function' ? fn(String(path)) : false;
    };

    // Fully fleshed-out Stats object. Node's `Stats` exposes seven
    // type-test methods (isFile / isDirectory / isSymbolicLink /
    // isBlockDevice / isCharacterDevice / isSocket / isFIFO) plus a
    // handful of mode/ino/size/mtime/atime/ctime/birthtime fields and
    // their `*Ms` counterparts. Libraries like path-scurry and chokidar
    // call `entToType(s)` over every field; missing methods crash with
    // "not a function" deep in their walkers. The host gives us file/
    // directory bits via `stat_sync`; everything else is `false` (we
    // don't surface block/char/socket/fifo through the bridge today).
    function shapeStats(parsed) {
        var s = parsed || {};
        s.isFile             = wrapBool(!!s.isFile);
        s.isDirectory        = wrapBool(!!s.isDirectory);
        s.isSymbolicLink     = wrapBool(!!s.isSymbolicLink);
        s.isBlockDevice      = wrapBool(!!s.isBlockDevice);
        s.isCharacterDevice  = wrapBool(!!s.isCharacterDevice);
        s.isSocket           = wrapBool(!!s.isSocket);
        s.isFIFO             = wrapBool(!!s.isFIFO);
        if (typeof s.mode  !== 'number') s.mode  = s.isDirectory() ? 0o040755 : 0o100644;
        if (typeof s.size  !== 'number') s.size  = 0;
        if (typeof s.ino   !== 'number') s.ino   = 0;
        if (typeof s.dev   !== 'number') s.dev   = 0;
        if (typeof s.nlink !== 'number') s.nlink = 1;
        if (typeof s.uid   !== 'number') s.uid   = 0;
        if (typeof s.gid   !== 'number') s.gid   = 0;
        if (typeof s.rdev  !== 'number') s.rdev  = 0;
        if (typeof s.blksize !== 'number') s.blksize = 4096;
        if (typeof s.blocks  !== 'number') s.blocks  = Math.ceil(s.size / 512);
        // Time fields. Node exposes both `ms` numeric and Date-shaped.
        var nowMs = (typeof s.mtimeMs === 'number') ? s.mtimeMs : Date.now();
        if (typeof s.atimeMs !== 'number')    s.atimeMs    = nowMs;
        if (typeof s.mtimeMs !== 'number')    s.mtimeMs    = nowMs;
        if (typeof s.ctimeMs !== 'number')    s.ctimeMs    = nowMs;
        if (typeof s.birthtimeMs !== 'number') s.birthtimeMs = nowMs;
        if (!s.atime)     s.atime     = new Date(s.atimeMs);
        if (!s.mtime)     s.mtime     = new Date(s.mtimeMs);
        if (!s.ctime)     s.ctime     = new Date(s.ctimeMs);
        if (!s.birthtime) s.birthtime = new Date(s.birthtimeMs);
        return s;
    }
    function wrapBool(v) { return function() { return v; }; }

    exports.statSync = function(path) {
        var raw = checkHostError(requireHost('stat_sync')(String(path)), 'statSync');
        return shapeStats(JSON.parse(raw));
    };
    // lstatSync — Node's `lstat` differs from `stat` only for
    // symlinks (it returns info about the link itself). The sandbox
    // bridge doesn't surface symlink-specific bits today; falling
    // back to `statSync` matches the symlink-followed posture we
    // already have for `readFileSync` / `readdirSync`.
    exports.lstatSync = function(path) {
        return exports.statSync(path);
    };

    // statfsSync(path[, options]) — file-system-level info (Node 19+).
    // We don't have a host bridge for `statvfs`; surface conservative
    // defaults so probing libraries don't crash. `bsize` matches the
    // common Linux page size; `bfree` / `bavail` are flagged as
    // available so callers don't think the volume is full.
    exports.statfsSync = function(path, options) {
        // We could route to `__host_fs_statfs_sync` if one becomes
        // available; for now return a synthesised StatFs object that
        // satisfies the standard property shape.
        var bigint = options && options.bigint === true;
        var fields = {
            type: 0,
            bsize: 4096,
            blocks: 0,
            bfree: 1 << 20,
            bavail: 1 << 20,
            files: 0,
            ffree: 1 << 20,
        };
        if (bigint) {
            for (var k in fields) {
                if (Object.prototype.hasOwnProperty.call(fields, k)) {
                    fields[k] = BigInt(fields[k]);
                }
            }
        }
        return fields;
    };
    exports.statfs = function(path, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        try {
            var v = exports.statfsSync(path, options);
            if (cb) queueMicrotask(function() { cb(null, v); });
            return new Promise(function(resolve) { resolve(v); });
        } catch (e) {
            if (cb) queueMicrotask(function() { cb(e); });
            return new Promise(function(_r, reject) { reject(e); });
        }
    };

    // readlinkSync — symlink target via the fs host bridge.
    // can fall through (most archive / module-resolution code probes
    // and degrades gracefully when readlink fails).
    exports.readlinkSync = function(path) {
        var fn = globalThis.__host_fs_readlink_sync;
        if (typeof fn === 'function') {
            return checkHostError(fn(String(path)), 'readlinkSync');
        }
        var e = new Error('fs.readlinkSync: host fn unavailable');
        e.code = 'ENOSYS';
        throw e;
    };

    // accessSync — Node uses bitwise mode constants. We map any
    // mode to `existsSync`, which is the semantic the vast majority
    // of consumers care about (does the path exist + is reachable).
    var F_OK = 0, R_OK = 4, W_OK = 2, X_OK = 1;
    exports.accessSync = function(path, _mode) {
        if (!exports.existsSync(path)) {
            var e = new Error("ENOENT: no such file or directory, access '" + String(path) + "'");
            e.code = 'ENOENT';
            e.errno = -2;
            e.path = String(path);
            throw e;
        }
    };

    exports.readdirSync = function(path) {
        // The host returns either an array of entries (success) or a
        // string starting with `__HOST_ERR__:` (failure — non-existent
        // path, permission denied, etc). Throwing on the error string
        // matches Node's contract and prevents callers from iterating
        // a single string as if it were a directory entry.
        var result = requireHost('readdir_sync')(String(path));
        if (typeof result === 'string' && result.indexOf('__HOST_ERR__:') === 0) {
            var msg = result.slice('__HOST_ERR__:'.length);
            var err = new Error("ENOENT: no such file or directory, scandir '" + String(path) + "'");
            err.code = 'ENOENT';
            err.errno = -2;
            err.syscall = 'scandir';
            err.path = String(path);
            // Preserve the original detail in case callers introspect
            // beyond `code`.
            err.message = err.message + ' (' + msg + ')';
            throw err;
        }
        return result;
    };

    exports.mkdirSync = function(path, options) {
        var recursive = !!(options && options.recursive);
        requireHost('mkdir_sync')(String(path), recursive);
    };

    exports.unlinkSync = function(path) {
        requireHost('unlink_sync')(String(path));
    };

    exports.renameSync = function(from, to) {
        requireHost('rename_sync')(String(from), String(to));
    };

    // Append. Build on readFileSync + writeFileSync — atomic-ish for
    // small files which is the only shape we'd hit in the sandbox.
    exports.appendFileSync = function(path, data, options) {
        var existing;
        try { existing = exports.readFileSync(path); } catch (_) { existing = ''; }
        var combined;
        if (Buffer.isBuffer(existing) || Buffer.isBuffer(data)) {
            combined = Buffer.concat([
                Buffer.isBuffer(existing) ? existing : Buffer.from(String(existing)),
                Buffer.isBuffer(data) ? data : Buffer.from(String(data))
            ]);
        } else {
            combined = String(existing) + String(data);
        }
        exports.writeFileSync(path, combined, options);
    };

    // copyFileSync — straight read-then-write, matches Node when
    // `flags` is the default 0 (copy contents, overwrite if exists).
    exports.copyFileSync = function(src, dst, _flags) {
        var data = exports.readFileSync(src);
        exports.writeFileSync(dst, data);
    };

    // truncateSync — read existing, truncate, rewrite. Sandbox-wide
    // libraries (npm, tar, etc.) only ever truncate small lockfiles
    // so the read+write path is fine.
    exports.truncateSync = function(path, len) {
        len = len || 0;
        var existing;
        try { existing = exports.readFileSync(path); } catch (_) { existing = Buffer.alloc(0); }
        var buf = Buffer.isBuffer(existing) ? existing : Buffer.from(String(existing));
        var truncated = buf.slice(0, len);
        exports.writeFileSync(path, truncated);
    };

    // rmdirSync / rmSync — no host bridge for recursive dir removal,
    // so we walk the tree and delete leaves. Slow for huge trees but
    // correct for lockfile / cache cleanup the sandbox actually sees.
    function _rmDir(path) {
        var entries;
        try { entries = exports.readdirSync(path); } catch (e) { entries = []; }
        for (var i = 0; i < entries.length; i++) {
            var child = String(path) + '/' + entries[i];
            var s;
            try { s = exports.statSync(child); } catch (_) { continue; }
            if (s.isDirectory()) _rmDir(child);
            else { try { exports.unlinkSync(child); } catch (_) {} }
        }
        try { requireHost('unlink_sync')(String(path)); } catch (_) {}
    }
    exports.rmdirSync = function(path, options) {
        if (options && options.recursive) { _rmDir(path); return; }
        try { requireHost('unlink_sync')(String(path)); }
        catch (e) {
            // Some hosts route directory removal through a separate fn;
            // fall back to the recursive walker if it's empty.
            _rmDir(path);
        }
    };
    exports.rmSync = function(path, options) {
        options = options || {};
        if (!exports.existsSync(path)) {
            if (options.force) return;
            var e = new Error("ENOENT: no such file or directory, rm '" + String(path) + "'");
            e.code = 'ENOENT';
            throw e;
        }
        var s;
        try { s = exports.statSync(path); } catch (_) { s = null; }
        if (s && s.isDirectory()) {
            if (options.recursive) _rmDir(path);
            else {
                var ee = new Error("EISDIR: illegal operation on a directory, rm '" + String(path) + "'");
                ee.code = 'EISDIR';
                throw ee;
            }
        } else {
            try { exports.unlinkSync(path); } catch (e) { if (!options.force) throw e; }
        }
    };

    // mkdtempSync — atomic-name temp dir creation. Use a 6-char
    // suffix matching Node's contract.
    exports.mkdtempSync = function(prefix) {
        var p = String(prefix);
        for (var attempt = 0; attempt < 16; attempt++) {
            var rnd = Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0');
            var name = p + rnd;
            try {
                requireHost('mkdir_sync')(name, false);
                return name;
            } catch (_) { /* collision — try again */ }
        }
        var e = new Error("mkdtempSync: failed to create unique directory");
        e.code = 'EEXIST';
        throw e;
    };

    // No-op chmod / chown / utimes / link / symlink / lchown —
    // the sandbox doesn't grant arbitrary metadata mutation, but
    // libraries that defensively call these (npm cache, tar
    // extraction) expect them to silently succeed when the
    // operation is harmless.
    exports.chmodSync   = function(_p, _m) {};
    exports.fchmodSync  = function(_fd, _m) {};
    exports.lchmodSync  = function(_p, _m) {};
    exports.chownSync   = function(_p, _u, _g) {};
    exports.fchownSync  = function(_fd, _u, _g) {};
    exports.lchownSync  = function(_p, _u, _g) {};
    exports.utimesSync  = function(_p, _a, _m) {};
    exports.lutimesSync = function(_p, _a, _m) {};
    exports.futimesSync = function(_fd, _a, _m) {};
    exports.linkSync    = function(existing, target) {
        // Best-effort: copy contents. Hard-link semantics are not
        // representable through the bridge, but most callers only
        // need the file to exist at the new path.
        exports.copyFileSync(existing, target);
    };
    exports.symlinkSync = function(target, p, _type) {
        // Same posture as linkSync — copy. Real symlink behavior
        // (lstat differing from stat) isn't representable.
        try { exports.copyFileSync(target, p); }
        catch (e) {
            // Source missing is the typical npm install case for
            // workspace symlinks; fail loudly so callers can
            // fall through to a real install path.
            throw e;
        }
    };

    // fs constants. Most tools probe `fs.constants.{F,R,W,X}_OK`
    // (access mode flags) and `O_*` (open flag bits). Linux numeric
    // values; we mirror Node's table.
    exports.constants = {
        F_OK: F_OK, R_OK: R_OK, W_OK: W_OK, X_OK: X_OK,
        O_RDONLY: 0, O_WRONLY: 1, O_RDWR: 2, O_CREAT: 64, O_EXCL: 128,
        O_NOCTTY: 256, O_TRUNC: 512, O_APPEND: 1024, O_DIRECTORY: 65536,
        O_NOATIME: 262144, O_NOFOLLOW: 131072, O_SYNC: 1052672,
        O_DSYNC: 4096, O_SYMLINK: 0, O_DIRECT: 16384, O_NONBLOCK: 2048,
        S_IFMT: 0o170000, S_IFREG: 0o100000, S_IFDIR: 0o040000,
        S_IFCHR: 0o020000, S_IFBLK: 0o060000, S_IFIFO: 0o010000,
        S_IFLNK: 0o120000, S_IFSOCK: 0o140000,
        S_IRWXU: 0o700, S_IRUSR: 0o400, S_IWUSR: 0o200, S_IXUSR: 0o100,
        S_IRWXG: 0o070, S_IRGRP: 0o040, S_IWGRP: 0o020, S_IXGRP: 0o010,
        S_IRWXO: 0o007, S_IROTH: 0o004, S_IWOTH: 0o002, S_IXOTH: 0o001,
        UV_FS_COPYFILE_EXCL: 1, COPYFILE_EXCL: 1,
        UV_FS_COPYFILE_FICLONE: 2, COPYFILE_FICLONE: 2,
        UV_FS_COPYFILE_FICLONE_FORCE: 4, COPYFILE_FICLONE_FORCE: 4,
    };

    // ---- streaming -----------------------------------------------------
    var EventEmitter = require('events');
    var Buffer = require('buffer').Buffer;

    // No event loop in the sandbox: stream emission has to be triggered
    // synchronously by something. We adopt the convention that emission
    // fires when the first `data` listener is added (or when the user
    // calls `.resume()` explicitly). Attach `end` / `error` listeners
    // *before* attaching `data`.
    function createReadStream(path, options) {
        options = options || {};
        var chunkSize = options.highWaterMark || 64 * 1024;
        var startOffset = options.start || 0;
        var endOffset = options.end;  // inclusive per Node semantics
        var encoding = options.encoding || null;

        var ee = new EventEmitter();
        var pumped = false;

        function pump() {
            if (pumped) return;
            pumped = true;
            try {
                var sizeFn = globalThis.__host_fs_size;
                if (typeof sizeFn !== 'function') throw new Error('fs.createReadStream: not available');
                var sizeRaw = sizeFn(String(path));
                if (typeof sizeRaw === 'string' && sizeRaw.indexOf('__HOST_ERR__:') === 0) {
                    throw new Error('fs: ' + sizeRaw.slice('__HOST_ERR__:'.length));
                }
                var total = parseInt(sizeRaw, 10);
                var endIdx = (endOffset === undefined || endOffset >= total) ? total - 1 : endOffset;

                var off = startOffset;
                var readFn = globalThis.__host_fs_read_chunk;
                if (typeof readFn !== 'function') throw new Error('fs.createReadStream: chunk reader not available');
                while (off <= endIdx) {
                    var want = Math.min(chunkSize, endIdx - off + 1);
                    var raw = readFn(String(path), off, want);
                    if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
                        throw new Error('fs: ' + raw.slice('__HOST_ERR__:'.length));
                    }
                    var buf = Buffer.from(raw, 'base64');
                    if (buf.length === 0) break;
                    var emitted = encoding ? buf.toString(encoding) : buf;
                    ee.emit('data', emitted);
                    off += buf.length;
                }
                ee.emit('end');
                ee.emit('close');
            } catch (e) {
                ee.emit('error', e);
            }
        }

        var origOn = ee.on.bind(ee);
        ee.on = function(name, fn) {
            origOn(name, fn);
            if (name === 'data') pump();
            return ee;
        };
        ee.addListener = ee.on;
        ee.resume = pump;
        ee.pipe = function(dest) {
            ee.on('end',  function() { if (dest.end) dest.end(); });
            ee.on('data', function(chunk) { dest.write(chunk); });
            return dest;
        };
        return ee;
    }

    function createWriteStream(path, options) {
        options = options || {};
        var off = options.start || 0;
        // Default flags='w' → overwrite, matching Node. Delete first so
        // existing file contents past the written region don't linger.
        var truncateFirst = (options.flags === undefined) || options.flags === 'w';
        var ee = new EventEmitter();
        var writeFn = globalThis.__host_fs_write_chunk;
        if (typeof writeFn !== 'function') {
            throw new Error('fs.createWriteStream: not available');
        }
        if (truncateFirst && typeof globalThis.__host_fs_unlink_sync === 'function') {
            // Ignore errors — file may not exist.
            try { globalThis.__host_fs_unlink_sync(String(path)); } catch (_) {}
        }
        ee.write = function(chunk) {
            try {
                var buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
                var raw = writeFn(String(path), off, buf.toString('base64'));
                if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
                    throw new Error('fs: ' + raw.slice('__HOST_ERR__:'.length));
                }
                off += buf.length;
                return true;
            } catch (e) { ee.emit('error', e); return false; }
        };
        ee.end = function(chunk) {
            if (chunk) ee.write(chunk);
            ee.emit('finish');
            ee.emit('close');
        };
        return ee;
    }

    exports.createReadStream  = createReadStream;
    exports.createWriteStream = createWriteStream;

    // ----- fd-based sync API ----------------------------------------
    //
    // tar's Unpack writes file contents via the classic Node
    // `openSync` / `writeSync` / `closeSync` triple. We don't have
    // real OS-level fds inside the wasm sandbox; instead, we keep a
    // per-process JS-side fd table that maps a small integer to
    // `{ path, offset }`. Writes go through `__host_fs_write_chunk`
    // (the same entry `createWriteStream` uses) — which means npm's
    // tarball extraction works end-to-end without us needing a real
    // libc-shaped fd surface.
    if (!globalThis.__ab_fd_table) globalThis.__ab_fd_table = { next: 3, slots: {} };
    var FDS = globalThis.__ab_fd_table;

    function _allocFd(slot) {
        var n = FDS.next++;
        FDS.slots[n] = slot;
        return n;
    }
    function _fdSlot(fd) {
        var s = FDS.slots[fd];
        if (!s) {
            var e = new Error('EBADF: bad file descriptor');
            e.code = 'EBADF';
            e.errno = -9;
            throw e;
        }
        return s;
    }

    exports.openSync = function(path, flags, _mode) {
        flags = flags || 'r';
        var pathStr = String(path);
        // Truncate when opening with `w` or `wx`. We don't model
        // every flag; `r`/`r+`/`a`/`w`/`wx` are the realistic set.
        var truncate = false;
        if (typeof flags === 'string') {
            if (flags === 'w' || flags === 'wx' || flags === 'w+' || flags === 'wx+') truncate = true;
        } else if (typeof flags === 'number') {
            // O_TRUNC = 0x200
            if (flags & 0x200) truncate = true;
        }
        if (truncate && typeof globalThis.__host_fs_unlink_sync === 'function') {
            try { globalThis.__host_fs_unlink_sync(pathStr); } catch (_) {}
        }
        return _allocFd({ path: pathStr, offset: 0, flags: flags });
    };

    exports.openAsBlob && (exports.openAsBlob = exports.openAsBlob); // keep ref
    exports.closeSync = function(fd) {
        var slot = FDS.slots[fd];
        if (!slot) {
            var e = new Error('EBADF: bad file descriptor');
            e.code = 'EBADF';
            throw e;
        }
        delete FDS.slots[fd];
    };

    // writeSync(fd, buffer[, offset[, length[, position]]])
    // Accepts both Buffer/Uint8Array and string forms.
    exports.writeSync = function(fd, buffer, offset, length, position) {
        var slot = _fdSlot(fd);
        var data;
        if (typeof buffer === 'string') {
            // writeSync(fd, string, position, encoding)
            // — string variant: offset arg becomes the position.
            var enc = (length && typeof length === 'string') ? length : 'utf8';
            data = Buffer.from(buffer, enc);
            if (typeof offset === 'number') position = offset;
            offset = 0;
            length = data.length;
        } else {
            offset = offset || 0;
            length = (typeof length === 'number') ? length : (buffer.length - offset);
            data = (Buffer.isBuffer(buffer) && offset === 0 && length === buffer.length)
                ? buffer
                : Buffer.from(buffer.buffer || buffer, (buffer.byteOffset || 0) + offset, length);
        }
        var pos = (typeof position === 'number') ? position : slot.offset;
        var writeFn = globalThis.__host_fs_write_chunk;
        if (typeof writeFn !== 'function') {
            var e = new Error('writeSync: __host_fs_write_chunk not available');
            e.code = 'ENOSYS';
            throw e;
        }
        var raw = writeFn(slot.path, pos, data.toString('base64'));
        if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
            var e2 = new Error('fs.writeSync: ' + raw.slice('__HOST_ERR__:'.length));
            throw e2;
        }
        if (typeof position !== 'number') slot.offset = pos + length;
        return length;
    };

    // readSync(fd, buffer, offset, length, position)
    exports.readSync = function(fd, buffer, offset, length, position) {
        var slot = _fdSlot(fd);
        var pos = (typeof position === 'number' && position !== null) ? position : slot.offset;
        var readFn = globalThis.__host_fs_read_chunk;
        if (typeof readFn !== 'function') {
            var e = new Error('readSync: __host_fs_read_chunk not available');
            e.code = 'ENOSYS';
            throw e;
        }
        var raw = readFn(slot.path, pos, length);
        if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
            var e2 = new Error('fs.readSync: ' + raw.slice('__HOST_ERR__:'.length));
            throw e2;
        }
        var got = Buffer.from(raw, 'base64');
        var n = Math.min(got.length, length);
        got.copy(buffer, offset, 0, n);
        if (typeof position !== 'number' || position === null) slot.offset = pos + n;
        return n;
    };

    // fstatSync(fd) — same shape as statSync, keyed by fd.
    exports.fstatSync = function(fd) {
        var slot = _fdSlot(fd);
        return exports.statSync(slot.path);
    };

    // fsyncSync / fdatasyncSync / ftruncateSync — best-effort no-ops.
    // Sandbox writes go through the host bridge synchronously already;
    // there's no buffer to flush.
    exports.fsyncSync     = function(_fd) {};
    exports.fdatasyncSync = function(_fd) {};
    exports.ftruncateSync = function(fd, len) {
        var slot = _fdSlot(fd);
        len = len || 0;
        var existing;
        try { existing = exports.readFileSync(slot.path); }
        catch (_) { existing = Buffer.alloc(0); }
        var buf = Buffer.isBuffer(existing) ? existing : Buffer.from(String(existing));
        var truncated = buf.slice(0, len);
        exports.writeFileSync(slot.path, truncated);
    };

    // Callback-style equivalents — auto-wrap the sync versions on a
    // microtask. The CALLBACK_NAMES forEach below already does this
    // for the existing entries; we add fd-shaped names here so they
    // get the same treatment without polluting that list.
    function _asyncWrap(syncName) {
        return function() {
            var args = [].slice.call(arguments);
            var cb = (typeof args[args.length - 1] === 'function') ? args.pop() : null;
            Promise.resolve().then(function() {
                try {
                    var r = exports[syncName].apply(null, args);
                    if (cb) cb(null, r);
                } catch (e) {
                    if (cb) cb(e);
                }
            });
        };
    }
    exports.open       = _asyncWrap('openSync');
    exports.close      = _asyncWrap('closeSync');
    // write(fd, buffer, ...rest, cb) — Node calls back with
    // `(err, bytesWritten, buffer)`. Keep that shape.
    exports.write = function(fd, buffer, offset, length, position, cb) {
        // Tolerate the (fd, buffer, cb) shorthand and
        // (fd, string, position, encoding, cb) string variant.
        if (typeof offset === 'function') { cb = offset; offset = undefined; }
        if (typeof length === 'function') { cb = length; length = undefined; }
        if (typeof position === 'function') { cb = position; position = undefined; }
        Promise.resolve().then(function() {
            try {
                var n = exports.writeSync(fd, buffer, offset, length, position);
                if (cb) cb(null, n, buffer);
            } catch (e) {
                if (cb) cb(e);
            }
        });
    };
    exports.read = function(fd, buffer, offset, length, position, cb) {
        Promise.resolve().then(function() {
            try {
                var n = exports.readSync(fd, buffer, offset, length, position);
                if (cb) cb(null, n, buffer);
            } catch (e) {
                if (cb) cb(e);
            }
        });
    };
    exports.fstat       = _asyncWrap('fstatSync');
    exports.fsync       = _asyncWrap('fsyncSync');
    exports.fdatasync   = _asyncWrap('fdatasyncSync');
    exports.ftruncate   = _asyncWrap('ftruncateSync');

    // ----- realpath ---------------------------------------------------

    exports.realpathSync = function(path) {
        var fn = requireHost('realpath_sync');
        return checkHostError(fn(String(path)), 'realpath');
    };
    /// `fs.realpathSync.native` / `fs.realpath.native` — Node calls
    /// the underlying libuv realpath here; we have one resolver, so
    /// the alias just points back at the same fn (matches Node's
    /// "they always return the same value" contract).
    exports.realpathSync.native = exports.realpathSync;
    exports.realpath = function(path, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        var self = exports;
        Promise.resolve().then(function() {
            try { cb(null, self.realpathSync(path)); }
            catch (e) { cb(e); }
        });
    };
    exports.realpath.native = exports.realpath;

    // ----- cp (recursive copy) ----------------------------------------

    exports.cpSync = function(src, dst, options) {
        var fn = requireHost('cp');
        var force = !!(options && options.force);
        // Node's default is force: true; match that.
        if (options === undefined || (options && options.force === undefined)) {
            force = true;
        }
        checkHostError(fn(String(src), String(dst), force), 'cp');
    };
    exports.cp = function(src, dst, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try { exports.cpSync(src, dst, options); cb(null); }
            catch (e) { cb(e); }
        });
    };

    // ----- opendir / Dir / Dirent -------------------------------------

    function Dirent(entry, parentPath) {
        this.name = entry.name;
        this.parentPath = parentPath;
        this.path = parentPath; // legacy alias
        this._isFile = !!entry.isFile;
        this._isDir = !!entry.isDir;
        this._isSymlink = !!entry.isSymlink;
    }
    Dirent.prototype.isFile = function() { return this._isFile; };
    Dirent.prototype.isDirectory = function() { return this._isDir; };
    Dirent.prototype.isSymbolicLink = function() { return this._isSymlink; };
    Dirent.prototype.isBlockDevice = function() { return false; };
    Dirent.prototype.isCharacterDevice = function() { return false; };
    Dirent.prototype.isFIFO = function() { return false; };
    Dirent.prototype.isSocket = function() { return false; };

    function rawDirEntries(path) {
        var fn = requireHost('opendir_sync');
        var json = checkHostError(fn(String(path)), 'opendir');
        try {
            var arr = JSON.parse(json);
            if (!Array.isArray(arr)) throw new Error('non-array');
            return arr;
        } catch (e) {
            var err = new Error('fs.opendir: malformed host response: ' + e.message);
            err.code = 'EOTHER';
            throw err;
        }
    }

    function Dir(path, entries) {
        this.path = path;
        this._entries = entries;
        this._idx = 0;
        this._closed = false;
    }
    Dir.prototype.read = function(cb) {
        var self = this;
        if (cb) {
            Promise.resolve().then(function() {
                try {
                    var ent = self._readNextSync();
                    cb(null, ent);
                } catch (e) { cb(e); }
            });
            return;
        }
        return new Promise(function(resolve, reject) {
            try { resolve(self._readNextSync()); }
            catch (e) { reject(e); }
        });
    };
    Dir.prototype.readSync = function() { return this._readNextSync(); };
    Dir.prototype._readNextSync = function() {
        if (this._closed) {
            var err = new Error('fs.Dir: read after close');
            err.code = 'ERR_DIR_CLOSED';
            throw err;
        }
        if (this._idx >= this._entries.length) return null;
        return new Dirent(this._entries[this._idx++], this.path);
    };
    Dir.prototype.close = function(cb) {
        this._closed = true;
        if (cb) { Promise.resolve().then(function() { cb(null); }); return; }
        return Promise.resolve();
    };
    Dir.prototype.closeSync = function() { this._closed = true; };
    // async iterator
    Dir.prototype[Symbol.asyncIterator] = function() {
        var self = this;
        return {
            next: function() {
                return self.read().then(function(ent) {
                    if (!ent) { self.close(); return { value: undefined, done: true }; }
                    return { value: ent, done: false };
                });
            },
            return: function() { return self.close().then(function() { return { value: undefined, done: true }; }); },
        };
    };

    exports.opendirSync = function(path, _options) {
        return new Dir(String(path), rawDirEntries(path));
    };
    exports.opendir = function(path, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try { cb(null, exports.opendirSync(path)); }
            catch (e) { cb(e); }
        });
    };
    exports.Dir = Dir;
    exports.Dirent = Dirent;

    /// fs.Stats — class probed by real apps. Real Node returns these
    /// from statSync etc.; our statSync returns plain objects with the
    /// same shape, but the class itself is also exposed. Subclassable
    /// for libraries that pattern-match `instanceof`.
    function Stats() {
        this.dev = 0;
        this.ino = 0;
        this.mode = 0;
        this.nlink = 1;
        this.uid = 0;
        this.gid = 0;
        this.rdev = 0;
        this.size = 0;
        this.blksize = 4096;
        this.blocks = 0;
        this.atimeMs = 0;
        this.mtimeMs = 0;
        this.ctimeMs = 0;
        this.birthtimeMs = 0;
    }
    Stats.prototype.isFile          = function() { return false; };
    Stats.prototype.isDirectory     = function() { return false; };
    Stats.prototype.isBlockDevice   = function() { return false; };
    Stats.prototype.isCharacterDevice = function() { return false; };
    Stats.prototype.isFIFO          = function() { return false; };
    Stats.prototype.isSocket        = function() { return false; };
    Stats.prototype.isSymbolicLink  = function() { return false; };
    exports.Stats = Stats;
    exports.StatFs = function StatFs() {
        this.type = 0;
        this.bsize = 4096;
        this.blocks = 0;
        this.bfree = 0;
        this.bavail = 0;
        this.files = 0;
        this.ffree = 0;
    };

    /// fs.ReadStream / fs.WriteStream — Real instances come back from
    /// `createReadStream` / `createWriteStream`; constructors are
    /// surface-only stand-ins. Some libs pattern-match
    /// `instanceof fs.ReadStream`.
    var _streamMod;
    function _streamModule() {
        if (!_streamMod) _streamMod = require('stream');
        return _streamMod;
    }
    function ReadStream(_path, _options) {
        _streamModule().Readable.call(this);
    }
    Object.defineProperty(exports, 'ReadStream', {
        configurable: true,
        get: function() {
            ReadStream.prototype = Object.create(_streamModule().Readable.prototype);
            ReadStream.prototype.constructor = ReadStream;
            return ReadStream;
        },
    });
    function WriteStream(_path, _options) {
        _streamModule().Writable.call(this);
    }
    Object.defineProperty(exports, 'WriteStream', {
        configurable: true,
        get: function() {
            WriteStream.prototype = Object.create(_streamModule().Writable.prototype);
            WriteStream.prototype.constructor = WriteStream;
            return WriteStream;
        },
    });
    /// fs.FileReadStream / FileWriteStream — Node aliases.
    Object.defineProperty(exports, 'FileReadStream', {
        configurable: true, get: function() { return exports.ReadStream; },
    });
    Object.defineProperty(exports, 'FileWriteStream', {
        configurable: true, get: function() { return exports.WriteStream; },
    });

    // Augment readdirSync with `withFileTypes` and `recursive` support
    // (Node 22+). The existing overload returns a plain string array;
    // opendir_sync gives us typed entries. `recursive: true` walks
    // the tree depth-first and returns paths relative to `path`.
    var _readdirSyncBasic = exports.readdirSync;
    exports.readdirSync = function(path, options) {
        var recursive = !!(options && options.recursive);
        var withFileTypes = !!(options && options.withFileTypes);
        var encoding = options && options.encoding;
        if (recursive) {
            // DFS walk. `parentPath` on Dirent is set to the dir we
            // listed (Node 20+ contract); names are relative to `path`.
            var rootStr = String(path);
            var out = [];
            var stack = [{ dir: rootStr, prefix: '' }];
            while (stack.length) {
                var top = stack.pop();
                var children;
                try { children = rawDirEntries(top.dir); }
                catch (_) { children = []; }
                for (var i = 0; i < children.length; i++) {
                    var c = children[i];
                    var rel = top.prefix ? (top.prefix + '/' + c.name) : c.name;
                    var abs = top.dir + '/' + c.name;
                    if (withFileTypes) {
                        var d = new Dirent(c, top.dir);
                        // Node-26 path field — the absolute joined path.
                        d.path = abs;
                        d.parentPath = top.dir;
                        out.push(d);
                    } else {
                        out.push(rel);
                    }
                    if (c.isDir) {
                        stack.push({ dir: abs, prefix: rel });
                    }
                }
            }
            return out;
        }
        if (withFileTypes) {
            var entries = rawDirEntries(path);
            var pp = String(path);
            return entries.map(function(e) {
                var d = new Dirent(e, pp);
                d.parentPath = pp;
                d.path = pp + '/' + e.name;
                return d;
            });
        }
        var raw = _readdirSyncBasic(path);
        if (encoding === 'buffer') {
            return raw.map(function(n) { return Buffer.from(String(n)); });
        }
        return raw;
    };

    // ----- watch (polling-based FSWatcher) ----------------------------

    var EventEmitter = require('events').EventEmitter;

    function FSWatcher(path, options) {
        EventEmitter.call(this);
        this._path = String(path);
        this._interval = (options && options.interval) || 250;
        this._closed = false;
        this._tick = this._tick.bind(this);
        this._scheduleNext();
    }
    FSWatcher.prototype = Object.create(EventEmitter.prototype);
    FSWatcher.prototype.constructor = FSWatcher;

    FSWatcher.prototype._scheduleNext = function() {
        if (this._closed) return;
        // Use setTimeout(0) so the first poll happens off the current
        // tick — matches Node's behavior of registering the watcher
        // synchronously and emitting events asynchronously.
        if (typeof setTimeout === 'function') {
            setTimeout(this._tick, 0);
        } else {
            // Fallback: microtask. Won't actually deliver host-watched
            // changes (host_fs_watch_poll blocks for `interval`ms), but
            // at least the watcher API surface works in environments
            // without a timer host (`burn` library mode).
            Promise.resolve().then(this._tick);
        }
    };

    FSWatcher.prototype._tick = function() {
        if (this._closed) return;
        var self = this;
        var fn;
        try { fn = requireHost('watch_poll'); }
        catch (e) {
            this.emit('error', e);
            this._closed = true;
            return;
        }
        var raw;
        try {
            raw = fn(self._path, self._interval);
        } catch (e) {
            this.emit('error', e);
            return this._scheduleNext();
        }
        if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
            var msg = raw.slice('__HOST_ERR__:'.length);
            var err = new Error('fs.watch: ' + msg);
            if (msg.toLowerCase().indexOf('permission denied') !== -1) err.code = 'EACCES';
            this.emit('error', err);
            this._closed = true;
            return;
        }
        try {
            var events = JSON.parse(raw);
            if (Array.isArray(events)) {
                for (var i = 0; i < events.length; i++) {
                    var ev = events[i];
                    self.emit('change', ev.kind, ev.filename);
                }
            }
        } catch (_) {}
        this._scheduleNext();
    };

    FSWatcher.prototype.close = function() {
        this._closed = true;
        try { this.emit('close'); } catch (_) {}
    };
    FSWatcher.prototype.ref = function() { return this; };
    FSWatcher.prototype.unref = function() { return this; };

    exports.FSWatcher = FSWatcher;
    exports.watch = function(path, options, listener) {
        if (typeof options === 'function') { listener = options; options = undefined; }
        var w = new FSWatcher(path, options);
        if (typeof listener === 'function') w.on('change', listener);
        return w;
    };

    // ----- FileHandle (fs.promises.open) ------------------------------

    function FileHandle(path, flags) {
        this._path = String(path);
        this._flags = flags || 'r';
        this._closed = false;
    }
    Object.defineProperty(FileHandle.prototype, 'fd', {
        // Node's fd is a small integer; we don't expose a real fd from
        // the WASM sandbox. Surface the path-keyed pseudo-fd so caller
        // code that just uses `.fd` for logging won't crash.
        get: function() { return -1; },
    });

    function _checkOpen(fh) {
        if (fh._closed) {
            var e = new Error('FileHandle: already closed');
            e.code = 'EBADF';
            throw e;
        }
    }

    FileHandle.prototype.read = function(buffer, offset, length, position) {
        _checkOpen(this);
        var Buffer = bufferModule();
        var path = this._path;
        // node-style positional or options-object call
        if (buffer && typeof buffer === 'object' && !Buffer.isBuffer(buffer)
            && !(buffer instanceof Uint8Array)) {
            var opts = buffer;
            buffer = opts.buffer;
            offset = opts.offset;
            length = opts.length;
            position = opts.position;
        }
        offset = offset | 0;
        length = (length === undefined || length === null) ? buffer.length - offset : length | 0;
        position = (position === undefined || position === null) ? 0 : position;
        return new Promise(function(resolve, reject) {
            try {
                var fn = requireHost('read_chunk');
                // host returns base64 encoded bytes
                var b64 = checkHostError(fn(path, position, length), 'FileHandle.read');
                var chunk = Buffer.from(b64, 'base64');
                var n = Math.min(chunk.length, length);
                for (var i = 0; i < n; i++) buffer[offset + i] = chunk[i];
                resolve({ bytesRead: n, buffer: buffer });
            } catch (e) { reject(e); }
        });
    };

    FileHandle.prototype.write = function(data, positionOrOffset, lengthOrEncoding, position) {
        _checkOpen(this);
        var Buffer = bufferModule();
        var path = this._path;
        var bytes;
        var pos;
        if (typeof data === 'string') {
            // (string, position, encoding)
            bytes = Buffer.from(data, lengthOrEncoding || 'utf8');
            pos = (positionOrOffset === undefined || positionOrOffset === null) ? 0 : positionOrOffset;
        } else {
            // (buffer, offset, length, position)
            var offset = positionOrOffset | 0;
            var length = (lengthOrEncoding === undefined || lengthOrEncoding === null)
                ? data.length - offset : lengthOrEncoding | 0;
            bytes = Buffer.from(data.slice(offset, offset + length));
            pos = (position === undefined || position === null) ? 0 : position;
        }
        return new Promise(function(resolve, reject) {
            try {
                var fn = requireHost('write_chunk');
                checkHostError(fn(path, pos, bytes.toString('base64')), 'FileHandle.write');
                resolve({ bytesWritten: bytes.length, buffer: data });
            } catch (e) { reject(e); }
        });
    };

    FileHandle.prototype.readFile = function(options) {
        _checkOpen(this);
        return Promise.resolve(exports.readFileSync(this._path, options));
    };

    FileHandle.prototype.writeFile = function(data, options) {
        _checkOpen(this);
        return Promise.resolve(exports.writeFileSync(this._path, data, options));
    };

    FileHandle.prototype.stat = function() {
        _checkOpen(this);
        return Promise.resolve(exports.statSync(this._path));
    };

    FileHandle.prototype.truncate = function(len) {
        _checkOpen(this);
        len = len | 0;
        var Buffer = bufferModule();
        var existing;
        try { existing = exports.readFileSync(this._path); }
        catch (e) { return Promise.reject(e); }
        var truncated = Buffer.alloc(len);
        existing.copy(truncated, 0, 0, Math.min(existing.length, len));
        try { exports.writeFileSync(this._path, truncated); return Promise.resolve(); }
        catch (e) { return Promise.reject(e); }
    };

    FileHandle.prototype.close = function() {
        this._closed = true;
        return Promise.resolve();
    };

    FileHandle.prototype[Symbol.asyncDispose] = function() { return this.close(); };

    // ----- fs.promises ------------------------------------------------

    exports.promises = {};
    // Auto-promisify every sync function that has a 1:1 promise twin.
    // Node 26 keeps these stable; if the upstream surface grows,
    // adding a new entry here is enough.
    [
        'readFile','writeFile','stat','lstat','readdir','mkdir',
        'unlink','rename','readlink','access','chmod','fchmod','lchmod',
        'chown','fchown','lchown','utimes','lutimes','futimes','link',
        'symlink','copyFile','appendFile','truncate','mkdtemp','rmdir','rm',
    ].forEach(function(name) {
        exports.promises[name] = function() {
            var args = [].slice.call(arguments);
            var syncName = name + 'Sync';
            return new Promise(function(resolve, reject) {
                try { resolve(exports[syncName].apply(null, args)); }
                catch (e) { reject(e); }
            });
        };
    });

    // New promise-only entries.
    exports.promises.realpath = function(path) {
        return new Promise(function(resolve, reject) {
            try { resolve(exports.realpathSync(path)); }
            catch (e) { reject(e); }
        });
    };
    /// `fs.promises.statfs(path, options)` — Node 19+ Promise twin
    /// of `fs.statfs` / `fs.statfsSync`.
    exports.promises.statfs = function(path, options) {
        return new Promise(function(resolve, reject) {
            try { resolve(exports.statfsSync(path, options)); }
            catch (e) { reject(e); }
        });
    };
    exports.promises.cp = function(src, dst, options) {
        return new Promise(function(resolve, reject) {
            try { exports.cpSync(src, dst, options); resolve(); }
            catch (e) { reject(e); }
        });
    };
    exports.promises.opendir = function(path, options) {
        return new Promise(function(resolve, reject) {
            try { resolve(exports.opendirSync(path, options)); }
            catch (e) { reject(e); }
        });
    };
    exports.promises.watch = function(path, options) {
        // Async-iterable wrapper around FSWatcher.
        var w = new FSWatcher(path, options);
        var queue = [];
        var pending = null;
        w.on('change', function(eventType, filename) {
            if (pending) {
                var p = pending; pending = null;
                p({ value: { eventType: eventType, filename: filename }, done: false });
            } else {
                queue.push({ eventType: eventType, filename: filename });
            }
        });
        w.on('error', function(err) {
            if (pending) { var p = pending; pending = null; p(Promise.reject(err)); }
        });
        return {
            [Symbol.asyncIterator]: function() { return this; },
            next: function() {
                if (queue.length) {
                    return Promise.resolve({ value: queue.shift(), done: false });
                }
                return new Promise(function(resolve) { pending = resolve; });
            },
            return: function() {
                w.close();
                return Promise.resolve({ value: undefined, done: true });
            },
        };
    };
    exports.promises.open = function(path, flags, _mode) {
        return new Promise(function(resolve, reject) {
            try {
                // Validate path is reachable; statSync will throw ENOENT
                // for read-only opens and give us a clean error path.
                if (typeof flags === 'string' && flags.indexOf('r') === 0) {
                    exports.statSync(path);
                }
                resolve(new FileHandle(path, flags));
            } catch (e) { reject(e); }
        });
    };
    exports.FileHandle = FileHandle;

    // Node 22+ added `fs.glob` / `fs.globSync` / `fs.promises.glob`
    // for pattern-matched directory walks. We don't pull in a full
    // micromatch engine; libraries that genuinely need glob semantics
    // import the `glob` npm package, which works on top of
    // `readdirSync` / `lstatSync`. The shim returns the bare-leaf
    // shape (no globs interpreted) so callers that pass a literal
    // path get the right answer and pattern callers fall through to
    // the empty-result path matching Node's no-match behavior.
    function _matchPattern(pattern, root) {
        var p = String(pattern);
        // Literal path passthrough — no `*` / `?` / `[` markers.
        if (!/[*?[]/.test(p)) {
            try {
                exports.statSync(p);
                return [p];
            } catch (_) { return []; }
        }
        // For pattern globs, walk the directory and return entries
        // whose name matches the trailing star-segment. Cheap but
        // correct enough for the npm log-cleanup `*.log` case.
        var slash = p.lastIndexOf('/');
        var dir = slash >= 0 ? p.slice(0, slash) : (root || '.');
        var rest = slash >= 0 ? p.slice(slash + 1) : p;
        var re = new RegExp('^' + rest
            .replace(/[.+^${}()|\\]/g, '\\$&')
            .replace(/\*/g, '.*')
            .replace(/\?/g, '.') + '$');
        var entries;
        try { entries = exports.readdirSync(dir); }
        catch (_) { return []; }
        var out = [];
        for (var i = 0; i < entries.length; i++) {
            if (re.test(entries[i])) out.push(dir + '/' + entries[i]);
        }
        return out;
    }
    exports.globSync = function(pattern, options) {
        var pats = Array.isArray(pattern) ? pattern : [pattern];
        var cwd = (options && options.cwd) ? String(options.cwd) : (typeof globalThis.__host_cwd === 'string' ? globalThis.__host_cwd : '.');
        var seen = {};
        var out = [];
        for (var i = 0; i < pats.length; i++) {
            var matches = _matchPattern(pats[i], cwd);
            for (var j = 0; j < matches.length; j++) {
                if (!seen[matches[j]]) { seen[matches[j]] = true; out.push(matches[j]); }
            }
        }
        return out;
    };
    exports.glob = function(pattern, options, cb) {
        if (typeof options === 'function') { cb = options; options = undefined; }
        Promise.resolve().then(function() {
            try { cb(null, exports.globSync(pattern, options)); }
            catch (e) { cb(e); }
        });
    };
    exports.promises.glob = function(pattern, options) {
        return new Promise(function(resolve, reject) {
            try { resolve(exports.globSync(pattern, options)); }
            catch (e) { reject(e); }
        });
    };
    /// fs.promises.constants — Node 18.4+ alias for fs.constants. Some
    /// libraries import only the promises namespace and expect the
    /// flag bag to be reachable from there too.
    exports.promises.constants = exports.constants;

    // Callback-style entry points for every sync function. Node ships
    // both shapes for the entire fs surface; libraries (path-scurry,
    // chokidar, npm's lockfile cleanup) call the callback form
    // directly. We auto-wrap each `*Sync` in an async-callback shim
    // — the result fires on a microtask so handlers attached after
    // dispatch see it (matches Node's CB-after-IO contract).
    var CALLBACK_NAMES = [
        'readFile','writeFile','appendFile','stat','lstat','fstat','exists',
        'readdir','mkdir','rmdir','rm','unlink','rename','readlink','access',
        'chmod','fchmod','lchmod','chown','fchown','lchown','utimes','lutimes',
        'futimes','link','symlink','copyFile','truncate','mkdtemp','realpath',
    ];
    CALLBACK_NAMES.forEach(function(name) {
        if (typeof exports[name] === 'function') return; // already defined (e.g. realpath)
        var syncName = name + 'Sync';
        if (typeof exports[syncName] !== 'function') return; // sync entry missing
        exports[name] = function() {
            var args = [].slice.call(arguments);
            var cb = (typeof args[args.length - 1] === 'function') ? args.pop() : null;
            // Schedule on a microtask so the cb fires after the
            // calling expression returns — matches Node's
            // async-callback contract for code like:
            //   `const r = fs.readdir(path, opts, cb); /* … */`.
            Promise.resolve().then(function() {
                try {
                    var r = exports[syncName].apply(null, args);
                    if (cb) cb(null, r);
                } catch (e) {
                    if (cb) cb(e);
                }
            });
        };
    });
    // existsSync's callback form has a single-arg shape (no err).
    exports.exists = function(path, cb) {
        Promise.resolve().then(function() {
            if (cb) cb(exports.existsSync(path));
        });
    };

    // `fs.writev` / `writevSync` — vectored writes. fs-minipass
    // gates a libuv-binding fallback on `!fs.writev`, so providing
    // even a sequential implementation skips the binding path
    // entirely. The fd is the path-keyed handle from FileHandle /
    // openSync; we serialise the iovec by concatenating buffers
    // and dispatching one write per call. `position === null` means
    // "current position" (Node default); a numeric value seeks first.
    exports.writevSync = function(fd, buffers, position) {
        var total = 0;
        var pos = (typeof position === 'number') ? position : 0;
        // FileHandle stores its path on `_path`; for raw numeric fds
        // we don't have a path mapping and fall through to sync write
        // via the chunk bridge.
        var path = (fd && typeof fd === 'object' && fd._path) ? fd._path : String(fd);
        var writeFn = globalThis.__host_fs_write_chunk;
        if (typeof writeFn !== 'function') {
            throw new Error('fs.writev: not available');
        }
        for (var i = 0; i < buffers.length; i++) {
            var b = buffers[i];
            var bb = Buffer.isBuffer(b) ? b : Buffer.from(b);
            var raw = writeFn(path, pos, bb.toString('base64'));
            if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
                throw new Error('fs: ' + raw.slice('__HOST_ERR__:'.length));
            }
            pos += bb.length;
            total += bb.length;
        }
        return total;
    };
    exports.writev = function(fd, buffers, position, cb) {
        if (typeof position === 'function') { cb = position; position = null; }
        Promise.resolve().then(function() {
            try {
                var n = exports.writevSync(fd, buffers, position);
                if (cb) cb(null, n, buffers);
            } catch (e) { if (cb) cb(e); }
        });
    };
    // `fs.readv` — gather-read vectored. Same posture: serialise.
    exports.readvSync = function(fd, buffers, position) {
        var total = 0;
        var pos = (typeof position === 'number') ? position : 0;
        var path = (fd && typeof fd === 'object' && fd._path) ? fd._path : String(fd);
        var readFn = globalThis.__host_fs_read_chunk;
        if (typeof readFn !== 'function') {
            throw new Error('fs.readv: not available');
        }
        for (var i = 0; i < buffers.length; i++) {
            var b = buffers[i];
            var want = b.length;
            var raw = readFn(path, pos, want);
            if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
                throw new Error('fs: ' + raw.slice('__HOST_ERR__:'.length));
            }
            var got = Buffer.from(raw, 'base64');
            got.copy(b, 0, 0, Math.min(got.length, want));
            pos += got.length;
            total += got.length;
            if (got.length < want) break;
        }
        return total;
    };
    exports.readv = function(fd, buffers, position, cb) {
        if (typeof position === 'function') { cb = position; position = null; }
        Promise.resolve().then(function() {
            try {
                var n = exports.readvSync(fd, buffers, position);
                if (cb) cb(null, n, buffers);
            } catch (e) { if (cb) cb(e); }
        });
    };

    // `fs.openAsBlob` — Node 19+. Returns a Blob backed by the
    // file's content. Sandbox-safe: we read eagerly via the host
    // bridge (no streaming Blob support yet, but the shape is
    // there for libraries that probe).
    exports.openAsBlob = function(path, _options) {
        var data = exports.readFileSync(path);
        if (typeof Blob === 'function') {
            return Promise.resolve(new Blob([data]));
        }
        // Pre-Blob runtimes — return a minimal blob-shaped object.
        var bytes = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
        return Promise.resolve({
            size: bytes.length,
            type: '',
            arrayBuffer: function() { return Promise.resolve(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)); },
            text:        function() { return Promise.resolve(bytes.toString('utf8')); },
            slice:       function() { return this; },
        });
    };
});
