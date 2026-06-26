// dgram — Node 20's UDP socket module. The host-side coordinator
// (`crates/afterburner-wasi/src/daemon_dgram.rs`) owns every
// `tokio::net::UdpSocket`; this polyfill is a thin EventEmitter
// façade. `dgram` requires daemon mode (the coordinator is tokio-
// backed); calling `bind` / `send` from library mode surfaces a clear
// `ERR_NO_DAEMON` rather than silently dropping packets.
//
// What works today: bind / address / send / close + `'listening'`,
// `'close'`, and `'message'` events. Inbound `'message'` delivery is
// fully wired: the host recv loop emits `dgram-message` envelopes
// that the daemon-event dispatcher routes to `__ab_dgram_handlers[id]`.

(function bootstrapDgramGlobals() {
    if (!globalThis.__ab_dgram_handlers) globalThis.__ab_dgram_handlers = {};
})();

__register_module('dgram', function(module, exports, require) {
    var EventEmitter = require('events').EventEmitter;
    var Buffer = require('buffer').Buffer;

    function mapHostErrorCode(rc) {
        switch (rc) {
            case -1: return 'ENO_DAEMON';
            case -2: return 'EACCES';
            case -3: return 'EBADID';
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
        var msg = detail ? (prefix + ': ' + detail) : prefix;
        var err = new Error(msg);
        err.code = mapHostErrorCode(rc);
        return err;
    }

    function Socket(opts) {
        EventEmitter.call(this);
        opts = opts || {};
        this.type = (typeof opts === 'string') ? opts : (opts.type || 'udp4');
        this._reuseAddr = !!opts.reuseAddr;
        this._ipv6Only = !!opts.ipv6Only;
        this._socketId = 0;
        this._bound = false;
        this._closed = false;
    }
    Socket.prototype = Object.create(EventEmitter.prototype);
    Socket.prototype.constructor = Socket;

    function ensureHost(name) {
        var fn = globalThis['__host_dgram_' + name];
        if (typeof fn !== 'function') {
            var err = new Error(
                'dgram.' + name + ': host coordinator not installed (daemon mode required)'
            );
            err.code = 'ERR_NO_DAEMON';
            throw err;
        }
        return fn;
    }

    Socket.prototype.bind = function(port, address, callback) {
        if (typeof port === 'function') { callback = port; port = 0; address = undefined; }
        else if (typeof address === 'function') { callback = address; address = undefined; }
        if (this._bound) {
            var bindErr = new Error('dgram.bind: socket already bound');
            bindErr.code = 'ERR_SOCKET_ALREADY_BOUND';
            if (typeof callback === 'function') {
                Promise.resolve().then(function() { callback(bindErr); });
            }
            throw bindErr;
        }
        port = port | 0;
        address = address || (this.type === 'udp6' ? '::' : '0.0.0.0');
        var fn;
        try { fn = ensureHost('bind'); }
        catch (e) {
            var self0 = this;
            Promise.resolve().then(function() { try { self0.emit('error', e); } catch (_) {} });
            if (typeof callback === 'function') Promise.resolve().then(function() { callback(e); });
            return this;
        }
        var rc = fn(String(address), port);
        if (rc < 0) {
            var err = makeError(rc, 'dgram.bind');
            var self = this;
            Promise.resolve().then(function() { try { self.emit('error', err); } catch (_) {} });
            if (typeof callback === 'function') Promise.resolve().then(function() { callback(err); });
            return this;
        }
        this._socketId = rc;
        this._bound = true;
        globalThis.__ab_dgram_handlers[this._socketId] = this;
        var self2 = this;
        Promise.resolve().then(function() {
            try { self2.emit('listening'); } catch (_) {}
            if (typeof callback === 'function') callback();
        });
        return this;
    };

    Socket.prototype.send = function(msg /*, [offset, length,] port, address, callback */) {
        var args = Array.prototype.slice.call(arguments, 1);
        var callback = (args.length && typeof args[args.length - 1] === 'function')
            ? args.pop() : null;
        // Argument shapes:
        //   send(msg, port[, address][, cb])
        //   send(msg, offset, length, port[, address][, cb])
        var port, address;
        if (args.length >= 3) {
            // (offset, length, port[, address])
            var offset = args[0] | 0;
            var length = args[1] | 0;
            port = args[2] | 0;
            address = args[3];
            if (typeof msg === 'string') msg = Buffer.from(msg, 'utf8');
            if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);
            msg = msg.slice(offset, offset + length);
        } else {
            // (port[, address])
            port = args[0] | 0;
            address = args[1];
            if (typeof msg === 'string') msg = Buffer.from(msg, 'utf8');
            if (!Buffer.isBuffer(msg)) msg = Buffer.from(msg);
        }
        address = address || (this.type === 'udp6' ? '::1' : '127.0.0.1');
        if (!this._bound) {
            // Implicit bind to ephemeral port — matches Node.
            try { this.bind(0); }
            catch (e) {
                if (callback) Promise.resolve().then(function() { callback(e); });
                return;
            }
        }
        var fn;
        try { fn = ensureHost('send'); }
        catch (e) {
            if (callback) Promise.resolve().then(function() { callback(e); });
            else throw e;
            return;
        }
        var b64 = msg.toString('base64');
        var rc = fn(this._socketId, String(address), port, b64);
        var self = this;
        if (rc < 0) {
            var err = makeError(rc, 'dgram.send');
            if (callback) Promise.resolve().then(function() { callback(err); });
            else Promise.resolve().then(function() {
                try { self.emit('error', err); } catch (_) {}
            });
            return;
        }
        if (callback) Promise.resolve().then(function() { callback(null, rc); });
    };

    Socket.prototype.close = function(callback) {
        if (this._closed) {
            if (typeof callback === 'function') Promise.resolve().then(function() { callback(); });
            return this;
        }
        this._closed = true;
        if (this._socketId) {
            try { ensureHost('close')(this._socketId); } catch (_) {}
            delete globalThis.__ab_dgram_handlers[this._socketId];
        }
        var self = this;
        Promise.resolve().then(function() {
            try { self.emit('close'); } catch (_) {}
            if (typeof callback === 'function') callback();
        });
        return this;
    };

    Socket.prototype.address = function() {
        if (!this._bound) {
            var e = new Error('Not running');
            e.code = 'ERR_SOCKET_DGRAM_NOT_RUNNING';
            throw e;
        }
        var fn;
        try { fn = ensureHost('address'); }
        catch (_) {
            return { address: '0.0.0.0', port: 0, family: this.type === 'udp6' ? 'IPv6' : 'IPv4' };
        }
        var raw = fn(this._socketId);
        if (typeof raw === 'string' && raw.indexOf('__HOST_ERR__:') === 0) {
            var err = new Error('dgram.address: ' + raw.slice('__HOST_ERR__:'.length));
            err.code = 'EOTHER';
            throw err;
        }
        try {
            var parsed = JSON.parse(raw);
            return {
                address: parsed.address,
                port: parsed.port,
                family: this.type === 'udp6' ? 'IPv6' : 'IPv4',
            };
        } catch (e) {
            var err2 = new Error('dgram.address: malformed host response');
            err2.code = 'EOTHER';
            throw err2;
        }
    };

    // Hook for the daemon-event dispatcher (not yet wired) to deliver
    // inbound 'message' events. The CLI's translator will call this
    // when a dgram-message envelope arrives.
    Socket.prototype._dispatchMessage = function(payloadB64, fromAddress, fromPort) {
        var msg;
        try { msg = Buffer.from(payloadB64, 'base64'); }
        catch (_) { return; }
        var rinfo = {
            address: fromAddress,
            port: fromPort,
            family: (fromAddress && fromAddress.indexOf(':') >= 0) ? 'IPv6' : 'IPv4',
            size: msg.length,
        };
        try { this.emit('message', msg, rinfo); } catch (_) {}
    };
    Socket.prototype._dispatchError = function(message) {
        var err = new Error(message || 'dgram error');
        err.code = 'EOTHER';
        try { this.emit('error', err); } catch (_) {}
    };

    // Unsupported / no-op options. UDP socket options below the
    // bind/send line aren't needed for the canonical use cases
    // (metrics push, request-response loops) and would expand the
    // host coordinator's surface for marginal value. They no-op so
    // libraries that defensively call them don't crash.
    Socket.prototype.connect = function() { throw notWired('connect'); };
    Socket.prototype.disconnect = function() { throw notWired('disconnect'); };
    Socket.prototype.remoteAddress = function() { throw notWired('remoteAddress'); };
    Socket.prototype.setBroadcast = function() {};
    Socket.prototype.setTTL = function() {};
    Socket.prototype.setMulticastTTL = function() {};
    Socket.prototype.setMulticastInterface = function() {};
    Socket.prototype.setMulticastLoopback = function() {};
    Socket.prototype.addMembership = function() {};
    Socket.prototype.dropMembership = function() {};
    Socket.prototype.addSourceSpecificMembership = function() {};
    Socket.prototype.dropSourceSpecificMembership = function() {};
    Socket.prototype.setRecvBufferSize = function() {};
    Socket.prototype.setSendBufferSize = function() {};
    Socket.prototype.getRecvBufferSize = function() { return 0; };
    Socket.prototype.getSendBufferSize = function() { return 0; };
    Socket.prototype.ref = function() { return this; };
    Socket.prototype.unref = function() { return this; };

    function notWired(name) {
        var e = new Error(
            'dgram.Socket.' + name + ' is not wired in burn — implementations focus '
            + 'on canonical bind/send use cases. File an issue if you need this.'
        );
        e.code = 'ERR_NOT_IMPLEMENTED';
        return e;
    }

    function createSocket(opts, callback) {
        var sock = new Socket(opts);
        if (typeof callback === 'function') sock.on('message', callback);
        return sock;
    }

    exports.createSocket = createSocket;
    exports.Socket = Socket;
});
