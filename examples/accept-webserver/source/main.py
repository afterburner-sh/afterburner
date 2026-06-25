# Section 15 acceptance: webserver using N1 (DaemonNet sockets) and N2 threads.
#
# Binds a real OS TCP port via Python's socket module (which routes through the
# Emscripten socket syscalls, which call DaemonNet::listen / accept), then
# serves concurrent HTTP requests by spawning a real OS thread (threading.Thread,
# which routes through the emscripten pthread_create shim -> DaemonWorkers)
# per accepted connection.
#
# Port: taken from the BURN_ACCEPT_PORT environment variable if set, else 8742.
# The acceptance integration test sets this variable to an ephemeral port it
# chooses. When run interactively, curl http://127.0.0.1:8742/ returns "burn-ok".

import http.server
import os
import threading

PORT = int(os.environ.get("BURN_ACCEPT_PORT", "8742"))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"burn-ok\n")

    def log_message(self, fmt, *args):
        pass  # suppress per-request noise; the accept test checks the body


class ThreadingHTTPServer(http.server.HTTPServer):
    """Minimal threading mix-in: one real thread per accepted request (N2)."""

    def process_request(self, request, client_address):
        t = threading.Thread(
            target=self.process_request_thread, args=(request, client_address)
        )
        t.daemon = True
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.serve_forever()
