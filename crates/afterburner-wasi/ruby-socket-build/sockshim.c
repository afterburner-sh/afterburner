/*
 * sockshim.c -- import-based BSD socket(2) shim for CRuby on wasm32-wasip1.
 *
 * Provides the socket functions that wasi-libc (wasi-sdk 22) declares but does
 * not define in libc.a, as imports of module "env" with sock_* names. clang
 * lowers each import-attributed *defined* (bodied) wrapper to a single
 * WebAssembly import, so the linked ruby.wasm imports env.sock_* alongside
 * wasi_snapshot_preview1. The afterburner host
 * (crates/afterburner-wasi/src/ruby_socket.rs) supplies env.sock_* and routes
 * them to DaemonNet, mirroring the Python/emscripten __syscall_socket path.
 *
 * Compiled with the same CPPFLAGS as the rest of ext/socket, which include
 * `-include sockcompat.h` (BSD decls, netdb, struct fixups).
 *
 * NOTE: getaddrinfo/getnameinfo/gai_strerror/freeaddrinfo are intentionally
 * NOT here. ext/socket's configure selects its bundled wide-getaddrinfo
 * emulation (GETADDRINFO_EMU) on this target, which defines those itself; the
 * emulation resolves names via gethostbyname, gethostbyaddr, getservbyname,
 * getservbyport and inet_aton/inet_pton, which we shim below.
 */
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SOCK_IMP(ret, nm, params, args)                                        \
  extern ret __sock_##nm params                                                \
    __attribute__((import_module("env"), import_name("sock_" #nm)));           \
  ret nm params { return __sock_##nm args; }

/* --- BSD socket(2) syscalls libc.a leaves undefined --- */
SOCK_IMP(int, socket,      (int a, int b, int c), (a, b, c))
SOCK_IMP(int, connect,     (int f, const struct sockaddr *a, socklen_t l), (f, a, l))
SOCK_IMP(int, bind,        (int f, const struct sockaddr *a, socklen_t l), (f, a, l))
SOCK_IMP(int, listen,      (int f, int b), (f, b))
SOCK_IMP(int, setsockopt,  (int f, int lv, int o, const void *v, socklen_t l), (f, lv, o, v, l))
SOCK_IMP(int, getsockname, (int f, struct sockaddr *a, socklen_t *l), (f, a, l))
SOCK_IMP(int, getpeername, (int f, struct sockaddr *a, socklen_t *l), (f, a, l))
SOCK_IMP(int, socketpair,  (int d, int t, int p, int sv[2]), (d, t, p, sv))
SOCK_IMP(ssize_t, sendto,  (int f, const void *b, size_t n, int fl, const struct sockaddr *a, socklen_t l), (f, b, n, fl, a, l))
SOCK_IMP(ssize_t, recvfrom,(int f, void *b, size_t n, int fl, struct sockaddr *a, socklen_t *l), (f, b, n, fl, a, l))
SOCK_IMP(ssize_t, sendmsg, (int f, const struct msghdr *m, int fl), (f, m, fl))
SOCK_IMP(ssize_t, recvmsg, (int f, struct msghdr *m, int fl), (f, m, fl))
SOCK_IMP(int, gethostname, (char *n, size_t l), (n, l))

/* --- name/service resolution used by the bundled getaddrinfo emulation --- */
SOCK_IMP(struct hostent *, gethostbyname, (const char *n), (n))
SOCK_IMP(struct hostent *, gethostbyaddr, (const void *a, socklen_t l, int t), (a, l, t))
SOCK_IMP(struct servent *, getservbyname, (const char *n, const char *p), (n, p))
SOCK_IMP(struct servent *, getservbyport, (int p, const char *pr), (p, pr))
SOCK_IMP(int, inet_aton, (const char *c, struct in_addr *a), (c, a))

/* --- interface name<->index (ancdata.c IP_PKTINFO path) --- */
SOCK_IMP(char *, if_indextoname, (unsigned i, char *n), (i, n))
SOCK_IMP(unsigned, if_nametoindex, (const char *n), (n))

/* h_errno: wasi-libc's <netdb.h> declares it `_Thread_local` but provides no
   definition; ext/socket's getaddrinfo emulation references it. Define it with
   matching thread-local storage (value is not load-bearing: the host reports
   errors through return codes). */
_Thread_local int h_errno;
