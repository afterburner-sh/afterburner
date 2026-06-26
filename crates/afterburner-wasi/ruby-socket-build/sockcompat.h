#ifndef AB_SOCKCOMPAT_H
#define AB_SOCKCOMPAT_H
/*
 * sockcompat.h -- forced-include compatibility header for building CRuby
 * ext/socket against wasi-libc (wasi-sdk 22) on wasm32-wasip1.
 *
 * Injected via `-include` from ext/socket/extconf.rb. It must come before any
 * system socket header. It:
 *   1. enables wasi-libc's BSD socket + <netdb.h> declarations
 *      (__wasilibc_use_wasip2),
 *   2. declares the few BSD functions wasi-libc still hides (socketpair),
 *   3. replaces wasi-libc's stub <sys/un.h> with a BSD-shaped sockaddr_un
 *      that has sun_path (wasi-libc omits UNIX-domain sockets), and
 *   4. fills in the address-family / protocol constants ext/socket references
 *      that wasi-libc does not define (PF_UNIX, AF_LOCAL, ...).
 *
 * The socket *functions* are provided by sockshim.c as env.sock_* WASM
 * imports; this header only closes the compile-time (decl/type/const) gaps.
 */

#ifndef __wasilibc_use_wasip2
#define __wasilibc_use_wasip2
#endif
/* _GNU_SOURCE unlocks wasi-libc's full struct cmsghdr (with cmsg_data[]),
   the CMSG_DATA / CMSG_NXTHDR / CMSG_FIRSTHDR macros, and SCM_RIGHTS, all of
   which are gated behind #ifdef _GNU_SOURCE in wasip2 <sys/socket.h>. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <sys/types.h>
#include <sys/socket.h>

/* Functions wasi-libc declares only under __wasilibc_unmodified_upstream. */
int socketpair(int, int, int, int [2]);
ssize_t sendmsg(int, const struct msghdr *, int);
ssize_t recvmsg(int, struct msghdr *, int);
char *if_indextoname(unsigned, char *);
unsigned if_nametoindex(const char *);

/* wasi-libc leaves `struct cmsghdr` an incomplete forward declaration (WASI
   has no ancillary-data / control-message support) and ships none of the
   CMSG_* accessor macros. ext/socket's ancdata.c needs the full POSIX
   control-message layer, so define it here (standard Linux-compatible layout).
   The sendmsg/recvmsg these feed route to env.sock_* host stubs. */
#define __AB_HAVE_CMSGHDR 1
struct cmsghdr {
  socklen_t cmsg_len;
  int cmsg_level;
  int cmsg_type;
};
#define CMSG_ALIGN(len) (((len) + sizeof(long) - 1) & (size_t) ~(sizeof(long) - 1))
#define CMSG_DATA(cmsg) ((unsigned char *)(((struct cmsghdr *)(cmsg)) + 1))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
#define CMSG_FIRSTHDR(mhdr) \
  ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) \
    ? (struct cmsghdr *)(mhdr)->msg_control : (struct cmsghdr *)0)
#define __CMSG_NEXT(cmsg) ((unsigned char *)(cmsg) + CMSG_ALIGN((cmsg)->cmsg_len))
#define __CMSG_END(mhdr)  ((unsigned char *)(mhdr)->msg_control + (mhdr)->msg_controllen)
#define CMSG_NXTHDR(mhdr, cmsg) \
  ((cmsg)->cmsg_len < sizeof(struct cmsghdr) || \
   __CMSG_NEXT(cmsg) + sizeof(struct cmsghdr) > __CMSG_END(mhdr) \
    ? (struct cmsghdr *)0 : (struct cmsghdr *)__CMSG_NEXT(cmsg))

/* Address-family / socket-type / option / message-flag constants ext/socket
   needs that wasi-libc does not define. */
#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef MSG_CTRUNC
#define MSG_CTRUNC 0x0008
#endif
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 0x01
#endif
#ifndef SO_LINGER
#define SO_LINGER 13
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* Replace the stub <sys/un.h> (no sun_path) with a BSD-shaped struct. */
#ifndef _SYS_UN_H
#define _SYS_UN_H
struct sockaddr_un {
  sa_family_t sun_family;
  char sun_path[108];
};
#endif
#ifndef SUN_LEN
#define SUN_LEN(s) (2 + strlen((s)->sun_path))
#endif

/* Protocol-family aliases wasi-libc omits (it defines AF_* but not all PF_*). */
#ifndef PF_UNIX
#define PF_UNIX AF_UNIX
#endif
#ifndef PF_LOCAL
#define PF_LOCAL AF_UNIX
#endif
#ifndef AF_LOCAL
#define AF_LOCAL AF_UNIX
#endif

#endif /* AB_SOCKCOMPAT_H */
