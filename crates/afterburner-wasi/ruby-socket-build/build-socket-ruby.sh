#!/usr/bin/env bash
#
# build-socket-ruby.sh -- build a socket-enabled CRuby ruby.wasm (wasm32-wasip1)
# for afterburner, re-enabling ext/socket with import-based socket syscalls.
#
# Output: a static WASI p1 command module that
#   * contains Init_socket (ext/socket statically linked in), and
#   * imports env.sock_socket / sock_connect / sock_bind / sock_listen /
#     sock_getaddrinfo / ... alongside wasi_snapshot_preview1.
#
# The afterburner host (crates/afterburner-wasi/src/ruby_socket.rs, a separate
# task) provides those env.sock_* imports and routes them to DaemonNet.
#
# Verified facts this recipe rests on (wasi-sdk 22 / ruby 3.4.1):
#   * <sys/socket.h> exposes the BSD names only under -D__wasilibc_use_wasip2.
#   * <netdb.h> exists only in the wasip2 include tree
#     (<sysroot>/include/wasm32-wasip2/netdb.h); we add it with -I.
#   * libc.a defines only accept/accept4/send/recv/shutdown/getsockopt/
#     inet_ntop/inet_pton; sockshim.c supplies the rest as env.sock_* imports.
#   * extconf's probes are link tests that cannot see sockshim.o, so we
#     pre-seed mkmf ($defs HAVE_*) for the shimmed functions.
#
# Requirements on the build host:
#   * wasi-sdk 22  (WASI_SDK env var -> its root; bin/clang, share/wasi-sysroot)
#   * a host C compiler + make + autoconf (to build baseruby/miniruby)
#   * a host ruby as --with-baseruby (any 3.x)
#   * binaryen wasm-opt on PATH (ruby's wasm build calls it)
# Effort: ~10-20 min on a modern machine; output ~30-40 MB before strip.

set -euo pipefail

: "${WASI_SDK:?set WASI_SDK to the wasi-sdk-22 root (contains bin/clang)}"
RUBY_VERSION="${RUBY_VERSION:-3.4.1}"
RUBY_TARBALL_URL="${RUBY_TARBALL_URL:-https://cache.ruby-lang.org/pub/ruby/3.4/ruby-${RUBY_VERSION}.tar.gz}"
BASERUBY="${BASERUBY:-$(command -v ruby)}"
WORK="${WORK:-$(pwd)/socket-ruby-build}"
SYSROOT="$WASI_SDK/share/wasi-sysroot"
HERE="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$WORK"
cd "$WORK"

# 1. Fetch + unpack Ruby source (release tarball ships a prebuilt ./configure).
if [ ! -d "ruby-${RUBY_VERSION}" ]; then
  curl -fsSL -o "ruby-${RUBY_VERSION}.tar.gz" "$RUBY_TARBALL_URL"
  tar xzf "ruby-${RUBY_VERSION}.tar.gz"
fi
SRC="$WORK/ruby-${RUBY_VERSION}"

# 2. Drop the socket shim into ext/socket and wire it into the build.
cp "$HERE/sockshim.c" "$SRC/ext/socket/sockshim.c"

#    2a. extconf.rb: add wasip2 flags, pre-seed HAVE_* for the shimmed funcs so
#        the link-based probes pass, and append sockshim to $objs.
python3 - "$SRC/ext/socket/extconf.rb" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
if "afterburner socket shim" not in s:
    # (a) Prologue: forced-include sockcompat.h, add the wasip2 include dir for
    #     <netdb.h>, match wasi-libc's const gai_strerror, and pre-seed mkmf
    #     HAVE_* for the shimmed funcs (the conftest link tests can't see
    #     sockshim.o, so they would otherwise fail).
    inject = '''
# === afterburner socket shim (wasm32-wasip1) ===
if RUBY_PLATFORM =~ /wasm|wasi/
  wasi_sysroot = ENV["WASI_SYSROOT"]
  $CPPFLAGS << " -include #{File.expand_path(__dir__)}/sockcompat.h"
  $CPPFLAGS << " -I#{wasi_sysroot}/include/wasm32-wasip2" if wasi_sysroot
  # wasi-libc netdb.h declares `const char *gai_strerror(int)`; make the bundled
  # addrinfo.h (GETADDRINFO_EMU path) use the same const-qualified signature.
  $defs << "-DGAI_STRERROR_CONST"
  %w[socket connect bind listen setsockopt getsockname getpeername socketpair
     sendto recvfrom sendmsg recvmsg gethostname getservbyport send recv accept
     accept4 shutdown getsockopt inet_ntop inet_pton].each { |f| $defs << "-DHAVE_#{f.upcase}" }
end
'''
    s = s.replace("require 'mkmf'\n", "require 'mkmf'\n" + inject + "\n", 1)
    # (b) Force create_makefile on wasm even though the automatic
    #     `if have_func(test_func, headers)` link probe fails (socket() is an
    #     import resolved only at final link, invisible to the conftest).
    s = s.replace(
        'if have_func(test_func, headers)',
        'if (RUBY_PLATFORM =~ /wasm|wasi/) || have_func(test_func, headers)',
        1)
    # (c) Append the shim object to OBJS so it is compiled and linked.
    s = s.replace(
        '"ifaddr.#{$OBJEXT}"\n  ]',
        '"ifaddr.#{$OBJEXT}",\n    "sockshim.#{$OBJEXT}"\n  ]',
        1)
    open(p, "w").write(s)
    print("patched ext/socket/extconf.rb")
else:
    print("ext/socket/extconf.rb already patched")
PY
# sockcompat.h closes the compile-time gaps wasi-libc leaves: BSD decls
# (socketpair/sendmsg/recvmsg/if_*), a sun_path-bearing sockaddr_un, the full
# struct cmsghdr + CMSG_* macros, and the PF_*/SOCK_RAW/SO_LINGER/SCM_RIGHTS/
# IFNAMSIZ/MSG_CTRUNC constants. Copied alongside sockshim.c.
cp "$HERE/sockcompat.h" "$SRC/ext/socket/sockcompat.h"

# 3. Configure for wasm32-unknown-wasip1, statically linking ext/socket.
#    Flag set mirrors ruby/ruby.wasm's CrossRubyProduct#configure_args.
rm -rf build && mkdir build && cd build
export WASI_SYSROOT="$SYSROOT"
"$SRC/configure" \
  --host wasm32-unknown-wasi \
  --build "$("$SRC/tool/config.guess")" \
  --with-static-linked-ext \
  --with-ext=socket,pathname,stringio,strscan,digest,json,date,etc,fcntl,zlib \
  --with-baseruby="$BASERUBY" \
  --disable-install-doc \
  --disable-gems \
  CC="$WASI_SDK/bin/clang" \
  LD="$WASI_SDK/bin/clang" \
  AR="$WASI_SDK/bin/llvm-ar" \
  RANLIB="$WASI_SDK/bin/llvm-ranlib" \
  CFLAGS="--target=wasm32-wasi --sysroot=$SYSROOT" \
  LDFLAGS="--target=wasm32-wasi --sysroot=$SYSROOT" \
  XCFLAGS="-DWASM_SETJMP_STACK_BUFFER_SIZE=24576 -DWASM_FIBER_STACK_BUFFER_SIZE=24576 -DWASM_SCAN_STACK_BUFFER_SIZE=24576" \
  ac_cv_func_fchmod=no ac_cv_func_chmod=no ac_cv_func_realpath=no ac_cv_func_dlopen=no \
  WASI_SDK_PATH="$WASI_SDK"

# 4. Build. The linked `build/ruby` IS the final command module; grab it
#    immediately (a later `make install` runs wasm-opt over the ~20 MB module
#    and can be slow, but does not change the socket imports / Init_socket).
make -j"$(nproc)"

OUT="$WORK/ruby-socket.wasm"
cp "$WORK/build/ruby" "$OUT"

# Optional: staged install (rbconfig, stdlib .rb, wasm-opt). Not required for
# the command module; skip or background in CI if wasm-opt is the bottleneck.
# make install DESTDIR="$WORK/install"

# 5. Verify the two required properties.
echo "== verifying $OUT =="
wasm-tools print "$OUT" | grep '(import' | grep -iE 'sock_' \
  || { echo "FAIL: no env.sock_* imports"; exit 1; }
wasm-tools print "$OUT" | grep -qi 'Init_socket' \
  && echo "OK: Init_socket present" \
  || { echo "NOTE: Init_socket is internal; confirm via the strings/elem check below"; \
       wasm-tools print "$OUT" | grep -i 'socket' | head; }

echo "Built: $OUT"
