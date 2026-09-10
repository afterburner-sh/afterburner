// Test fixture: a minimal HTTP daemon exporting the `afterburner_daemon_*`
// ABI (docs/wasi-daemon-abi.md) via Go's `//go:wasmexport` (Go >= 1.24;
// see `preflight_go` in crates/afterburner/src/cli/compile/lang.rs).
//
// Behavior: identical to the Rust fixture (server.rs) in this directory -
// replies to every request with `request #N path=<url>`, N counting up
// from 1, proving both multi-request serving and that guest state (the
// counter) survives across calls. `__PORT__` is substituted by the test
// harness with an ephemeral port.
package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync/atomic"
	"unsafe"

	_ "unsafe"
)

var count int32

// Buffers handed back to the host via a response header must stay alive
// until the host frees them with afterburner_dealloc - Go's GC does not
// know the host holds a reference, so pin every outstanding buffer here,
// keyed by its pointer, until it is explicitly released.
var pinned = map[int32][]byte{}

//go:wasmexport afterburner_alloc
func afterburnerAlloc(length int32) int32 {
	buf := make([]byte, length)
	ptr := int32(uintptr(unsafe.Pointer(unsafe.SliceData(buf))))
	pinned[ptr] = buf
	return ptr
}

//go:wasmexport afterburner_dealloc
func afterburnerDealloc(ptr int32, _ int32) {
	delete(pinned, ptr)
}

func respond(body []byte) int32 {
	bodyPtr := afterburnerAlloc(int32(len(body)))
	copy(pinned[bodyPtr], body)

	header := make([]byte, 8)
	putU32(header[0:4], uint32(bodyPtr))
	putU32(header[4:8], uint32(len(body)))
	headerPtr := afterburnerAlloc(8)
	copy(pinned[headerPtr], header)
	return headerPtr
}

func putU32(dst []byte, v uint32) {
	dst[0] = byte(v)
	dst[1] = byte(v >> 8)
	dst[2] = byte(v >> 16)
	dst[3] = byte(v >> 24)
}

func extractJSONString(haystack, key string) string {
	needle := "\"" + key + "\":\""
	start := strings.Index(haystack, needle)
	if start < 0 {
		return ""
	}
	start += len(needle)
	end := strings.Index(haystack[start:], "\"")
	if end < 0 {
		return ""
	}
	return haystack[start : start+end]
}

//go:wasmexport afterburner_daemon_init
func afterburnerDaemonInit(_ int32, _ int32) int32 {
	return respond([]byte(`{"listen":[{"port":__PORT__}]}`))
}

//go:wasmexport afterburner_daemon_dispatch
func afterburnerDaemonDispatch(ptr int32, length int32) int32 {
	reqBytes := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), length)
	url := extractJSONString(string(reqBytes), "url")

	n := atomic.AddInt32(&count, 1)
	body := fmt.Sprintf("request #%d path=%s", n, url)
	resp := fmt.Sprintf(`{"status":200,"headers":{},"body_b64":"%s"}`, base64.StdEncoding.EncodeToString([]byte(body)))
	return respond([]byte(resp))
}

func main() {}
