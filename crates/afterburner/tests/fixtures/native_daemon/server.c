// Test fixture: a minimal HTTP daemon exporting the `afterburner_daemon_*`
// ABI (docs/wasi-daemon-abi.md) via wasi-sdk clang's
// `__attribute__((export_name(...)))`.
//
// Behavior: identical to the Rust/Go fixtures in this directory - replies
// to every request with `request #N path=<url>`, N counting up from 1,
// proving both multi-request serving and that guest state (the counter)
// survives across calls. `__PORT__` is substituted by the test harness
// with an ephemeral port.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int32_t counter = 0;

__attribute__((export_name("afterburner_alloc")))
int32_t afterburner_alloc(int32_t len) {
    return (int32_t)(intptr_t)malloc((size_t)(len > 0 ? len : 0));
}

__attribute__((export_name("afterburner_dealloc")))
void afterburner_dealloc(int32_t ptr, int32_t len) {
    (void)len;
    free((void *)(intptr_t)ptr);
}

/* Allocate an owned response buffer, write the 8-byte
 * [ptr: u32 LE][len: u32 LE] header, and return a pointer to it - the
 * calling convention every afterburner_daemon_* export uses to hand
 * bytes back to the host. */
static int32_t respond(const char *body, size_t body_len) {
    char *buf = (char *)malloc(body_len);
    memcpy(buf, body, body_len);

    uint8_t *header = (uint8_t *)malloc(8);
    uint32_t ptr = (uint32_t)(intptr_t)buf;
    uint32_t len = (uint32_t)body_len;
    header[0] = (uint8_t)(ptr);
    header[1] = (uint8_t)(ptr >> 8);
    header[2] = (uint8_t)(ptr >> 16);
    header[3] = (uint8_t)(ptr >> 24);
    header[4] = (uint8_t)(len);
    header[5] = (uint8_t)(len >> 8);
    header[6] = (uint8_t)(len >> 16);
    header[7] = (uint8_t)(len >> 24);
    return (int32_t)(intptr_t)header;
}

static const char B64[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Caller-owned output buffer; `out` must hold at least
 * 4 * ((len + 2) / 3) + 1 bytes. Returns the encoded length. */
static size_t b64_encode(const uint8_t *data, size_t len, char *out) {
    size_t i = 0, o = 0;
    while (i < len) {
        uint8_t b0 = data[i];
        uint8_t b1 = (i + 1 < len) ? data[i + 1] : 0;
        uint8_t b2 = (i + 2 < len) ? data[i + 2] : 0;
        out[o++] = B64[b0 >> 2];
        out[o++] = B64[((b0 & 0x03) << 4) | (b1 >> 4)];
        out[o++] = (i + 1 < len) ? B64[((b1 & 0x0f) << 2) | (b2 >> 6)] : '=';
        out[o++] = (i + 2 < len) ? B64[b2 & 0x3f] : '=';
        i += 3;
    }
    out[o] = '\0';
    return o;
}

/* Pull the value of a "key":"value" pair out of a flat JSON blob with a
 * plain substring scan - wasi-sdk ships no JSON parser and this fixture
 * doesn't need a real one. Returns a pointer into `haystack` plus length
 * via `out_len`, or NULL if not found. */
static const char *extract_json_string(const char *haystack, const char *key, size_t *out_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *start = strstr(haystack, needle);
    if (!start) {
        return NULL;
    }
    start += strlen(needle);
    const char *end = strchr(start, '"');
    if (!end) {
        return NULL;
    }
    *out_len = (size_t)(end - start);
    return start;
}

__attribute__((export_name("afterburner_daemon_init")))
int32_t afterburner_daemon_init(int32_t ptr, int32_t len) {
    (void)ptr;
    (void)len;
    const char body[] = "{\"listen\":[{\"port\":__PORT__}]}";
    return respond(body, sizeof(body) - 1);
}

__attribute__((export_name("afterburner_daemon_dispatch")))
int32_t afterburner_daemon_dispatch(int32_t ptr, int32_t len) {
    const char *req = (const char *)(intptr_t)ptr;
    size_t url_len = 0;
    const char *url = extract_json_string(req, "url", &url_len);
    if (!url) {
        url = "";
        url_len = 0;
    }

    counter += 1;
    char body[256];
    int body_len = snprintf(body, sizeof(body), "request #%d path=%.*s", counter, (int)url_len, url);

    char b64[512];
    size_t b64_len = b64_encode((const uint8_t *)body, (size_t)body_len, b64);

    char resp[768];
    int resp_len = snprintf(resp, sizeof(resp),
        "{\"status\":200,\"headers\":{},\"body_b64\":\"%.*s\"}", (int)b64_len, b64);

    (void)len;
    (void)ptr;
    return respond(resp, (size_t)resp_len);
}

int main(void) { return 0; }
