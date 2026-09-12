// Test fixture: a minimal HTTP daemon exporting the `afterburner_daemon_*`
// ABI (docs/wasi-daemon-abi.md). Compiled by `burn run` via bare `rustc`
// (no Cargo, no crates.io deps - `compile_single_file_rust` invokes
// `rustc` directly), so this uses only `std` and hand-rolls the tiny bit
// of JSON / base64 a real dependency would otherwise provide.
//
// Behavior: replies to every request with `request #N path=<url>`, N
// counting up from 1 - proving both that the daemon serves more than one
// request and that guest state (the counter) survives across calls.
// `__PORT__` is substituted by the test harness with an ephemeral port.

use std::sync::atomic::{AtomicI32, Ordering};

static COUNT: AtomicI32 = AtomicI32::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn afterburner_alloc(len: i32) -> i32 {
    let mut buf = Vec::<u8>::with_capacity(len.max(0) as usize);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn afterburner_dealloc(ptr: i32, len: i32) {
    unsafe {
        drop(Vec::from_raw_parts(ptr as *mut u8, 0, len.max(0) as usize));
    }
}

/// Allocate an owned response buffer, write an 8-byte
/// `[ptr: u32 LE][len: u32 LE]` header for it, and return a pointer to
/// the header - the calling convention every `afterburner_daemon_*`
/// export uses to hand bytes back to the host.
fn respond(bytes: Vec<u8>) -> i32 {
    let mut boxed = bytes.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);

    let mut header = Vec::<u8>::with_capacity(8);
    header.extend_from_slice(&(ptr as u32).to_le_bytes());
    header.extend_from_slice(&(len as u32).to_le_bytes());
    let header_ptr = header.as_ptr() as i32;
    std::mem::forget(header);
    header_ptr
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Pull the value of a `"key":"value"` pair out of a flat JSON blob with a
/// plain substring scan - a real parser is more than this fixture (no
/// crates.io deps available to a bare-rustc single-file build) needs.
fn extract_json_string(haystack: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = haystack.find(&needle)? + needle.len();
    let end = haystack[start..].find('"')?;
    Some(haystack[start..start + end].to_string())
}

#[unsafe(no_mangle)]
pub extern "C" fn afterburner_daemon_init(_ptr: i32, _len: i32) -> i32 {
    respond(br#"{"listen":[{"port":__PORT__}]}"#.to_vec())
}

#[unsafe(no_mangle)]
pub extern "C" fn afterburner_daemon_dispatch(ptr: i32, len: i32) -> i32 {
    let req_bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
    let req_str = String::from_utf8_lossy(req_bytes);
    let url = extract_json_string(&req_str, "url").unwrap_or_default();

    let n = COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    let body = format!("request #{n} path={url}");
    let body_b64 = b64_encode(body.as_bytes());
    let resp = format!(r#"{{"status":200,"headers":{{}},"body_b64":"{body_b64}"}}"#);
    respond(resp.into_bytes())
}

fn main() {}
