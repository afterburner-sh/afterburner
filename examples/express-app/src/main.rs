//! Real HTTP server (nuclei) that dispatches every request to
//! a real Express.js app running inside Afterburner.
//!
//! Setup:
//!
//! ```text
//! $ cd examples/express-app
//! $ npm install        # populates ./node_modules/express + transitive deps
//! $ cargo run --release
//! listening on http://127.0.0.1:3000
//!
//! $ curl http://127.0.0.1:3000/
//! $ curl http://127.0.0.1:3000/health
//! $ curl http://127.0.0.1:3000/hello/world
//! $ curl -X POST -H 'Content-Type: application/json' -d '[1,2,3]' http://127.0.0.1:3000/sum
//! ```
//!
//! Pipeline:
//!
//! * A nuclei listener accepts connections; each one is a nuclei task.
//! * Each request serialises to a JSON envelope and calls
//!   `Afterburner::run` on nuclei's blocking pool. Because the Afterburner
//!   is built with `threaded(N)`, those calls fan into the N-worker
//!   scheduler; concurrent requests execute on different workers.
//! * Inside the sandbox, `app.js` does `const express = require('express')`
//!   Afterburner's CommonJS resolver walks up from the example dir
//!   and reads `node_modules/express/...` via the host fs bridge,
//!   gated by the `Manifold` we install below.
//! * JS state is fresh per call (Afterburner invariant). Sessions /
//!   long-lived state must live host-side and ride the envelope.

use afterburner::{Afterburner, FsAccess, Manifold};
use anyhow::{Context, Result};
use nuclei::io::{AsyncReadExt, AsyncWriteExt};
use nuclei::net::{TcpListener, TcpStream};
use serde_json::{Map, Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

const JS_APP: &str = include_str!("app.js");
const BODY_LIMIT: usize = 1 << 20; // 1 MiB
const HEAD_LIMIT: usize = 64 << 10; // 64 KiB

struct AppState {
    ab: Arc<Afterburner>,
    script_id: afterburner::ScriptId,
}

/// A parsed HTTP/1.1 request: head fields plus the whole body.
struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// The response written back: status, headers and body bytes.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn text(status: u16, msg: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "text/plain; charset=utf-8".into())],
            body: msg.into().into_bytes(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.body.len() + 256);
        out.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", self.status, reason(self.status)).as_bytes(),
        );
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "content-length: {}\r\nconnection: close\r\n\r\n",
                self.body.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(&self.body);
        out
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        _ => "",
    }
}

fn main() -> Result<()> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(8);

    // Resolve the example root (the dir containing `package.json` +
    // `node_modules`). `Afterburner::builder().cwd(path)` pins the
    // require resolver to walk `node_modules` from here.
    let example_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let node_modules = example_root.join("node_modules");
    if !node_modules.is_dir() {
        anyhow::bail!(
            "missing {}\n\nThis example uses the real `express` npm package.\n\
             From this directory, run:\n\n    npm install\n\n\
             Then retry `cargo run --release`.",
            node_modules.display()
        );
    }

    eprintln!("afterburner-example-express-app");
    eprintln!("  thrust workers: {workers}");
    eprintln!("  cwd:            {}", example_root.display());

    // Read-only fs grant scoped to the example root + crypto for
    // Express's transitive deps. The `etag` npm package (used by
    // `res.send` to generate response ETags) calls
    // `crypto.createHash('sha1')`. body-parser uses crypto for
    // signed cookies. Sealed manifold (the default) blocks both.
    // Net, env, child_process, exit all stay denied.
    let manifold = Manifold {
        fs: FsAccess::ReadOnly(vec![example_root.clone()]),
        crypto: true,
        ..Manifold::sealed()
    };

    // Manifold goes BEFORE threaded(): `ThreadedBuilder` doesn't
    // expose .manifold (typed-builder discipline). cwd is on the
    // base builder too and propagates into the threaded variant.
    let ab = Afterburner::builder()
        .manifold(manifold)
        .cwd(example_root.clone())
        .threaded(workers)
        .build()
        .context("build afterburner")?;

    let script_id = ab.register(JS_APP).context("register app.js")?;
    let state = Arc::new(AppState {
        ab: Arc::new(ab),
        script_id,
    });

    let rt = nuclei::Runtime::new().context("nuclei runtime")?;
    rt.block_on(serve(state))
}

async fn serve(state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:3000").await?;
    eprintln!("  listening on http://{}", listener.local_addr()?);

    // Dropping a nuclei task cancels it: ctrl-c ends the accept loop.
    let accept = nuclei::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => nuclei::spawn(serve_conn(stream, state.clone())).detach(),
                Err(e) => {
                    eprintln!("  accept failed: {e}");
                    return;
                }
            }
        }
    });
    let _ = nuclei::signal::ctrl_c().await;
    eprintln!("  shutting down…");
    drop(accept);
    Ok(())
}

async fn serve_conn(mut stream: TcpStream, state: Arc<AppState>) {
    let reply = match read_request(&mut stream).await {
        Ok(req) => dispatch(&state, req).await,
        Err((status, msg)) => Reply::text(status, msg),
    };
    let _ = stream.write_all(&reply.encode()).await;
    let _ = stream.shutdown().await;
}

fn find(hay: &[u8], pat: &[u8]) -> Option<usize> {
    hay.windows(pat.len()).position(|w| w == pat)
}

/// The request head once `\r\n\r\n` has arrived: the request plus the
/// length of the head, or `None` while it is still incomplete.
fn parse_head(buf: &[u8]) -> Result<Option<(Request, usize)>, (u16, String)> {
    let bad = |m: &str| (400, m.to_string());
    let Some(end) = find(buf, b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end]).map_err(|_| bad("request head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(_version)) = (first.next(), first.next(), first.next())
    else {
        return Err(bad("malformed request line"));
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers = Vec::new();
    for line in lines {
        let (k, v) = line.split_once(':').ok_or_else(|| bad("malformed header"))?;
        headers.push((k.trim().to_lowercase(), v.trim().to_string()));
    }
    let req = Request {
        method: method.to_string(),
        path: path.to_string(),
        query: query.to_string(),
        headers,
        body: Vec::new(),
    };
    Ok(Some((req, end + 4)))
}

/// A complete chunked body, or `None` while more bytes are needed.
fn decode_chunked(mut b: &[u8]) -> Result<Option<Vec<u8>>, (u16, String)> {
    let mut out = Vec::new();
    loop {
        let Some(p) = find(b, b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&b[..p]).map_err(|_| (400, "bad chunk size".to_string()))?;
        let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| (400, "bad chunk size".to_string()))?;
        b = &b[p + 2..];
        if size == 0 {
            let done = b.starts_with(b"\r\n") || find(b, b"\r\n\r\n").is_some();
            return Ok(done.then_some(out));
        }
        if out.len().saturating_add(size) > BODY_LIMIT {
            return Err((413, format!("body exceeds {BODY_LIMIT} bytes")));
        }
        if b.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<Request, (u16, String)> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 8192];
    let (mut req, head_len) = loop {
        if let Some(parsed) = parse_head(&buf)? {
            break parsed;
        }
        if buf.len() > HEAD_LIMIT {
            return Err((431, "request head too large".into()));
        }
        fill(stream, &mut buf, &mut chunk).await?;
    };

    let header = |name: &str| {
        req.headers
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    let chunked = header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let len = match header("content-length") {
        Some(v) if !chunked => v
            .parse::<usize>()
            .map_err(|_| (400, "bad content-length".to_string()))?,
        _ => 0,
    };
    if len > BODY_LIMIT {
        return Err((413, format!("body exceeds {BODY_LIMIT} bytes")));
    }

    req.body = if chunked {
        loop {
            if let Some(body) = decode_chunked(&buf[head_len..])? {
                break body;
            }
            fill(stream, &mut buf, &mut chunk).await?;
        }
    } else {
        while buf.len() - head_len < len {
            fill(stream, &mut buf, &mut chunk).await?;
        }
        buf[head_len..head_len + len].to_vec()
    };
    Ok(req)
}

async fn fill(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    chunk: &mut [u8],
) -> Result<(), (u16, String)> {
    match stream.read(chunk).await {
        Ok(0) | Err(_) => Err((400, "connection closed before the request was complete".into())),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
    }
}

async fn dispatch(state: &AppState, req: Request) -> Reply {
    let started = Instant::now();
    let envelope = build_envelope(&req);

    // `run` blocks, so it goes to nuclei's blocking pool and the
    // connection tasks keep flowing.
    let ab = state.ab.clone();
    let id = state.script_id;
    let out = nuclei::spawn_blocking(move || ab.run(&id, &envelope))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"));

    match out {
        Ok(v) => {
            let resp = shape_response(v);
            eprintln!(
                "  {} {} → {} ({:?})",
                req.method,
                req.path,
                resp.status,
                started.elapsed()
            );
            resp
        }
        Err(e) => {
            eprintln!("  {} {} → 500 (handler error: {e})", req.method, req.path);
            Reply::text(500, format!("{e}"))
        }
    }
}

fn build_envelope(req: &Request) -> Value {
    // Header keys are already lowercased, matching Express's
    // convention.
    let hdrs: Map<String, Value> = req
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();

    // Try to parse body as JSON; fall back to a string so text/html
    // endpoints still work.
    let body = if req.body.is_empty() {
        Value::Null
    } else if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
        v
    } else {
        Value::String(String::from_utf8_lossy(&req.body).into_owned())
    };

    json!({
        "method": req.method,
        "path": req.path,
        "query": req.query,
        "headers": Value::Object(hdrs),
        "body": body,
    })
}

fn shape_response(v: Value) -> Reply {
    let obj = v.as_object();
    let status = obj
        .and_then(|o| o.get("status"))
        .and_then(|s| s.as_u64())
        .filter(|s| (100..1000).contains(s))
        .unwrap_or(200) as u16;

    let headers_map = obj
        .and_then(|o| o.get("headers"))
        .and_then(|h| h.as_object())
        .cloned()
        .unwrap_or_default();

    let body = obj.and_then(|o| o.get("body")).cloned().unwrap_or(Value::Null);

    // Serialize the response body per `content-type`. If the JS set
    // one, honor it. Otherwise default to JSON.
    let ct = headers_map
        .get("content-type")
        .and_then(|c| c.as_str())
        .unwrap_or("application/json");

    let (body_bytes, content_type): (Vec<u8>, String) = if ct.starts_with("application/json") {
        (serde_json::to_vec(&body).unwrap_or_default(), ct.to_string())
    } else if let Some(s) = body.as_str() {
        (s.as_bytes().to_vec(), ct.to_string())
    } else {
        (
            serde_json::to_vec(&body).unwrap_or_default(),
            "application/json".to_string(),
        )
    };

    let mut headers = vec![("content-type".to_string(), content_type)];
    for (k, v) in &headers_map {
        // The framing headers are ours; a value with a line break would
        // split the response.
        if matches!(
            k.as_str(),
            "content-type" | "content-length" | "transfer-encoding" | "connection"
        ) {
            continue;
        }
        let valid_name = !k.is_empty()
            && k.bytes()
                .all(|b| b.is_ascii_graphic() && b != b':' && b != b'(' && b != b')');
        if let Some(s) = v.as_str()
            && valid_name
            && !s.contains(['\r', '\n'])
        {
            headers.push((k.clone(), s.to_string()));
        }
    }
    Reply {
        status,
        headers,
        body: body_bytes,
    }
}
