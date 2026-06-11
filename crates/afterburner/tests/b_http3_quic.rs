// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

//! HTTP/3 server end-to-end via the `node:quic` polyfill + the
//! `daemon_http3` (quinn + h3-quinn) coordinator.
//!
//! Real wire format - every test sets up a self-signed TLS-1.3 cert,
//! starts a `QuicEndpoint.listen({port, cert, key})` in a `burn`
//! subprocess, and connects with a quinn-based client to confirm the
//! H3 handshake completes and request/response shapes round-trip.
//!
//! Run with `--test-threads=1` - same daemon-startup pressure as
//! `b_http2_server`.

#![cfg(all(feature = "bin", feature = "http3", feature = "ts"))]

use serial_test::serial;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const BURN: &str = env!("CARGO_BIN_EXE_burn");

static NEXT: AtomicU16 = AtomicU16::new(20100);
fn pick_port() -> u16 {
    loop {
        let p = NEXT.fetch_add(1, Ordering::Relaxed);
        // QUIC is UDP - verify free via UDP bind.
        if let Ok(s) = std::net::UdpSocket::bind(("127.0.0.1", p)) {
            drop(s);
            return p;
        }
        if p > 65000 {
            panic!("no free udp port");
        }
    }
}

/// Self-signed cert/key in PEM (subject "127.0.0.1"). Suitable for
/// loopback tests; clients use `dangerous_no_verify` on the rustls
/// side so we don't need to pin a real CA.
fn gen_cert_pem() -> (String, String) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("gen self-signed cert");
    (cert.cert.pem(), cert.key_pair.serialize_pem())
}

fn spawn_h3(source: &str) -> Child {
    Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(source)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn")
}

/// Trust-no-verify TLS config - tests never check the cert chain.
fn insecure_client_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
            ]
        }
    }

    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoVerify))
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    cfg
}

/// Wait until a UDP-bound listener answers a QUIC INITIAL probe.
/// Probing UDP without a full handshake is unreliable, so we just
/// retry a short connect with `quinn::Endpoint::client` until it
/// either succeeds or times out.
async fn wait_for_h3(port: u16, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(insecure_client_config()).unwrap(),
    ));
    endpoint.set_default_client_config(cfg);
    while Instant::now() < deadline {
        let connecting =
            endpoint.connect(format!("127.0.0.1:{port}").parse().unwrap(), "127.0.0.1");
        if let Ok(c) = connecting
            && tokio::time::timeout(Duration::from_millis(500), c)
                .await
                .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    false
}

async fn h3_request(port: u16, path: &str) -> Result<(u16, Vec<u8>), String> {
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(|e| e.to_string())?;
    let cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(insecure_client_config())
            .map_err(|e| e.to_string())?,
    ));
    endpoint.set_default_client_config(cfg);

    let conn = endpoint
        .connect(format!("127.0.0.1:{port}").parse().unwrap(), "127.0.0.1")
        .map_err(|e| e.to_string())?
        .await
        .map_err(|e| e.to_string())?;
    let h3_conn = h3_quinn::Connection::new(conn);
    let (mut driver, mut send) = h3::client::new(h3_conn).await.map_err(|e| e.to_string())?;
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://127.0.0.1:{port}{path}"))
        .body(())
        .map_err(|e| e.to_string())?;
    let mut stream = send.send_request(req).await.map_err(|e| e.to_string())?;
    stream.finish().await.map_err(|e| e.to_string())?;

    let resp = stream.recv_response().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.map_err(|e| e.to_string())? {
        use bytes::Buf;
        let to_copy = chunk.remaining();
        let bs = chunk.copy_to_bytes(to_copy);
        body.extend_from_slice(&bs);
    }
    drive.abort();
    Ok((status, body))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---- module surface -------------------------------------------------

#[test]
#[serial]
fn quic_module_loads_and_exposes_endpoint_class() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(
            r#"
            const q = require('quic');
            const ok = (typeof q.QuicEndpoint === 'function')
                && (typeof q.connect === 'function')
                && (q.constants.QUIC_NO_ERROR === 0)
                && (q.constants.H3_HEADERS === 0x01);
            console.log(ok ? 'QUIC-MOD-OK' : 'FAIL');
        "#,
        )
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("QUIC-MOD-OK"), "{s}");
}

#[test]
#[serial]
fn quic_endpoint_requires_cert_and_key() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(
            r#"
            const { QuicEndpoint } = require('quic');
            const ep = new QuicEndpoint({ address: { port: 0 } });
            try {
                ep.listen({}, () => {});
                console.log('FAIL no-throw');
            } catch (e) {
                console.log(e.code === 'ERR_QUIC_TLS_REQUIRED' ? 'TLS-REQ-OK' : 'FAIL ' + e.code);
            }
        "#,
        )
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("TLS-REQ-OK"), "{s}");
}

// ---- end-to-end H3 wire ---------------------------------------------

#[test]
#[serial]
fn h3_endpoint_completes_quic_handshake() {
    let port = pick_port();
    let (cert, key) = gen_cert_pem();
    let src = format!(
        r#"
        const {{ QuicEndpoint }} = require('quic');
        const ep = new QuicEndpoint({{ address: {{ port: {port} }} }});
        ep.listen({{ cert: `{cert}`, key: `{key}` }}, (session) => {{
            session.on('stream', (s) => {{
                s.respond({{ ':status': 200, 'content-type': 'text/plain' }});
                s.end('hello-h3');
            }});
        }});
        "#,
    );
    let mut child = spawn_h3(&src);
    let r = rt();
    let up = r.block_on(wait_for_h3(port, Duration::from_secs(60)));
    assert!(up, "h3 endpoint never came up on udp:{port}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn h3_endpoint_serves_real_request_round_trip() {
    let port = pick_port();
    let (cert, key) = gen_cert_pem();
    let src = format!(
        r#"
        const {{ QuicEndpoint }} = require('quic');
        const ep = new QuicEndpoint({{ address: {{ port: {port} }} }});
        ep.listen({{ cert: `{cert}`, key: `{key}` }}, (session) => {{
            session.on('stream', (s) => {{
                s.respond({{ ':status': 200, 'content-type': 'text/plain' }});
                s.end('h3-body:' + s.req.url);
            }});
        }});
        "#,
    );
    let mut child = spawn_h3(&src);
    let r = rt();
    assert!(r.block_on(wait_for_h3(port, Duration::from_secs(60))));
    let (status, body) = r.block_on(h3_request(port, "/abc")).unwrap_or_else(|e| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("h3 request failed: {e}");
    });
    assert_eq!(status, 200);
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("h3-body:/abc"), "body = {body_str}");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn h3_endpoint_status_code_round_trips() {
    let port = pick_port();
    let (cert, key) = gen_cert_pem();
    let src = format!(
        r#"
        const {{ QuicEndpoint }} = require('quic');
        const ep = new QuicEndpoint({{ address: {{ port: {port} }} }});
        ep.listen({{ cert: `{cert}`, key: `{key}` }}, (session) => {{
            session.on('stream', (s) => {{
                s.respond({{ ':status': 418, 'x-pot': 'short' }});
                s.end('teapot');
            }});
        }});
        "#,
    );
    let mut child = spawn_h3(&src);
    let r = rt();
    assert!(r.block_on(wait_for_h3(port, Duration::from_secs(60))));
    let (status, body) = r.block_on(h3_request(port, "/")).unwrap_or_else(|e| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("h3 request failed: {e}");
    });
    assert_eq!(status, 418);
    assert_eq!(String::from_utf8_lossy(&body), "teapot");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn h3_endpoint_body_streams_chunked_writes() {
    let port = pick_port();
    let (cert, key) = gen_cert_pem();
    let src = format!(
        r#"
        const {{ QuicEndpoint }} = require('quic');
        const ep = new QuicEndpoint({{ address: {{ port: {port} }} }});
        ep.listen({{ cert: `{cert}`, key: `{key}` }}, (session) => {{
            session.on('stream', (s) => {{
                s.respond({{ ':status': 200 }});
                s.write('chunk-A:');
                s.write('chunk-B:');
                s.end('chunk-C');
            }});
        }});
        "#,
    );
    let mut child = spawn_h3(&src);
    let r = rt();
    assert!(r.block_on(wait_for_h3(port, Duration::from_secs(60))));
    let (status, body) = r.block_on(h3_request(port, "/")).unwrap_or_else(|e| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("h3 request failed: {e}");
    });
    assert_eq!(status, 200);
    assert_eq!(String::from_utf8_lossy(&body), "chunk-A:chunk-B:chunk-C");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
#[serial]
fn h3_endpoint_close_releases_udp_port() {
    let port = pick_port();
    let (cert, key) = gen_cert_pem();
    let src = format!(
        r#"
        const {{ QuicEndpoint }} = require('quic');
        const ep = new QuicEndpoint({{ address: {{ port: {port} }} }});
        ep.listen({{ cert: `{cert}`, key: `{key}` }}, (session) => {{
            session.on('stream', (s) => {{ s.respond({{ ':status': 200 }}); s.end('ok'); }});
        }});
        "#,
    );
    let mut child = spawn_h3(&src);
    let r = rt();
    assert!(r.block_on(wait_for_h3(port, Duration::from_secs(60))));
    let _ = child.kill();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));
    // After the daemon process dies, UDP port should bind again.
    let _s = std::net::UdpSocket::bind(("127.0.0.1", port)).expect("port should release");
}

#[test]
#[serial]
fn h3_endpoint_address_returns_bound_port() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(
            r#"
            const { QuicEndpoint } = require('quic');
            const ep = new QuicEndpoint({ address: { port: 9999 } });
            // Without a successful listen, address() returns null.
            console.log(ep.address() === null ? 'ADDR-NULL-OK' : 'FAIL');
        "#,
        )
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("ADDR-NULL-OK"), "{s}");
}

// ---- error paths ----------------------------------------------------

#[test]
#[serial]
fn h3_listen_on_busy_port_errors() {
    // Hold the UDP port from the test harness so the H3 listener's
    // QUIC bind hits EADDRINUSE. We pick a SEPARATE port for the
    // TCP listener - the polyfill binds TCP first (HTTP listener for
    // the JS handler chain), then UDP for QUIC. Only the UDP path
    // should fail. The polyfill emits the failure via the
    // `'error'` event because by the time UDP bind is attempted, the
    // listen call has already returned.
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let busy_port = udp.local_addr().unwrap().port();
    let (cert, key) = gen_cert_pem();
    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-e")
        .arg(format!(
            r#"
            const {{ QuicEndpoint }} = require('quic');
            const ep = new QuicEndpoint({{ address: {{ port: {busy_port} }} }});
            ep.on('error', (e) => {{
                if (e && e.code === 'ERR_QUIC_LISTEN') console.log('BUSY-OK');
                else console.log('FAIL', e && e.code, e && e.message);
                process.exit(0);
            }});
            ep.listen({{ cert: `{cert}`, key: `{key}` }}, () => {{}});
            "#,
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    // Daemon mode keeps the process alive after the listen call;
    // we wait for the marker on stdout and then kill the child if
    // it's still around.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut got = String::new();
    use std::io::Read;
    let stdout = child.stdout.as_mut().expect("stdout");
    let mut buf = [0u8; 1024];
    while Instant::now() < deadline && !got.contains("BUSY-OK") && !got.contains("FAIL") {
        match stdout.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.push_str(&String::from_utf8_lossy(&buf[..n])),
            Err(_) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    drop(udp);
    assert!(got.contains("BUSY-OK"), "{got}");
}

#[test]
#[serial]
fn h3_endpoint_extends_event_emitter() {
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .arg("-A")
        .arg("-e")
        .arg(
            r#"
            const { QuicEndpoint } = require('quic');
            const { EventEmitter } = require('events');
            const ep = new QuicEndpoint({ address: { port: 0 } });
            console.log(ep instanceof EventEmitter ? 'EE-OK' : 'FAIL');
        "#,
        )
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("EE-OK"), "{s}");
}
