// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Psila.AI
// Licensed under the Business Source License 1.1.
// Change Date: 4 years after this version's release. Change License: Apache-2.0.

#![cfg(feature = "bin")]
//! B7 — `tls` raw TLS integration.
//!
//! Each test generates a fresh self-signed cert with `rcgen`, starts
//! a tokio-rustls echo server in a multi-thread runtime on a
//! background thread, then runs `burn` with an inline parent script
//! that opens a TLS connection back to that server. Round-tripping
//! bytes through the rustls handshake validates the full IPC path:
//! `__host_tls_connect` → tokio-rustls handshake → Connect event →
//! daemon-event dispatcher → `socket._dispatchSecureConnect` → user
//! 'secureConnect' callback; same in reverse for the data direction.
//!
//! The burn-as-server test (`burn_serves_tls_and_host_client_echoes`)
//! flips the topology — burn binds, host connects with rustls — to
//! cover the `tls.createServer` path.

use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serial_test::serial;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioListener;
use tokio_rustls::TlsAcceptor;

const BURN: &str = env!("CARGO_BIN_EXE_burn");

/// Test cert + key pair tied to `localhost`. Returned as PEM strings
/// so we can hand them straight to burn (`tls.createServer`) or build
/// a rustls config from them in the test thread.
struct TestCerts {
    cert_pem: String,
    key_pem: String,
    cert_der: CertificateDer<'static>,
}

fn make_test_certs() -> TestCerts {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let cert_der = cert.cert.der().clone();
    TestCerts {
        cert_pem,
        key_pem,
        cert_der,
    }
}

/// Bind a tokio-rustls echo server. Returns the bound port. The
/// server is single-threaded (one connection at a time) — fine for
/// the round-trip tests.
fn spawn_tls_echo_server(certs: &TestCerts) -> u16 {
    // Bind synchronously so the test can return a port before the
    // tokio runtime has fully set up.
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = std_listener.local_addr().expect("local_addr").port();
    std_listener.set_nonblocking(true).expect("set_nonblocking");

    let cert_chain = vec![CertificateDer::from(certs.cert_der.to_vec())];
    let key = parse_pem_key(&certs.key_pem);
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config"),
    );

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async move {
            let tokio_listener = TokioListener::from_std(std_listener).expect("from_std");
            let acceptor = TlsAcceptor::from(server_config);
            loop {
                let (stream, _) = match tokio_listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let mut tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let mut buf = [0u8; 4096];
                    loop {
                        match tls.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if tls.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    // Flush close_notify before dropping so the burn
                    // client side gets a clean EOF rather than a
                    // "peer closed without close_notify" error.
                    let _ = tls.shutdown().await;
                });
            }
        });
    });
    port
}

fn parse_pem_key(pem: &str) -> PrivateKeyDer<'static> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut cursor)
        .expect("private_key parse")
        .expect("private_key present")
}

#[test]
#[serial]
fn round_trip_echo() {
    let certs = make_test_certs();
    let port = spawn_tls_echo_server(&certs);

    let parent = format!(
        r#"
            const tls = require('tls');
            const {{ Buffer }} = require('buffer');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                rejectUnauthorized: false,
            }});
            const got = [];
            sock.on('secureConnect', () => {{
                sock.write(Buffer.from('hello-tls'));
            }});
            sock.on('data', (chunk) => {{
                got.push(chunk);
                const total = Buffer.concat(got).toString('utf8');
                if (total === 'hello-tls') {{
                    console.log('TLS_ROUND_TRIP_OK');
                    sock.end();
                }}
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('client error:', e && e.message || e);
                process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("TLS_ROUND_TRIP_OK"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn handshake_failure_self_signed_with_strict_verification() {
    // Self-signed cert + default rejectUnauthorized=true → rustls
    // rejects the cert during handshake, the polyfill emits 'error'
    // followed by 'close'. The test passes when we see ERR_TLS_HANDSHAKE.
    let certs = make_test_certs();
    let port = spawn_tls_echo_server(&certs);

    let parent = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                // Default is strict — explicitly leave it on.
            }});
            sock.on('error', (e) => {{
                console.log('HANDSHAKE_FAIL code=' + (e.code || 'NONE'));
            }});
            sock.on('close', () => process.exit(0));
            sock.on('secureConnect', () => {{
                console.error('LEAK: handshake succeeded against self-signed cert');
                process.exit(1);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("HANDSHAKE_FAIL"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn destroy_kills_connection() {
    let certs = make_test_certs();
    let port = spawn_tls_echo_server(&certs);

    let parent = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                rejectUnauthorized: false,
            }});
            sock.on('secureConnect', () => {{
                sock.destroy();
            }});
            sock.on('close', () => {{
                console.log('CLOSED_OK destroyed=' + sock.destroyed);
                process.exit(0);
            }});
            sock.on('error', (e) => {{
                console.error('unexpected error:', e.code, e.message);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("CLOSED_OK destroyed=true"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn burn_serves_tls_and_host_client_echoes() {
    // Burn binds the TLS listener; this test thread is the client and
    // talks rustls back to it. Read the bound port off stdout.
    let certs = make_test_certs();

    let parent = format!(
        r#"
            const tls = require('tls');
            const cert = {cert};
            const key = {key};
            const server = tls.createServer({{ cert, key }}, (sock) => {{
                sock.on('data', (chunk) => sock.write(chunk));
                sock.on('end', () => sock.end());
            }});
            server.listen(0, '127.0.0.1', () => {{
                const addr = server.address();
                console.log('PORT=' + addr.port);
            }});
        "#,
        cert = serde_json::to_string(&certs.cert_pem).unwrap(),
        key = serde_json::to_string(&certs.key_pem).unwrap()
    );

    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn server");

    let (port_tx, port_rx) = mpsc::channel::<u16>();
    let stdout = child.stdout.take().expect("piped stdout");
    thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stdout);
        for line in r.lines() {
            let Ok(line) = line else { return };
            if let Some(rest) = line.strip_prefix("PORT=") {
                let p: u16 = rest.parse().expect("port parse");
                let _ = port_tx.send(p);
                return;
            }
        }
    });
    let port = port_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("burn server announced port");

    // Build a rustls client that accepts our self-signed cert by
    // pinning it as the only trusted root.
    let mut roots = RootCertStore::empty();
    roots.add(certs.cert_der.clone()).expect("add root");
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from("localhost").expect("sni");
    let mut conn =
        rustls::ClientConnection::new(Arc::new(client_config), server_name).expect("client conn");
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
    tls.write_all(b"abc-from-host").expect("write");
    let mut got = Vec::new();
    let mut buf = [0u8; 64];
    let want = b"abc-from-host".len();
    while got.len() < want {
        let n = tls.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(&got, b"abc-from-host");
    child.kill().ok();
    child.wait().ok();
}

#[test]
#[serial]
fn alpn_echo_negotiates_protocol() {
    let certs = make_test_certs();
    // Echo server with ALPN advertising "burn-test/1".
    let std_listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = std_listener.local_addr().expect("local_addr").port();
    std_listener.set_nonblocking(true).expect("set_nonblocking");

    let cert_chain = vec![CertificateDer::from(certs.cert_der.to_vec())];
    let key = parse_pem_key(&certs.key_pem);
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("server config");
    server_config.alpn_protocols = vec![b"burn-test/1".to_vec()];
    let server_config = Arc::new(server_config);

    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("rt");
        rt.block_on(async move {
            let tokio_listener = TokioListener::from_std(std_listener).expect("from_std");
            let acceptor = TlsAcceptor::from(server_config);
            if let Ok((stream, _)) = tokio_listener.accept().await
                && let Ok(mut tls) = acceptor.accept(stream).await
            {
                let mut buf = [0u8; 4096];
                while let Ok(n) = tls.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let _ = tls.write_all(&buf[..n]).await;
                }
                let _ = tls.shutdown().await;
            }
        });
    });

    let parent = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                rejectUnauthorized: false,
                ALPNProtocols: ['burn-test/1'],
            }});
            sock.on('secureConnect', () => {{
                console.log('ALPN=' + sock.alpnProtocol);
                console.log('PROTO=' + sock.getProtocol());
                sock.end();
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('client error:', e.message);
                process.exit(2);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("ALPN=burn-test/1"),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("PROTO=TLSv1."),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[test]
#[serial]
fn get_peer_certificate_returns_real_chain() {
    // After the handshake, `socket.getPeerCertificate()` returns the
    // server's leaf certificate (DER bytes + sha256 fingerprint).
    // Verify the bytes match what we generated.
    let certs = make_test_certs();
    let port = spawn_tls_echo_server(&certs);
    let expected_der_b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(certs.cert_der.as_ref())
    };
    let parent = format!(
        r#"
            const tls = require('tls');
            const {{ Buffer }} = require('buffer');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                rejectUnauthorized: false,
            }});
            sock.on('secureConnect', () => {{
                const cert = sock.getPeerCertificate();
                if (!cert.raw || !Buffer.isBuffer(cert.raw)) {{
                    console.error('no raw'); process.exit(2);
                }}
                if (cert.raw.toString('base64') !== {expected_der_b64:?}) {{
                    console.error('cert DER mismatch'); process.exit(3);
                }}
                if (typeof cert.fingerprint256 !== 'string' || !/^[A-F0-9:]+$/.test(cert.fingerprint256)) {{
                    console.error('bad fingerprint:', cert.fingerprint256); process.exit(4);
                }}
                console.log('PEER_CERT_OK fp=' + cert.fingerprint256.slice(0, 11));
                sock.end();
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error('client error:', e.message); process.exit(5);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("PEER_CERT_OK fp="), "stdout:\n{stdout}");
}

#[test]
#[serial]
fn get_cipher_returns_negotiated_suite_name() {
    // rustls negotiates a TLS 1.3 suite by default; the IANA name
    // surfaces as `cipher.name`. We assert the shape (name + version)
    // rather than a specific suite to avoid pinning to one kernel /
    // platform.
    let certs = make_test_certs();
    let port = spawn_tls_echo_server(&certs);
    let parent = format!(
        r#"
            const tls = require('tls');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                rejectUnauthorized: false,
            }});
            sock.on('secureConnect', () => {{
                const c = sock.getCipher();
                if (typeof c.name !== 'string' || c.name === 'unknown') {{
                    console.error('cipher name:', c.name); process.exit(2);
                }}
                if (!/^TLS_/.test(c.name)) {{
                    console.error('cipher name not IANA-shaped:', c.name); process.exit(3);
                }}
                if (c.standardName !== c.name) {{
                    console.error('standardName mismatch:', c.standardName, c.name); process.exit(4);
                }}
                if (!/^TLSv1\./.test(c.version)) {{
                    console.error('version:', c.version); process.exit(5);
                }}
                console.log('CIPHER_OK name=' + c.name + ' version=' + c.version);
                sock.end();
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error(e.message); process.exit(6);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("CIPHER_OK name=TLS_"), "stdout:\n{stdout}");
}

#[test]
#[serial]
fn get_peer_cert_chain_returns_full_chain() {
    // For our self-signed test cert the chain is length 1; assert
    // `getPeerCertChain()` exposes that uniform shape.
    let certs = make_test_certs();
    let port = spawn_tls_echo_server(&certs);
    let parent = format!(
        r#"
            const tls = require('tls');
            const {{ Buffer }} = require('buffer');
            const sock = tls.connect({{
                port: {port},
                host: '127.0.0.1',
                servername: 'localhost',
                rejectUnauthorized: false,
            }});
            sock.on('secureConnect', () => {{
                const chain = sock.getPeerCertChain();
                if (!Array.isArray(chain) || chain.length < 1) {{
                    console.error('chain length:', chain.length); process.exit(2);
                }}
                if (!Buffer.isBuffer(chain[0].raw)) {{
                    console.error('chain[0].raw not Buffer'); process.exit(3);
                }}
                console.log('CHAIN_OK len=' + chain.length);
                sock.end();
            }});
            sock.on('close', () => process.exit(0));
            sock.on('error', (e) => {{
                console.error(e.message); process.exit(4);
            }});
            setTimeout(() => process.exit(99), 30000);
        "#
    );
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("CHAIN_OK len=1"), "stdout:\n{stdout}");
}

/// Generate a self-signed cert pinned to a single SAN. Returns
/// `(cert_pem, key_pem, cert_der)` so the test thread can build a
/// rustls client root store containing exactly that cert.
fn make_named_certs(san: &str) -> (String, String, CertificateDer<'static>) {
    let cert = generate_simple_self_signed(vec![san.into()]).expect("rcgen");
    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();
    let cert_der = cert.cert.der().clone();
    (cert_pem, key_pem, cert_der)
}

/// rustls verifier that captures whatever cert chain the server
/// presents and accepts everything. We use it inside the SNI tests
/// to observe which leaf cert is sent for an arbitrary `server_name`,
/// even when that name doesn't match the cert's SAN.
#[derive(Debug)]
struct CapturingNoVerify;

impl rustls::client::danger::ServerCertVerifier for CapturingNoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Drive a rustls handshake to `port` over TCP and return the leaf
/// certificate the server actually presented. Used to verify SNI
/// routing — caller asserts on the cert bytes. Bypasses hostname
/// verification so we can probe arbitrary SNIs (including ones the
/// fallback default cert won't validate against).
fn fetch_presented_cert(port: u16, server_name: &str) -> Vec<u8> {
    let cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CapturingNoVerify))
        .with_no_client_auth();
    let sni = rustls::pki_types::ServerName::try_from(server_name.to_string()).expect("sni");
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), sni).expect("client conn");
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).expect("tcp connect");
    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .unwrap_or_else(|e| panic!("tls handshake to {server_name}: {e}"));
    }
    let peer = conn.peer_certificates().expect("peer cert chain");
    assert!(!peer.is_empty(), "empty cert chain for {server_name}");
    peer[0].as_ref().to_vec()
}

#[test]
#[serial]
fn sni_routes_distinct_cert_per_servername() {
    // Burn hosts two SNI contexts ('alpha.local' + 'beta.local') over
    // a default cert. Verify each ClientHello with the matching
    // server_name receives its dedicated leaf cert.
    let (def_cert, def_key, def_der) = make_named_certs("default.local");
    let (alpha_cert, alpha_key, alpha_der) = make_named_certs("alpha.local");
    let (beta_cert, beta_key, beta_der) = make_named_certs("beta.local");

    let parent = format!(
        r#"
            const tls = require('tls');
            const server = tls.createServer({{
                cert: {def_cert},
                key: {def_key},
                serverContexts: {{
                    'alpha.local': {{ cert: {alpha_cert}, key: {alpha_key} }},
                    'beta.local':  tls.createSecureContext({{ cert: {beta_cert}, key: {beta_key} }}),
                }},
            }}, (sock) => {{
                sock.on('data', (chunk) => sock.write(chunk));
                sock.on('end', () => sock.end());
            }});
            server.listen(0, '127.0.0.1', () => {{
                console.log('PORT=' + server.address().port);
            }});
        "#,
        def_cert = serde_json::to_string(&def_cert).unwrap(),
        def_key = serde_json::to_string(&def_key).unwrap(),
        alpha_cert = serde_json::to_string(&alpha_cert).unwrap(),
        alpha_key = serde_json::to_string(&alpha_key).unwrap(),
        beta_cert = serde_json::to_string(&beta_cert).unwrap(),
        beta_key = serde_json::to_string(&beta_key).unwrap(),
    );

    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn server");

    let (port_tx, port_rx) = mpsc::channel::<u16>();
    let stdout = child.stdout.take().expect("piped stdout");
    thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stdout);
        for line in r.lines() {
            let Ok(line) = line else { return };
            if let Some(rest) = line.strip_prefix("PORT=") {
                let p: u16 = rest.parse().expect("port parse");
                let _ = port_tx.send(p);
                return;
            }
        }
    });
    let port = port_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("burn announced port");

    let presented_alpha = fetch_presented_cert(port, "alpha.local");
    assert_eq!(
        presented_alpha,
        alpha_der.as_ref().to_vec(),
        "alpha.local SNI should yield alpha cert"
    );
    let presented_beta = fetch_presented_cert(port, "beta.local");
    assert_eq!(
        presented_beta,
        beta_der.as_ref().to_vec(),
        "beta.local SNI should yield beta cert"
    );
    let presented_other = fetch_presented_cert(port, "unknown.local");
    assert_eq!(
        presented_other,
        def_der.as_ref().to_vec(),
        "unknown SNI should fall through to default cert"
    );

    child.kill().ok();
    child.wait().ok();
}

#[test]
#[serial]
fn sni_add_context_works_post_construction() {
    // Same as sni_routes_distinct_cert_per_servername but the SNI
    // context is added *after* the Server is constructed, via
    // `Server.addContext`. Exercises the addContext code path.
    let (def_cert, def_key, def_der) = make_named_certs("default.local");
    let (extra_cert, extra_key, extra_der) = make_named_certs("extra.local");

    let parent = format!(
        r#"
            const tls = require('tls');
            const server = tls.createServer({{ cert: {def_cert}, key: {def_key} }}, (sock) => {{
                sock.on('data', (chunk) => sock.write(chunk));
            }});
            server.addContext('extra.local', tls.createSecureContext({{
                cert: {extra_cert}, key: {extra_key}
            }}));
            server.listen(0, '127.0.0.1', () => {{
                console.log('PORT=' + server.address().port);
            }});
        "#,
        def_cert = serde_json::to_string(&def_cert).unwrap(),
        def_key = serde_json::to_string(&def_key).unwrap(),
        extra_cert = serde_json::to_string(&extra_cert).unwrap(),
        extra_key = serde_json::to_string(&extra_key).unwrap(),
    );

    let mut child = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", &parent])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn burn server");

    let (port_tx, port_rx) = mpsc::channel::<u16>();
    let stdout = child.stdout.take().expect("piped stdout");
    thread::spawn(move || {
        use std::io::BufRead;
        let r = std::io::BufReader::new(stdout);
        for line in r.lines() {
            let Ok(line) = line else { return };
            if let Some(rest) = line.strip_prefix("PORT=") {
                let p: u16 = rest.parse().expect("port parse");
                let _ = port_tx.send(p);
                return;
            }
        }
    });
    let port = port_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("burn announced port");

    let _ = def_der; // silence unused; the default cert isn't asserted on here.
    let presented = fetch_presented_cert(port, "extra.local");
    assert_eq!(presented, extra_der.as_ref().to_vec());

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn ip_helpers() {
    // tls.isIP* re-exports net's helpers — quick smoke test.
    let parent = r#"
        const tls = require('tls');
        const out = [];
        out.push(tls.isIPv4('127.0.0.1'));
        out.push(tls.isIPv6('::1'));
        out.push(tls.isIP('1.2.3.4'));
        console.log('IP=' + JSON.stringify(out));
    "#;
    let out = Command::new(BURN)
        .env("BURN_QUIET", "1")
        .env("BURN_SHARDS", "2")
        .args(["-A", "-e", parent])
        .output()
        .expect("spawn burn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stdout: {stdout}");
    assert!(stdout.contains("IP=[true,true,4]"), "stdout: {stdout}");
}
