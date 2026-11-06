//! HTTP/3 over the adapter on one nuclei shard: a request with a body and its response, a
//! request the server stops, and the client's close once its last sender drops. Every QUIC
//! stream kind the adapter wraps carries traffic: the requests' bidirectional streams, and the
//! control and QPACK unidirectional streams each side opens.

use std::future::poll_fn;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::error::{Code, ConnectionError, LocalError, StreamError};
use h3_quinn::quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use h3_quinn::quinn::{self, EndpointConfig, NucleiRuntime};
use nuclei::RuntimeHandle;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn endpoint(server_config: Option<quinn::ServerConfig>) -> quinn::Endpoint {
    quinn::Endpoint::new(
        EndpointConfig::default(),
        server_config,
        UdpSocket::bind("[::1]:0").unwrap(),
        NucleiRuntime::new(RuntimeHandle::current()),
    )
    .unwrap()
}

/// A server endpoint, a client endpoint that trusts it, and the server's port.
fn endpoints() -> (quinn::Endpoint, quinn::Endpoint, u16) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = CertificateDer::from(certified.cert);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let server = endpoint(Some(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_crypto).unwrap(),
    ))));
    let port = server.local_addr().unwrap().port();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = endpoint(None);
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_crypto).unwrap(),
    )));
    (server, client, port)
}

async fn read_body<S: h3::quic::RecvStream>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
) -> Vec<u8> {
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    body
}

#[nuclei::test(threads = 0)]
async fn requests_responses_resets_and_the_close_cross_the_adapter() {
    let (server, client, port) = endpoints();

    let server_side = async {
        let conn = server.accept().await.unwrap().await.unwrap();
        let mut conn = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();

        let resolver = conn.accept().await.unwrap().unwrap();
        let (request, mut stream) = resolver.resolve_request().await.unwrap();
        assert_eq!(request.uri().path(), "/echo");
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        body.reverse();
        stream
            .send_response(http::Response::builder().status(200).body(()).unwrap())
            .await
            .unwrap();
        stream.send_data(Bytes::from(body)).await.unwrap();
        stream.finish().await.unwrap();

        let resolver = conn.accept().await.unwrap().unwrap();
        let (_, mut stream) = resolver.resolve_request().await.unwrap();
        stream.stop_stream(Code::H3_REQUEST_CANCELLED);

        // The client closes once its last sender drops; the server sees that close.
        let Err(closed) = conn.accept().await else {
            panic!("the client closes the connection");
        };
        assert!(
            closed.is_h3_no_error(),
            "the server sees the client's close: {closed:?}"
        );
    };

    let client_side = async {
        let addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();

        let requests = async move {
            let mut stream = sender
                .send_request(
                    http::Request::post("https://localhost/echo")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream
                .send_data(Bytes::from_static(b"nuclei"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(read_body(&mut stream).await, b"ielcun");

            let mut stream = sender
                .send_request(
                    http::Request::get("https://localhost/stopped")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let Err(stopped) = stream.recv_response().await else {
                panic!("the server stops the request");
            };
            assert!(
                matches!(stopped, StreamError::RemoteTerminate { code, .. } if code == Code::H3_REQUEST_CANCELLED),
                "the server's stop reaches the client: {stopped:?}"
            );
            // Dropping the last sender closes the connection.
        };

        let (closed, ()) = futures::join!(poll_fn(|cx| driver.poll_close(cx)), requests);
        assert!(
            matches!(
                &closed,
                ConnectionError::Local {
                    error: LocalError::Application { code, .. },
                    ..
                } if *code == Code::H3_NO_ERROR
            ),
            "the client closes with H3_NO_ERROR: {closed:?}"
        );
    };

    futures::join!(server_side, client_side);
}
