use afterburner_cloud::{CloudError, RegistryClient, cache};
use httpmock::prelude::*;
use serde_json::json;

fn anon(server: &MockServer) -> RegistryClient {
    RegistryClient::new(server.base_url(), None)
}
fn authed(server: &MockServer) -> RegistryClient {
    RegistryClient::with_token(server.base_url(), "afbpat_test")
}

#[test]
fn search_parses_results() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/packages")
            .query_param("q", "claude");
        then.status(200).json_body(json!({
            "count": 1,
            "packages": [{
                "namespace": "burn", "name": "anthropic", "description": "Claude",
                "downloads": 12, "keywords": ["llm"], "latest": "0.1.0"
            }]
        }));
    });
    let res = anon(&server).search("claude").unwrap();
    m.assert();
    assert_eq!(res.count, 1);
    assert_eq!(res.packages[0].name, "anthropic");
    assert_eq!(res.packages[0].latest.as_deref(), Some("0.1.0"));
}

#[test]
fn get_package_exposes_digest_for_version() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/packages/burn/anthropic");
        then.status(200).json_body(json!({
            "namespace": "burn", "name": "anthropic", "latest": "0.1.0",
            "versions": [{"version": "0.1.0", "digest": "abcd", "size_bytes": 10, "yanked": false}]
        }));
    });
    let meta = anon(&server).get_package("burn", "anthropic").unwrap();
    assert_eq!(meta.digest_for("0.1.0"), Some("abcd"));
    assert_eq!(meta.digest_for("9.9.9"), None);
}

#[test]
fn login_returns_token() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/login");
        then.status(200)
            .json_body(json!({"token": "afbpat_xyz", "username": "admin", "is_admin": true}));
    });
    let r = anon(&server).login("admin", "pw").unwrap();
    assert_eq!(r.token, "afbpat_xyz");
    assert!(r.is_admin);
}

#[test]
fn me_sends_bearer_and_unauth_errors_client_side() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/me")
            .header("authorization", "Bearer afbpat_test");
        then.status(200)
            .json_body(json!({"username": "admin", "is_admin": false}));
    });
    assert_eq!(authed(&server).me().unwrap().username, "admin");
    // No token configured -> fail before any request is made.
    assert!(matches!(
        anon(&server).me().unwrap_err(),
        CloudError::NotLoggedIn
    ));
}

#[test]
fn publish_ok_with_bearer() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/publish")
            .header("authorization", "Bearer afbpat_test");
        then.status(200).json_body(json!({
            "namespace": "acme", "name": "hello", "version": "0.1.0", "digest": "ff", "size_bytes": 5
        }));
    });
    let r = authed(&server).publish(b"afbbytes").unwrap();
    m.assert();
    assert_eq!(r.digest, "ff");
}

#[test]
fn publish_conflict_maps_to_conflict() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/publish");
        then.status(409)
            .json_body(json!({"error": "version exists"}));
    });
    let err = authed(&server).publish(b"x").unwrap_err();
    assert!(matches!(err, CloudError::Conflict(_)));
}

#[test]
fn yank_adds_undo_query() {
    let server = MockServer::start();
    let m = server.mock(|when, then| {
        when.method(POST)
            .path("/api/v1/packages/acme/hello/0.1.0/yank")
            .query_param("undo", "true")
            .header("authorization", "Bearer afbpat_test");
        then.status(200).json_body(json!({
            "namespace": "acme", "name": "hello", "version": "0.1.0", "yanked": false
        }));
    });
    let r = authed(&server)
        .yank("acme", "hello", "0.1.0", true)
        .unwrap();
    m.assert();
    assert!(!r.yanked);
}

#[test]
fn download_returns_bytes() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/packages/p/n/0.1.0/download");
        then.status(200).body("afbdata");
    });
    assert_eq!(
        anon(&server).download("p", "n", "0.1.0").unwrap(),
        b"afbdata"
    );
}

#[test]
fn forbidden_status_maps() {
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET);
        then.status(403).body("nope");
    });
    let err = anon(&server).download("p", "n", "0.1.0").unwrap_err();
    assert!(matches!(err, CloudError::Forbidden));
}

#[test]
fn cache_rejects_wrong_digest() {
    let wrong = "0".repeat(64);
    let err = cache::verify_and_store(&wrong, b"not that content").unwrap_err();
    assert!(matches!(err, CloudError::DigestMismatch { .. }));
}

#[test]
fn afb_size_cap_is_in_sync_with_the_registry() {
    // The registry caps a published .afb at 50 MiB (afterburner-registry
    // src/afb/mod.rs). The client's afb crate must match, or downloads/installs
    // would reject packages the registry happily serves.
    assert_eq!(
        afterburner_cloud::afterburner_afb::MAX_AFB_BYTES,
        50 * 1024 * 1024
    );
}
