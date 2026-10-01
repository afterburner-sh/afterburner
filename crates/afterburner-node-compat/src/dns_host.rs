// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 vertexclique
// Licensed under the Business Source License 1.1.
// Change Date: 10 years after this version's release. Change License: Apache-2.0.

//! `dns` host functions - synchronous lookups built on `hickory-resolver`
//! and `ToSocketAddrs`. We have no event loop, and the plugin can't
//! host-call from inside an async stack (it's running synchronously
//! inside Wasmtime), so every entry point here runs the actual
//! resolver call on a short-lived worker thread and `select!`s on
//! the result vs. an `after()` timer. The configurable cap lives on
//! the `Manifold` (`http_timeout_ms` is shared across all
//! network-adjacent host ops; DNS piggybacks on it).
//!
//! ### Coverage
//!
//! * `lookup` - A/AAAA via `ToSocketAddrs` (matches Node's default
//!   `lookup` semantics: first IP, family detected).
//! * `resolve4` / `resolve6` - A / AAAA via hickory.
//! * `resolve_mx` - MX records `[{exchange, priority}]`.
//! * `resolve_txt` - TXT records `[["fragment", ...]]` (Node's
//!   "array of arrays" shape - TXT records can have multiple
//!   character-strings per record).
//! * `resolve_cname` - CNAME chain.
//! * `resolve_ns` - NS records.
//! * `reverse` - PTR (reverse-IP → hostname).
//!
//! ### Timeouts (P5)
//!
//! A hung resolver can otherwise wedge the calling thread forever.
//! Same `kovan_channel::select!` pattern as `lookup`. If the timeout
//! fires, we return a typed `AfterburnerError::Host` - the detached
//! worker thread is orphaned and cleans itself up when the resolver
//! eventually returns.

use afterburner_core::governance::helper_governance;
use afterburner_core::{AfterburnerError, Manifold, NetAccess, Result};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use kovan_channel::flavors::after::after;
use kovan_channel::{bounded, select};
use std::future::Future;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// Default per-call resolver timeout when the Manifold doesn't supply
/// one. Matches the HTTP default (30 s) - DNS is usually sub-second,
/// but adversarial or misconfigured resolvers can stall indefinitely
/// without a hard cap.
const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_secs(30);

fn check_net(m: &Manifold, label: &str) -> Result<()> {
    if matches!(m.net, NetAccess::None) {
        Err(AfterburnerError::PermissionDenied(label.to_string()))
    } else {
        Ok(())
    }
}

fn timeout(m: &Manifold) -> Duration {
    m.http_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_DNS_TIMEOUT)
}

/// Run `f` on a worker thread and `select!` on its result vs. the
/// configured timeout. Same pattern shared by every entry below -
/// keeping it factored out drops a hundred lines of boilerplate and
/// guarantees uniform timeout semantics. The worker is governed (T7):
/// named and subordinated per whatever
/// `afterburner_core::governance::set_helper_governance` last installed
/// for this process, or ungoverned by default. A governance failure
/// (e.g. a denied affinity) fails this call loudly rather than silently
/// running the resolver ungoverned.
fn with_timeout<T, F>(m: &Manifold, label: String, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let (tx, rx) = bounded::<Result<T>>(1);
    let name = helper_governance().thread_name("afterburner-dns-resolve", "");
    crate::governance::spawn_governed(name, move || {
        tx.send(f());
    })?;
    let timer = after(timeout(m));
    select! {
        got = rx => got,
        _tick = timer => Err(AfterburnerError::Host(format!(
            "{label}: timed out after {}ms",
            timeout(m).as_millis()
        ))),
    }
}

/// Drive a hickory future to completion on a throwaway single-thread
/// runtime. hickory 0.26 is async-only; every caller already runs on a
/// short-lived worker thread (see [`with_timeout`]), so a per-call
/// current-thread runtime keeps the synchronous host-call model.
fn block_on<T>(fut: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| AfterburnerError::Host(format!("dns: runtime init: {e}")))?
        .block_on(fut)
}

/// Build a hickory `Resolver`. When `servers` is non-empty, build a
/// `ResolverConfig` from those addresses (UDP+TCP, port 53 default
/// unless the address already specifies one). When empty, fall back
/// to the system `/etc/resolv.conf` and finally to Cloudflare. We
/// build per-call rather than caching: avoiding a global resolver
/// keeps the code simpler and the `Resolver` constructor is cheap
/// (~microseconds; no I/O until a lookup runs). Must run inside a
/// tokio runtime (see [`block_on`]).
fn make_resolver(servers: &[String]) -> Result<TokioResolver> {
    use hickory_resolver::config::{
        CLOUDFLARE, ConnectionConfig, NameServerConfig, ResolverConfig,
    };
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    let provider = TokioRuntimeProvider::default();
    if !servers.is_empty() {
        let mut name_servers = Vec::new();
        for s in servers {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Accept "1.1.1.1", "1.1.1.1:53", or "[::1]:53" forms.
            let addr: std::net::SocketAddr = match trimmed.parse() {
                Ok(a) => a,
                Err(_) => {
                    // Bare IP without port - append default DNS port 53.
                    let with_port = if trimmed.contains(':') && !trimmed.starts_with('[') {
                        // IPv6 without brackets - wrap.
                        format!("[{trimmed}]:53")
                    } else {
                        format!("{trimmed}:53")
                    };
                    with_port.parse().map_err(|e| {
                        AfterburnerError::Host(format!(
                            "dns: setServers: cannot parse `{trimmed}`: {e}"
                        ))
                    })?
                }
            };
            // Add both UDP and TCP - DNS responses larger than 512 bytes
            // (DNSSEC, big TXT) fall back to TCP; matching `getaddrinfo`
            // behavior keeps records like long SPF strings retrievable.
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            name_servers.push(NameServerConfig::new(addr.ip(), false, vec![udp, tcp]));
        }
        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        return Resolver::builder_with_config(config, provider)
            .build()
            .map_err(|e| {
                AfterburnerError::Host(format!("dns: resolver init (custom servers): {e}"))
            });
    }
    match Resolver::builder_tokio().and_then(|b| b.build()) {
        Ok(r) => Ok(r),
        Err(_) => {
            // Fall back to Cloudflare's resolver. Hickory ships preset
            // configs for the major public resolvers.
            Resolver::builder_with_config(ResolverConfig::udp_and_tcp(&CLOUDFLARE), provider)
                .build()
                .map_err(|e| AfterburnerError::Host(format!("dns resolver init: {e}")))
        }
    }
}

// ----- lookup (A/AAAA via ToSocketAddrs) ----------------------------------

pub fn lookup(hostname: &str, m: &Manifold) -> Result<String> {
    check_net(m, &format!("dns.lookup({hostname})"))?;
    let probe = format!("{hostname}:0");
    let label = format!("dns.lookup({hostname})");
    let hn = hostname.to_string();
    with_timeout(m, label.clone(), move || {
        probe
            .to_socket_addrs()
            .map_err(|e| AfterburnerError::Host(format!("{label}: {e}")))
            .and_then(|mut iter| {
                iter.next()
                    .map(|sa| sa.ip().to_string())
                    .ok_or_else(|| AfterburnerError::Host(format!("dns.lookup({hn}): no result")))
            })
    })
}

// ----- record-type-aware resolvers ----------------------------------------

pub fn resolve4(hostname: &str, servers: &[String], m: &Manifold) -> Result<Vec<String>> {
    check_net(m, &format!("dns.resolve4({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolve4({hostname})"), move || {
        block_on(async {
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .ipv4_lookup(&hn)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolve4({hn}): {e}")))?;
            Ok(lookup
                .answers()
                .iter()
                .map(|r| &r.data)
                .filter_map(|r| match r {
                    RData::A(a) => Some(a.0.to_string()),
                    _ => None,
                })
                .collect())
        })
    })
}

pub fn resolve6(hostname: &str, servers: &[String], m: &Manifold) -> Result<Vec<String>> {
    check_net(m, &format!("dns.resolve6({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolve6({hostname})"), move || {
        block_on(async {
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .ipv6_lookup(&hn)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolve6({hn}): {e}")))?;
            Ok(lookup
                .answers()
                .iter()
                .map(|r| &r.data)
                .filter_map(|r| match r {
                    RData::AAAA(a) => Some(a.0.to_string()),
                    _ => None,
                })
                .collect())
        })
    })
}

pub fn resolve_mx(hostname: &str, servers: &[String], m: &Manifold) -> Result<Vec<MxRecord>> {
    check_net(m, &format!("dns.resolveMx({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolveMx({hostname})"), move || {
        block_on(async {
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .mx_lookup(&hn)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolveMx({hn}): {e}")))?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(mx) => Some(MxRecord {
                        exchange: mx.exchange.to_string(),
                        priority: mx.preference,
                    }),
                    _ => None,
                })
                .collect())
        })
    })
}

pub fn resolve_txt(hostname: &str, servers: &[String], m: &Manifold) -> Result<Vec<Vec<String>>> {
    check_net(m, &format!("dns.resolveTxt({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolveTxt({hostname})"), move || {
        block_on(async {
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .txt_lookup(&hn)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolveTxt({hn}): {e}")))?;
            // Node's `resolveTxt` returns `string[][]` - outer per record,
            // inner per character-string fragment. TXT records can have
            // multiple <character-string>s per RR (RFC 1035 §3.3.14).
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::TXT(rec) => Some(
                        rec.txt_data
                            .iter()
                            .map(|frag| String::from_utf8_lossy(frag).into_owned())
                            .collect::<Vec<_>>(),
                    ),
                    _ => None,
                })
                .collect())
        })
    })
}

pub fn resolve_cname(hostname: &str, servers: &[String], m: &Manifold) -> Result<Vec<String>> {
    check_net(m, &format!("dns.resolveCname({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolveCname({hostname})"), move || {
        block_on(async {
            use hickory_resolver::proto::rr::RecordType;
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .lookup(&hn, RecordType::CNAME)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolveCname({hn}): {e}")))?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::CNAME(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect())
        })
    })
}

pub fn resolve_ns(hostname: &str, servers: &[String], m: &Manifold) -> Result<Vec<String>> {
    check_net(m, &format!("dns.resolveNs({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolveNs({hostname})"), move || {
        block_on(async {
            use hickory_resolver::proto::rr::RecordType;
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .lookup(&hn, RecordType::NS)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolveNs({hn}): {e}")))?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::NS(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect())
        })
    })
}

/// SOA (Start Of Authority) record. Returns the single SOA Node
/// shape: `{nsname, hostmaster, serial, refresh, retry, expire, minttl}`.
pub fn resolve_soa(hostname: &str, servers: &[String], m: &Manifold) -> Result<serde_json::Value> {
    check_net(m, &format!("dns.resolveSoa({hostname})"))?;
    let hn = hostname.to_string();
    let s = servers.to_vec();
    with_timeout(m, format!("dns.resolveSoa({hostname})"), move || {
        block_on(async {
            use hickory_resolver::proto::rr::RecordType;
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .lookup(&hn, RecordType::SOA)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.resolveSoa({hn}): {e}")))?;
            let soa = lookup
                .answers()
                .iter()
                .find_map(|r| match &r.data {
                    RData::SOA(soa) => Some(soa),
                    _ => None,
                })
                .ok_or_else(|| {
                    AfterburnerError::Host(format!("dns.resolveSoa({hn}): no SOA record"))
                })?;
            Ok(serde_json::json!({
                "nsname":     soa.mname.to_string(),
                "hostmaster": soa.rname.to_string(),
                "serial":     soa.serial,
                "refresh":    soa.refresh,
                "retry":      soa.retry,
                "expire":     soa.expire,
                "minttl":     soa.minimum,
            }))
        })
    })
}

pub fn reverse(ip: &str, servers: &[String], m: &Manifold) -> Result<Vec<String>> {
    check_net(m, &format!("dns.reverse({ip})"))?;
    let parsed: IpAddr = ip.parse().map_err(|_| {
        AfterburnerError::Host(format!("dns.reverse({ip}): not a valid IP address"))
    })?;
    let s = servers.to_vec();
    with_timeout(m, format!("dns.reverse({ip})"), move || {
        block_on(async {
            let resolver = make_resolver(&s)?;
            let lookup = resolver
                .reverse_lookup(parsed)
                .await
                .map_err(|e| AfterburnerError::Host(format!("dns.reverse: {e}")))?;
            Ok(lookup
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::PTR(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect())
        })
    })
}

// ----- helpers carried over the host-import boundary ----------------------

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub exchange: String,
    pub priority: u16,
}

impl MxRecord {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "exchange": self.exchange,
            "priority": self.priority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn denied_when_net_is_none() {
        let m = Manifold::sealed();
        let result = lookup("example.com", &m);
        assert!(matches!(result, Err(AfterburnerError::PermissionDenied(_))));
    }

    #[test]
    fn localhost_resolves_quickly() {
        let mut m = Manifold::open();
        m.http_timeout_ms = Some(2_000);
        let t0 = Instant::now();
        let result = lookup("localhost", &m);
        let elapsed = t0.elapsed();
        assert!(result.is_ok(), "localhost should resolve: {result:?}");
        assert!(
            elapsed < Duration::from_millis(500),
            "localhost resolution took {elapsed:?} - unusually slow"
        );
    }

    #[test]
    fn short_timeout_bounds_unresolvable() {
        // An unreachable TLD that the resolver may dither on. We set
        // a 500 ms timeout and assert we either succeed promptly
        // (resolver NXDOMAINs fast) or time out within 1.5s - never
        // hang. This is the production gate.
        let mut m = Manifold::open();
        m.http_timeout_ms = Some(500);
        let t0 = Instant::now();
        let _ = lookup("afterburner-test-unreachable-nonexistent-host.invalid", &m);
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(1_500),
            "hung past 1.5 s ({elapsed:?}); timeout knob not honored"
        );
    }

    #[test]
    fn resolve_methods_respect_sealed_manifold() {
        // Every entry checks `check_net` first - none of them get to
        // the resolver under `Manifold::sealed`.
        let m = Manifold::sealed();
        let no_servers: Vec<String> = vec![];
        assert!(matches!(
            resolve4("example.com", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
        assert!(matches!(
            resolve6("example.com", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
        assert!(matches!(
            resolve_mx("example.com", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
        assert!(matches!(
            resolve_txt("example.com", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
        assert!(matches!(
            resolve_cname("example.com", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
        assert!(matches!(
            resolve_ns("example.com", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
        assert!(matches!(
            reverse("8.8.8.8", &no_servers, &m),
            Err(AfterburnerError::PermissionDenied(_))
        ));
    }

    #[test]
    fn reverse_rejects_non_ip() {
        let m = Manifold::open();
        let result = reverse("not-an-ip", &[], &m);
        assert!(matches!(result, Err(AfterburnerError::Host(_))));
    }

    #[test]
    fn make_resolver_with_custom_servers_succeeds() {
        // Bare IP gets default port 53 appended.
        let r = block_on(async { make_resolver(&["1.1.1.1".into()]) });
        assert!(r.is_ok(), "err: {:?}", r.err());
        // IP with explicit port honored verbatim.
        let r = block_on(async { make_resolver(&["8.8.8.8:53".into()]) });
        assert!(r.is_ok());
    }

    #[test]
    fn make_resolver_rejects_garbage_server() {
        let r = block_on(async { make_resolver(&["not an ip".into()]) });
        assert!(matches!(r, Err(AfterburnerError::Host(_))));
    }
}
