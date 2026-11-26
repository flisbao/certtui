//! Which network destinations a certificate-supplied URL may reach.
//!
//! OCSP, CRL and AIA URLs come from certificates, so a hostile certificate can
//! aim them at the machine running certtui: `http://localhost:22`, or the
//! cloud metadata service at `http://169.254.169.254/`. The default policy
//! refuses loopback, link-local (which includes that metadata address),
//! unspecified (all of `0.0.0.0/8`), multicast and broadcast addresses, plus
//! the metadata addresses of clouds that do not use link-local. IPv6 forms
//! that carry an IPv4 address (mapped, NAT64, 6to4) are judged by it. Private ranges (`10.x`, `192.168.x`,
//! unique-local IPv6) stay allowed: internal CAs publish their OCSP and CRL
//! there. `--allow-internal-urls` lifts the whole policy.
//!
//! Hostnames are checked after resolution, on the very addresses the
//! connection then uses, so a DNS answer cannot change between check and use.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

use certtui_app::proxy::ProxySettings;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Alibaba Cloud's metadata address, inside the shared (CGNAT) range.
const ALIBABA_METADATA: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);

/// AWS's IPv6 metadata address, inside unique-local space.
const AWS_METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

/// Whether the default policy refuses to connect to `ip`.
#[must_use]
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => {
            blocked_v6(v6)
                || v6.to_ipv4().is_some_and(blocked_v4)
                || embedded_v4(v6).is_some_and(blocked_v4)
        }
    }
}

/// The IPv4 address a translation prefix carries: NAT64 (`64:ff9b::/96`,
/// RFC 6052) in the last 32 bits, 6to4 (`2002::/16`, RFC 3056) right after
/// the prefix. A gateway on the path turns them into that IPv4 address.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = ip.octets();
    let segments = ip.segments();
    let nat64 = segments.get(..6) == Some(&[0x64, 0xff9b, 0, 0, 0, 0][..]);
    let tail = if nat64 {
        octets.get(12..16)?
    } else if segments.first() == Some(&0x2002) {
        octets.get(2..6)?
    } else {
        return None;
    };
    let bytes: [u8; 4] = tail.try_into().ok()?;
    Some(Ipv4Addr::from(bytes))
}

fn blocked_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_link_local()
        // 0.0.0.0/8, "this network": Linux connects 0.x.y.z to the host.
        || ip.octets().first() == Some(&0)
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip == ALIBABA_METADATA
}

fn blocked_v6(ip: Ipv6Addr) -> bool {
    let link_local = ip
        .segments()
        .first()
        .is_some_and(|first| first & 0xffc0 == 0xfe80);
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || link_local
        || ip == AWS_METADATA_V6
}

/// The destination is refused by the policy.
#[derive(Debug)]
pub struct Blocked;

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("destination address is not allowed")
    }
}

impl Error for Blocked {}

/// A DNS resolver that drops the addresses the policy refuses; when nothing
/// is left the connection fails with [`Blocked`].
pub struct FilteringResolver {
    allow_internal: Arc<AtomicBool>,
    /// The proxy, whose own address is the user's choice, not a
    /// certificate's: it is never filtered.
    proxy: Arc<RwLock<Option<ProxySettings>>>,
}

impl FilteringResolver {
    /// A resolver that reads `allow_internal` on every lookup.
    #[must_use]
    pub fn new(allow_internal: Arc<AtomicBool>) -> Self {
        Self::with_proxy(allow_internal, Arc::new(RwLock::new(None)))
    }

    /// Like [`new`](Self::new), but the host of the configured proxy is
    /// resolved without filtering.
    #[must_use]
    pub fn with_proxy(
        allow_internal: Arc<AtomicBool>,
        proxy: Arc<RwLock<Option<ProxySettings>>>,
    ) -> Self {
        Self {
            allow_internal,
            proxy,
        }
    }

    /// Whether `name` is the host of the configured proxy.
    fn is_proxy_host(&self, name: &str) -> bool {
        self.proxy
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|settings| settings.endpoint.host.eq_ignore_ascii_case(name))
    }
}

impl Resolve for FilteringResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let allow =
            self.allow_internal.load(Ordering::Relaxed) || self.is_proxy_host(name.as_str());
        Box::pin(async move {
            let found = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let kept: Vec<SocketAddr> = found
                .filter(|addr| allow || !is_blocked(addr.ip()))
                .collect();
            if kept.is_empty() {
                return Err(Box::new(Blocked) as Box<dyn Error + Send + Sync>);
            }
            Ok(Box::new(kept.into_iter()) as Addrs)
        })
    }
}

/// Whether `error`, or any error it wraps, is [`Blocked`].
#[must_use]
pub fn is_blocked_error(error: &(dyn Error + 'static)) -> bool {
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(err) = current {
        if err.is::<Blocked>() {
            return true;
        }
        current = err.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn quando_loopback_link_local_ou_metadata_deve_bloquear() {
        for text in [
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "169.254.169.254",
            "169.254.0.1",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            // 0.0.0.0/8 ("this network"), not only 0.0.0.0.
            "0.1.2.3",
            // NAT64 (RFC 6052 well-known prefix) embedding loopback/metadata.
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            // 6to4 embedding loopback/metadata.
            "2002:7f00:1::",
            "2002:a9fe:a9fe::1",
        ] {
            assert!(is_blocked(ip(text)), "{text}");
        }
    }

    #[test]
    fn quando_faixa_privada_ou_publica_deve_liberar() {
        for text in [
            "10.0.0.5",
            "172.16.4.9",
            "192.168.1.10",
            "203.0.113.5",
            "93.184.216.34",
            "100.64.0.1",
            "fd12:3456::1",
            "2606:2800:220:1:248:1893:25c8:1946",
            "::ffff:10.0.0.5",
            // NAT64 and 6to4 of public or private addresses stay allowed.
            "64:ff9b::5db8:d822",
            "2002:0a00:0005::1",
        ] {
            assert!(!is_blocked(ip(text)), "{text}");
        }
    }

    #[test]
    fn quando_erro_embrulha_blocked_deve_reconhecer() {
        #[derive(Debug)]
        struct Wrapper(Blocked);
        impl fmt::Display for Wrapper {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("wrapped")
            }
        }
        impl Error for Wrapper {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                Some(&self.0)
            }
        }
        assert!(is_blocked_error(&Wrapper(Blocked)));
        assert!(!is_blocked_error(&fmt::Error));
    }

    #[tokio::test]
    async fn quando_nome_resolve_so_para_loopback_deve_falhar_com_blocked() {
        let resolver = FilteringResolver::new(Arc::new(AtomicBool::new(false)));
        let name: Name = "localhost".parse().unwrap();

        let got = resolver.resolve(name).await;

        let error = got.err().expect("localhost must be refused");
        assert!(is_blocked_error(error.as_ref()));
    }

    #[tokio::test]
    async fn quando_politica_esta_liberada_deve_resolver_localhost() {
        let resolver = FilteringResolver::new(Arc::new(AtomicBool::new(true)));
        let name: Name = "localhost".parse().unwrap();

        let got = resolver.resolve(name).await;

        assert!(got.is_ok());
    }
}
