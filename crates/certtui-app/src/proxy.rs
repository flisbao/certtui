//! Which proxy a connection goes through (spec section 3.1, `--proxy`).

use std::fmt;

/// Where an HTTP CONNECT proxy listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    /// Host name or IP literal (without brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl fmt::Display for ProxyEndpoint {
    /// `host:port`, with an IPv6 literal in brackets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// The proxy to use and the hosts that skip it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySettings {
    /// The proxy.
    pub endpoint: ProxyEndpoint,
    /// `NO_PROXY` of the environment, when the proxy came from it. A proxy
    /// given with `--proxy` or in the config is meant for every target.
    pub no_proxy: Option<String>,
}

impl ProxySettings {
    /// The proxy to reach `host` through, or `None` to connect directly.
    #[must_use]
    pub fn endpoint_for(&self, host: &str) -> Option<&ProxyEndpoint> {
        match &self.no_proxy {
            Some(list) if bypass(host, list) => None,
            _ => Some(&self.endpoint),
        }
    }
}

/// Whether `host` matches the `NO_PROXY` list: `*`, a host name (which also
/// matches its subdomains, with or without a leading dot), or an IP address,
/// separated by commas or spaces. A `:port` after an entry is ignored. IP
/// ranges (CIDR) are not supported.
#[must_use]
pub fn bypass(host: &str, no_proxy: &str) -> bool {
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    no_proxy
        .split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            if entry == "*" {
                return true;
            }
            let entry = entry.to_ascii_lowercase();
            let entry = strip_port(&entry).trim_matches(['[', ']']);
            let entry = entry.strip_prefix('.').unwrap_or(entry);
            !entry.is_empty()
                && (host == entry
                    || host
                        .strip_suffix(entry)
                        .is_some_and(|rest| rest.ends_with('.')))
        })
}

/// `example.com:8443` -> `example.com`; an IPv6 literal keeps its colons.
fn strip_port(entry: &str) -> &str {
    match entry.rsplit_once(':') {
        Some((host, port))
            if !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit()) =>
        {
            host
        }
        _ => entry,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_deve_seguir_a_tabela_do_no_proxy() {
        let cases = [
            ("anything.example", "*", true),
            ("a.example.com", ".example.com", true),
            ("example.com", ".example.com", true),
            ("a.example.com", "example.com", true),
            ("example.com", "example.com", true),
            ("notexample.com", "example.com", false),
            ("notexample.com", ".example.com", false),
            ("localhost", "localhost", true),
            ("10.0.0.1", "10.0.0.1", true),
            ("10.0.0.2", "10.0.0.1", false),
            ("A.Example.COM", "example.com", true),
            ("a.example.com", "other.org, example.com", true),
            ("a.example.com", "other.org example.com", true),
            ("a.example.com", "other.org,,  ", false),
            ("a.example.com", "", false),
            ("a.example.com", "example.com:8443", true),
            ("::1", "::1", true),
            ("::1", "[::1]", true),
            ("", "*", false),
        ];
        for (host, no_proxy, expected) in cases {
            assert_eq!(bypass(host, no_proxy), expected, "{host} vs {no_proxy:?}");
        }
    }

    fn settings(no_proxy: Option<&str>) -> ProxySettings {
        ProxySettings {
            endpoint: ProxyEndpoint {
                host: "proxy.corp".to_owned(),
                port: 3128,
            },
            no_proxy: no_proxy.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn quando_host_casa_no_no_proxy_deve_conectar_direto() {
        let s = settings(Some("internal.corp,.lan"));
        assert_eq!(s.endpoint_for("db.lan"), None);
        assert_eq!(s.endpoint_for("internal.corp"), None);
        assert_eq!(
            s.endpoint_for("public.example").map(ToString::to_string),
            Some("proxy.corp:3128".to_owned())
        );
    }

    #[test]
    fn quando_nao_ha_no_proxy_deve_usar_o_proxy_para_todos() {
        let s = settings(None);
        assert!(s.endpoint_for("localhost").is_some());
    }

    #[test]
    fn endpoint_ipv6_deve_aparecer_entre_colchetes() {
        let endpoint = ProxyEndpoint {
            host: "::1".to_owned(),
            port: 3128,
        };
        assert_eq!(endpoint.to_string(), "[::1]:3128");
    }
}
