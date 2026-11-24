//! What is being inspected.

use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

/// A network endpoint to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkTarget {
    /// Host name or IP literal.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Server name to send in SNI, when different from `host`.
    pub sni: Option<String>,
    /// Address to connect to instead of resolving `host`.
    pub connect_to: Option<SocketAddr>,
}

/// Why a network target argument was rejected.
///
/// No variant carries the offending host or credentials, so neither `Display`
/// nor `Debug` can leak a password typed into the target.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetError {
    /// The URL scheme is not `https`. Holds the lowercased scheme only.
    #[error("unsupported scheme `{0}`; only https is supported")]
    UnsupportedScheme(String),
    /// The host is not a valid DNS name (after IDNA) or IP literal.
    #[error("invalid host name")]
    InvalidHost,
    /// The port is empty, not a number, zero or above 65535.
    #[error("invalid port; use a number from 1 to 65535")]
    InvalidPort,
    /// The target carries `user[:password]@`, which is never accepted.
    #[error("credentials in the target are not supported")]
    CredentialsNotAllowed,
    /// The target is empty, or a URL without a host.
    #[error("empty target")]
    Empty,
}

/// The subject of an inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A TLS server.
    Network(NetworkTarget),
    /// A certificate, bundle or keystore file.
    File(PathBuf),
    /// A directory of certificate files.
    Directory {
        /// Directory to scan.
        path: PathBuf,
        /// Whether to descend into subdirectories.
        recursive: bool,
    },
    /// Standard input.
    Stdin,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_target_rede_deve_guardar_sni_e_connect_to() {
        let t = Target::Network(NetworkTarget {
            host: "example.com".to_owned(),
            port: 443,
            sni: Some("alt.example.com".to_owned()),
            connect_to: Some("127.0.0.1:8443".parse().unwrap()),
        });
        let Target::Network(n) = t else {
            panic!("not network")
        };
        assert_eq!(n.port, 443);
        assert_eq!(n.sni.as_deref(), Some("alt.example.com"));
    }
}
