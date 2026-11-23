//! What is being inspected.

use std::net::SocketAddr;
use std::path::PathBuf;

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
