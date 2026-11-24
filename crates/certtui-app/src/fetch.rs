//! Types exchanged with the [`ChainFetcher`](crate::ports::ChainFetcher) port.

use std::fmt;

use certtui_domain::limits::Limits;
use certtui_domain::model::{LoadNote, Timings, TlsSessionInfo};
use certtui_domain::target::NetworkTarget;
use thiserror::Error;

/// What to fetch and the budget to fetch it within.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchRequest {
    /// The network target to connect to.
    pub target: NetworkTarget,
    /// Timeouts and byte budgets (spec section 9).
    pub limits: Limits,
}

/// What a successful fetch brings back from the peer.
///
/// `Debug` prints counts and sizes, not the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchedChain {
    /// Certificates as presented by the server, leaf first, DER encoded.
    pub ders: Vec<Vec<u8>>,
    /// The stapled OCSP response, when the server sent one.
    pub ocsp_staple: Option<Vec<u8>>,
    /// Negotiated TLS parameters, available only after a completed handshake.
    pub session: Option<TlsSessionInfo>,
    /// A partial capture carries one diagnostic about the interrupted handshake.
    pub note: Option<LoadNote>,
    /// Durations of the phases that ran.
    pub timings: Timings,
}

impl fmt::Debug for FetchedChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchedChain")
            .field("der_count", &self.ders.len())
            .field("ocsp_staple_len", &self.ocsp_staple.as_ref().map(Vec::len))
            .field("session", &self.session)
            .field("note", &self.note)
            .field("timings", &self.timings)
            .finish()
    }
}

/// A phase of a network fetch, used to say where a timeout struck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// DNS resolution.
    Dns,
    /// TCP connection.
    Connect,
    /// TLS handshake.
    Handshake,
    /// The whole fetch for one target.
    Total,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dns => "DNS resolution",
            Self::Connect => "TCP connect",
            Self::Handshake => "TLS handshake",
            Self::Total => "overall fetch",
        })
    }
}

/// Why a network fetch failed.
///
/// Messages are short English sentences with no secrets and no raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FetchError {
    /// The host name could not be resolved.
    #[error("DNS resolution failed: {0}")]
    Dns(String),
    /// The TCP connection could not be established.
    #[error("connection failed: {0}")]
    Connect(String),
    /// A phase ran out of time.
    #[error("timed out during {0}")]
    Timeout(Stage),
    /// The TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    Handshake(String),
    /// The peer does not speak a TLS version this tool supports.
    #[error("the peer does not support TLS 1.2 or 1.3")]
    UnsupportedProtocol,
    /// The peer sent more handshake bytes than allowed.
    #[error("handshake data exceeded the limit of {limit} bytes")]
    ByteBudgetExceeded {
        /// The configured maximum in bytes.
        limit: usize,
    },
    /// The handshake finished without any certificate.
    #[error("the peer presented no certificates")]
    EmptyChain,
    /// The fetch was cancelled by the caller.
    #[error("the fetch was cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::ChainFetcher;
    use crate::testing::FakeChainFetcher;
    use certtui_domain::limits::Limits;
    use certtui_domain::model::{Timings, TlsSessionInfo};
    use certtui_domain::target::NetworkTarget;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio_util::sync::CancellationToken;

    fn request() -> FetchRequest {
        FetchRequest {
            target: NetworkTarget {
                host: "example.com".to_owned(),
                port: 443,
                sni: None,
                connect_to: None,
            },
            limits: Limits::default(),
        }
    }

    fn chain() -> FetchedChain {
        FetchedChain {
            ders: vec![vec![0x30, 0x03, 0x02, 0x01, 0x00]],
            ocsp_staple: Some(vec![1, 2, 3]),
            session: Some(TlsSessionInfo {
                version: "TLSv1.3".to_owned(),
                cipher_suite: "TLS13_AES_128_GCM_SHA256".to_owned(),
                key_exchange_group: None,
                alpn: None,
                peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            }),
            note: None,
            timings: Timings::default(),
        }
    }

    fn every_variant() -> Vec<FetchError> {
        vec![
            FetchError::Dns("no such host".to_owned()),
            FetchError::Connect("connection refused".to_owned()),
            FetchError::Timeout(Stage::Dns),
            FetchError::Timeout(Stage::Connect),
            FetchError::Timeout(Stage::Handshake),
            FetchError::Timeout(Stage::Total),
            FetchError::Handshake("alert received".to_owned()),
            FetchError::UnsupportedProtocol,
            FetchError::ByteBudgetExceeded { limit: 65_536 },
            FetchError::EmptyChain,
            FetchError::Cancelled,
        ]
    }

    #[test]
    fn quando_fetch_error_vira_exit_3_deve_ter_mensagem_em_ingles() {
        for err in every_variant() {
            let msg = err.to_string();
            assert!(!msg.trim().is_empty(), "empty message for {err:?}");
            assert!(msg.is_ascii(), "non-ASCII message: {msg}");
            assert!(
                msg.chars().any(|c| c.is_ascii_alphabetic()),
                "no words in: {msg}"
            );
            let lower = msg.to_ascii_lowercase();
            for secret in ["password", "secret", "private key", "token", "0x"] {
                assert!(!lower.contains(secret), "{secret:?} leaked in: {msg}");
            }
        }
    }

    #[test]
    fn quando_timeout_deve_nomear_a_fase() {
        assert!(FetchError::Timeout(Stage::Dns).to_string().contains("DNS"));
        assert!(
            FetchError::Timeout(Stage::Handshake)
                .to_string()
                .contains("handshake")
        );
    }

    #[test]
    fn quando_byte_budget_estoura_deve_citar_o_limite() {
        let msg = FetchError::ByteBudgetExceeded { limit: 65_536 }.to_string();
        assert!(msg.contains("65536"), "{msg}");
    }

    #[test]
    fn quando_fetched_chain_debug_deve_omitir_os_bytes() {
        let dbg = format!("{:?}", chain());
        assert!(dbg.contains("der_count"), "{dbg}");
        assert!(!dbg.contains("[48, 3"), "{dbg}");
    }

    #[tokio::test]
    async fn quando_fake_tem_cadeia_deve_devolver_a_cadeia_pelo_trait_object() {
        let fetcher: Box<dyn ChainFetcher> = Box::new(FakeChainFetcher(Ok(chain())));
        let got = fetcher
            .fetch(&request(), CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(got, chain());
    }

    #[tokio::test]
    async fn quando_fake_tem_erro_deve_devolver_o_erro_por_referencia_ao_trait() {
        let fake = FakeChainFetcher(Err(FetchError::EmptyChain));
        let fetcher: &dyn ChainFetcher = &fake;
        let got = fetcher.fetch(&request(), CancellationToken::new()).await;
        assert_eq!(got, Err(FetchError::EmptyChain));
    }

    #[tokio::test]
    async fn quando_token_ja_cancelado_deve_devolver_cancelled() {
        let fake = FakeChainFetcher(Ok(chain()));
        let token = CancellationToken::new();
        token.cancel();
        let got = fake.fetch(&request(), token).await;
        assert_eq!(got, Err(FetchError::Cancelled));
    }
}
