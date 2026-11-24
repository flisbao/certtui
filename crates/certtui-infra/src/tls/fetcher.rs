//! [`RustlsChainFetcher`]: the network adapter of the `ChainFetcher` port.
//!
//! Flow (spec section 6.1): DNS (skipped with `connect_to`), sequential TCP
//! connect, a TLS handshake over a byte-budgeted stream with an accept-all
//! verifier that records what the server presents, then `close_notify` and
//! drop. No application data is ever sent.

use std::error::Error as StdError;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use certtui_app::fetch::{FetchError, FetchRequest, FetchedChain, Stage};
use certtui_app::ports::ChainFetcher;
use certtui_domain::model::Timings;
use certtui_domain::target::NetworkTarget;
use rustls::client::Resumption;
use rustls::client::danger::ServerCertVerifier;
use rustls::{AlertDescription, ClientConfig, PeerIncompatible};
use rustls_pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;

use super::capturing_verifier::{CapturedHandshake, CapturingVerifier};
use super::connect::{Resolver, SystemResolver, connect_first, resolve};
use super::limited_stream::{ByteBudgetExceeded, LimitedStream};
use super::session::{build_session_info, sanitize};

/// Longest `String` payload put into a [`FetchError`].
const MAX_ERROR_TEXT: usize = 200;
/// Longest source chain walked when looking for the cause of an error.
const MAX_CAUSE_DEPTH: usize = 8;
/// Time allowed to send `close_notify` after a successful handshake.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(500);

/// The TLS stream the handshake runs on.
type Stream = TlsStream<LimitedStream<TcpStream>>;

/// Fetches certificate chains with `tokio-rustls` (provider `ring`).
///
/// Verification is deliberately disabled: the chain is captured as presented,
/// valid or not, and judged later. See [`CapturingVerifier`].
pub struct RustlsChainFetcher {
    resolver: Arc<dyn Resolver>,
}

impl RustlsChainFetcher {
    /// Creates a fetcher that resolves names with the operating system.
    #[must_use]
    pub fn new() -> Self {
        Self::with_resolver(Arc::new(SystemResolver))
    }

    /// Creates a fetcher with a custom [`Resolver`] (for tests).
    #[doc(hidden)]
    #[must_use]
    pub fn with_resolver(resolver: Arc<dyn Resolver>) -> Self {
        Self { resolver }
    }

    /// Addresses to connect to and how long DNS took (`None` when skipped).
    async fn addresses(
        &self,
        req: &FetchRequest,
    ) -> Result<(Vec<SocketAddr>, Option<Duration>), FetchError> {
        if let Some(addr) = req.target.connect_to {
            return Ok((vec![addr], None));
        }
        let t = &req.target;
        let started = Instant::now();
        let found = resolve(&*self.resolver, &t.host, t.port, req.limits.dns_timeout).await?;
        let is_literal = t.host.parse::<std::net::IpAddr>().is_ok();
        Ok((found, (!is_literal).then(|| started.elapsed())))
    }

    /// Connects, handshakes and describes the result; the stream is returned
    /// so the caller can close it politely after the budgets are released.
    async fn run(
        &self,
        req: &FetchRequest,
        started: Instant,
    ) -> Result<(FetchedChain, Stream), FetchError> {
        let limits = &req.limits;
        let (addrs, dns) = self.addresses(req).await?;
        let phase = Instant::now();
        let (tcp, peer) = connect_first(&addrs, limits.connect_timeout).await?;
        let connect = phase.elapsed();

        let phase = Instant::now();
        let (tls, captured) = negotiate(req, tcp).await?;
        let handshake = phase.elapsed();

        let session = build_session_info(tls.get_ref().1, peer.ip());
        let timings = Timings {
            dns,
            connect: Some(connect),
            handshake: Some(handshake),
            total: Some(started.elapsed()),
        };
        let chain = assemble(captured, session, timings)?;
        Ok((chain, tls))
    }
}

impl Default for RustlsChainFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RustlsChainFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsChainFetcher").finish_non_exhaustive()
    }
}

#[async_trait]
impl ChainFetcher for RustlsChainFetcher {
    /// Fetches the chain `req.target` presents.
    ///
    /// Each phase has its own timeout and the whole call is bounded by
    /// `target_total_timeout`. Timeout and cancellation race: whichever fires
    /// first decides the error, and cancellation yields
    /// [`FetchError::Cancelled`] (also when `cancel` is already set on entry,
    /// in which case nothing is connected). The best-effort `close_notify`
    /// after a successful handshake takes at most half a second and runs
    /// outside those budgets.
    async fn fetch(
        &self,
        req: &FetchRequest,
        cancel: CancellationToken,
    ) -> Result<FetchedChain, FetchError> {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        let work = tokio::time::timeout(
            req.limits.target_total_timeout,
            self.run(req, Instant::now()),
        );
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => Err(FetchError::Cancelled),
            timed = work => timed.unwrap_or(Err(FetchError::Timeout(Stage::Total))),
        };
        let (chain, stream) = outcome?;
        close_quietly(stream).await;
        Ok(chain)
    }
}

/// TLS client: ring provider, TLS 1.2 and 1.3, ALPN, no client auth, no
/// session resumption, and `verifier` as the (accept-all) certificate check.
fn connector(verifier: &Arc<CapturingVerifier>) -> Result<TlsConnector, FetchError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = Arc::clone(verifier) as _;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|_| FetchError::Handshake("TLS client configuration failed".to_owned()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.resumption = Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Name for SNI: `--sni` or the host. An IP address makes rustls send no SNI.
fn server_name(target: &NetworkTarget) -> Result<ServerName<'static>, FetchError> {
    let name = target.sni.as_deref().unwrap_or(&target.host);
    ServerName::try_from(name.to_owned())
        .map_err(|_| FetchError::Handshake("the server name is not valid for SNI".to_owned()))
}

/// Handshakes over `tcp` and returns the stream with what the verifier saw.
async fn negotiate(
    req: &FetchRequest,
    tcp: TcpStream,
) -> Result<(Stream, Option<CapturedHandshake>), FetchError> {
    let verifier = CapturingVerifier::new();
    let connector = connector(&verifier)?;
    let name = server_name(&req.target)?;
    let limited = LimitedStream::new(tcp, req.limits.max_handshake_bytes);
    let tls = handshake(&connector, name, limited, req.limits.handshake_timeout).await?;
    Ok((tls, verifier.captured()))
}

/// Runs the TLS handshake within `timeout`.
async fn handshake(
    connector: &TlsConnector,
    name: ServerName<'static>,
    stream: LimitedStream<TcpStream>,
    timeout: Duration,
) -> Result<Stream, FetchError> {
    tokio::time::timeout(timeout, connector.connect(name, stream))
        .await
        .map_err(|_| FetchError::Timeout(Stage::Handshake))?
        .map_err(|e| map_tls_error(&e))
}

/// Builds the result from what the verifier captured.
fn assemble(
    captured: Option<CapturedHandshake>,
    session: certtui_domain::model::TlsSessionInfo,
    timings: Timings,
) -> Result<FetchedChain, FetchError> {
    let captured = captured
        .filter(|c| !c.end_entity.is_empty())
        .ok_or(FetchError::EmptyChain)?;
    let mut ders = vec![captured.end_entity];
    ders.extend(captured.intermediates);
    // rustls erases "no staple" and "empty staple": empty means none.
    let ocsp_staple = (!captured.ocsp_response.is_empty()).then_some(captured.ocsp_response);
    Ok(FetchedChain {
        ders,
        ocsp_staple,
        session,
        timings,
    })
}

/// Sends `close_notify` (best effort, bounded) and drops the stream.
async fn close_quietly(mut stream: Stream) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, stream.shutdown()).await;
}

/// Maps a handshake failure to a [`FetchError`] with a short, control-free
/// message. Never waits: every case here is already a failure.
pub(crate) fn map_tls_error(err: &io::Error) -> FetchError {
    for cause in causes(err) {
        if let Some(exceeded) = cause.downcast_ref::<ByteBudgetExceeded>() {
            return FetchError::ByteBudgetExceeded {
                limit: exceeded.limit,
            };
        }
        if let Some(tls) = cause.downcast_ref::<rustls::Error>() {
            return map_rustls_error(tls);
        }
    }
    let text = match err.kind() {
        io::ErrorKind::UnexpectedEof => "connection closed by the peer during the handshake",
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
            "connection reset by the peer during the handshake"
        }
        _ => return handshake_error(&err.to_string()),
    };
    FetchError::Handshake(text.to_owned())
}

/// The error wrapped by `err` and its sources, outermost first, bounded.
fn causes(err: &io::Error) -> impl Iterator<Item = &(dyn StdError + 'static)> {
    let first = err.get_ref().map(|e| e as &(dyn StdError + 'static));
    std::iter::successors(first, |e| (*e).source()).take(MAX_CAUSE_DEPTH)
}

fn map_rustls_error(err: &rustls::Error) -> FetchError {
    use rustls::Error;
    match err {
        Error::AlertReceived(AlertDescription::ProtocolVersion) => FetchError::UnsupportedProtocol,
        Error::PeerIncompatible(why) if is_version_mismatch(why) => FetchError::UnsupportedProtocol,
        Error::AlertReceived(alert) => handshake_error(&format!("the peer sent alert {alert:?}")),
        Error::InvalidMessage(_)
        | Error::InappropriateMessage { .. }
        | Error::InappropriateHandshakeMessage { .. } => {
            FetchError::Handshake("the peer did not answer with valid TLS".to_owned())
        }
        other => handshake_error(&other.to_string()),
    }
}

fn is_version_mismatch(why: &PeerIncompatible) -> bool {
    matches!(
        why,
        PeerIncompatible::ServerDoesNotSupportTls12Or13
            | PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig
            | PeerIncompatible::Tls12NotOffered
            | PeerIncompatible::Tls12NotOfferedOrEnabled
    )
}

fn handshake_error(text: &str) -> FetchError {
    FetchError::Handshake(sanitize(text, MAX_ERROR_TEXT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{AlertDescription, InvalidMessage};

    fn wrapped(err: impl StdError + Send + Sync + 'static) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }

    #[test]
    fn quando_alert_protocol_version_deve_ser_unsupported_protocol() {
        let err = wrapped(rustls::Error::AlertReceived(
            AlertDescription::ProtocolVersion,
        ));
        assert_eq!(map_tls_error(&err), FetchError::UnsupportedProtocol);
    }

    #[test]
    fn quando_peer_incompativel_na_versao_deve_ser_unsupported_protocol() {
        let why = PeerIncompatible::ServerDoesNotSupportTls12Or13;
        let err = wrapped(rustls::Error::PeerIncompatible(why));
        assert_eq!(map_tls_error(&err), FetchError::UnsupportedProtocol);
    }

    #[test]
    fn quando_outro_alert_deve_ser_handshake_com_o_nome_do_alert() {
        let err = wrapped(rustls::Error::AlertReceived(
            AlertDescription::HandshakeFailure,
        ));
        let FetchError::Handshake(msg) = map_tls_error(&err) else {
            panic!("expected Handshake");
        };
        assert!(msg.contains("HandshakeFailure"), "{msg}");
    }

    #[test]
    fn quando_mensagem_invalida_deve_ser_handshake_curto() {
        let err = wrapped(rustls::Error::InvalidMessage(
            InvalidMessage::InvalidContentType,
        ));
        let FetchError::Handshake(msg) = map_tls_error(&err) else {
            panic!("expected Handshake");
        };
        assert!(msg.contains("valid TLS"), "{msg}");
    }

    #[test]
    fn quando_orcamento_estoura_direto_deve_citar_o_limite() {
        let err = io::Error::other(ByteBudgetExceeded { limit: 1234 });
        assert_eq!(
            map_tls_error(&err),
            FetchError::ByteBudgetExceeded { limit: 1234 }
        );
    }

    #[test]
    fn quando_orcamento_estoura_dentro_de_outro_erro_deve_citar_o_limite() {
        #[derive(Debug)]
        struct Outer(ByteBudgetExceeded);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("outer")
            }
        }
        impl StdError for Outer {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&self.0)
            }
        }
        let err = wrapped(Outer(ByteBudgetExceeded { limit: 99 }));
        assert_eq!(
            map_tls_error(&err),
            FetchError::ByteBudgetExceeded { limit: 99 }
        );
    }

    #[test]
    fn quando_eof_deve_ser_handshake_de_conexao_fechada() {
        let err = io::Error::new(io::ErrorKind::UnexpectedEof, "tls handshake eof");
        let FetchError::Handshake(msg) = map_tls_error(&err) else {
            panic!("expected Handshake");
        };
        assert!(msg.contains("closed"), "{msg}");
    }

    #[test]
    fn quando_erro_tem_controles_e_e_longo_deve_sanear_e_limitar() {
        let text = format!("bad\r\n\u{1b}[31m{}", "x".repeat(1000));
        let FetchError::Handshake(msg) = map_tls_error(&io::Error::other(text)) else {
            panic!("expected Handshake");
        };
        assert!(msg.chars().count() <= MAX_ERROR_TEXT, "{}", msg.len());
        assert!(msg.chars().all(|c| !c.is_control()), "{msg:?}");
        assert!(msg.starts_with("bad??"), "{msg}");
    }

    #[test]
    fn quando_nada_foi_capturado_deve_dar_empty_chain() {
        let session = certtui_domain::model::TlsSessionInfo {
            version: "TLSv1.3".to_owned(),
            cipher_suite: "X".to_owned(),
            key_exchange_group: None,
            alpn: None,
            peer_ip: std::net::Ipv4Addr::LOCALHOST.into(),
        };
        let got = assemble(None, session, Timings::default());
        assert_eq!(got, Err(FetchError::EmptyChain));
    }
}
