//! In-process TLS test server (dev/test only; never part of the library).
//!
//! [`TestServer::start`] binds `127.0.0.1:0` and serves one [`Behavior`] on a
//! background tokio task until the value is dropped (or [`TestServer::shutdown`]
//! is called). Certificates are generated with `rcgen` on every start:
//! CA -> intermediate -> leaf (SAN `localhost` and `127.0.0.1`).
//!
//! Besides serving, the server records what it observed so tests can assert on
//! the client: the SNI of the last `ClientHello`, the ALPN protocol negotiated
//! by the last completed handshake and the number of accepted connections.
//!
//! Everything is bounded: at most [`MAX_CONNECTIONS`] concurrent connections,
//! raw reads limited to one TLS record, flood limited to [`FLOOD_CAP_BYTES`].
//!
//! The file is shared with `examples/tls_test_server.rs` through `#[path]`.

// Justificativa: this file is compiled both by the sanity tests and by the
// example, and each of them uses a different subset of the harness API.
#![allow(dead_code)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

/// Error type of the harness (test code only).
pub type HarnessError = Box<dyn std::error::Error + Send + Sync>;

/// Maximum number of simultaneously served connections; extra ones are dropped.
pub const MAX_CONNECTIONS: usize = 256;
/// Total bytes written by [`Behavior::FloodBytes`] before it gives up.
pub const FLOOD_CAP_BYTES: usize = 64 * 1024 * 1024;
/// Largest TLS record body the raw stubs are willing to read.
const MAX_RECORD_BODY: usize = 16 * 1024 + 2048;
/// Time the raw stubs wait for the client's first record.
const RAW_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Size of each flood record body.
const FLOOD_RECORD_BODY: usize = 16 * 1024;

/// Fatal alert `protocol_version` (70) in a TLS 1.0 record.
pub const ALERT_PROTOCOL_VERSION: [u8; 7] = [0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 70];
/// Fatal alert `handshake_failure` (40) in a TLS 1.2 record.
pub const ALERT_HANDSHAKE_FAILURE: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40];
/// Reply of [`Behavior::PlainHttp`].
pub const PLAIN_HTTP_REPLY: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// What the server does with each accepted connection.
#[derive(Debug, Clone)]
pub enum Behavior {
    /// Normal TLS 1.2/1.3 server; sends leaf, intermediate, CA.
    Ok,
    /// TLS server that sends only the leaf.
    IncompleteChain,
    /// TLS server that sends leaf, CA, intermediate (last two swapped).
    WrongOrder,
    /// TLS server whose leaf `notAfter` is in the past.
    Expired,
    /// TLS server whose only certificate is a self-signed leaf.
    SelfSigned,
    /// TLS server that staples the given bytes as the OCSP response (rustls
    /// sends it only when the client asked for `status_request`).
    WithStaple(Vec<u8>),
    /// TLS server that waits this long before answering the `ClientHello`.
    Slow(Duration),
    /// Accepts and keeps the socket open without ever writing.
    NeverResponds,
    /// Accepts and writes TLS-looking records until the peer disconnects
    /// (or [`FLOOD_CAP_BYTES`] were written).
    FloodBytes,
    /// TLS server restricted to TLS 1.2.
    Tls12Only,
    /// TLS server restricted to TLS 1.3.
    Tls13Only,
    /// Replies `HTTP/1.1 400 Bad Request` in clear text and closes.
    PlainHttp,
    /// Accepts and drops the connection.
    CloseImmediately,
    /// Reads the `ClientHello`, sends fatal alert `handshake_failure`, closes.
    TlsAlert,
    /// Raw stub that reads the `ClientHello`, sends fatal alert
    /// `protocol_version` (as a TLS 1.0-only server would) and closes.
    Tls10Only,
}

/// What the server saw of a client-controlled value (SNI, ALPN).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Observation<T> {
    /// No connection reached the point where the value is known yet.
    #[default]
    NotYet,
    /// The point was reached and the client supplied no value.
    Absent,
    /// The client supplied this value.
    Present(T),
}

impl<T> Observation<T> {
    fn from_option(value: Option<T>) -> Self {
        value.map_or(Self::Absent, Self::Present)
    }
}

/// Counters and observations shared with the connection tasks.
#[derive(Debug, Default)]
struct Shared {
    accepted: AtomicUsize,
    sni: Mutex<Observation<String>>,
    alpn: Mutex<Observation<Vec<u8>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Resolver that records the SNI of every `ClientHello` and serves one key.
#[derive(Debug)]
struct RecordingResolver {
    key: Arc<CertifiedKey>,
    shared: Arc<Shared>,
}

impl ResolvesServerCert for RecordingResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        *lock(&self.shared.sni) =
            Observation::from_option(client_hello.server_name().map(str::to_owned));
        Some(Arc::clone(&self.key))
    }
}

/// Generated certificates (DER) plus the leaf private key (PKCS#8 DER).
struct Pki {
    /// Trust anchor: the CA, or the lone certificate when self-signed.
    anchor: Vec<u8>,
    intermediate: Vec<u8>,
    leaf: Vec<u8>,
    leaf_key: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PkiKind {
    Chain,
    ExpiredLeaf,
    SelfSignedLeaf,
}

fn ca_cert_params(name: &str, path_len: Option<u8>) -> Result<CertificateParams, HarnessError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = match path_len {
        Some(n) => IsCa::Ca(BasicConstraints::Constrained(n)),
        None => IsCa::Ca(BasicConstraints::Unconstrained),
    };
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

fn leaf_params(kind: PkiKind) -> Result<CertificateParams, HarnessError> {
    let mut params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "certtui test leaf");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    if kind == PkiKind::ExpiredLeaf {
        params.not_before = date_time_ymd(2000, 1, 1);
        params.not_after = date_time_ymd(2001, 1, 1);
    }
    Ok(params)
}

impl Pki {
    fn generate(kind: PkiKind) -> Result<Self, HarnessError> {
        let leaf_key = KeyPair::generate()?;
        let leaf_params = leaf_params(kind)?;
        if kind == PkiKind::SelfSignedLeaf {
            let leaf = leaf_params.self_signed(&leaf_key)?.der().to_vec();
            return Ok(Self {
                anchor: leaf.clone(),
                intermediate: Vec::new(),
                leaf,
                leaf_key: leaf_key.serialize_der(),
            });
        }
        let ca_key = KeyPair::generate()?;
        let ca_params = ca_cert_params("certtui test CA", None)?;
        let ca = ca_params.self_signed(&ca_key)?;
        let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

        let inter_key = KeyPair::generate()?;
        let inter_params = ca_cert_params("certtui test intermediate", Some(0))?;
        let inter = inter_params.signed_by(&inter_key, &ca_issuer)?;
        let inter_issuer = Issuer::from_params(&inter_params, &inter_key);

        let leaf = leaf_params.signed_by(&leaf_key, &inter_issuer)?;
        Ok(Self {
            anchor: ca.der().to_vec(),
            intermediate: inter.der().to_vec(),
            leaf: leaf.der().to_vec(),
            leaf_key: leaf_key.serialize_der(),
        })
    }
}

/// How a connection is served.
enum Mode {
    Tls {
        acceptor: TlsAcceptor,
        delay: Duration,
    },
    Close,
    NeverResponds,
    Flood,
    PlainHttp,
    Alert(&'static [u8]),
}

fn tls_config(
    key: Arc<CertifiedKey>,
    shared: &Arc<Shared>,
    versions: &[&'static SupportedProtocolVersion],
) -> Result<Arc<ServerConfig>, HarnessError> {
    let resolver = RecordingResolver {
        key,
        shared: Arc::clone(shared),
    };
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn certified_key(
    pki: &Pki,
    presented: &[Vec<u8>],
    ocsp: Option<Vec<u8>>,
) -> Result<Arc<CertifiedKey>, HarnessError> {
    let chain: Vec<CertificateDer<'static>> = presented
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(pki.leaf_key.clone()));
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)?;
    let mut certified = CertifiedKey::new(chain, signer);
    certified.ocsp = ocsp;
    Ok(Arc::new(certified))
}

/// In-process TLS (or deliberately broken) server bound to `127.0.0.1`.
///
/// Dropping the value aborts the listener and every connection task.
#[derive(Debug)]
pub struct TestServer {
    addr: SocketAddr,
    shared: Arc<Shared>,
    anchor: Vec<u8>,
    presented: Vec<Vec<u8>>,
    task: JoinHandle<()>,
}

impl TestServer {
    /// Binds `127.0.0.1:0`, generates the certificates and starts serving.
    ///
    /// # Errors
    ///
    /// Fails if binding, certificate generation or TLS configuration fails.
    pub async fn start(behavior: Behavior) -> Result<Self, HarnessError> {
        let shared = Arc::new(Shared::default());
        let kind = match behavior {
            Behavior::Expired => PkiKind::ExpiredLeaf,
            Behavior::SelfSigned => PkiKind::SelfSignedLeaf,
            _ => PkiKind::Chain,
        };
        let pki = Pki::generate(kind)?;
        let normal = if kind == PkiKind::SelfSignedLeaf {
            vec![pki.leaf.clone()]
        } else {
            vec![
                pki.leaf.clone(),
                pki.intermediate.clone(),
                pki.anchor.clone(),
            ]
        };
        let all = rustls::ALL_VERSIONS;
        let tls = |presented: &[Vec<u8>],
                   ocsp: Option<Vec<u8>>,
                   versions: &[&'static SupportedProtocolVersion],
                   delay: Duration|
         -> Result<(Mode, Vec<Vec<u8>>), HarnessError> {
            let config = tls_config(certified_key(&pki, presented, ocsp)?, &shared, versions)?;
            let mode = Mode::Tls {
                acceptor: TlsAcceptor::from(config),
                delay,
            };
            Ok((mode, presented.to_vec()))
        };
        let (mode, presented) = match behavior {
            Behavior::Ok | Behavior::Expired | Behavior::SelfSigned => {
                tls(&normal, None, all, Duration::ZERO)?
            }
            Behavior::IncompleteChain => {
                tls(std::slice::from_ref(&pki.leaf), None, all, Duration::ZERO)?
            }
            Behavior::WrongOrder => tls(
                &[
                    pki.leaf.clone(),
                    pki.anchor.clone(),
                    pki.intermediate.clone(),
                ],
                None,
                all,
                Duration::ZERO,
            )?,
            Behavior::WithStaple(bytes) => tls(&normal, Some(bytes), all, Duration::ZERO)?,
            Behavior::Slow(delay) => tls(&normal, None, all, delay)?,
            Behavior::Tls12Only => tls(&normal, None, &[&rustls::version::TLS12], Duration::ZERO)?,
            Behavior::Tls13Only => tls(&normal, None, &[&rustls::version::TLS13], Duration::ZERO)?,
            Behavior::NeverResponds => (Mode::NeverResponds, Vec::new()),
            Behavior::FloodBytes => (Mode::Flood, Vec::new()),
            Behavior::PlainHttp => (Mode::PlainHttp, Vec::new()),
            Behavior::CloseImmediately => (Mode::Close, Vec::new()),
            Behavior::TlsAlert => (Mode::Alert(&ALERT_HANDSHAKE_FAILURE), Vec::new()),
            Behavior::Tls10Only => (Mode::Alert(&ALERT_PROTOCOL_VERSION), Vec::new()),
        };

        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let task = tokio::spawn(accept_loop(listener, Arc::new(mode), Arc::clone(&shared)));
        Ok(Self {
            addr,
            shared,
            anchor: pki.anchor,
            presented,
            task,
        })
    }

    /// Address the server listens on (always `127.0.0.1:<ephemeral port>`).
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// DER of the trust anchor: the CA, or the lone cert for `SelfSigned`.
    #[must_use]
    pub fn ca_der(&self) -> &[u8] {
        &self.anchor
    }

    /// DER of every certificate the server presents, in the order it sends
    /// them. Empty for behaviors that do not speak TLS.
    #[must_use]
    pub fn presented_chain(&self) -> &[Vec<u8>] {
        &self.presented
    }

    /// Number of TCP connections accepted so far.
    #[must_use]
    pub fn accepted_connections(&self) -> usize {
        self.shared.accepted.load(Ordering::SeqCst)
    }

    /// SNI of the last `ClientHello` that reached certificate selection.
    ///
    /// `NotYet`: no `ClientHello` seen. `Absent`: the client sent no SNI.
    /// `Present(name)`: the SNI host name.
    #[must_use]
    pub fn last_sni(&self) -> Observation<String> {
        lock(&self.shared.sni).clone()
    }

    /// ALPN protocol negotiated by the last completed handshake.
    ///
    /// `NotYet`: no handshake completed. `Absent`: completed without ALPN.
    /// Recorded after the server processed the client's
    /// `Finished`, so it can lag the client by a moment; prefer
    /// [`TestServer::negotiated_alpn`] right after a client handshake.
    #[must_use]
    pub fn last_alpn(&self) -> Observation<Vec<u8>> {
        lock(&self.shared.alpn).clone()
    }

    /// Polls [`TestServer::last_alpn`] until it is set or `timeout` elapses.
    pub async fn negotiated_alpn(&self, timeout: Duration) -> Observation<Vec<u8>> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let alpn = self.last_alpn();
            if alpn != Observation::NotYet || tokio::time::Instant::now() >= deadline {
                return alpn;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Stops the listener and every connection (same as dropping the value).
    pub fn shutdown(self) {
        drop(self);
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        // Aborting the listener drops its `JoinSet`, which aborts the connections.
        self.task.abort();
    }
}

async fn accept_loop(listener: TcpListener, mode: Arc<Mode>, shared: Arc<Shared>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                };
                shared.accepted.fetch_add(1, Ordering::SeqCst);
                if connections.len() >= MAX_CONNECTIONS {
                    continue;
                }
                connections.spawn(serve(stream, Arc::clone(&mode), Arc::clone(&shared)));
            }
            Some(_finished) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve(mut stream: TcpStream, mode: Arc<Mode>, shared: Arc<Shared>) {
    match &*mode {
        Mode::Tls { acceptor, delay } => {
            if !delay.is_zero() {
                tokio::time::sleep(*delay).await;
            }
            let Ok(mut tls) = acceptor.accept(stream).await else {
                return;
            };
            *lock(&shared.alpn) =
                Observation::from_option(tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec));
            let _ = tokio::time::timeout(Duration::from_secs(1), tls.shutdown()).await;
        }
        Mode::Close => drop(stream),
        Mode::NeverResponds => std::future::pending::<()>().await,
        Mode::Flood => flood(&mut stream).await,
        Mode::PlainHttp => {
            read_first_record(&mut stream).await;
            let _ = stream.write_all(PLAIN_HTTP_REPLY).await;
            let _ = stream.shutdown().await;
        }
        Mode::Alert(alert) => {
            read_first_record(&mut stream).await;
            let _ = stream.write_all(alert).await;
            let _ = stream.shutdown().await;
        }
    }
}

/// Best-effort bounded read of the client's first TLS record (one header plus
/// at most [`MAX_RECORD_BODY`] bytes, within [`RAW_READ_TIMEOUT`]). Reading it
/// avoids a TCP reset discarding the reply that follows.
async fn read_first_record(stream: &mut TcpStream) {
    let read = async {
        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).await?;
        let [_, _, _, hi, lo] = header;
        let len = usize::from(u16::from_be_bytes([hi, lo])).min(MAX_RECORD_BODY);
        let mut body = vec![0_u8; len];
        stream.read_exact(&mut body).await?;
        io::Result::Ok(())
    };
    let _ = tokio::time::timeout(RAW_READ_TIMEOUT, read).await;
}

/// Writes handshake-looking records forever (up to [`FLOOD_CAP_BYTES`]): the
/// first announces a `ServerHello` of 0xFFF0 bytes, the rest continue it, so a
/// TLS client keeps reading instead of failing on the first byte.
async fn flood(stream: &mut TcpStream) {
    let [hi, lo] = u16::try_from(FLOOD_RECORD_BODY)
        .unwrap_or(u16::MAX)
        .to_be_bytes();
    let header = [0x16, 0x03, 0x03, hi, lo];
    let mut first = header.to_vec();
    first.extend_from_slice(&[0x02, 0x00, 0xFF, 0xF0]);
    first.resize(header.len() + FLOOD_RECORD_BODY, 0);
    let mut next = header.to_vec();
    next.resize(header.len() + FLOOD_RECORD_BODY, 0);

    if stream.write_all(&first).await.is_err() {
        return;
    }
    let mut written = first.len();
    while written < FLOOD_CAP_BYTES {
        if stream.write_all(&next).await.is_err() {
            return;
        }
        written += next.len();
    }
}
