//! Name resolution and TCP connection for the TLS fetcher.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use certtui_app::fetch::{FetchError, Stage};
use tokio::net::TcpStream;

use super::session::sanitize;

/// Most addresses kept from a resolution; a host with more is still reachable.
const MAX_RESOLVED_ADDRS: usize = 16;
/// Longest error text copied out of an I/O error.
const MAX_IO_TEXT: usize = 120;

/// Source of the socket addresses for a host name.
///
/// Public only so integration tests can inject fake resolution (tests cannot
/// see `pub(crate)` items); not part of the supported API.
#[doc(hidden)]
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    /// Resolves `host` to socket addresses for `port`, in preference order.
    ///
    /// The caller applies the DNS timeout; implementations need not.
    ///
    /// # Errors
    ///
    /// Any [`io::Error`] the lookup produces.
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// Resolver backed by the operating system (`getaddrinfo` via tokio).
#[doc(hidden)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

#[async_trait::async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let found = tokio::net::lookup_host((host, port)).await?;
        Ok(found.take(MAX_RESOLVED_ADDRS).collect())
    }
}

/// Resolves `host` within `timeout`. An IP literal is returned as is, without
/// asking `resolver`.
///
/// # Errors
///
/// [`FetchError::Dns`] on failure or an empty answer,
/// [`FetchError::Timeout`] with [`Stage::Dns`] when `timeout` elapses.
pub(crate) async fn resolve(
    resolver: &dyn Resolver,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, FetchError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let found = tokio::time::timeout(timeout, resolver.resolve(host, port))
        .await
        .map_err(|_| FetchError::Timeout(Stage::Dns))?
        .map_err(|e| FetchError::Dns(io_text(&e)))?;
    if found.is_empty() {
        return Err(FetchError::Dns("no addresses found".to_owned()));
    }
    Ok(found.into_iter().take(MAX_RESOLVED_ADDRS).collect())
}

/// Connects to the first address that accepts, trying them one after another
/// within ONE `timeout` budget shared by all attempts.
///
/// # Errors
///
/// [`FetchError::Connect`] with the last failure when every address refused,
/// [`FetchError::Timeout`] with [`Stage::Connect`] when the budget ran out.
pub(crate) async fn connect_first(
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), FetchError> {
    let attempts = async {
        let mut last = "no address to connect to".to_owned();
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok((stream, *addr)),
                Err(e) => last = io_text(&e),
            }
        }
        Err(FetchError::Connect(last))
    };
    tokio::time::timeout(timeout, attempts)
        .await
        .unwrap_or(Err(FetchError::Timeout(Stage::Connect)))
}

/// Short, control-free text for an I/O error (the OS wording can vary).
fn io_text(err: &io::Error) -> String {
    sanitize(&err.to_string(), MAX_IO_TEXT)
}
