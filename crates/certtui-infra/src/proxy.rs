//! HTTP CONNECT proxies: parsing `--proxy`, tunnelling a TCP connection and
//! reading the proxy from the environment.

use std::time::Duration;

use certtui_app::proxy::{ProxyEndpoint, ProxySettings};
use certtui_domain::target_parse::parse_network_target;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::env::EnvVars;

/// Longest answer to a CONNECT read from the proxy (status line and headers).
pub const MAX_CONNECT_RESPONSE_BYTES: usize = 8 * 1024;

/// Port of a proxy URL that names none.
const DEFAULT_PROXY_PORT: u16 = 80;

/// Why a proxy could not be used.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProxyError {
    /// The proxy URL is not `http://host[:port]`; the text never quotes the URL
    /// (it could hold credentials).
    #[error("invalid proxy: {0}")]
    Invalid(&'static str),
    /// The proxy answered `407`: it wants credentials, which are not supported.
    #[error("the proxy requires authentication (407), which is not supported")]
    AuthRequired,
    /// The proxy refused the tunnel.
    #[error("the proxy refused the tunnel (status {0})")]
    Status(u16),
    /// The proxy closed the connection without a usable answer.
    #[error("the proxy closed the connection without answering")]
    Closed,
    /// The answer is larger than [`MAX_CONNECT_RESPONSE_BYTES`].
    #[error("the proxy answer is larger than {MAX_CONNECT_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    /// The answer is not an HTTP status line.
    #[error("the proxy answer is not valid HTTP")]
    Malformed,
    /// The proxy did not answer within the connect budget.
    #[error("the proxy did not answer in time")]
    Timeout,
    /// The TCP connection to the proxy failed.
    #[error("cannot connect to the proxy: {0}")]
    Connect(String),
}

/// Parses `http://host[:port]` (port 80 when absent). Credentials, other
/// schemes, paths and queries are refused, without echoing the URL.
///
/// # Errors
///
/// [`ProxyError::Invalid`] with the reason.
pub fn parse_proxy_url(url: &str) -> Result<ProxyEndpoint, ProxyError> {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .map(|_| url.get("http://".len()..).unwrap_or_default())
        .ok_or(ProxyError::Invalid(
            "only http://host:port is supported (no https, socks or credentials)",
        ))?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains('@') {
        return Err(ProxyError::Invalid(
            "credentials in the proxy URL are not supported",
        ));
    }
    if authority.is_empty() || authority.contains(['/', '?', '#']) {
        return Err(ProxyError::Invalid("expected http://host:port"));
    }
    let has_port = match authority.strip_prefix('[') {
        Some(after) => after
            .split_once(']')
            .is_some_and(|(_, tail)| tail.starts_with(':')),
        None => authority.contains(':'),
    };
    let parsed = if has_port {
        parse_network_target(authority)
    } else {
        parse_network_target(&format!("{authority}:{DEFAULT_PROXY_PORT}"))
    }
    .map_err(|_| ProxyError::Invalid("the proxy host or port is not valid"))?;
    Ok(ProxyEndpoint {
        host: parsed.host,
        port: parsed.port,
    })
}

/// Opens a TCP connection to `proxy` and asks it to tunnel to
/// `target_host:target_port`, all within `budget`. Returns the stream, ready
/// for the TLS handshake. Reads at most [`MAX_CONNECT_RESPONSE_BYTES`] of the
/// answer, one byte at a time, so nothing past the blank line is consumed.
///
/// # Errors
///
/// [`ProxyError`] describing why the tunnel could not be opened.
pub async fn connect_via_proxy(
    proxy: &ProxyEndpoint,
    target_host: &str,
    target_port: u16,
    budget: Duration,
) -> Result<TcpStream, ProxyError> {
    if target_host.is_empty() || target_host.contains(['\r', '\n', ' ', '\t']) {
        return Err(ProxyError::Malformed);
    }
    tokio::time::timeout(budget, open_tunnel(proxy, target_host, target_port))
        .await
        .map_err(|_| ProxyError::Timeout)?
}

async fn open_tunnel(
    proxy: &ProxyEndpoint,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, ProxyError> {
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port))
        .await
        .map_err(|error| ProxyError::Connect(error.kind().to_string()))?;
    let authority = if target_host.contains(':') {
        format!("[{target_host}]:{target_port}")
    } else {
        format!("{target_host}:{target_port}")
    };
    let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| ProxyError::Closed)?;
    let head = read_head(&mut stream).await?;
    match status_of(&head)? {
        200..=299 => Ok(stream),
        407 => Err(ProxyError::AuthRequired),
        status => Err(ProxyError::Status(status)),
    }
}

/// Reads up to the blank line that ends the answer.
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, ProxyError> {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if head.len() >= MAX_CONNECT_RESPONSE_BYTES {
            return Err(ProxyError::ResponseTooLarge);
        }
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return Err(ProxyError::Closed),
            Ok(_) => head.extend_from_slice(&byte),
        }
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

/// The status code of `HTTP/1.x SSS ...`.
fn status_of(head: &[u8]) -> Result<u16, ProxyError> {
    let line = head
        .split(|&b| b == b'\n')
        .next()
        .ok_or(ProxyError::Malformed)?;
    let line = std::str::from_utf8(line).map_err(|_| ProxyError::Malformed)?;
    let mut parts = line.trim_end().split(' ');
    match (parts.next(), parts.next()) {
        (Some(version), Some(code)) if version.starts_with("HTTP/1.") => {
            code.parse().map_err(|_| ProxyError::Malformed)
        }
        _ => Err(ProxyError::Malformed),
    }
}

/// The proxy named by the environment.
#[derive(Debug, Clone, Copy)]
pub struct EnvProxy;

impl EnvProxy {
    /// The proxy of `HTTPS_PROXY` (or `https_proxy`) with the `NO_PROXY` list,
    /// only when `enabled` (`network.use_env_proxy`). `host:port` without a
    /// scheme is taken as `http://host:port`.
    ///
    /// # Errors
    ///
    /// [`ProxyError::Invalid`] when the variable is set but is not a usable
    /// `http://` proxy. Falling back to a direct connection would send the
    /// traffic around a proxy the user asked for.
    pub fn from_env(env: &EnvVars, enabled: bool) -> Result<Option<ProxySettings>, ProxyError> {
        if !enabled {
            return Ok(None);
        }
        let Some(value) = env.get("HTTPS_PROXY").or_else(|| env.get("https_proxy")) else {
            return Ok(None);
        };
        let url = if value.contains("://") {
            value.to_owned()
        } else {
            format!("http://{value}")
        };
        let endpoint = parse_proxy_url(&url)?;
        let no_proxy = env
            .get("NO_PROXY")
            .or_else(|| env.get("no_proxy"))
            .map(ToOwned::to_owned);
        Ok(Some(ProxySettings {
            endpoint,
            // Always `Some`: a proxy from the environment honors `NO_PROXY`.
            no_proxy: Some(no_proxy.unwrap_or_default()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(url: &str) -> Result<(String, u16), ProxyError> {
        parse_proxy_url(url).map(|e| (e.host, e.port))
    }

    #[test]
    fn parse_proxy_url_deve_aceitar_so_http_simples() {
        assert_eq!(endpoint("http://p:3128"), Ok(("p".to_owned(), 3128)));
        assert_eq!(endpoint("http://p:3128/"), Ok(("p".to_owned(), 3128)));
        assert_eq!(
            endpoint("HTTP://Proxy.Corp:8080"),
            Ok(("proxy.corp".to_owned(), 8080))
        );
        assert_eq!(endpoint("http://p"), Ok(("p".to_owned(), 80)));
        assert_eq!(
            endpoint("http://127.0.0.1:3128"),
            Ok(("127.0.0.1".to_owned(), 3128))
        );
        assert_eq!(endpoint("http://[::1]:3128"), Ok(("::1".to_owned(), 3128)));
    }

    #[test]
    fn parse_proxy_url_deve_recusar_https_socks_credenciais_e_lixo() {
        for url in [
            "https://p:3128",
            "socks5://p:1080",
            "ftp://p",
            "p:3128",
            "",
            "http://",
            "http://u:pw@p:3128",
            "http://u@p:3128",
            "http://p:3128/path",
            "http://p:3128?x=1",
            "http://p:notaport",
            "http://p:99999",
            "http://bad host:3128",
        ] {
            assert!(
                matches!(parse_proxy_url(url), Err(ProxyError::Invalid(_))),
                "{url}"
            );
        }
    }

    #[test]
    fn parse_proxy_url_nao_deve_ecoar_a_url_nem_a_senha() {
        let error = parse_proxy_url("http://user:pw@proxy.corp:3128").unwrap_err();
        let text = format!("{error} {error:?}");
        assert!(!text.contains("pw"), "{text}");
        assert!(!text.contains("user"), "{text}");
        assert!(!text.contains("proxy.corp"), "{text}");
    }

    fn env(pairs: &[(&str, &str)]) -> EnvVars {
        EnvVars::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn quando_use_env_proxy_false_deve_ignorar_https_proxy() {
        let vars = env(&[
            ("HTTPS_PROXY", "http://p:3128"),
            ("https_proxy", "http://q:1"),
        ]);
        assert_eq!(EnvProxy::from_env(&vars, false), Ok(None));
    }

    #[test]
    fn quando_use_env_proxy_true_deve_ler_https_proxy_em_maiusculas_ou_minusculas() {
        let upper = EnvProxy::from_env(&env(&[("HTTPS_PROXY", "http://p:3128")]), true)
            .unwrap()
            .unwrap();
        assert_eq!(upper.endpoint.host, "p");
        let lower = EnvProxy::from_env(&env(&[("https_proxy", "http://q:8080")]), true)
            .unwrap()
            .unwrap();
        assert_eq!(
            (lower.endpoint.host.as_str(), lower.endpoint.port),
            ("q", 8080)
        );
        // Upper case wins when both are set.
        let both = EnvProxy::from_env(
            &env(&[("HTTPS_PROXY", "http://p:1"), ("https_proxy", "http://q:2")]),
            true,
        )
        .unwrap()
        .unwrap();
        assert_eq!(both.endpoint.port, 1);
    }

    #[test]
    fn quando_variavel_nao_tem_esquema_deve_tratar_como_http() {
        let settings = EnvProxy::from_env(&env(&[("HTTPS_PROXY", "p:3128")]), true)
            .unwrap()
            .unwrap();
        assert_eq!(settings.endpoint.port, 3128);
    }

    #[test]
    fn quando_variavel_e_invalida_com_use_env_proxy_deve_dar_erro_sem_ecoar_a_url() {
        for value in ["socks5://p:1080", "https://p:1", "http://u:pw@p:1", "::::"] {
            let result = EnvProxy::from_env(&env(&[("HTTPS_PROXY", value)]), true);
            let Err(error) = result else {
                unreachable!("{value} must be refused, got {result:?}");
            };
            assert!(matches!(error, ProxyError::Invalid(_)), "{value}");
            let text = format!("{error} {error:?}");
            assert!(!text.contains("pw"), "{text}");
        }
    }

    #[test]
    fn quando_variavel_e_invalida_sem_use_env_proxy_deve_ser_ignorada() {
        let vars = env(&[("HTTPS_PROXY", "http://u:pw@p:1")]);
        assert_eq!(EnvProxy::from_env(&vars, false), Ok(None));
    }

    #[test]
    fn quando_nao_ha_variavel_deve_dar_none() {
        assert_eq!(EnvProxy::from_env(&env(&[]), true), Ok(None));
    }

    #[test]
    fn quando_use_env_proxy_true_e_no_proxy_casa_deve_conectar_direto() {
        let vars = env(&[
            ("HTTPS_PROXY", "http://p:3128"),
            ("NO_PROXY", "localhost,.internal.corp"),
        ]);
        let settings = EnvProxy::from_env(&vars, true).unwrap().unwrap();
        assert_eq!(settings.endpoint_for("localhost"), None);
        assert_eq!(settings.endpoint_for("db.internal.corp"), None);
        assert!(settings.endpoint_for("example.com").is_some());
        // The lower-case spelling of the list works too.
        let vars = env(&[("HTTPS_PROXY", "http://p:3128"), ("no_proxy", "*")]);
        assert_eq!(
            EnvProxy::from_env(&vars, true)
                .unwrap()
                .unwrap()
                .endpoint_for("x.example"),
            None
        );
    }

    #[test]
    fn status_of_deve_ler_o_codigo_da_linha_de_status() {
        assert_eq!(
            status_of(b"HTTP/1.1 200 Connection established\r\n\r\n"),
            Ok(200)
        );
        assert_eq!(
            status_of(b"HTTP/1.0 407 Proxy Authentication Required\r\n\r\n"),
            Ok(407)
        );
        for bad in [
            &b"garbage\r\n\r\n"[..],
            b"HTTP/1.1 abc\r\n\r\n",
            b"\r\n\r\n",
            b"SMTP/1.1 200\r\n\r\n",
        ] {
            assert_eq!(status_of(bad), Err(ProxyError::Malformed), "{bad:?}");
        }
    }
}
