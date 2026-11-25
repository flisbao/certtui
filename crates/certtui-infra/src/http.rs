//! HTTP adapter for OCSP, CRL and AIA downloads: the `HttpFetcher` port on `reqwest`.
//!
//! URLs come from hostile certificates. This adapter never lets `reqwest`
//! follow redirects: it follows them by hand, a bounded number of times,
//! never from `https` to `http`, and re-checks every hop like the first URL.
//! The body is read chunk by chunk against a byte ceiling, and one timeout
//! covers connect, redirects and the whole body (so a server that drips one
//! byte a second still ends).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use certtui_app::http::HttpError;
use certtui_app::ports::HttpFetcher;
use certtui_app::proxy::ProxySettings;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use reqwest::{Method, Url};

use crate::destination::{FilteringResolver, is_blocked, is_blocked_error};

const USER_AGENT: &str = concat!("certtui/", env!("CARGO_PKG_VERSION"));

/// `HttpFetcher` backed by `reqwest` with `rustls` (`ring` provider).
///
/// The HTTP client (which loads the system trust roots) is built on the first
/// request, so a run that never reaches the network pays nothing for it.
/// A proxy (`--proxy`, or the environment when the config allows it) is
/// consulted on every request, so it can be set after the first one.
#[derive(Debug)]
pub struct ReqwestHttpFetcher {
    client: OnceLock<Result<reqwest::Client, HttpError>>,
    max_redirects: usize,
    /// Lifts the refusal of internal destinations (`--allow-internal-urls`).
    allow_internal: Arc<AtomicBool>,
    /// The proxy requests go through, read by the client on each request.
    proxy: Arc<RwLock<Option<ProxySettings>>>,
}

impl ReqwestHttpFetcher {
    /// A fetcher that follows at most `max_redirects` redirects
    /// (`Limits::max_http_redirects`).
    #[must_use]
    pub fn new(max_redirects: usize) -> Self {
        Self {
            client: OnceLock::new(),
            max_redirects,
            allow_internal: Arc::new(AtomicBool::new(false)),
            proxy: Arc::new(RwLock::new(None)),
        }
    }

    /// The same fetcher with internal destinations (loopback, link-local,
    /// cloud metadata) allowed or refused. Refused is the default.
    #[must_use]
    pub fn with_internal_allowed(self, allow: bool) -> Self {
        self.allow_internal.store(allow, Ordering::Relaxed);
        self
    }

    fn internal_allowed(&self) -> bool {
        self.allow_internal.load(Ordering::Relaxed)
    }

    fn client(&self) -> Result<&reqwest::Client, HttpError> {
        let allow_internal = Arc::clone(&self.allow_internal);
        let proxy = Arc::clone(&self.proxy);
        self.client
            .get_or_init(|| {
                reqwest::Client::builder()
                    .dns_resolver(Arc::new(FilteringResolver::new(allow_internal)))
                    .redirect(reqwest::redirect::Policy::none())
                    .proxy(reqwest::Proxy::custom(move |url| proxy_for(&proxy, url)))
                    .user_agent(USER_AGENT)
                    .build()
                    .map_err(|_| HttpError::Transport("client setup failed".to_owned()))
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    async fn execute(
        &self,
        method: Method,
        url: &str,
        payload: Option<(&str, Vec<u8>)>,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, HttpError> {
        let first = parse_url(url, self.internal_allowed())?;
        tokio::time::timeout(timeout, self.run(first, method, payload, max_bytes))
            .await
            .map_err(|_| HttpError::Timeout)?
    }

    async fn run(
        &self,
        mut url: Url,
        mut method: Method,
        mut payload: Option<(&str, Vec<u8>)>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        let mut redirects = 0_usize;
        loop {
            let mut request = self.client()?.request(method.clone(), url.clone());
            if let Some((content_type, body)) = &payload {
                request = request
                    .header(CONTENT_TYPE, *content_type)
                    .body(body.clone());
            }
            let response = request.send().await.map_err(|e| map_reqwest_error(&e))?;
            let status = response.status().as_u16();
            if !is_followed_redirect(status) {
                if !response.status().is_success() {
                    return Err(HttpError::Status(status));
                }
                return read_capped(response, max_bytes).await;
            }
            if redirects >= self.max_redirects {
                return Err(HttpError::TooManyRedirects);
            }
            redirects += 1;
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(HttpError::Status(status))?;
            url = redirect_target(&url, location, self.internal_allowed())?;
            if !preserves_method(status) {
                method = Method::GET;
                payload = None;
            }
        }
    }
}

/// The proxy URL for a request to `url`, or `None` to go direct. Never
/// panics: a poisoned lock or an unparsable endpoint means "direct".
fn proxy_for(proxy: &RwLock<Option<ProxySettings>>, url: &Url) -> Option<Url> {
    let guard = proxy.read().unwrap_or_else(PoisonError::into_inner);
    let endpoint = guard.as_ref()?.endpoint_for(url.host_str()?)?;
    Url::parse(&format!("http://{endpoint}")).ok()
}

#[async_trait]
impl HttpFetcher for ReqwestHttpFetcher {
    fn use_proxy(&self, proxy: Option<ProxySettings>) {
        *self.proxy.write().unwrap_or_else(PoisonError::into_inner) = proxy;
    }

    fn allow_internal_urls(&self, allow: bool) {
        self.allow_internal.store(allow, Ordering::Relaxed);
    }

    async fn get(
        &self,
        url: &str,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, HttpError> {
        self.execute(Method::GET, url, None, max_bytes, timeout)
            .await
    }

    async fn post(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, HttpError> {
        self.execute(
            Method::POST,
            url,
            Some((content_type, body)),
            max_bytes,
            timeout,
        )
        .await
    }
}

/// Reads the body in chunks, stopping as soon as `max_bytes` is exceeded.
async fn read_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, HttpError> {
    let too_large = HttpError::BodyTooLarge { limit: max_bytes };
    let limit = u64::try_from(max_bytes).unwrap_or(u64::MAX);
    if response.content_length().is_some_and(|len| len > limit) {
        return Err(too_large);
    }
    let mut body = Vec::new();
    let mut total = 0_usize;
    while let Some(chunk) = response.chunk().await.map_err(|e| map_reqwest_error(&e))? {
        total = total.checked_add(chunk.len()).ok_or(too_large.clone())?;
        if total > max_bytes {
            return Err(too_large);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Statuses whose `Location` we follow; other 3xx are plain failures.
fn is_followed_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Only 307 and 308 keep the method and body; the rest become a bodiless GET.
fn preserves_method(status: u16) -> bool {
    matches!(status, 307 | 308)
}

/// Rejects whitespace and control characters before the URL parser, which
/// would silently strip or encode them.
fn check_raw(raw: &str) -> Result<(), HttpError> {
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(HttpError::InvalidUrl(
            "contains whitespace or control characters".to_owned(),
        ));
    }
    Ok(())
}

fn check_url(url: &Url, allow_internal: bool) -> Result<(), HttpError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(HttpError::DisallowedScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpError::InvalidUrl("contains credentials".to_owned()));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(HttpError::InvalidUrl("has no host".to_owned()));
    }
    // An IP literal never reaches the resolver, so it is judged here; the
    // resolver judges every name. The URL parser has already normalized
    // forms like `http://2130706433/` to `127.0.0.1`.
    let literal = url.host_str().and_then(|host| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .ok()
    });
    if !allow_internal && literal.is_some_and(is_blocked) {
        return Err(HttpError::DisallowedDestination);
    }
    Ok(())
}

/// Parses and vets the URL a certificate asked us to fetch.
fn parse_url(raw: &str, allow_internal: bool) -> Result<Url, HttpError> {
    check_raw(raw)?;
    let url = Url::parse(raw).map_err(|_| HttpError::InvalidUrl("not a valid URL".to_owned()))?;
    check_url(&url, allow_internal)?;
    Ok(url)
}

/// Resolves a `Location` against `current` and vets the next hop.
fn redirect_target(current: &Url, location: &str, allow_internal: bool) -> Result<Url, HttpError> {
    check_raw(location)?;
    let next = current
        .join(location)
        .map_err(|_| HttpError::InvalidUrl("not a valid redirect target".to_owned()))?;
    check_url(&next, allow_internal)?;
    if current.scheme() == "https" && next.scheme() == "http" {
        return Err(HttpError::DowngradeRedirect);
    }
    Ok(next)
}

/// Maps a `reqwest` failure to a message that carries no URL and no bytes.
fn map_reqwest_error(err: &reqwest::Error) -> HttpError {
    if is_blocked_error(err) {
        return HttpError::DisallowedDestination;
    }
    if err.is_timeout() {
        return HttpError::Timeout;
    }
    let what = if err.is_connect() {
        "connection failed"
    } else if err.is_body() || err.is_decode() {
        "reading the response failed"
    } else if err.is_request() || err.is_builder() {
        "sending the request failed"
    } else {
        "HTTP error"
    };
    HttpError::Transport(what.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(raw: &str) -> Url {
        Url::parse(raw).unwrap()
    }

    #[test]
    fn quando_redirect_https_para_http_deve_dar_downgrade_redirect() {
        let got = redirect_target(
            &url("https://ca.example/ocsp"),
            "http://ca.example/ocsp",
            false,
        );
        assert_eq!(got, Err(HttpError::DowngradeRedirect));
    }

    #[test]
    fn quando_redirect_http_para_https_deve_aceitar() {
        let got = redirect_target(&url("http://ca.example/a"), "https://ca.example/b", false);
        assert_eq!(got, Ok(url("https://ca.example/b")));
    }

    #[test]
    fn quando_redirect_e_relativo_deve_resolver_contra_a_url_atual() {
        let got = redirect_target(&url("http://ca.example/a/b"), "../c", false);
        assert_eq!(got, Ok(url("http://ca.example/c")));
    }

    #[test]
    fn quando_redirect_aponta_para_file_deve_dar_disallowed_scheme() {
        let got = redirect_target(&url("http://ca.example/a"), "file:///etc/passwd", false);
        assert_eq!(got, Err(HttpError::DisallowedScheme));
    }

    #[test]
    fn quando_redirect_tem_espaco_deve_dar_invalid_url() {
        let got = redirect_target(&url("http://ca.example/a"), "http://a b/", false);
        assert!(matches!(got, Err(HttpError::InvalidUrl(_))));
    }

    #[test]
    fn quando_url_e_file_ou_gopher_deve_dar_disallowed_scheme() {
        for raw in [
            "file:///etc/passwd",
            "gopher://example.com/",
            "ftp://example.com/x",
        ] {
            assert_eq!(
                parse_url(raw, false),
                Err(HttpError::DisallowedScheme),
                "{raw}"
            );
        }
    }

    #[test]
    fn quando_url_tem_espaco_ou_controle_deve_dar_invalid_url() {
        for raw in [
            "http://a b/",
            "http://exa\u{7}mple.com/",
            "http://example.com/\n",
            " http://example.com/",
        ] {
            assert!(
                matches!(parse_url(raw, false), Err(HttpError::InvalidUrl(_))),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn quando_url_tem_credenciais_deve_dar_invalid_url() {
        for raw in ["http://user:pw@example.com/", "https://user@example.com/"] {
            assert!(
                matches!(parse_url(raw, false), Err(HttpError::InvalidUrl(_))),
                "{raw}"
            );
        }
    }

    #[test]
    fn quando_url_e_ip_interno_deve_dar_disallowed_destination() {
        for raw in [
            "http://127.0.0.1/",
            "http://127.0.0.1:22/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:127.0.0.1]/",
            "http://2130706433/",
            "http://0x7f.0.0.1/",
            "http://0.0.0.0/",
            "http://100.100.100.200/",
            "http://[fd00:ec2::254]/",
        ] {
            assert_eq!(
                parse_url(raw, false),
                Err(HttpError::DisallowedDestination),
                "{raw}"
            );
        }
    }

    #[test]
    fn quando_url_e_ip_privado_ou_publico_deve_aceitar() {
        for raw in [
            "http://10.0.0.5/ocsp",
            "http://192.168.1.10:8080/crl",
            "http://172.16.4.9/",
            "http://[fd12:3456::1]/",
            "http://203.0.113.5/",
        ] {
            assert!(parse_url(raw, false).is_ok(), "{raw}");
        }
    }

    #[test]
    fn quando_politica_esta_liberada_deve_aceitar_ip_interno() {
        assert!(parse_url("http://127.0.0.1:8080/", true).is_ok());
        assert!(parse_url("http://169.254.169.254/", true).is_ok());
    }

    #[test]
    fn quando_redirect_aponta_para_ip_interno_deve_dar_disallowed_destination() {
        for target in [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]:22/",
        ] {
            let got = redirect_target(&url("http://ca.example/ocsp"), target, false);
            assert_eq!(got, Err(HttpError::DisallowedDestination), "{target}");
        }
        let allowed = redirect_target(
            &url("http://ca.example/ocsp"),
            "http://10.0.0.5/ocsp",
            false,
        );
        assert!(allowed.is_ok());
    }

    #[test]
    fn quando_url_e_http_comum_deve_aceitar() {
        assert!(parse_url("http://ocsp.example.com/ocsp", false).is_ok());
        assert!(parse_url("https://crl.example.com:8443/a.crl", false).is_ok());
    }
}
