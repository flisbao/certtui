//! HTTP adapter for OCSP, CRL and AIA downloads: the `HttpFetcher` port on `reqwest`.
//!
//! URLs come from hostile certificates. This adapter never lets `reqwest`
//! follow redirects: it follows them by hand, a bounded number of times,
//! never from `https` to `http`, and re-checks every hop like the first URL.
//! The body is read chunk by chunk against a byte ceiling, and one timeout
//! covers connect, redirects and the whole body (so a server that drips one
//! byte a second still ends).

use std::time::Duration;

use async_trait::async_trait;
use certtui_app::http::HttpError;
use certtui_app::ports::HttpFetcher;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use reqwest::{Method, Url};

const USER_AGENT: &str = concat!("certtui/", env!("CARGO_PKG_VERSION"));

/// `HttpFetcher` backed by `reqwest` with `rustls` (`ring` provider).
///
/// No proxy is used until the configuration milestone (M8).
#[derive(Debug, Clone)]
pub struct ReqwestHttpFetcher {
    client: reqwest::Client,
    max_redirects: usize,
}

impl ReqwestHttpFetcher {
    /// Builds a fetcher that follows at most `max_redirects` redirects
    /// (`Limits::max_http_redirects`).
    ///
    /// # Errors
    ///
    /// [`HttpError::Transport`] when the HTTP client cannot be built.
    pub fn new(max_redirects: usize) -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .user_agent(USER_AGENT)
            .build()
            .map_err(|_| HttpError::Transport("client setup failed".to_owned()))?;
        Ok(Self {
            client,
            max_redirects,
        })
    }

    async fn execute(
        &self,
        method: Method,
        url: &str,
        payload: Option<(&str, Vec<u8>)>,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, HttpError> {
        let first = parse_url(url)?;
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
            let mut request = self.client.request(method.clone(), url.clone());
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
            url = redirect_target(&url, location)?;
            if !preserves_method(status) {
                method = Method::GET;
                payload = None;
            }
        }
    }
}

#[async_trait]
impl HttpFetcher for ReqwestHttpFetcher {
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

fn check_url(url: &Url) -> Result<(), HttpError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(HttpError::DisallowedScheme);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpError::InvalidUrl("contains credentials".to_owned()));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(HttpError::InvalidUrl("has no host".to_owned()));
    }
    Ok(())
}

/// Parses and vets the URL a certificate asked us to fetch.
fn parse_url(raw: &str) -> Result<Url, HttpError> {
    check_raw(raw)?;
    let url = Url::parse(raw).map_err(|_| HttpError::InvalidUrl("not a valid URL".to_owned()))?;
    check_url(&url)?;
    Ok(url)
}

/// Resolves a `Location` against `current` and vets the next hop.
fn redirect_target(current: &Url, location: &str) -> Result<Url, HttpError> {
    check_raw(location)?;
    let next = current
        .join(location)
        .map_err(|_| HttpError::InvalidUrl("not a valid redirect target".to_owned()))?;
    check_url(&next)?;
    if current.scheme() == "https" && next.scheme() == "http" {
        return Err(HttpError::DowngradeRedirect);
    }
    Ok(next)
}

/// Maps a `reqwest` failure to a message that carries no URL and no bytes.
fn map_reqwest_error(err: &reqwest::Error) -> HttpError {
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
        let got = redirect_target(&url("https://ca.example/ocsp"), "http://ca.example/ocsp");
        assert_eq!(got, Err(HttpError::DowngradeRedirect));
    }

    #[test]
    fn quando_redirect_http_para_https_deve_aceitar() {
        let got = redirect_target(&url("http://ca.example/a"), "https://ca.example/b");
        assert_eq!(got, Ok(url("https://ca.example/b")));
    }

    #[test]
    fn quando_redirect_e_relativo_deve_resolver_contra_a_url_atual() {
        let got = redirect_target(&url("http://ca.example/a/b"), "../c");
        assert_eq!(got, Ok(url("http://ca.example/c")));
    }

    #[test]
    fn quando_redirect_aponta_para_file_deve_dar_disallowed_scheme() {
        let got = redirect_target(&url("http://ca.example/a"), "file:///etc/passwd");
        assert_eq!(got, Err(HttpError::DisallowedScheme));
    }

    #[test]
    fn quando_redirect_tem_espaco_deve_dar_invalid_url() {
        let got = redirect_target(&url("http://ca.example/a"), "http://a b/");
        assert!(matches!(got, Err(HttpError::InvalidUrl(_))));
    }

    #[test]
    fn quando_url_e_file_ou_gopher_deve_dar_disallowed_scheme() {
        for raw in [
            "file:///etc/passwd",
            "gopher://example.com/",
            "ftp://example.com/x",
        ] {
            assert_eq!(parse_url(raw), Err(HttpError::DisallowedScheme), "{raw}");
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
                matches!(parse_url(raw), Err(HttpError::InvalidUrl(_))),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn quando_url_tem_credenciais_deve_dar_invalid_url() {
        for raw in ["http://user:pw@example.com/", "https://user@example.com/"] {
            assert!(
                matches!(parse_url(raw), Err(HttpError::InvalidUrl(_))),
                "{raw}"
            );
        }
    }

    #[test]
    fn quando_url_e_http_comum_deve_aceitar() {
        assert!(parse_url("http://ocsp.example.com/ocsp").is_ok());
        assert!(parse_url("https://crl.example.com:8443/a.crl").is_ok());
    }
}
