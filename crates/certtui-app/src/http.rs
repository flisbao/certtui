//! Types exchanged with the [`HttpFetcher`](crate::ports::HttpFetcher) port.

use thiserror::Error;

/// Why an HTTP request made on behalf of revocation checking or AIA chasing
/// failed.
///
/// URLs come from hostile certificates, so no variant carries the URL or any
/// response bytes: messages are short English sentences.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HttpError {
    /// The URL is malformed, has credentials, or contains whitespace or
    /// control characters.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// The URL scheme is neither `http` nor `https`.
    #[error("URL scheme is not allowed")]
    DisallowedScheme,
    /// A redirect went from `https` to `http`.
    #[error("redirect from https to http refused")]
    DowngradeRedirect,
    /// More redirects than the configured maximum.
    #[error("too many redirects")]
    TooManyRedirects,
    /// The response body is larger than the allowed number of bytes.
    #[error("response body exceeded the limit of {limit} bytes")]
    BodyTooLarge {
        /// The configured maximum in bytes.
        limit: usize,
    },
    /// The request ran out of time.
    #[error("request timed out")]
    Timeout,
    /// The server answered with a non-success status.
    #[error("server answered with HTTP status {0}")]
    Status(u16),
    /// Connection or protocol failure.
    #[error("transport error: {0}")]
    Transport(String),
}
