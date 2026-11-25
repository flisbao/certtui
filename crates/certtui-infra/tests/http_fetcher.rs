//! `ReqwestHttpFetcher` against local servers: bodies, limits, redirects, timeouts.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use certtui_app::http::HttpError;
use certtui_app::ports::HttpFetcher;
use certtui_infra::http::ReqwestHttpFetcher;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::{body_bytes, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LIMIT: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

fn fetcher() -> ReqwestHttpFetcher {
    ReqwestHttpFetcher::new(3).unwrap()
}

/// Reads the request head so the raw servers below answer like HTTP servers.
async fn read_request_head(stream: &mut TcpStream) {
    let mut seen = Vec::new();
    let mut byte = [0_u8; 1];
    while !seen.ends_with(b"\r\n\r\n") {
        if stream.read_exact(&mut byte).await.is_err() {
            return;
        }
        seen.push(byte[0]);
    }
}

#[tokio::test]
async fn quando_get_ok_deve_devolver_corpo() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.der"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1, 2, 3]))
        .mount(&server)
        .await;

    let got = fetcher()
        .get(&format!("{}/ca.der", server.uri()), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Ok(vec![1, 2, 3]));
}

#[tokio::test]
async fn quando_post_deve_enviar_content_type_e_corpo() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/ocsp"))
        .and(header("content-type", "application/ocsp-request"))
        .and(body_bytes(vec![9, 8, 7]))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![4, 5]))
        .expect(1)
        .mount(&server)
        .await;

    let got = fetcher()
        .post(
            &format!("{}/ocsp", server.uri()),
            "application/ocsp-request",
            vec![9, 8, 7],
            LIMIT,
            TIMEOUT,
        )
        .await;

    assert_eq!(got, Ok(vec![4, 5]));
}

#[tokio::test]
async fn quando_corpo_passa_do_teto_deve_dar_body_too_large_sem_ler_tudo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let written = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&written);
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let chunk = vec![0_u8; 64 * 1024];
        // Would be 1 GiB if the client kept reading.
        for _ in 0..16_384 {
            if stream.write_all(&chunk).await.is_err() {
                break;
            }
            counter.fetch_add(chunk.len(), Ordering::SeqCst);
        }
    });

    let got = fetcher()
        .get(&format!("http://{addr}/big"), 16 * 1024, TIMEOUT)
        .await;

    assert_eq!(got, Err(HttpError::BodyTooLarge { limit: 16 * 1024 }));
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .unwrap()
        .unwrap();
    let sent = written.load(Ordering::SeqCst);
    assert!(sent < 256 * 1024 * 1024, "server sent {sent} bytes");
}

#[tokio::test]
async fn quando_content_length_passa_do_teto_deve_dar_body_too_large() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0_u8; 4096]))
        .mount(&server)
        .await;

    let got = fetcher().get(&server.uri(), 1024, TIMEOUT).await;

    assert_eq!(got, Err(HttpError::BodyTooLarge { limit: 1024 }));
}

#[tokio::test]
async fn quando_servidor_e_lento_deve_dar_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&server)
        .await;

    let started = Instant::now();
    let got = fetcher()
        .get(&server.uri(), LIMIT, Duration::from_millis(200))
        .await;

    assert_eq!(got, Err(HttpError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn quando_servidor_pinga_um_byte_por_vez_deve_dar_timeout_total() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request_head(&mut stream).await;
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n";
        if stream.write_all(head).await.is_err() {
            return;
        }
        while stream.write_all(&[0]).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let started = Instant::now();
    let got = fetcher()
        .get(
            &format!("http://{addr}/drip"),
            10_000_000,
            Duration::from_millis(500),
        )
        .await;

    assert_eq!(got, Err(HttpError::Timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn quando_status_404_deve_dar_status_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404).set_body_string("<html>nope</html>"))
        .mount(&server)
        .await;

    let got = fetcher().get(&server.uri(), LIMIT, TIMEOUT).await;

    assert_eq!(got, Err(HttpError::Status(404)));
}

#[tokio::test]
async fn quando_redirect_loop_deve_dar_too_many_redirects() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "/loop"))
        .mount(&server)
        .await;

    let got = fetcher()
        .get(&format!("{}/loop", server.uri()), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Err(HttpError::TooManyRedirects));
}

#[tokio::test]
async fn quando_redirect_e_relativo_deve_seguir_ate_o_corpo() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/old"))
        .respond_with(ResponseTemplate::new(301).insert_header("Location", "/new"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/new"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7]))
        .mount(&server)
        .await;

    let got = fetcher()
        .get(&format!("{}/old", server.uri()), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Ok(vec![7]));
}

#[tokio::test]
async fn quando_redirect_aponta_para_file_deve_dar_disallowed_scheme() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "file:///etc/passwd"))
        .mount(&server)
        .await;

    let got = fetcher().get(&server.uri(), LIMIT, TIMEOUT).await;

    assert_eq!(got, Err(HttpError::DisallowedScheme));
}

#[tokio::test]
async fn quando_url_e_file_ou_gopher_deve_dar_disallowed_scheme_sem_rede() {
    for url in ["file:///etc/passwd", "gopher://example.com/"] {
        let got = fetcher().get(url, LIMIT, TIMEOUT).await;
        assert_eq!(got, Err(HttpError::DisallowedScheme), "{url}");
    }
}

#[tokio::test]
async fn quando_url_tem_espaco_ou_credenciais_deve_dar_invalid_url() {
    for url in ["http://a b/", "http://user:pw@127.0.0.1/"] {
        let got = fetcher().get(url, LIMIT, TIMEOUT).await;
        assert!(matches!(got, Err(HttpError::InvalidUrl(_))), "{url}");
    }
}
