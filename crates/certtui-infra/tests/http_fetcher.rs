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

/// Local servers live on loopback, which the default policy refuses.
fn fetcher() -> ReqwestHttpFetcher {
    ReqwestHttpFetcher::new(3).with_internal_allowed(true)
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

#[tokio::test]
async fn quando_politica_padrao_deve_recusar_ip_literal_interno_sem_conectar() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    // `server.uri()` is `http://127.0.0.1:<port>`.
    let got = ReqwestHttpFetcher::new(3)
        .get(&server.uri(), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Err(HttpError::DisallowedDestination));
}

#[tokio::test]
async fn quando_politica_padrao_deve_recusar_nome_que_resolve_para_loopback() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let port = server.address().port();

    let got = ReqwestHttpFetcher::new(3)
        .get(&format!("http://localhost:{port}/"), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Err(HttpError::DisallowedDestination));
}

#[tokio::test]
async fn quando_flag_libera_urls_internas_deve_conectar_em_loopback_por_nome_e_por_ip() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1]))
        .mount(&server)
        .await;
    let port = server.address().port();
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.allow_internal_urls(true);

    let by_ip = fetcher.get(&server.uri(), LIMIT, TIMEOUT).await;
    let by_name = fetcher
        .get(&format!("http://localhost:{port}/"), LIMIT, TIMEOUT)
        .await;

    assert_eq!(by_ip, Ok(vec![1]));
    assert_eq!(by_name, Ok(vec![1]));
}

fn proxy_settings(
    server: &MockServer,
    no_proxy: Option<&str>,
) -> certtui_app::proxy::ProxySettings {
    let addr = *server.address();
    certtui_app::proxy::ProxySettings {
        endpoint: certtui_app::proxy::ProxyEndpoint {
            host: addr.ip().to_string(),
            port: addr.port(),
        },
        no_proxy: no_proxy.map(ToOwned::to_owned),
    }
}

#[tokio::test]
async fn quando_ha_proxy_deve_pedir_a_url_absoluta_ao_proxy() {
    // A plain-HTTP URL through a proxy is sent as `GET http://host/path`.
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocsp-response"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![9, 9]))
        .expect(1)
        .mount(&proxy)
        .await;
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));

    let got = fetcher
        .get("http://ocsp.example.invalid/ocsp-response", LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Ok(vec![9, 9]));
    let received = proxy.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(
        received.first().unwrap().url.host_str(),
        Some("ocsp.example.invalid")
    );
}

#[tokio::test]
async fn quando_host_esta_no_no_proxy_deve_ir_direto_sem_tocar_no_proxy() {
    let origin = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ca.der"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![7]))
        .mount(&origin)
        .await;
    let proxy = MockServer::start().await;
    let fetcher = ReqwestHttpFetcher::new(3).with_internal_allowed(true);
    fetcher.use_proxy(Some(proxy_settings(&proxy, Some("127.0.0.1"))));

    let got = fetcher
        .get(&format!("{}/ca.der", origin.uri()), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Ok(vec![7]));
    assert_eq!(proxy.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn quando_proxy_e_removido_deve_voltar_a_conexao_direta() {
    let origin = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1]))
        .mount(&origin)
        .await;
    let proxy = MockServer::start().await;
    let fetcher = ReqwestHttpFetcher::new(3).with_internal_allowed(true);
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));
    fetcher.use_proxy(None);

    let got = fetcher
        .get(&format!("{}/x", origin.uri()), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Ok(vec![1]));
    assert_eq!(proxy.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn quando_proxy_e_nome_resolve_para_loopback_deve_recusar_sem_tocar_no_proxy() {
    // Through a proxy the proxy resolves the name, so the policy is applied to
    // what this machine resolves too: `localhost` is loopback.
    let proxy = MockServer::start().await;
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));

    let got = fetcher.get("http://localhost:9/x", LIMIT, TIMEOUT).await;

    assert_eq!(got, Err(HttpError::DisallowedDestination));
    assert_eq!(proxy.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn quando_proxy_e_internal_permitido_deve_deixar_o_nome_interno_passar() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![5]))
        .mount(&proxy)
        .await;
    let fetcher = ReqwestHttpFetcher::new(3).with_internal_allowed(true);
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));

    let got = fetcher.get("http://localhost:9/x", LIMIT, TIMEOUT).await;

    assert_eq!(got, Ok(vec![5]));
    assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn quando_redirect_leva_a_nome_interno_pelo_proxy_deve_recusar_o_salto() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/start"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "http://localhost:9/next"),
        )
        .mount(&proxy)
        .await;
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));

    let got = fetcher
        .get("http://public.example.invalid/start", LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Err(HttpError::DisallowedDestination));
    // Only the first hop reached the proxy.
    assert_eq!(proxy.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn quando_proxy_e_nome_nao_resolve_aqui_deve_deixar_o_proxy_resolver() {
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1]))
        .mount(&proxy)
        .await;
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));

    let got = fetcher
        .get(
            "http://only-the-proxy-knows.example.invalid/ok",
            LIMIT,
            TIMEOUT,
        )
        .await;

    assert_eq!(got, Ok(vec![1]));
}

#[tokio::test]
async fn quando_use_limits_zera_redirects_deve_recusar_o_primeiro_redirect() {
    let origin = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/a"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/b"))
        .mount(&origin)
        .await;
    let fetcher = fetcher();
    fetcher.use_limits(&certtui_domain::limits::Limits {
        max_http_redirects: 0,
        ..certtui_domain::limits::Limits::default()
    });

    let got = fetcher
        .get(&format!("{}/a", origin.uri()), LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Err(HttpError::TooManyRedirects));
}

#[tokio::test]
async fn quando_proxy_e_dado_por_nome_de_loopback_deve_poder_ser_alcancado() {
    // A proxy named `localhost` (a local squid, an SSH tunnel) is the user's
    // own choice, not a certificate's: the destination policy must not refuse
    // to connect to it.
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/ocsp-response"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![4, 2]))
        .mount(&proxy)
        .await;
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.use_proxy(Some(certtui_app::proxy::ProxySettings {
        endpoint: certtui_app::proxy::ProxyEndpoint {
            host: "localhost".to_owned(),
            port: proxy.address().port(),
        },
        no_proxy: None,
    }));

    let got = fetcher
        .get("http://ocsp.example.invalid/ocsp-response", LIMIT, TIMEOUT)
        .await;

    assert_eq!(got, Ok(vec![4, 2]));
}

#[tokio::test]
async fn quando_lookup_local_estoura_o_dns_timeout_deve_deixar_o_proxy_resolver() {
    // A local DNS that hangs must cost one `dns_timeout`, not the whole
    // request budget; the name is then left to the proxy (best effort).
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![3]))
        .mount(&proxy)
        .await;
    let fetcher = ReqwestHttpFetcher::new(3);
    fetcher.use_limits(&certtui_domain::limits::Limits {
        dns_timeout: Duration::ZERO,
        ..certtui_domain::limits::Limits::default()
    });
    fetcher.use_proxy(Some(proxy_settings(&proxy, None)));

    // `localhost` would be refused if the lookup completed.
    let got = fetcher.get("http://localhost:9/x", LIMIT, TIMEOUT).await;

    assert_eq!(got, Ok(vec![3]));
}
