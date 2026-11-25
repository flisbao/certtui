//! AIA chasing (`--aia`): download the missing issuers a certificate points to.
//!
//! The URLs come from hostile certificates, so the loop is iterative and
//! bounded: a URL is fetched at most once, a certificate is added at most
//! once, the chain never grows past `max_chain_len`, and every download is
//! capped in bytes and time. Nothing here decides trust: a downloaded
//! certificate is only checked to *name* the issuer being looked for.

use certtui_domain::chain_analysis::{KnownIssuer, analyze_chain};
use certtui_domain::extract::scan_text;
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertOrigin, CertificateRecord, Chain};
use std::collections::HashSet;
use tokio_util::sync::CancellationToken;

use crate::cancel::cancellable;
use crate::ports::HttpFetcher;

/// Only the first few `caIssuers` URLs of a certificate are tried: a hostile
/// certificate can list thousands, each costing up to `http_timeout`.
const MAX_AIA_URLS_PER_CERT: usize = 3;

/// Completes the chain with issuers fetched from `Authority Information Access`.
///
/// Returns the (possibly longer) chain and the URLs that supplied a
/// certificate that was kept. Network failures, oversized or foreign
/// downloads are skipped silently: AIA is best effort and `CHAIN_INCOMPLETE`
/// stays in the report when it did not help.
pub async fn chase_aia(
    http: &dyn HttpFetcher,
    chain: Chain,
    anchors: &[KnownIssuer],
    limits: &Limits,
    cancel: CancellationToken,
) -> (Chain, Vec<String>) {
    let mut chain = chain;
    let mut used = Vec::new();
    let mut tried: HashSet<String> = HashSet::new();
    // Total downloads for the whole chase: one per certificate the chain may still gain.
    let mut budget = limits.max_chain_len;
    let mut seen: HashSet<[u8; 32]> = chain
        .records()
        .iter()
        .map(|r| r.fingerprints.sha256.0)
        .collect();
    while chain.len() < limits.max_chain_len && !cancel.is_cancelled() {
        let analysis = analyze_chain(&chain, anchors, limits);
        if !analysis.incomplete {
            break;
        }
        let Some(tail) = analysis.path.last().and_then(|i| chain.get(*i)) else {
            break;
        };
        let urls: Vec<String> = tail.summary.aia.ca_issuers.clone();
        let wanted = tail.summary.issuer.rfc4514.clone();
        let Some((record, url)) = fetch_issuer(
            http,
            &urls,
            &wanted,
            &mut Fetching {
                tried: &mut tried,
                seen: &mut seen,
                budget: &mut budget,
            },
            limits,
            &cancel,
        )
        .await
        else {
            break;
        };
        let mut records = chain.records().to_vec();
        records.push(record);
        let Ok(longer) = Chain::new(records, limits) else {
            break;
        };
        chain = longer;
        used.push(url);
    }
    (chain, used)
}

/// What the chase remembers between iterations.
struct Fetching<'a> {
    /// URLs already requested (each is fetched once).
    tried: &'a mut HashSet<String>,
    /// SHA-256 of every certificate already in the chain.
    seen: &'a mut HashSet<[u8; 32]>,
    /// Downloads still allowed.
    budget: &'a mut usize,
}

/// The first new certificate, among the downloads of `urls` not yet tried,
/// whose subject is `wanted`.
async fn fetch_issuer(
    http: &dyn HttpFetcher,
    urls: &[String],
    wanted: &str,
    state: &mut Fetching<'_>,
    limits: &Limits,
    cancel: &CancellationToken,
) -> Option<(CertificateRecord, String)> {
    for url in urls.iter().take(MAX_AIA_URLS_PER_CERT) {
        if *state.budget == 0 {
            return None;
        }
        if !state.tried.insert(url.clone()) {
            continue;
        }
        *state.budget -= 1;
        let download = cancellable(
            cancel,
            http.get(url, limits.max_aia_cert_bytes, limits.http_timeout),
        )
        .await;
        let Some(Ok(bytes)) = download else {
            if cancel.is_cancelled() {
                return None;
            }
            continue;
        };
        for der in certificates_in(&bytes, limits) {
            let origin = CertOrigin::AiaFetched { url: url.clone() };
            let Ok(record) = CertificateRecord::from_der(&der, origin, limits) else {
                continue;
            };
            if record.summary.subject.rfc4514 == wanted
                && state.seen.insert(record.fingerprints.sha256.0)
            {
                return Some((record, url.clone()));
            }
        }
    }
    None
}

/// DER certificates in a download: one raw DER blob, or whatever the text
/// scanner finds (PEM, PKCS#7 text dumps, ...).
fn certificates_in(bytes: &[u8], limits: &Limits) -> Vec<Vec<u8>> {
    if bytes.first() == Some(&0x30) {
        return vec![bytes.to_vec()];
    }
    scan_text(bytes, limits)
        .candidates
        .into_iter()
        .map(|candidate| candidate.der)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpError;
    use crate::testing::FakeHttpFetcher;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/revocation/",
                $name
            ))
        };
    }

    const AIA_URL: &str = "http://ca.example.test/ca.der";

    fn record(der: &[u8], position: usize) -> CertificateRecord {
        CertificateRecord::from_der(der, CertOrigin::Presented { position }, &Limits::default())
            .unwrap()
    }

    fn chain_of(ders: &[&[u8]]) -> Chain {
        let records = ders.iter().enumerate().map(|(i, d)| record(d, i)).collect();
        Chain::new(records, &Limits::default()).unwrap()
    }

    /// The anchor list that makes `ca.der`'s subject a known issuer.
    fn ca_anchor() -> Vec<KnownIssuer> {
        vec![KnownIssuer {
            subject_rfc4514: record(fixture!("ca.der"), 0).summary.subject.rfc4514,
        }]
    }

    async fn chase(
        http: &FakeHttpFetcher,
        chain: Chain,
        anchors: &[KnownIssuer],
    ) -> (Chain, Vec<String>) {
        chase_aia(
            http,
            chain,
            anchors,
            &Limits::default(),
            CancellationToken::new(),
        )
        .await
    }

    #[tokio::test]
    async fn quando_falta_intermediario_e_aia_responde_der_deve_completar_e_marcar_origem() {
        let http =
            FakeHttpFetcher::new().on("GET", AIA_URL, Ok(fixture!("intermediate.der").to_vec()));
        let chain = chain_of(&[fixture!("leaf-int.der")]);

        let (got, urls) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 2);
        assert_eq!(urls, vec![AIA_URL.to_owned()]);
        let fetched = got.get(1).unwrap();
        assert_eq!(
            fetched.origin,
            CertOrigin::AiaFetched {
                url: AIA_URL.to_owned()
            }
        );
        assert_eq!(
            http.calls().first().unwrap().max_bytes,
            Limits::default().max_aia_cert_bytes
        );
    }

    #[tokio::test]
    async fn quando_aia_responde_pem_deve_completar() {
        let pem = fixture!("intermediate.pem").to_vec();
        let http = FakeHttpFetcher::new().on("GET", AIA_URL, Ok(pem));
        let chain = chain_of(&[fixture!("leaf-int.der")]);

        let (got, urls) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 2);
        assert_eq!(urls.len(), 1);
    }

    #[tokio::test]
    async fn quando_aia_devolve_o_proprio_leaf_deve_parar_sem_loop() {
        let http = FakeHttpFetcher::new().on("GET", AIA_URL, Ok(fixture!("leaf-int.der").to_vec()));
        let chain = chain_of(&[fixture!("leaf-int.der")]);

        let (got, urls) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 1);
        assert_eq!(urls, Vec::<String>::new());
        assert_eq!(http.calls().len(), 1);
    }

    #[tokio::test]
    async fn quando_aia_aponta_em_ciclo_deve_parar() {
        let http = FakeHttpFetcher::new()
            .on(
                "GET",
                "http://aia.example.test/loop-b.der",
                Ok(fixture!("aia-loop-b.der").to_vec()),
            )
            .on(
                "GET",
                "http://aia.example.test/loop-a.der",
                Ok(fixture!("aia-loop-a.der").to_vec()),
            );
        let chain = chain_of(&[fixture!("aia-loop-a.der")]);

        let (got, urls) = chase(&http, chain, &[]).await;

        assert_eq!(got.len(), 2, "A, then B; A again is a duplicate");
        assert_eq!(urls, vec!["http://aia.example.test/loop-b.der".to_owned()]);
        assert_eq!(http.calls().len(), 2);
    }

    #[tokio::test]
    async fn quando_aia_nunca_converge_deve_parar_em_max_chain_len() {
        let ring: [&[u8]; 12] = [
            fixture!("aia-ring-00.der"),
            fixture!("aia-ring-01.der"),
            fixture!("aia-ring-02.der"),
            fixture!("aia-ring-03.der"),
            fixture!("aia-ring-04.der"),
            fixture!("aia-ring-05.der"),
            fixture!("aia-ring-06.der"),
            fixture!("aia-ring-07.der"),
            fixture!("aia-ring-08.der"),
            fixture!("aia-ring-09.der"),
            fixture!("aia-ring-10.der"),
            fixture!("aia-ring-11.der"),
        ];
        let mut http = FakeHttpFetcher::new();
        for (i, der) in ring.iter().enumerate().skip(1) {
            http = http.on(
                "GET",
                &format!("http://aia.example.test/ring-{i:02}.der"),
                Ok(der.to_vec()),
            );
        }
        let chain = chain_of(&[ring[0]]);
        let limits = Limits::default();

        let (got, urls) = chase(&http, chain, &[]).await;

        assert_eq!(got.len(), limits.max_chain_len);
        assert_eq!(urls.len(), limits.max_chain_len - 1);
        assert_eq!(http.calls().len(), limits.max_chain_len - 1);
    }

    #[tokio::test]
    async fn quando_download_passa_do_teto_deve_ignorar_e_seguir() {
        let http =
            FakeHttpFetcher::new().on("GET", AIA_URL, Err(HttpError::BodyTooLarge { limit: 8 }));
        let chain = chain_of(&[fixture!("leaf-int.der")]);

        let (got, urls) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 1);
        assert_eq!(urls, Vec::<String>::new());
    }

    #[tokio::test]
    async fn quando_cert_baixado_nao_e_o_emissor_deve_descartar() {
        // `leaf-int` is issued by `intermediate`; serving the root instead is not its issuer.
        let http = FakeHttpFetcher::new().on("GET", AIA_URL, Ok(fixture!("ca.der").to_vec()));
        let chain = chain_of(&[fixture!("leaf-int.der")]);

        let (got, urls) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 1);
        assert_eq!(urls, Vec::<String>::new());
    }

    #[tokio::test]
    async fn quando_resposta_e_lixo_deve_ignorar() {
        let http = FakeHttpFetcher::new().on("GET", AIA_URL, Ok(b"<html>nope</html>".to_vec()));
        let chain = chain_of(&[fixture!("leaf-int.der")]);

        let (got, _) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 1);
    }

    #[tokio::test]
    async fn quando_cadeia_ja_completa_deve_nao_baixar_nada() {
        let http = FakeHttpFetcher::new();
        let chain = chain_of(&[fixture!("leaf-int.der"), fixture!("intermediate.der")]);

        let (got, urls) = chase(&http, chain, &ca_anchor()).await;

        assert_eq!(got.len(), 2);
        assert_eq!(urls, Vec::<String>::new());
        assert_eq!(http.calls(), Vec::new());
    }

    #[tokio::test]
    async fn quando_certificado_lista_dezenas_de_urls_deve_tentar_so_as_primeiras() {
        let http = FakeHttpFetcher::new();
        let chain = chain_of(&[fixture!("orphan-many-urls.der")]);

        let (got, _) = chase(&http, chain, &[]).await;

        assert_eq!(got.len(), 1);
        let urls: Vec<_> = http.calls().into_iter().map(|c| c.url).collect();
        assert_eq!(urls.len(), MAX_AIA_URLS_PER_CERT, "{urls:?}");
        assert_eq!(
            urls.first().map(String::as_str),
            Some("http://many.example.test/issuer/0")
        );
    }

    #[tokio::test]
    async fn quando_cancelado_deve_nao_baixar_nada() {
        let http = FakeHttpFetcher::hanging();
        let chain = chain_of(&[fixture!("leaf-int.der")]);
        let cancel = CancellationToken::new();
        cancel.cancel();

        let (got, _) = chase_aia(&http, chain, &ca_anchor(), &Limits::default(), cancel).await;

        assert_eq!(got.len(), 1);
        assert_eq!(http.calls(), Vec::new());
    }
}
