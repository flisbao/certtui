//! The `inspect_network` use case: a TLS server's presented chain.

use certtui_domain::error::ChainError;
use certtui_domain::limits::Limits;
use certtui_domain::model::{
    CertOrigin, CertificateRecord, Chain, DiagnosticNoteCollector, InspectionReport, LoadNote,
    TrustVerdict,
};
use certtui_domain::target::{NetworkTarget, Target};
use tokio_util::sync::CancellationToken;

use crate::error::InspectError;
use crate::fetch::{FetchError, FetchRequest};
use crate::ports::ChainFetcher;

/// Fetches the chain `target` presents and assembles an [`InspectionReport`].
///
/// Each presented certificate is parsed with its position in the presented
/// order as [`CertOrigin::Presented`]. One that fails X.509 parsing becomes a
/// [`LoadNote::Unparsable`] (retained within `limits.max_scan_diagnostics`)
/// and is absent from the chain. The chain is capped by `limits.max_chain_len`
/// and trust is not evaluated: the chain is reported as presented, valid or
/// not.
///
/// # Errors
///
/// - [`InspectError::Fetch`] for any [`FetchError`], including
///   [`FetchError::EmptyChain`] when the fetcher returned no certificate and
///   [`FetchError::Cancelled`] when `cancel` fired.
/// - [`InspectError::ChainTooLong`] when the peer presented more than
///   `limits.max_chain_len` certificates (nothing is parsed then).
/// - [`InspectError::NoUsableCertificates`] when none of them parses.
pub async fn inspect_network(
    fetcher: &dyn ChainFetcher,
    target: NetworkTarget,
    limits: &Limits,
    cancel: CancellationToken,
) -> Result<InspectionReport, InspectError> {
    let request = FetchRequest {
        target,
        limits: *limits,
    };
    let fetched_chain = fetcher.fetch(&request, cancel).await?;
    if fetched_chain.ders.is_empty() {
        return Err(FetchError::EmptyChain.into());
    }
    if fetched_chain.ders.len() > limits.max_chain_len {
        return Err(InspectError::ChainTooLong {
            len: fetched_chain.ders.len(),
            max: limits.max_chain_len,
        });
    }
    let (records, notes) = parse_presented(&fetched_chain.ders, fetched_chain.note, limits);
    if records.is_empty() {
        return Err(InspectError::NoUsableCertificates { notes });
    }
    let chain = Chain::new(records, limits).map_err(|error| match error {
        ChainError::TooLong { len, max } => InspectError::ChainTooLong { len, max },
    })?;
    Ok(InspectionReport {
        target: Target::Network(request.target),
        tls: fetched_chain.session,
        ocsp_staple: fetched_chain.ocsp_staple,
        chain,
        trust: TrustVerdict::NotEvaluated,
        revocation: Vec::new(),
        staple: certtui_domain::model::StapleState::NotApplicable,
        findings: Vec::new(),
        timings: fetched_chain.timings,
        notes,
    })
}

/// Parses every presented DER; failures become notes within the shared
/// diagnostics budget.
fn parse_presented(
    ders: &[Vec<u8>],
    fetch_note: Option<LoadNote>,
    limits: &Limits,
) -> (Vec<CertificateRecord>, Vec<LoadNote>) {
    let mut collector = DiagnosticNoteCollector::new(limits.max_scan_diagnostics);
    if let Some(note) = fetch_note {
        collector.push(note);
    }
    let mut records = Vec::new();
    for (position, der) in ders.iter().enumerate() {
        match CertificateRecord::from_der(der, CertOrigin::Presented { position }, limits) {
            Ok(record) => records.push(record),
            Err(_) => collector.push(LoadNote::Unparsable { offset: None }),
        }
    }
    let (notes, _remaining, _dropped) = collector.finish();
    (records, notes)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use certtui_domain::limits::Limits;
    use certtui_domain::model::{CertOrigin, LoadNote, Timings, TlsSessionInfo, TrustVerdict};
    use certtui_domain::target::{NetworkTarget, Target};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::error::InspectError;
    use crate::fetch::{FetchError, FetchedChain};
    use crate::testing::FakeChainFetcher;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn der(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    fn garbage() -> Vec<u8> {
        vec![
            0x30, 0x0A, 0x02, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03,
        ]
    }

    fn target() -> NetworkTarget {
        NetworkTarget {
            host: "example.test".to_owned(),
            port: 443,
            sni: Some("alt.example.test".to_owned()),
            connect_to: Some("127.0.0.1:8443".parse().unwrap()),
        }
    }

    fn session() -> TlsSessionInfo {
        TlsSessionInfo {
            version: "TLSv1.3".to_owned(),
            cipher_suite: "TLS13_AES_256_GCM_SHA384".to_owned(),
            key_exchange_group: Some("X25519".to_owned()),
            alpn: Some("h2".to_owned()),
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    fn timings() -> Timings {
        Timings {
            dns: None,
            connect: Some(Duration::from_millis(3)),
            handshake: Some(Duration::from_millis(41)),
            total: Some(Duration::from_millis(50)),
        }
    }

    fn fetched(ders: Vec<Vec<u8>>) -> FetchedChain {
        FetchedChain {
            ders,
            ocsp_staple: Some(vec![9, 9, 9]),
            session: Some(session()),
            note: None,
            timings: timings(),
        }
    }

    async fn run(
        result: Result<FetchedChain, FetchError>,
        limits: &Limits,
    ) -> Result<InspectionReport, InspectError> {
        let fetcher = FakeChainFetcher(result);
        inspect_network(&fetcher, target(), limits, CancellationToken::new()).await
    }

    #[tokio::test]
    async fn quando_fetch_devolve_ders_deve_montar_chain_com_origem_presented() {
        let ders = vec![der("rsa2048-leaf.der"), der("expired.der")];
        let report = run(Ok(fetched(ders.clone())), &Limits::default())
            .await
            .unwrap();

        assert_eq!(report.chain.len(), 2);
        for (position, expected) in ders.iter().enumerate() {
            let record = report.chain.get(position).unwrap();
            assert_eq!(record.der.as_ref(), expected.as_slice());
            assert_eq!(record.origin, CertOrigin::Presented { position });
        }
        assert_eq!(report.target, Target::Network(target()));
        assert_eq!(report.tls, Some(session()));
        assert_eq!(report.timings, timings());
        assert_eq!(report.ocsp_staple, Some(vec![9, 9, 9]));
        assert_eq!(report.trust, TrustVerdict::NotEvaluated);
        assert_eq!(report.revocation, Vec::new());
        assert_eq!(report.findings, Vec::new());
        assert_eq!(report.notes, Vec::new());
    }

    #[tokio::test]
    async fn quando_der_invalido_na_cadeia_deve_virar_nota() {
        let ders = vec![der("rsa2048-leaf.der"), garbage(), der("expired.der")];
        let report = run(Ok(fetched(ders)), &Limits::default()).await.unwrap();

        assert_eq!(report.chain.len(), 2);
        assert_eq!(
            report.chain.get(1).unwrap().origin,
            CertOrigin::Presented { position: 2 },
            "the position is the index in the presented chain"
        );
        assert_eq!(report.notes, vec![LoadNote::Unparsable { offset: None }]);
    }

    #[tokio::test]
    async fn quando_cadeia_vazia_deve_dar_empty_chain() {
        let got = run(Ok(fetched(Vec::new())), &Limits::default()).await;
        assert_eq!(
            got.unwrap_err(),
            InspectError::Fetch(FetchError::EmptyChain)
        );
    }

    #[tokio::test]
    async fn quando_nenhum_der_parseia_deve_dar_erro_com_as_notas() {
        let got = run(Ok(fetched(vec![garbage(), garbage()])), &Limits::default()).await;
        assert_eq!(
            got.unwrap_err(),
            InspectError::NoUsableCertificates {
                notes: vec![
                    LoadNote::Unparsable { offset: None },
                    LoadNote::Unparsable { offset: None },
                ]
            }
        );
    }

    #[tokio::test]
    async fn quando_fetch_falha_deve_propagar_o_erro_do_fetcher() {
        let error = FetchError::Connect("connection refused".to_owned());
        let got = run(Err(error.clone()), &Limits::default()).await;
        assert_eq!(got.unwrap_err(), InspectError::Fetch(error));
    }

    #[tokio::test]
    async fn quando_token_ja_cancelado_deve_dar_cancelled() {
        let fetcher = FakeChainFetcher(Ok(fetched(vec![der("rsa2048-leaf.der")])));
        let token = CancellationToken::new();
        token.cancel();
        let got = inspect_network(&fetcher, target(), &Limits::default(), token).await;
        assert_eq!(got.unwrap_err(), InspectError::Fetch(FetchError::Cancelled));
    }

    #[tokio::test]
    async fn quando_cadeia_passa_de_max_chain_len_deve_dar_chain_too_long() {
        let limits = Limits {
            max_chain_len: 2,
            ..Limits::default()
        };
        let ders = vec![der("rsa2048-leaf.der"); 3];
        let got = run(Ok(fetched(ders)), &limits).await;
        assert_eq!(
            got.unwrap_err(),
            InspectError::ChainTooLong { len: 3, max: 2 }
        );
    }

    #[tokio::test]
    async fn quando_cadeia_tem_exatamente_max_chain_len_deve_aceitar() {
        let limits = Limits {
            max_chain_len: 2,
            ..Limits::default()
        };
        let ders = vec![der("rsa2048-leaf.der"); 2];
        let report = run(Ok(fetched(ders)), &limits).await.unwrap();
        assert_eq!(report.chain.len(), 2);
    }

    #[tokio::test]
    async fn quando_diagnosticos_passam_do_teto_deve_truncar_com_marcador() {
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        let ders = vec![garbage(), garbage(), der("rsa2048-leaf.der"), garbage()];
        let report = run(Ok(fetched(ders)), &limits).await.unwrap();
        assert_eq!(
            report.notes,
            vec![
                LoadNote::Unparsable { offset: None },
                LoadNote::DiagnosticsTruncated { limit: 1 },
            ]
        );
    }

    #[tokio::test]
    async fn quando_captura_parcial_deve_compartilhar_o_teto_de_notas_com_o_parse() {
        let note = LoadNote::HandshakeFailedAfterClientCertRequest {
            peer_ip: Ipv4Addr::LOCALHOST.into(),
        };
        let mut partial = fetched(vec![garbage(), der("rsa2048-leaf.der")]);
        partial.session = None;
        partial.note = Some(note.clone());
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        let report = run(Ok(partial), &limits).await.unwrap();
        assert_eq!(report.tls, None);
        assert_eq!(report.trust, TrustVerdict::NotEvaluated);
        assert_eq!(
            report.notes,
            vec![note, LoadNote::DiagnosticsTruncated { limit: 1 }]
        );
    }

    #[tokio::test]
    async fn quando_sem_staple_deve_manter_none() {
        let mut chain = fetched(vec![der("rsa2048-leaf.der")]);
        chain.ocsp_staple = None;
        let report = run(Ok(chain), &Limits::default()).await.unwrap();
        assert_eq!(report.ocsp_staple, None);
    }
}
