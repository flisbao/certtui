//! The stage between "gather" and "validate": AIA chasing and revocation.
//!
//! A gathered report holds the chain as presented. This stage may lengthen it
//! (`--aia`) and fills in revocation status and the OCSP staple state, so the
//! lints that run next see them. It never fails: whatever cannot be learned
//! becomes `Unknown`.

use std::sync::Arc;

use certtui_domain::chain_analysis::KnownIssuer;
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertRevocation, InspectionReport, StapleState};
use certtui_domain::target::Target;
use tokio_util::sync::CancellationToken;

use crate::aia::chase_aia;
use crate::ports::{Clock, HttpFetcher};
use crate::proxy::ProxySettings;
use crate::revocation::{RevocationProtocol, RevocationScope, RevocationService, check_revocation};

/// What `--aia`, `--revocation` and `--no-revocation` ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationOptions {
    /// Which certificates are checked for revocation (network targets only).
    pub scope: RevocationScope,
    /// Download missing issuers from AIA.
    pub aia: bool,
    /// Let certificate-supplied URLs reach loopback, link-local and cloud
    /// metadata addresses (`--allow-internal-urls`); refused by default.
    pub allow_internal_urls: bool,
}

impl Default for RevocationOptions {
    /// Leaf-only revocation, no AIA chasing.
    fn default() -> Self {
        Self {
            scope: RevocationScope::Leaf,
            aia: false,
            allow_internal_urls: false,
        }
    }
}

/// Completes a gathered report before validation.
#[async_trait::async_trait]
pub trait ReportEnricher: Send + Sync {
    /// Sets the proxy the OCSP, CRL and AIA downloads go through, or `None`.
    fn use_proxy(&self, _proxy: Option<ProxySettings>) {}

    /// Returns `report` with the chain completed through AIA when asked and,
    /// for network targets, revocation status and staple state filled in.
    /// `anchors` are the issuers already known (they end AIA chasing).
    /// Stops promptly when `cancel` fires.
    async fn enrich(
        &self,
        report: InspectionReport,
        anchors: &[KnownIssuer],
        options: RevocationOptions,
        cancel: CancellationToken,
    ) -> InspectionReport;
}

/// An enricher that changes nothing: for tests and runs without network.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEnricher;

#[async_trait::async_trait]
impl ReportEnricher for NoEnricher {
    async fn enrich(
        &self,
        report: InspectionReport,
        _anchors: &[KnownIssuer],
        _options: RevocationOptions,
        _cancel: CancellationToken,
    ) -> InspectionReport {
        report
    }
}

/// The real enricher: HTTP for AIA, the revocation service for the rest.
pub struct NetworkEnricher {
    http: Arc<dyn HttpFetcher>,
    service: RevocationService,
    limits: Limits,
}

impl NetworkEnricher {
    /// Builds the enricher over the given collaborators.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpFetcher>,
        protocol: Arc<dyn RevocationProtocol>,
        clock: Arc<dyn Clock>,
        limits: Limits,
    ) -> Self {
        let service = RevocationService::new(Arc::clone(&http), protocol, clock, limits);
        Self {
            http,
            service,
            limits,
        }
    }
}

#[async_trait::async_trait]
impl ReportEnricher for NetworkEnricher {
    fn use_proxy(&self, proxy: Option<ProxySettings>) {
        self.http.use_proxy(proxy);
    }

    async fn enrich(
        &self,
        report: InspectionReport,
        anchors: &[KnownIssuer],
        options: RevocationOptions,
        cancel: CancellationToken,
    ) -> InspectionReport {
        let mut report = report;
        self.http.allow_internal_urls(options.allow_internal_urls);
        if options.aia {
            let (chain, _urls) = chase_aia(
                self.http.as_ref(),
                report.chain.clone(),
                anchors,
                &self.limits,
                cancel.clone(),
            )
            .await;
            report.chain = chain;
        }
        let checks_revocation =
            matches!(report.target, Target::Network(_)) && options.scope != RevocationScope::Off;
        if checks_revocation {
            let outcome = check_revocation(
                &self.service,
                &report.chain,
                report.ocsp_staple.as_deref(),
                options.scope,
                cancel,
            )
            .await;
            report.revocation = outcome
                .statuses
                .into_iter()
                .map(|(cert_index, status)| CertRevocation { cert_index, status })
                .collect();
            report.staple = outcome.staple;
        } else {
            report.staple = StapleState::NotApplicable;
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::{OcspRequest, RevocationError};
    use crate::testing::{FakeHttpFetcher, FakeRevocationProtocol, FixedClock};
    use certtui_domain::model::{
        CertOrigin, CertificateRecord, Chain, RevocationStatus, Timings, TrustVerdict,
    };
    use certtui_domain::target::NetworkTarget;
    use certtui_domain::time::Timestamp;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/revocation/",
                $name
            ))
        };
    }

    const OCSP_URL: &str = "http://ocsp.example.test/ocsp";
    const AIA_URL: &str = "http://ca.example.test/ca.der";

    fn target(network: bool) -> Target {
        if network {
            Target::Network(NetworkTarget {
                host: "good.example.test".to_owned(),
                port: 443,
                sni: None,
                connect_to: None,
            })
        } else {
            Target::Stdin
        }
    }

    fn report(ders: &[&[u8]], network: bool, staple: Option<Vec<u8>>) -> InspectionReport {
        let limits = Limits::default();
        let records = ders
            .iter()
            .enumerate()
            .map(|(position, der)| {
                CertificateRecord::from_der(der, CertOrigin::Presented { position }, &limits)
                    .unwrap()
            })
            .collect();
        InspectionReport {
            target: target(network),
            tls: None,
            ocsp_staple: staple,
            chain: Chain::new(records, &limits).unwrap(),
            trust: TrustVerdict::NotEvaluated,
            revocation: Vec::new(),
            staple: StapleState::NotApplicable,
            findings: Vec::new(),
            timings: Timings::default(),
            notes: Vec::new(),
        }
    }

    fn enricher(http: &Arc<FakeHttpFetcher>) -> NetworkEnricher {
        let protocol = FakeRevocationProtocol::new(
            Ok(OcspRequest {
                body: vec![1],
                get_url_suffix: "c3VmZml4".to_owned(),
                cache_key: (vec![1], vec![2]),
            }),
            Ok(RevocationStatus::Good),
            Err(RevocationError::Stale),
        );
        NetworkEnricher::new(
            Arc::clone(http) as Arc<dyn HttpFetcher>,
            Arc::new(protocol),
            Arc::new(FixedClock(Timestamp::from_unix_saturating(1_793_577_600))),
            Limits::default(),
        )
    }

    fn options(scope: RevocationScope, aia: bool) -> RevocationOptions {
        RevocationOptions {
            scope,
            aia,
            allow_internal_urls: false,
        }
    }

    #[tokio::test]
    async fn quando_alvo_de_rede_deve_preencher_revocation_e_staple() {
        let http = Arc::new(FakeHttpFetcher::new().on("POST", OCSP_URL, Ok(b"r".to_vec())));
        let input = report(&[fixture!("leaf-good.der"), fixture!("ca.der")], true, None);

        let got = enricher(&http)
            .enrich(
                input,
                &[],
                options(RevocationScope::Leaf, false),
                CancellationToken::new(),
            )
            .await;

        assert_eq!(
            got.revocation,
            vec![CertRevocation {
                cert_index: 0,
                status: RevocationStatus::Good
            }]
        );
        assert_eq!(got.staple, StapleState::Missing);
    }

    #[tokio::test]
    async fn quando_scope_off_deve_nao_fazer_requisicoes_http() {
        let http = Arc::new(FakeHttpFetcher::new());
        let input = report(
            &[fixture!("leaf-good.der"), fixture!("ca.der")],
            true,
            Some(vec![9]),
        );

        let got = enricher(&http)
            .enrich(
                input,
                &[],
                options(RevocationScope::Off, false),
                CancellationToken::new(),
            )
            .await;

        assert_eq!(http.calls(), Vec::new());
        assert_eq!(got.revocation, Vec::new());
        assert_eq!(got.staple, StapleState::NotApplicable);
    }

    #[tokio::test]
    async fn quando_alvo_e_local_deve_nao_checar_revogacao() {
        let http = Arc::new(FakeHttpFetcher::new());
        let input = report(
            &[fixture!("leaf-good.der"), fixture!("ca.der")],
            false,
            None,
        );

        let got = enricher(&http)
            .enrich(
                input,
                &[],
                options(RevocationScope::Full, false),
                CancellationToken::new(),
            )
            .await;

        assert_eq!(http.calls(), Vec::new());
        assert_eq!(got.revocation, Vec::new());
    }

    #[tokio::test]
    async fn quando_aia_ligado_e_cadeia_incompleta_deve_completar_antes_da_revogacao() {
        let http = Arc::new(
            FakeHttpFetcher::new()
                .on("GET", AIA_URL, Ok(fixture!("intermediate.der").to_vec()))
                .on("POST", OCSP_URL, Ok(b"r".to_vec())),
        );
        let input = report(&[fixture!("leaf-int.der")], true, None);

        let got = enricher(&http)
            .enrich(
                input,
                &[],
                options(RevocationScope::Leaf, true),
                CancellationToken::new(),
            )
            .await;

        assert_eq!(got.chain.len(), 2);
        assert_eq!(
            got.chain.get(1).map(|r| r.origin.clone()),
            Some(CertOrigin::AiaFetched {
                url: AIA_URL.to_owned()
            })
        );
        // With the issuer now in the chain, the leaf could be checked at all.
        assert_eq!(got.revocation.len(), 1);
        assert_eq!(
            got.revocation.first().map(|r| r.status.clone()),
            Some(RevocationStatus::Good)
        );
    }

    #[tokio::test]
    async fn quando_aia_desligado_deve_nao_baixar_emissores() {
        let http = Arc::new(FakeHttpFetcher::new());
        let input = report(&[fixture!("leaf-int.der")], false, None);

        let got = enricher(&http)
            .enrich(
                input,
                &[],
                options(RevocationScope::Leaf, false),
                CancellationToken::new(),
            )
            .await;

        assert_eq!(got.chain.len(), 1);
        assert_eq!(http.calls(), Vec::new());
    }

    #[tokio::test]
    async fn quando_no_enricher_deve_devolver_o_relatorio_intacto() {
        let input = report(&[fixture!("leaf-good.der")], true, None);
        let got = NoEnricher
            .enrich(
                input.clone(),
                &[],
                RevocationOptions::default(),
                CancellationToken::new(),
            )
            .await;
        assert_eq!(got, input);
    }

    #[test]
    fn quando_padrao_deve_ser_leaf_sem_aia() {
        let defaults = RevocationOptions::default();
        assert_eq!(defaults.scope, RevocationScope::Leaf);
        assert!(!defaults.aia);
        assert!(!defaults.allow_internal_urls);
    }
}
