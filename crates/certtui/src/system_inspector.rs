//! The [`Inspector`] of the real program: the same inspect-then-validate
//! pipeline the CLI commands run, behind the TUI's job interface.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use certtui_app::enrich::{NetworkEnricher, ReportEnricher};
use certtui_app::inspect::inspect_local;
use certtui_app::inspect_network::inspect_network;
use certtui_app::ports::{ChainFetcher, ChainVerifier, Clock, SourceLoader, TrustStoreProvider};
use certtui_app::trust::TrustAnchors;
use certtui_app::validate::known_issuers;
use certtui_domain::limits::Limits;
use certtui_domain::lint::Thresholds;
use certtui_domain::model::InspectionReport;
use certtui_domain::target::{NetworkTarget, Target};
use certtui_infra::clock::SystemClock;
use certtui_infra::http::ReqwestHttpFetcher;
use certtui_infra::revocation::X509RevocationProtocol;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use crate::cli::validate_for_target;
use crate::command_executor::Inspector;
use crate::network_args::with_timeout;
use crate::output::single_line;
use crate::target_parse::local_source;
use crate::tui_launch::InspectorOptions;

/// Builds the trust store provider for the `--ca-file` paths of a run.
pub type TrustProviderFactory =
    Arc<dyn Fn(Vec<PathBuf>) -> Box<dyn TrustStoreProvider> + Send + Sync>;

/// The enricher of the real program: reqwest over HTTP, `x509-ocsp` and
/// `x509-parser` for the wire formats, the system clock.
#[must_use]
pub fn real_enricher() -> NetworkEnricher {
    let limits = Limits::default();
    NetworkEnricher::new(
        Arc::new(ReqwestHttpFetcher::new(limits.max_http_redirects)),
        Arc::new(X509RevocationProtocol),
        Arc::new(SystemClock),
        limits,
    )
}

/// The ports and the command line options an inspection needs.
pub struct SystemInspector {
    /// Reads local certificates.
    pub loader: Arc<dyn SourceLoader>,
    /// Fetches the chain of a network target.
    pub fetcher: Arc<dyn ChainFetcher>,
    /// Decides whether a chain is trusted.
    pub verifier: Arc<dyn ChainVerifier>,
    /// Source of "now".
    pub clock: Arc<dyn Clock>,
    /// Builds the trust store provider.
    pub trust_provider: TrustProviderFactory,
    /// AIA chasing and revocation, between gathering and validating.
    pub enricher: Arc<dyn ReportEnricher>,
    /// The command line options of the run.
    pub options: InspectorOptions,
    /// Anchors, loaded on the first inspection and reused after.
    pub anchors: OnceCell<Result<Arc<TrustAnchors>, String>>,
}

impl SystemInspector {
    async fn anchors(&self) -> Result<Arc<TrustAnchors>, String> {
        self.anchors
            .get_or_init(|| async {
                let provider = (self.trust_provider)(self.options.ca_files.clone());
                let sources = self.options.trust_sources.clone();
                tokio::task::spawn_blocking(move || provider.anchors(&sources))
                    .await
                    .map_err(|error| format!("loading the trust store failed: {error}"))?
                    .map(Arc::new)
                    .map_err(|error| single_line(&error.to_string()))
            })
            .await
            .clone()
    }

    fn network_target(&self, parsed: NetworkTarget) -> NetworkTarget {
        NetworkTarget {
            sni: self.options.sni.clone(),
            connect_to: self.options.connect_to.map(|connect_to| {
                SocketAddr::new(connect_to.ip, connect_to.port.unwrap_or(parsed.port))
            }),
            ..parsed
        }
    }

    fn limits(&self) -> Limits {
        self.options
            .timeout
            .map_or_else(Limits::default, |timeout| {
                with_timeout(&Limits::default(), timeout)
            })
    }
}

#[async_trait::async_trait]
impl Inspector for SystemInspector {
    async fn inspect(
        &self,
        target: Target,
        cancel: CancellationToken,
    ) -> Result<InspectionReport, String> {
        let anchors = self.anchors().await?;
        let report = match target {
            Target::Network(parsed) => {
                let network = self.network_target(parsed);
                inspect_network(
                    self.fetcher.as_ref(),
                    network,
                    &self.limits(),
                    cancel.clone(),
                )
                .await
                .map_err(|error| single_line(&error.to_string()))?
            }
            local => {
                let source = local_source(&local)
                    .ok_or_else(|| "a network target reached the local loader".to_owned())?;
                let loader = Arc::clone(&self.loader);
                tokio::task::spawn_blocking(move || {
                    inspect_local(loader.as_ref(), &source, local, &Limits::default())
                })
                .await
                .map_err(|error| format!("reading the certificates failed: {error}"))?
                .map_err(|error| single_line(&error.to_string()))?
            }
        };
        let report = self
            .enricher
            .enrich(
                report,
                &known_issuers(&anchors),
                self.options.revocation,
                cancel,
            )
            .await;
        Ok(validate_for_target(
            report,
            self.verifier.as_ref(),
            &anchors,
            self.clock.as_ref(),
            Thresholds::default(),
            self.options.host_check.as_deref(),
        ))
    }
}
