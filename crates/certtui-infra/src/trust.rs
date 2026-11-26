//! `NativeTrustProvider`: loads trust anchors from the system store, the
//! bundled Mozilla roots and user-supplied CA files.

use std::path::PathBuf;
use std::sync::Arc;

use certtui_app::ports::{LocalSource, SourceLoader, TrustStoreProvider};
use certtui_app::trust::{TrustAnchor, TrustAnchors, TrustError, TrustSource};
use certtui_domain::limits::Limits;
use certtui_domain::model::{DistinguishedName, LoadNote, parse_der_cert, parse_name_content};
use certtui_domain::sanitize::sanitize_display;
use rustls_pki_types::CertificateDer;

/// What a system store lookup produced: DER certificates plus error texts.
///
/// A neutral shape (no `rustls-native-certs` types) so tests can inject a
/// failing source.
#[derive(Debug, Default)]
pub struct SystemCerts {
    /// DER bytes of every certificate that could be read.
    pub certs: Vec<Vec<u8>>,
    /// Non-fatal problems met while reading the store.
    pub errors: Vec<String>,
}

/// Reads the operating system trust store through `rustls-native-certs`.
fn load_native_system() -> SystemCerts {
    let result = rustls_native_certs::load_native_certs();
    SystemCerts {
        certs: result
            .certs
            .into_iter()
            .map(|c| c.as_ref().to_vec())
            .collect(),
        errors: result.errors.iter().map(ToString::to_string).collect(),
    }
}

/// Loads [`TrustAnchors`] from the system, Mozilla and custom sources.
pub struct NativeTrustProvider {
    custom_files: Vec<PathBuf>,
    loader: Arc<dyn SourceLoader>,
    limits: Limits,
    load_system: fn() -> SystemCerts,
}

impl std::fmt::Debug for NativeTrustProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeTrustProvider")
            .field("custom_files", &self.custom_files)
            .finish_non_exhaustive()
    }
}

impl NativeTrustProvider {
    /// Creates a provider. `custom_files` are read through `loader` (any
    /// format it accepts) when [`TrustSource::Custom`] is requested.
    #[must_use]
    pub fn new(custom_files: Vec<PathBuf>, loader: Arc<dyn SourceLoader>, limits: Limits) -> Self {
        Self::with_system_loader(custom_files, loader, limits, load_native_system)
    }

    /// Like [`Self::new`], with an injected system store reader (tests).
    #[must_use]
    pub fn with_system_loader(
        custom_files: Vec<PathBuf>,
        loader: Arc<dyn SourceLoader>,
        limits: Limits,
        load_system: fn() -> SystemCerts,
    ) -> Self {
        Self {
            custom_files,
            loader,
            limits,
            load_system,
        }
    }

    fn add_system(&self, out: &mut TrustAnchors) {
        let system = (self.load_system)();
        for error in &system.errors {
            out.warnings
                .push(format!("system trust store: {}", sanitize_display(error)));
        }
        let mut skipped = 0_usize;
        for der in &system.certs {
            match anchor_from_der(der, TrustSource::System) {
                Some(anchor) => out.entries.push(anchor),
                None => skipped = skipped.saturating_add(1),
            }
        }
        if skipped > 0 {
            out.warnings.push(format!(
                "system trust store: {skipped} unusable certificate(s) skipped"
            ));
        }
        if system.certs.is_empty() {
            out.warnings
                .push("system trust store: no certificates loaded".to_owned());
        }
    }

    fn add_mozilla(out: &mut TrustAnchors) {
        for anchor in webpki_roots::TLS_SERVER_ROOTS {
            let subject = anchor.subject.as_ref();
            out.entries.push(TrustAnchor {
                subject_der: subject.to_vec(),
                spki_der: anchor.subject_public_key_info.as_ref().to_vec(),
                name_constraints_der: anchor
                    .name_constraints
                    .as_ref()
                    .map(|nc| nc.as_ref().to_vec()),
                source: TrustSource::Mozilla,
                label: label_from_subject_content(subject),
            });
        }
    }

    fn add_custom(&self, out: &mut TrustAnchors) -> Result<(), TrustError> {
        let cap = self.limits.max_ca_file_certs;
        let mut load_limits = self.limits;
        load_limits.max_certs_per_source = cap;
        for path in &self.custom_files {
            let loaded = self
                .loader
                .load(&LocalSource::File(path.clone()), &load_limits)
                .map_err(|error| TrustError::CustomFile {
                    path: path.clone(),
                    cause: error.to_string(),
                })?;
            let total = loaded.certs.len();
            let mut skipped = 0_usize;
            for raw in loaded.certs.iter().take(cap) {
                match anchor_from_der(&raw.der, TrustSource::Custom) {
                    Some(anchor) => out.entries.push(anchor),
                    None => skipped = skipped.saturating_add(1),
                }
            }
            let loader_truncated = loaded
                .notes
                .iter()
                .any(|note| matches!(note, LoadNote::TruncatedAtCertLimit { .. }));
            if total > cap || loader_truncated {
                out.warnings.push(format!(
                    "custom CA file {}: truncated at {cap} certificates",
                    sanitize_display(&path.display().to_string())
                ));
            }
            if loaded
                .notes
                .contains(&LoadNote::KeystoreIntegrityUnverified)
            {
                out.warnings.push(format!(
                    "custom CA file {}: the keystore was read without verifying its integrity; \
                     its certificates are trusted as given",
                    sanitize_display(&path.display().to_string())
                ));
            }
            if skipped > 0 {
                out.warnings.push(format!(
                    "custom CA file {}: {skipped} unusable certificate(s) skipped",
                    sanitize_display(&path.display().to_string())
                ));
            }
        }
        Ok(())
    }
}

impl TrustStoreProvider for NativeTrustProvider {
    fn anchors(&self, sources: &[TrustSource]) -> Result<TrustAnchors, TrustError> {
        let mut out = TrustAnchors::default();
        let mut seen = Vec::new();
        for &source in sources {
            if seen.contains(&source) {
                continue;
            }
            seen.push(source);
            match source {
                TrustSource::System => self.add_system(&mut out),
                TrustSource::Mozilla => Self::add_mozilla(&mut out),
                TrustSource::Custom => self.add_custom(&mut out)?,
            }
        }
        Ok(out)
    }
}

/// Turns one DER certificate into an anchor; `None` when it is unusable.
pub(crate) fn anchor_from_der(der: &[u8], source: TrustSource) -> Option<TrustAnchor> {
    let cert_der = CertificateDer::from(der);
    let anchor = webpki::anchor_from_trusted_cert(&cert_der).ok()?;
    Some(TrustAnchor {
        subject_der: anchor.subject.as_ref().to_vec(),
        spki_der: anchor.subject_public_key_info.as_ref().to_vec(),
        name_constraints_der: anchor
            .name_constraints
            .as_ref()
            .map(|nc| nc.as_ref().to_vec()),
        source,
        label: label_for_cert(der, anchor.subject.as_ref()),
    })
}

fn label_for_cert(der: &[u8], subject_content: &[u8]) -> String {
    match parse_der_cert(der, &Limits::default()) {
        Ok(summary) => display_name(&summary.subject),
        Err(_) => label_from_subject_content(subject_content),
    }
}

/// `subject` of a webpki anchor is the *content* of the `Name` SEQUENCE.
fn label_from_subject_content(content: &[u8]) -> String {
    parse_name_content(content).map_or_else(|| "unknown subject".to_owned(), |n| display_name(&n))
}

fn display_name(name: &DistinguishedName) -> String {
    let text = name.common_name.as_deref().unwrap_or(&name.rfc4514);
    sanitize_display(text).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::FsSourceLoader;
    use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
    use std::sync::atomic::{AtomicU32, Ordering};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn loader() -> Arc<dyn SourceLoader> {
        Arc::new(FsSourceLoader::new())
    }

    fn no_system() -> SystemCerts {
        SystemCerts::default()
    }

    fn failing_system() -> SystemCerts {
        SystemCerts {
            certs: Vec::new(),
            errors: vec!["cannot read /etc/ssl/certs".to_owned()],
        }
    }

    fn provider(files: Vec<PathBuf>, limits: &Limits) -> NativeTrustProvider {
        NativeTrustProvider::with_system_loader(files, loader(), *limits, no_system)
    }

    fn temp_path(name: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("certtui-trust-{}-{n}-{name}", std::process::id()))
    }

    fn ca_pem() -> String {
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "CertTui Test Root");
        let key = KeyPair::generate().expect("key");
        params.self_signed(&key).expect("cert").pem()
    }

    #[test]
    fn quando_ca_file_e_keystore_sem_integridade_deve_avisar() {
        use certtui_app::ports::{LoadedCerts, RawCert};
        use certtui_app::testing::FakeSourceLoader;
        use certtui_domain::model::CertOrigin;

        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "Truststore Root");
        let key = KeyPair::generate().expect("key");
        let der = params.self_signed(&key).expect("cert").der().to_vec();
        let loaded = LoadedCerts {
            certs: vec![RawCert {
                der,
                origin: CertOrigin::Keystore {
                    path: PathBuf::from("trust.jks"),
                    alias: "root".to_owned(),
                },
            }],
            notes: vec![LoadNote::KeystoreIntegrityUnverified],
        };
        let provider = NativeTrustProvider::with_system_loader(
            vec![PathBuf::from("trust.jks")],
            Arc::new(FakeSourceLoader(Ok(loaded))),
            Limits::default(),
            no_system,
        );

        let anchors = provider.anchors(&[TrustSource::Custom]).unwrap();

        assert_eq!(anchors.entries.len(), 1, "the anchor is still used");
        assert!(
            anchors
                .warnings
                .iter()
                .any(|w| w.contains("without verifying its integrity")),
            "{:?}",
            anchors.warnings
        );
    }

    #[test]
    fn quando_source_mozilla_deve_ter_mais_de_100_ancoras() {
        let anchors = provider(Vec::new(), &Limits::default())
            .anchors(&[TrustSource::Mozilla])
            .expect("anchors");
        assert!(anchors.len() > 100, "got {}", anchors.len());
        assert!(anchors.has_public_source());
        assert!(
            anchors.entries.iter().all(|a| a.label != "unknown subject"),
            "every Mozilla anchor should have a readable label"
        );
    }

    #[test]
    fn quando_custom_e_pem_deve_carregar_ancora() {
        let path = temp_path("root.pem");
        std::fs::write(&path, ca_pem()).expect("write");
        let anchors = provider(vec![path.clone()], &Limits::default())
            .anchors(&[TrustSource::Custom])
            .expect("anchors");
        std::fs::remove_file(&path).ok();
        assert_eq!(anchors.len(), 1);
        let anchor = anchors.entries.first().expect("anchor");
        assert_eq!(anchor.source, TrustSource::Custom);
        assert_eq!(anchor.label, "CertTui Test Root");
        assert!(!anchors.has_public_source());
    }

    #[test]
    fn quando_custom_e_texto_sujo_deve_carregar_ancora() {
        let path = PathBuf::from(format!("{FIXTURES}/messy/pem-email-quoted.txt"));
        let anchors = provider(vec![path], &Limits::default())
            .anchors(&[TrustSource::Custom])
            .expect("anchors");
        assert!(!anchors.is_empty());
    }

    #[test]
    fn quando_custom_tem_mais_certs_que_o_limite_deve_truncar_com_warning() {
        let path = PathBuf::from(format!("{FIXTURES}/chain-3.pem"));
        let limits = Limits {
            max_ca_file_certs: 2,
            ..Limits::default()
        };
        let anchors = provider(vec![path], &limits)
            .anchors(&[TrustSource::Custom])
            .expect("anchors");
        assert_eq!(anchors.len(), 2);
        assert!(
            anchors.warnings.iter().any(|w| w.contains("truncated")),
            "{:?}",
            anchors.warnings
        );
    }

    #[test]
    fn quando_custom_nao_existe_deve_dar_custom_file_error() {
        let path = temp_path("missing.pem");
        let error = provider(vec![path.clone()], &Limits::default())
            .anchors(&[TrustSource::Custom])
            .expect_err("missing file");
        assert!(matches!(error, TrustError::CustomFile { path: p, .. } if p == path));
    }

    #[test]
    fn quando_system_falha_deve_dar_anchors_vazias_com_warning() {
        let provider = NativeTrustProvider::with_system_loader(
            Vec::new(),
            loader(),
            Limits::default(),
            failing_system,
        );
        let anchors = provider.anchors(&[TrustSource::System]).expect("anchors");
        assert!(anchors.is_empty());
        assert!(
            anchors.warnings.iter().any(|w| w.contains("cannot read")),
            "{:?}",
            anchors.warnings
        );
    }

    #[test]
    fn quando_fonte_repetida_deve_carregar_uma_vez() {
        let anchors = provider(Vec::new(), &Limits::default())
            .anchors(&[TrustSource::Mozilla, TrustSource::Mozilla])
            .expect("anchors");
        assert_eq!(anchors.len(), webpki_roots::TLS_SERVER_ROOTS.len());
    }
}
