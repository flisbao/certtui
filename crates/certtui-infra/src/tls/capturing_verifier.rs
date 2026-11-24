//! Always-accept certificate verifier that records what the server sent.
//!
//! `CertTui` is an inspection tool: it must be able to show a certificate chain
//! even when that chain is expired, self-signed, signed with an exotic
//! algorithm, or otherwise untrustworthy. The TLS handshake is therefore run
//! with [`CapturingVerifier`], which keeps the DER bytes the server presented
//! and accepts everything. Trust is decided separately, after the handshake,
//! by validating the captured chain with `rustls-webpki` (milestone M3).

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// DER material the server presented during the TLS handshake.
#[derive(Clone, PartialEq, Eq)]
pub struct CapturedHandshake {
    /// DER of the end-entity (leaf) certificate.
    pub end_entity: Vec<u8>,
    /// DER of the intermediate certificates, in the order the server sent them.
    pub intermediates: Vec<Vec<u8>>,
    /// DER of the stapled OCSP response; empty when the server stapled none.
    pub ocsp_response: Vec<u8>,
}

impl fmt::Debug for CapturedHandshake {
    /// Prints lengths and counts only, never the DER bytes themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedHandshake")
            .field("end_entity_len", &self.end_entity.len())
            .field("intermediates", &self.intermediates.len())
            .field("ocsp_response_len", &self.ocsp_response.len())
            .finish()
    }
}

/// Server certificate verifier that accepts everything and remembers the chain.
///
/// # UNSAFE FOR AUTHENTICATION
///
/// This type performs **no** validation: it does not check the chain, the
/// validity period, the server name, the revocation status or the handshake
/// signatures. A connection established with it is not authenticated and must
/// never carry anything but the handshake needed to read the certificates.
/// Never use it for any purpose other than inspection.
///
/// Why it exists: we inspect certificates that may be invalid on purpose
/// (expired, self-signed, wrong host, unknown algorithm). Rejecting them
/// during the handshake would hide exactly what the user wants to see. The
/// trust verdict is computed later, over the captured bytes, with
/// `rustls-webpki` (M3).
///
/// If [`ServerCertVerifier::verify_server_cert`] is called more than once
/// (for example on a retried handshake), the last call wins. The amount of
/// data is already bounded by the byte budget of the stream the handshake runs
/// on, so no extra cap is applied here.
pub struct CapturingVerifier {
    captured: Mutex<Option<CapturedHandshake>>,
    schemes: Vec<SignatureScheme>,
}

impl CapturingVerifier {
    /// Creates a verifier with nothing captured yet.
    ///
    /// The advertised signature schemes are those of the `ring` crypto provider.
    #[must_use]
    pub fn new() -> Arc<Self> {
        let schemes = rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes();
        Arc::new(Self {
            captured: Mutex::new(None),
            schemes,
        })
    }

    /// Returns a copy of what the server presented, or `None` if the handshake
    /// never reached certificate verification.
    #[must_use]
    pub fn captured(&self) -> Option<CapturedHandshake> {
        self.lock().clone()
    }

    /// Locks the state, recovering the data if another thread panicked while
    /// holding the lock (the stored value is always a complete snapshot).
    fn lock(&self) -> MutexGuard<'_, Option<CapturedHandshake>> {
        self.captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for CapturingVerifier {
    /// Prints the captured lengths only, never the DER bytes themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturingVerifier")
            .field("captured", &self.lock())
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for CapturingVerifier {
    /// Stores the presented DER bytes (replacing any earlier capture) and accepts.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let snapshot = CapturedHandshake {
            end_entity: end_entity.as_ref().to_vec(),
            intermediates: intermediates.iter().map(|c| c.as_ref().to_vec()).collect(),
            ocsp_response: ocsp_response.to_vec(),
        };
        *self.lock() = Some(snapshot);
        Ok(ServerCertVerified::assertion())
    }

    /// Accepts any TLS 1.2 handshake signature: trust is decided in M3.
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    /// Accepts any TLS 1.3 handshake signature: trust is decided in M3.
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rcgen::{CertificateParams, KeyPair, date_time_ymd};
    use rustls::client::danger::ServerCertVerifier;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;

    fn self_signed_der(name: &str, expired: bool) -> Vec<u8> {
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        if expired {
            params.not_before = date_time_ymd(2000, 1, 1);
            params.not_after = date_time_ymd(2001, 1, 1);
        }
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn call_verify(
        verifier: &CapturingVerifier,
        end_entity: &[u8],
        intermediates: &[Vec<u8>],
        ocsp: &[u8],
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ee = CertificateDer::from(end_entity.to_vec());
        let inter: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|d| CertificateDer::from(d.clone()))
            .collect();
        let name = ServerName::try_from("example.com").unwrap();
        verifier.verify_server_cert(&ee, &inter, &name, ocsp, UnixTime::now())
    }

    #[test]
    fn quando_cert_chega_deve_capturar_end_entity_e_intermediarios_na_ordem() {
        let verifier = CapturingVerifier::new();
        let leaf = self_signed_der("leaf.example", false);
        let inter_a = self_signed_der("inter-a.example", false);
        let inter_b = self_signed_der("inter-b.example", false);

        call_verify(&verifier, &leaf, &[inter_a.clone(), inter_b.clone()], &[]).unwrap();

        let got = verifier.captured().unwrap();
        assert_eq!(got.end_entity, leaf);
        assert_eq!(got.intermediates, vec![inter_a, inter_b]);
    }

    #[test]
    fn quando_ha_staple_deve_capturar_bytes() {
        let verifier = CapturingVerifier::new();
        let leaf = self_signed_der("leaf.example", false);
        let staple = vec![0x30, 0x03, 0x0a, 0x01, 0x00];

        call_verify(&verifier, &leaf, &[], &staple).unwrap();

        assert_eq!(verifier.captured().unwrap().ocsp_response, staple);
    }

    #[test]
    fn quando_nao_ha_staple_deve_capturar_vazio() {
        let verifier = CapturingVerifier::new();
        let leaf = self_signed_der("leaf.example", false);

        call_verify(&verifier, &leaf, &[], &[]).unwrap();

        assert_eq!(verifier.captured().unwrap().ocsp_response, Vec::<u8>::new());
    }

    #[test]
    fn quando_cert_e_invalido_deve_aceitar_mesmo_assim() {
        let verifier = CapturingVerifier::new();
        let expired = self_signed_der("other.example", true);

        let result = call_verify(&verifier, &expired, &[], &[]);

        assert!(result.is_ok());
        assert_eq!(verifier.captured().unwrap().end_entity, expired);
    }

    #[test]
    fn quando_verify_nao_foi_chamado_deve_retornar_none() {
        assert!(CapturingVerifier::new().captured().is_none());
    }

    #[test]
    fn quando_verify_e_chamado_duas_vezes_deve_valer_a_ultima() {
        let verifier = CapturingVerifier::new();
        let first = self_signed_der("first.example", false);
        let second = self_signed_der("second.example", false);
        let inter = self_signed_der("inter.example", false);

        call_verify(&verifier, &first, &[inter], &[1, 2, 3]).unwrap();
        call_verify(&verifier, &second, &[], &[]).unwrap();

        let got = verifier.captured().unwrap();
        assert_eq!(got.end_entity, second);
        assert_eq!(got.intermediates, Vec::<Vec<u8>>::new());
        assert_eq!(got.ocsp_response, Vec::<u8>::new());
    }

    #[test]
    fn quando_mutex_esta_envenenado_deve_continuar_capturando_e_lendo() {
        let verifier = CapturingVerifier::new();
        let poisoner = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = verifier.captured.lock().unwrap();
            panic!("poison the mutex on purpose");
        }));
        assert!(poisoner.is_err());
        let leaf = self_signed_der("leaf.example", false);

        call_verify(&verifier, &leaf, &[], &[]).unwrap();

        assert_eq!(verifier.captured().unwrap().end_entity, leaf);
    }

    #[test]
    fn quando_debug_e_formatado_nao_deve_conter_bytes_der() {
        let verifier = CapturingVerifier::new();
        let marker = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD];
        call_verify(&verifier, &marker, std::slice::from_ref(&marker), &marker).unwrap();

        let captured = verifier.captured().unwrap();
        let rendered = format!("{verifier:?} {captured:?}");

        assert!(!rendered.contains("222"), "DER byte leaked: {rendered}");
        assert!(!rendered.contains("173"), "DER byte leaked: {rendered}");
        assert!(rendered.contains("end_entity_len: 6"), "{rendered}");
        assert!(rendered.contains("intermediates: 1"), "{rendered}");
    }

    #[test]
    fn quando_pergunta_esquemas_deve_listar_os_do_provider_ring() {
        let verifier: Arc<dyn ServerCertVerifier> = CapturingVerifier::new();

        assert_ne!(verifier.supported_verify_schemes(), Vec::new());
    }
}
