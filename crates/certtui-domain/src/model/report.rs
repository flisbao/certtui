//! The result of inspecting one target.

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::finding::Finding;
use crate::model::{Chain, LoadNote};
use crate::target::Target;
use crate::time::Timestamp;

/// Negotiated TLS session parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsSessionInfo {
    /// Protocol version, for example `TLSv1.3`.
    pub version: String,
    /// Negotiated cipher suite name.
    pub cipher_suite: String,
    /// Key exchange group, when known.
    pub key_exchange_group: Option<String>,
    /// Negotiated ALPN protocol, when any.
    pub alpn: Option<String>,
    /// Address of the peer that was connected to.
    pub peer_ip: IpAddr,
}

/// How long each phase of a network inspection took.
///
/// Deliberately not `Serialize`: serde would emit `Duration` as
/// `{"secs","nanos"}`, so the JSON layer maps it to integer milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    /// DNS resolution.
    pub dns: Option<Duration>,
    /// TCP connection.
    pub connect: Option<Duration>,
    /// TLS handshake.
    pub handshake: Option<Duration>,
    /// The whole inspection.
    pub total: Option<Duration>,
}

/// Outcome of validating the chain against trust anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TrustVerdict {
    /// The chain validates against `anchor`.
    Trusted {
        /// Subject of the anchor that was used.
        anchor: String,
    },
    /// The chain does not validate.
    Untrusted {
        /// Why validation failed.
        reason: String,
    },
    /// Trust was not evaluated (for example, file inputs).
    NotEvaluated,
}

/// Revocation status of one certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Not revoked.
    Good,
    /// Revoked.
    Revoked {
        /// Revocation reason, when given.
        reason: Option<String>,
        /// Revocation time, when given.
        at: Option<Timestamp>,
    },
    /// Could not be determined.
    Unknown {
        /// Why it could not be determined.
        why: String,
    },
}

/// Everything learned about one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectionReport {
    /// What was inspected.
    pub target: Target,
    /// TLS session parameters (network targets only).
    pub tls: Option<TlsSessionInfo>,
    /// The certificates found.
    pub chain: Chain,
    /// Trust verdict.
    pub trust: TrustVerdict,
    /// Revocation status per verified certificate.
    pub revocation: Vec<RevocationStatus>,
    /// Findings, ordered by descending severity.
    pub findings: Vec<Finding>,
    /// Phase durations.
    pub timings: Timings,
    /// Read and extraction diagnostics (empty for network targets).
    pub notes: Vec<LoadNote>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_timings_default_deve_ter_tudo_none() {
        let t = Timings::default();
        assert!(
            t.dns.is_none() && t.connect.is_none() && t.handshake.is_none() && t.total.is_none()
        );
    }

    #[test]
    fn quando_trust_verdict_serializa_deve_marcar_status() {
        let v = TrustVerdict::Trusted {
            anchor: "Root".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&v).unwrap(),
            r#"{"status":"trusted","anchor":"Root"}"#
        );
        assert_eq!(
            serde_json::to_string(&TrustVerdict::NotEvaluated).unwrap(),
            r#"{"status":"not_evaluated"}"#
        );
    }

    #[test]
    fn quando_revocation_status_serializa_deve_marcar_status() {
        let at = Timestamp::from_unix(0).unwrap();
        let revoked = RevocationStatus::Revoked {
            reason: Some("keyCompromise".to_owned()),
            at: Some(at),
        };
        assert_eq!(
            serde_json::to_string(&revoked).unwrap(),
            r#"{"status":"revoked","reason":"keyCompromise","at":"1970-01-01T00:00:00Z"}"#
        );
        assert_eq!(
            serde_json::to_string(&RevocationStatus::Unknown {
                why: "no OCSP".to_owned()
            })
            .unwrap(),
            r#"{"status":"unknown","why":"no OCSP"}"#
        );
        assert_eq!(
            serde_json::to_string(&RevocationStatus::Good).unwrap(),
            r#"{"status":"good"}"#
        );
    }

    #[test]
    fn quando_tls_session_info_serializa_deve_emitir_ip_como_string() {
        let info = TlsSessionInfo {
            version: "TLSv1.3".to_owned(),
            cipher_suite: "TLS_AES_128_GCM_SHA256".to_owned(),
            key_exchange_group: None,
            alpn: Some("h2".to_owned()),
            peer_ip: "192.0.2.1".parse().unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&info).unwrap(),
            r#"{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","key_exchange_group":null,"alpn":"h2","peer_ip":"192.0.2.1"}"#
        );
    }
}
