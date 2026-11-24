//! Describing a finished TLS handshake: [`TlsSessionInfo`] and safe text.

use std::net::IpAddr;

use certtui_domain::model::TlsSessionInfo;
use rustls::{ClientConnection, ProtocolVersion};

/// Longest negotiated-parameter name copied into the session info.
const MAX_NAME_CHARS: usize = 64;

/// Makes peer- or OS-influenced text safe to show: keeps printable ASCII only
/// (everything else becomes `?`) and cuts it to `max_chars` characters.
pub(crate) fn sanitize(text: &str, max_chars: usize) -> String {
    text.chars()
        .take(max_chars)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn version_name(version: Option<ProtocolVersion>) -> String {
    match version {
        Some(ProtocolVersion::TLSv1_3) => "TLSv1.3".to_owned(),
        Some(ProtocolVersion::TLSv1_2) => "TLSv1.2".to_owned(),
        Some(other) => sanitize(&format!("{other:?}"), MAX_NAME_CHARS),
        None => "unknown".to_owned(),
    }
}

/// Builds the session description from a connection whose handshake finished.
pub(crate) fn build_session_info(conn: &ClientConnection, peer_ip: IpAddr) -> TlsSessionInfo {
    let cipher = conn
        .negotiated_cipher_suite()
        .map_or_else(|| "unknown".to_owned(), |s| format!("{:?}", s.suite()));
    TlsSessionInfo {
        version: version_name(conn.protocol_version()),
        cipher_suite: sanitize(&cipher, MAX_NAME_CHARS),
        key_exchange_group: conn
            .negotiated_key_exchange_group()
            .map(|g| sanitize(&format!("{:?}", g.name()), MAX_NAME_CHARS)),
        alpn: conn
            .alpn_protocol()
            .map(|p| sanitize(&String::from_utf8_lossy(p), MAX_NAME_CHARS)),
        peer_ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_texto_tem_controles_deve_trocar_por_interrogacao() {
        assert_eq!(sanitize("a\r\nb\u{1b}[0m\tc", 50), "a??b?[0m?c");
    }

    #[test]
    fn quando_texto_e_nao_ascii_deve_trocar_por_interrogacao() {
        assert_eq!(sanitize("caf\u{e9} \u{202e}x", 50), "caf? ?x");
    }

    #[test]
    fn quando_texto_e_longo_deve_cortar_no_limite() {
        assert_eq!(sanitize(&"a".repeat(500), 200).len(), 200);
    }

    #[test]
    fn quando_versao_e_conhecida_deve_usar_nome_tls() {
        assert_eq!(version_name(Some(ProtocolVersion::TLSv1_3)), "TLSv1.3");
        assert_eq!(version_name(Some(ProtocolVersion::TLSv1_2)), "TLSv1.2");
        assert_eq!(version_name(None), "unknown");
    }
}
