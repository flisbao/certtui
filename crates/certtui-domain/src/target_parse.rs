//! Parsing of network target arguments (spec section 6.4, rules 3 to 5).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::target::{NetworkTarget, TargetError};

/// Port used when the target does not name one.
const DEFAULT_PORT: u16 = 443;
/// Longest accepted argument, in bytes; longer input is rejected unread.
const MAX_ARG_BYTES: usize = 2048;
/// Longest accepted host before IDNA, in bytes (non-ASCII text is longer
/// than its punycode form, so this is looser than the DNS limit).
const MAX_RAW_HOST_BYTES: usize = 1024;
/// Longest DNS name, without the trailing dot.
const MAX_HOST_LEN: usize = 253;
/// Longest DNS label.
const MAX_LABEL_LEN: usize = 63;
/// Longest scheme kept in an error.
const MAX_SCHEME_LEN: usize = 32;

/// Parses `[https://]host[:port][/path]`, `v4[:port]` or `[v6][:port]`.
///
/// The host is lowercased, converted to punycode (IDNA, strict STD3 rules) and
/// stripped of one trailing dot; an IPv6 literal is stored without brackets.
/// The port defaults to 443. Path, query and fragment of a URL are ignored.
/// `sni` and `connect_to` are always `None`. Work is bounded by the input
/// length cap and the function never recurses.
///
/// An authority that is empty (`https://`) is reported as
/// [`TargetError::Empty`]; an empty host next to a port (`:443`) is
/// [`TargetError::InvalidHost`].
///
/// # Errors
///
/// A [`TargetError`] naming the first problem found. Credentials
/// (`user:pw@host`) are rejected without echoing them.
pub fn parse_network_target(arg: &str) -> Result<NetworkTarget, TargetError> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Err(TargetError::Empty);
    }
    if arg.len() > MAX_ARG_BYTES {
        return Err(TargetError::InvalidHost);
    }
    let rest = strip_scheme(arg)?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(TargetError::Empty);
    }
    if authority.contains('@') {
        return Err(TargetError::CredentialsNotAllowed);
    }
    let (host, port) = split_host_port(authority)?;
    let port = match port {
        Some(port) => parse_port(port)?,
        None => DEFAULT_PORT,
    };
    Ok(NetworkTarget {
        host,
        port,
        sni: None,
        connect_to: None,
    })
}

/// Validates and normalizes a `--sni` value: a DNS name (lowercased,
/// punycode, one trailing dot removed) or an IP literal.
///
/// The rules are those of the host of [`parse_network_target`]; an IPv6
/// literal is given without brackets. An IP literal is accepted because the
/// TLS client then simply sends no SNI.
///
/// # Errors
///
/// [`TargetError::InvalidHost`] for an empty, over-long or malformed name
/// (spaces, bad IDNA, empty labels, ...). The value is never echoed.
pub fn parse_sni(name: &str) -> Result<String, TargetError> {
    if name.len() > MAX_RAW_HOST_BYTES {
        return Err(TargetError::InvalidHost);
    }
    match name.parse::<Ipv6Addr>() {
        Ok(addr) => Ok(addr.to_string()),
        Err(_) => normalize_host(name),
    }
}

/// Removes an `https://` prefix; rejects any other scheme.
fn strip_scheme(arg: &str) -> Result<&str, TargetError> {
    let Some((scheme, rest)) = arg.split_once("://") else {
        return Ok(arg);
    };
    if !is_scheme(scheme) {
        return Err(TargetError::InvalidHost);
    }
    if scheme.eq_ignore_ascii_case("https") {
        Ok(rest)
    } else {
        Err(TargetError::UnsupportedScheme(scheme.to_ascii_lowercase()))
    }
}

fn is_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    scheme.len() <= MAX_SCHEME_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Splits the authority into a normalized host and the raw port text.
fn split_host_port(authority: &str) -> Result<(String, Option<&str>), TargetError> {
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (literal, after) = bracketed.split_once(']').ok_or(TargetError::InvalidHost)?;
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or(TargetError::InvalidHost)?),
        };
        let addr: Ipv6Addr = literal.parse().map_err(|_| TargetError::InvalidHost)?;
        return Ok((addr.to_string(), port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !port.contains(':') => (host, Some(port)),
        // A second colon: an IPv6 literal without brackets is ambiguous.
        Some(_) => return Err(TargetError::InvalidHost),
        None => (authority, None),
    };
    Ok((normalize_host(host)?, port))
}

fn parse_port(port: &str) -> Result<u16, TargetError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TargetError::InvalidPort);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(TargetError::InvalidPort),
        Ok(port) => Ok(port),
    }
}

/// An IPv4 literal or a punycode DNS name in lowercase, without trailing dot.
fn normalize_host(host: &str) -> Result<String, TargetError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_RAW_HOST_BYTES {
        return Err(TargetError::InvalidHost);
    }
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return Ok(addr.to_string());
    }
    // `idna` is the only IDNA/punycode implementation (ADR 0001); the strict
    // variant applies STD3 ASCII rules and DNS length checks.
    let ascii = idna::domain_to_ascii_strict(host).map_err(|_| TargetError::InvalidHost)?;
    if !is_valid_dns_name(&ascii) {
        return Err(TargetError::InvalidHost);
    }
    Ok(ascii)
}

fn is_valid_dns_name(name: &str) -> bool {
    name.len() <= MAX_HOST_LEN
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= MAX_LABEL_LEN)
        // A numeric last label would make `127.1` or `1.2.3` ambiguous with
        // legacy IPv4 notations.
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(arg: &str) -> (String, u16) {
        let target = parse_network_target(arg).unwrap_or_else(|e| panic!("{arg:?}: {e:?}"));
        assert_eq!(target.sni, None, "{arg}");
        assert_eq!(target.connect_to, None, "{arg}");
        (target.host, target.port)
    }

    fn pair(host: &str, port: u16) -> (String, u16) {
        (host.to_owned(), port)
    }

    #[test]
    fn quando_host_simples_deve_usar_porta_443() {
        assert_eq!(ok("example.com"), pair("example.com", 443));
    }

    #[test]
    fn quando_host_com_porta_deve_usar_a_porta() {
        assert_eq!(ok("example.com:8443"), pair("example.com", 8443));
    }

    #[test]
    fn quando_url_https_com_path_query_e_fragmento_deve_ignora_los() {
        assert_eq!(ok("https://example.com/a/b?x#y"), pair("example.com", 443));
        assert_eq!(ok("https://example.com?x"), pair("example.com", 443));
        assert_eq!(ok("https://example.com#y"), pair("example.com", 443));
    }

    #[test]
    fn quando_url_https_com_porta_deve_usar_a_porta() {
        assert_eq!(ok("https://example.com:8443/"), pair("example.com", 8443));
    }

    #[test]
    fn quando_esquema_em_maiusculas_deve_aceitar_e_baixar_o_host() {
        assert_eq!(ok("HTTPS://Example.COM"), pair("example.com", 443));
    }

    #[test]
    fn quando_ipv4_deve_manter_o_literal() {
        assert_eq!(ok("1.2.3.4"), pair("1.2.3.4", 443));
        assert_eq!(ok("1.2.3.4:8443"), pair("1.2.3.4", 8443));
    }

    #[test]
    fn quando_ipv6_entre_colchetes_deve_guardar_sem_colchetes() {
        assert_eq!(ok("[::1]:8443"), pair("::1", 8443));
        assert_eq!(ok("[::1]"), pair("::1", 443));
        assert_eq!(ok("[2001:db8::1]"), pair("2001:db8::1", 443));
        assert_eq!(ok("https://[::1]:8443/x"), pair("::1", 8443));
        assert_eq!(ok("[2001:DB8::1]"), pair("2001:db8::1", 443));
    }

    #[test]
    fn quando_host_em_maiusculas_deve_baixar() {
        assert_eq!(ok("EXAMPLE.com"), pair("example.com", 443));
    }

    #[test]
    fn quando_ponto_final_deve_remover() {
        assert_eq!(ok("example.com."), pair("example.com", 443));
        assert_eq!(ok("example.com.:8443"), pair("example.com", 8443));
    }

    #[test]
    fn quando_host_internacionalizado_deve_virar_punycode() {
        assert_eq!(ok("bücher.de"), pair("xn--bcher-kva.de", 443));
        assert_eq!(ok("BÜCHER.de:8443"), pair("xn--bcher-kva.de", 8443));
    }

    #[test]
    fn quando_esquema_nao_https_deve_ser_esquema_nao_suportado() {
        for (arg, scheme) in [("http://x", "http"), ("ftp://x", "ftp"), ("FTP://x", "ftp")] {
            assert_eq!(
                parse_network_target(arg),
                Err(TargetError::UnsupportedScheme(scheme.to_owned())),
                "{arg}"
            );
        }
    }

    #[test]
    fn quando_porta_invalida_deve_ser_invalid_port() {
        for arg in [
            "example.com:0",
            "example.com:65536",
            "example.com:abc",
            "example.com:",
            "example.com:+443",
            "example.com:-1",
            "example.com:443443",
            "[::1]:",
            "https://example.com:x/",
        ] {
            assert_eq!(
                parse_network_target(arg),
                Err(TargetError::InvalidPort),
                "{arg}"
            );
        }
    }

    #[test]
    fn quando_porta_maxima_deve_aceitar() {
        assert_eq!(ok("example.com:65535"), pair("example.com", 65535));
    }

    #[test]
    fn quando_vazio_ou_so_espacos_deve_ser_empty() {
        for arg in ["", " ", "\t\n", "https://", "https:///path"] {
            assert_eq!(
                parse_network_target(arg),
                Err(TargetError::Empty),
                "{arg:?}"
            );
        }
    }

    #[test]
    fn quando_host_invalido_deve_ser_invalid_host() {
        for arg in [
            "a b.com",
            "a_b.com",
            "a..com",
            ".",
            ".example.com",
            ":443",
            "-a.com",
            "a.com..",
            "127.1",
            "1.2.3",
            "999.1.1.1",
            "::1",
            "2001:db8::1",
            "[::1",
            "[::1]x",
            "[fe80::1%eth0]",
            "[1.2.3.4]",
            "[example.com]",
            "a!b.com",
            "a/b://c",
        ] {
            assert_eq!(
                parse_network_target(arg),
                Err(TargetError::InvalidHost),
                "{arg}"
            );
        }
    }

    #[test]
    fn quando_rotulo_maior_que_63_deve_ser_invalid_host() {
        let ok_label = "a".repeat(63);
        assert!(parse_network_target(&format!("{ok_label}.com")).is_ok());
        let long_label = "a".repeat(64);
        assert_eq!(
            parse_network_target(&format!("{long_label}.com")),
            Err(TargetError::InvalidHost)
        );
    }

    #[test]
    fn quando_host_maior_que_253_deve_ser_invalid_host() {
        let label = "a".repeat(63);
        let at_limit = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(at_limit.len(), 253);
        assert!(parse_network_target(&at_limit).is_ok());
        assert_eq!(
            parse_network_target(&format!("{at_limit}a")),
            Err(TargetError::InvalidHost)
        );
    }

    #[test]
    fn quando_argumento_absurdamente_longo_deve_rejeitar_cedo() {
        let huge = "a".repeat(MAX_ARG_BYTES + 1);
        assert_eq!(parse_network_target(&huge), Err(TargetError::InvalidHost));
        let huge_non_ascii = "ü".repeat(MAX_ARG_BYTES);
        assert_eq!(
            parse_network_target(&huge_non_ascii),
            Err(TargetError::InvalidHost)
        );
    }

    #[test]
    fn quando_credenciais_deve_rejeitar_sem_vazar_a_senha() {
        for arg in [
            "https://user:pw@example.com",
            "user:pw@example.com",
            "https://user@example.com:8443/x",
        ] {
            let err = parse_network_target(arg).unwrap_err();
            assert_eq!(err, TargetError::CredentialsNotAllowed, "{arg}");
            let shown = format!("{err}");
            let debug = format!("{err:?}");
            for text in [&shown, &debug] {
                assert!(!text.contains("pw"), "{text}");
                assert!(!text.contains("user"), "{text}");
            }
        }
    }

    #[test]
    fn quando_arroba_so_no_path_deve_aceitar() {
        assert_eq!(ok("https://example.com/@x"), pair("example.com", 443));
    }

    #[test]
    fn quando_esquema_invalido_antes_de_separador_deve_ser_invalid_host() {
        assert_eq!(
            parse_network_target("1http://x"),
            Err(TargetError::InvalidHost)
        );
    }

    #[test]
    fn quando_sni_e_nome_dns_deve_normalizar_para_minusculas_e_punycode() {
        assert_eq!(parse_sni("Example.COM").as_deref(), Ok("example.com"));
        assert_eq!(parse_sni("example.com.").as_deref(), Ok("example.com"));
        assert_eq!(
            parse_sni("b\u{fc}cher.example").as_deref(),
            Ok("xn--bcher-kva.example")
        );
    }

    #[test]
    fn quando_sni_e_literal_ip_deve_aceitar() {
        assert_eq!(parse_sni("127.0.0.1").as_deref(), Ok("127.0.0.1"));
        assert_eq!(parse_sni("::1").as_deref(), Ok("::1"));
        assert_eq!(parse_sni("2001:DB8::1").as_deref(), Ok("2001:db8::1"));
    }

    #[test]
    fn quando_sni_invalido_deve_ser_invalid_host_sem_eco() {
        let too_long_label = "a".repeat(64);
        let too_long_name = format!("{}.com", "a.".repeat(130));
        for name in [
            "",
            " ",
            "a b.example",
            "exa mple.com",
            "-bad.example",
            "bad_name.example",
            "a..b",
            ".",
            "ex\u{0}ample.com",
            "[::1]",
            "example.com:443",
            "xn--zz.example",
            &too_long_label,
            &too_long_name,
        ] {
            let err = parse_sni(name).unwrap_err();
            assert_eq!(err, TargetError::InvalidHost, "{name:?}");
        }
    }
}
