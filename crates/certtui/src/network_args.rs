//! Parsers of the network-only options (`--sni`, `--connect-to`, `--timeout`).
//! SNI is validated after Clap parses the raw string so an invalid value is
//! never echoed by Clap in its usage error.

use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use certtui_domain::target_parse::parse_sni as parse_sni_name;

/// The address given to `--connect-to`; the port is optional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectTo {
    /// The address to connect to instead of resolving the host name.
    pub ip: IpAddr,
    /// The port, when given; otherwise the target's port applies.
    pub port: Option<u16>,
}

/// Validates and normalizes `--sni`: a DNS name (lowercased, punycode) or an
/// IP literal.
///
/// # Errors
///
/// A short message when the value is not a valid name; it never echoes it.
pub fn parse_sni(value: &str) -> Result<String, String> {
    parse_sni_name(value).map_err(|_| "not a valid DNS name or IP literal".to_owned())
}

/// Parses `--connect-to`: `IPV4`, `IPV4:PORT`, `IPV6`, `[IPV6]` or
/// `[IPV6]:PORT`.
///
/// # Errors
///
/// A short message naming the accepted forms.
pub fn parse_connect_to(value: &str) -> Result<ConnectTo, String> {
    parse_connect_to_inner(value)
        .ok_or_else(|| "expected IP, IP:PORT, IPV6 or [IPV6]:PORT (port 1 to 65535)".to_owned())
}

fn parse_connect_to_inner(value: &str) -> Option<ConnectTo> {
    if let Some(bracketed) = value.strip_prefix('[') {
        let (literal, after) = bracketed.split_once(']')?;
        let ip = IpAddr::V6(literal.parse::<Ipv6Addr>().ok()?);
        let port = match after {
            "" => None,
            _ => Some(parse_port(after.strip_prefix(':')?)?),
        };
        return Some(ConnectTo { ip, port });
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ConnectTo { ip, port: None });
    }
    let (host, port) = value.split_once(':')?;
    Some(ConnectTo {
        ip: IpAddr::V4(host.parse().ok()?),
        port: Some(parse_port(port)?),
    })
}

fn parse_port(port: &str) -> Option<u16> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port.parse::<u16>().ok().filter(|port| *port != 0)
}

/// Parses `--timeout`: a whole number of seconds, at least 1.
///
/// # Errors
///
/// A short message when the value is zero or not a number.
pub fn parse_timeout(value: &str) -> Result<Duration, String> {
    match value.parse::<u64>() {
        Ok(seconds) if seconds > 0 => Ok(Duration::from_secs(seconds)),
        _ => Err("expected a whole number of seconds, 1 or more".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connect(value: &str) -> Result<(String, Option<u16>), String> {
        parse_connect_to(value).map(|c| (c.ip.to_string(), c.port))
    }

    fn expected(ip: &str, port: Option<u16>) -> (String, Option<u16>) {
        (ip.to_owned(), port)
    }

    #[test]
    fn quando_connect_to_valido_deve_aceitar_as_formas_documentadas() {
        assert_eq!(connect("127.0.0.1").unwrap(), expected("127.0.0.1", None));
        assert_eq!(
            connect("127.0.0.1:8443").unwrap(),
            expected("127.0.0.1", Some(8443))
        );
        assert_eq!(connect("::1").unwrap(), expected("::1", None));
        assert_eq!(
            connect("2001:db8::1").unwrap(),
            expected("2001:db8::1", None)
        );
        assert_eq!(connect("[::1]").unwrap(), expected("::1", None));
        assert_eq!(connect("[::1]:8443").unwrap(), expected("::1", Some(8443)));
    }

    #[test]
    fn quando_connect_to_invalido_deve_rejeitar() {
        for value in [
            "",
            "localhost",
            "example.com:443",
            "1.2.3.4:0",
            "1.2.3.4:65536",
            "1.2.3.4:",
            "1.2.3.4:x",
            "1.2.3.4:+5",
            "1.2.3.4:443:1",
            "999.1.1.1",
            "[::1",
            "[::1]x",
            "[::1]:",
            "[1.2.3.4]:443",
            "::1:443:1:",
            " 1.2.3.4",
        ] {
            assert!(parse_connect_to(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn quando_timeout_e_numero_positivo_deve_aceitar() {
        assert_eq!(parse_timeout("2"), Ok(Duration::from_secs(2)));
        assert_eq!(
            parse_timeout("18446744073709551615"),
            Ok(Duration::from_secs(u64::MAX))
        );
    }

    #[test]
    fn quando_timeout_e_zero_ou_nao_numerico_deve_rejeitar() {
        for value in ["0", "", "-1", "1.5", "abc", "2s", " 2"] {
            assert!(parse_timeout(value).is_err(), "{value:?}");
        }
    }

    #[test]
    fn quando_timeout_passa_do_teto_deve_ser_limitado_ao_hard_cap() {
        use certtui_app::config::{CliOverrides, Config};
        use certtui_domain::limits::Limits;

        let resolve = |seconds| {
            let flags = CliOverrides {
                timeout_secs: Some(seconds),
                ..CliOverrides::default()
            };
            Config::default().resolve(&flags).unwrap().limits
        };
        assert_eq!(
            resolve(10_000).target_total_timeout,
            Limits::HARD_CAPS.target_total_timeout
        );
        let limits = resolve(2);
        assert_eq!(limits.target_total_timeout, Duration::from_secs(2));
        assert_eq!(limits.dns_timeout, Limits::default().dns_timeout);
    }

    #[test]
    fn quando_sni_invalido_deve_dar_mensagem_curta_sem_eco() {
        let error = parse_sni("bad name").unwrap_err();
        assert!(!error.contains("bad name"), "{error}");
        assert_eq!(parse_sni("Example.com").as_deref(), Ok("example.com"));
    }
}
