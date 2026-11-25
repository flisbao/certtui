//! Parsing of batch target lists (spec section 6.5).

use std::collections::HashSet;

use thiserror::Error;

use crate::limits::Limits;
use crate::target::{NetworkTarget, TargetError};
use crate::target_parse::parse_network_target;

/// A parsed batch list: the valid targets and the entries that were skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchInput {
    /// Unique targets, in input order.
    pub targets: Vec<NetworkTarget>,
    /// Entries that could not be parsed, in input order.
    pub skipped: Vec<SkippedLine>,
}

/// An entry of the list that was not accepted as a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedLine {
    /// 1-based line of a text list, or 1-based position in a JSON array.
    pub line: usize,
    /// Why the entry was rejected.
    pub reason: TargetError,
}

/// Why a whole batch list was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BatchInputError {
    /// The list has more unique targets than `max_batch_targets`.
    #[error("too many targets; the limit is {max}")]
    TooManyTargets {
        /// The configured limit.
        max: usize,
    },
    /// The input looks like a JSON array but is not a valid array of strings.
    #[error("invalid JSON target list: {0}")]
    InvalidJson(String),
    /// The input is larger than `max_input_file_bytes`.
    #[error("target list is too large")]
    TooLarge,
}

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// Parses a batch list: one target per line (`#` starts a comment, blank
/// lines are ignored) or a JSON array of strings.
///
/// JSON is detected by a first non-blank byte of `[`. A UTF-8 BOM and CRLF
/// line endings are accepted. Targets are parsed with [`parse_network_target`]
/// and deduplicated by `(host, port)`, keeping the first. Entries that do not
/// parse are reported in [`BatchInput::skipped`] instead of aborting; at most
/// `max_batch_targets` of them are kept so a hostile list cannot grow the
/// report without bound. Work is linear in the input size.
///
/// # Errors
///
/// [`BatchInputError`] when the input exceeds `max_input_file_bytes`, is
/// malformed JSON, or holds more unique targets than `max_batch_targets`.
pub fn parse_batch_input(bytes: &[u8], limits: &Limits) -> Result<BatchInput, BatchInputError> {
    if bytes.len() > limits.max_input_file_bytes {
        return Err(BatchInputError::TooLarge);
    }
    let bytes = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    let mut collector = Collector::new(limits);
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace());
    if first == Some(&b'[') {
        let entries: Vec<String> = serde_json::from_slice(bytes)
            .map_err(|err| BatchInputError::InvalidJson(err.to_string()))?;
        for (index, entry) in entries.iter().enumerate() {
            collector.add(index.saturating_add(1), entry)?;
        }
    } else {
        for (index, raw) in bytes.split(|b| *b == b'\n').enumerate() {
            let line = index.saturating_add(1);
            match std::str::from_utf8(raw) {
                Ok(text) => {
                    let text = text.trim();
                    if text.is_empty() || text.starts_with('#') {
                        continue;
                    }
                    collector.add(line, text)?;
                }
                Err(_) => collector.skip(line, TargetError::InvalidHost),
            }
        }
    }
    Ok(collector.finish())
}

struct Collector {
    targets: Vec<NetworkTarget>,
    skipped: Vec<SkippedLine>,
    seen: HashSet<(String, u16)>,
    max_targets: usize,
}

impl Collector {
    fn new(limits: &Limits) -> Self {
        Self {
            targets: Vec::new(),
            skipped: Vec::new(),
            seen: HashSet::new(),
            max_targets: limits.max_batch_targets,
        }
    }

    fn add(&mut self, line: usize, text: &str) -> Result<(), BatchInputError> {
        match parse_network_target(text) {
            Ok(target) => {
                if self.seen.contains(&(target.host.clone(), target.port)) {
                    return Ok(());
                }
                if self.targets.len() >= self.max_targets {
                    return Err(BatchInputError::TooManyTargets {
                        max: self.max_targets,
                    });
                }
                self.seen.insert((target.host.clone(), target.port));
                self.targets.push(target);
            }
            Err(reason) => self.skip(line, reason),
        }
        Ok(())
    }

    fn skip(&mut self, line: usize, reason: TargetError) {
        if self.skipped.len() < self.max_targets {
            self.skipped.push(SkippedLine { line, reason });
        }
    }

    fn finish(self) -> BatchInput {
        BatchInput {
            targets: self.targets,
            skipped: self.skipped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Result<BatchInput, BatchInputError> {
        parse_batch_input(input.as_bytes(), &Limits::default())
    }

    fn hosts(input: &BatchInput) -> Vec<(&str, u16)> {
        input
            .targets
            .iter()
            .map(|t| (t.host.as_str(), t.port))
            .collect()
    }

    #[test]
    fn quando_linhas_com_comentarios_e_vazias_deve_ignorar() {
        let input = parse("# topo\na.com\n\n   \n  # outro\nb.com:8443\n").unwrap();
        assert_eq!(hosts(&input), [("a.com", 443), ("b.com", 8443)]);
        assert_eq!(input.skipped.len(), 0);
    }

    #[test]
    fn quando_json_array_deve_parsear() {
        let input = parse(r#"  ["a.com", "b.com:8443"]  "#).unwrap();
        assert_eq!(hosts(&input), [("a.com", 443), ("b.com", 8443)]);
    }

    #[test]
    fn quando_json_invalido_deve_dar_invalid_json() {
        for text in ["[\"a.com\"", "[1, 2]", "[\"a.com\",]", "[{\"a\":1}]"] {
            assert!(
                matches!(parse(text), Err(BatchInputError::InvalidJson(_))),
                "{text:?}"
            );
        }
    }

    #[test]
    fn quando_tem_bom_e_crlf_deve_parsear() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"a.com\r\nb.com:8443\r\n");
        let input = parse_batch_input(&bytes, &Limits::default()).unwrap();
        assert_eq!(hosts(&input), [("a.com", 443), ("b.com", 8443)]);

        let mut json = vec![0xEF, 0xBB, 0xBF];
        json.extend_from_slice(b"[\"a.com\"]");
        let input = parse_batch_input(&json, &Limits::default()).unwrap();
        assert_eq!(hosts(&input), [("a.com", 443)]);
    }

    #[test]
    fn quando_alvo_duplicado_em_caixa_diferente_deve_deduplicar() {
        let input = parse("A.com\na.com:443\nhttps://A.COM/x\nb.com\na.com:8443\n").unwrap();
        assert_eq!(
            hosts(&input),
            [("a.com", 443), ("b.com", 443), ("a.com", 8443)]
        );
    }

    #[test]
    fn quando_acima_de_max_batch_targets_deve_dar_too_many_targets() {
        let limits = Limits {
            max_batch_targets: 2,
            ..Limits::default()
        };
        let err = parse_batch_input(b"a.com\nb.com\nc.com\n", &limits).unwrap_err();
        assert_eq!(err, BatchInputError::TooManyTargets { max: 2 });
        // Duplicates do not count against the limit.
        let ok = parse_batch_input(b"a.com\nb.com\nA.com\n", &limits).unwrap();
        assert_eq!(ok.targets.len(), 2);
    }

    #[test]
    fn quando_linha_invalida_deve_ir_para_skipped_com_numero_da_linha() {
        let input = parse("a.com\nbad host\n\nftp://x.com\nb.com\n").unwrap();
        assert_eq!(hosts(&input), [("a.com", 443), ("b.com", 443)]);
        assert_eq!(
            input.skipped,
            [
                SkippedLine {
                    line: 2,
                    reason: TargetError::InvalidHost
                },
                SkippedLine {
                    line: 4,
                    reason: TargetError::UnsupportedScheme("ftp".to_owned())
                },
            ]
        );
    }

    #[test]
    fn quando_linha_tem_1mib_deve_virar_skipped_sem_panic() {
        let mut text = "a.com\n".to_owned();
        text.push_str(&"x".repeat(1024 * 1024));
        text.push_str("\nb.com\n");
        let input = parse(&text).unwrap();
        assert_eq!(hosts(&input), [("a.com", 443), ("b.com", 443)]);
        assert_eq!(input.skipped.len(), 1);
        assert_eq!(input.skipped[0].line, 2);
    }

    #[test]
    fn quando_url_https_deve_virar_host_e_porta() {
        let input = parse("https://example.com:8443/path?q=1\nhttps://b.com\n").unwrap();
        assert_eq!(hosts(&input), [("example.com", 8443), ("b.com", 443)]);
    }

    #[test]
    fn quando_bytes_nao_sao_utf8_deve_virar_skipped() {
        let input = parse_batch_input(b"a.com\n\xff\xfe\nb.com\n", &Limits::default()).unwrap();
        assert_eq!(input.targets.len(), 2);
        assert_eq!(input.skipped.len(), 1);
        assert_eq!(input.skipped[0].line, 2);
    }

    #[test]
    fn quando_entrada_passa_de_max_input_file_bytes_deve_dar_too_large() {
        let limits = Limits {
            max_input_file_bytes: 8,
            ..Limits::default()
        };
        assert_eq!(
            parse_batch_input(b"a.com\nb.com\n", &limits),
            Err(BatchInputError::TooLarge)
        );
    }

    #[test]
    fn quando_json_tem_entrada_invalida_deve_pular_com_posicao() {
        let input = parse(r#"["a.com", "bad host", ""]"#).unwrap();
        assert_eq!(hosts(&input), [("a.com", 443)]);
        assert_eq!(input.skipped.len(), 2);
        assert_eq!(input.skipped[0].line, 2);
        assert_eq!(input.skipped[1].reason, TargetError::Empty);
    }

    #[test]
    fn quando_skipped_enche_deve_parar_no_teto() {
        let limits = Limits {
            max_batch_targets: 3,
            ..Limits::default()
        };
        let input = parse_batch_input(b"x y\nx y\nx y\nx y\nx y\n", &limits).unwrap();
        assert_eq!(input.skipped.len(), 3);
    }
}
