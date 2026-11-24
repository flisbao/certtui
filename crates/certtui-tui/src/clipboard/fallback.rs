//! Try several sinks in order.

use super::{ClipboardError, ClipboardSink, CopyMethod};

/// Tries each sink in turn and stops at the first that works.
pub struct FallbackSink {
    sinks: Vec<Box<dyn ClipboardSink>>,
}

impl FallbackSink {
    /// A fallback over `sinks`, tried in the given order.
    #[must_use]
    pub fn new(sinks: Vec<Box<dyn ClipboardSink>>) -> Self {
        Self { sinks }
    }
}

impl std::fmt::Debug for FallbackSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackSink")
            .field("sinks", &self.sinks.len())
            .finish()
    }
}

impl ClipboardSink for FallbackSink {
    fn copy(&self, text: &str) -> Result<CopyMethod, ClipboardError> {
        if self.sinks.is_empty() {
            return Err(ClipboardError::Unavailable(
                "no clipboard method is enabled".to_owned(),
            ));
        }
        let mut errors = Vec::new();
        for sink in &self.sinks {
            match sink.copy(text) {
                Ok(method) => return Ok(method),
                Err(error) => errors.push(error.to_string()),
            }
        }
        Err(ClipboardError::Unavailable(errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Result<CopyMethod, ClipboardError>);

    impl ClipboardSink for Fixed {
        fn copy(&self, _text: &str) -> Result<CopyMethod, ClipboardError> {
            self.0.clone()
        }
    }

    fn sink(result: Result<CopyMethod, ClipboardError>) -> Box<dyn ClipboardSink> {
        Box::new(Fixed(result))
    }

    #[test]
    fn quando_fallback_primeiro_falha_e_segundo_ok_deve_retornar_segundo() {
        let fallback = FallbackSink::new(vec![
            sink(Err(ClipboardError::Timeout)),
            sink(Ok(CopyMethod::Osc52)),
            sink(Ok(CopyMethod::Native)),
        ]);
        assert_eq!(fallback.copy("x"), Ok(CopyMethod::Osc52));
    }

    #[test]
    fn quando_todos_falham_deve_acumular_erros_na_ordem() {
        let fallback = FallbackSink::new(vec![
            sink(Err(ClipboardError::Unavailable("no display".to_owned()))),
            sink(Err(ClipboardError::Io("closed".to_owned()))),
        ]);
        assert_eq!(
            fallback.copy("x"),
            Err(ClipboardError::Unavailable(
                "clipboard unavailable: no display; clipboard I/O error: closed".to_owned()
            ))
        );
    }

    #[test]
    fn quando_sem_sinks_deve_dar_unavailable() {
        let fallback = FallbackSink::new(Vec::new());
        assert!(matches!(
            fallback.copy("x"),
            Err(ClipboardError::Unavailable(_))
        ));
    }
}
