//! Policy of the `check` command: which findings fail a run.

use certtui_domain::finding::{Finding, Severity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The lowest severity that makes a check fail (`--fail-on`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    /// Warnings and errors fail the check.
    Warning,
    /// Only errors fail the check.
    #[default]
    Error,
}

impl FailOn {
    /// The lowest [`Severity`] that fails.
    #[must_use]
    pub fn threshold(self) -> Severity {
        match self {
            FailOn::Warning => Severity::Warning,
            FailOn::Error => Severity::Error,
        }
    }

    /// Whether any of `findings` is at or above the threshold.
    #[must_use]
    pub fn fails(self, findings: &[Finding]) -> bool {
        findings.iter().any(|f| f.severity >= self.threshold())
    }
}

#[cfg(test)]
mod tests {
    use certtui_domain::finding::{FindingCategory, FindingCode};

    use super::*;

    fn finding(severity: Severity) -> Finding {
        Finding {
            code: FindingCode::ExpiresSoon,
            severity,
            category: FindingCategory::Quality,
            cert_index: None,
            message: String::new(),
        }
    }

    #[test]
    fn quando_fail_on_error_e_ha_so_warning_deve_nao_falhar() {
        assert!(!FailOn::Error.fails(&[finding(Severity::Warning), finding(Severity::Info)]));
        assert!(FailOn::Error.fails(&[finding(Severity::Error)]));
    }

    #[test]
    fn quando_fail_on_warning_e_ha_warning_deve_falhar() {
        assert!(FailOn::Warning.fails(&[finding(Severity::Warning)]));
        assert!(!FailOn::Warning.fails(&[finding(Severity::Info)]));
    }

    #[test]
    fn quando_sem_achados_deve_nao_falhar() {
        assert!(!FailOn::Warning.fails(&[]));
        assert!(!FailOn::Error.fails(&[]));
    }

    #[test]
    fn quando_padrao_deve_ser_error() {
        assert_eq!(FailOn::default(), FailOn::Error);
    }
}
