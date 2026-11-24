//! Process exit codes (spec section 8).

use certtui_app::error::{InspectError, LoadError};

/// Exit status of the CLI.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Success.
    Ok = 0,
    /// Usage error (arguments, unsupported target).
    Usage = 2,
    /// I/O failure, or input without any certificate.
    Input = 3,
    /// Internal error (a bug).
    Internal = 4,
}

impl From<&LoadError> for ExitCode {
    fn from(_error: &LoadError) -> Self {
        // Every load failure is an input problem: the arguments were valid but
        // the source could not be read or held no usable certificate.
        ExitCode::Input
    }
}

impl From<&InspectError> for ExitCode {
    fn from(_error: &InspectError) -> Self {
        // The target was valid but could not be reached, spoke no usable
        // TLS or presented no usable certificate: an input problem.
        ExitCode::Input
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code as u8)
    }
}

#[cfg(test)]
mod tests {
    use certtui_app::fetch::FetchError;

    use super::*;

    #[test]
    fn quando_codigo_deve_ter_o_valor_numerico_da_especificacao() {
        assert_eq!(ExitCode::Ok as i32, 0);
        assert_eq!(ExitCode::Usage as i32, 2);
        assert_eq!(ExitCode::Input as i32, 3);
        assert_eq!(ExitCode::Internal as i32, 4);
    }

    #[test]
    fn quando_load_error_deve_virar_input() {
        let errors = [
            LoadError::TooLarge { limit: 1 },
            LoadError::Io("x".to_owned()),
            LoadError::NoCertificatesFound { notes: Vec::new() },
            LoadError::Unsupported("x"),
            LoadError::Malformed("x".to_owned()),
            LoadError::TooManyCerts { len: 2, max: 1 },
        ];
        for error in &errors {
            assert_eq!(ExitCode::from(error), ExitCode::Input, "{error}");
        }
    }

    #[test]
    fn quando_inspect_error_deve_virar_input() {
        let errors = [
            InspectError::Fetch(FetchError::EmptyChain),
            InspectError::Fetch(FetchError::Cancelled),
            InspectError::NoUsableCertificates { notes: Vec::new() },
            InspectError::ChainTooLong { len: 3, max: 2 },
        ];
        for error in &errors {
            assert_eq!(ExitCode::from(error), ExitCode::Input, "{error}");
        }
    }

    #[test]
    fn quando_converte_para_process_exit_code_deve_preservar_o_valor() {
        assert_eq!(
            std::process::ExitCode::from(ExitCode::Usage),
            std::process::ExitCode::from(2)
        );
    }
}
