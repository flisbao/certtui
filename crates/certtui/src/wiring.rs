//! Composition root: the only place that instantiates infrastructure.

use std::io::{self, Write};

use certtui_infra::source::FsSourceLoader;

use crate::cli;
use crate::exit_code::ExitCode;

/// Runs the CLI against the real process environment.
pub fn run_process() -> std::process::ExitCode {
    let loader = FsSourceLoader::new();
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();
    let result = cli::run(std::env::args_os(), &loader, &mut out, &mut err)
        .and_then(|code| out.flush().map(|()| code).map_err(anyhow::Error::from));
    exit_code_for(result, &mut err).into()
}

/// Maps the outcome of [`cli::run`] to an exit code; unexpected errors are
/// reported on `err` and become [`ExitCode::Internal`], except a closed
/// output pipe (`certtui ... | head`), which is a normal way to stop.
pub fn exit_code_for(result: anyhow::Result<ExitCode>, err: &mut dyn Write) -> ExitCode {
    match result {
        Ok(code) => code,
        Err(error) if is_broken_pipe(&error) => ExitCode::Ok,
        Err(error) => {
            // Nothing more can be done if stderr itself is gone.
            let _ = writeln!(err, "certtui: internal error: {error:#}");
            ExitCode::Internal
        }
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<io::Error>())
        .any(|io_error| io_error.kind() == io::ErrorKind::BrokenPipe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_resultado_ok_deve_manter_o_codigo() {
        let mut err = Vec::new();
        assert_eq!(
            exit_code_for(Ok(ExitCode::Input), &mut err),
            ExitCode::Input
        );
        assert_eq!(err, Vec::<u8>::new());
    }

    #[test]
    fn quando_erro_inesperado_deve_ser_4_e_explicar_no_stderr() {
        let mut err = Vec::new();
        let error = anyhow::anyhow!("boom");
        assert_eq!(exit_code_for(Err(error), &mut err), ExitCode::Internal);
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "certtui: internal error: boom\n"
        );
    }

    #[test]
    fn quando_pipe_fechado_deve_sair_0_sem_ruido() {
        let mut err = Vec::new();
        let error = anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe))
            .context("writing the output");
        assert_eq!(exit_code_for(Err(error), &mut err), ExitCode::Ok);
        assert_eq!(err, Vec::<u8>::new());
    }
}
