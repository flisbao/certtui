//! Binary entry point of the certificate TUI.

mod cli;
mod exit_code;
mod network_args;
mod output;
mod runtime;
mod target_parse;
mod wiring;

fn main() -> std::process::ExitCode {
    wiring::run_process()
}
