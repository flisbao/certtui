//! Binary entry point of the certificate TUI.

mod cli;
// Justificativa: wired into the CLI by the next change (TUI entry).
#[allow(dead_code)]
mod command_executor;
mod exit_code;
mod network_args;
mod output;
mod runtime;
// Justificativa: wired into the CLI by the next change (TUI entry).
#[allow(dead_code)]
mod system_inspector;
mod target_parse;
// Justificativa: wired into the CLI by the next change (TUI entry).
#[allow(dead_code)]
mod tui_runner;
mod wiring;

fn main() -> std::process::ExitCode {
    wiring::run_process()
}
