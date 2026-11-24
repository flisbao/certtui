//! Binary entry point of the certificate TUI.

mod cli;
mod command_executor;
mod exit_code;
mod network_args;
mod output;
mod runtime;
mod system_inspector;
mod target_parse;
mod tui_launch;
mod tui_runner;
mod wiring;

fn main() -> std::process::ExitCode {
    wiring::run_process()
}
