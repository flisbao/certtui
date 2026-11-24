//! Serves `Behavior::Ok` on `127.0.0.1` until the process is killed.
//!
//! The first line written to stdout is `PORT=<n>` (the ephemeral port chosen),
//! flushed immediately; scripts (`scripts/rss_check.sh`) parse that line. The
//! certificate chain is generated at start-up; the SAN covers `localhost` and
//! `127.0.0.1`, and the CA is not exported, so clients must not verify it.

#[path = "../tests/support/tls_server.rs"]
mod tls_server;

use std::io::Write;

use tls_server::{Behavior, TestServer};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), tls_server::HarnessError> {
    let server = TestServer::start(Behavior::Ok).await?;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "PORT={}", server.addr().port())?;
    stdout.flush()?;
    std::future::pending::<()>().await;
    Ok(())
}
