//! Serves `Behavior::Ok` on many `127.0.0.1` ports until the process is killed.
//!
//! Usage: `tls_multi_server <COUNT> <LIST_FILE>`. It binds `COUNT` listeners,
//! writes their `127.0.0.1:<port>` addresses to `LIST_FILE`, one per line (the
//! format of `certtui batch`), and then writes `READY` to stdout, flushed
//! immediately; `scripts/rss_batch_check.sh` waits for that line. The leaf
//! certificates are not trusted by anything, which is what the memory check
//! wants: every target answers with a full chain and an untrusted verdict.

#[path = "../tests/support/tls_server.rs"]
mod tls_server;

use std::fmt::Write as _;
use std::io::Write;

use tls_server::{Behavior, TestServer};

/// Most listeners one run may start: a mistyped count must not exhaust the
/// file descriptors of the machine.
const MAX_COUNT: usize = 20_000;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), tls_server::HarnessError> {
    let mut args = std::env::args().skip(1);
    let (Some(count), Some(list_path), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: tls_multi_server <COUNT> <LIST_FILE>");
        std::process::exit(2);
    };
    let count = match count.parse::<usize>() {
        Ok(count) if (1..=MAX_COUNT).contains(&count) => count,
        _ => {
            eprintln!("COUNT must be a number from 1 to {MAX_COUNT}");
            std::process::exit(2);
        }
    };
    let mut servers = Vec::with_capacity(count);
    let mut list = String::new();
    for _ in 0..count {
        let server = TestServer::start(Behavior::Ok).await?;
        writeln!(list, "127.0.0.1:{}", server.addr().port()).map_err(std::io::Error::other)?;
        servers.push(server);
    }
    std::fs::write(&list_path, list)?;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "READY")?;
    stdout.flush()?;
    std::future::pending::<()>().await;
    drop(servers);
    Ok(())
}
