//! Memory of a batch screen with 10 000 rows (spec section 9: RSS of at most
//! 128 MiB). The peak resident set of this test process, read from
//! `/proc/self/status`, must stay under the limit while the state is built,
//! sorted by every column and filtered.
//!
//! One test only: the peak (`VmHWM`) belongs to the whole process, so a second
//! test running in parallel would be measured too.
#![cfg(target_os = "linux")]
// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Instant;

use certtui_app::batch::BatchEvent;
use certtui_domain::batch_row::{BatchRow, RowStatus};
use certtui_domain::target::NetworkTarget;
use certtui_tui::update_batch::{on_events, start_batch};
use certtui_tui::{AppState, Command, Msg, update};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

const ROWS: usize = 10_000;
const LIMIT_KIB: u64 = 128 * 1024;

/// A value of `/proc/self/status` in KiB, e.g. `VmHWM` or `VmRSS`.
fn status_kib(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
        .unwrap_or_else(|| panic!("{field} missing from /proc/self/status"));
    line.split_whitespace().next().unwrap().parse().unwrap()
}

fn key(c: char) -> Msg {
    Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
}

/// A row with strings of the size real certificates have.
fn row(i: usize) -> BatchRow {
    BatchRow {
        target: format!("host-{i}.internal.example.com:443"),
        status: match i % 4 {
            0 => RowStatus::Ok,
            1 => RowStatus::Warning,
            2 => RowStatus::Error,
            _ => RowStatus::Failed,
        },
        days_to_expiry: Some(i64::try_from(i % 900).unwrap() - 100),
        subject_cn: Some(format!("host-{i}.internal.example.com")),
        issuer_cn: Some("Example Corp Issuing CA 2026 G3".to_owned()),
        errors: u32::try_from(i % 3).unwrap(),
        warnings: u32::try_from(i % 5).unwrap(),
        infos: 2,
        failure: (i % 4 == 3).then(|| "connection refused".to_owned()),
    }
}

#[test]
fn quando_10000_rows_na_tela_batch_deve_ficar_abaixo_de_128_mib() {
    let mut state = AppState::new(Instant::now());
    let targets: Vec<NetworkTarget> = (0..ROWS)
        .map(|i| NetworkTarget {
            host: format!("host-{i}.internal.example.com"),
            port: 443,
            sni: None,
            connect_to: None,
        })
        .collect();
    let Some(Command::RunBatch { id, .. }) = start_batch(&mut state, targets).into_iter().next()
    else {
        panic!("start_batch must ask for a job");
    };
    // Rows arrive in groups of 64, like the executor sends them.
    for start in (0..ROWS).step_by(64) {
        let end = (start + 64).min(ROWS);
        let mut events: Vec<BatchEvent> = (start..end)
            .map(|index| BatchEvent::Row {
                index,
                row: row(index),
            })
            .collect();
        events.push(BatchEvent::Progress {
            done: end,
            total: ROWS,
        });
        on_events(&mut state, id, events);
    }
    on_events(
        &mut state,
        id,
        vec![BatchEvent::Finished { cancelled: false }],
    );
    // Every column once, reversed, and a filter that keeps a tenth of the rows.
    for _ in 0..7 {
        update(&mut state, key('s'));
        update(&mut state, key('S'));
    }
    update(&mut state, key('/'));
    for c in "host-12".chars() {
        update(&mut state, key(c));
    }
    update(
        &mut state,
        Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
    );
    let batch = state.batch.as_ref().unwrap();
    assert_eq!(batch.total(), ROWS);
    assert!(!batch.view.is_empty() && batch.view.len() < ROWS);

    let peak = status_kib("VmHWM");
    eprintln!(
        "peak rss={peak} KiB, now={} KiB (limit {LIMIT_KIB})",
        status_kib("VmRSS")
    );
    assert!(
        peak <= LIMIT_KIB,
        "peak rss {peak} KiB is over {LIMIT_KIB} KiB"
    );
}
