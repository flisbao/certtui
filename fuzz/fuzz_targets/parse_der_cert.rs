//! Fuzz target: DER certificate parsing must never panic or hang.

#![no_main]

use certtui_domain::limits::Limits;
use certtui_domain::model::parse_der_cert;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only absence of panics, hangs and OOM matters; the result is discarded.
    let _ = parse_der_cert(data, &Limits::default());
});
