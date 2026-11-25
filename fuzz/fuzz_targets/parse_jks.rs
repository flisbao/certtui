//! Fuzz target: the JKS reader must never panic, hang or allocate from
//! untrusted counts and lengths, with or without the password.

#![no_main]

use certtui_domain::limits::Limits;
use certtui_infra::keystore::fuzzing::read_jks;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only absence of panics, hangs and OOM matters; the count is discarded.
    let _ = read_jks(data, &Limits::default());
});
