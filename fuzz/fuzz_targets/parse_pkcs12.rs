//! Fuzz target: the PKCS#12 reader must never panic, hang or allocate from
//! untrusted lengths, with or without the password.

#![no_main]

use certtui_domain::limits::Limits;
use certtui_infra::keystore::fuzzing::read_pkcs12;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only absence of panics, hangs and OOM matters; the count is discarded.
    let _ = read_pkcs12(data, &Limits::default());
});
