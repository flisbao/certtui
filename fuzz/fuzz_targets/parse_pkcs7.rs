//! Fuzz target: the bounded PKCS#7 / CMS envelope reader must never panic,
//! hang or allocate from untrusted lengths.

#![no_main]

use certtui_domain::limits::Limits;
use certtui_infra::source::fuzzing::extract_pkcs7_certs;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only absence of panics, hangs and OOM matters; the result is discarded.
    let _ = extract_pkcs7_certs(data, &Limits::default());
});
