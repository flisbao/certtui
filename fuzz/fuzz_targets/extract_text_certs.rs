//! Fuzz target: the text scanner and the parsing of its candidates must never
//! panic or hang.

#![no_main]

use certtui_domain::extract::scan_text;
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertOrigin, CertificateRecord};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let outcome = scan_text(data, &limits);
    for (position, candidate) in outcome.candidates.iter().enumerate() {
        // Only absence of panics, hangs and OOM matters; the result is discarded.
        let _ = CertificateRecord::from_der(
            &candidate.der,
            CertOrigin::Presented { position },
            &limits,
        );
    }
});
