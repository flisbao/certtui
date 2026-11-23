//! Fingerprints computed over fixture DER files must match `openssl x509 -fingerprint`.

use certtui_domain::model::{FingerprintAlgorithm, FingerprintFormat, Fingerprints};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

/// Extracts the value after `=` from the line that starts with `<prefix> Fingerprint=`.
fn expected(txt: &str, prefix: &str) -> Option<String> {
    txt.lines().find_map(|line| {
        let (head, value) = line.split_once('=')?;
        (head
            .trim()
            .eq_ignore_ascii_case(&format!("{prefix} Fingerprint")))
        .then(|| value.trim().to_owned())
    })
}

#[test]
fn quando_der_da_fixture_deve_bater_com_openssl() {
    for name in [
        "rsa2048-leaf",
        "ec-p256-leaf",
        "san-multi",
        "expired",
        "public-leaf-with-sct",
        "chain-3",
    ] {
        let der = std::fs::read(format!("{FIXTURES}/{name}.der")).unwrap();
        let txt = std::fs::read_to_string(format!("{FIXTURES}/{name}.fingerprints.txt")).unwrap();
        let fps = Fingerprints::compute(&der);
        for (alg, prefix) in [
            (FingerprintAlgorithm::Sha1, "sha1"),
            (FingerprintAlgorithm::Sha256, "sha256"),
            (FingerprintAlgorithm::Sha512, "sha512"),
        ] {
            assert_eq!(
                fps.format(alg, FingerprintFormat::ColonHexUpper),
                expected(&txt, prefix).unwrap(),
                "{name} {prefix}"
            );
        }
    }
}
