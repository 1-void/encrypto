#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // These validators must never panic on arbitrary bytes.
    let _ = qpgp_policy::ensure_pqc_encryption_output(data);
    let _ = qpgp_policy::ensure_pqc_signature_output(data);
});

