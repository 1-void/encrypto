use qpgp_core::{Backend, EncryptRequest, KeyId, PqcPolicy};
use qpgp_pgp::{GpgBackend, GpgConfig};

#[test]
fn gpg_backend_is_disabled() {
    let backend = GpgBackend::new(GpgConfig::default());
    assert!(
        backend.list_keys().is_err(),
        "gpg backend should be disabled"
    );

    let result = backend.encrypt(EncryptRequest {
        recipients: vec![KeyId("dummy".to_string())],
        plaintext: b"test".to_vec(),
        armor: false,
        pqc_policy: PqcPolicy::Required,
        compat: false,
    });
    assert!(result.is_err(), "gpg backend should be disabled");
}
