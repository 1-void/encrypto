use encrypto_core::{
    Backend, KeyGenParams, PqcLevel, PqcPolicy, RevocationReason, RevokeRequest, RotateRequest,
    UserId,
};
use encrypto_pgp::NativeBackend;

fn set_temp_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    unsafe {
        std::env::set_var("ENCRYPTO_HOME", dir.path());
    }
    dir
}

fn assert_revoked(cert_bytes: &[u8]) {
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::types::RevocationStatus;
    use sequoia_openpgp as openpgp;

    let cert = openpgp::Cert::from_bytes(cert_bytes).expect("parse cert");
    let policy = StandardPolicy::new();
    match cert.revocation_status(&policy, None) {
        RevocationStatus::Revoked(_) => {}
        other => panic!("expected revoked cert, got {other:?}"),
    }
}

#[test]
fn revoke_marks_cert_revoked() {
    let _home = set_temp_home();
    let passphrase = "rotate-pass";
    let backend = NativeBackend::with_passphrase(PqcPolicy::Required, Some(passphrase.to_string()));
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Revoke <revoke@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: Some(passphrase.to_string()),
            allow_unprotected: false,
        })
        .expect("keygen");

    let result = backend
        .revoke_key(RevokeRequest {
            key_id: meta.key_id.clone(),
            reason: RevocationReason::KeyCompromised,
            message: Some("test revoke".to_string()),
            armor: false,
        })
        .expect("revoke");

    assert_revoked(&result.updated_cert);
}

#[test]
fn rotate_creates_new_key_and_revokes_old() {
    let _home = set_temp_home();
    let passphrase = "rotate-pass";
    let backend = NativeBackend::with_passphrase(PqcPolicy::Required, Some(passphrase.to_string()));
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Rotate <rotate@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: Some(passphrase.to_string()),
            allow_unprotected: false,
        })
        .expect("keygen");

    let rotated = backend
        .rotate_key(RotateRequest {
            key_id: meta.key_id.clone(),
            new_user_id: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: Some(passphrase.to_string()),
            allow_unprotected: false,
            revoke_old: true,
        })
        .expect("rotate");

    assert!(rotated.old_key_revoked, "expected old key revoked");
    assert_ne!(
        rotated.new_key.key_id, meta.key_id,
        "rotation should create a new key"
    );

    let old_public = backend
        .export_key(&meta.key_id, false)
        .expect("export old cert");
    assert_revoked(&old_public);
}
