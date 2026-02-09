use qpgp_core::{
    Backend, DecryptRequest, EncryptRequest, KeyGenParams, PqcLevel, PqcPolicy, RevocationReason,
    RevokeRequest, RotateRequest, UserId,
};
mod common;

use common::{require_pqc, set_temp_home};
use qpgp_pgp::NativeBackend;

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
    if !require_pqc(backend.supports_pqc()) {
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
    if !require_pqc(backend.supports_pqc()) {
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
        .export_key(&meta.key_id, false, false)
        .expect("export old cert");
    assert_revoked(&old_public);
}

#[test]
fn decrypt_with_revoked_keys_requires_explicit_opt_in() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Revoked Decrypt <revdec@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let plaintext = b"archive message".to_vec();
    let ciphertext = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id.clone()],
            plaintext: plaintext.clone(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");

    // Revoke the key (common rotation/incident response workflow).
    backend
        .revoke_key(RevokeRequest {
            key_id: meta.key_id.clone(),
            reason: RevocationReason::KeySuperseded,
            message: Some("test revoke".to_string()),
            armor: false,
        })
        .expect("revoke");

    // Default behavior: refuse to use revoked keys for decryption.
    let default_attempt = backend.decrypt(DecryptRequest {
        ciphertext: ciphertext.clone(),
        pqc_policy: PqcPolicy::Required,
        allow_revoked_keys: false,
    });
    assert!(
        default_attempt.is_err(),
        "expected decryption with revoked keys to fail by default"
    );

    // Opt-in behavior: allow archival recovery.
    let recovered = backend
        .decrypt(DecryptRequest {
            ciphertext,
            pqc_policy: PqcPolicy::Required,
            allow_revoked_keys: true,
        })
        .expect("decrypt with revoked keys");
    assert_eq!(recovered, plaintext);
}

#[test]
fn load_all_certs_merges_public_updates_into_secret_store() {
    use std::path::PathBuf;

    use openpgp::parse::Parse;
    use openpgp::types::ReasonForRevocation;
    use sequoia_openpgp as openpgp;
    use sequoia_openpgp::serialize::SerializeInto;

    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Merge Test <merge@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    // Keep a stale secret copy on disk, but update only the public copy to include a revocation.
    let tsk_bytes = backend
        .export_key(&meta.key_id, true, false)
        .expect("export secret");
    let cert = openpgp::Cert::from_bytes(&tsk_bytes).expect("parse secret cert");

    let key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .expect("secret key load");
    let mut keypair = key.into_keypair().expect("keypair");
    let rev = cert
        .revoke(
            &mut keypair,
            ReasonForRevocation::KeyCompromised,
            b"test revocation",
        )
        .expect("make revocation");
    let (revoked_cert, _) = cert.clone().insert_packets(rev).expect("insert revocation");
    let revoked_public = revoked_cert.to_vec().expect("serialize revoked cert");

    let home = PathBuf::from(std::env::var("QPGP_HOME").expect("QPGP_HOME"));
    let public_path = home.join("public").join(format!("{}.pgp", meta.key_id.0));
    let secret_path = home.join("secret").join(format!("{}.pgp", meta.key_id.0));

    std::fs::write(&public_path, revoked_public).expect("write public update");
    std::fs::write(&secret_path, tsk_bytes).expect("ensure secret stays stale");

    // load_all_certs() should merge the public revocation into the secret cert.
    let exported = backend
        .export_key(&meta.key_id, false, false)
        .expect("export merged cert");
    assert_revoked(&exported);
}
