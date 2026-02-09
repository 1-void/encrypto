mod common;

use common::{require_pqc, set_temp_home};
use openpgp::parse::Parse;
use qpgp_core::{
    Backend, EncryptRequest, KeyGenParams, PqcLevel, PqcPolicy, SignRequest, UserId, VerifyRequest,
};
use qpgp_pgp::{NativeBackend, pqc_suite_supported};
use qpgp_policy::{
    cert_has_pqc_encryption_key, cert_has_pqc_signing_key, cert_is_pqc_only,
    ensure_pqc_encryption_output, ensure_pqc_signature_output,
};
use sequoia_openpgp as openpgp;

fn require_pqc_high_or_baseline() -> PqcLevel {
    if pqc_suite_supported(PqcLevel::High) {
        PqcLevel::High
    } else {
        PqcLevel::Baseline
    }
}

#[test]
fn native_keygen_produces_pqc_only_cert() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let level = require_pqc_high_or_baseline();
    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Test <test@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: level,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let exported = backend
        .export_key(&meta.key_id, false, false)
        .expect("export public");
    let cert = openpgp::Cert::from_bytes(&exported).expect("parse cert");

    assert!(cert_is_pqc_only(&cert), "cert must be PQC-only");
    assert!(
        cert_has_pqc_signing_key(&cert),
        "cert must have PQC signing capability"
    );
    assert!(
        cert_has_pqc_encryption_key(&cert),
        "cert must have PQC encryption capability"
    );
}

#[test]
fn native_encrypt_output_is_pqc_only_and_decrypts() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let level = require_pqc_high_or_baseline();
    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Enc <enc@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: level,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let plaintext = b"hello pqc encrypt".to_vec();
    let ciphertext = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id.clone()],
            plaintext: plaintext.clone(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");

    ensure_pqc_encryption_output(&ciphertext).expect("ciphertext must be PQC-only + AEAD");

    let decrypted = backend
        .decrypt(qpgp_core::DecryptRequest {
            ciphertext,
            pqc_policy: PqcPolicy::Required,
            allow_revoked_keys: false,
        })
        .expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn native_signatures_are_pqc_and_verify() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let level = require_pqc_high_or_baseline();
    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Sig <sig@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: level,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let message = b"hello pqc signature".to_vec();
    let signature = backend
        .sign(SignRequest {
            signer: meta.key_id.clone(),
            message: message.clone(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");

    ensure_pqc_signature_output(&signature).expect("signature must be PQC + v6 + strong hash");

    let result = backend
        .verify(VerifyRequest {
            message,
            signature,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");

    assert!(result.valid, "signature must verify");
    assert!(result.signer.is_some(), "verify should report signer");
}
