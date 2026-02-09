use qpgp_core::{
    Backend, DecryptRequest, EncryptRequest, ImportRequest, KeyGenParams, KeyId, PqcLevel,
    PqcPolicy, SignRequest, UserId, VerifyRequest,
};
mod common;

use common::{require_pqc, set_home, set_temp_home};
use qpgp_pgp::NativeBackend;
use sequoia_openpgp::serialize::SerializeInto;

fn assert_pqc_encryption(bytes: &[u8]) {
    use openpgp::parse::Parse;
    use openpgp::types::PublicKeyAlgorithm;
    use openpgp::{Packet, PacketPile};
    use sequoia_openpgp as openpgp;

    let pile = PacketPile::from_bytes(bytes).expect("parse encrypted output");
    let mut pkesk_count = 0usize;
    for packet in pile.descendants() {
        if let Packet::PKESK(pkesk) = packet {
            pkesk_count += 1;
            assert!(
                matches!(
                    pkesk.pk_algo(),
                    PublicKeyAlgorithm::MLKEM768_X25519 | PublicKeyAlgorithm::MLKEM1024_X448
                ),
                "non-PQC recipient packet found: {:?}",
                pkesk.pk_algo()
            );
        }
    }
    assert!(pkesk_count > 0, "no recipient packets found");
}

fn assert_pqc_signature(bytes: &[u8]) {
    use openpgp::parse::Parse;
    use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};
    use openpgp::{Packet, PacketPile};
    use sequoia_openpgp as openpgp;

    let pile = PacketPile::from_bytes(bytes).expect("parse signature output");
    let mut sig_count = 0usize;
    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            sig_count += 1;
            assert!(
                matches!(
                    sig.pk_algo(),
                    PublicKeyAlgorithm::MLDSA65_Ed25519
                        | PublicKeyAlgorithm::MLDSA87_Ed448
                        | PublicKeyAlgorithm::SLHDSA128s
                        | PublicKeyAlgorithm::SLHDSA128f
                        | PublicKeyAlgorithm::SLHDSA256s
                ),
                "non-PQC signature found: {:?}",
                sig.pk_algo()
            );
            assert!(
                matches!(
                    sig.hash_algo(),
                    HashAlgorithm::SHA256
                        | HashAlgorithm::SHA384
                        | HashAlgorithm::SHA512
                        | HashAlgorithm::SHA3_256
                        | HashAlgorithm::SHA3_512
                ),
                "weak hash used: {:?}",
                sig.hash_algo()
            );
        }
    }
    assert!(sig_count > 0, "no signatures found");
}

fn generate_classic_cert_bytes(user_id: &str) -> Vec<u8> {
    use openpgp::Profile;
    use openpgp::cert::prelude::*;
    use sequoia_openpgp as openpgp;

    let (cert, _rev) = CertBuilder::general_purpose(Some(user_id))
        .set_profile(Profile::RFC9580)
        .expect("profile")
        .set_cipher_suite(CipherSuite::Cv25519)
        .generate()
        .expect("generate cert");

    cert.as_tsk().to_vec().expect("serialize secret cert")
}

#[test]
fn pqc_required_outputs_are_pqc() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Alice <alice@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let plaintext = b"pqc test";
    let encrypted = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id.clone()],
            plaintext: plaintext.to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");
    assert_pqc_encryption(&encrypted);

    let signature = backend
        .sign(SignRequest {
            signer: meta.key_id,
            message: plaintext.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");
    assert_pqc_signature(&signature);
}

#[test]
fn list_keys_empty_returns_empty() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    let keys = backend.list_keys().expect("list keys");
    assert!(keys.is_empty(), "expected empty key list");
}

#[test]
fn relative_home_rejected_without_override() {
    let _home = set_home(std::path::Path::new("relative-home"));
    let backend = NativeBackend::new(PqcPolicy::Required);
    let err = backend
        .list_keys()
        .expect_err("expected relative home error");
    assert!(
        err.to_string()
            .contains("QPGP_HOME must be an absolute path"),
        "unexpected error: {err}"
    );
}

#[test]
fn relative_home_allowed_with_override() {
    // Allowing a relative home is insecure; only used in tests.
    let backend = NativeBackend::from_home(
        std::path::Path::new("relative-home-allow").to_path_buf(),
        PqcPolicy::Required,
        true,
    );
    let keys = backend.list_keys().expect("list keys");
    assert!(keys.is_empty(), "expected empty key list");
}

#[test]
fn import_empty_bytes_rejected() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    let err = backend
        .import_key(ImportRequest {
            bytes: Vec::new(),
            allow_unprotected: false,
        })
        .expect_err("expected import error");
    assert!(
        err.to_string().contains("no certificates found"),
        "unexpected error: {err}"
    );
}

#[test]
fn export_missing_key_fails() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    let err = backend
        .export_key(
            &KeyId("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_string()),
            false,
            false,
        )
        .expect_err("expected missing key error");
    assert!(
        err.to_string().contains("key not found"),
        "unexpected error: {err}"
    );
}

#[test]
fn export_secret_requires_secret_key() {
    let public;
    let key_id;
    {
        let _home = set_temp_home();
        let backend = NativeBackend::new(PqcPolicy::Required);
        if !require_pqc(backend.supports_pqc()) {
            return;
        }
        let meta = backend
            .generate_key(KeyGenParams {
                user_id: UserId("PublicOnly <public@example.com>".to_string()),
                algo: None,
                pqc_policy: PqcPolicy::Required,
                pqc_level: PqcLevel::Baseline,
                passphrase: None,
                allow_unprotected: true,
            })
            .expect("keygen");
        key_id = meta.key_id.clone();
        public = backend
            .export_key(&meta.key_id, false, false)
            .expect("export public");
    }

    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }
    backend
        .import_key(ImportRequest {
            bytes: public,
            allow_unprotected: false,
        })
        .expect("import public");
    let err = backend
        .export_key(&key_id, true, false)
        .expect_err("expected secret missing");
    assert!(
        err.to_string().contains("secret key not available"),
        "unexpected error: {err}"
    );
}

#[test]
fn partial_id_lists_matches() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let _ = backend
        .generate_key(KeyGenParams {
            user_id: UserId("MatchOne <match@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let _ = backend
        .generate_key(KeyGenParams {
            user_id: UserId("MatchTwo <match@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let err = backend
        .sign(SignRequest {
            signer: KeyId("Match".to_string()),
            message: b"test".to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect_err("expected partial id error");
    let message = err.to_string();
    assert!(
        message.contains("full fingerprint required; matches:"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("MatchOne") && message.contains("MatchTwo"),
        "expected matches list: {message}"
    );
}

#[test]
fn pqc_roundtrip_import_export() {
    let (secret, public, key_id) = {
        let _home = set_temp_home();
        let backend = NativeBackend::new(PqcPolicy::Required);
        if !require_pqc(backend.supports_pqc()) {
            return;
        }

        let meta = backend
            .generate_key(KeyGenParams {
                user_id: UserId("Roundtrip <rt@example.com>".to_string()),
                algo: None,
                pqc_policy: PqcPolicy::Required,
                pqc_level: PqcLevel::Baseline,
                passphrase: None,
                allow_unprotected: true,
            })
            .expect("keygen");

        let secret = backend
            .export_key(&meta.key_id, true, false)
            .expect("export secret");
        let public = backend
            .export_key(&meta.key_id, false, false)
            .expect("export public");
        (secret, public, meta.key_id)
    };

    let _home2 = set_temp_home();
    let backend2 = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend2.supports_pqc()) {
        return;
    }
    backend2
        .import_key(ImportRequest {
            bytes: secret,
            allow_unprotected: true,
        })
        .expect("import secret");
    backend2
        .import_key(ImportRequest {
            bytes: public,
            allow_unprotected: false,
        })
        .expect("import public");

    let msg = b"roundtrip message";
    let sig = backend2
        .sign(SignRequest {
            signer: key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");
    let verify = backend2
        .verify(VerifyRequest {
            message: msg.to_vec(),
            signature: sig,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");
    assert!(verify.valid, "signature did not verify");
    assert!(
        verify.signer.is_some(),
        "expected signer fingerprint in verify result"
    );

    let enc = backend2
        .encrypt(EncryptRequest {
            recipients: vec![key_id],
            plaintext: msg.to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");
    let dec = backend2
        .decrypt(DecryptRequest {
            ciphertext: enc,
            pqc_policy: PqcPolicy::Required,
            allow_revoked_keys: false,
        })
        .expect("decrypt");
    assert_eq!(dec, msg);
}

#[test]
fn cleartext_sign_verify_roundtrip() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Cleartext <clear@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let msg = b"cleartext message\nsecond line";
    let signed = backend
        .sign(SignRequest {
            signer: meta.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: true,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("clearsign");
    let signed_text = String::from_utf8_lossy(&signed);
    assert!(
        signed_text.contains("BEGIN PGP SIGNED MESSAGE"),
        "expected cleartext armor header"
    );

    let result = backend
        .verify(VerifyRequest {
            message: Vec::new(),
            signature: signed,
            cleartext: true,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");

    assert!(result.valid, "cleartext signature invalid");
    let verified = result.message.expect("missing cleartext message");
    let verified_text = String::from_utf8_lossy(&verified);
    assert!(
        verified_text.contains("cleartext message"),
        "cleartext message content missing"
    );
}

#[test]
fn cleartext_sign_verify_allows_signature_delimiter_in_body() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Cleartext Delim <delim@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    // This line begins with '-', so cleartext signing will dash-escape it in the body (RFC 4880/9580).
    // Previously, our naive substring search would treat that escaped line as the start of the
    // signature armor block, causing a policy failure (DoS).
    let msg = b"hello\n-----BEGIN PGP SIGNATURE-----\nworld";
    let signed = backend
        .sign(SignRequest {
            signer: meta.key_id,
            message: msg.to_vec(),
            armor: false,
            cleartext: true,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("clearsign");

    let result = backend
        .verify(VerifyRequest {
            message: Vec::new(),
            signature: signed,
            cleartext: true,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");

    assert!(result.valid, "cleartext signature invalid");
}

#[test]
fn cleartext_verify_requires_signature_block() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let err = backend
        .verify(VerifyRequest {
            message: Vec::new(),
            signature: b"not a cleartext signature".to_vec(),
            cleartext: true,
            pqc_policy: PqcPolicy::Required,
        })
        .expect_err("expected cleartext block error");
    assert!(
        err.to_string()
            .contains("cleartext signature block not found"),
        "unexpected error: {err}"
    );
}

#[test]
fn encrypt_requires_recipients() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }
    let result = backend.encrypt(EncryptRequest {
        recipients: Vec::new(),
        plaintext: b"no recipients".to_vec(),
        armor: false,
        pqc_policy: PqcPolicy::Required,
        compat: false,
    });
    assert!(result.is_err(), "expected recipient error");
}

#[test]
fn short_key_id_rejected_for_signing() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Short Key <short@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let short = meta.key_id.0.chars().take(16).collect::<String>();
    let err = backend
        .sign(SignRequest {
            signer: KeyId(short),
            message: b"test".to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect_err("expected short key id to be rejected");
    assert!(
        err.to_string().contains("full fingerprint required"),
        "unexpected error: {err}"
    );
}

#[test]
fn non_required_policy_rejected() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Disabled);

    let result = backend.generate_key(KeyGenParams {
        user_id: UserId("No Classic <classic@example.com>".to_string()),
        algo: None,
        pqc_policy: PqcPolicy::Disabled,
        pqc_level: PqcLevel::Baseline,
        passphrase: None,
        allow_unprotected: true,
    });
    assert!(result.is_err(), "expected non-required policy to fail");
}

#[test]
fn non_pqc_import_rejected() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);

    let classic = generate_classic_cert_bytes("Classic Import <classic-import@example.com>");
    let result = backend.import_key(ImportRequest {
        bytes: classic,
        allow_unprotected: false,
    });
    assert!(result.is_err(), "expected non-PQC import to fail");
}

#[test]
fn compat_rejected_when_pqc_required() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Compat Reject <compat-reject@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let result = backend.encrypt(EncryptRequest {
        recipients: vec![meta.key_id],
        plaintext: b"compat test".to_vec(),
        armor: false,
        pqc_policy: PqcPolicy::Required,
        compat: true,
    });
    assert!(result.is_err(), "expected compat to be rejected");
}

#[test]
fn armored_sign_and_verify() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Armor Sign <armor-sign@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let msg = b"armored sign message";
    let sig = backend
        .sign(SignRequest {
            signer: meta.key_id.clone(),
            message: msg.to_vec(),
            armor: true,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");
    let sig_text = String::from_utf8_lossy(&sig);
    assert!(
        sig_text.contains("BEGIN PGP SIGNATURE"),
        "expected armored signature header"
    );

    let result = backend
        .verify(VerifyRequest {
            message: msg.to_vec(),
            signature: sig,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");
    assert!(result.valid, "armored signature did not verify");
    assert!(result.signer.is_some(), "expected signer fingerprint");
}

#[test]
fn armored_encrypt_decrypt_roundtrip() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Armor Enc <armor-enc@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let msg = b"armored encrypt message";
    let ciphertext = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id],
            plaintext: msg.to_vec(),
            armor: true,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");
    let cipher_text = String::from_utf8_lossy(&ciphertext);
    assert!(
        cipher_text.contains("BEGIN PGP MESSAGE"),
        "expected armored message header"
    );

    let plaintext = backend
        .decrypt(DecryptRequest {
            ciphertext,
            pqc_policy: PqcPolicy::Required,
            allow_revoked_keys: false,
        })
        .expect("decrypt");
    assert_eq!(plaintext, msg);
}

#[test]
fn export_secret_armor_contains_header() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Armor Secret <armor-secret@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let secret = backend
        .export_key(&meta.key_id, true, true)
        .expect("export secret armor");
    let text = String::from_utf8_lossy(&secret);
    assert!(
        text.contains("BEGIN PGP PRIVATE KEY BLOCK") || text.contains("BEGIN PGP SECRET KEY BLOCK"),
        "expected armored secret key block"
    );
}

#[test]
fn native_passphrase_encrypts_secret_keys() {
    let _home = set_temp_home();
    let passphrase = "correct horse battery staple";
    let backend = NativeBackend::with_passphrase(PqcPolicy::Required, Some(passphrase.to_string()));
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Passphrase <pw@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: Some(passphrase.to_string()),
            allow_unprotected: false,
        })
        .expect("keygen");

    let secret = backend
        .export_key(&meta.key_id, true, false)
        .expect("export secret");
    {
        use openpgp::parse::Parse;
        use sequoia_openpgp as openpgp;
        let cert = openpgp::Cert::from_bytes(&secret).expect("parse secret cert");
        let has_encrypted = cert
            .keys()
            .secret()
            .any(|key| key.key().secret().is_encrypted());
        assert!(has_encrypted, "secret key material should be encrypted");
    }

    let msg = b"passphrase sign test";
    let sig = backend
        .sign(SignRequest {
            signer: meta.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");

    let result = backend.verify(VerifyRequest {
        message: msg.to_vec(),
        signature: sig,
        cleartext: false,
        pqc_policy: PqcPolicy::Required,
    });
    assert!(result.expect("verify").valid, "signature did not verify");

    let backend_no_pass = NativeBackend::new(PqcPolicy::Required);
    let sign_without = backend_no_pass.sign(SignRequest {
        signer: meta.key_id,
        message: msg.to_vec(),
        armor: false,
        cleartext: false,
        pqc_policy: PqcPolicy::Required,
    });
    assert!(sign_without.is_err(), "expected passphrase error");
}

#[test]
fn decrypt_requires_passphrase_for_encrypted_secret() {
    let _home = set_temp_home();
    let passphrase = "passphrase";
    let backend = NativeBackend::with_passphrase(PqcPolicy::Required, Some(passphrase.to_string()));
    if !require_pqc(backend.supports_pqc()) {
        return;
    }
    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Decrypt Pass <decrypt-pass@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: Some(passphrase.to_string()),
            allow_unprotected: false,
        })
        .expect("keygen");

    let ciphertext = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id],
            plaintext: b"secret message".to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");

    let backend_no_pass = NativeBackend::new(PqcPolicy::Required);
    let err = backend_no_pass
        .decrypt(DecryptRequest {
            ciphertext,
            pqc_policy: PqcPolicy::Required,
            allow_revoked_keys: false,
        })
        .expect_err("expected passphrase error");
    assert!(
        err.to_string().contains("passphrase required"),
        "unexpected error: {err}"
    );
}

#[test]
fn keygen_requires_passphrase_by_default() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let result = backend.generate_key(KeyGenParams {
        user_id: UserId("NoPass <nopass@example.com>".to_string()),
        algo: None,
        pqc_policy: PqcPolicy::Required,
        pqc_level: PqcLevel::Baseline,
        passphrase: None,
        allow_unprotected: false,
    });
    assert!(result.is_err(), "expected keygen to require passphrase");
}

#[test]
fn pqc_import_rejects_corrupt_cert() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Corrupt <corrupt@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let public = backend
        .export_key(&meta.key_id, false, false)
        .expect("export public");

    let mut corrupted = public.clone();
    if !corrupted.is_empty() {
        let idx = corrupted.len() / 2;
        corrupted[idx] ^= 0xFF;
    }

    let result = backend.import_key(ImportRequest {
        bytes: corrupted,
        allow_unprotected: false,
    });
    assert!(result.is_err(), "expected corrupt cert to be rejected");
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Tamper <tamper@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let ciphertext = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id],
            plaintext: b"tamper test".to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");

    let mut tampered = ciphertext.clone();
    if let Some(byte) = tampered.last_mut() {
        *byte ^= 0xFF;
    }

    let result = backend.decrypt(DecryptRequest {
        ciphertext: tampered,
        pqc_policy: PqcPolicy::Required,
        allow_revoked_keys: false,
    });
    assert!(result.is_err(), "expected tampered ciphertext to fail");
}

#[test]
fn decrypt_rejects_wrong_key() {
    let (public_a, key_a_id) = {
        let _home = set_temp_home();
        let backend_a = NativeBackend::new(PqcPolicy::Required);
        if !require_pqc(backend_a.supports_pqc()) {
            return;
        }

        let key_a = backend_a
            .generate_key(KeyGenParams {
                user_id: UserId("KeyA <a@example.com>".to_string()),
                algo: None,
                pqc_policy: PqcPolicy::Required,
                pqc_level: PqcLevel::Baseline,
                passphrase: None,
                allow_unprotected: true,
            })
            .expect("keygen A");

        let public_a = backend_a
            .export_key(&key_a.key_id, false, false)
            .expect("export A");
        (public_a, key_a.key_id)
    };

    let _home2 = set_temp_home();
    let backend_b = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend_b.supports_pqc()) {
        return;
    }

    let _key_b = backend_b
        .generate_key(KeyGenParams {
            user_id: UserId("KeyB <b@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen B");

    backend_b
        .import_key(ImportRequest {
            bytes: public_a,
            allow_unprotected: false,
        })
        .expect("import A public");

    let ciphertext = backend_b
        .encrypt(EncryptRequest {
            recipients: vec![key_a_id],
            plaintext: b"wrong key test".to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
            compat: false,
        })
        .expect("encrypt");

    let result = backend_b.decrypt(DecryptRequest {
        ciphertext,
        pqc_policy: PqcPolicy::Required,
        allow_revoked_keys: false,
    });
    assert!(result.is_err(), "expected wrong key decrypt to fail");
}

#[test]
fn verify_rejects_modified_message() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Verify <verify@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let msg = b"original";
    let sig = backend
        .sign(SignRequest {
            signer: meta.key_id,
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");

    let result = backend.verify(VerifyRequest {
        message: b"modified".to_vec(),
        signature: sig,
        cleartext: false,
        pqc_policy: PqcPolicy::Required,
    });
    let result = result.expect("verify");
    assert!(!result.valid, "expected invalid signature");
    assert!(
        result.signer.is_none(),
        "invalid signature should not report signer"
    );
}

#[test]
fn verify_is_not_jammed_by_extra_valid_signature() {
    // If multiple good detached signatures are present (OpenPGP allows this),
    // verification should still succeed. The caller/CLI can then enforce an
    // expected signer fingerprint without being vulnerable to "bypass-by-DoS".
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let a = backend
        .generate_key(KeyGenParams {
            user_id: UserId("SignerA <a@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen A");
    let b = backend
        .generate_key(KeyGenParams {
            user_id: UserId("SignerB <b@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen B");

    let msg = b"detached signature jamming test";
    let sig_a = backend
        .sign(SignRequest {
            signer: a.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign A");
    let sig_b = backend
        .sign(SignRequest {
            signer: b.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign B");

    // Attacker appends their own valid signature packet(s).
    let mut combined = sig_a.clone();
    combined.extend_from_slice(&sig_b);

    let result = backend
        .verify(VerifyRequest {
            message: msg.to_vec(),
            signature: combined,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");
    assert!(result.valid, "expected verification to succeed");
    assert!(
        result.signers.iter().any(|s| s.0 == a.key_id.0),
        "expected legitimate signer to be present"
    );
    assert!(
        result.signers.iter().any(|s| s.0 == b.key_id.0),
        "expected extra signer to be present"
    );
    assert!(
        result.signer.is_none(),
        "expected signer=None when multiple good signers exist"
    );
}

#[test]
fn verify_is_not_jammed_by_extra_invalid_signature() {
    // If a detached signature blob contains at least one good signature, an attacker
    // should not be able to force verification failure by appending a bad signature.
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let a = backend
        .generate_key(KeyGenParams {
            user_id: UserId("SignerA <a@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen A");
    let b = backend
        .generate_key(KeyGenParams {
            user_id: UserId("SignerB <b@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen B");

    let msg = b"detached signature jamming test (invalid)";
    let sig_a = backend
        .sign(SignRequest {
            signer: a.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign A");
    let mut sig_b = backend
        .sign(SignRequest {
            signer: b.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign B");

    // Corrupt B's signature while keeping the packet parseable.
    if let Some(last) = sig_b.last_mut() {
        *last ^= 0x01;
    }

    let mut combined = sig_a.clone();
    combined.extend_from_slice(&sig_b);

    let result = backend
        .verify(VerifyRequest {
            message: msg.to_vec(),
            signature: combined,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");
    assert!(result.valid, "expected verification to succeed");
    assert!(
        result.signers.iter().any(|s| s.0 == a.key_id.0),
        "expected legitimate signer to be present"
    );
    assert!(
        !result.signers.iter().any(|s| s.0 == b.key_id.0),
        "expected corrupted signer to be absent"
    );
    assert_eq!(
        result.signer.as_ref().map(|s| s.0.as_str()),
        Some(a.key_id.0.as_str()),
        "expected signer=SignerA when exactly one good signer exists"
    );
}

#[test]
fn export_armor_contains_header() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Armor Export <armor-export@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: None,
            allow_unprotected: true,
        })
        .expect("keygen");

    let public = backend
        .export_key(&meta.key_id, false, true)
        .expect("export armor");
    let text = String::from_utf8_lossy(&public);
    assert!(
        text.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "expected armored public key block"
    );
}

#[test]
fn decrypt_rejects_invalid_ciphertext() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }
    let err = backend
        .decrypt(DecryptRequest {
            ciphertext: b"not an openpgp message".to_vec(),
            pqc_policy: PqcPolicy::Required,
            allow_revoked_keys: false,
        })
        .expect_err("expected parse error");
    assert!(
        err.to_string().contains("parse output failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn sign_with_wrong_passphrase_fails() {
    let _home = set_temp_home();
    let backend = NativeBackend::with_passphrase(PqcPolicy::Required, Some("correct".to_string()));
    if !require_pqc(backend.supports_pqc()) {
        return;
    }
    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Wrong Pass <wrong-pass@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Required,
            pqc_level: PqcLevel::Baseline,
            passphrase: Some("correct".to_string()),
            allow_unprotected: false,
        })
        .expect("keygen");

    let backend_wrong =
        NativeBackend::with_passphrase(PqcPolicy::Required, Some("wrong".to_string()));
    let err = backend_wrong
        .sign(SignRequest {
            signer: meta.key_id,
            message: b"bad passphrase".to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect_err("expected passphrase error");
    assert!(
        err.to_string().contains("key decrypt failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn empty_key_id_rejected() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !require_pqc(backend.supports_pqc()) {
        return;
    }
    let err = backend
        .sign(SignRequest {
            signer: KeyId("".to_string()),
            message: b"empty id".to_vec(),
            armor: false,
            cleartext: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect_err("expected empty id error");
    assert!(
        err.to_string().contains("empty key id"),
        "unexpected error: {err}"
    );
}
