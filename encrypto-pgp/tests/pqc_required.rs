use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, KeyGenParams, PqcLevel, PqcPolicy, SignRequest,
    UserId, VerifyRequest,
};
use encrypto_pgp::NativeBackend;
use sequoia_openpgp::serialize::SerializeInto;

fn set_temp_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    unsafe {
        std::env::set_var("ENCRYPTO_HOME", dir.path());
    }
    dir
}

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
    use openpgp::cert::prelude::*;
    use openpgp::Profile;
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
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
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
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");
    assert_pqc_signature(&signature);
}

#[test]
fn pqc_roundtrip_import_export() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
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
        .export_key(&meta.key_id, true)
        .expect("export secret");
    let public = backend
        .export_key(&meta.key_id, false)
        .expect("export public");

    let _home2 = set_temp_home();
    let backend2 = NativeBackend::new(PqcPolicy::Required);
    if !backend2.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
        return;
    }
    backend2.import_key(&secret).expect("import secret");
    backend2.import_key(&public).expect("import public");

    let msg = b"roundtrip message";
    let sig = backend2
        .sign(SignRequest {
            signer: meta.key_id.clone(),
            message: msg.to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");
    let verify = backend2
        .verify(VerifyRequest {
            message: msg.to_vec(),
            signature: sig,
            pqc_policy: PqcPolicy::Required,
        })
        .expect("verify");
    assert!(verify.valid, "signature did not verify");

    let enc = backend2
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id],
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
        })
        .expect("decrypt");
    assert_eq!(dec, msg);
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
    let result = backend.import_key(&classic);
    assert!(result.is_err(), "expected non-PQC import to fail");
}

#[test]
fn compat_rejected_when_pqc_required() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
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
fn native_passphrase_encrypts_secret_keys() {
    let _home = set_temp_home();
    let passphrase = "correct horse battery staple";
    let backend = NativeBackend::with_passphrase(PqcPolicy::Required, Some(passphrase.to_string()));
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
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
        .export_key(&meta.key_id, true)
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
            pqc_policy: PqcPolicy::Required,
        })
        .expect("sign");

    let result = backend.verify(VerifyRequest {
        message: msg.to_vec(),
        signature: sig,
        pqc_policy: PqcPolicy::Required,
    });
    assert!(result.expect("verify").valid, "signature did not verify");

    let backend_no_pass = NativeBackend::new(PqcPolicy::Required);
    let sign_without = backend_no_pass.sign(SignRequest {
        signer: meta.key_id,
        message: msg.to_vec(),
        armor: false,
        pqc_policy: PqcPolicy::Required,
    });
    assert!(sign_without.is_err(), "expected passphrase error");
}

#[test]
fn keygen_requires_passphrase_by_default() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Required);
    if !backend.supports_pqc() {
        eprintln!("pqc not supported in this environment; skipping");
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
