use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, KeyGenParams, PqcLevel, PqcPolicy, SignRequest,
    UserId, VerifyRequest,
};
use encrypto_pgp::NativeBackend;

fn set_temp_home() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    unsafe {
        std::env::set_var("ENCRYPTO_HOME", dir.path());
    }
    dir
}

fn assert_pqc_encryption(bytes: &[u8]) {
    use sequoia_openpgp as openpgp;
    use openpgp::{Packet, PacketPile};
    use openpgp::parse::Parse;
    use openpgp::types::PublicKeyAlgorithm;

    let pile = PacketPile::from_bytes(bytes).expect("parse encrypted output");
    let mut pkesk_count = 0usize;
    for packet in pile.descendants() {
        if let Packet::PKESK(pkesk) = packet {
            pkesk_count += 1;
            assert!(
                matches!(
                    pkesk.pk_algo(),
                    PublicKeyAlgorithm::MLKEM768_X25519
                        | PublicKeyAlgorithm::MLKEM1024_X448
                ),
                "non-PQC recipient packet found: {:?}",
                pkesk.pk_algo()
            );
        }
    }
    assert!(pkesk_count > 0, "no recipient packets found");
}

fn assert_pqc_signature(bytes: &[u8]) {
    use sequoia_openpgp as openpgp;
    use openpgp::{Packet, PacketPile};
    use openpgp::parse::Parse;
    use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};

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
        })
        .expect("keygen");

    let plaintext = b"pqc test";
    let encrypted = backend
        .encrypt(EncryptRequest {
            recipients: vec![meta.key_id.clone()],
            plaintext: plaintext.to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Required,
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
        })
        .expect("encrypt");
    let dec = backend2
        .decrypt(DecryptRequest { ciphertext: enc })
        .expect("decrypt");
    assert_eq!(dec, msg);
}

#[test]
fn classical_signature_rejected_when_pqc_required() {
    let _home = set_temp_home();
    let backend = NativeBackend::new(PqcPolicy::Disabled);

    let meta = backend
        .generate_key(KeyGenParams {
            user_id: UserId("Classic <classic@example.com>".to_string()),
            algo: None,
            pqc_policy: PqcPolicy::Disabled,
            pqc_level: PqcLevel::Baseline,
        })
        .expect("keygen");

    let msg = b"classic message";
    let sig = backend
        .sign(SignRequest {
            signer: meta.key_id,
            message: msg.to_vec(),
            armor: false,
            pqc_policy: PqcPolicy::Disabled,
        })
        .expect("sign");

    let required_backend = NativeBackend::new(PqcPolicy::Required);
    let result = required_backend.verify(VerifyRequest {
        message: msg.to_vec(),
        signature: sig,
        pqc_policy: PqcPolicy::Required,
    });
    assert!(result.is_err(), "expected PQC-required verify to fail");
}
