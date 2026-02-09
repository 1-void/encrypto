use qpgp_policy::{
    cert_has_pqc_encryption_key, cert_has_pqc_signing_key, cert_is_pqc_only,
    ensure_pqc_encryption_has_pqc, ensure_pqc_encryption_output, ensure_pqc_signature_output,
    hash_is_pqc_ok, is_pqc_kem_algo, is_pqc_sign_algo, pqc_kem_key_version_ok,
    pqc_sign_key_version_ok,
};
use sequoia_openpgp as openpgp;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient, Signer};
use sequoia_openpgp::types::{
    AEADAlgorithm, Features, HashAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm,
};
use std::io::Write;

#[test]
fn pqc_algo_identification() {
    assert!(is_pqc_sign_algo(PublicKeyAlgorithm::MLDSA65_Ed25519));
    assert!(is_pqc_sign_algo(PublicKeyAlgorithm::MLDSA87_Ed448));
    assert!(is_pqc_sign_algo(PublicKeyAlgorithm::SLHDSA128s));
    assert!(!is_pqc_sign_algo(PublicKeyAlgorithm::Ed25519));

    assert!(is_pqc_kem_algo(PublicKeyAlgorithm::MLKEM768_X25519));
    assert!(is_pqc_kem_algo(PublicKeyAlgorithm::MLKEM1024_X448));
    assert!(!is_pqc_kem_algo(PublicKeyAlgorithm::X25519));
}

#[test]
fn pqc_key_version_rules() {
    assert!(pqc_sign_key_version_ok(6));
    assert!(!pqc_sign_key_version_ok(5));

    assert!(pqc_kem_key_version_ok(
        PublicKeyAlgorithm::MLKEM768_X25519,
        4
    ));
    assert!(!pqc_kem_key_version_ok(
        PublicKeyAlgorithm::MLKEM768_X25519,
        3
    ));

    assert!(pqc_kem_key_version_ok(
        PublicKeyAlgorithm::MLKEM1024_X448,
        6
    ));
    assert!(!pqc_kem_key_version_ok(
        PublicKeyAlgorithm::MLKEM1024_X448,
        5
    ));
}

#[test]
fn kem_v4_exception_is_key_version_only() {
    // The PQC draft allows ML-KEM-768+X25519 (algorithm 35) in v4 encryption subkeys for
    // interop. This is strictly a *key version* exception; it does not imply PKESK v3 is
    // acceptable with SEIP v2.
    assert!(
        pqc_kem_key_version_ok(PublicKeyAlgorithm::MLKEM768_X25519, 4),
        "algo 35 should be accepted at v4"
    );
    assert!(
        !pqc_kem_key_version_ok(PublicKeyAlgorithm::MLKEM1024_X448, 4),
        "algo 38 should not be accepted at v4"
    );
}

fn pqc_available() -> bool {
    CipherSuite::MLDSA65_Ed25519.is_supported().is_ok()
}

fn classic_available() -> bool {
    CipherSuite::Cv25519.is_supported().is_ok()
}

fn generate_pqc_cert() -> openpgp::Result<openpgp::Cert> {
    let (cert, _rev) = CertBuilder::general_purpose(Some("Policy Test <policy@example.com>"))
        .set_profile(openpgp::Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .generate()?;
    Ok(cert)
}

fn generate_classic_cert() -> openpgp::Result<openpgp::Cert> {
    let (cert, _rev) = CertBuilder::general_purpose(Some("Classic <classic@example.com>"))
        .set_profile(openpgp::Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::Cv25519)
        .generate()?;
    Ok(cert)
}

fn encrypt_with_features(
    cert: &openpgp::Cert,
    features: Features,
    force_aead: bool,
) -> openpgp::Result<Vec<u8>> {
    encrypt_with_params(
        cert,
        features,
        SymmetricAlgorithm::AES256,
        force_aead.then_some(AEADAlgorithm::OCB),
    )
}

fn encrypt_with_params(
    cert: &openpgp::Cert,
    features: Features,
    sym: SymmetricAlgorithm,
    aead: Option<AEADAlgorithm>,
) -> openpgp::Result<Vec<u8>> {
    let p = &StandardPolicy::new();
    let recipients = cert
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .map(|ka| Recipient::new(features.clone(), None::<KeyHandle>, ka.key()));

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut encryptor = Encryptor::for_recipients(message, recipients).symmetric_algo(sym);
    if let Some(aead) = aead {
        encryptor = encryptor.aead_algo(aead);
    }
    let message = encryptor.build()?;
    let mut writer = LiteralWriter::new(message).build()?;
    writer.write_all(b"policy test")?;
    writer.finalize()?;
    Ok(sink)
}

fn sign_detached(cert: &openpgp::Cert, msg: &[u8]) -> openpgp::Result<Vec<u8>> {
    let p = &StandardPolicy::new();
    let key = cert
        .keys()
        .secret()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or_else(|| openpgp::Error::InvalidOperation("no signing key".into()))?;
    let keypair = key.key().clone().into_keypair()?;

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut signer = Signer::new(message, keypair)?.detached().build()?;
    signer.write_all(msg)?;
    signer.finalize()?;
    Ok(sink)
}

#[test]
fn policy_rejects_seipv1_encryption() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let ciphertext = encrypt_with_features(&cert, Features::empty(), false).expect("encrypt");
    let result = ensure_pqc_encryption_output(&ciphertext);
    assert!(result.is_err(), "expected SEIP v1 to be rejected");
}

#[test]
fn policy_accepts_aead_encryption() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let ciphertext = encrypt_with_features(&cert, Features::sequoia(), true).expect("encrypt");
    ensure_pqc_encryption_output(&ciphertext).expect("expected AEAD encryption to pass");
}

#[test]
fn policy_rejects_pkesk_v3_with_seipv2() {
    use sequoia_openpgp::crypto::SessionKey;
    use sequoia_openpgp::packet::pkesk::PKESK3;

    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");

    // Generate a syntactically valid SEIP v2 message (our policy requires AEAD).
    let ciphertext = encrypt_with_features(&cert, Features::sequoia(), true).expect("encrypt");

    // Construct a PKESK v3 packet (still parseable) and splice it in front of the SEIP v2
    // packet. The policy should reject this combination as spec-nonconformant.
    let p = &StandardPolicy::new();
    let recipient = cert
        .keys()
        .with_policy(p, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .next()
        .expect("recipient key");
    let sess_key = SessionKey::new(32).expect("session key");
    let pkesk3 = PKESK3::for_recipient(SymmetricAlgorithm::AES256, &sess_key, recipient.key())
        .expect("pkesk v3");

    let pile = openpgp::PacketPile::from_bytes(&ciphertext).expect("parse pile");
    let mut mutated = Vec::new();
    let mut replaced = false;
    for packet in pile.children() {
        if matches!(packet, openpgp::Packet::PKESK(_)) && !replaced {
            let packet: openpgp::Packet = pkesk3.clone().into();
            packet.serialize(&mut mutated).expect("serialize");
            replaced = true;
            continue;
        }
        packet.serialize(&mut mutated).expect("serialize");
    }
    if !replaced {
        // Some messages may not contain a PKESK (e.g., SKESK-only). That would make this test
        // meaningless.
        panic!("expected a PKESK packet in the AEAD ciphertext");
    }

    let err = ensure_pqc_encryption_output(&mutated).expect_err("expected v3+v2 rejection");
    assert!(
        err.to_string().contains("PKESK v3 is not allowed"),
        "unexpected: {err}"
    );
}

#[test]
fn policy_rejects_non_aes256_seipv2() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let ciphertext = encrypt_with_params(
        &cert,
        Features::sequoia(),
        SymmetricAlgorithm::AES128,
        Some(AEADAlgorithm::OCB),
    )
    .expect("encrypt");
    let err = ensure_pqc_encryption_output(&ciphertext).expect_err("expected non-AES256 rejection");
    assert!(err.to_string().contains("non-AES256"), "unexpected: {err}");
}

#[test]
fn policy_rejects_non_ocb_seipv2() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    // Some backends only support OCB for OpenPGP AEAD encryption. To exercise
    // the policy's "require OCB" rejection branch without relying on runtime
    // backend support for other AEAD modes, generate a valid OCB message and
    // then mutate the SEIP2 header to claim a different AEAD algorithm.
    let ciphertext = encrypt_with_params(
        &cert,
        Features::sequoia(),
        SymmetricAlgorithm::AES256,
        Some(AEADAlgorithm::OCB),
    )
    .expect("encrypt");

    let pile = openpgp::PacketPile::from_bytes(&ciphertext).expect("parse pile");
    let mut mutated = Vec::new();
    for packet in pile.children() {
        match packet {
            openpgp::Packet::SEIP(openpgp::packet::SEIP::V2(seip2)) => {
                let mut seip2 = seip2.clone();
                seip2.set_aead(AEADAlgorithm::EAX);
                let packet: openpgp::Packet = seip2.into();
                packet.serialize(&mut mutated).expect("serialize");
            }
            _ => packet.serialize(&mut mutated).expect("serialize"),
        }
    }

    let err = ensure_pqc_encryption_output(&mutated).expect_err("expected AEAD rejection");
    assert!(err.to_string().contains("require OCB"), "unexpected: {err}");
}

#[test]
fn policy_rejects_classic_pkesk() {
    if !classic_available() {
        return;
    }
    let cert = generate_classic_cert().expect("classic cert");
    let ciphertext = encrypt_with_features(&cert, Features::sequoia(), true).expect("encrypt");
    let err = ensure_pqc_encryption_output(&ciphertext).expect_err("expected PKESK rejection");
    assert!(
        err.to_string().contains("non-PQC recipient"),
        "unexpected: {err}"
    );
}

#[test]
fn policy_rejects_missing_pkesk() {
    // A non-encrypted literal message should be parseable, but contain no PKESKs.
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut writer = LiteralWriter::new(message).build().expect("literal writer");
    writer.write_all(b"not encrypted").expect("write");
    writer.finalize().expect("finalize");

    let err = ensure_pqc_encryption_output(&sink).expect_err("expected missing PKESK rejection");
    assert!(
        err.to_string().contains("no recipient packets"),
        "unexpected: {err}"
    );
}

#[test]
fn policy_rejects_missing_seip_packet() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let ciphertext = encrypt_with_features(&cert, Features::sequoia(), true).expect("encrypt");

    // Remove any SEIP packet from the top-level packet stream.
    let pile = openpgp::PacketPile::from_bytes(&ciphertext).expect("parse pile");
    let mut stripped = Vec::new();
    for packet in pile.children() {
        if matches!(packet, openpgp::Packet::SEIP(_)) {
            continue;
        }
        packet.serialize(&mut stripped).expect("serialize");
    }
    let err = ensure_pqc_encryption_output(&stripped).expect_err("expected missing SEIP rejection");
    assert!(
        err.to_string().contains("missing SEIP"),
        "unexpected: {err}"
    );
}

#[test]
fn policy_rejects_mdc_packet() {
    use sequoia_openpgp::packet::MDC;

    let mut bytes = Vec::new();
    let packet: openpgp::Packet = MDC::from([0u8; 20]).into();
    packet.serialize(&mut bytes).expect("serialize");

    let err = ensure_pqc_encryption_output(&bytes).expect_err("expected MDC rejection");
    assert!(err.to_string().contains("MDC"), "unexpected: {err}");
}

#[test]
fn policy_rejects_sed_and_aed_packets() {
    // Sequoia intentionally treats SED/AED as unsupported. We only need a
    // syntactically valid packet header so the parser yields a packet with
    // the corresponding tag.
    //
    // New-format CTB is 0b1100_0000 | tag, followed by a one-octet length.
    //
    // Note: Sequoia enforces a minimum length on SED packets (>= 16 bytes),
    // so we provide a trivially-sized body that still parses.
    let sed_min = [
        0xC0 | 9,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];
    let aed_min = [
        0xC0 | 20,
        0x10,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ];

    for bytes in [sed_min.as_slice(), aed_min.as_slice()] {
        let err = ensure_pqc_encryption_output(bytes).expect_err("expected rejection");
        assert!(
            err.to_string().contains("deprecated encrypted"),
            "unexpected: {err}"
        );
    }
}

#[test]
fn policy_accepts_multiple_signatures() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let sig1 = sign_detached(&cert, b"hello").expect("sign");
    let sig2 = sign_detached(&cert, b"hello").expect("sign");
    let mut combined = sig1.clone();
    combined.extend_from_slice(&sig2);
    let result = ensure_pqc_signature_output(&combined);
    assert!(
        result.is_ok(),
        "expected multiple PQC signatures to be accepted"
    );
}

#[test]
fn policy_accepts_pqc_signature_with_extra_classic_signature() {
    if !pqc_available() || !classic_available() {
        return;
    }
    let pqc = generate_pqc_cert().expect("pqc cert");
    let classic = generate_classic_cert().expect("classic cert");

    let pqc_sig = sign_detached(&pqc, b"hello").expect("pqc sign");
    let classic_sig = sign_detached(&classic, b"hello").expect("classic sign");

    let mut combined = pqc_sig.clone();
    combined.extend_from_slice(&classic_sig);
    ensure_pqc_signature_output(&combined).expect("expected PQC signature to be accepted");
}

#[test]
fn policy_accepts_single_signature() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let sig = sign_detached(&cert, b"hello").expect("sign");
    ensure_pqc_signature_output(&sig).expect("expected single signature to pass");
}

#[test]
fn hash_policy_allows_strong_hashes() {
    assert!(hash_is_pqc_ok(HashAlgorithm::SHA256));
    assert!(hash_is_pqc_ok(HashAlgorithm::SHA3_256));
    assert!(!hash_is_pqc_ok(HashAlgorithm::SHA1));
}

#[test]
fn cert_pqc_detection() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    assert!(cert_has_pqc_encryption_key(&cert));
    assert!(cert_has_pqc_signing_key(&cert));
    assert!(cert_is_pqc_only(&cert));
}

#[test]
fn cert_classic_detection() {
    if !classic_available() {
        return;
    }
    let cert = generate_classic_cert().expect("classic cert");
    assert!(!cert_has_pqc_encryption_key(&cert));
    assert!(!cert_has_pqc_signing_key(&cert));
    assert!(!cert_is_pqc_only(&cert));
}

#[test]
fn policy_requires_pqc_recipient_packets() {
    if !pqc_available() {
        return;
    }
    let cert = generate_pqc_cert().expect("cert");
    let ciphertext = encrypt_with_features(&cert, Features::sequoia(), true).expect("encrypt");
    ensure_pqc_encryption_has_pqc(&ciphertext).expect("expected PQC recipient");

    if !classic_available() {
        return;
    }
    let classic = generate_classic_cert().expect("classic cert");
    let ciphertext =
        encrypt_with_features(&classic, Features::empty(), false).expect("classic encrypt");
    let result = ensure_pqc_encryption_has_pqc(&ciphertext);
    assert!(result.is_err(), "expected classic recipients to fail");
}

#[test]
fn policy_rejects_classic_signature() {
    if !classic_available() {
        return;
    }
    let cert = generate_classic_cert().expect("classic cert");
    let sig = sign_detached(&cert, b"classic").expect("sign");
    let result = ensure_pqc_signature_output(&sig);
    assert!(result.is_err(), "expected classic signature to fail");
}
