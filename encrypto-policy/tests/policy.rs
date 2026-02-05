use encrypto_policy::{
    ensure_pqc_encryption_output, ensure_pqc_signature_output, is_pqc_kem_algo, is_pqc_sign_algo,
    pqc_kem_key_version_ok, pqc_sign_key_version_ok,
};
use sequoia_openpgp as openpgp;
use sequoia_openpgp::KeyHandle;
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message, Recipient, Signer};
use sequoia_openpgp::types::{AEADAlgorithm, Features, PublicKeyAlgorithm};
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

fn pqc_available() -> bool {
    CipherSuite::MLDSA65_Ed25519.is_supported().is_ok()
}

fn generate_pqc_cert() -> openpgp::Result<openpgp::Cert> {
    let (cert, _rev) = CertBuilder::general_purpose(Some("Policy Test <policy@example.com>"))
        .set_profile(openpgp::Profile::RFC9580)?
        .set_cipher_suite(CipherSuite::MLDSA65_Ed25519)
        .generate()?;
    Ok(cert)
}

fn encrypt_with_features(
    cert: &openpgp::Cert,
    features: Features,
    force_aead: bool,
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
    let mut encryptor = Encryptor::for_recipients(message, recipients);
    if force_aead {
        encryptor = encryptor.aead_algo(AEADAlgorithm::default());
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
fn policy_rejects_multiple_signatures() {
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
        result.is_err(),
        "expected multiple signatures to be rejected"
    );
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
