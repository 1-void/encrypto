use openpgp::Cert;
use openpgp::Packet;
use openpgp::PacketPile;
use openpgp::packet::Tag;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm};
use sequoia_openpgp as openpgp;

#[derive(Debug)]
pub enum PolicyError {
    Parse(String),
    Violation(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Parse(msg) => write!(f, "policy parse error: {msg}"),
            PolicyError::Violation(msg) => write!(f, "policy violation: {msg}"),
        }
    }
}

impl std::error::Error for PolicyError {}

pub fn is_pqc_sign_algo(algo: PublicKeyAlgorithm) -> bool {
    matches!(
        algo,
        PublicKeyAlgorithm::MLDSA65_Ed25519
            | PublicKeyAlgorithm::MLDSA87_Ed448
            | PublicKeyAlgorithm::SLHDSA128s
            | PublicKeyAlgorithm::SLHDSA128f
            | PublicKeyAlgorithm::SLHDSA256s
    )
}

pub fn is_pqc_kem_algo(algo: PublicKeyAlgorithm) -> bool {
    matches!(
        algo,
        PublicKeyAlgorithm::MLKEM768_X25519 | PublicKeyAlgorithm::MLKEM1024_X448
    )
}

pub fn pqc_sign_key_version_ok(version: u8) -> bool {
    version >= 6
}

pub fn pqc_kem_key_version_ok(algo: PublicKeyAlgorithm, version: u8) -> bool {
    match algo {
        PublicKeyAlgorithm::MLKEM768_X25519 => version >= 4,
        PublicKeyAlgorithm::MLKEM1024_X448 => version >= 6,
        _ => false,
    }
}

pub fn hash_is_pqc_ok(hash: HashAlgorithm) -> bool {
    matches!(
        hash,
        HashAlgorithm::SHA256
            | HashAlgorithm::SHA384
            | HashAlgorithm::SHA512
            | HashAlgorithm::SHA3_256
            | HashAlgorithm::SHA3_512
    )
}

pub fn cert_has_pqc_encryption_key(cert: &Cert) -> bool {
    let policy = StandardPolicy::new();
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .any(|key| {
            let algo = key.key().pk_algo();
            let version = key.key().version();
            is_pqc_kem_algo(algo) && pqc_kem_key_version_ok(algo, version)
        })
}

pub fn cert_has_pqc_signing_key(cert: &Cert) -> bool {
    let policy = StandardPolicy::new();
    cert.keys()
        .with_policy(&policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_signing()
        .any(|key| {
            let algo = key.key().pk_algo();
            let version = key.key().version();
            is_pqc_sign_algo(algo) && pqc_sign_key_version_ok(version)
        })
}

pub fn cert_is_pqc_only(cert: &Cert) -> bool {
    let policy = StandardPolicy::new();
    for key in cert
        .keys()
        .with_policy(&policy, None)
        .alive()
        .revoked(false)
    {
        let algo = key.key().pk_algo();
        let version = key.key().version();
        if is_pqc_sign_algo(algo) {
            if !pqc_sign_key_version_ok(version) {
                return false;
            }
        } else if is_pqc_kem_algo(algo) {
            if !pqc_kem_key_version_ok(algo, version) {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

pub fn ensure_pqc_encryption_output(bytes: &[u8]) -> Result<(), PolicyError> {
    let pile = PacketPile::from_bytes(bytes)
        .map_err(|err| PolicyError::Parse(format!("parse output failed: {err}")))?;
    let mut pkesk_count = 0usize;
    let mut seip_count = 0usize;
    let mut seip_v2_count = 0usize;
    for packet in pile.descendants() {
        if let Packet::PKESK(pkesk) = packet {
            pkesk_count += 1;
            if !is_pqc_kem_algo(pkesk.pk_algo()) {
                return Err(PolicyError::Violation(format!(
                    "non-PQC recipient packet found: {:?}",
                    pkesk.pk_algo()
                )));
            }
        }
        if let Packet::SEIP(seip) = packet {
            seip_count += 1;
            if seip.version() == 2 {
                seip_v2_count += 1;
            } else {
                return Err(PolicyError::Violation(
                    "SEIP v1 is not allowed; require AEAD (SEIP v2)".to_string(),
                ));
            }
        }
        let tag = packet.tag();
        if tag == Tag::MDC {
            return Err(PolicyError::Violation(
                "deprecated MDC packet found".to_string(),
            ));
        }
        if matches!(tag, Tag::SED | Tag::AED) {
            return Err(PolicyError::Violation(format!(
                "deprecated encrypted packet found: {:?}",
                tag
            )));
        }
    }
    if pkesk_count == 0 {
        return Err(PolicyError::Violation(
            "no recipient packets found".to_string(),
        ));
    }
    if seip_count == 0 {
        return Err(PolicyError::Violation(
            "encrypted data is not integrity protected (missing SEIP packet)".to_string(),
        ));
    }
    if seip_v2_count == 0 {
        return Err(PolicyError::Violation(
            "AEAD is required (SEIP v2 missing)".to_string(),
        ));
    }
    Ok(())
}

pub fn ensure_pqc_encryption_has_pqc(bytes: &[u8]) -> Result<(), PolicyError> {
    let pile = PacketPile::from_bytes(bytes)
        .map_err(|err| PolicyError::Parse(format!("parse output failed: {err}")))?;
    let mut pqc_count = 0usize;
    for packet in pile.descendants() {
        if let Packet::PKESK(pkesk) = packet
            && is_pqc_kem_algo(pkesk.pk_algo())
        {
            pqc_count += 1;
        }
    }
    if pqc_count == 0 {
        return Err(PolicyError::Violation(
            "no PQC recipient packets found".to_string(),
        ));
    }
    Ok(())
}

pub fn ensure_pqc_signature_output(bytes: &[u8]) -> Result<(), PolicyError> {
    let pile = PacketPile::from_bytes(bytes)
        .map_err(|err| PolicyError::Parse(format!("parse output failed: {err}")))?;
    let mut sig_count = 0usize;
    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            sig_count += 1;
            let algo = sig.pk_algo();
            if !is_pqc_sign_algo(algo) {
                return Err(PolicyError::Violation(format!(
                    "non-PQC signature found: {:?}",
                    algo
                )));
            }
            if sig.version() < 6 {
                return Err(PolicyError::Violation(format!(
                    "signature version is v{}",
                    sig.version()
                )));
            }
            if !hash_is_pqc_ok(sig.hash_algo()) {
                return Err(PolicyError::Violation(format!(
                    "weak hash used: {:?}",
                    sig.hash_algo()
                )));
            }
        }
    }
    if sig_count == 0 {
        return Err(PolicyError::Violation("no signatures found".to_string()));
    }
    if sig_count > 1 {
        return Err(PolicyError::Violation(format!(
            "multiple signatures found ({sig_count}); expected exactly one"
        )));
    }
    Ok(())
}
