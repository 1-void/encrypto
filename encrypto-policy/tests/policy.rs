use encrypto_policy::{
    is_pqc_kem_algo, is_pqc_sign_algo, pqc_kem_key_version_ok, pqc_sign_key_version_ok,
};
use sequoia_openpgp::types::PublicKeyAlgorithm;

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

    assert!(pqc_kem_key_version_ok(PublicKeyAlgorithm::MLKEM768_X25519, 4));
    assert!(!pqc_kem_key_version_ok(PublicKeyAlgorithm::MLKEM768_X25519, 3));

    assert!(pqc_kem_key_version_ok(PublicKeyAlgorithm::MLKEM1024_X448, 6));
    assert!(!pqc_kem_key_version_ok(PublicKeyAlgorithm::MLKEM1024_X448, 5));
}
