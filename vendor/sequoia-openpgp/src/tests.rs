//! Test data for Sequoia.
//!
//! This module includes the test data from `openpgp/tests/data` in a
//! structured way.

use std::fmt;
use std::collections::BTreeMap;

use crate::PublicKeyAlgorithm;

pub struct Test {
    path: &'static str,
    pub bytes: &'static [u8],
}

impl fmt::Display for Test {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "openpgp/tests/data/{}", self.path)
    }
}

macro_rules! t {
    ( $path: expr ) => {
        &Test {
            path: $path,
            bytes: include_bytes!(concat!("../tests/data/", $path)),
        }
    }
}

pub const CERTS: &[&Test] = &[
    t!("keys/dennis-simon-anton.pgp"),
    t!("keys/dsa2048-elgamal3072.pgp"),
    t!("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp384.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp521.pgp"),
    t!("keys/testy-new.pgp"),
    t!("keys/testy.pgp"),
    t!("keys/neal.pgp"),
    t!("keys/dkg-sigs-out-of-order.pgp"),
];

pub const TSKS: &[&Test] = &[
    t!("keys/dennis-simon-anton-private.pgp"),
    t!("keys/dsa2048-elgamal3072-private.pgp"),
    t!("keys/emmelie-dorothea-dina-samantha-awina-ed25519-private.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp384-private.pgp"),
    t!("keys/erika-corinna-daniela-simone-antonia-nistp521-private.pgp"),
    t!("keys/testy-new-private.pgp"),
    t!("keys/testy-nistp256-private.pgp"),
    t!("keys/testy-nistp384-private.pgp"),
    t!("keys/testy-nistp521-private.pgp"),
    t!("keys/testy-private.pgp"),
];

pub const PQC_CERT_PAIRS: &[(PublicKeyAlgorithm, &str, &str)] = &[
    //
    // artifacts/ test vectors from ietf draft
    //
    (PublicKeyAlgorithm::MLDSA65_Ed25519,
    "pqc/ietf/v6-mldsa-65-sample-pk.pgp",
    "pqc/ietf/v6-mldsa-65-sample-sk.pgp"
    ),
    (PublicKeyAlgorithm::MLDSA87_Ed448,
    "pqc/ietf/v6-mldsa-87-sample-pk.pgp",
    "pqc/ietf/v6-mldsa-87-sample-sk.pgp"
    ),
    (PublicKeyAlgorithm::SLHDSA128s,
    "pqc/ietf/v6-slhdsa-128s-sample-pk.pgp",
    "pqc/ietf/v6-slhdsa-128s-sample-sk.pgp"
    ),
    (PublicKeyAlgorithm::SLHDSA128f,
    "pqc/ietf/v6-slhdsa-128f-sample-pk.pgp",
    "pqc/ietf/v6-slhdsa-128f-sample-sk.pgp"
    ),
    (PublicKeyAlgorithm::SLHDSA256s,
    "pqc/ietf/v6-slhdsa-256s-sample-pk.pgp",
    "pqc/ietf/v6-slhdsa-256s-sample-sk.pgp"
    ),
    (PublicKeyAlgorithm::Ed25519,
    "pqc/ietf/v4-eddsa-sample-pk.pgp",
    "pqc/ietf/v4-eddsa-sample-sk.pgp"
    ),
    //
    // rpgp artifacts
    //
    (PublicKeyAlgorithm::Ed25519,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v4-ed25519-mlkem768x25519_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v4-ed25519-mlkem768x25519_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::Ed25519,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-ed25519-mlkem768x25519_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-ed25519-mlkem768x25519_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::MLDSA65_Ed25519,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-mldsa65ed25519-mlkem768x25519_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-mldsa65ed25519-mlkem768x25519_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::MLDSA87_Ed448,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-mldsa87ed448-mlkem1024x448_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-mldsa87ed448-mlkem1024x448_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::SLHDSA128f,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-slhdsashake128f-mlkem768x25519_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-slhdsashake128f-mlkem768x25519_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::SLHDSA128s,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-slhdsashake128s-mlkem768x25519_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-slhdsashake128s-mlkem768x25519_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::SLHDSA256s,
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-slhdsashake256s-mlkem1024x448_alice_pk.pgp",
    "pqc/rpgp/rsop_draft-ietf-openpgp-pqc-08-v6-slhdsashake256s-mlkem1024x448_alice_sk.pgp"
    ),
    //
    // gopenpgp artifacts
    //
    (PublicKeyAlgorithm::MLDSA65_Ed25519,
    "pqc/gopenpgp/gosop_draft-ietf-openpgp-pqc-09_alice_pk.pgp",
    "pqc/gopenpgp/gosop_draft-ietf-openpgp-pqc-09_alice_sk.pgp"
    ),
    (PublicKeyAlgorithm::MLDSA87_Ed448,
    "pqc/gopenpgp/gosop_draft-ietf-openpgp-pqc-09-high-security_alice_pk.pgp",
    "pqc/gopenpgp/gosop_draft-ietf-openpgp-pqc-09-high-security_alice_sk.pgp"
    ),
];

/// Returns the content of the given file below `openpgp/tests/data`.
pub fn file(name: &str) -> &'static [u8] {
    use std::sync::OnceLock;

    static FILES: OnceLock<BTreeMap<&'static str, &'static [u8]>>
        = OnceLock::new();
    FILES.get_or_init(|| {
        let mut m: BTreeMap<&'static str, &'static [u8]> =
            Default::default();

        macro_rules! add {
            ( $key: expr, $path: expr ) => {
                m.insert($key, include_bytes!($path))
            }
        }
        include!(concat!(env!("OUT_DIR"), "/tests.index.rs.inc"));

        // Sanity checks.
        assert!(m.contains_key("messages/a-cypherpunks-manifesto.txt"));
        assert!(m.contains_key("keys/testy.pgp"));
        assert!(m.contains_key("keys/testy-private.pgp"));
        m
    }).get(name).unwrap_or_else(|| panic!("No such file {:?}", name))
}

/// Returns the content of the given file below `openpgp/tests/data/keys`.
pub fn key(name: &str) -> &'static [u8] {
    file(&format!("keys/{}", name))
}

/// Returns the content of the given file below `openpgp/tests/data/messages`.
pub fn message(name: &str) -> &'static [u8] {
    file(&format!("messages/{}", name))
}

/// Returns the cypherpunks manifesto.
pub fn manifesto() -> &'static [u8] {
    message("a-cypherpunks-manifesto.txt")
}
