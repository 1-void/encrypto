use crate::{Error, Result};

use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::backend::openssl::der;
use crate::crypto::mpi;
use crate::crypto::mpi::{ProtectedMPI, MPI};
use crate::crypto::mem::Protected;
use crate::crypto::SessionKey;
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{key, Key};
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use ossl::{
    pkey::{EccData, EvpPkey, EvpPkeyType, DsaData, MlkeyData, PkeyData, RsaData, SlhDsaKeyData},
    asymcipher::{EncAlg, EncOp, OsslAsymcipher},
    signature::{OsslSignature, SigAlg, SigOp},
};

use std::ffi::CStr;
const E: &CStr = unsafe { CStr::from_ptr(b"e\0".as_ptr() as *const _) };
const N: &CStr = unsafe { CStr::from_ptr(b"n\0".as_ptr() as *const _) };
const D: &CStr = unsafe { CStr::from_ptr(b"d\0".as_ptr() as *const _) };
const RSA: &CStr = unsafe { CStr::from_ptr(b"RSA\0".as_ptr() as *const _) };

/// Signals that OpenSSL failed to return some property.
fn not_set() -> anyhow::Error {
    Error::InvalidOperation("a required value was not set".into())
        .into()
}

fn require_len(actual: usize, expected: usize, label: &'static str) -> Result<()> {
    if actual != expected {
        return Err(Error::InvalidOperation(format!(
            "{label} length mismatch: {actual} != {expected}"
        ))
        .into());
    }
    Ok(())
}

/// Signals that OpenSSL returned an unexpected key type.
pub fn wrong_key() -> anyhow::Error {
    Error::InvalidOperation("an unexpected key type was returned".into())
        .into()
}

/// Parameterized implementation of SLH-DSA.
///
/// This generates a generate, sign and verify method for a SLH-DSA
/// variant.
macro_rules! slhdsa {
    ($generate_key:ident,
     $priv_type:ty,
     $sign:ident,
     $verify:ident,
     $evp_pkey_type:ident,
     $n:literal,
     $sig_alg:ident,
     $sig_size:literal) =>
    {
        fn $generate_key() -> Result<(Protected, $priv_type)>
        {
            let ctx = super::context();

            let key = EvpPkey::generate(
                &ctx, EvpPkeyType::$evp_pkey_type)?;
            match key.export()? {
                PkeyData::SlhDsaKey(SlhDsaKeyData {
                    ref pubkey,
                    ref prikey,
                    ..
                }) => {
                    let pubkey = pubkey.as_ref().ok_or_else(not_set)?;
                    let prikey = prikey.as_ref().ok_or_else(not_set)?;

                    require_len(pubkey.len(), 2 * $n, "SLH-DSA public key")?;
                    require_len(prikey.len(), 4 * $n, "SLH-DSA private key")?;

                    let mut public = [0; 2 * $n];
                    public.copy_from_slice(pubkey);

                    // From
                    // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-17.html#name-key-material-packets-3
                    //
                    //   The algorithm-specific part of the secret key
                    //   consists of:
                    //
                    //   * A fixed-length octet string containing the
                    //     SLH-DSA secret key, whose length depends on
                    //     the algorithm ID as specified in Table 8.

                    // From
                    // https://docs.openssl.org/3.5/man7/EVP_PKEY-SLH-DSA/#keygen-parameters
                    //
                    //   The private key has a size of 4 * n bytes,
                    //   which includes the public key
                    //   components. i.e. It consists of the
                    //   concatenation of SK.seed, SK.prf, PK.seed and
                    //   PF.root as defined by FIPS 205 Figure 15.
                    let private = Protected::from(prikey);

                    Ok((private, public.into()))
                },
                _ => Err(wrong_key()),
            }
        }

        fn $sign(secret: &Protected, digest: &[u8])
            -> Result<Box<[u8; $sig_size]>>
        {
            let ctx = super::context();

            let mut key = EvpPkey::import(
                &ctx, EvpPkeyType::$evp_pkey_type,
                PkeyData::SlhDsaKey(SlhDsaKeyData {
                    pubkey: None,
                    prikey: Some(secret.into()),
                })
            )?;

            let mut signer = OsslSignature::new(
                &ctx, SigOp::Sign, SigAlg::$sig_alg, &mut key, None)?;
            let mut signature = Box::new([0; $sig_size]);
            signer.sign(digest, Some(&mut signature[..]))?;
            Ok(signature)
        }

        fn $verify(public: &[u8; 2 * $n], digest: &[u8],
                   signature: &[u8; $sig_size])
            -> Result<bool>
        {
            let ctx = super::context();

            let mut key = EvpPkey::import(
                &ctx, EvpPkeyType::$evp_pkey_type,
                PkeyData::SlhDsaKey(SlhDsaKeyData {
                    pubkey: Some(public.to_vec()),
                    prikey: None,
                })
            )?;

            let mut verifier = OsslSignature::new(
                &ctx, SigOp::Verify, SigAlg::$sig_alg, &mut key, None)?;
            Ok(verifier.verify(digest, Some(&signature[..])).is_ok())
        }
    };
}

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match algo {
            X25519 | Ed25519 |
            X448 | Ed448 |
            RSAEncryptSign | RSAEncrypt | RSASign => true,
            DSA => true,
            ECDH | ECDSA | EdDSA => true,
            MLDSA65_Ed25519 | MLDSA87_Ed448 => pqc_algo_supported(algo),
            SLHDSA128s | SLHDSA128f | SLHDSA256s => pqc_algo_supported(algo),
            MLKEM768_X25519 | MLKEM1024_X448 => pqc_algo_supported(algo),
            ElGamalEncrypt | ElGamalEncryptSign |
            Private(_) | Unknown(_)
                => false,
        }
    }

    fn supports_curve(curve: &Curve) -> bool {
        if matches!(curve, Curve::Ed25519 | Curve::Cv25519) {
            // 25519-based algorithms are special-cased and supported
            true
        } else {
            // the rest of EC algorithms are supported via the same
            // codepath

            // XXX: We should do a runtime check here.
            EvpPkeyType::try_from(curve).is_ok()
        }
    }

    fn x25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::X25519)?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, ref prikey }) =>
                Ok((prikey.as_ref().ok_or_else(not_set)?.into(),
                    pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)),

            _ => Err(wrong_key()),
        }
    }

    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        let ctx = super::context();

        let key = EvpPkey::import(
            &ctx, EvpPkeyType::X25519,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(secret.into()),
            })
        )?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, .. }) => {
                Ok(pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)
            },

            _ => Err(wrong_key()),
        }
    }

    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected> {
        let ctx = super::context();

        let mut public = EvpPkey::import(
            &ctx, EvpPkeyType::X25519,
            PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            })
        )?;

        let mut secret = EvpPkey::import(
            &ctx, EvpPkeyType::X25519,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(secret.into()),
            })
        )?;

        let mut deriver = ossl::derive::EcdhDerive::new(&ctx, &mut secret)?;
        let mut shared: Protected = vec![0; 32].into();
        deriver.derive(&mut public, &mut shared)?;
        Ok(shared)
    }

    fn x448_generate_key() -> Result<(Protected, [u8; 56])> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::X448)?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, ref prikey }) =>
                Ok((prikey.as_ref().ok_or_else(not_set)?.into(),
                    pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)),

            _ => Err(wrong_key()),
        }
    }

    fn x448_derive_public(secret: &Protected) -> Result<[u8; 56]> {
        let ctx = super::context();

        let key = EvpPkey::import(
            &ctx, EvpPkeyType::X448,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(secret.into()),
            })
        )?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, .. }) => {
                Ok(pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)
            },

            _ => Err(wrong_key()),
        }
    }

    fn x448_shared_point(secret: &Protected, public: &[u8; 56])
                           -> Result<Protected> {
        let ctx = super::context();

        let mut public = EvpPkey::import(
            &ctx, EvpPkeyType::X448,
            PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            })
        )?;

        let mut secret = EvpPkey::import(
            &ctx, EvpPkeyType::X448,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(secret.into()),
            })
        )?;

        let mut deriver = ossl::derive::EcdhDerive::new(&ctx, &mut secret)?;
        let mut shared: Protected = vec![0; 56].into();
        deriver.derive(&mut public, &mut shared)?;
        Ok(shared)
    }

    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::Ed25519)?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, ref prikey }) =>
                Ok((prikey.as_ref().ok_or_else(not_set)?.into(),
                    pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)),

            _ => Err(wrong_key()),
        }
    }

    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]> {
        let ctx = super::context();

        let key = EvpPkey::import(
            &ctx, EvpPkeyType::Ed25519,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(secret.into()),
            })
        )?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, .. }) => {
                Ok(pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)
            },

            _ => Err(wrong_key()),
        }
    }

    fn ed25519_sign(secret: &Protected, public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]> {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Ed25519,
            PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: Some(secret.into()),
            })
        )?;

        let mut signer = OsslSignature::new(
            &ctx, SigOp::Sign, SigAlg::Ed25519, &mut key, None)?;
        let mut signature = [0; 64];
        signer.sign(digest, Some(&mut signature))?;
        Ok(signature)
    }

    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool> {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Ed25519,
            PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            })
        )?;

        let mut verifier = OsslSignature::new(
            &ctx, SigOp::Verify, SigAlg::Ed25519, &mut key, None)?;
        Ok(verifier.verify(digest, Some(&signature[..])).is_ok())
    }

    fn ed448_generate_key() -> Result<(Protected, [u8; 57])> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::Ed448)?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, ref prikey }) =>
                Ok((prikey.as_ref().ok_or_else(not_set)?.into(),
                    pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)),

            _ => Err(wrong_key()),
        }
    }

    fn ed448_derive_public(secret: &Protected) -> Result<[u8; 57]> {
        let ctx = super::context();

        let key = EvpPkey::import(
            &ctx, EvpPkeyType::Ed448,
            PkeyData::Ecc(EccData {
                pubkey: None,
                prikey: Some(secret.into()),
            })
        )?;
        match key.export()? {
            PkeyData::Ecc(EccData { ref pubkey, .. }) => {
                Ok(pubkey.as_ref().ok_or_else(not_set)?.as_slice().try_into()?)
            },

            _ => Err(wrong_key()),
        }
    }

    fn ed448_sign(secret: &Protected, public: &[u8; 57], digest: &[u8])
                    -> Result<[u8; 114]> {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Ed448,
            PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: Some(secret.into()),
            })
        )?;

        let mut signer = OsslSignature::new(
            &ctx, SigOp::Sign, SigAlg::Ed448, &mut key, None)?;
        let mut signature = [0; 114];
        signer.sign(digest, Some(&mut signature))?;
        Ok(signature)
    }

    fn ed448_verify(public: &[u8; 57], digest: &[u8], signature: &[u8; 114])
                      -> Result<bool> {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Ed448,
            PkeyData::Ecc(EccData {
                pubkey: Some(public.to_vec()),
                prikey: None,
            })
        )?;

        let mut verifier = OsslSignature::new(
            &ctx, SigOp::Verify, SigAlg::Ed448, &mut key, None)?;
        Ok(verifier.verify(digest, Some(&signature[..])).is_ok())
    }

    fn dsa_generate_key(p_bits: usize)
                        -> Result<(MPI, MPI, MPI, MPI, ProtectedMPI)>
    {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::Dsa(p_bits))?;
        match key.export()? {
            PkeyData::Dsa(key) => {
                Ok((key.p.into(), key.q.into(), key.g.into(),
                    key.pub_key.into(), key.priv_key.ok_or_else(not_set)?.into()))
            },
            _ => Err(wrong_key()),
        }
    }

    fn dsa_sign(x: &ProtectedMPI,
                p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                digest: &[u8])
                -> Result<(MPI, MPI)>
    {
        let ctx = super::context();

        let pbits = p.bits();
        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Dsa(pbits),
            PkeyData::Dsa(DsaData {
                p: p.value().into(),
                q: q.value().into(),
                g: g.value().into(),
                priv_key: Some(x.into()),
                pub_key: y.value().into(),
            }),
        )?;

        let mut signer = OsslSignature::new(
            &ctx, SigOp::Sign, SigAlg::Dsa, &mut key, None)?;
        let sig_len = signer.sign(digest, None)?;
        let mut signature = vec![0u8; sig_len];
        let sig_len = signer.sign(digest, Some(&mut signature))?;
        signature.truncate(sig_len);
        let (r, s) = der::parse_sig_r_s(&signature)?;
        Ok((MPI::new(r), MPI::new(s)))
    }

    fn dsa_verify(p: &MPI, q: &MPI, g: &MPI, y: &MPI,
                  digest: &[u8],
                  r: &MPI, s: &MPI)
                  -> Result<bool>
    {
        let ctx = super::context();

        let pbits = p.bits();
        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Dsa(pbits),
            PkeyData::Dsa(DsaData {
                p: p.value().into(),
                q: q.value().into(),
                g: g.value().into(),
                priv_key: None,
                pub_key: y.value().into(),
            }),
        )?;

        let mut signature = Vec::new();
        der::encode_sig_r_s(&mut signature, r.value(), s.value())?;
        let mut verifier = OsslSignature::new(
            &ctx, SigOp::Verify, SigAlg::Dsa, &mut key, None)?;
        Ok(verifier.verify(digest, Some(&signature)).is_ok())
    }

    fn mldsa65_generate_key() -> Result<(Protected, Box<[u8; 1952]>)> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::Mldsa65)?;
        match key.export()? {
            PkeyData::Mlkey(MlkeyData { ref pubkey, ref seed, .. }) => {
                let pubkey = pubkey.as_ref().ok_or_else(not_set)?;
                let mut public = Box::new([0; 1952]);
                require_len(pubkey.len(), public.len(), "ML-DSA-65 public key")?;
                public.copy_from_slice(pubkey);
                Ok((seed.as_ref().ok_or_else(not_set)?.into(), public))
            },
            _ => Err(wrong_key()),
        }
    }

    fn mldsa65_sign(secret: &Protected, digest: &[u8])
                    -> Result<Box<[u8; 3309]>>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Mldsa65,
            PkeyData::Mlkey(MlkeyData {
                pubkey: None,
                prikey: None,
                seed: Some(secret.into()),
            })
        )?;

        let mut signer = OsslSignature::new(
            &ctx, SigOp::Sign, SigAlg::Mldsa65, &mut key, None)?;
        let mut signature = Box::new([0; 3309]);
        signer.sign(digest, Some(&mut signature[..]))?;
        Ok(signature)
    }

    fn mldsa65_verify(public: &[u8; 1952], digest: &[u8], signature: &[u8; 3309])
                      -> Result<bool>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Mldsa65,
            PkeyData::Mlkey(MlkeyData {
                pubkey: Some(public.to_vec()),
                prikey: None,
                seed: None,
            })
        )?;

        let mut verifier = OsslSignature::new(
            &ctx, SigOp::Verify, SigAlg::Mldsa65, &mut key, None)?;
        Ok(verifier.verify(digest, Some(&signature[..])).is_ok())
    }

    fn mldsa87_generate_key() -> Result<(Protected, Box<[u8; 2592]>)> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::Mldsa87)?;
        match key.export()? {
            PkeyData::Mlkey(MlkeyData { ref pubkey, ref seed, .. }) => {
                let pubkey = pubkey.as_ref().ok_or_else(not_set)?;
                let mut public = Box::new([0; 2592]);
                require_len(pubkey.len(), public.len(), "ML-DSA-87 public key")?;
                public.copy_from_slice(pubkey);
                Ok((seed.as_ref().ok_or_else(not_set)?.into(), public))
            },
            _ => Err(wrong_key()),
        }
    }

    fn mldsa87_sign(secret: &Protected, digest: &[u8])
                    -> Result<Box<[u8; 4627]>>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Mldsa87,
            PkeyData::Mlkey(MlkeyData {
                pubkey: None,
                prikey: None,
                seed: Some(secret.into()),
            })
        )?;

        let mut signer = OsslSignature::new(
            &ctx, SigOp::Sign, SigAlg::Mldsa87, &mut key, None)?;
        let mut signature = Box::new([0; 4627]);
        signer.sign(digest, Some(&mut signature[..]))?;
        Ok(signature)
    }

    fn mldsa87_verify(public: &[u8; 2592], digest: &[u8], signature: &[u8; 4627])
                      -> Result<bool>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::Mldsa87,
            PkeyData::Mlkey(MlkeyData {
                pubkey: Some(public.to_vec()),
                prikey: None,
                seed: None,
            })
        )?;

        let mut verifier = OsslSignature::new(
            &ctx, SigOp::Verify, SigAlg::Mldsa87, &mut key, None)?;
        Ok(verifier.verify(digest, Some(&signature[..])).is_ok())
    }

    slhdsa!(slhdsa128s_generate_key,
            [u8; 32],
            slhdsa128s_sign,
            slhdsa128s_verify,
            SlhdsaShake128s,
            16,
            SlhdsaShake128s,
            7856);
    slhdsa!(slhdsa128f_generate_key,
            [u8; 32],
            slhdsa128f_sign,
            slhdsa128f_verify,
            SlhdsaShake128f,
            16,
            SlhdsaShake128f,
            17088);
    slhdsa!(slhdsa256s_generate_key,
            Box<[u8; 64]>,
            slhdsa256s_sign,
            slhdsa256s_verify,
            SlhdsaShake256s,
            32,
            SlhdsaShake256s,
            29792);

    /// Generates a ML-KEM-768 key pair.
    fn mlkem768_generate_key() -> Result<(Protected, Box<[u8; 1184]>)> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::MlKem768)?;
        match key.export()? {
            PkeyData::Mlkey(MlkeyData { ref pubkey, ref seed, .. }) => {
                let pubkey = pubkey.as_ref().ok_or_else(not_set)?;
                let mut public = Box::new([0; 1184]);
                require_len(pubkey.len(), public.len(), "ML-KEM-768 public key")?;
                public.copy_from_slice(pubkey);
                Ok((seed.as_ref().ok_or_else(not_set)?.into(), public))
            },
            _ => Err(wrong_key()),
        }
    }

    /// Generates and encapsulates a secret using ML-KEM-768.
    fn mlkem768_encapsulate(public: &[u8; 1184])
                            -> Result<(Box<[u8; 1088]>, Protected)>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::MlKem768,
            PkeyData::Mlkey(MlkeyData {
                pubkey: Some(public.to_vec()),
                prikey: None,
                seed: None,
            })
        )?;

        let mut encryptor = OsslAsymcipher::new(
            &ctx, EncOp::Encapsulate, &mut key, None)?;
        let mut ciphertext = Protected::from(vec![0; 1088]);
        let (keyshare, l) =
            encryptor.encapsulate(&mut ciphertext)?;
        require_len(l, 1088, "ML-KEM-768 ciphertext")?;
        require_len(ciphertext.len(), l, "ML-KEM-768 ciphertext buffer")?;
        let mut boxed_ciphertext = Box::new([0; 1088]);
        boxed_ciphertext.copy_from_slice(&ciphertext);

        Ok((boxed_ciphertext, Protected::from(keyshare)))
    }

    /// Decapsulates a secret using ML-KEM-768.
    fn mlkem768_decapsulate(secret: &Protected,
                            ciphertext: &[u8; 1088])
                            -> Result<Protected>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::MlKem768,
            PkeyData::Mlkey(MlkeyData {
                pubkey: None,
                prikey: None,
                seed: Some(secret.into()),
            })
        )?;

        let mut encryptor = OsslAsymcipher::new(
            &ctx, EncOp::Decapsulate, &mut key, None)?;
        let keyshare = encryptor.decapsulate(&ciphertext[..])?;
        require_len(keyshare.len(), 32, "ML-KEM-768 shared secret")?;

        Ok(keyshare.into())
    }

    /// Generates a ML-KEM-1024 key pair.
    fn mlkem1024_generate_key() -> Result<(Protected, Box<[u8; 1568]>)> {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, EvpPkeyType::MlKem1024)?;
        match key.export()? {
            PkeyData::Mlkey(MlkeyData { ref pubkey, ref seed, .. }) => {
                let pubkey = pubkey.as_ref().ok_or_else(not_set)?;
                let mut public = Box::new([0; 1568]);
                require_len(pubkey.len(), public.len(), "ML-KEM-1024 public key")?;
                public.copy_from_slice(pubkey);
                Ok((seed.as_ref().ok_or_else(not_set)?.into(), public))
            },
            _ => Err(wrong_key()),
        }
    }

    /// Generates and encapsulates a secret using ML-KEM-1024.
    fn mlkem1024_encapsulate(public: &[u8; 1568])
                             -> Result<(Box<[u8; 1568]>, Protected)>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::MlKem1024,
            PkeyData::Mlkey(MlkeyData {
                pubkey: Some(public.to_vec()),
                prikey: None,
                seed: None,
            })
        )?;

        let mut encryptor = OsslAsymcipher::new(
            &ctx, EncOp::Encapsulate, &mut key, None)?;
        let mut ciphertext = Protected::from(vec![0; 1568]);
        let (keyshare, l) =
            encryptor.encapsulate(&mut ciphertext)?;
        require_len(l, 1568, "ML-KEM-1024 ciphertext")?;
        require_len(ciphertext.len(), l, "ML-KEM-1024 ciphertext buffer")?;
        let mut boxed_ciphertext = Box::new([0; 1568]);
        boxed_ciphertext.copy_from_slice(&ciphertext);

        Ok((boxed_ciphertext, Protected::from(keyshare)))
    }

    /// Decapsulates a secret using ML-KEM-1024.
    fn mlkem1024_decapsulate(secret: &Protected,
                             ciphertext: &[u8; 1568])
                             -> Result<Protected>
    {
        let ctx = super::context();

        let mut key = EvpPkey::import(
            &ctx, EvpPkeyType::MlKem1024,
            PkeyData::Mlkey(MlkeyData {
                pubkey: None,
                prikey: None,
                seed: Some(secret.into()),
            })
        )?;

        let mut encryptor = OsslAsymcipher::new(
            &ctx, EncOp::Decapsulate, &mut key, None)?;
        let keyshare = encryptor.decapsulate(&ciphertext[..])?;
        require_len(keyshare.len(), 32, "ML-KEM-1024 shared secret")?;

        Ok(keyshare.into())
    }
}

fn pqc_algo_supported(algo: PublicKeyAlgorithm) -> bool {
    use PublicKeyAlgorithm::*;
    static CACHE: OnceLock<Mutex<HashMap<PublicKeyAlgorithm, bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut guard) = cache.lock() {
        if let Some(value) = guard.get(&algo) {
            return *value;
        }
        let ctx = super::context();
        let supported = match algo {
            MLDSA65_Ed25519 => EvpPkey::generate(&ctx, EvpPkeyType::Mldsa65).is_ok(),
            MLDSA87_Ed448 => EvpPkey::generate(&ctx, EvpPkeyType::Mldsa87).is_ok(),
            SLHDSA128s => EvpPkey::generate(&ctx, EvpPkeyType::SlhdsaShake128s).is_ok(),
            SLHDSA128f => EvpPkey::generate(&ctx, EvpPkeyType::SlhdsaShake128f).is_ok(),
            SLHDSA256s => EvpPkey::generate(&ctx, EvpPkeyType::SlhdsaShake256s).is_ok(),
            MLKEM768_X25519 => EvpPkey::generate(&ctx, EvpPkeyType::MlKem768).is_ok(),
            MLKEM1024_X448 => EvpPkey::generate(&ctx, EvpPkeyType::MlKem1024).is_ok(),
            _ => false,
        };
        guard.insert(algo, supported);
        return supported;
    }
    false
}

impl KeyPair {
    pub(crate) fn sign_backend(&self,
                               secret: &mpi::SecretKeyMaterial,
                               hash_algo: HashAlgorithm,
                               digest: &[u8])
                               -> Result<mpi::Signature>
    {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match (self.public().pk_algo(), self.public().mpis(), secret) {
                (
                    RSAEncryptSign,
                    mpi::PublicKey::RSA { e, n },
                    mpi::SecretKeyMaterial::RSA { d, .. },
                )
                | (
                    RSASign,
                    mpi::PublicKey::RSA { e, n },
                    mpi::SecretKeyMaterial::RSA { d, .. },
                ) => {
                    let ctx = super::context();

                    const MAX_OID_SIZE: usize = 20;
                    let mut v = Vec::with_capacity(MAX_OID_SIZE + digest.len());
                    v.extend(hash_algo.oid()?);
                    v.extend(digest);

                    let mut params = ossl::OsslParamBuilder::with_capacity(3);
                    params.add_bn(E, e.value())?;
                    params.add_bn(N, n.value())?;
                    params.add_bn(D, d.value())?;
                    let params = params.finalize();

                    let mut key = EvpPkey::fromdata(
                        &ctx, RSA, ossl::bindings::EVP_PKEY_KEYPAIR, &params)?;
                    let mut signer = OsslSignature::new(
                        &ctx, SigOp::Sign, SigAlg::Rsa, &mut key, None)?;

                    let size = signer.sign(&v, None)?;
                    let mut signature = vec![0; size];
                    let real_size =
                        signer.sign(&v, Some(&mut signature))?;
                    crate::vec_truncate(&mut signature, real_size);

                    Ok(mpi::Signature::RSA {
                        s: signature.into(),
                    })
                }

                (
                    PublicKeyAlgorithm::ECDSA,
                    mpi::PublicKey::ECDSA { curve, q },
                    mpi::SecretKeyMaterial::ECDSA { scalar },
                ) => {
                    let ctx = super::context();

                    let mut key = EvpPkey::import(
                        &ctx, curve.try_into()?,
                        PkeyData::Ecc(EccData {
                            pubkey: Some(q.value().to_vec()),
                            prikey: Some(
                                ossl::OsslSecret::from_slice(scalar.value())),
                        })
                    )?;

                    let mut signer = OsslSignature::new(
                        &ctx, SigOp::Sign, SigAlg::Ecdsa, &mut key, None)?;
                    let size = signer.sign(digest, None)?;
                    let mut signature = vec![0; size];
                    let real_size =
                        signer.sign(digest, Some(&mut signature))?;
                    crate::vec_truncate(&mut signature, real_size);

                    // Recover the DER-encoded R and S.
                    let (r, s) = der::parse_sig_r_s(&signature)?;

                    Ok(mpi::Signature::ECDSA {
                        r: MPI::new(r),
                        s: MPI::new(s),
                    })
                }

                (pk_algo, _, _) => Err(crate::Error::InvalidOperation(format!(
                    "unsupported combination of algorithm {:?}, key {:?}, \
                        and secret key {:?} by OpenSSL backend",
                    pk_algo,
                    self.public(),
                    self.secret()
                ))
                .into()),
        }
    }
}

impl TryFrom<&Curve> for EvpPkeyType {
    type Error = crate::Error;

    fn try_from(c: &Curve) -> std::result::Result<Self, Self::Error> {
        match c {
            Curve::NistP256 => Ok(EvpPkeyType::P256),
            Curve::NistP384 => Ok(EvpPkeyType::P384),
            Curve::NistP521 => Ok(EvpPkeyType::P521),
            Curve::BrainpoolP256 => Ok(EvpPkeyType::BrainpoolP256r1),
            Curve::BrainpoolP384 => Ok(EvpPkeyType::BrainpoolP384r1),
            Curve::BrainpoolP512 => Ok(EvpPkeyType::BrainpoolP512r1),
            c => Err(Error::UnsupportedEllipticCurve(c.clone()))?,
        }
    }
}

impl KeyPair {
    pub(crate) fn decrypt_backend(
        &self,
        secret: &mpi::SecretKeyMaterial,
        ciphertext: &mpi::Ciphertext,
        plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        use crate::crypto::mpi::PublicKey;

        Ok(match (self.public().mpis(), secret, ciphertext) {
                (
                    PublicKey::RSA { ref e, ref n },
                    mpi::SecretKeyMaterial::RSA { d, .. },
                    mpi::Ciphertext::RSA { ref c },
                ) => {
                    let ctx = super::context();

                    let mut params = ossl::OsslParamBuilder::with_capacity(3);
                    params.add_bn(E, e.value())?;
                    params.add_bn(N, n.value())?;
                    params.add_bn(D, d.value())?;
                    let params = params.finalize();

                    let mut key = EvpPkey::fromdata(
                        &ctx, RSA, ossl::bindings::EVP_PKEY_KEYPAIR, &params)?;
                    let params = ossl::asymcipher::rsa_enc_params(
                        EncAlg::RsaPkcs1_5, None)?;
                    let mut decryptor = OsslAsymcipher::new(
                        &ctx, EncOp::Decrypt, &mut key, Some(&params))?;

                    let size = decryptor.decrypt(c.value(), None)?;
                    let mut buf: Protected = vec![0; size].into();
                    let real_size =
                        decryptor.decrypt(c.value(), Some(&mut buf))?;
                    let mut plaintext: Protected = vec![0; real_size].into();
                    plaintext[..].copy_from_slice(&buf[..real_size]);
                    plaintext.into()
                }

                (
                    PublicKey::ECDH { .. },
                    mpi::SecretKeyMaterial::ECDH { .. },
                    mpi::Ciphertext::ECDH { .. },
                ) => crate::crypto::ecdh::decrypt(self.public(), secret,
                                                  ciphertext,
                                                  plaintext_len)?,

                (public, secret, ciphertext) => {
                    return Err(crate::Error::InvalidOperation(format!(
                        "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                        public, secret, ciphertext
                    ))
                    .into())
                }
        })
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => match self.mpis() {
                mpi::PublicKey::RSA { e, n } => {
                    // The ciphertext has the length of the modulus.
                    let ciphertext_len = n.value().len();
                    if data.len() + 11 > ciphertext_len {
                        return Err(crate::Error::InvalidArgument(
                            "Plaintext data too large".into(),
                        )
                        .into());
                    }

                    let ctx = super::context();

                    let mut params = ossl::OsslParamBuilder::with_capacity(2);
                    params.add_bn(E, e.value())?;
                    params.add_bn(N, n.value())?;
                    let params = params.finalize();

                    let mut key = EvpPkey::fromdata(
                        &ctx, RSA, ossl::bindings::EVP_PKEY_PUBLIC_KEY, &params)?;
                    let params = ossl::asymcipher::rsa_enc_params(
                        EncAlg::RsaPkcs1_5, None)?;
                    let mut encryptor = OsslAsymcipher::new(
                        &ctx, EncOp::Encrypt, &mut key, Some(&params))?;

                    let size = encryptor.encrypt(data, None)?;
                    let mut buf = vec![0; size];
                    let real_size =
                        encryptor.encrypt(data, Some(&mut buf))?;
                    crate::vec_truncate(&mut buf, real_size);

                    Ok(mpi::Ciphertext::RSA {
                        c: buf.into(),
                    })
                }
                pk => Err(crate::Error::MalformedPacket(format!(
                    "Key: Expected RSA public key, got {:?}",
                    pk
                ))
                .into()),
            },

            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),

            RSASign | DSA | ECDSA | EdDSA | Ed25519 | Ed448 |
                MLDSA65_Ed25519 | MLDSA87_Ed448
                | SLHDSA128s | SLHDSA128f | SLHDSA256s =>
                Err(Error::InvalidOperation(
                    format!("{} is not an encryption algorithm", self.pk_algo())
                ).into()),

            X25519 | // Handled in common code.
            X448 | // Handled in common code.
            ElGamalEncrypt | ElGamalEncryptSign |
            MLKEM768_X25519 | // Handled in common code.
            MLKEM1024_X448 | // Handled in common code.
            Private(_) | Unknown(_) =>
                Err(Error::UnsupportedPublicKeyAlgorithm(self.pk_algo()).into()),
        }
    }

    /// Verifies the given signature.
    pub(crate) fn verify_backend(
        &self,
        sig: &mpi::Signature,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<()> {
        let ok = match (self.mpis(), sig) {
            (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                let ctx = super::context();

                let mut params = ossl::OsslParamBuilder::with_capacity(2);
                params.add_bn(E, e.value())?;
                params.add_bn(N, n.value())?;
                let params = params.finalize();

                let mut key = EvpPkey::fromdata(
                    &ctx, RSA, ossl::bindings::EVP_PKEY_PUBLIC_KEY, &params)?;
                let mut verifier = OsslSignature::new(
                    &ctx, SigOp::Verify, SigAlg::Rsa, &mut key, None)?;

                let mut v = vec![];
                v.extend(hash_algo.oid()?);
                v.extend(digest);

                verifier.verify(&v, Some(s.value())).is_ok()
            }

            (mpi::PublicKey::ECDSA { curve, q }, mpi::Signature::ECDSA { r, s }) => {
                let ctx = super::context();

                let mut key = EvpPkey::import(
                    &ctx, curve.try_into()?,
                    PkeyData::Ecc(EccData {
                        pubkey: Some(q.value().to_vec()),
                        prikey: None,
                    })
                )?;

                // DER-encode R and S.
                let mut signature = Vec::new();
                der::encode_sig_r_s(&mut signature, r.value(), s.value())?;

                let mut verifier = OsslSignature::new(
                    &ctx, SigOp::Verify, SigAlg::Ecdsa, &mut key, None)?;
                verifier.verify(digest, Some(&signature)).is_ok()
            }
            _ => {
                return Err(crate::Error::MalformedPacket(format!(
                    "unsupported combination of key {} and signature {:?}.",
                    self.pk_algo(),
                    sig
                ))
                .into())
            }
        };

        if ok {
            Ok(())
        } else {
            Err(crate::Error::ManipulatedMessage.into())
        }
    }
}

impl<R> Key4<SecretParts, R>
where
    R: key::KeyRole,
{
    /// Creates a new OpenPGP secret key packet for an existing RSA key.
    ///
    /// The RSA key will use the secret exponent `d`, derived from the
    /// secret primes `p` and `q`.  The key will have its creation
    /// date set to `ctime` or the current time if `None` is given.
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // RFC 4880: `p < q`
        let (p, q) = crate::crypto::rsa_sort_raw_pq(p, q);

        let (e, key_data) = RsaData::from_dpq(d, p, q)?;

        let ctx = super::context();
        let key = EvpPkey::import(
            &ctx, EvpPkeyType::Rsa(0, vec![]),
            PkeyData::Rsa(key_data))?;

        Self::make_rsa(&e, key, ctime.into())
    }

    /// Generates a new RSA key with a public modulus of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let ctx = super::context();

        let e = 65537_i32.to_be_bytes();
        let key = EvpPkey::generate(
            &ctx, EvpPkeyType::Rsa(bits, e.to_vec()))?;
        Self::make_rsa(&e, key, None)
    }

    /// Creates an RSA OpenPGP key from the given `EvpPkey`.
    fn make_rsa(e: &[u8], key: EvpPkey, ctime: Option<SystemTime>)
                -> Result<Self>
    {
        use ossl::pkey::PkeyData;

        match key.export()? {
            PkeyData::Rsa(mut key) => {
                use crate::crypto::raw_bigint_cmp;
                use std::cmp::Ordering;

                // Make sure that p < q.
                let p_ref = key.p.as_ref().ok_or_else(not_set)?;
                let q_ref = key.q.as_ref().ok_or_else(not_set)?;
                if raw_bigint_cmp(p_ref, q_ref)
                    == Ordering::Greater
                {
                    // p > q, swap!
                    std::mem::swap(&mut key.p, &mut key.q);
                }
                let u = key.inverse_p_mod_q()?;

                Self::with_secret(
                    ctime.unwrap_or_else(crate::now),
                    PublicKeyAlgorithm::RSAEncryptSign,
                    mpi::PublicKey::RSA {
                        e: MPI::new(&e),
                        n: MPI::new(key.n.as_ref()),
                    },
                    mpi::SecretKeyMaterial::RSA {
                        d: key.d.as_ref().ok_or_else(not_set)?.into(),
                        p: key.p.as_ref().ok_or_else(not_set)?.into(),
                        q: key.q.as_ref().ok_or_else(not_set)?.into(),
                        u: u.into(),
                    }
                    .into())
            },

            _ => Err(Error::InvalidOperation(
                "got the wrong key type".into()).into()),
        }
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub(crate) fn generate_ecc_backend(for_signing: bool, curve: Curve)
                                       -> Result<(PublicKeyAlgorithm,
                                                  mpi::PublicKey,
                                                  mpi::SecretKeyMaterial)>
    {
        let ctx = super::context();

        let key = EvpPkey::generate(&ctx, (&curve).try_into()?)?;
        let hash = crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
        let sym = crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);

        match key.export()? {
            PkeyData::Ecc(key) => {
                let q = key.pubkey.as_ref().ok_or_else(not_set)?.clone().into();
                let scalar = key.prikey.as_ref().ok_or_else(not_set)?.into();

                if for_signing {
                    Ok((
                        PublicKeyAlgorithm::ECDSA,
                        mpi::PublicKey::ECDSA { curve, q },
                        mpi::SecretKeyMaterial::ECDSA { scalar },
                    ))
                } else {
                    Ok((
                        PublicKeyAlgorithm::ECDH,
                        mpi::PublicKey::ECDH {
                            curve, q, hash, sym,
                        },
                        mpi::SecretKeyMaterial::ECDH { scalar },
                    ))
                }
            },

            _ => Err(Error::InvalidOperation(
                "got the wrong key type".into()).into()),
        }
    }
}
