//! Elliptic Curve Diffie-Hellman.

use crate::crypto::backend::openssl::asymmetric::wrong_key;
use crate::crypto::ecdh::{decrypt_unwrap, encrypt_wrap};
use crate::crypto::mpi;
use crate::crypto::mpi::{Ciphertext, SecretKeyMaterial};
use crate::crypto::{mem::Protected, SessionKey};
use crate::packet::{key, Key};
use crate::types::Curve;
use crate::{Error, Result};

use ossl::pkey::{EccData, EvpPkey, PkeyData};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
pub fn encrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    session_key: &SessionKey,
) -> Result<Ciphertext>
where
    R: key::KeyRole,
{
    let (curve, q) = match recipient.mpis() {
        mpi::PublicKey::ECDH { curve, q, .. } => (curve, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };
    if curve == &Curve::Cv25519 {
        return Err(Error::InvalidArgument("implemented elsewhere".into()).into());
    }

    let ctx = super::context();

    let mut public = EvpPkey::import(
        &ctx, curve.try_into()?,
        PkeyData::Ecc(EccData {
            pubkey: Some(q.value().to_vec()),
            prikey: None,
        })
    )?;

    let mut ephemeral = EvpPkey::generate(&ctx, curve.try_into()?)?;

    let mut deriver = ossl::derive::EcdhDerive::new(&ctx, &mut ephemeral)?;
    let mut shared: Protected = vec![0; curve.field_size()?].into();
    let size = deriver.derive(&mut public, &mut shared)?;
    if shared.len() != size {
        return Err(Error::InvalidOperation(format!(
            "ECDH derive size mismatch: {} != {}",
            shared.len(),
            size
        ))
        .into());
    }

    let q = match ephemeral.export()? {
        PkeyData::Ecc(EccData { ref pubkey, .. }) => {
            pubkey
                .as_ref()
                .ok_or_else(|| {
                    Error::InvalidOperation("ECDH ephemeral public key not set".into())
                })?
                .clone()
                .into()
        },

        _ => return Err(wrong_key()),
    };

    encrypt_wrap(recipient.role_as_subordinate(), session_key, q, &shared)
}

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
pub fn decrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    recipient_sec: &SecretKeyMaterial,
    ciphertext: &Ciphertext,
    plaintext_len: Option<usize>,
) -> Result<SessionKey>
where
    R: key::KeyRole,
{
    let (curve, scalar, e, q) = match (recipient.mpis(), recipient_sec, ciphertext) {
        (
            mpi::PublicKey::ECDH {
                ref curve, ref q, ..
            },
            SecretKeyMaterial::ECDH { ref scalar },
            Ciphertext::ECDH { ref e, .. },
        ) => (curve, scalar, e, q),
        _ => return Err(Error::InvalidArgument("Expected an ECDHPublicKey".into()).into()),
    };

    if curve == &Curve::Cv25519 {
        return Err(Error::InvalidArgument("implemented elsewhere".into()).into());
    }

    let ctx = super::context();

    let mut ephemeral = EvpPkey::import(
        &ctx, curve.try_into()?,
        PkeyData::Ecc(EccData {
            pubkey: Some(e.value().to_vec()),
            prikey: None,
        })
    )?;

    let mut secret = EvpPkey::import(
        &ctx, curve.try_into()?,
        PkeyData::Ecc(EccData {
            pubkey: Some(q.value().to_vec()),
            prikey: Some(ossl::OsslSecret::from_slice(scalar.value())),
        })
    )?;

    let mut deriver = ossl::derive::EcdhDerive::new(&ctx, &mut secret)?;
    let mut shared: Protected = vec![0; curve.field_size()?].into();
    let size = deriver.derive(&mut ephemeral, &mut shared)?;
    if shared.len() != size {
        return Err(Error::InvalidOperation(format!(
            "ECDH derive size mismatch: {} != {}",
            shared.len(),
            size
        ))
        .into());
    }

    decrypt_unwrap(recipient.role_as_unspecified(), &shared, ciphertext,
                   plaintext_len)
}
