use ossl::{
    derive::{HkdfDerive, HkdfMode},
    digest::DigestAlg,
};

use crate::{
    Result,
    crypto::{
        SessionKey,
        backend::interface::Kdf,
    },
};

impl Kdf for super::Backend {
    fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        let ctx = super::context();

        let mut hkdf = HkdfDerive::new(&ctx, DigestAlg::Sha2_256)?;
        hkdf.set_mode(HkdfMode::ExtractAndExpand);
        hkdf.set_key(&ikm);
        if let Some(salt) = salt {
            hkdf.set_salt(salt);
        }
        hkdf.set_info(info);
        hkdf.derive(okm)?;
        Ok(())
    }

    fn hkdf_sha512(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        let ctx = super::context();

        let mut hkdf = HkdfDerive::new(&ctx, DigestAlg::Sha2_512)?;
        hkdf.set_mode(HkdfMode::ExtractAndExpand);
        hkdf.set_key(&ikm);
        if let Some(salt) = salt {
            hkdf.set_salt(salt);
        }
        hkdf.set_info(info);
        hkdf.derive(okm)?;
        Ok(())
    }
}
