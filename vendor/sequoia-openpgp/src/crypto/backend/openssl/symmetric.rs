use std::borrow::Cow;

use crate::{Error, Result};

use crate::crypto::{
    AEADAlgorithm,
    SymmetricAlgorithm,
    self,
    mem::Protected,
    symmetric::{BlockCipherMode, Context},
};

use ossl::cipher::{
    AeadParams,
    AesSize,
    CamelliaSize,
    EncAlg,
    OsslCipher,
};

impl crypto::backend::interface::Symmetric for super::Backend {
    fn supports_algo(algo: SymmetricAlgorithm) -> bool {
        let key = vec![0; algo.key_size().unwrap_or(0)].into();
        Self::encryptor_impl(algo, BlockCipherMode::ECB, &key,
                             Cow::Borrowed(&[])).is_ok()
    }

    fn encryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB =>
                Ok(Box::new(OpenSslMode::new(algo, mode, None, true, key, Some(iv))?)),

            BlockCipherMode::CBC =>
                Ok(Box::new(OpenSslMode::new(algo, mode, Some(false), true, key, Some(iv))?)),

            BlockCipherMode::ECB =>
                Ok(Box::new(OpenSslMode::new(algo, mode, Some(false), true, key, None)?)),
        }
    }

    fn decryptor_impl(algo: SymmetricAlgorithm, mode: BlockCipherMode,
		      key: &Protected, iv: Cow<'_, [u8]>)
                      -> Result<Box<dyn Context>>
    {
        match mode {
            BlockCipherMode::CFB =>
                Ok(Box::new(OpenSslMode::new(algo, mode, None, false, key, Some(iv))?)),

            BlockCipherMode::CBC =>
                Ok(Box::new(OpenSslMode::new(algo, mode, Some(false), false, key, Some(iv))?)),

            BlockCipherMode::ECB =>
                Ok(Box::new(OpenSslMode::new(algo, mode, Some(false), false, key, None)?)),
        }
    }
}

#[derive(Debug)]
pub enum OsslMode {
    Unauthenticated(BlockCipherMode),
    Authenticated(AEADAlgorithm, Vec<u8>),
}

impl From<BlockCipherMode> for OsslMode {
    fn from(v: BlockCipherMode) -> Self {
        OsslMode::Unauthenticated(v)
    }
}

#[derive(Debug)]
pub struct OpenSslMode {
    pub ctx: OsslCipher,
}

impl OpenSslMode {
    pub fn new(algo: SymmetricAlgorithm,
               mode: impl Into<OsslMode>,
               padding: Option<bool>,
               enc: bool,
               key: &Protected,
               iv: Option<Cow<'_, [u8]>>) -> Result<Self>
    {
        let ctx = super::context();

        use SymmetricAlgorithm::*;
        use AEADAlgorithm::*;
        use BlockCipherMode::*;
        #[allow(deprecated)]
        let (alg, aead) = match (algo, mode.into()) {
            (AES128, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::AesCfb128(AesSize::Aes128), None),
            (AES192, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::AesCfb128(AesSize::Aes192), None),
            (AES256, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::AesCfb128(AesSize::Aes256), None),
            (TripleDES, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::TripleDesCfb, None),
            (IDEA, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::IdeaCfb, None),
            (Camellia128, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::CamelliaCfb(CamelliaSize::Camellia128), None),
            (Camellia192, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::CamelliaCfb(CamelliaSize::Camellia192), None),
            (Camellia256, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::CamelliaCfb(CamelliaSize::Camellia256), None),
            (Blowfish, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::BlowfishCfb, None),
            (CAST5, OsslMode::Unauthenticated(CFB)) =>
                (EncAlg::Cast5Cfb, None),

            (AES128, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::AesCbc(AesSize::Aes128), None),
            (AES192, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::AesCbc(AesSize::Aes192), None),
            (AES256, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::AesCbc(AesSize::Aes256), None),
            (TripleDES, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::TripleDesCbc, None),
            (IDEA, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::IdeaCbc, None),
            (Camellia128, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::CamelliaCbc(CamelliaSize::Camellia128), None),
            (Camellia192, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::CamelliaCbc(CamelliaSize::Camellia192), None),
            (Camellia256, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::CamelliaCbc(CamelliaSize::Camellia256), None),
            (Blowfish, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::BlowfishCbc, None),
            (CAST5, OsslMode::Unauthenticated(CBC)) =>
                (EncAlg::Cast5Cbc, None),

            (AES128, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::AesEcb(AesSize::Aes128), None),
            (AES192, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::AesEcb(AesSize::Aes192), None),
            (AES256, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::AesEcb(AesSize::Aes256), None),
            (TripleDES, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::TripleDesEcb, None),
            (IDEA, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::IdeaEcb, None),
            (Camellia128, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::CamelliaEcb(CamelliaSize::Camellia128), None),
            (Camellia192, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::CamelliaEcb(CamelliaSize::Camellia192), None),
            (Camellia256, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::CamelliaEcb(CamelliaSize::Camellia256), None),
            (Blowfish, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::BlowfishEcb, None),
            (CAST5, OsslMode::Unauthenticated(ECB)) =>
                (EncAlg::Cast5Ecb, None),

            (AES128, OsslMode::Authenticated(OCB, aad)) =>
                (EncAlg::AesOcb(AesSize::Aes128), Some(AeadParams::new(Some(aad), OCB.digest_size()?, 0))),
            (AES192, OsslMode::Authenticated(OCB, aad)) =>
                (EncAlg::AesOcb(AesSize::Aes192), Some(AeadParams::new(Some(aad), OCB.digest_size()?, 0))),
            (AES256, OsslMode::Authenticated(OCB, aad)) =>
                (EncAlg::AesOcb(AesSize::Aes256), Some(AeadParams::new(Some(aad), OCB.digest_size()?, 0))),

            (AES128, OsslMode::Authenticated(GCM, aad)) =>
                (EncAlg::AesGcm(AesSize::Aes128), Some(AeadParams::new(Some(aad), GCM.digest_size()?, 0))),
            (AES192, OsslMode::Authenticated(GCM, aad)) =>
                (EncAlg::AesGcm(AesSize::Aes192), Some(AeadParams::new(Some(aad), GCM.digest_size()?, 0))),
            (AES256, OsslMode::Authenticated(GCM, aad)) =>
                (EncAlg::AesGcm(AesSize::Aes256), Some(AeadParams::new(Some(aad), GCM.digest_size()?, 0))),

            (a, OsslMode::Unauthenticated(_)) => return Err(
                Error::UnsupportedSymmetricAlgorithm(a).into()),
            (_, OsslMode::Authenticated(a, _)) => return Err(
                Error::UnsupportedAEADAlgorithm(a).into()),
        };

        let mut ctx = OsslCipher::new(
            &ctx,
            alg,
            enc,
            key.into(),
            iv.map(|iv| iv.to_vec()),
            aead)?;

        if let Some(p) = padding {
            ctx.set_padding(p)?;
        }

        Ok(Self { ctx })
    }
}

impl Context for OpenSslMode {
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        // Note that for cipher constructions that OpenSSL considers
        // "streaming" (such as CFB mode) the block size will be
        // always "1" instead of the real block size of the underlying
        // cipher.
        if let Some(block_size) = self.ctx.block_size() {
            // SAFETY: If this is a block cipher we require the source length
            // to be a multiple of the block size.
            if block_size > 1 && src.len() % block_size > 0 {
                return Err(Error::InvalidArgument(
                    "src needs to be a multiple of the block size".into()).into());
            }
        }

        // SAFETY: `dst` must be big enough to hold decrypted data.
        if dst.len() < src.len() {
            return Err(Error::InvalidArgument(
                "dst need to be big enough to hold decrypted data".into(),
            )
            .into());
        }

        // SAFETY: This call is safe because either:
        //
        // - this is a streaming cipher (block_size == 1),
        // - or a block cipher (block_size > 1) and `src` and `dst`
        //   are a multiple of the block size, and we don't use any
        //   padding.
        debug_assert_eq!(dst.len(), src.len());
        self.ctx.update(src, dst)?;

        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        self.encrypt(dst, src)
    }
}
