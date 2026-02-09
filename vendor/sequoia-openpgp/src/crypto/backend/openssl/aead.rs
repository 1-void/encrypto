//! Implementation of AEAD using OpenSSL cryptographic library.

use crate::Result;

use crate::crypto::aead::{Context, CipherOp};
use crate::crypto::mem::Protected;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use super::symmetric::{OpenSslMode, OsslMode};

#[derive(Debug)]
struct OpenSslContext {
    ctx: OpenSslMode,
    digest_size: usize,
}

impl Context for OpenSslContext {
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());

        // Split dst into ciphertext and tag.
        let (ciphertext, tag) =
            dst.split_at_mut(dst.len().saturating_sub(self.digest_size()));
        debug_assert_eq!(ciphertext.len(), src.len());

        let written = self.ctx.ctx.update(src, ciphertext)?;
        self.ctx.ctx.finalize(&mut ciphertext[written..])?;
        self.ctx.ctx.get_tag(tag)?;

        Ok(())
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert!(src.len() >= self.digest_size());
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());

        // Split src into ciphertext and tag.
        let (ciphertext, tag) =
            src.split_at(src.len().saturating_sub(self.digest_size()));

        let written = self.ctx.ctx.update(ciphertext, dst)?;
        self.ctx.ctx.set_tag(tag)?;
        let finalized = self.ctx.ctx.finalize(&mut dst[written..])?;

        debug_assert_eq!(written + finalized, dst.len());
        Ok(())
    }

    fn digest_size(&self) -> usize {
        self.digest_size
    }
}

impl crate::seal::Sealed for OpenSslContext {}


impl crate::crypto::backend::interface::Aead for super::Backend {
    fn supports_algo(algo: AEADAlgorithm) -> bool {
        // First, check whether support is compiled in or not.
        (match algo {
            AEADAlgorithm::EAX => false,
            AEADAlgorithm::OCB => true,
            AEADAlgorithm::GCM => true,
            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }) && {
            // Then, check whether it has been disabled at runtime,
            // for example by putting OpenSSL into FIPS mode.
            use std::sync::OnceLock;

            static MODES: [OnceLock<bool>; 3] = [const { OnceLock::new() }; 3];
            MODES.get(u8::from(algo) as usize - 1)
                .map(|cell| cell.get_or_init(|| {
                    let symm = SymmetricAlgorithm::AES128;
                    let key = Protected::from([0; 16]);
                    let nonce = &key[..algo.nonce_size().unwrap_or(16)];

                    Self::context(algo, symm, &key, &[], nonce,
                                  crate::crypto::aead::CipherOp::Encrypt)
                        .is_ok()
                }))
                .cloned()
                .unwrap_or(false)
        }
    }

    fn supports_algo_with_symmetric(algo: AEADAlgorithm,
                                    symm: SymmetricAlgorithm)
                                    -> bool
    {
        match algo {
            AEADAlgorithm::EAX => false,

            AEADAlgorithm::OCB => match symm {
                // OpenSSL supports OCB only with AES
                // see: https://wiki.openssl.org/index.php/OCB
                SymmetricAlgorithm::AES128 |
                SymmetricAlgorithm::AES192 |
                SymmetricAlgorithm::AES256 => true,
                _ => false,
            },

            AEADAlgorithm::GCM => match symm {
                // OpenSSL supports GCM only with AES
                // see: https://wiki.openssl.org/index.php/GCM
                SymmetricAlgorithm::AES128 |
                SymmetricAlgorithm::AES192 |
                SymmetricAlgorithm::AES256 => true,
                _ => false,
            },

            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }
    }

    fn context(
        algo: AEADAlgorithm,
        sym_algo: SymmetricAlgorithm,
        key: &Protected,
        aad: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Context>> {
        Ok(Box::new(OpenSslContext {
            ctx: OpenSslMode::new(
                sym_algo,
                OsslMode::Authenticated(algo, aad.to_vec()),
                None,
                match op {
                    CipherOp::Encrypt => true,
                    CipherOp::Decrypt => false,
                },
                key,
                Some(std::borrow::Cow::Borrowed(nonce)))?,
            digest_size: algo.digest_size()?,
        }))
    }
}
