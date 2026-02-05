use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, EncryptoError, KeyGenParams, KeyId, KeyMeta, PqcLevel,
    PqcPolicy, RevocationReason, RevokeRequest, RevokeResult, RotateRequest, RotateResult,
    SignRequest, UserId, VerifyRequest, VerifyResult,
};
use encrypto_policy::{
    cert_has_pqc_encryption_key, cert_has_pqc_signing_key, cert_is_pqc_only,
    ensure_pqc_encryption_output, ensure_pqc_signature_output, is_pqc_kem_algo, is_pqc_sign_algo,
    pqc_kem_key_version_ok, pqc_sign_key_version_ok,
};
use openpgp::armor::{Kind as ArmorKind, Writer as ArmorWriter};
use openpgp::cert::prelude::*;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageStructure,
    VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::types::ReasonForRevocation;
use openpgp::types::{PublicKeyAlgorithm, SymmetricAlgorithm};
use openpgp::{Cert, KeyHandle, KeyID, Profile};
use sequoia_openpgp as openpgp;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;

#[derive(Clone)]
pub struct NativeBackend {
    home: PathBuf,
    pqc_policy: PqcPolicy,
    passphrase: Option<Password>,
}

impl NativeBackend {
    pub fn new(pqc_policy: PqcPolicy) -> Self {
        Self::with_passphrase(pqc_policy, None)
    }

    pub fn with_passphrase(pqc_policy: PqcPolicy, passphrase: Option<String>) -> Self {
        let home = resolve_native_home();
        let passphrase = passphrase.map(Password::from);
        Self {
            home,
            pqc_policy,
            passphrase,
        }
    }

    fn ensure_pqc_only(&self, policy: &PqcPolicy) -> Result<(), EncryptoError> {
        if !matches!(self.pqc_policy, PqcPolicy::Required) || !matches!(policy, PqcPolicy::Required)
        {
            return Err(EncryptoError::InvalidInput(
                "PQC-only build requires PqcPolicy::Required".to_string(),
            ));
        }
        Ok(())
    }

    fn ensure_dirs(&self) -> Result<(), EncryptoError> {
        fs::create_dir_all(self.public_dir())
            .map_err(|err| EncryptoError::Io(format!("create dir failed: {err}")))?;
        fs::create_dir_all(self.secret_dir())
            .map_err(|err| EncryptoError::Io(format!("create dir failed: {err}")))?;
        Ok(())
    }

    fn public_dir(&self) -> PathBuf {
        self.home.join("public")
    }

    fn secret_dir(&self) -> PathBuf {
        self.home.join("secret")
    }

    fn load_all_certs(&self) -> Result<Vec<Cert>, EncryptoError> {
        let mut certs: HashMap<String, Cert> = HashMap::new();
        for cert in self.load_certs_from_dir(&self.public_dir())? {
            certs.insert(cert.fingerprint().to_hex(), cert);
        }
        for cert in self.load_certs_from_dir(&self.secret_dir())? {
            certs.insert(cert.fingerprint().to_hex(), cert);
        }
        Ok(certs.into_values().collect())
    }

    fn load_secret_certs(&self) -> Result<Vec<Cert>, EncryptoError> {
        self.load_certs_from_dir(&self.secret_dir())
    }

    fn load_certs_from_dir(&self, dir: &Path) -> Result<Vec<Cert>, EncryptoError> {
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut certs = Vec::new();
        for entry in
            fs::read_dir(dir).map_err(|err| EncryptoError::Io(format!("read dir failed: {err}")))?
        {
            let entry =
                entry.map_err(|err| EncryptoError::Io(format!("read dir failed: {err}")))?;
            if !entry
                .file_type()
                .map_err(|err| EncryptoError::Io(format!("stat failed: {err}")))?
                .is_file()
            {
                continue;
            }
            let bytes = fs::read(entry.path())
                .map_err(|err| EncryptoError::Io(format!("read failed: {err}")))?;
            let ppr = openpgp::parse::PacketParser::from_bytes(&bytes)
                .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?;
            for cert in openpgp::cert::CertParser::from(ppr) {
                match cert {
                    Ok(cert) => {
                        if !cert_is_pqc_only(&cert) {
                            return Err(EncryptoError::InvalidInput(
                                "non-PQC key material found; PQC-only build".to_string(),
                            ));
                        }
                        certs.push(cert);
                    }
                    Err(err) => {
                        return Err(EncryptoError::Backend(format!(
                            "invalid certificate: {err}"
                        )));
                    }
                }
            }
        }

        Ok(certs)
    }

    fn store_cert(&self, cert: &Cert, secret: bool) -> Result<(), EncryptoError> {
        self.ensure_dirs()?;
        let fingerprint = cert.fingerprint().to_hex();
        let dir = if secret {
            self.secret_dir()
        } else {
            self.public_dir()
        };
        let path = dir.join(format!("{fingerprint}.pgp"));
        let bytes = if secret {
            cert.as_tsk()
                .to_vec()
                .map_err(|err| EncryptoError::Backend(format!("serialize failed: {err}")))?
        } else {
            cert.to_vec()
                .map_err(|err| EncryptoError::Backend(format!("serialize failed: {err}")))?
        };
        fs::write(&path, bytes).map_err(|err| EncryptoError::Io(format!("write failed: {err}")))?;
        #[cfg(unix)]
        if secret {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)
                .map_err(|err| EncryptoError::Io(format!("stat failed: {err}")))?
                .permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)
                .map_err(|err| EncryptoError::Io(format!("chmod failed: {err}")))?;
        }
        Ok(())
    }

    fn find_cert(&self, id: &KeyId, secret_only: bool) -> Result<Cert, EncryptoError> {
        let needle = normalize_id(&id.0);
        if needle.is_empty() {
            return Err(EncryptoError::InvalidInput("empty key id".to_string()));
        }
        let mut matches = Vec::new();
        let certs = if secret_only {
            self.load_secret_certs()?
        } else {
            self.load_all_certs()?
        };

        for cert in certs {
            if cert_matches(&cert, &needle, &id.0) {
                matches.push(cert);
            }
        }

        match matches.len() {
            0 => Err(EncryptoError::InvalidInput(format!(
                "key not found: {}",
                id.0
            ))),
            1 => Ok(matches.remove(0)),
            _ => Err(EncryptoError::InvalidInput(format!(
                "key id is ambiguous: {}",
                id.0
            ))),
        }
    }

    fn meta_from_cert(&self, cert: &Cert) -> KeyMeta {
        let algo = format!("{:?}", cert.primary_key().key().pk_algo());
        let created_utc = cert
            .primary_key()
            .key()
            .creation_time()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs().to_string());
        let user_id = cert
            .userids()
            .next()
            .map(|u| UserId(u.userid().to_string()));
        KeyMeta {
            key_id: KeyId(cert.fingerprint().to_hex()),
            user_id,
            algo,
            created_utc,
        }
    }

    fn select_cipher_suite(&self, params: &KeyGenParams) -> Result<CipherSuite, EncryptoError> {
        let prefer_pqc = matches!(
            params.pqc_policy,
            PqcPolicy::Preferred | PqcPolicy::Required
        ) || matches!(self.pqc_policy, PqcPolicy::Preferred | PqcPolicy::Required);

        if prefer_pqc {
            let suite = match params.pqc_level {
                PqcLevel::Baseline => CipherSuite::MLDSA65_Ed25519,
                PqcLevel::High => CipherSuite::MLDSA87_Ed448,
            };
            if pqc_available_for_suite(suite) {
                return Ok(suite);
            }
            if matches!(params.pqc_level, PqcLevel::High) && pqc_available() {
                return Ok(CipherSuite::MLDSA65_Ed25519);
            }
            if matches!(params.pqc_policy, PqcPolicy::Required)
                || matches!(self.pqc_policy, PqcPolicy::Required)
            {
                return Err(pqc_required_error());
            }
        }

        Ok(CipherSuite::Cv25519)
    }

    fn export_cert_bytes(
        &self,
        cert: &Cert,
        secret: bool,
        armor: bool,
    ) -> Result<Vec<u8>, EncryptoError> {
        if armor {
            let kind = if secret {
                ArmorKind::SecretKey
            } else {
                ArmorKind::PublicKey
            };
            let mut writer = ArmorWriter::new(Vec::new(), kind)
                .map_err(|err| EncryptoError::Backend(format!("armor failed: {err}")))?;
            if secret {
                cert.as_tsk()
                    .serialize(&mut writer)
                    .map_err(|err| EncryptoError::Backend(format!("serialize failed: {err}")))?;
            } else {
                cert.serialize(&mut writer)
                    .map_err(|err| EncryptoError::Backend(format!("serialize failed: {err}")))?;
            }
            let output = writer
                .finalize()
                .map_err(|err| EncryptoError::Backend(format!("armor finalize failed: {err}")))?;
            return Ok(output);
        }

        if secret {
            cert.as_tsk()
                .to_vec()
                .map_err(|err| EncryptoError::Backend(format!("serialize failed: {err}")))
        } else {
            cert.to_vec()
                .map_err(|err| EncryptoError::Backend(format!("serialize failed: {err}")))
        }
    }

    fn build_signer<'a>(
        &self,
        mut message: Message<'a>,
        armor: bool,
        keypair: openpgp::crypto::KeyPair,
    ) -> Result<Message<'a>, EncryptoError> {
        if armor {
            message = Armorer::new(message)
                .kind(ArmorKind::Signature)
                .build()
                .map_err(|err| EncryptoError::Backend(format!("armor failed: {err}")))?;
        }
        Signer::new(message, keypair)
            .map_err(|err| EncryptoError::Backend(format!("signer failed: {err}")))?
            .detached()
            .build()
            .map_err(|err| EncryptoError::Backend(format!("signer build failed: {err}")))
    }
}

impl std::fmt::Debug for NativeBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeBackend")
            .field("home", &self.home)
            .field("pqc_policy", &self.pqc_policy)
            .field("passphrase_set", &self.passphrase.is_some())
            .finish()
    }
}

impl Default for NativeBackend {
    fn default() -> Self {
        Self::new(PqcPolicy::Required)
    }
}

pub fn pqc_algorithms_supported() -> Vec<(&'static str, bool)> {
    use PublicKeyAlgorithm::*;
    vec![
        ("MLDSA65_Ed25519", MLDSA65_Ed25519.is_supported()),
        ("MLDSA87_Ed448", MLDSA87_Ed448.is_supported()),
        ("SLHDSA128s", SLHDSA128s.is_supported()),
        ("SLHDSA128f", SLHDSA128f.is_supported()),
        ("SLHDSA256s", SLHDSA256s.is_supported()),
        ("MLKEM768_X25519", MLKEM768_X25519.is_supported()),
        ("MLKEM1024_X448", MLKEM1024_X448.is_supported()),
    ]
}

impl Backend for NativeBackend {
    fn name(&self) -> &'static str {
        "native"
    }

    fn supports_pqc(&self) -> bool {
        pqc_available()
    }

    fn list_keys(&self) -> Result<Vec<KeyMeta>, EncryptoError> {
        self.ensure_pqc_only(&self.pqc_policy)?;
        let mut keys = Vec::new();
        for cert in self.load_all_certs()? {
            keys.push(self.meta_from_cert(&cert));
        }
        Ok(keys)
    }

    fn generate_key(&self, params: KeyGenParams) -> Result<KeyMeta, EncryptoError> {
        self.ensure_pqc_only(&params.pqc_policy)?;
        self.ensure_dirs()?;

        if (matches!(params.pqc_policy, PqcPolicy::Required)
            || matches!(self.pqc_policy, PqcPolicy::Required))
            && !self.supports_pqc()
        {
            return Err(pqc_required_error());
        }

        let mut builder = CertBuilder::general_purpose(Some(params.user_id.0.clone()));
        builder = builder
            .set_profile(Profile::RFC9580)
            .map_err(|err| EncryptoError::Backend(format!("profile failed: {err}")))?;

        let suite = self.select_cipher_suite(&params)?;
        builder = builder.set_cipher_suite(suite);
        let password = params
            .passphrase
            .map(Password::from)
            .or_else(|| self.passphrase.clone());
        if password.is_none() && !params.allow_unprotected {
            return Err(EncryptoError::InvalidInput(
                "passphrase required; use --no-passphrase to override".to_string(),
            ));
        }
        if password.is_some() {
            builder = builder.set_password(password);
        }

        let (cert, _rev) = builder
            .generate()
            .map_err(|err| EncryptoError::Backend(format!("keygen failed: {err}")))?;

        self.store_cert(&cert, true)?;
        self.store_cert(&cert, false)?;

        Ok(self.meta_from_cert(&cert))
    }

    fn import_key(&self, bytes: &[u8]) -> Result<KeyMeta, EncryptoError> {
        self.ensure_pqc_only(&self.pqc_policy)?;
        self.ensure_dirs()?;

        let ppr = openpgp::parse::PacketParser::from_bytes(bytes)
            .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?;
        let mut certs = Vec::new();
        for cert in openpgp::cert::CertParser::from(ppr) {
            match cert {
                Ok(cert) => certs.push(cert),
                Err(err) => {
                    return Err(EncryptoError::Backend(format!(
                        "invalid certificate: {err}"
                    )));
                }
            }
        }

        if certs.is_empty() {
            return Err(EncryptoError::InvalidInput(
                "no certificates found".to_string(),
            ));
        }

        for cert in &certs {
            if !cert_is_pqc_only(cert) {
                return Err(EncryptoError::InvalidInput(
                    "non-PQC key material found; PQC-only build".to_string(),
                ));
            }
            if cert.is_tsk() {
                self.store_cert(cert, true)?;
                self.store_cert(cert, false)?;
            } else {
                self.store_cert(cert, false)?;
            }
        }

        Ok(self.meta_from_cert(&certs[0]))
    }

    fn export_key(&self, id: &KeyId, secret: bool) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_only(&self.pqc_policy)?;
        let cert = self.find_cert(id, secret)?;
        if secret && !cert.is_tsk() {
            return Err(EncryptoError::InvalidInput(
                "secret key not available".to_string(),
            ));
        }
        self.export_cert_bytes(&cert, secret, false)
    }

    fn encrypt(&self, req: EncryptRequest) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_only(&req.pqc_policy)?;
        if matches!(req.pqc_policy, PqcPolicy::Required) && !self.supports_pqc() {
            return Err(pqc_required_error());
        }
        if req.compat {
            return Err(EncryptoError::InvalidInput(
                "compat mode is not allowed in a PQC-only build".to_string(),
            ));
        }

        let mut certs = Vec::new();
        for recipient in &req.recipients {
            certs.push(self.find_cert(recipient, false)?);
        }

        if matches!(req.pqc_policy, PqcPolicy::Required)
            && !certs.iter().all(cert_has_pqc_encryption_key)
        {
            return Err(EncryptoError::InvalidInput(
                "PQC required but one or more recipient keys are not PQC".to_string(),
            ));
        }

        let prefer_pqc = matches!(req.pqc_policy, PqcPolicy::Preferred | PqcPolicy::Required);
        let policy = StandardPolicy::new();
        let mut recipients: Vec<openpgp::serialize::stream::Recipient<'_>> = Vec::new();
        for cert in &certs {
            let mut pqc_keys = Vec::new();
            let mut classic_keys = Vec::new();
            for key in cert
                .keys()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
            {
                let algo = key.key().pk_algo();
                let version = key.key().version();
                if is_pqc_kem_algo(algo) && pqc_kem_key_version_ok(algo, version) {
                    pqc_keys.push(key);
                } else {
                    if is_pqc_kem_algo(algo) && std::env::var_os("ENCRYPTO_DEBUG").is_some() {
                        eprintln!(
                            "pqc: ignoring encryption key with unsupported version v{version} ({algo:?})"
                        );
                    }
                    classic_keys.push(key);
                }
            }

            if req.compat && !matches!(req.pqc_policy, PqcPolicy::Disabled) {
                if matches!(req.pqc_policy, PqcPolicy::Required) && pqc_keys.is_empty() {
                    return Err(EncryptoError::InvalidInput(
                        "PQC required but recipient has no PQC encryption keys".to_string(),
                    ));
                }
                let pqc_key = pqc_keys.into_iter().next();
                let classic_key = classic_keys.into_iter().next();
                if pqc_key.is_none() && classic_key.is_none() {
                    return Err(EncryptoError::InvalidInput(
                        "no encryption-capable keys found".to_string(),
                    ));
                }
                if let Some(key) = pqc_key {
                    recipients.push(key.into());
                }
                if let Some(key) = classic_key {
                    recipients.push(key.into());
                }
            } else {
                let selected = if matches!(req.pqc_policy, PqcPolicy::Required) {
                    if pqc_keys.is_empty() {
                        return Err(EncryptoError::InvalidInput(
                            "PQC required but recipient has no PQC encryption keys".to_string(),
                        ));
                    }
                    pqc_keys
                } else if prefer_pqc && !pqc_keys.is_empty() {
                    pqc_keys
                } else if !classic_keys.is_empty() {
                    classic_keys
                } else {
                    pqc_keys
                };

                let key = selected.into_iter().next().ok_or_else(|| {
                    EncryptoError::InvalidInput("no encryption-capable keys found".to_string())
                })?;
                recipients.push(key.into());
            }
        }
        if recipients.is_empty() {
            return Err(EncryptoError::InvalidInput(
                "no encryption-capable keys found".to_string(),
            ));
        }

        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let mut message = message;
        if req.armor {
            message = Armorer::new(message)
                .build()
                .map_err(|err| EncryptoError::Backend(format!("armor failed: {err}")))?;
        }

        let message = Encryptor::for_recipients(message, recipients)
            .build()
            .map_err(|err| EncryptoError::Backend(format!("encryptor failed: {err}")))?;
        let mut message = LiteralWriter::new(message)
            .build()
            .map_err(|err| EncryptoError::Backend(format!("literal writer failed: {err}")))?;
        message
            .write_all(&req.plaintext)
            .map_err(|err| EncryptoError::Io(format!("write failed: {err}")))?;
        message
            .finalize()
            .map_err(|err| EncryptoError::Backend(format!("finalize failed: {err}")))?;
        if matches!(req.pqc_policy, PqcPolicy::Required) {
            ensure_pqc_encryption_output(&sink).map_err(policy_error)?;
        }
        Ok(sink)
    }

    fn decrypt(&self, req: DecryptRequest) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_only(&req.pqc_policy)?;
        if matches!(req.pqc_policy, PqcPolicy::Required) && !self.supports_pqc() {
            return Err(pqc_required_error());
        }
        if matches!(req.pqc_policy, PqcPolicy::Required) {
            ensure_pqc_encryption_output(&req.ciphertext).map_err(policy_error)?;
        }
        let certs = self.load_all_certs()?;
        let has_encrypted_secret = certs.iter().any(|cert| {
            cert.keys()
                .secret()
                .any(|key| key.key().secret().is_encrypted())
        });
        let helper = NativeHelper::new(certs, self.passphrase.clone());
        let p = &StandardPolicy::new();
        let mut decryptor = DecryptorBuilder::from_bytes(&req.ciphertext)
            .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?
            .with_policy(p, None, helper)
            .map_err(|err| EncryptoError::Backend(format!("decryptor failed: {err}")))?;

        let mut out = Vec::new();
        if let Err(err) = decryptor.read_to_end(&mut out) {
            if self.passphrase.is_none() && has_encrypted_secret {
                return Err(EncryptoError::InvalidInput(
                    "secret key is encrypted; passphrase required".to_string(),
                ));
            }
            return Err(EncryptoError::Io(format!("read failed: {err}")));
        }
        Ok(out)
    }

    fn sign(&self, req: SignRequest) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_only(&req.pqc_policy)?;
        let cert = self.find_cert(&req.signer, true)?;
        if matches!(req.pqc_policy, PqcPolicy::Required) && !cert_has_pqc_signing_key(&cert) {
            return Err(EncryptoError::InvalidInput(
                "PQC required but signing key is not PQC".to_string(),
            ));
        }

        let prefer_pqc = matches!(req.pqc_policy, PqcPolicy::Preferred | PqcPolicy::Required);
        let p = &StandardPolicy::new();
        let mut pqc_keys = Vec::new();
        let mut classic_keys = Vec::new();
        for key in cert
            .keys()
            .secret()
            .with_policy(p, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
        {
            let algo = key.key().pk_algo();
            let version = key.key().version();
            if is_pqc_sign_algo(algo) && pqc_sign_key_version_ok(version) {
                pqc_keys.push(key);
            } else {
                if is_pqc_sign_algo(algo) && std::env::var_os("ENCRYPTO_DEBUG").is_some() {
                    eprintln!(
                        "pqc: ignoring signing key with unsupported version v{version} ({algo:?})"
                    );
                }
                classic_keys.push(key);
            }
        }

        let mut candidates = if matches!(req.pqc_policy, PqcPolicy::Required) {
            if pqc_keys.is_empty() {
                return Err(EncryptoError::InvalidInput(
                    "PQC required but no PQC signing keys found".to_string(),
                ));
            }
            pqc_keys
        } else if prefer_pqc && !pqc_keys.is_empty() {
            pqc_keys
        } else {
            let mut all = Vec::with_capacity(pqc_keys.len() + classic_keys.len());
            all.extend(pqc_keys);
            all.extend(classic_keys);
            all
        };

        let key = candidates
            .pop()
            .ok_or_else(|| EncryptoError::InvalidInput("no signing key found".to_string()))?;
        let mut key = key.key().clone();
        if key.secret().is_encrypted() {
            let passphrase = self.passphrase.as_ref().ok_or_else(|| {
                EncryptoError::InvalidInput(
                    "signing key is encrypted; passphrase required".to_string(),
                )
            })?;
            key = key
                .decrypt_secret(passphrase)
                .map_err(|err| EncryptoError::InvalidInput(format!("key decrypt failed: {err}")))?;
        }
        let keypair = key
            .into_keypair()
            .map_err(|err| EncryptoError::Backend(format!("keypair failed: {err}")))?;

        let mut sink = Vec::new();
        let message = Message::new(&mut sink);
        let mut message = self.build_signer(message, req.armor, keypair)?;
        message
            .write_all(&req.message)
            .map_err(|err| EncryptoError::Io(format!("write failed: {err}")))?;
        message
            .finalize()
            .map_err(|err| EncryptoError::Backend(format!("finalize failed: {err}")))?;
        if matches!(req.pqc_policy, PqcPolicy::Required) {
            ensure_pqc_signature_output(&sink).map_err(policy_error)?;
        }
        Ok(sink)
    }

    fn verify(&self, req: VerifyRequest) -> Result<VerifyResult, EncryptoError> {
        self.ensure_pqc_only(&req.pqc_policy)?;
        let require_pqc = matches!(req.pqc_policy, PqcPolicy::Required)
            || matches!(self.pqc_policy, PqcPolicy::Required);
        if require_pqc {
            ensure_pqc_signature_output(&req.signature).map_err(policy_error)?;
        }
        let certs = self.load_all_certs()?;
        let helper = NativeHelper::new(certs, self.passphrase.clone());
        let p = &StandardPolicy::new();
        let mut verifier = DetachedVerifierBuilder::from_bytes(&req.signature)
            .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?
            .with_policy(p, None, helper)
            .map_err(|err| EncryptoError::Backend(format!("verifier failed: {err}")))?;

        let valid = verifier.verify_bytes(&req.message).is_ok();

        Ok(VerifyResult {
            valid,
            signer: None,
        })
    }

    fn revoke_key(&self, req: RevokeRequest) -> Result<RevokeResult, EncryptoError> {
        self.ensure_pqc_only(&self.pqc_policy)?;
        let cert = self.find_cert(&req.key_id, true)?;
        if !cert.is_tsk() {
            return Err(EncryptoError::InvalidInput(
                "secret key not available for revocation".to_string(),
            ));
        }

        let mut key = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .map_err(|err| EncryptoError::Backend(format!("secret key load failed: {err}")))?;
        if key.secret().is_encrypted() {
            let passphrase = self.passphrase.as_ref().ok_or_else(|| {
                EncryptoError::InvalidInput(
                    "secret key is encrypted; passphrase required".to_string(),
                )
            })?;
            key = key
                .decrypt_secret(passphrase)
                .map_err(|err| EncryptoError::InvalidInput(format!("key decrypt failed: {err}")))?;
        }
        let mut keypair = key
            .into_keypair()
            .map_err(|err| EncryptoError::Backend(format!("keypair failed: {err}")))?;

        let reason = map_revocation_reason(req.reason);
        let message = req
            .message
            .unwrap_or_else(|| "revoked by encrypto".to_string());
        let rev = cert
            .revoke(&mut keypair, reason, message.as_bytes())
            .map_err(|err| EncryptoError::Backend(format!("revocation failed: {err}")))?;
        let (revoked_cert, _) = cert
            .clone()
            .insert_packets(rev)
            .map_err(|err| EncryptoError::Backend(format!("revocation insert failed: {err}")))?;

        self.store_cert(&revoked_cert, true)?;
        self.store_cert(&revoked_cert, false)?;

        let updated = self.export_cert_bytes(&revoked_cert, false, req.armor)?;
        Ok(RevokeResult {
            updated_cert: updated,
        })
    }

    fn rotate_key(&self, req: RotateRequest) -> Result<RotateResult, EncryptoError> {
        self.ensure_pqc_only(&req.pqc_policy)?;
        let cert = self.find_cert(&req.key_id, false)?;
        let user_id = match req.new_user_id {
            Some(uid) => uid,
            None => cert
                .userids()
                .next()
                .map(|u| UserId(u.userid().to_string()))
                .ok_or_else(|| {
                    EncryptoError::InvalidInput("cannot rotate key without a user id".to_string())
                })?,
        };

        let params = KeyGenParams {
            user_id,
            algo: None,
            pqc_policy: req.pqc_policy,
            pqc_level: req.pqc_level,
            passphrase: req.passphrase.clone(),
            allow_unprotected: req.allow_unprotected,
        };
        let new_key = self.generate_key(params)?;

        let mut revoked = false;
        if req.revoke_old {
            let _ = self.revoke_key(RevokeRequest {
                key_id: req.key_id,
                reason: RevocationReason::KeySuperseded,
                message: Some("superseded by key rotation".to_string()),
                armor: false,
            })?;
            revoked = true;
        }

        Ok(RotateResult {
            new_key,
            old_key_revoked: revoked,
        })
    }
}

struct NativeHelper {
    certs: Vec<Cert>,
    passphrase: Option<Password>,
}

impl NativeHelper {
    fn new(certs: Vec<Cert>, passphrase: Option<Password>) -> Self {
        Self { certs, passphrase }
    }
}

impl VerificationHelper for NativeHelper {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        if ids.is_empty() {
            return Ok(self.certs.clone());
        }
        let mut matches = Vec::new();
        for cert in &self.certs {
            let fpr = cert.fingerprint();
            if ids.iter().any(|id| fpr.aliases(id)) {
                matches.push(cert.clone());
            }
        }
        Ok(matches)
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for NativeHelper {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        for pkesk in pkesks {
            for cert in &self.certs {
                let policy = StandardPolicy::new();
                for key in cert
                    .keys()
                    .secret()
                    .with_policy(&policy, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .for_transport_encryption()
                {
                    let mut key = key.key().clone();
                    if key.secret().is_encrypted() {
                        let passphrase = match self.passphrase.as_ref() {
                            Some(passphrase) => passphrase,
                            None => continue,
                        };
                        match key.decrypt_secret(passphrase) {
                            Ok(decrypted) => key = decrypted,
                            Err(_) => continue,
                        }
                    }
                    let mut keypair = key.into_keypair()?;
                    if let Some((algo, sk)) = pkesk.decrypt(&mut keypair, sym_algo) {
                        if decrypt(algo, &sk) {
                            return Ok(Some(cert.clone()));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

fn resolve_native_home() -> PathBuf {
    if let Ok(value) = std::env::var("ENCRYPTO_HOME") {
        return PathBuf::from(value);
    }
    if let Some(dir) = dirs::data_local_dir() {
        return dir.join("encrypto");
    }
    PathBuf::from(".encrypto")
}

fn pqc_available() -> bool {
    static PQC_AVAILABLE: OnceLock<bool> = OnceLock::new();
    *PQC_AVAILABLE.get_or_init(|| pqc_available_for_suite(CipherSuite::MLDSA65_Ed25519))
}

fn pqc_available_for_suite(suite: CipherSuite) -> bool {
    let debug = std::env::var_os("ENCRYPTO_DEBUG").is_some();
    if let Err(err) = suite.is_supported() {
        if debug {
            eprintln!("pqc: {suite:?} unsupported: {err:?}");
        }
        return false;
    }
    let builder =
        match CertBuilder::general_purpose(Some("pqc-probe")).set_profile(Profile::RFC9580) {
            Ok(builder) => builder,
            Err(_) => return false,
        };
    match builder.set_cipher_suite(suite).generate() {
        Ok(_) => true,
        Err(err) => {
            if debug {
                eprintln!("pqc: {suite:?} keygen probe failed: {err:?}");
                let mut source = err.source();
                while let Some(inner) = source {
                    eprintln!("pqc: caused by: {inner}");
                    source = inner.source();
                }
            }
            false
        }
    }
}

fn pqc_required_error() -> EncryptoError {
    EncryptoError::Backend(
        "PQC required but PQC algorithms are not available (install OpenSSL 3.5+ with PQC support)"
            .to_string(),
    )
}

fn normalize_id(input: &str) -> String {
    input
        .trim()
        .trim_start_matches("0x")
        .replace(' ', "")
        .replace('\t', "")
        .to_uppercase()
}

fn policy_error(err: encrypto_policy::PolicyError) -> EncryptoError {
    EncryptoError::Backend(err.to_string())
}

fn map_revocation_reason(reason: RevocationReason) -> ReasonForRevocation {
    match reason {
        RevocationReason::Unspecified => ReasonForRevocation::Unspecified,
        RevocationReason::KeyCompromised => ReasonForRevocation::KeyCompromised,
        RevocationReason::KeySuperseded => ReasonForRevocation::KeySuperseded,
        RevocationReason::KeyRetired => ReasonForRevocation::KeyRetired,
        RevocationReason::UserIdInvalid => ReasonForRevocation::UIDRetired,
    }
}

fn cert_matches(cert: &Cert, needle_hex: &str, needle_raw: &str) -> bool {
    let fpr = cert.fingerprint();
    let fpr_hex = fpr.to_hex();
    let keyid_hex = KeyID::from(&fpr).to_hex();

    if fpr_hex == needle_hex || keyid_hex == needle_hex {
        return true;
    }
    if fpr_hex.ends_with(needle_hex) || keyid_hex.ends_with(needle_hex) {
        return true;
    }

    let needle_raw = needle_raw.to_lowercase();
    cert.userids()
        .any(|u| u.userid().to_string().to_lowercase().contains(&needle_raw))
}
