use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, EncryptoError, KeyGenParams, KeyId, KeyMeta, PqcLevel,
    PqcPolicy, RevocationReason, RevokeRequest, RevokeResult, RotateRequest, RotateResult,
    SignRequest, UserId, VerifyRequest, VerifyResult,
};
use encrypto_policy::{
    cert_has_pqc_encryption_key, cert_has_pqc_signing_key, cert_is_pqc_only,
    ensure_pqc_encryption_output, ensure_pqc_signature_output, hash_is_pqc_ok, is_pqc_kem_algo,
    is_pqc_sign_algo, pqc_kem_key_version_ok, pqc_sign_key_version_ok,
};
use openpgp::armor::{Kind as ArmorKind, Writer as ArmorWriter};
use openpgp::cert::prelude::*;
use openpgp::crypto::{Password, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::types::ReasonForRevocation;
use openpgp::types::{AEADAlgorithm, PublicKeyAlgorithm, SymmetricAlgorithm};
use openpgp::{Cert, KeyHandle, KeyID, Packet, PacketPile, Profile};
use sequoia_openpgp as openpgp;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::UNIX_EPOCH;
use tempfile::NamedTempFile;

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

    fn ensure_absolute_home(&self) -> Result<(), EncryptoError> {
        if self.home.is_absolute() {
            return Ok(());
        }
        if std::env::var_os("ENCRYPTO_ALLOW_RELATIVE_HOME").is_some() {
            return Ok(());
        }
        Err(EncryptoError::InvalidInput(
            "ENCRYPTO_HOME must be an absolute path (set ENCRYPTO_ALLOW_RELATIVE_HOME=1 to override)"
                .to_string(),
        ))
    }

    fn ensure_dirs(&self) -> Result<(), EncryptoError> {
        self.ensure_absolute_home()?;
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
        self.ensure_absolute_home()?;
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
        self.ensure_absolute_home()?;
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
        let mode = if secret { 0o600 } else { 0o644 };
        write_atomic(&path, &bytes, mode)?;
        Ok(())
    }

    fn find_cert_candidates(
        &self,
        selector: &str,
        secret_only: bool,
    ) -> Result<Vec<Cert>, EncryptoError> {
        let needle = normalize_id(selector);
        if needle.is_empty() {
            return Err(EncryptoError::InvalidInput("empty key id".to_string()));
        }
        let certs = if secret_only {
            self.load_secret_certs()?
        } else {
            self.load_all_certs()?
        };
        Ok(certs
            .into_iter()
            .filter(|cert| cert_matches(cert, &needle, selector))
            .collect())
    }

    fn find_cert_strict(&self, id: &KeyId, secret_only: bool) -> Result<Cert, EncryptoError> {
        let needle = normalize_id(&id.0);
        if !is_full_fingerprint(&needle) {
            let matches = self.find_cert_candidates(&id.0, secret_only)?;
            if matches.is_empty() {
                return Err(EncryptoError::InvalidInput(format!(
                    "full fingerprint required; no matches for {}",
                    id.0
                )));
            }
            let mut lines = Vec::new();
            for cert in matches {
                let user = cert
                    .userids()
                    .next()
                    .map(|u| u.userid().to_string())
                    .unwrap_or_else(|| "(no user id)".to_string());
                lines.push(format!("{} | {}", cert.fingerprint().to_hex(), user));
            }
            return Err(EncryptoError::InvalidInput(format!(
                "full fingerprint required; matches:\n{}",
                lines.join("\n")
            )));
        }

        let certs = if secret_only {
            self.load_secret_certs()?
        } else {
            self.load_all_certs()?
        };
        for cert in certs {
            if normalize_id(&cert.fingerprint().to_hex()) == needle {
                return Ok(cert);
            }
        }
        if secret_only {
            let certs = self.load_all_certs()?;
            for cert in certs {
                if normalize_id(&cert.fingerprint().to_hex()) == needle {
                    return Err(EncryptoError::InvalidInput(
                        "secret key not available".to_string(),
                    ));
                }
            }
        }
        Err(EncryptoError::InvalidInput(format!(
            "key not found: {}",
            id.0
        )))
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
            has_secret: cert.is_tsk(),
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
            if matches!(params.pqc_level, PqcLevel::High) {
                return Err(EncryptoError::InvalidInput(
                    "PQC high suite not available; install OpenSSL 3.5+ with PQC support"
                        .to_string(),
                ));
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
    let baseline = pqc_available_for_suite(CipherSuite::MLDSA65_Ed25519);
    let high = pqc_available_for_suite(CipherSuite::MLDSA87_Ed448);
    vec![
        ("MLDSA65_Ed25519", baseline),
        ("MLDSA87_Ed448", high),
        ("SLHDSA128s", SLHDSA128s.is_supported()),
        ("SLHDSA128f", SLHDSA128f.is_supported()),
        ("SLHDSA256s", SLHDSA256s.is_supported()),
        ("MLKEM768_X25519", baseline),
        ("MLKEM1024_X448", high),
    ]
}

pub fn pqc_suite_supported(level: PqcLevel) -> bool {
    match level {
        PqcLevel::Baseline => pqc_available_for_suite(CipherSuite::MLDSA65_Ed25519),
        PqcLevel::High => pqc_available_for_suite(CipherSuite::MLDSA87_Ed448),
    }
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
            ensure_cert_signatures_pqc(cert)?;
            if cert.is_tsk() {
                self.store_cert(cert, true)?;
                self.store_cert(cert, false)?;
            } else {
                self.store_cert(cert, false)?;
            }
        }

        Ok(self.meta_from_cert(&certs[0]))
    }

    fn export_key(&self, id: &KeyId, secret: bool, armor: bool) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_only(&self.pqc_policy)?;
        let cert = self.find_cert_strict(id, secret)?;
        if secret && !cert.is_tsk() {
            return Err(EncryptoError::InvalidInput(
                "secret key not available".to_string(),
            ));
        }
        self.export_cert_bytes(&cert, secret, armor)
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
            certs.push(self.find_cert_strict(recipient, false)?);
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
            .aead_algo(AEADAlgorithm::default())
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
        let mut decryptor = match DecryptorBuilder::from_bytes(&req.ciphertext)
            .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?
            .with_policy(p, None, helper)
        {
            Ok(decryptor) => decryptor,
            Err(err) => {
                if self.passphrase.is_none() && has_encrypted_secret {
                    if err
                        .downcast_ref::<openpgp::Error>()
                        .is_some_and(|e| matches!(e, openpgp::Error::MissingSessionKey(_)))
                    {
                        return Err(EncryptoError::InvalidInput(
                            "secret key is encrypted; passphrase required".to_string(),
                        ));
                    }
                }
                return Err(EncryptoError::Backend(format!("decryptor failed: {err}")));
            }
        };

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
        let cert = self.find_cert_strict(&req.signer, true)?;
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
        if req.cleartext {
            let mut signer = Signer::new(message, keypair)
                .map_err(|err| EncryptoError::Backend(format!("signer failed: {err}")))?
                .cleartext()
                .build()
                .map_err(|err| EncryptoError::Backend(format!("signer build failed: {err}")))?;
            signer
                .write_all(&req.message)
                .map_err(|err| EncryptoError::Io(format!("write failed: {err}")))?;
            signer
                .finalize()
                .map_err(|err| EncryptoError::Backend(format!("finalize failed: {err}")))?;
            if matches!(req.pqc_policy, PqcPolicy::Required) {
                let sig_block = cleartext_signature_block(&sink)?;
                ensure_pqc_signature_output(&sig_block).map_err(policy_error)?;
            }
            return Ok(sink);
        }

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
        let certs = self.load_all_certs()?;
        let helper = NativeHelper::new(certs, self.passphrase.clone());
        let p = &StandardPolicy::new();
        if req.cleartext {
            let sig_block = cleartext_signature_block(&req.signature)?;
            if require_pqc {
                ensure_pqc_signature_output(&sig_block).map_err(policy_error)?;
            }
            let mut verifier = openpgp::parse::stream::VerifierBuilder::from_bytes(&req.signature)
                .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?
                .with_policy(p, None, helper)
                .map_err(|err| EncryptoError::Backend(format!("verifier failed: {err}")))?;
            let mut content = Vec::new();
            let read_ok = verifier.read_to_end(&mut content).is_ok();
            let helper = verifier.into_helper();
            let valid = read_ok && helper.valid_signature();
            let signer = if valid {
                helper
                    .signer()
                    .or_else(|| signer_from_signature_bytes(&sig_block))
            } else {
                None
            };
            return Ok(VerifyResult {
                valid,
                signer,
                message: if valid { Some(content) } else { None },
            });
        }

        if require_pqc {
            ensure_pqc_signature_output(&req.signature).map_err(policy_error)?;
        }
        let mut verifier = DetachedVerifierBuilder::from_bytes(&req.signature)
            .map_err(|err| EncryptoError::Backend(format!("parse failed: {err}")))?
            .with_policy(p, None, helper)
            .map_err(|err| EncryptoError::Backend(format!("verifier failed: {err}")))?;

        let read_ok = verifier.verify_bytes(&req.message).is_ok();
        let helper = verifier.into_helper();
        let valid = read_ok && helper.valid_signature();
        let signer = if valid {
            helper
                .signer()
                .or_else(|| signer_from_signature_bytes(&req.signature))
        } else {
            None
        };

        Ok(VerifyResult {
            valid,
            signer,
            message: None,
        })
    }

    fn revoke_key(&self, req: RevokeRequest) -> Result<RevokeResult, EncryptoError> {
        self.ensure_pqc_only(&self.pqc_policy)?;
        let cert = self.find_cert_strict(&req.key_id, true)?;
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
        let cert = self.find_cert_strict(&req.key_id, false)?;
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
    signer: Option<KeyId>,
    multiple_signers: bool,
    saw_signature: bool,
    has_valid_signature: bool,
}

impl NativeHelper {
    fn new(certs: Vec<Cert>, passphrase: Option<Password>) -> Self {
        Self {
            certs,
            passphrase,
            signer: None,
            multiple_signers: false,
            saw_signature: false,
            has_valid_signature: false,
        }
    }

    fn signer(&self) -> Option<KeyId> {
        if self.multiple_signers {
            None
        } else {
            self.signer.clone()
        }
    }

    fn valid_signature(&self) -> bool {
        self.saw_signature && self.has_valid_signature
    }
}

impl VerificationHelper for NativeHelper {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        if ids.is_empty() {
            return Ok(self.certs.clone());
        }
        let mut matches = Vec::new();
        for cert in &self.certs {
            let mut matched = false;
            for id in ids {
                if cert.fingerprint().aliases(id) {
                    matched = true;
                    break;
                }
                if cert.keys().any(|key| key.key().fingerprint().aliases(id)) {
                    matched = true;
                    break;
                }
            }
            if matched {
                matches.push(cert.clone());
            }
        }
        Ok(matches)
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    self.saw_signature = true;
                    if let Ok(good) = result {
                        self.has_valid_signature = true;
                        let fpr = good.ka.cert().fingerprint().to_hex();
                        match &self.signer {
                            None => self.signer = Some(KeyId(fpr)),
                            Some(existing) if existing.0 == fpr => {}
                            Some(_) => self.multiple_signers = true,
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn signer_from_signature_bytes(bytes: &[u8]) -> Option<KeyId> {
    let pile = PacketPile::from_bytes(bytes).ok()?;
    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            if let Some(issuer) = sig.get_issuers().into_iter().next() {
                return Some(match issuer {
                    KeyHandle::Fingerprint(fpr) => KeyId(fpr.to_hex()),
                    KeyHandle::KeyID(id) => KeyId(id.to_hex()),
                });
            }
        }
    }
    None
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
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".encrypto")
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

fn ensure_cert_signatures_pqc(cert: &Cert) -> Result<(), EncryptoError> {
    if cert.bad_signatures().next().is_some() {
        return Err(EncryptoError::InvalidInput(
            "certificate contains invalid signatures".to_string(),
        ));
    }
    for sig in cert.primary_key().signatures() {
        ensure_signature_pqc(sig)?;
    }
    for uid in cert.userids() {
        for sig in uid.signatures() {
            ensure_signature_pqc(sig)?;
        }
    }
    for attr in cert.user_attributes() {
        for sig in attr.signatures() {
            ensure_signature_pqc(sig)?;
        }
    }
    for key in cert.keys() {
        for sig in key.signatures() {
            ensure_signature_pqc(sig)?;
        }
    }
    Ok(())
}

fn ensure_signature_pqc(sig: &openpgp::packet::Signature) -> Result<(), EncryptoError> {
    let algo = sig.pk_algo();
    if !is_pqc_sign_algo(algo) {
        return Err(EncryptoError::InvalidInput(format!(
            "non-PQC signature in certificate: {algo:?}"
        )));
    }
    if sig.version() < 6 {
        return Err(EncryptoError::InvalidInput(format!(
            "signature version is v{}",
            sig.version()
        )));
    }
    if !hash_is_pqc_ok(sig.hash_algo()) {
        return Err(EncryptoError::InvalidInput(format!(
            "weak hash used in certificate signature: {:?}",
            sig.hash_algo()
        )));
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), EncryptoError> {
    let dir = path
        .parent()
        .ok_or_else(|| EncryptoError::InvalidInput("invalid path for atomic write".to_string()))?;
    let mut temp = NamedTempFile::new_in(dir)
        .map_err(|err| EncryptoError::Io(format!("temp file error: {err}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = temp
            .as_file()
            .metadata()
            .map_err(|err| EncryptoError::Io(format!("stat failed: {err}")))?
            .permissions();
        perms.set_mode(mode);
        temp.as_file()
            .set_permissions(perms)
            .map_err(|err| EncryptoError::Io(format!("chmod failed: {err}")))?;
    }
    temp.write_all(bytes)
        .map_err(|err| EncryptoError::Io(format!("write failed: {err}")))?;
    temp.as_file()
        .sync_all()
        .map_err(|err| EncryptoError::Io(format!("sync failed: {err}")))?;
    temp.persist(path)
        .map_err(|err| EncryptoError::Io(format!("persist failed: {err}")))?;
    Ok(())
}

fn is_full_fingerprint(input: &str) -> bool {
    let len = input.len();
    if len != 40 && len != 64 {
        return false;
    }
    input.chars().all(|c| c.is_ascii_hexdigit())
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

// signer extraction is handled by the streaming verifier helper.

fn cleartext_signature_block(bytes: &[u8]) -> Result<Vec<u8>, EncryptoError> {
    const BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
    const END: &str = "-----END PGP SIGNATURE-----";
    let text = String::from_utf8_lossy(bytes);
    let start = text.find(BEGIN).ok_or_else(|| {
        EncryptoError::InvalidInput("cleartext signature block not found".to_string())
    })?;
    let end_rel = text[start..].find(END).ok_or_else(|| {
        EncryptoError::InvalidInput("cleartext signature block not found".to_string())
    })?;
    let mut end = start + end_rel + END.len();
    if let Some(rest) = text[end..].find('\n') {
        end += rest + 1;
    }
    Ok(text[start..end].as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("encrypto-native-{name}-{nanos}"))
    }

    #[test]
    fn normalize_id_strips_prefix_and_whitespace() {
        let normalized = normalize_id("  0xAb Cd\tEf ");
        assert_eq!(normalized, "ABCDEF");
    }

    #[test]
    fn is_full_fingerprint_checks_len_and_hex() {
        assert!(is_full_fingerprint(
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
        ));
        assert!(!is_full_fingerprint("deadbeef"));
        assert!(!is_full_fingerprint(
            "ZZZZBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
        ));
    }

    #[test]
    fn map_revocation_reason_matches_expected() {
        assert_eq!(
            map_revocation_reason(RevocationReason::KeyCompromised),
            ReasonForRevocation::KeyCompromised
        );
        assert_eq!(
            map_revocation_reason(RevocationReason::UserIdInvalid),
            ReasonForRevocation::UIDRetired
        );
    }

    #[test]
    fn cleartext_signature_block_extracts_block() {
        let input = b"hello\n-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n";
        let block = cleartext_signature_block(input).expect("extract");
        let text = String::from_utf8_lossy(&block);
        assert!(text.contains("BEGIN PGP SIGNATURE"));
        assert!(text.contains("END PGP SIGNATURE"));
    }

    #[test]
    fn cleartext_signature_block_rejects_missing_block() {
        let err = cleartext_signature_block(b"no signature").expect_err("expected error");
        assert!(
            err.to_string()
                .contains("cleartext signature block not found")
        );
    }

    #[test]
    fn write_atomic_writes_and_sets_mode() {
        let path = temp_path("atomic");
        write_atomic(&path, b"payload", 0o600).expect("write");
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes, b"payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn signer_from_signature_bytes_extracts_issuer() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "../vendor/sequoia-openpgp/tests/data/pqc/ietf/v6-slhdsa-256s-sample-signature.pgp",
        );
        let bytes = std::fs::read(&path).expect("read signature bytes");
        let signer = signer_from_signature_bytes(&bytes);
        assert!(signer.is_some(), "expected issuer fingerprint in signature");
    }
}
