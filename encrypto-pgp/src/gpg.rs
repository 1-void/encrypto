use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, EncryptoError, KeyGenParams, KeyId, KeyMeta,
    PqcPolicy, RevokeRequest, RevokeResult, RotateRequest, RotateResult, SignRequest, UserId,
    VerifyRequest, VerifyResult,
};
use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinentryMode {
    Default,
    Ask,
    Loopback,
}

impl PinentryMode {
    fn as_str(self) -> &'static str {
        match self {
            PinentryMode::Default => "default",
            PinentryMode::Ask => "ask",
            PinentryMode::Loopback => "loopback",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GpgConfig {
    pub gpg_path: String,
    pub homedir: Option<String>,
    pub pinentry_mode: PinentryMode,
    pub passphrase: Option<String>,
    pub passphrase_file: Option<String>,
    pub batch: bool,
}

impl Default for GpgConfig {
    fn default() -> Self {
        Self {
            gpg_path: "gpg".to_string(),
            homedir: None,
            pinentry_mode: PinentryMode::Default,
            passphrase: None,
            passphrase_file: None,
            batch: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GpgBackend {
    config: GpgConfig,
}

impl GpgBackend {
    pub fn new(config: GpgConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &GpgConfig {
        &self.config
    }

    fn ensure_pqc_only_backend(&self) -> Result<(), EncryptoError> {
        Err(EncryptoError::Backend(
            "PQC-only build: gpg backend is disabled".to_string(),
        ))
    }

    fn ensure_pqc_policy(&self, policy: &PqcPolicy) -> Result<(), EncryptoError> {
        if !matches!(policy, PqcPolicy::Required) {
            return Err(EncryptoError::InvalidInput(
                "PQC-only build requires --pqc required".to_string(),
            ));
        }
        self.ensure_pqc_only_backend()
    }

    fn build_base_args(&self) -> Result<(Vec<String>, Option<NamedTempFile>), EncryptoError> {
        let mut args = Vec::new();
        let mut passphrase_file = None;
        let mut pinentry_mode = self.config.pinentry_mode;
        let mut using_passphrase = false;

        if let Some(homedir) = &self.config.homedir {
            args.push("--homedir".to_string());
            args.push(homedir.clone());
        }

        if let Some(path) = &self.config.passphrase_file {
            args.push("--passphrase-file".to_string());
            args.push(path.clone());
            using_passphrase = true;
        } else if let Some(passphrase) = &self.config.passphrase {
            let mut file = NamedTempFile::new()
                .map_err(|err| EncryptoError::Io(format!("temp file error: {err}")))?;
            file.write_all(passphrase.as_bytes())
                .map_err(|err| EncryptoError::Io(format!("temp write error: {err}")))?;
            args.push("--passphrase-file".to_string());
            args.push(file.path().to_string_lossy().to_string());
            passphrase_file = Some(file);
            using_passphrase = true;
        }

        if using_passphrase && pinentry_mode == PinentryMode::Default {
            pinentry_mode = PinentryMode::Loopback;
        }

        if self.config.batch || using_passphrase {
            args.push("--batch".to_string());
        }

        if pinentry_mode != PinentryMode::Default {
            args.push("--pinentry-mode".to_string());
            args.push(pinentry_mode.as_str().to_string());
        }

        Ok((args, passphrase_file))
    }

    fn run_gpg(&self, args: &[&str], input: Option<&[u8]>) -> Result<CommandOutput, EncryptoError> {
        let (base_args, _passphrase_file) = self.build_base_args()?;
        let mut cmd = Command::new(&self.config.gpg_path);
        cmd.args(base_args)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|err| EncryptoError::Backend(format!("failed to spawn gpg: {err}")))?;

        if let Some(bytes) = input {
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(bytes)
                    .map_err(|err| EncryptoError::Io(format!("gpg stdin write failed: {err}")))?;
            }
        }

        let output = child
            .wait_with_output()
            .map_err(|err| EncryptoError::Backend(format!("gpg failed: {err}")))?;

        Ok(CommandOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    fn output_or_error(&self, output: CommandOutput) -> Result<Vec<u8>, EncryptoError> {
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(EncryptoError::Backend(format!(
                "gpg error: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    fn parse_keys(&self, output: &[u8]) -> Vec<KeyMeta> {
        let text = String::from_utf8_lossy(output);
        let mut keys = Vec::new();
        let mut current: Option<KeyMeta> = None;

        for line in text.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.is_empty() {
                continue;
            }

            match fields[0] {
                "pub" | "sec" => {
                    if let Some(key) = current.take() {
                        keys.push(key);
                    }
                    let key_id = fields.get(4).unwrap_or(&"").to_string();
                    let algo = format_algo(fields.get(3).unwrap_or(&""));
                    let created_utc = fields.get(5).and_then(|value| {
                        if value.is_empty() {
                            None
                        } else {
                            Some(value.to_string())
                        }
                    });
                    current = Some(KeyMeta {
                        key_id: KeyId(key_id),
                        user_id: None,
                        algo,
                        created_utc,
                    });
                }
                "uid" => {
                    if let Some(ref mut key) = current {
                        if let Some(uid) = fields.get(9) {
                            if !uid.is_empty() {
                                key.user_id = Some(UserId(uid.to_string()));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if let Some(key) = current {
            keys.push(key);
        }

        keys
    }

    fn import_key_id(&self, output: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(output);
        let mut key_id = None;
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            if parts.get(1) == Some(&"IMPORT_OK") || parts.get(1) == Some(&"IMPORTED") {
                if let Some(last) = parts.last() {
                    key_id = Some((*last).to_string());
                }
            }
        }
        key_id
    }

    fn list_keys_inner(&self) -> Result<Vec<KeyMeta>, EncryptoError> {
        let output = self.run_gpg(
            &["--list-keys", "--with-colons", "--keyid-format", "LONG"],
            None,
        )?;
        self.output_or_error(output)
            .map(|data| self.parse_keys(&data))
    }

    fn parse_verify_status(output: &[u8]) -> Option<KeyId> {
        let text = String::from_utf8_lossy(output);
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("[GNUPG:] VALIDSIG ") {
                let mut parts = rest.split_whitespace();
                if let Some(fingerprint) = parts.next() {
                    return Some(KeyId(fingerprint.to_string()));
                }
            }
            if let Some(rest) = line.strip_prefix("[GNUPG:] GOODSIG ") {
                let mut parts = rest.split_whitespace();
                if let Some(key_id) = parts.next() {
                    return Some(KeyId(key_id.to_string()));
                }
            }
        }
        None
    }
}

impl Default for GpgBackend {
    fn default() -> Self {
        Self::new(GpgConfig::default())
    }
}

impl Backend for GpgBackend {
    fn name(&self) -> &'static str {
        "gpg"
    }

    fn supports_pqc(&self) -> bool {
        false
    }

    fn list_keys(&self) -> Result<Vec<KeyMeta>, EncryptoError> {
        self.ensure_pqc_only_backend()?;
        self.list_keys_inner()
    }

    fn generate_key(&self, params: KeyGenParams) -> Result<KeyMeta, EncryptoError> {
        self.ensure_pqc_policy(&params.pqc_policy)?;
        let algo = params.algo.as_deref().unwrap_or("default");
        let output = self.run_gpg(
            &[
                "--quick-generate-key",
                &params.user_id.0,
                algo,
                "default",
                "never",
            ],
            None,
        )?;
        self.output_or_error(output)?;

        let keys = self.list_keys_inner()?;
        if let Some(key) = keys
            .into_iter()
            .find(|k| k.user_id.as_ref().map(|u| &u.0) == Some(&params.user_id.0))
        {
            return Ok(key);
        }

        Err(EncryptoError::Backend(
            "key generated but not found in keyring".to_string(),
        ))
    }

    fn import_key(&self, bytes: &[u8]) -> Result<KeyMeta, EncryptoError> {
        self.ensure_pqc_only_backend()?;
        let output = self.run_gpg(&["--status-fd", "1", "--import"], Some(bytes))?;
        let status_output = self.output_or_error(output)?;
        if let Some(key_id) = self.import_key_id(&status_output) {
            return Ok(KeyMeta {
                key_id: KeyId(key_id),
                user_id: None,
                algo: "unknown".to_string(),
                created_utc: None,
            });
        }

        Err(EncryptoError::Backend(
            "import completed but key id was not found".to_string(),
        ))
    }

    fn export_key(&self, id: &KeyId, secret: bool) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_only_backend()?;
        let args = if secret {
            vec!["--export-secret-keys", &id.0]
        } else {
            vec!["--export", &id.0]
        };
        let output = self.run_gpg(&args, None)?;
        self.output_or_error(output)
    }

    fn encrypt(&self, req: EncryptRequest) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_policy(&req.pqc_policy)?;
        let mut args = vec!["--encrypt"];
        if req.armor {
            args.push("--armor");
        }
        for recipient in &req.recipients {
            args.push("-r");
            args.push(&recipient.0);
        }
        let output = self.run_gpg(&args, Some(&req.plaintext))?;
        self.output_or_error(output)
    }

    fn decrypt(&self, req: DecryptRequest) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_policy(&req.pqc_policy)?;
        let output = self.run_gpg(&["--decrypt"], Some(&req.ciphertext))?;
        self.output_or_error(output)
    }

    fn sign(&self, req: SignRequest) -> Result<Vec<u8>, EncryptoError> {
        self.ensure_pqc_policy(&req.pqc_policy)?;
        let mut args = vec!["--detach-sign", "--local-user", &req.signer.0];
        if req.armor {
            args.push("--armor");
        }
        let output = self.run_gpg(&args, Some(&req.message))?;
        self.output_or_error(output)
    }

    fn verify(&self, req: VerifyRequest) -> Result<VerifyResult, EncryptoError> {
        self.ensure_pqc_policy(&req.pqc_policy)?;
        let mut message_file = NamedTempFile::new()
            .map_err(|err| EncryptoError::Io(format!("temp file error: {err}")))?;
        message_file
            .write_all(&req.message)
            .map_err(|err| EncryptoError::Io(format!("temp write error: {err}")))?;

        let mut sig_file = NamedTempFile::new()
            .map_err(|err| EncryptoError::Io(format!("temp file error: {err}")))?;
        sig_file
            .write_all(&req.signature)
            .map_err(|err| EncryptoError::Io(format!("temp write error: {err}")))?;

        let output = self.run_gpg(
            &[
                "--status-fd",
                "1",
                "--verify",
                sig_file.path().to_str().unwrap_or(""),
                message_file.path().to_str().unwrap_or(""),
            ],
            None,
        )?;

        Ok(VerifyResult {
            valid: output.status.success(),
            signer: Self::parse_verify_status(&output.stdout),
        })
    }

    fn revoke_key(&self, _req: RevokeRequest) -> Result<RevokeResult, EncryptoError> {
        Err(EncryptoError::not_implemented(
            "revocation is not implemented for the gpg backend",
        ))
    }

    fn rotate_key(&self, _req: RotateRequest) -> Result<RotateResult, EncryptoError> {
        Err(EncryptoError::not_implemented(
            "rotation is not implemented for the gpg backend",
        ))
    }
}

struct CommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn format_algo(id: &str) -> String {
    match id {
        "1" => "RSA".to_string(),
        "17" => "DSA".to_string(),
        "18" => "ECDH".to_string(),
        "19" => "ECDSA".to_string(),
        "22" => "EdDSA".to_string(),
        "23" => "X25519".to_string(),
        "24" => "Ed25519".to_string(),
        _ => format!("algo-{id}"),
    }
}
