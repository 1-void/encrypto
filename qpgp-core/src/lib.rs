use std::fmt;

/// Sanitizes untrusted text for display in a terminal.
///
/// OpenPGP User IDs are attacker-controlled and may contain control
/// characters or ANSI escape sequences. This function ensures terminal output
/// cannot be manipulated by stripping/escaping control bytes.
pub fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {
                // ASCII-only escape to make the presence of a control char obvious.
                let code = c as u32;
                if code <= 0xFF {
                    out.push_str("\\x");
                    out.push_str(&format!("{:02X}", code));
                } else {
                    out.push_str("\\u{");
                    out.push_str(&format!("{:X}", code));
                    out.push('}');
                }
            }
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PqcPolicy {
    Disabled,
    Preferred,
    #[default]
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PqcLevel {
    #[default]
    Baseline,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId(pub String);

pub const OPENPGP_PQC_DRAFT: &str = "draft-ietf-openpgp-pqc-17";

#[derive(Debug, Clone)]
pub struct KeyMeta {
    pub key_id: KeyId,
    pub user_id: Option<UserId>,
    pub algo: String,
    pub created_utc: Option<String>,
    pub has_secret: bool,
}

#[derive(Debug, Clone)]
pub struct KeyGenParams {
    pub user_id: UserId,
    pub algo: Option<String>,
    pub pqc_policy: PqcPolicy,
    pub pqc_level: PqcLevel,
    pub passphrase: Option<String>,
    pub allow_unprotected: bool,
}

#[derive(Debug, Clone)]
pub struct EncryptRequest {
    pub recipients: Vec<KeyId>,
    pub plaintext: Vec<u8>,
    pub armor: bool,
    pub pqc_policy: PqcPolicy,
    pub compat: bool,
}

#[derive(Debug, Clone)]
pub struct DecryptRequest {
    pub ciphertext: Vec<u8>,
    pub pqc_policy: PqcPolicy,
    /// Allow decryption using revoked keys (useful for archival recovery).
    pub allow_revoked_keys: bool,
}

#[derive(Debug, Clone)]
pub struct SignRequest {
    pub signer: KeyId,
    pub message: Vec<u8>,
    pub armor: bool,
    pub cleartext: bool,
    pub pqc_policy: PqcPolicy,
}

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub cleartext: bool,
    pub pqc_policy: PqcPolicy,
}

#[derive(Debug, Clone)]
pub struct ImportRequest {
    pub bytes: Vec<u8>,
    pub allow_unprotected: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid: bool,
    /// The signer if exactly one good signature was found.
    pub signer: Option<KeyId>,
    /// All unique signers for signatures that were verified as good.
    pub signers: Vec<KeyId>,
    pub message: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromised,
    KeySuperseded,
    KeyRetired,
    UserIdInvalid,
}

#[derive(Debug, Clone)]
pub struct RevokeRequest {
    pub key_id: KeyId,
    pub reason: RevocationReason,
    pub message: Option<String>,
    pub armor: bool,
}

#[derive(Debug, Clone)]
pub struct RevokeResult {
    pub updated_cert: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RotateRequest {
    pub key_id: KeyId,
    pub new_user_id: Option<UserId>,
    pub pqc_policy: PqcPolicy,
    pub pqc_level: PqcLevel,
    pub passphrase: Option<String>,
    pub allow_unprotected: bool,
    pub revoke_old: bool,
}

#[derive(Debug, Clone)]
pub struct RotateResult {
    pub new_key: KeyMeta,
    pub old_key_revoked: bool,
}

#[derive(Debug)]
pub enum QpgpError {
    NotImplemented(&'static str),
    InvalidInput(String),
    Backend(String),
    Io(String),
}

impl QpgpError {
    pub fn not_implemented(msg: &'static str) -> Self {
        QpgpError::NotImplemented(msg)
    }
}

impl fmt::Display for QpgpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QpgpError::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
            QpgpError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            QpgpError::Backend(msg) => write!(f, "backend error: {msg}"),
            QpgpError::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl std::error::Error for QpgpError {}

pub trait Backend {
    fn name(&self) -> &'static str;
    fn supports_pqc(&self) -> bool;

    fn list_keys(&self) -> Result<Vec<KeyMeta>, QpgpError>;
    fn generate_key(&self, params: KeyGenParams) -> Result<KeyMeta, QpgpError>;
    fn import_key(&self, req: ImportRequest) -> Result<KeyMeta, QpgpError>;
    fn export_key(&self, id: &KeyId, secret: bool, armor: bool) -> Result<Vec<u8>, QpgpError>;

    fn encrypt(&self, req: EncryptRequest) -> Result<Vec<u8>, QpgpError>;
    fn decrypt(&self, req: DecryptRequest) -> Result<Vec<u8>, QpgpError>;

    fn sign(&self, req: SignRequest) -> Result<Vec<u8>, QpgpError>;
    fn verify(&self, req: VerifyRequest) -> Result<VerifyResult, QpgpError>;

    fn revoke_key(&self, req: RevokeRequest) -> Result<RevokeResult, QpgpError>;
    fn rotate_key(&self, req: RotateRequest) -> Result<RotateResult, QpgpError>;
}
