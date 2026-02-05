use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcPolicy {
    Disabled,
    Preferred,
    Required,
}

impl Default for PqcPolicy {
    fn default() -> Self {
        PqcPolicy::Required
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqcLevel {
    Baseline,
    High,
}

impl Default for PqcLevel {
    fn default() -> Self {
        PqcLevel::Baseline
    }
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
}

#[derive(Debug, Clone)]
pub struct SignRequest {
    pub signer: KeyId,
    pub message: Vec<u8>,
    pub armor: bool,
    pub pqc_policy: PqcPolicy,
}

#[derive(Debug, Clone)]
pub struct VerifyRequest {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub pqc_policy: PqcPolicy,
}

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid: bool,
    pub signer: Option<KeyId>,
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
pub enum EncryptoError {
    NotImplemented(&'static str),
    InvalidInput(String),
    Backend(String),
    Io(String),
}

impl EncryptoError {
    pub fn not_implemented(msg: &'static str) -> Self {
        EncryptoError::NotImplemented(msg)
    }
}

impl fmt::Display for EncryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptoError::NotImplemented(msg) => write!(f, "not implemented: {msg}"),
            EncryptoError::InvalidInput(msg) => write!(f, "invalid input: {msg}"),
            EncryptoError::Backend(msg) => write!(f, "backend error: {msg}"),
            EncryptoError::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

impl std::error::Error for EncryptoError {}

pub trait Backend {
    fn name(&self) -> &'static str;
    fn supports_pqc(&self) -> bool;

    fn list_keys(&self) -> Result<Vec<KeyMeta>, EncryptoError>;
    fn generate_key(&self, params: KeyGenParams) -> Result<KeyMeta, EncryptoError>;
    fn import_key(&self, bytes: &[u8]) -> Result<KeyMeta, EncryptoError>;
    fn export_key(&self, id: &KeyId, secret: bool) -> Result<Vec<u8>, EncryptoError>;

    fn encrypt(&self, req: EncryptRequest) -> Result<Vec<u8>, EncryptoError>;
    fn decrypt(&self, req: DecryptRequest) -> Result<Vec<u8>, EncryptoError>;

    fn sign(&self, req: SignRequest) -> Result<Vec<u8>, EncryptoError>;
    fn verify(&self, req: VerifyRequest) -> Result<VerifyResult, EncryptoError>;

    fn revoke_key(&self, req: RevokeRequest) -> Result<RevokeResult, EncryptoError>;
    fn rotate_key(&self, req: RotateRequest) -> Result<RotateResult, EncryptoError>;
}
