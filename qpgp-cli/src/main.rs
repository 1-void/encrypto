use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use qpgp_core::{
    Backend, DecryptRequest, EncryptRequest, ImportRequest, KeyGenParams, KeyId, OPENPGP_PQC_DRAFT,
    PqcLevel, PqcPolicy, RevocationReason, RevokeRequest, RotateRequest, SignRequest, UserId,
    VerifyRequest, VerifyResult, sanitize_for_terminal,
};
use qpgp_pgp::{NativeBackend, pqc_algorithms_supported, pqc_suite_supported};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::process::Command as ProcessCommand;

#[derive(Parser, Debug)]
#[command(
    name = "qpgp",
    version,
    about = "PQC-only OpenPGP-compatible crypto CLI (QPGP)"
)]
struct Cli {
    #[arg(
        long = "passphrase",
        global = true,
        value_name = "PASS",
        help = "Unsafe passphrase via argv (requires --allow-unsafe-passphrase)",
        long_help = "Provide a passphrase directly on the command line (unsafe: leaks via shell history and process listings). Requires --allow-unsafe-passphrase. Prefer --passphrase-file."
    )]
    passphrase: Option<String>,

    #[arg(
        long = "passphrase-file",
        global = true,
        value_name = "FILE",
        help = "Read passphrase from file (recommended)"
    )]
    passphrase_file: Option<String>,

    #[arg(
        long = "allow-unsafe-passphrase",
        global = true,
        help = "Allow using --passphrase (unsafe)"
    )]
    allow_unsafe_passphrase: bool,

    #[arg(long = "allow-insecure-home", global = true)]
    allow_insecure_home: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum PqcLevelArg {
    Baseline,
    High,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum RevocationReasonArg {
    Unspecified,
    KeyCompromised,
    KeySuperseded,
    KeyRetired,
    UserIdInvalid,
}

impl From<PqcLevelArg> for PqcLevel {
    fn from(level: PqcLevelArg) -> Self {
        match level {
            PqcLevelArg::Baseline => PqcLevel::Baseline,
            PqcLevelArg::High => PqcLevel::High,
        }
    }
}

impl From<RevocationReasonArg> for RevocationReason {
    fn from(reason: RevocationReasonArg) -> Self {
        match reason {
            RevocationReasonArg::Unspecified => RevocationReason::Unspecified,
            RevocationReasonArg::KeyCompromised => RevocationReason::KeyCompromised,
            RevocationReasonArg::KeySuperseded => RevocationReason::KeySuperseded,
            RevocationReasonArg::KeyRetired => RevocationReason::KeyRetired,
            RevocationReasonArg::UserIdInvalid => RevocationReason::UserIdInvalid,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    Info,
    Doctor,
    #[command(alias = "ls")]
    ListKeys {
        #[arg(long, conflicts_with = "public")]
        secret: bool,
        #[arg(long, conflicts_with = "secret")]
        public: bool,
    },
    #[command(alias = "gen")]
    Keygen {
        user_id: String,
        #[arg(long, value_enum, default_value_t = PqcLevelArg::High)]
        pqc_level: PqcLevelArg,
        #[arg(long = "no-passphrase")]
        no_passphrase: bool,
    },
    Import {
        path: String,
        #[arg(long)]
        allow_unprotected_import: bool,
    },
    Export {
        key_id: String,
        #[arg(long)]
        secret: bool,
        #[arg(short = 'a', long)]
        armor: bool,
        #[arg(long)]
        out: Option<String>,
    },
    #[command(alias = "enc")]
    Encrypt {
        #[arg(short = 'r', long = "recipient", value_name = "RECIPIENT")]
        recipients: Vec<String>,
        #[arg(long = "to", value_name = "RECIPIENT", value_delimiter = ',')]
        to: Vec<String>,
        #[arg(short = 'a', long)]
        armor: bool,
        #[arg(long, alias = "in")]
        input: Option<String>,
        #[arg(short = 'o', long, alias = "out")]
        output: Option<String>,
        #[arg(value_name = "FILE", index = 1)]
        input_file: Option<String>,
    },
    #[command(alias = "dec")]
    Decrypt {
        #[arg(long, alias = "in")]
        input: Option<String>,
        #[arg(short = 'o', long, alias = "out")]
        output: Option<String>,
        #[arg(
            long = "allow-revoked-keys",
            help = "Allow decrypting using revoked keys (useful for archival recovery)"
        )]
        allow_revoked_keys: bool,
        #[arg(value_name = "FILE", index = 1)]
        input_file: Option<String>,
    },
    #[command(alias = "sig")]
    Sign {
        #[arg(short = 'u', long = "local-user", alias = "key")]
        key_id: String,
        #[arg(short = 'a', long, conflicts_with = "clearsign")]
        armor: bool,
        #[arg(long, conflicts_with = "armor")]
        clearsign: bool,
        #[arg(long, alias = "in")]
        input: Option<String>,
        #[arg(short = 'o', long, alias = "out")]
        output: Option<String>,
        #[arg(value_name = "FILE", index = 1)]
        input_file: Option<String>,
    },
    #[command(alias = "ver")]
    Verify {
        #[arg(long, alias = "in")]
        input: Option<String>,
        #[arg(long, alias = "sig")]
        sig: Option<String>,
        #[arg(value_name = "SIGFILE", index = 1)]
        sig_file: Option<String>,
        #[arg(value_name = "FILE", index = 2)]
        input_file: Option<String>,
        #[arg(long, conflicts_with_all = ["sig", "sig_file"])]
        clearsigned: bool,
        #[arg(short = 'o', long, alias = "out", requires = "clearsigned")]
        output: Option<String>,
        #[arg(long)]
        signer: Option<String>,
    },
    Revoke {
        key_id: String,
        #[arg(long, value_enum, default_value_t = RevocationReasonArg::Unspecified)]
        reason: RevocationReasonArg,
        #[arg(long)]
        message: Option<String>,
        #[arg(short = 'a', long)]
        armor: bool,
        #[arg(short = 'o', long, alias = "out")]
        output: Option<String>,
    },
    Rotate {
        key_id: String,
        #[arg(long)]
        user_id: Option<String>,
        #[arg(long, value_enum, default_value_t = PqcLevelArg::High)]
        pqc_level: PqcLevelArg,
        #[arg(long = "no-passphrase")]
        no_passphrase: bool,
        #[arg(long = "no-revoke")]
        no_revoke: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pqc_policy = PqcPolicy::Required;

    if cli.allow_insecure_home && !io::stdin().is_terminal() {
        let override_ok = std::env::var("QPGP_ALLOW_INSECURE_HOME_NONINTERACTIVE")
            .ok()
            .is_some_and(|v| v == "1");
        if !override_ok {
            return Err(anyhow!(
                "--allow-insecure-home is not allowed in non-interactive mode; refusing to proceed. If you understand the risk and need this for CI/testing, set QPGP_ALLOW_INSECURE_HOME_NONINTERACTIVE=1."
            ));
        }
    }

    if cli.allow_insecure_home
        && let Ok(home) = std::env::var("QPGP_HOME")
        && !std::path::Path::new(&home).is_absolute()
    {
        eprintln!(
            "warning: QPGP_HOME is relative and --allow-insecure-home was used; this is insecure and should only be used for testing"
        );
    }

    if cli.passphrase.is_some() && !cli.allow_unsafe_passphrase {
        return Err(anyhow!(
            "--passphrase is unsafe (leaks via shell history / process listings); use --passphrase-file, or pass --allow-unsafe-passphrase to proceed"
        ));
    }

    if cli.passphrase.is_some() {
        eprintln!("warning: --passphrase can expose secrets in process listings (allowed)");
    }

    if cli.passphrase.is_some() && cli.passphrase_file.is_some() {
        eprintln!("warning: both --passphrase and --passphrase-file set; using file");
    }

    let native_passphrase = if let Some(path) = &cli.passphrase_file {
        Some(read_passphrase_file(path)?)
    } else {
        cli.passphrase.clone()
    };

    let backend: Box<dyn Backend> = Box::new(NativeBackend::with_passphrase_allow_insecure_home(
        pqc_policy.clone(),
        native_passphrase.clone(),
        cli.allow_insecure_home,
    ));

    if matches!(pqc_policy, PqcPolicy::Required) && !backend.supports_pqc() {
        return Err(anyhow!(
            "PQC-only build requires PQC support; see scripts/bootstrap-pqc.sh"
        ));
    }

    match cli.cmd {
        Command::Info => {
            println!("backend: {}", backend.name());
            println!("pqc policy: {}", format_policy(&pqc_policy));
            println!("openpgp pqc draft: {OPENPGP_PQC_DRAFT}");
            println!("pqc supported: {}", backend.supports_pqc());
            if backend.name() == "native" {
                for (name, supported) in pqc_algorithms_supported() {
                    println!("pqc algo {name}: {supported}");
                }
            }
            Ok(())
        }
        Command::Doctor => {
            println!("backend: {}", backend.name());
            println!("pqc policy: {}", format_policy(&pqc_policy));
            println!("openpgp pqc draft: {OPENPGP_PQC_DRAFT}");
            println!("pqc supported: {}", backend.supports_pqc());
            if backend.name() == "native" {
                for (name, supported) in pqc_algorithms_supported() {
                    println!("pqc algo {name}: {supported}");
                }
                let baseline = pqc_suite_supported(PqcLevel::Baseline);
                let high = pqc_suite_supported(PqcLevel::High);
                if !baseline {
                    return Err(anyhow!(
                        "PQC baseline suite missing: baseline={baseline}, high={high}. Run scripts/bootstrap-pqc.sh"
                    ));
                }
                if !high {
                    eprintln!(
                        "warning: PQC high suite unavailable (baseline={baseline}, high={high}); High will fall back to Baseline"
                    );
                }

                // Best-effort build manifest to help debugging provider-loading issues.
                let openssl_bin = std::env::var("OPENSSL_DIR")
                    .ok()
                    .map(|d| std::path::Path::new(&d).join("bin/openssl"))
                    .filter(|p| p.exists());
                let bin = openssl_bin
                    .as_ref()
                    .and_then(|p| p.to_str())
                    .unwrap_or("openssl");
                if let Ok(out) = ProcessCommand::new(bin).args(["version", "-a"]).output() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Some(first) = text.lines().next() {
                        println!("openssl: {first}");
                    }
                }
                if let Ok(out) = ProcessCommand::new(bin)
                    .args(["list", "-providers"])
                    .output()
                {
                    let text = String::from_utf8_lossy(&out.stdout);
                    let providers = text.lines().take(12).collect::<Vec<_>>().join("\n");
                    if !providers.trim().is_empty() {
                        println!("openssl providers:\n{providers}");
                    }
                }
            }
            print_env("QPGP_HOME");
            print_env("QPGP_OPENSSL_CONF");
            print_env("OPENSSL_CONF");
            print_env("OPENSSL_MODULES");
            print_env("LD_LIBRARY_PATH");
            Ok(())
        }
        Command::ListKeys { secret, public } => {
            let mut keys = backend.list_keys()?;
            if secret {
                keys.retain(|key| key.has_secret);
            } else if public {
                keys.retain(|key| !key.has_secret);
            }
            if keys.is_empty() {
                println!("no keys found");
                return Ok(());
            }
            for key in keys {
                let user = key
                    .user_id
                    .as_ref()
                    .map(|u| u.0.as_str())
                    .unwrap_or("(no user id)");
                let user = sanitize_for_terminal(user);
                let created = key.created_utc.as_deref().unwrap_or("(unknown)");
                let kind = if key.has_secret { "sec" } else { "pub" };
                println!(
                    "{} | {} | {} | {} | {}",
                    kind, key.key_id.0, user, key.algo, created
                );
            }
            Ok(())
        }
        Command::Keygen {
            user_id,
            pqc_level,
            no_passphrase,
        } => {
            if native_passphrase.is_none() && !no_passphrase {
                return Err(anyhow!(
                    "passphrase required for native keygen; use --passphrase/--passphrase-file or --no-passphrase"
                ));
            }
            let params = KeyGenParams {
                user_id: UserId(user_id),
                algo: None,
                pqc_policy: pqc_policy.clone(),
                pqc_level: pqc_level.into(),
                passphrase: native_passphrase.clone(),
                allow_unprotected: no_passphrase,
            };
            let meta = backend.generate_key(params)?;
            println!("created key: {}", meta.key_id.0);
            Ok(())
        }
        Command::Import {
            path,
            allow_unprotected_import,
        } => {
            let bytes = read_import_file(&path)?;
            if allow_unprotected_import {
                eprintln!(
                    "warning: --allow-unprotected-import enabled; this may store plaintext secret key material on disk"
                );
            }
            let meta = backend.import_key(ImportRequest {
                bytes,
                allow_unprotected: allow_unprotected_import,
            })?;
            println!("imported key: {}", meta.key_id.0);
            Ok(())
        }
        Command::Export {
            key_id,
            secret,
            armor,
            out,
        } => {
            let bytes = backend.export_key(&KeyId(key_id), secret, armor)?;
            write_output(out, &bytes)
        }
        Command::Encrypt {
            recipients,
            to,
            armor,
            input,
            output,
            input_file,
        } => {
            let mut all_recipients = recipients;
            all_recipients.extend(to);
            if all_recipients.is_empty() {
                return Err(anyhow!("at least one -r/--recipient (or --to) is required"));
            }
            let input_path = merge_arg("input", input, input_file, "--input", "FILE")?;
            let plaintext = read_input(input_path)?;
            let request = EncryptRequest {
                recipients: all_recipients.into_iter().map(KeyId).collect(),
                plaintext,
                armor,
                pqc_policy: pqc_policy.clone(),
                compat: false,
            };
            let ciphertext = backend.encrypt(request)?;
            write_output(output, &ciphertext)
        }
        Command::Decrypt {
            input,
            output,
            allow_revoked_keys,
            input_file,
        } => {
            let input_path = merge_arg("input", input, input_file, "--input", "FILE")?;
            let ciphertext = read_input(input_path)?;
            let plaintext = backend.decrypt(DecryptRequest {
                ciphertext,
                pqc_policy: pqc_policy.clone(),
                allow_revoked_keys,
            })?;
            write_output(output, &plaintext)
        }
        Command::Sign {
            key_id,
            armor,
            clearsign,
            input,
            output,
            input_file,
        } => {
            let input_path = merge_arg("input", input, input_file, "--input", "FILE")?;
            let message = read_input(input_path)?;
            let request = SignRequest {
                signer: KeyId(key_id),
                message,
                armor,
                cleartext: clearsign,
                pqc_policy: pqc_policy.clone(),
            };
            let signature = backend.sign(request)?;
            write_output(output, &signature)
        }
        Command::Verify {
            input,
            sig,
            sig_file,
            input_file,
            clearsigned,
            output,
            signer,
        } => {
            let expected_signer = signer
                .as_ref()
                .ok_or_else(|| anyhow!("verify requires --signer <FULL_FINGERPRINT>"))?;
            let expected_signer = normalize_fingerprint(expected_signer)?;
            if clearsigned {
                let input_path = merge_arg("input", input, input_file, "--input", "FILE")?;
                let signature = read_input(input_path)?;
                let result = backend.verify(VerifyRequest {
                    message: Vec::new(),
                    signature,
                    cleartext: true,
                    pqc_policy: pqc_policy.clone(),
                })?;
                if result.valid {
                    enforce_expected_signer(Some(&expected_signer), &result)?;
                    match result.signer {
                        Some(signer) => println!("valid signature from {}", signer.0),
                        None => println!("valid signature"),
                    }
                    if let Some(path) = output
                        && let Some(message) = result.message
                    {
                        write_output(Some(path), &message)?;
                    }
                    Ok(())
                } else {
                    Err(anyhow!("invalid signature"))
                }
            } else {
                let sig_path = merge_arg("signature", sig, sig_file, "--sig", "SIGFILE")?;
                if sig_path.is_none() {
                    return Err(anyhow!("signature file is required"));
                }
                let input_path = merge_arg("input", input, input_file, "--input", "FILE")?;
                let signature = read_input(sig_path)?;
                let message = read_input(input_path)?;
                let result = backend.verify(VerifyRequest {
                    message,
                    signature,
                    cleartext: false,
                    pqc_policy: pqc_policy.clone(),
                })?;
                if result.valid {
                    enforce_expected_signer(Some(&expected_signer), &result)?;
                    match result.signer {
                        Some(signer) => println!("valid signature from {}", signer.0),
                        None => println!("valid signature"),
                    }
                    Ok(())
                } else {
                    Err(anyhow!("invalid signature"))
                }
            }
        }
        Command::Revoke {
            key_id,
            reason,
            message,
            armor,
            output,
        } => {
            let result = backend.revoke_key(RevokeRequest {
                key_id: KeyId(key_id),
                reason: reason.into(),
                message,
                armor,
            })?;
            if let Some(path) = output {
                write_output(Some(path), &result.updated_cert)?;
            }
            println!("revoked key");
            Ok(())
        }
        Command::Rotate {
            key_id,
            user_id,
            pqc_level,
            no_passphrase,
            no_revoke,
        } => {
            if native_passphrase.is_none() && !no_passphrase {
                return Err(anyhow!(
                    "passphrase required for native rotation; use --passphrase/--passphrase-file or --no-passphrase"
                ));
            }
            let result = backend.rotate_key(RotateRequest {
                key_id: KeyId(key_id),
                new_user_id: user_id.map(UserId),
                pqc_policy: pqc_policy.clone(),
                pqc_level: pqc_level.into(),
                passphrase: native_passphrase.clone(),
                allow_unprotected: no_passphrase,
                revoke_old: !no_revoke,
            })?;
            println!("rotated key: {}", result.new_key.key_id.0);
            if result.old_key_revoked {
                println!("old key revoked");
            }
            Ok(())
        }
    }
}

fn read_input(path: Option<String>) -> Result<Vec<u8>> {
    let limit = max_input_bytes()?;
    match path {
        Some(path) if path == "-" => read_to_end_limited(io::stdin(), limit),
        Some(path) => {
            let metadata = fs::metadata(&path)?;
            if metadata.len() > limit as u64 {
                return Err(anyhow!(
                    "input exceeds size limit ({limit} bytes); set QPGP_MAX_INPUT_BYTES to override"
                ));
            }
            Ok(fs::read(path)?)
        }
        None => read_to_end_limited(io::stdin(), limit),
    }
}

fn read_passphrase_file(path: &str) -> Result<String> {
    const MAX_PASSPHRASE_FILE_BYTES: u64 = 16 * 1024;

    // Avoid symlink surprises and enforce basic operational hygiene.
    // Do an explicit symlink check for a stable error message, then rely on
    // O_NOFOLLOW + fstat checks to avoid TOCTOU races.
    let link_meta = fs::symlink_metadata(path)?;
    if link_meta.file_type().is_symlink() {
        return Err(anyhow!("passphrase file must not be a symlink"));
    }

    // Use O_NOFOLLOW + fstat-based checks to avoid TOCTOU races.
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        opts.open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)?;

    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(anyhow!("passphrase file must be a regular file"));
    }
    if meta.len() > MAX_PASSPHRASE_FILE_BYTES {
        return Err(anyhow!(
            "passphrase file exceeds size limit ({} bytes; max {} bytes)",
            meta.len(),
            MAX_PASSPHRASE_FILE_BYTES
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "passphrase file permissions too broad (mode {:04o}); require 0400/0600 (no group/other access)",
                mode
            ));
        }
        let uid = meta.uid();
        let euid = unsafe { libc::geteuid() };
        if uid != euid {
            return Err(anyhow!(
                "passphrase file must be owned by the current user (uid {uid}, expected {euid})"
            ));
        }
    }

    let bytes = read_to_end_limited(file, MAX_PASSPHRASE_FILE_BYTES as usize)?;
    let mut passphrase = String::from_utf8(bytes)
        .map_err(|err| anyhow!("passphrase file must be valid UTF-8: {err}"))?;
    while passphrase.ends_with('\n') || passphrase.ends_with('\r') {
        passphrase.pop();
    }
    Ok(passphrase)
}

fn print_env(var: &str) {
    match std::env::var(var) {
        Ok(value) if !value.is_empty() => println!("{var}: {value}"),
        _ => println!("{var}: (not set)"),
    }
}

fn max_import_bytes() -> Result<usize> {
    const DEFAULT_LIMIT: usize = 16 * 1024 * 1024;
    match std::env::var("QPGP_MAX_IMPORT_BYTES") {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|err| anyhow!("invalid QPGP_MAX_IMPORT_BYTES value {value:?}: {err}")),
        Err(_) => Ok(DEFAULT_LIMIT),
    }
}

fn read_import_file(path: &str) -> Result<Vec<u8>> {
    let limit = max_import_bytes()?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > limit as u64 {
        return Err(anyhow!(
            "import exceeds size limit ({limit} bytes); set QPGP_MAX_IMPORT_BYTES to override"
        ));
    }
    let file = std::fs::File::open(path)?;
    read_to_end_limited(file, limit)
}

fn write_output(path: Option<String>, bytes: &[u8]) -> Result<()> {
    match path {
        Some(path) => {
            write_file_secure(&path, bytes)?;
            Ok(())
        }
        None => {
            let mut stdout = io::stdout();
            stdout.write_all(bytes)?;
            stdout.flush()?;
            Ok(())
        }
    }
}

fn merge_arg(
    label: &str,
    primary: Option<String>,
    secondary: Option<String>,
    primary_name: &str,
    secondary_name: &str,
) -> Result<Option<String>> {
    if primary.is_some() && secondary.is_some() {
        return Err(anyhow!(
            "use either {primary_name} or {secondary_name} for {label}"
        ));
    }
    Ok(primary.or(secondary))
}

fn format_policy(policy: &PqcPolicy) -> &'static str {
    match policy {
        PqcPolicy::Disabled => "disabled",
        PqcPolicy::Preferred => "preferred",
        PqcPolicy::Required => "required",
    }
}

fn max_input_bytes() -> Result<usize> {
    const DEFAULT_LIMIT: usize = 64 * 1024 * 1024;
    match std::env::var("QPGP_MAX_INPUT_BYTES") {
        Ok(value) => value
            .parse::<usize>()
            .map_err(|err| anyhow!("invalid QPGP_MAX_INPUT_BYTES value {value:?}: {err}")),
        Err(_) => Ok(DEFAULT_LIMIT),
    }
}

fn read_to_end_limited<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if buf.len() + read > limit {
            return Err(anyhow!(
                "input exceeds size limit ({limit} bytes); set QPGP_MAX_INPUT_BYTES to override"
            ));
        }
        buf.extend_from_slice(&chunk[..read]);
    }
    Ok(buf)
}

fn write_file_secure(path: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use std::fs::Permissions;
    use std::path::Path;

    let dest = Path::new(path);

    // On Unix, proactively check the destination and its parent using O_NOFOLLOW
    // to avoid obvious symlink-based surprises.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let parent = dest.parent().unwrap_or_else(|| Path::new("."));

        // Reject a symlink as the final parent path component (best-effort; does not
        // prevent symlinks in earlier path components without an openat-based walk).
        let mut d = std::fs::OpenOptions::new();
        d.read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let dirfd = d.open(parent).map_err(|err| {
            anyhow!(
                "refusing to write into directory {}: {err}",
                parent.display()
            )
        })?;
        drop(dirfd);

        // If the destination exists, ensure it is a regular file and not a symlink.
        let mut f = std::fs::OpenOptions::new();
        f.read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        match f.open(dest) {
            Ok(handle) => {
                let meta = handle.metadata()?;
                if !meta.is_file() {
                    return Err(anyhow!(
                        "refusing to write to non-regular file path: {}",
                        dest.display()
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow!(
                    "refusing to write to destination {}: {err}",
                    dest.display()
                ));
            }
        }
    }

    if let Ok(meta) = fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            return Err(anyhow!(
                "refusing to write to symlink path: {}",
                dest.display()
            ));
        }
        if !meta.file_type().is_file() {
            return Err(anyhow!(
                "refusing to write to non-regular file path: {}",
                dest.display()
            ));
        }
    }

    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;

    // Ensure strict permissions on the FD, not just on creation.
    #[cfg(unix)]
    {
        tmp.as_file()
            .set_permissions(Permissions::from_mode(0o600))?;
    }

    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;

    // Persist atomically where possible.
    #[cfg(unix)]
    {
        tmp.persist(dest)
            .map_err(|e| anyhow!("persist failed: {}", e.error))?;
    }
    #[cfg(not(unix))]
    {
        // Best-effort on non-Unix platforms: `persist` may fail if the destination exists.
        match tmp.persist(dest) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Non-atomic fallback: remove then persist.
                let _ = std::fs::remove_file(dest);
                e.file
                    .persist(dest)
                    .map_err(|e| anyhow!("persist failed: {}", e.error))?;
            }
            Err(e) => return Err(anyhow!("persist failed: {}", e.error)),
        }
    }

    // Ensure final mode even if an existing file had broader perms.
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(dest, Permissions::from_mode(0o600));
        if let Ok(dirfd) = std::fs::File::open(parent) {
            let _ = dirfd.sync_all();
        }
    }
    Ok(())
}

fn normalize_fingerprint(value: &str) -> Result<String> {
    let normalized = value
        .trim()
        .trim_start_matches("0x")
        .replace([' ', '\t'], "")
        .to_uppercase();
    let len = normalized.len();
    if (len != 40 && len != 64) || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "fingerprint must be 40 or 64 hex characters (got {len})"
        ));
    }
    Ok(normalized)
}

fn enforce_expected_signer(expected: Option<&str>, result: &VerifyResult) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    // Prefer the single-signer field if present, otherwise fall back to all good signers.
    if let Some(actual) = result.signer.as_ref() {
        let actual = normalize_fingerprint(&actual.0)
            .map_err(|_| anyhow!("signature does not include full fingerprint"))?;
        if actual == expected {
            return Ok(());
        }
        return Err(anyhow!("signature made by {actual}, expected {expected}"));
    }

    if result.signers.is_empty() {
        return Err(anyhow!("signature does not include signer fingerprint"));
    }
    for signer in &result.signers {
        if let Ok(actual) = normalize_fingerprint(&signer.0)
            && actual == expected
        {
            return Ok(());
        }
    }
    Err(anyhow!("signature not made by expected signer {expected}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env_var<F: FnOnce()>(key: &str, value: Option<&str>, f: F) {
        let _lock = ENV_LOCK.lock().expect("env lock poisoned");
        let prev = std::env::var_os(key);
        // Safety: tests serialize env changes via ENV_LOCK.
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        f();
        // Safety: tests serialize env changes via ENV_LOCK.
        unsafe {
            match prev {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    fn temp_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("qpgp-cli-test-{name}-{nanos}"))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn normalize_fingerprint_accepts_valid_inputs() {
        let short = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let normalized = normalize_fingerprint(short).expect("normalize");
        assert_eq!(normalized, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF");

        let spaced = "ab cd ef 12 34 56 78 90 ab cd ef 12 34 56 78 90 ab cd ef 12";
        let normalized = normalize_fingerprint(spaced).expect("normalize");
        assert_eq!(normalized, "ABCDEF1234567890ABCDEF1234567890ABCDEF12");
    }

    #[test]
    fn normalize_fingerprint_rejects_invalid_inputs() {
        let err = normalize_fingerprint("not-hex").expect_err("invalid");
        assert!(err.to_string().contains("fingerprint must be 40 or 64"));

        let err = normalize_fingerprint("abcd").expect_err("invalid");
        assert!(err.to_string().contains("fingerprint must be 40 or 64"));
    }

    #[test]
    fn merge_arg_enforces_exclusive_args() {
        let err = merge_arg("input", Some("a".into()), Some("b".into()), "--in", "FILE")
            .expect_err("expected conflict");
        assert!(err.to_string().contains("use either"));

        let merged = merge_arg("input", Some("a".into()), None, "--in", "FILE").expect("merge");
        assert_eq!(merged.as_deref(), Some("a"));
    }

    #[test]
    fn max_input_bytes_env_override() {
        with_env_var("QPGP_MAX_INPUT_BYTES", Some("1234"), || {
            let limit = max_input_bytes().expect("limit");
            assert_eq!(limit, 1234);
        });
    }

    #[test]
    fn max_input_bytes_invalid_env() {
        with_env_var("QPGP_MAX_INPUT_BYTES", Some("not-a-number"), || {
            let err = max_input_bytes().expect_err("expected error");
            assert!(err.to_string().contains("invalid QPGP_MAX_INPUT_BYTES"));
        });
    }

    #[test]
    fn read_to_end_limited_enforces_limit() {
        let data = vec![1u8; 10];
        let err = read_to_end_limited(Cursor::new(&data), 5).expect_err("expected limit error");
        assert!(err.to_string().contains("input exceeds size limit"));

        let ok = read_to_end_limited(Cursor::new(&data), 20).expect("read");
        assert_eq!(ok, data);
    }

    #[test]
    fn read_input_reads_file() {
        let path = temp_path("input");
        std::fs::write(&path, b"hello").expect("write input");
        let bytes = read_input(Some(path.clone())).expect("read input");
        assert_eq!(bytes, b"hello");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_input_rejects_large_file() {
        let path = temp_path("input-large");
        std::fs::write(&path, b"hello").expect("write input");
        with_env_var("QPGP_MAX_INPUT_BYTES", Some("2"), || {
            let err = read_input(Some(path.clone())).expect_err("expected size error");
            assert!(err.to_string().contains("input exceeds size limit"));
        });
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_passphrase_file_trims_newlines() {
        let path = temp_path("passphrase");
        std::fs::write(&path, b"secret\n").expect("write passphrase");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let passphrase = read_passphrase_file(&path).expect("read");
        assert_eq!(passphrase, "secret");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_passphrase_file_rejects_non_file() {
        let path = temp_path("passphrase-dir");
        std::fs::create_dir_all(&path).expect("mkdir");
        let err = read_passphrase_file(&path).expect_err("expected file type error");
        assert!(
            err.to_string().contains("regular file"),
            "unexpected: {err}"
        );
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn read_passphrase_file_rejects_invalid_utf8() {
        let path = temp_path("passphrase-invalid");
        std::fs::write(&path, [0xff, 0xfe]).expect("write passphrase");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        }
        let err = read_passphrase_file(&path).expect_err("expected utf8 error");
        assert!(
            err.to_string()
                .contains("passphrase file must be valid UTF-8")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn read_passphrase_file_rejects_broad_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("passphrase-broad");
        std::fs::write(&path, b"secret\n").expect("write passphrase");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let err = read_passphrase_file(&path).expect_err("expected perms error");
        assert!(err.to_string().contains("permissions too broad"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_file_secure_writes_and_sets_perms() {
        let path = temp_path("write");
        write_file_secure(&path, b"data").expect("write");
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes, b"data");
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
    #[cfg(unix)]
    fn write_file_secure_overwrites_with_strict_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("write-existing");
        std::fs::write(&path, b"old").expect("write existing");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        write_file_secure(&path, b"new").expect("write");

        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes, b"new");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn write_file_secure_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let target = temp_path("symlink-target");
        let link = temp_path("symlink-link");
        std::fs::write(&target, b"t").expect("write target");
        symlink(&target, &link).expect("symlink");

        let err = write_file_secure(&link, b"secret").expect_err("expected symlink error");
        assert!(err.to_string().contains("symlink"));

        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&link);
    }

    #[test]
    fn enforce_expected_signer_checks_identity() {
        let result = VerifyResult {
            valid: true,
            signer: Some(KeyId("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".into())),
            signers: vec![KeyId("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".into())],
            message: None,
        };
        enforce_expected_signer(Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"), &result)
            .expect("expected match");

        let err =
            enforce_expected_signer(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), &result)
                .expect_err("expected mismatch");
        assert!(err.to_string().contains("expected"));

        let result = VerifyResult {
            valid: true,
            signer: None,
            signers: vec![KeyId("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".into())],
            message: None,
        };
        enforce_expected_signer(Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"), &result)
            .expect("expected match via signers list");

        let err =
            enforce_expected_signer(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), &result)
                .expect_err("expected mismatch");
        assert!(err.to_string().contains("expected signer"));
    }

    #[test]
    fn format_policy_outputs_expected_labels() {
        assert_eq!(format_policy(&PqcPolicy::Disabled), "disabled");
        assert_eq!(format_policy(&PqcPolicy::Preferred), "preferred");
        assert_eq!(format_policy(&PqcPolicy::Required), "required");
    }
}
