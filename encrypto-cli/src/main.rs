use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, KeyGenParams, KeyId, OPENPGP_PQC_DRAFT, PqcLevel,
    PqcPolicy, RevocationReason, RevokeRequest, RotateRequest, SignRequest, UserId, VerifyRequest,
};
use encrypto_pgp::{NativeBackend, pqc_algorithms_supported};
use std::fs;
use std::io::{self, Read, Write};

#[derive(Parser, Debug)]
#[command(
    name = "encrypto",
    version,
    about = "PQC-only OpenPGP-compatible crypto CLI"
)]
struct Cli {
    #[arg(long = "passphrase", global = true)]
    passphrase: Option<String>,

    #[arg(long = "passphrase-file", global = true)]
    passphrase_file: Option<String>,

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
    ListKeys,
    #[command(alias = "gen")]
    Keygen {
        user_id: String,
        #[arg(long, value_enum, default_value_t = PqcLevelArg::Baseline)]
        pqc_level: PqcLevelArg,
        #[arg(long = "no-passphrase")]
        no_passphrase: bool,
    },
    Import {
        path: String,
    },
    Export {
        key_id: String,
        #[arg(long)]
        secret: bool,
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
        #[arg(value_name = "FILE", index = 1)]
        input_file: Option<String>,
    },
    #[command(alias = "sig")]
    Sign {
        #[arg(short = 'u', long = "local-user", alias = "key")]
        key_id: String,
        #[arg(short = 'a', long)]
        armor: bool,
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
        #[arg(long, value_enum, default_value_t = PqcLevelArg::Baseline)]
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

    if cli.passphrase.is_some() {
        eprintln!("warning: --passphrase can expose secrets in process listings");
    }

    if cli.passphrase.is_some() && cli.passphrase_file.is_some() {
        eprintln!("warning: both --passphrase and --passphrase-file set; using file");
    }

    let native_passphrase = if let Some(path) = &cli.passphrase_file {
        Some(read_passphrase_file(path)?)
    } else {
        cli.passphrase.clone()
    };

    let backend: Box<dyn Backend> = Box::new(NativeBackend::with_passphrase(
        pqc_policy.clone(),
        native_passphrase.clone(),
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
            }
            print_env("ENCRYPTO_HOME");
            print_env("ENCRYPTO_OPENSSL_CONF");
            print_env("OPENSSL_CONF");
            print_env("OPENSSL_MODULES");
            print_env("LD_LIBRARY_PATH");
            Ok(())
        }
        Command::ListKeys => {
            let keys = backend.list_keys()?;
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
                let created = key.created_utc.as_deref().unwrap_or("(unknown)");
                println!("{} | {} | {} | {}", key.key_id.0, user, key.algo, created);
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
        Command::Import { path } => {
            let bytes = fs::read(path)?;
            let meta = backend.import_key(&bytes)?;
            println!("imported key: {}", meta.key_id.0);
            Ok(())
        }
        Command::Export {
            key_id,
            secret,
            out,
        } => {
            let bytes = backend.export_key(&KeyId(key_id), secret)?;
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
            input_file,
        } => {
            let input_path = merge_arg("input", input, input_file, "--input", "FILE")?;
            let ciphertext = read_input(input_path)?;
            let plaintext = backend.decrypt(DecryptRequest {
                ciphertext,
                pqc_policy: pqc_policy.clone(),
            })?;
            write_output(output, &plaintext)
        }
        Command::Sign {
            key_id,
            armor,
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
        } => {
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
                pqc_policy: pqc_policy.clone(),
            })?;
            if result.valid {
                match result.signer {
                    Some(signer) => println!("valid signature from {}", signer.0),
                    None => println!("valid signature"),
                }
                Ok(())
            } else {
                Err(anyhow!("invalid signature"))
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
    match path {
        Some(path) if path == "-" => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
        Some(path) => Ok(fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn read_passphrase_file(path: &str) -> Result<String> {
    let bytes = fs::read(path)?;
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

fn write_output(path: Option<String>, bytes: &[u8]) -> Result<()> {
    match path {
        Some(path) => {
            fs::write(path, bytes)?;
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
