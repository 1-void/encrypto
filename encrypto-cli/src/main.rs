use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, ValueEnum};
use encrypto_core::{
    Backend, DecryptRequest, EncryptRequest, KeyGenParams, KeyId, PqcLevel, PqcPolicy, SignRequest,
    UserId,
    VerifyRequest,
};
use encrypto_pgp::{
    pqc_algorithms_supported, GpgBackend, GpgConfig, NativeBackend, PinentryMode,
};
use std::fs;
use std::io::{self, Read, Write};

#[derive(Parser, Debug)]
#[command(
    name = "encrypto",
    version,
    about = "OpenPGP-compatible crypto CLI with PQC planning"
)]
struct Cli {
    #[arg(long, value_enum, default_value_t = BackendKind::Gpg)]
    backend: BackendKind,

    #[arg(long, value_enum, default_value_t = PqcMode::Preferred)]
    pqc: PqcMode,

    #[arg(long = "gpg-path", global = true, default_value = "gpg")]
    gpg_path: String,

    #[arg(long = "gpg-home", global = true)]
    gpg_home: Option<String>,

    #[arg(
        long = "gpg-pinentry",
        value_enum,
        global = true,
        default_value_t = PinentryModeArg::Default
    )]
    gpg_pinentry: PinentryModeArg,

    #[arg(long = "gpg-passphrase", global = true)]
    gpg_passphrase: Option<String>,

    #[arg(long = "gpg-passphrase-file", global = true)]
    gpg_passphrase_file: Option<String>,

    #[arg(long = "gpg-batch", global = true)]
    gpg_batch: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum BackendKind {
    Gpg,
    Native,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum PqcMode {
    Disabled,
    Preferred,
    Required,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum PqcLevelArg {
    Baseline,
    High,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum PinentryModeArg {
    Default,
    Ask,
    Loopback,
}

impl From<PqcMode> for PqcPolicy {
    fn from(mode: PqcMode) -> Self {
        match mode {
            PqcMode::Disabled => PqcPolicy::Disabled,
            PqcMode::Preferred => PqcPolicy::Preferred,
            PqcMode::Required => PqcPolicy::Required,
        }
    }
}

impl From<PinentryModeArg> for PinentryMode {
    fn from(mode: PinentryModeArg) -> Self {
        match mode {
            PinentryModeArg::Default => PinentryMode::Default,
            PinentryModeArg::Ask => PinentryMode::Ask,
            PinentryModeArg::Loopback => PinentryMode::Loopback,
        }
    }
}

impl From<PqcLevelArg> for PqcLevel {
    fn from(level: PqcLevelArg) -> Self {
        match level {
            PqcLevelArg::Baseline => PqcLevel::Baseline,
            PqcLevelArg::High => PqcLevel::High,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    Info,
    ListKeys,
    Keygen {
        user_id: String,
        #[arg(long)]
        algo: Option<String>,
        #[arg(long, value_enum, default_value_t = PqcLevelArg::Baseline)]
        pqc_level: PqcLevelArg,
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
    Encrypt {
        #[arg(long = "to")]
        recipients: Vec<String>,
        #[arg(long)]
        armor: bool,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
    Decrypt {
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
    Sign {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        armor: bool,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        output: Option<String>,
    },
    Verify {
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        sig: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pqc_policy: PqcPolicy = cli.pqc.into();

    if cli.gpg_passphrase.is_some() {
        eprintln!("warning: --gpg-passphrase can expose secrets in process listings");
    }

    if cli.gpg_passphrase.is_some() && cli.gpg_passphrase_file.is_some() {
        eprintln!("warning: both --gpg-passphrase and --gpg-passphrase-file set; using file");
    }

    let gpg_config = GpgConfig {
        gpg_path: cli.gpg_path.clone(),
        homedir: cli.gpg_home.clone(),
        pinentry_mode: cli.gpg_pinentry.into(),
        passphrase: if cli.gpg_passphrase_file.is_some() {
            None
        } else {
            cli.gpg_passphrase.clone()
        },
        passphrase_file: cli.gpg_passphrase_file.clone(),
        batch: cli.gpg_batch,
    };

    let backend: Box<dyn Backend> = match cli.backend {
        BackendKind::Gpg => Box::new(GpgBackend::new(gpg_config)),
        BackendKind::Native => Box::new(NativeBackend::new(pqc_policy.clone())),
    };

    if matches!(pqc_policy, PqcPolicy::Required) && !backend.supports_pqc() {
        return Err(anyhow!(
            "backend '{}' does not support PQC but --pqc required was set",
            backend.name()
        ));
    }

    match cli.cmd {
        Command::Info => {
            println!("backend: {}", backend.name());
            println!("pqc policy: {}", format_policy(&pqc_policy));
            println!("pqc supported: {}", backend.supports_pqc());
            if backend.name() == "native" {
                for (name, supported) in pqc_algorithms_supported() {
                    println!("pqc algo {name}: {supported}");
                }
            }
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
            algo,
            pqc_level,
        } => {
            let params = KeyGenParams {
                user_id: UserId(user_id),
                algo,
                pqc_policy: pqc_policy.clone(),
                pqc_level: pqc_level.into(),
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
            armor,
            input,
            output,
        } => {
            if recipients.is_empty() {
                return Err(anyhow!("at least one --to recipient is required"));
            }
            let plaintext = read_input(input)?;
            let request = EncryptRequest {
                recipients: recipients.into_iter().map(KeyId).collect(),
                plaintext,
                armor,
                pqc_policy: pqc_policy.clone(),
            };
            let ciphertext = backend.encrypt(request)?;
            write_output(output, &ciphertext)
        }
        Command::Decrypt { input, output } => {
            let ciphertext = read_input(input)?;
            let plaintext = backend.decrypt(DecryptRequest { ciphertext })?;
            write_output(output, &plaintext)
        }
        Command::Sign {
            key_id,
            armor,
            input,
            output,
        } => {
            let message = read_input(input)?;
            let request = SignRequest {
                signer: KeyId(key_id),
                message,
                armor,
                pqc_policy: pqc_policy.clone(),
            };
            let signature = backend.sign(request)?;
            write_output(output, &signature)
        }
        Command::Verify { input, sig } => {
            let message = read_input(input)?;
            let signature = read_input(sig)?;
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
    }
}

fn read_input(path: Option<String>) -> Result<Vec<u8>> {
    match path {
        Some(path) => Ok(fs::read(path)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
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

fn format_policy(policy: &PqcPolicy) -> &'static str {
    match policy {
        PqcPolicy::Disabled => "disabled",
        PqcPolicy::Preferred => "preferred",
        PqcPolicy::Required => "required",
    }
}
