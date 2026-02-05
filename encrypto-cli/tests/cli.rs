use encrypto_core::{Backend, PqcLevel, PqcPolicy};
use encrypto_pgp::{NativeBackend, pqc_suite_supported};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

fn pqc_available() -> bool {
    NativeBackend::new(PqcPolicy::Required).supports_pqc()
}

fn pqc_high_available() -> bool {
    let supported = pqc_suite_supported(PqcLevel::High);
    if !supported && std::env::var_os("CI").is_some() {
        panic!("PQC high suite not available in CI; run scripts/bootstrap-pqc.sh");
    }
    supported
}

fn temp_home() -> PathBuf {
    let mut dir = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    dir.push(format!("encrypto-cli-test-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn temp_file_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.push(format!("encrypto-cli-test-file-{name}-{nanos}"));
    path
}

fn run_cli(args: &[&str], home: &PathBuf, stdin: Option<&[u8]>) -> (i32, String, String) {
    let bin = env!("CARGO_BIN_EXE_encrypto-cli");
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .env("ENCRYPTO_HOME", home)
        .env("RUST_BACKTRACE", "0")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
        cmd.env("LLVM_PROFILE_FILE", profile);
    }

    let mut child = cmd.spawn().expect("spawn encrypto-cli");
    if let Some(input) = stdin {
        let mut handle = child.stdin.take().expect("stdin handle");
        handle.write_all(input).expect("write stdin");
    }
    let output = child.wait_with_output().expect("wait output");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn parse_first_fingerprint(output: &str) -> Option<String> {
    for line in output.lines() {
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 2 && (parts[0] == "sec" || parts[0] == "pub") {
            return Some(parts[1].to_string());
        }
    }
    None
}

#[test]
fn verify_requires_signer_flag() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(&["verify", "sig", "msg"], &home, None);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("verify requires --signer"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn verify_rejects_invalid_signer_format() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["verify", "--signer", "deadbeef", "sig", "msg"],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("fingerprint must be 40 or 64 hex characters"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn encrypt_requires_full_fingerprint() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(&["encrypt", "-r", "short"], &home, Some(b"hi"));
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("full fingerprint required"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn list_keys_rejects_relative_home() {
    if !pqc_available() {
        return;
    }
    let bin = env!("CARGO_BIN_EXE_encrypto-cli");
    let output = Command::new(bin)
        .args(["list-keys"])
        .env("ENCRYPTO_HOME", "relative-home")
        .output()
        .expect("run list-keys");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ENCRYPTO_HOME must be an absolute path"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn keygen_defaults_to_high() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["keygen", "Default <default@example.com>", "--no-passphrase"],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    assert!(
        stdout.contains("MLDSA87_Ed448"),
        "expected high-level algorithm in list-keys output: {stdout}"
    );
}

#[test]
fn info_reports_pqc_status() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, stdout, stderr) = run_cli(&["info"], &home, None);
    assert_eq!(code, 0, "info failed: {stderr}");
    assert!(stdout.contains("backend:"), "missing backend line");
    assert!(stdout.contains("pqc supported:"), "missing pqc line");
}

#[test]
fn doctor_requires_pqc_suites() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, stdout, stderr) = run_cli(&["doctor"], &home, None);
    assert_eq!(code, 0, "doctor failed: {stderr}");
    assert!(stdout.contains("pqc algo"), "missing algo output");
}

#[test]
fn encrypt_requires_recipient() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(&["encrypt"], &home, Some(b"hi"));
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("at least one -r/--recipient"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn encrypt_decrypt_roundtrip() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["keygen", "CLI Enc <cli-enc@example.com>", "--no-passphrase"],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let msg_path = home.join("msg.txt");
    let cipher_path = home.join("msg.pgp");
    let out_path = home.join("msg.out");
    std::fs::write(&msg_path, b"hello encrypt").expect("write msg");

    let (code, _stdout, stderr) = run_cli(
        &[
            "encrypt",
            "-r",
            &fpr,
            "--in",
            msg_path.to_str().unwrap(),
            "--out",
            cipher_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "encrypt failed: {stderr}");

    let (code, _stdout, stderr) = run_cli(
        &[
            "decrypt",
            "--in",
            cipher_path.to_str().unwrap(),
            "--out",
            out_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "decrypt failed: {stderr}");
    let output = std::fs::read(&out_path).expect("read output");
    assert_eq!(output, b"hello encrypt");
}

#[test]
fn encrypt_rejects_conflicting_input_args() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let input_path = temp_file_path("input-conflict");
    std::fs::write(&input_path, b"hello").expect("write input");
    let (code, _stdout, stderr) = run_cli(
        &[
            "encrypt",
            "-r",
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            "--input",
            input_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ],
        &home,
        Some(b"stdin"),
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("use either --input or FILE"),
        "unexpected stderr: {stderr}"
    );
    let _ = std::fs::remove_file(&input_path);
}

#[test]
fn sign_and_verify_roundtrip() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI Sign <cli-sign@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let msg_path = home.join("msg.txt");
    let sig_path = home.join("msg.sig");
    std::fs::write(&msg_path, b"hello cli").expect("write msg");

    let (code, _stdout, stderr) = run_cli(
        &[
            "sign",
            "-u",
            &fpr,
            "--in",
            msg_path.to_str().unwrap(),
            "--out",
            sig_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "sign failed: {stderr}");

    let (code, _stdout, stderr) = run_cli(
        &[
            "verify",
            "--signer",
            &fpr,
            sig_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "verify failed: {stderr}");
}

#[test]
fn clearsign_and_verify_roundtrip() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI Clearsign <cli-clearsign@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let msg_path = home.join("clear.txt");
    let sig_path = home.join("clear.asc");
    std::fs::write(&msg_path, b"clear text content").expect("write msg");

    let (code, _stdout, stderr) = run_cli(
        &[
            "sign",
            "-u",
            &fpr,
            "--clearsign",
            "--in",
            msg_path.to_str().unwrap(),
            "--out",
            sig_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "clearsign failed: {stderr}");

    let (code, _stdout, stderr) = run_cli(
        &[
            "verify",
            "--signer",
            &fpr,
            "--clearsigned",
            sig_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "verify clearsigned failed: {stderr}");
}

#[test]
fn sign_rejects_conflicting_input_args() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI Conflict <cli-conflict@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let msg_path = home.join("conflict.txt");
    std::fs::write(&msg_path, b"hello cli").expect("write msg");

    let (code, _stdout, stderr) = run_cli(
        &[
            "sign",
            "-u",
            &fpr,
            "--input",
            msg_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("use either --input or FILE"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn verify_requires_signature_file_when_not_clearsigned() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &[
            "verify",
            "--signer",
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            "--input",
            "msg.txt",
        ],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("signature file is required"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn decrypt_rejects_conflicting_input_args() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let input_path = temp_file_path("decrypt-conflict");
    std::fs::write(&input_path, b"cipher").expect("write input");
    let (code, _stdout, stderr) = run_cli(
        &[
            "decrypt",
            "--input",
            input_path.to_str().unwrap(),
            input_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("use either --input or FILE"),
        "unexpected stderr: {stderr}"
    );
    let _ = std::fs::remove_file(&input_path);
}

#[test]
fn decrypt_rejects_empty_input() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(&["decrypt"], &home, None);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("parse output failed") || !stderr.trim().is_empty(),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn verify_rejects_conflicting_input_args() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let sig_path = temp_file_path("sig-conflict");
    let msg_path = temp_file_path("msg-conflict");
    std::fs::write(&sig_path, b"sig").expect("write sig");
    std::fs::write(&msg_path, b"msg").expect("write msg");
    let (code, _stdout, stderr) = run_cli(
        &[
            "verify",
            "--signer",
            "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
            "--input",
            msg_path.to_str().unwrap(),
            sig_path.to_str().unwrap(),
            msg_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("use either --input or FILE"),
        "unexpected stderr: {stderr}"
    );
    let _ = std::fs::remove_file(&sig_path);
    let _ = std::fs::remove_file(&msg_path);
}

#[test]
fn keygen_requires_passphrase_without_flag() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["keygen", "Need Passphrase <need-pass@example.com>"],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("passphrase required for native keygen"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn rotate_requires_passphrase_without_flag() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI Rotate <cli-rotate@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let (code, _stdout, stderr) = run_cli(&["rotate", &fpr], &home, None);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("passphrase required for native rotation"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn import_errors_on_missing_file() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let missing = temp_file_path("missing-key");
    let (code, _stdout, stderr) = run_cli(&["import", missing.to_str().unwrap()], &home, None);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        stderr.contains("No such file") || stderr.contains("no such file"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn export_errors_on_missing_key() {
    if !pqc_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &["export", "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"],
        &home,
        None,
    );
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(!stderr.trim().is_empty(), "expected stderr for missing key");
}

#[test]
fn export_errors_on_unwritable_output() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI Export <cli-export@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let bad_dir = temp_file_path("export-dir");
    std::fs::create_dir_all(&bad_dir).expect("create dir");
    let bad_path = bad_dir.to_str().unwrap();
    let (code, _stdout, stderr) = run_cli(&["export", &fpr, "--out", bad_path], &home, None);
    assert_ne!(code, 0, "expected non-zero exit");
    assert!(
        !stderr.trim().is_empty(),
        "expected stderr for unwritable output: {stderr}"
    );
}

#[test]
fn export_secret_requires_secret_key() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let public_path = temp_file_path("public-key");
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI PublicOnly <cli-public@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let (code, _stdout, stderr) = run_cli(
        &["export", &fpr, "--out", public_path.to_str().unwrap()],
        &home,
        None,
    );
    assert_eq!(code, 0, "export failed: {stderr}");

    let home2 = temp_home();
    let (code, _stdout, stderr) = run_cli(&["import", public_path.to_str().unwrap()], &home2, None);
    assert_eq!(code, 0, "import failed: {stderr}");

    let (code, _stdout, stderr) = run_cli(&["export", &fpr, "--secret"], &home2, None);
    assert_ne!(code, 0, "expected secret export failure");
    assert!(
        stderr.contains("secret key not available"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn export_armor_contains_header() {
    if !pqc_available() || !pqc_high_available() {
        return;
    }
    let home = temp_home();
    let output_path = temp_file_path("armor-export");
    let (code, _stdout, stderr) = run_cli(
        &[
            "keygen",
            "CLI Armor <cli-armor@example.com>",
            "--no-passphrase",
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "keygen failed: {stderr}");

    let (code, stdout, stderr) = run_cli(&["list-keys", "--secret"], &home, None);
    assert_eq!(code, 0, "list-keys failed: {stderr}");
    let fpr = parse_first_fingerprint(&stdout).expect("fingerprint");

    let (code, _stdout, stderr) = run_cli(
        &[
            "export",
            &fpr,
            "--armor",
            "--out",
            output_path.to_str().unwrap(),
        ],
        &home,
        None,
    );
    assert_eq!(code, 0, "export failed: {stderr}");

    let armored = std::fs::read_to_string(&output_path).expect("read armored");
    assert!(
        armored.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "expected public key armor"
    );
}
