use qpgp_policy::{ensure_pqc_encryption_output, ensure_pqc_signature_output};
use std::fs;
use std::path::Path;

fn load_vectors(prefix: &str) -> Vec<Vec<u8>> {
    let dir = Path::new("qpgp-pgp/tests/vectors");
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str())
                && name.starts_with(prefix)
                && name.ends_with(".asc")
                && let Ok(bytes) = fs::read(&path)
            {
                entries.push(bytes);
            }
        }
    }
    entries
}

#[test]
fn draft_message_vectors_are_pqc() {
    let vectors = load_vectors("message-");
    if vectors.is_empty() {
        eprintln!("draft vectors not found; run scripts/fetch-draft-vectors.sh");
        return;
    }
    for bytes in vectors {
        ensure_pqc_encryption_output(&bytes).expect("draft message is not PQC");
    }
}

#[test]
fn draft_signature_vectors_are_pqc() {
    let vectors = load_vectors("signature-");
    if vectors.is_empty() {
        eprintln!("draft vectors not found; run scripts/fetch-draft-vectors.sh");
        return;
    }
    for bytes in vectors {
        ensure_pqc_signature_output(&bytes).expect("draft signature is not PQC");
    }
}
