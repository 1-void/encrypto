use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub struct TempHome {
    _lock: MutexGuard<'static, ()>,
    _dir: TempDir,
    prev: Option<OsString>,
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // Safety: tests serialize env changes via ENV_LOCK.
        unsafe {
            match &self.prev {
                Some(value) => std::env::set_var("ENCRYPTO_HOME", value),
                None => std::env::remove_var("ENCRYPTO_HOME"),
            }
        }
    }
}

pub fn set_temp_home() -> TempHome {
    let lock = ENV_LOCK.lock().expect("env lock poisoned");
    let dir = tempfile::tempdir().expect("tempdir");
    let prev = std::env::var_os("ENCRYPTO_HOME");
    // Safety: tests serialize env changes via ENV_LOCK.
    unsafe {
        std::env::set_var("ENCRYPTO_HOME", dir.path());
    }
    TempHome {
        _lock: lock,
        _dir: dir,
        prev,
    }
}

pub fn require_pqc(supported: bool) -> bool {
    if supported {
        return true;
    }
    if std::env::var_os("CI").is_some() {
        panic!("PQC not available in CI; run scripts/bootstrap-pqc.sh");
    }
    eprintln!("pqc not supported in this environment; skipping");
    false
}
