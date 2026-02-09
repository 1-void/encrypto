use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

pub struct TempHome {
    _lock: MutexGuard<'static, ()>,
    _dir: TempDir,
    prev: Option<OsString>,
}

#[allow(dead_code)]
pub struct EnvHome {
    _lock: MutexGuard<'static, ()>,
    prev: Option<OsString>,
}

impl Drop for EnvHome {
    fn drop(&mut self) {
        // Safety: tests serialize env changes via ENV_LOCK.
        unsafe {
            match &self.prev {
                Some(value) => std::env::set_var("QPGP_HOME", value),
                None => std::env::remove_var("QPGP_HOME"),
            }
        }
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        // Safety: tests serialize env changes via ENV_LOCK.
        unsafe {
            match &self.prev {
                Some(value) => std::env::set_var("QPGP_HOME", value),
                None => std::env::remove_var("QPGP_HOME"),
            }
        }
    }
}

#[allow(dead_code)]
pub fn set_home(path: &std::path::Path) -> EnvHome {
    let lock = ENV_LOCK.lock().expect("env lock poisoned");
    let prev = std::env::var_os("QPGP_HOME");
    // Safety: tests serialize env changes via ENV_LOCK.
    unsafe {
        std::env::set_var("QPGP_HOME", path);
    }
    EnvHome { _lock: lock, prev }
}

pub fn set_temp_home() -> TempHome {
    let lock = ENV_LOCK.lock().expect("env lock poisoned");
    let dir = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod temp home");
    }
    let prev = std::env::var_os("QPGP_HOME");
    // Safety: tests serialize env changes via ENV_LOCK.
    unsafe {
        std::env::set_var("QPGP_HOME", dir.path());
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
