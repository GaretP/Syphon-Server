//! Keeping the library unlocked across an update.
//!
//! The key that opens the library lives only in memory, so a plain restart locks it until someone signs in.
//! During an update that would mean a trip to every node. Instead the root helper, right before it restarts the
//! node, drops an "arm" file. A node that is shutting down and finds a fresh arm file writes its key to a file in
//! a private, memory-only folder (`/run/syphon-handoff`, readable only by the node's own account). The node that
//! starts next reads it, unlocks, and deletes it. Nothing is ever written to disk: /run is memory.
//!
//! A reboot or power cut still needs the password: the memory-only folder is gone by then. The hand-over only
//! works for a restart the helper started a moment ago, and a file that is old, in the wrong place or wrongly
//! owned is ignored and removed.

use crate::state::App;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const ARM_MAX_AGE: Duration = Duration::from_secs(300);
const KEY_MAX_AGE: Duration = Duration::from_secs(300);

pub fn default_dir() -> PathBuf {
    std::env::var_os("SYPHON_HANDOFF_DIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/run/syphon-handoff"))
}

fn fresh(p: &Path, max: Duration) -> bool {
    std::fs::symlink_metadata(p)
        .ok()
        .filter(|m| m.is_file())
        .and_then(|m| m.modified().ok())
        .and_then(|t| SystemTime::now().duration_since(t).ok().or(Some(Duration::ZERO)))
        .map(|age| age <= max)
        .unwrap_or(false)
}

#[cfg(unix)]
fn only_ours(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::symlink_metadata(p) else { return false };
    let me = self_uid();
    m.is_file() && m.mode() & 0o077 == 0 && m.uid() == me
}
#[cfg(not(unix))]
fn only_ours(_: &Path) -> bool {
    false
}

#[cfg(unix)]
fn self_uid() -> u32 {
    // the owner of our own data folder is this process's account
    std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m)).unwrap_or(u32::MAX)
}

fn wipe(p: &Path) {
    if let Ok(m) = std::fs::symlink_metadata(p) {
        if m.is_file() {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(p) {
                let _ = f.write_all(&vec![0u8; m.len() as usize]);
                let _ = f.sync_all();
            }
        }
    }
    let _ = std::fs::remove_file(p);
}

/// Called while shutting down: if the helper armed a hand-over a moment ago and the library is unlocked,
/// leave the key for the next start. Returns whether a key was left.
pub fn save_to(app: &App, dir: &Path) -> bool {
    let arm = dir.join("arm");
    let armed = fresh(&arm, ARM_MAX_AGE);
    let _ = std::fs::remove_file(&arm);
    if !armed {
        return false;
    }
    let Some(master) = app.keyring.export_master() else { return false };
    let key = dir.join("key");
    wipe(&key);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600); // create_new refuses to follow a symlink someone left at this path
    }
    match opts.open(&key).and_then(|mut f| {
        f.write_all(hex::encode(&*master).as_bytes())?;
        f.sync_all()
    }) {
        Ok(()) => {
            tracing::info!("update: the library key was left in memory-only storage for the next start");
            true
        }
        Err(e) => {
            tracing::warn!("update: could not leave the library key ({e}); the library will need a sign-in");
            false
        }
    }
}

pub fn save(app: &App) -> bool {
    save_to(app, &default_dir())
}

/// Called at start: take the key left by the previous run, unlock with it and delete it.
pub fn restore_from(app: &App, dir: &Path) -> bool {
    let key = dir.join("key");
    if !key.exists() && std::fs::symlink_metadata(&key).is_err() {
        return false;
    }
    let ok = fresh(&key, KEY_MAX_AGE) && only_ours(&key);
    let text = if ok { std::fs::read_to_string(&key).ok() } else { None };
    wipe(&key);
    let Some(text) = text else {
        tracing::warn!("update: ignored an old or unsafe key file; the library needs a sign-in");
        return false;
    };
    let Ok(bytes) = hex::decode(text.trim()) else { return false };
    let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else { return false };
    match app.keyring.unlock_with_master(&arr) {
        Ok(()) => {
            tracing::info!("update: the library was unlocked again after the restart");
            true
        }
        Err(_) => {
            tracing::warn!("update: the left-over key did not fit this library; sign in to unlock it");
            false
        }
    }
}

pub fn restore(app: &App) -> bool {
    restore_from(app, &default_dir())
}
