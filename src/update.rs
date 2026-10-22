//! Updating a node. The node itself never runs anything privileged: the owner's "Update" button only
//! drops a small request file. A separate root-owned systemd unit (`syphon-update`) notices it, downloads the
//! release you built and signed (through Tor), refuses anything whose signed manifest, hash or contents do not
//! check out, saves a copy of the database, swaps the program in, restarts the node (which keeps the library
//! unlocked, see handoff.rs), checks that it came back, and rolls back if not.
//! It reports progress in `update/status.json`, which is all this module reads.

use crate::state::App;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::path::PathBuf;

pub fn version() -> &'static str {
    env!("SYPHON_VERSION")
}

fn dir(app: &App) -> PathBuf {
    app.dirs.root.join("update")
}

/// Is there an update service on this machine, and where does it pull from (host only)?
pub fn configured() -> Option<String> {
    let conf = std::fs::read_to_string("/etc/syphon/update.conf").ok()?;
    let repo = conf.lines().find_map(|l| l.strip_prefix("REPO="))?.trim().trim_matches('"').to_string();
    if repo.is_empty() {
        return None;
    }
    let host = repo.split("://").nth(1).unwrap_or(&repo).split(['/', ':']).next().unwrap_or("").trim_start_matches("git@").to_string();
    Some(if host.is_empty() { "your repository".into() } else { host })
}

pub fn status(app: &App) -> Value {
    let mut v: Value = std::fs::read_to_string(dir(app).join("status.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_else(|| json!({ "state": "idle" }));
    v["current"] = json!(version());
    v["source"] = json!(configured());
    v["has_previous"] = json!(std::path::Path::new("/usr/local/bin/syphon.prev").exists());
    v
}

/// Ask the update service to do something: "check", "apply" or "rollback".
pub fn request(app: &App, action: &str) -> Result<()> {
    if !["check", "apply", "rollback"].contains(&action) {
        bail!("unknown update action");
    }
    if configured().is_none() {
        bail!("updates are not set up on this machine yet. Run: sudo syphon-ctl update-source set <your repository address>");
    }
    crate::storage::write_request(&app.dirs.root, action, &[]).map_err(|e| anyhow::anyhow!(e))
}

/// Remove this node from the machine. With the installer's root helper present, ask it to remove everything
/// Syphon put on the computer (program, service, data, user). Without it (a hand-run node), wipe the data
/// folder ourselves and exit. Returns which way it went.
pub fn kill(app: &App) -> Result<&'static str> {
    let root = app.dirs.root.clone();
    if root.components().count() < 3 {
        bail!("refusing to wipe an unsafe folder");
    }
    // 1. ask the root helper to remove the program, services and user (if it is installed)
    let helper = std::path::Path::new("/usr/local/bin/syphon-update").exists();
    if helper {
        crate::storage::write_request(&root, "kill", &[]).map_err(|e| anyhow::anyhow!(e))?;
    }
    // 2. whatever the helper does, this node wipes its own data and stops for good (exit 3 = do not restart)
    app.keyring.lock();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
            let p = e.path();
            if helper && p.file_name().map(|n| n == "update").unwrap_or(false) {
                continue; // the helper's request lives here
            }
            let _ = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
        }
        std::process::exit(3);
    });
    Ok(if helper { "helper" } else { "self" })
}
