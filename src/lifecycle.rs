//! Starting up after a crash or power cut, and shutting down cleanly.
//!
//! Two modes (`persistence` in config.toml, asked by the installer):
//!  * `always_on`: the node may lose power at any moment. Writes are flushed to disk, unfinished
//!    downloads and transfers pick up again by themselves, and a clean shutdown keeps all of that.
//!  * `on_demand`: the node is switched on and off by hand. A clean shutdown also forgets transient
//!    leftovers (queued downloads, half-received files, waiting sign-in approvals), so nothing
//!    half-finished is left on the disk.
//! Videos already in the library are kept in both modes.

use crate::state::{App, Shared};
use crate::util::now;
use anyhow::Result;
use std::path::Path;
use std::time::Duration;

#[derive(Default, Debug, Clone)]
pub struct Recovery {
    pub stale_files: usize,
    pub chunk_rows_fixed: usize,
    pub downloads_paused: usize,
    pub database_ok: bool,
}

fn remove_matching(dir: &Path, pred: &dyn Fn(&str) -> bool, recurse: bool) -> usize {
    let mut n = 0;
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if recurse {
                n += remove_matching(&p, pred, true);
            }
        } else if pred(&name) && std::fs::remove_file(&p).is_ok() {
            n += 1;
        }
    }
    n
}

/// Run once before anything else starts. Safe to run on a clean disk.
pub fn recover_on_start(app: &App) -> Result<Recovery> {
    let mut r = Recovery::default();

    // files that were being written when the power went: none of them was ever promised to anyone
    for d in crate::storage::all_dirs(app, "quarantine") {
        r.stale_files += remove_matching(&d, &(|n| n.starts_with("incoming-") && n.ends_with(".tmp")), false);
    }
    for d in crate::storage::all_dirs(app, "vault") {
        r.stale_files += remove_matching(&d, &(|n| n.starts_with("incoming-") && n.ends_with(".tmp")), false);
    }
    for d in crate::storage::all_dirs(app, "inbox") {
        r.stale_files += remove_matching(&d, &(|n| n.ends_with(".assemble") || n.ends_with(".part")), true);
    }
    r.stale_files += remove_matching(&app.dirs.root, &(|n| n.ends_with(".tmp")), false);
    r.stale_files += remove_matching(&app.dirs.tor(), &(|n| n.ends_with(".tmp")), false);

    r.database_ok = app
        .db
        .with(|c| Ok(c.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))?))
        .map(|s| s == "ok")
        .unwrap_or(false);
    if !r.database_ok {
        tracing::error!("the database failed its integrity check; restore syphon.db from a backup if things look wrong");
    }

    // nothing is transferring right now, so "syncing" can only be left over
    app.db.with(|c| {
        c.execute("UPDATE items SET local='absent' WHERE local='syncing'", [])?;
        Ok(())
    })?;
    // a received-chunk record only counts if its file survived intact
    let rows: Vec<(String, i64)> = app.db.with(|c| {
        let mut st = c.prepare("SELECT item,idx FROM chunks")?;
        let v = st.query_map([], |x| Ok((x.get(0)?, x.get(1)?)))?;
        Ok(v.collect::<rusqlite::Result<_>>()?)
    })?;
    for (item, idx) in rows {
        let f = crate::library::inbox_dir(app, &item).join(idx.to_string());
        if !f.is_file() {
            app.db.with(|c| {
                c.execute("DELETE FROM chunks WHERE item=?1 AND idx=?2", rusqlite::params![item, idx])?;
                Ok(())
            })?;
            r.chunk_rows_fixed += 1;
        }
    }

    if app.cfg.persistent() {
        r.downloads_paused = app.db.with(|c| {
            Ok(c.execute("UPDATE downloads SET status='waiting', error='interrupted; starts again after sign-in' WHERE status IN ('queued','resolving','downloading','retrying')", [])?)
        })?;
    } else {
        discard_transient(app);
    }

    // nodes made before downloads were sent through Tor: switch them over once
    if app.cfg.transport == "tor" && app.cfg.acquire.route == "direct" && app.db.get_setting("route_migrated").ok().flatten().is_none() {
        let mut cfg = app.cfg.clone();
        cfg.acquire.route = "auto".into();
        if cfg.save(&app.dirs).is_ok() {
            tracing::info!("downloads now go through Tor (set [acquire] route = \"direct\" again to opt out)");
        }
        let _ = app.db.set_setting("route_migrated", "1");
    }
    Ok(r)
}

/// "On demand" mode: forget unfinished, transient work.
fn discard_transient(app: &App) {
    let _ = app.db.with(|c| {
        c.execute("UPDATE downloads SET status='failed', error='cancelled by a restart' WHERE status IN ('queued','resolving','downloading','retrying','waiting')", [])?;
        c.execute("DELETE FROM approvals WHERE status='pending'", [])?;
        c.execute("DELETE FROM chunks", [])?;
        c.execute("UPDATE items SET local='absent' WHERE local='syncing'", [])?;
        Ok(())
    });
    for inbox in crate::storage::all_dirs(app, "inbox") {
        if let Ok(rd) = std::fs::read_dir(&inbox) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let _ = std::fs::remove_dir_all(&p);
                }
            }
        }
        remove_matching(&inbox, &(|n| n.ends_with(".assemble")), false);
    }
}

/// After the owner signs in (the library key is available again): pick unfinished work back up.
pub async fn on_unlock(app: &Shared) {
    let _ = crate::library::assemble_pending(app).await;
    crate::acquire::resume_downloads(app);
    // files that arrived but were not inspected before the interruption: the background scanner takes them
    if app.cfg.scan.background {
        app.scan_wake.notify_one();
    } else {
        let ids: Vec<String> = app
            .db
            .with(|c| {
                let mut st = c.prepare("SELECT id FROM items WHERE local='quarantine' AND scan IS NULL AND deleted=0")?;
                let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(v)
            })
            .unwrap_or_default();
        for id in ids {
            let _ = crate::quarantine::process_one(app, &id).await;
        }
    }
    app.wake.notify_waiters();
}

/// Everything that should happen before the process exits. Safe to call more than once.
pub async fn shutdown(app: &Shared) {
    use std::sync::atomic::Ordering;
    if app.shutting_down.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::info!("shutting down: finishing what is in flight");
    app.shutdown.notify_waiters();
    app.wake.notify_waiters();

    // give running chunk writes and downloads a moment to stop at a safe point
    for _ in 0..50 {
        let busy = !app.active_downloads.lock().unwrap().is_empty() || app.active_serves.load(Ordering::SeqCst) > 0 || !app.transfers.lock().unwrap().is_empty();
        if !busy {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if !app.cfg.persistent() {
        discard_transient(app);
    }
    app.sessions.lock().unwrap().clear();
    crate::handoff::save(app);
    app.keyring.lock();
    let _ = app.db.set_setting("last_clean_shutdown", &now().to_string());
    let _ = app.db.with(|c| {
        c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    });
    let a = app.clone();
    let _ = tokio::task::spawn_blocking(move || crate::tor::stop(&a)).await;
    tracing::info!("stopped cleanly");
}

/// Resolves when SIGTERM (power button, `systemctl stop`), SIGINT (Ctrl-C) or SIGHUP-less quit arrives.
pub async fn wait_for_stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("signal handler");
        let mut int = signal(SignalKind::interrupt()).expect("signal handler");
        tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// A consistent copy of the database (taken while the node runs) plus the small files that matter (keyring,
/// node identity, settings). The library's videos are not copied: updates never touch them.
pub fn snapshot(root: &std::path::Path, to: &std::path::Path) -> anyhow::Result<usize> {
    use rusqlite::{Connection, OpenFlags};
    std::fs::create_dir_all(to)?;
    let dest = to.join("syphon.db");
    let _ = std::fs::remove_file(&dest);
    let src = root.join("syphon.db");
    let mut n = 0;
    if src.exists() {
        let c = Connection::open_with_flags(&src, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        c.busy_timeout(std::time::Duration::from_secs(30))?;
        c.execute("VACUUM INTO ?1", [dest.to_string_lossy().as_ref()])?;
        n += 1;
    }
    for e in std::fs::read_dir(root)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        let m = e.metadata()?;
        if m.is_file() && m.len() <= 8 << 20 && !name.starts_with("syphon.db") && !name.starts_with('.') {
            std::fs::copy(e.path(), to.join(&name))?;
            n += 1;
        }
    }
    Ok(n)
}
