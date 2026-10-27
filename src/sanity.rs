//! The periodic sanity check: a small, safe pass over the node that keeps names tidy, retries titles whose
//! details were not found, and looks for trouble early (a damaged database, videos whose stored file has gone
//! missing, forgotten uploads, an overgrown trash).
//!
//! It runs every 6 hours. It never changes or deletes a video's bytes; it only reports what it cannot fix by itself.

use crate::state::App;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Duration;

const DEFAULT_HOURS: u64 = 6;

/// Seconds between checks.
pub fn interval_secs(_app: &App) -> i64 {
    DEFAULT_HOURS as i64 * 3600
}

pub fn last(app: &App) -> Option<Value> {
    app.db.get_setting("sanity_last").ok().flatten().and_then(|s| serde_json::from_str(&s).ok())
}

pub fn status(app: &App) -> Value {
    let l = last(app);
    let at = l.as_ref().and_then(|v| v["at"].as_i64());
    json!({
        "last": l,
        "next_at": at.map(|a| a + interval_secs(app)).unwrap_or_else(crate::util::now),
        "every_hours": interval_secs(app) / 3600,
        "running": app.sanity_running.load(Ordering::Relaxed),
    })
}

struct Running<'a>(&'a App);
impl<'a> Running<'a> {
    fn new(app: &'a App) -> Option<Self> {
        if app.sanity_running.swap(true, Ordering::SeqCst) {
            None
        } else {
            Some(Running(app))
        }
    }
}
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.sanity_running.store(false, Ordering::SeqCst);
    }
}

/// One pass. Safe to run at any time; returns what it found and what it did.
pub fn check(app: &App) -> Option<Value> {
    let _running = Running::new(app)?;
    let mut issues: Vec<String> = vec![];
    let mut did: Vec<String> = vec![];

    // 1. the database
    match app.db.with(|c| Ok(c.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))?)) {
        Ok(s) if s == "ok" => {}
        Ok(s) => issues.push(format!("the database reports a problem ({s}); restore it from a backup if things look wrong")),
        Err(e) => issues.push(format!("the database could not be checked: {e}")),
    }

    // 2. names: what is stored matches what is shown
    crate::library::tidy_all(app);

    // 3. titles whose details were not found get another try (the background lookup picks them up)
    if app.keyring.is_unlocked() {
        if let Ok(n) = crate::metadata::retry_unknown(app) {
            if n > 0 {
                did.push(format!("{n} title(s) will have their details looked up again"));
            }
        }
    }

    // 4. videos the library lists as stored here, whose file is not there (a disconnected drive, a manual delete)
    let present: Vec<String> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT id FROM items WHERE local='present' AND vault_user IS NULL")?;
            let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(v)
        })
        .unwrap_or_default();
    let missing = present.iter().filter(|id| !crate::library::library_path(app, id).exists()).count();
    if missing > 0 {
        issues.push(format!("{missing} video(s) are listed here but their stored file is missing. If a drive or network share is disconnected, reconnect it; nothing was changed"));
    }

    // 5. housekeeping: forgotten uploads, trash past its retention
    crate::library::expire_uploads(app);
    match crate::library::purge_trash(app) {
        Ok(n) if n > 0 => did.push(format!("{n} video(s) past the trash retention were removed")),
        _ => {}
    }

    // 6. files waiting for a scan that cannot run
    if !app.keyring.is_unlocked() {
        let waiting: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM items WHERE local='quarantine' AND scan IS NULL AND deleted=0", [], |r| r.get(0))?)).unwrap_or(0);
        if waiting > 0 {
            issues.push(format!("{waiting} file(s) are waiting for their safety scan; the library is locked, so they are held until it is unlocked"));
        }
    }

    let rep = json!({ "at": crate::util::now(), "ok": issues.is_empty(), "issues": issues, "did": did, "checked": present.len() });
    let _ = app.db.set_setting("sanity_last", &rep.to_string());
    if issues.is_empty() {
        tracing::info!("sanity check: all good ({} videos checked)", present.len());
    } else {
        tracing::warn!("sanity check found: {}", rep["issues"]);
    }
    Some(rep)
}

/// Runs for the life of the node. Looks every minute (every five while resting) whether a check is due.
pub async fn run(app: std::sync::Arc<App>) {
    loop {
        crate::rest::sleep(&app, Duration::from_secs(60)).await;
        if app.is_shutting_down() {
            return;
        }
        let due = last(&app).and_then(|v| v["at"].as_i64()).map(|a| crate::util::now() - a >= interval_secs(&app) - 300).unwrap_or(crate::rest::uptime_secs(&app) > 120);
        if due {
            let a = app.clone();
            let _ = tokio::task::spawn_blocking(move || check(&a)).await;
        }
    }
}
