//! Rest mode: a dedicated node that nobody is using goes quiet.
//!
//! Tor and the web/mesh servers never stop (they are how a request gets in, and they are slow to start). What
//! rests is everything that only exists to keep the library tidy: the folder watchers, the metadata lookups, the
//! hardware sampler, the drive checks and the scan poller. They stretch their waiting to minutes instead of
//! seconds, so the machine can sit nearly idle. The first real request (a page load, a click, a video, work
//! asked by another node) wakes everything at once.
//!
//! Rest mode is software only: the computer itself keeps running.

use crate::state::App;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub struct Rest {
    last: Mutex<Instant>,
    resting: AtomicBool,
    since: Mutex<Option<Instant>>,
    wake: Notify,
    started: Instant,
    /// what the last real use was and what is holding the node awake now (shown to the owner)
    why: Mutex<(String, Option<Instant>)>,
    blocker: Mutex<Option<String>>,
}

impl Default for Rest {
    fn default() -> Self {
        Rest { last: Mutex::new(Instant::now()), resting: AtomicBool::new(false), since: Mutex::new(None), wake: Notify::new(), started: Instant::now(), why: Mutex::new((String::new(), None)), blocker: Mutex::new(None) }
    }
}

/// How long background loops wait while resting, at least.
const REST_WAIT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    /// rest when the node is dedicated (the default)
    Auto,
    On,
    Off,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "auto" => Some(Mode::Auto),
            "on" => Some(Mode::On),
            "off" => Some(Mode::Off),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Mode::Auto => "auto",
            Mode::On => "on",
            Mode::Off => "off",
        }
    }
}

pub fn mode(app: &App) -> Mode {
    app.db.get_setting("rest_mode").ok().flatten().and_then(|s| Mode::parse(&s)).unwrap_or(Mode::Auto)
}

/// Minutes without any use before the node rests.
pub fn idle_minutes(app: &App) -> u64 {
    app.db.get_setting("rest_idle_min").ok().flatten().and_then(|s| s.parse().ok()).unwrap_or(10u64).clamp(1, 1440)
}

pub fn enabled(app: &App) -> bool {
    match mode(app) {
        Mode::On => true,
        Mode::Off => false,
        Mode::Auto => app.perf_dedicated.load(Ordering::Relaxed),
    }
}

/// Seconds since this node started.
pub fn uptime_secs(app: &App) -> u64 {
    app.rest.started.elapsed().as_secs()
}

pub fn is_resting(app: &App) -> bool {
    app.rest.resting.load(Ordering::Relaxed)
}

pub fn resting_for(app: &App) -> Option<u64> {
    if !is_resting(app) {
        return None;
    }
    app.rest.since.lock().unwrap().map(|t| t.elapsed().as_secs())
}

/// Someone is really using the node: note it and wake everything if it was resting.
pub fn touch(app: &App) {
    touch_for(app, "something");
}

/// Same, remembering what it was, so the owner can see what keeps the node awake.
pub fn touch_for(app: &App, what: &str) {
    *app.rest.last.lock().unwrap() = Instant::now();
    *app.rest.why.lock().unwrap() = (what.chars().take(80).collect(), Some(Instant::now()));
    if app.rest.resting.swap(false, Ordering::SeqCst) {
        *app.rest.since.lock().unwrap() = None;
        tracing::info!("rest mode: woken by a request");
        app.rest.wake.notify_waiters();
        app.scan_wake.notify_one();
        app.storage_wake.notify_one();
    }
}

/// Start resting now.
pub fn enter(app: &App) {
    app.rest.resting.store(true, Ordering::SeqCst);
    *app.rest.since.lock().unwrap() = Some(Instant::now());
}

/// Work that must not be cut off by resting; says what it is.
pub fn busy_reason(app: &App) -> Option<String> {
    let n = app.active_downloads.lock().unwrap().len() + app.running_downloads.load(Ordering::Relaxed);
    if n > 0 {
        return Some(format!("{n} download(s) running"));
    }
    // an upload nobody has touched for a few minutes is a forgotten tab, not someone waiting
    let fresh = crate::util::now() - 300;
    if app.uploads.lock().unwrap().values().any(|u| u.touched.load(Ordering::Relaxed) >= fresh) {
        return Some("an upload is in progress".into());
    }
    if !app.transfers.lock().unwrap().is_empty() {
        return Some("a transfer from another node is in progress".into());
    }
    if app.active_transcodes.load(Ordering::Relaxed) > 0 {
        return Some("a video is being converted".into());
    }
    if app.sanity_running.load(Ordering::Relaxed) {
        return Some("the periodic check is running".into());
    }
    if app.active_streams.load(Ordering::Relaxed) > 0 {
        return Some("a video is being watched".into());
    }
    // Files waiting for a safety scan only hold the node awake when it can actually scan them (a locked library
    // cannot), otherwise a locked node would never rest.
    if app.keyring.is_unlocked() && app.db.with(|c| Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM items WHERE local='quarantine' AND scan IS NULL AND deleted=0)", [], |r| r.get::<_, bool>(0))?)).unwrap_or(false) {
        return Some("files are waiting for their safety scan".into());
    }
    None
}

pub fn busy(app: &App) -> bool {
    busy_reason(app).is_some()
}

/// For the owner: what last counted as use, how long ago, and what is holding the node awake right now.
pub fn activity(app: &App) -> serde_json::Value {
    let (what, at) = app.rest.why.lock().unwrap().clone();
    serde_json::json!({
        "last_use": if at.is_some() { Some(what) } else { None },
        "last_use_secs": at.map(|t| t.elapsed().as_secs()),
        "blocked_by": app.rest.blocker.lock().unwrap().clone(),
    })
}

/// Background loops wait with this instead of a plain sleep: normal length while awake, long while resting,
/// and a wake-up the moment the node is used again.
pub async fn sleep(app: &App, dur: Duration) {
    if !is_resting(app) {
        tokio::time::sleep(dur).await;
        return;
    }
    let woken = app.rest.wake.notified();
    tokio::pin!(woken);
    // register before the check so a wake between the two is not lost
    woken.as_mut().enable();
    if !is_resting(app) {
        return;
    }
    tokio::select! {
        _ = tokio::time::sleep(dur.max(REST_WAIT)) => {}
        _ = &mut woken => {}
        _ = app.shutdown.notified() => {}
    }
}

/// Decides when the node rests. Checks every 15 seconds.
pub async fn run(app: crate::state::Shared) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(15)) => {}
            _ = app.shutdown.notified() => return,
        }
        if app.is_shutting_down() {
            return;
        }
        if !enabled(&app) {
            if is_resting(&app) {
                touch(&app);
            }
            continue;
        }
        if let Some(why) = busy_reason(&app) {
            *app.rest.last.lock().unwrap() = Instant::now();
            *app.rest.blocker.lock().unwrap() = Some(why);
            continue;
        }
        *app.rest.blocker.lock().unwrap() = None;
        let idle = app.rest.last.lock().unwrap().elapsed();
        if !is_resting(&app) && idle >= Duration::from_secs(idle_minutes(&app) * 60) {
            enter(&app);
            tracing::info!("rest mode: nobody has used this node for {} min, background work is slowing down", idle.as_secs() / 60);
        }
    }
}

/// Is this web request real use (and not a tab polling in the background)?
pub fn counts_as_use(method: &axum::http::Method, path: &str) -> bool {
    if method != axum::http::Method::GET && method != axum::http::Method::HEAD {
        return true;
    }
    path == "/"
        || ["/api/stream", "/api/frame", "/api/items", "/api/library", "/api/poster", "/api/thumb"].iter().any(|p| path.starts_with(p))
}

/// Same for requests from other nodes: heartbeats are only "are you there", everything else is work.
/// Only work that really needs this node counts: a video being fetched, or a new node asking to pair. The
/// "are you there" traffic (heartbeats, catalog pulls, asking for items and polling for the answer) happens
/// every cycle forever and must never keep a node awake.
pub fn mesh_counts(path: &str) -> bool {
    path.starts_with("/mesh/chunk/") || path.starts_with("/mesh/pair/")
}

#[cfg(test)]
mod tests {

    use super::*;
    use axum::http::Method;

    #[test]
    fn routine_traffic_between_nodes_never_keeps_a_node_awake() {
        for p in ["/mesh/heartbeat", "/mesh/ops?node=a&after=3", "/mesh/sync/request", "/mesh/sync/request/abc"] {
            assert!(!mesh_counts(p), "{p}");
        }
        assert!(mesh_counts("/mesh/chunk/item/4"));
        assert!(mesh_counts("/mesh/pair/request"));
    }

    #[test]
    fn a_page_polling_in_the_background_is_not_use() {
        assert!(!counts_as_use(&Method::GET, "/api/sync"));
        assert!(!counts_as_use(&Method::GET, "/api/review"));
        assert!(counts_as_use(&Method::GET, "/api/stream/x"));
        assert!(counts_as_use(&Method::POST, "/api/anything"));
    }
}
