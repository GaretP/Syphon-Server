//! Sleep: the computer itself suspends when nobody uses it, or on a schedule, and wakes again from its network card
//! (wake-on-LAN, sent by the VPN box or the Syphon app) or from a wake time set in its clock.
//!
//! What counts as use is rest mode's: pages, videos, clicks, work asked by another node (not a tab polling in the
//! background, not heartbeats). Nothing that is running gets cut off: a video being watched, a download, a transfer,
//! a conversion, an upload or the periodic check all keep the node awake (`rest::busy_reason`).
//!
//! Suspending needs root, so the node asks its system helper (`syphon-update`, action `suspend`), which also makes
//! sure the network card listens for wake packets and sets the clock's wake time.

use crate::state::App;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// After waking, stay up at least this long, whatever the settings say (the request that woke it is on its way).
const GRACE_SECS: u64 = 300;
/// Inside the scheduled sleep window, this much quiet is enough.
const WINDOW_IDLE_SECS: u64 = 300;
/// Without a wake time, the sleep window lasts this long after the sleep time.
const WINDOW_DEFAULT_MIN: u32 = 240;

#[derive(Default)]
pub struct Sleep {
    /// wall clock at the last check, to notice that the computer was asleep in between
    last_wall: Mutex<i64>,
    woke: Mutex<Option<Instant>>,
    /// a suspend was asked for at (wall clock); cleared when the computer is seen to have slept
    asked: Mutex<Option<i64>>,
    /// don't ask again before (wall clock): the helper did not suspend last time
    hold_until: Mutex<i64>,
    pub last_sleep: Mutex<i64>,
    pub last_wake: Mutex<i64>,
    note: Mutex<String>,
    /// last time the network card's address was given to the VPN box
    told_box: Mutex<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Plan {
    /// sleep after this many minutes without use (None: not on inactivity)
    pub idle_min: Option<u64>,
    /// minutes after midnight, local time
    pub sleep_at: Option<u32>,
    pub wake_at: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Stay(String),
    /// suspend now; the clock wakes it at this time (unix seconds) if set
    Sleep { wake: Option<i64>, why: String },
}

pub fn parse_hhmm(s: &str) -> Option<u32> {
    let (h, m) = s.trim().split_once(':')?;
    let (h, m): (u32, u32) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

pub fn hhmm(m: u32) -> String {
    format!("{:02}:{:02}", m / 60, m % 60)
}

pub fn plan(app: &App) -> Plan {
    let get = |k: &str| app.db.get_setting(k).ok().flatten().unwrap_or_default();
    let idle_min = (get("sleep_idle") == "on").then(|| get("sleep_idle_min").parse().unwrap_or(30u64).clamp(5, 1440));
    Plan { idle_min, sleep_at: parse_hhmm(&get("sleep_at")), wake_at: parse_hhmm(&get("wake_at")) }
}

pub fn enabled(p: &Plan) -> bool {
    p.idle_min.is_some() || p.sleep_at.is_some()
}

/// Is `now` (minutes after midnight) inside the window from `from` (inclusive) to `to` (exclusive), across midnight?
fn within(now: u32, from: u32, to: u32) -> bool {
    if from <= to { now >= from && now < to } else { now >= from || now < to }
}

/// The next time (unix seconds) the local clock shows `at`, at least a minute from now.
pub fn next_at(now_unix: i64, offset_secs: i64, at: u32) -> i64 {
    let local = now_unix + offset_secs;
    let midnight = local - local.rem_euclid(86400);
    let mut t = midnight + at as i64 * 60;
    if t <= local + 60 {
        t += 86400;
    }
    t - offset_secs
}

/// What to do now. `local_min` is minutes after local midnight; `idle_secs` how long nobody used the node;
/// `since_wake` seconds since it last woke or started.
pub fn decide(p: &Plan, now_unix: i64, offset_secs: i64, local_min: u32, idle_secs: u64, since_wake: u64, busy: Option<&str>) -> Decision {
    if !enabled(p) {
        return Decision::Stay("sleep is off".into());
    }
    if let Some(b) = busy {
        return Decision::Stay(format!("awake: {b}"));
    }
    if since_wake < GRACE_SECS {
        return Decision::Stay("awake: it only just woke up".into());
    }
    let wake = p.wake_at.map(|w| next_at(now_unix, offset_secs, w));
    if let Some(from) = p.sleep_at {
        let to = p.wake_at.unwrap_or((from + WINDOW_DEFAULT_MIN) % 1440);
        if within(local_min, from, to) {
            return if idle_secs >= WINDOW_IDLE_SECS {
                Decision::Sleep { wake, why: format!("scheduled sleep time ({})", hhmm(from)) }
            } else {
                Decision::Stay("awake: in use, sleeps after 5 quiet minutes (scheduled sleep time)".into())
            };
        }
    }
    if let Some(m) = p.idle_min {
        if idle_secs >= m * 60 {
            return Decision::Sleep { wake, why: format!("nobody used it for {m} minutes") };
        }
        let left = (m * 60 - idle_secs).div_ceil(60);
        return Decision::Stay(format!("awake: sleeps after {left} more quiet minute{}", if left == 1 { "" } else { "s" }));
    }
    Decision::Stay(format!("awake until the scheduled sleep time ({})", hhmm(p.sleep_at.unwrap_or(0))))
}

/// The local clock's distance from UTC, as the computer's C library sees it (SQLite asks it for us).
pub fn utc_offset(app: &App) -> i64 {
    app.db.with(|c| Ok(c.query_row("SELECT CAST(strftime('%s','now','localtime') AS INTEGER) - CAST(strftime('%s','now') AS INTEGER)", [], |r| r.get::<_, i64>(0))?)).unwrap_or(0)
}

/// The network card the computer reaches the world through, from /proc/net/route's default route.
pub fn parse_default_iface(route: &str) -> Option<String> {
    route.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}

/// The network card's name, hardware address (for wake-on-LAN) and IPv4 address.
pub fn nic() -> Option<(String, String, Option<String>)> {
    let iface = parse_default_iface(&std::fs::read_to_string("/proc/net/route").ok()?)?;
    let mac = std::fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?.trim().to_lowercase();
    if mac.len() != 17 || mac == "00:00:00:00:00:00" {
        return None;
    }
    let ip = if_addrs::get_if_addrs().ok()?.into_iter().find(|a| a.name == iface && a.ip().is_ipv4()).map(|a| a.ip().to_string());
    Some((iface, mac, ip))
}

/// For the owner's page.
pub fn status(app: &App) -> Value {
    let p = plan(app);
    let now = crate::util::now();
    let off = utc_offset(app);
    let local_min = ((now + off).rem_euclid(86400) / 60) as u32;
    let idle = crate::rest::idle_secs(app);
    let since = app.sleep.woke.lock().unwrap().map(|t| t.elapsed().as_secs()).unwrap_or_else(|| crate::rest::uptime_secs(app));
    let d = decide(&p, now, off, local_min, idle, since, crate::rest::busy_reason(app).as_deref());
    let nic = nic();
    json!({
        "idle": p.idle_min.is_some(),
        "idle_min": p.idle_min.unwrap_or_else(|| app.db.get_setting("sleep_idle_min").ok().flatten().and_then(|s| s.parse().ok()).unwrap_or(30)),
        "sleep_at": p.sleep_at.map(hhmm),
        "wake_at": p.wake_at.map(hhmm),
        "now": match &d { Decision::Stay(s) => s.clone(), Decision::Sleep { why, .. } => format!("going to sleep: {why}") },
        "last_sleep": *app.sleep.last_sleep.lock().unwrap(),
        "last_wake": *app.sleep.last_wake.lock().unwrap(),
        "note": app.sleep.note.lock().unwrap().clone(),
        "iface": nic.as_ref().map(|n| n.0.clone()),
        "mac": nic.as_ref().map(|n| n.1.clone()),
        "ip": nic.as_ref().and_then(|n| n.2.clone()),
        "helper": std::path::Path::new("/usr/local/bin/syphon-update").exists(),
    })
}

/// Ask the helper to suspend the computer now (and set the clock's wake time).
pub fn suspend_now(app: &App, wake: Option<i64>, why: &str) -> Result<(), String> {
    let w = wake.map(|w| w.to_string()).unwrap_or_default();
    crate::storage::request_helper_why(app, "suspend", &[("wake", &w)])?;
    *app.sleep.asked.lock().unwrap() = Some(crate::util::now());
    tracing::info!("sleep: suspending ({why}){}", wake.map(|w| format!(", the clock wakes it at {w}")).unwrap_or_default());
    Ok(())
}

/// Tell the VPN box which network card to wake (so it can wake this node when a device wants it).
async fn tell_box(app: &App) {
    let Some(l) = crate::vpnbox::saved(app) else { return };
    let Some((_, mac, _)) = nic() else { return };
    match crate::vpnbox::call(&l, "set_wake", Some(&mac)).await {
        Ok(_) => *app.sleep.told_box.lock().unwrap() = crate::util::now(),
        Err(e) => tracing::debug!("sleep: could not give the VPN box the wake address: {e}"),
    }
}

/// Give the box the wake address soon (after linking, or when the sleep settings change).
pub fn tell_box_soon(app: &App) {
    *app.sleep.told_box.lock().unwrap() = 0;
}

/// Checks every 20 seconds.
pub async fn run(app: crate::state::Shared) {
    *app.sleep.last_wall.lock().unwrap() = crate::util::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(20)) => {}
            _ = app.shutdown.notified() => return,
        }
        if app.is_shutting_down() {
            return;
        }
        let now = crate::util::now();
        let prev = std::mem::replace(&mut *app.sleep.last_wall.lock().unwrap(), now);
        // the wall clock jumped ahead: the computer was asleep
        if now - prev > 80 {
            let asked = app.sleep.asked.lock().unwrap().take();
            *app.sleep.last_sleep.lock().unwrap() = asked.unwrap_or(prev);
            *app.sleep.last_wake.lock().unwrap() = now;
            *app.sleep.woke.lock().unwrap() = Some(Instant::now());
            app.sleep.note.lock().unwrap().clear();
            crate::rest::touch_for(&app, "woke from sleep");
            app.tor_restart.notify_one(); // its connections are stale after a long sleep
            tracing::info!("sleep: woke after {} min", (now - prev) / 60);
        }
        // asked to suspend but the computer kept running: the helper didn't (too old, or not allowed)
        let stuck = { app.sleep.asked.lock().unwrap().filter(|t| now - t > 150) };
        if stuck.is_some() {
            *app.sleep.asked.lock().unwrap() = None;
            *app.sleep.hold_until.lock().unwrap() = now + 1800;
            *app.sleep.note.lock().unwrap() = "The node asked to sleep, but the computer did not suspend. Update Syphon (the system helper learns to suspend with this version), and check that \"sudo systemctl suspend\" works on this computer.".into();
            tracing::warn!("sleep: the computer did not suspend when asked");
        }
        if now - *app.sleep.told_box.lock().unwrap() > 6 * 3600 {
            *app.sleep.told_box.lock().unwrap() = now; // also when it fails: try again in 6 hours, not every 20 s
            tell_box(&app).await;
        }
        if app.sleep.asked.lock().unwrap().is_some() || now < *app.sleep.hold_until.lock().unwrap() {
            continue;
        }
        let p = plan(&app);
        if !enabled(&p) {
            continue;
        }
        let off = utc_offset(&app);
        let local_min = ((now + off).rem_euclid(86400) / 60) as u32;
        let since = app.sleep.woke.lock().unwrap().map(|t| t.elapsed().as_secs()).unwrap_or_else(|| crate::rest::uptime_secs(&app));
        if let Decision::Sleep { wake, why } = decide(&p, now, off, local_min, crate::rest::idle_secs(&app), since, crate::rest::busy_reason(&app).as_deref()) {
            if let Err(e) = suspend_now(&app, wake, &why) {
                *app.sleep.note.lock().unwrap() = e;
                *app.sleep.hold_until.lock().unwrap() = now + 1800;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: i64 = 3600;
    fn p(idle: Option<u64>, s: Option<&str>, w: Option<&str>) -> Plan {
        Plan { idle_min: idle, sleep_at: s.and_then(parse_hhmm), wake_at: w.and_then(parse_hhmm) }
    }
    fn at(hm: &str) -> u32 {
        parse_hhmm(hm).unwrap()
    }

    #[test]
    fn times_are_read_and_the_next_one_found() {
        assert_eq!((parse_hhmm("07:30"), parse_hhmm("24:00"), parse_hhmm("7"), parse_hhmm(" 0:05 ")), (Some(450), None, None, Some(5)));
        // 2026-10-27 22:00 UTC, clock at UTC+1: local 23:00. Next 07:00 local is 06:00 UTC on the 28th.
        let now = 1_793_224_800;
        assert_eq!(next_at(now, H, at("07:00")), now + 8 * H);
        assert_eq!(next_at(now, H, at("23:30")), now + H / 2);
        assert_eq!(next_at(now, H, at("23:00")), now + 24 * H, "the same minute counts as tomorrow");
    }

    #[test]
    fn it_sleeps_after_quiet_minutes_and_never_while_busy_or_just_woken() {
        let pl = p(Some(30), None, None);
        let d = |idle: u64, since: u64, busy: Option<&str>| decide(&pl, 0, 0, at("15:00"), idle, since, busy);
        assert!(matches!(d(1800, 9999, None), Decision::Sleep { wake: None, .. }));
        assert!(matches!(d(1799, 9999, None), Decision::Stay(s) if s.contains("1 more quiet minute")));
        assert!(matches!(d(99999, 9999, Some("a video is being watched")), Decision::Stay(s) if s.contains("video")));
        assert!(matches!(d(99999, 60, None), Decision::Stay(s) if s.contains("just woke")));
        assert_eq!(decide(&p(None, None, None), 0, 0, 0, 99999, 99999, None), Decision::Stay("sleep is off".into()));
    }

    #[test]
    fn the_schedule_puts_it_to_sleep_in_its_window_and_sets_the_wake_time() {
        let pl = p(None, Some("01:00"), Some("07:00"));
        let now = 1_793_224_800;
        assert!(matches!(decide(&pl, now, H, at("00:59"), 9999, 9999, None), Decision::Stay(s) if s.contains("01:00")));
        assert_eq!(decide(&pl, now, H, at("01:00"), 9999, 9999, None), Decision::Sleep { wake: Some(next_at(now, H, at("07:00"))), why: "scheduled sleep time (01:00)".into() });
        assert!(matches!(decide(&pl, now, H, at("03:00"), 100, 9999, None), Decision::Stay(s) if s.contains("5 quiet minutes")), "woken in the night and in use: stays up");
        assert!(matches!(decide(&pl, now, H, at("07:00"), 9999, 9999, None), Decision::Stay(_)), "after the window it stays up");
        // across midnight, and a window without a wake time lasts four hours
        let late = p(None, Some("23:30"), None);
        assert!(matches!(decide(&late, now, H, at("02:00"), 9999, 9999, None), Decision::Sleep { wake: None, .. }));
        assert!(matches!(decide(&late, now, H, at("04:00"), 9999, 9999, None), Decision::Stay(_)));
        // inactivity outside the window still counts, and keeps the morning wake time
        let both = p(Some(20), Some("01:00"), Some("07:00"));
        assert!(matches!(decide(&both, now, H, at("21:00"), 1200, 9999, None), Decision::Sleep { wake: Some(_), .. }));
    }

    #[test]
    fn the_network_card_is_the_one_with_the_default_route() {
        let route = "Iface\tDestination\tGateway\tFlags\nenp3s0\t0014A8C0\t00000000\t0001\nenp2s0\t00000000\t0114A8C0\t0003\n";
        assert_eq!(parse_default_iface(route).as_deref(), Some("enp2s0"));
        assert_eq!(parse_default_iface("Iface\tDestination\n"), None);
    }
}
