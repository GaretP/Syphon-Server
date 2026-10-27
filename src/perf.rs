//! How hard this node works, matched to the machine it runs on.
//!
//! Two modes. **Shared** (the default) is for a computer that does other things too: the limits stay small and
//! fixed, exactly as they always were. **Dedicated** is for a machine that only runs Syphon: the node looks at the
//! processor, memory, disk and network it has and sizes its work to fit (parallel transfers, downloads, transcodes,
//! scans, scan memory windows, upload slots). It keeps looking: every few seconds it re-reads the hardware and the
//! busiest network speed it has seen, so a faster internet plan, more RAM or a new CPU is picked up without a
//! restart, and a busy machine eases off by itself.
//!
//! `compute` is a plain function from what was measured to the limits, so it can be tested without any hardware.

use crate::state::App;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Hardware {
    pub cores: u32,
    pub ram_mb: u64,
    pub ram_avail_mb: u64,
    /// one-minute load average
    pub load1: f32,
    /// the network card's own speed, when it tells us (virtual machines often do not)
    pub link_mbps: Option<u32>,
    /// the fastest this machine's network has been seen to go in the last day
    pub observed_mbps: f32,
    pub disk_free_gb: u64,
    pub disk_total_gb: u64,
    pub iface: Option<String>,
}

impl Hardware {
    /// The speed the limits are sized for: the card's rating, or what has actually been seen, or a modest guess.
    pub fn net_mbps(&self) -> u32 {
        match (self.link_mbps, self.observed_mbps) {
            (Some(l), _) => l.max(10),
            (None, o) if o >= 1.0 => o.max(10.0) as u32,
            _ => 100,
        }
    }
}

/// What the owner's fixed settings say, used as-is in shared mode.
#[derive(Clone, Debug)]
pub struct Base {
    pub streams: u32,
    pub download_parallel: u32,
    pub transcode_threads: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Tuning {
    pub dedicated: bool,
    /// parallel chunk transfers to and from other nodes
    pub streams: u32,
    pub download_parallel: u32,
    pub transcode_max: u32,
    pub transcode_threads: u32,
    pub scan_parallel: u32,
    /// how much of a big file one ClamAV pass covers
    pub scan_window_mib: u64,
    pub decode_max_mib: u64,
    pub scan_nice: i32,
    pub max_uploads: u32,
    /// files the browser uploads at once
    pub upload_parallel: u32,
    /// plain-language reasons for the numbers, shown in Settings
    pub notes: Vec<String>,
}

/// Turn measurements into limits.
pub fn compute(hw: &Hardware, dedicated: bool, base: &Base) -> Tuning {
    if !dedicated {
        return Tuning {
            dedicated: false,
            streams: base.streams.clamp(1, 8),
            download_parallel: base.download_parallel.max(1),
            transcode_max: 2,
            transcode_threads: base.transcode_threads.max(1),
            scan_parallel: 1,
            scan_window_mib: 1536,
            decode_max_mib: 2048,
            scan_nice: 10,
            max_uploads: 16,
            upload_parallel: 2,
            notes: vec!["Shared computer: small, fixed limits so Syphon stays out of the way of whatever else runs here.".into()],
        };
    }
    let c = hw.cores.max(1);
    let ram = hw.ram_mb.max(512);
    let avail = hw.ram_avail_mb.min(ram).max(256);
    let net = hw.net_mbps();
    let mut notes = vec![];

    // transfers: about one stream per 25 Mb/s, but never more than two per core
    let streams = ((net + 24) / 25).clamp(2, 16).min((c * 2).max(2));
    notes.push(format!("{streams} parallel transfers ({net} Mb/s network, {c} processor core{})", if c == 1 { "" } else { "s" }));

    let download_parallel = (c / 2).clamp(2, 6).min(streams);

    // transcodes cost a core or so each, and a few hundred MB
    let transcode_max = (c / 2).clamp(1, 8).min(((avail / 600) as u32).max(1));
    let transcode_threads = (c / transcode_max.max(1)).clamp(1, 8);

    // a scan needs the antivirus (a gigabyte or more) resident: only run several when the memory is really there
    let by_ram = (avail / 3500) as u32;
    let mut scan_parallel = (c / 4).min(by_ram).clamp(1, 3);
    let mut scan_nice = 5;
    // a machine already working hard lets the scans wait their turn
    if hw.load1 > c as f32 * 0.9 {
        scan_parallel = 1;
        scan_nice = 12;
        notes.push("The machine is busy right now, so scanning runs one file at a time at low priority.".into());
    }
    // the antivirus window goes to disk in a scratch file: bigger when memory is plentiful, never more than a quarter of the free disk
    let mut window = (avail / 2).clamp(1536, 4096);
    if hw.disk_free_gb > 0 {
        window = window.min((hw.disk_free_gb * 1024 / 4).max(512));
    }
    let decode = if c >= 8 { 8192 } else if c >= 4 { 4096 } else { 2048 };
    notes.push(format!("Scanning: {scan_parallel} at a time, {} GB antivirus window, first {} GB decoded ({} MB memory free)", window / 1024.max(1), decode / 1024, avail));

    Tuning {
        dedicated: true,
        streams,
        download_parallel,
        transcode_max,
        transcode_threads,
        scan_parallel,
        scan_window_mib: window,
        decode_max_mib: decode,
        scan_nice,
        max_uploads: (c * 4).clamp(16, 64),
        upload_parallel: (c / 2).clamp(2, 6),
        notes,
    }
}

// ------------------------------------------------------------------ measuring

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn meminfo(key: &str) -> Option<u64> {
    read("/proc/meminfo")?.lines().find_map(|l| l.strip_prefix(key)?.trim().trim_end_matches("kB").trim().parse::<u64>().ok()).map(|kb| kb / 1024)
}

/// A container or service may be allowed less memory than the machine has.
fn memory_limit_mb() -> Option<u64> {
    for p in ["/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"] {
        if let Some(n) = read(p).and_then(|s| s.trim().parse::<u64>().ok()) {
            if n < (1u64 << 50) {
                return Some(n >> 20);
            }
        }
    }
    None
}

fn default_iface() -> Option<String> {
    read("/proc/net/route")?.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[1] == "00000000").then(|| f[0].to_string())
    })
}

fn iface_bytes(iface: &str) -> Option<u64> {
    read("/proc/net/dev")?.lines().find_map(|l| {
        let (name, rest) = l.split_once(':')?;
        if name.trim() != iface {
            return None;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        Some(f.first().copied()? + f.get(8).copied()?)
    })
}

/// Read the machine as it is right now (observed speed is filled in by the watcher).
pub fn detect(app: Option<&App>) -> Hardware {
    let cores = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);
    let mut ram = meminfo("MemTotal:").unwrap_or(2048);
    let mut avail = meminfo("MemAvailable:").unwrap_or(ram / 2);
    if let Some(l) = memory_limit_mb() {
        ram = ram.min(l);
        avail = avail.min(l);
    }
    let load1 = read("/proc/loadavg").and_then(|s| s.split_whitespace().next().and_then(|x| x.parse().ok())).unwrap_or(0.0);
    let iface = default_iface();
    let link = iface.as_deref().and_then(|i| read(&format!("/sys/class/net/{i}/speed"))).and_then(|s| s.trim().parse::<i64>().ok()).filter(|n| *n > 0).map(|n| n as u32);
    let (total, free) = app.map(crate::storage::totals).unwrap_or((0, 0));
    Hardware { cores, ram_mb: ram, ram_avail_mb: avail, load1, link_mbps: link, observed_mbps: 0.0, disk_free_gb: free >> 30, disk_total_gb: total >> 30, iface }
}

/// Make the scanner use the limits (it reads these without needing the node around it).
fn apply(t: &Tuning) {
    // shared mode leaves the window and decode size to the defaults / config file
    crate::scanner::TUNE_WINDOW_MIB.store(if t.dedicated { t.scan_window_mib } else { 0 }, Ordering::Relaxed);
    crate::scanner::TUNE_DECODE_MIB.store(if t.dedicated { t.decode_max_mib } else { 0 }, Ordering::Relaxed);
    crate::scanner::TUNE_NICE.store(t.scan_nice, Ordering::Relaxed);
}

pub fn base_of(app: &App) -> Base {
    let p = app.policy();
    Base { streams: p.max_concurrent, download_parallel: app.cfg.acquire.max_parallel as u32, transcode_threads: p.transcode_threads }
}

/// Work out the limits again now and publish them. Returns a line describing what changed, if anything.
pub fn refresh(app: &App) -> Option<String> {
    let mut hw = detect(Some(app));
    hw.observed_mbps = app.hw.read().unwrap().observed_mbps;
    let t = compute(&hw, app.perf_dedicated.load(Ordering::Relaxed), &base_of(app));
    apply(&t);
    let old = app.tuning.read().unwrap().clone();
    let oldhw = app.hw.read().unwrap().clone();
    *app.hw.write().unwrap() = hw.clone();
    if old == t {
        return None;
    }
    *app.tuning.write().unwrap() = t.clone();
    let what = format!(
        "{} cores, {} MB RAM, {} Mb/s: {} transfers, {} downloads, {} transcodes, {} scans at once",
        hw.cores, hw.ram_mb, hw.net_mbps(), t.streams, t.download_parallel, t.transcode_max, t.scan_parallel
    );
    let _ = oldhw;
    Some(what)
}

/// The watcher. Samples the network every ten seconds to learn how fast it really goes, and re-reads everything else.
pub async fn run(app: crate::state::Shared) {
    let mut peaks: VecDeque<(i64, f32)> = VecDeque::new();
    let mut last: Option<(std::time::Instant, u64)> = None;
    let mut tick = 0u64;
    loop {
        if app.is_shutting_down() {
            return;
        }
        let iface = default_iface();
        if let Some(b) = iface.as_deref().and_then(iface_bytes) {
            let now = std::time::Instant::now();
            if let Some((t0, b0)) = last {
                let secs = now.duration_since(t0).as_secs_f32().max(0.5);
                let mbps = (b.saturating_sub(b0) as f32 * 8.0) / 1_000_000.0 / secs;
                let ts = crate::util::now();
                // keep the best reading per minute, for a day
                match peaks.back_mut() {
                    Some(l) if ts - l.0 < 60 => l.1 = l.1.max(mbps),
                    _ => peaks.push_back((ts, mbps)),
                }
                while peaks.front().map(|p| ts - p.0 > 86_400).unwrap_or(false) {
                    peaks.pop_front();
                }
                app.hw.write().unwrap().observed_mbps = peaks.iter().map(|p| p.1).fold(0.0, f32::max);
            }
            last = Some((now, b));
        }
        if tick % 3 == 0 {
            if let Some(what) = refresh(&app) {
                tracing::info!("performance limits changed: {what}");
            }
        }
        tick += 1;
        tokio::select! {
            _ = crate::rest::sleep(&app, Duration::from_secs(10)) => {}
            _ = app.shutdown.notified() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw(cores: u32, ram: u64, link: Option<u32>) -> Hardware {
        Hardware { cores, ram_mb: ram, ram_avail_mb: ram * 3 / 4, load1: 0.1, link_mbps: link, observed_mbps: 0.0, disk_free_gb: 2000, disk_total_gb: 4000, iface: None }
    }
    const BASE: Base = Base { streams: 3, download_parallel: 2, transcode_threads: 2 };

    #[test]
    fn a_shared_computer_keeps_the_small_fixed_limits_whatever_it_has() {
        let big = compute(&hw(32, 131_072, Some(10_000)), false, &BASE);
        let small = compute(&hw(2, 2048, Some(100)), false, &BASE);
        assert_eq!(big, small);
        assert_eq!((big.streams, big.scan_parallel, big.download_parallel), (3, 1, 2));
    }

    #[test]
    fn a_dedicated_node_grows_when_the_network_the_memory_or_the_processor_does() {
        let a = compute(&hw(4, 8192, Some(100)), true, &BASE);
        let faster_net = compute(&hw(4, 8192, Some(1000)), true, &BASE);
        assert!(faster_net.streams > a.streams, "{a:?} -> {faster_net:?}");
        let more_ram = compute(&hw(8, 32_768, Some(1000)), true, &BASE);
        assert!(more_ram.scan_parallel > a.scan_parallel && more_ram.scan_window_mib >= a.scan_window_mib);
        let more_cpu = compute(&hw(16, 32_768, Some(1000)), true, &BASE);
        assert!(more_cpu.transcode_max > more_ram.transcode_max && more_cpu.decode_max_mib >= more_ram.decode_max_mib);
    }

    #[test]
    fn a_small_dedicated_machine_stays_inside_what_it_has() {
        let t = compute(&hw(1, 1024, None), true, &BASE);
        assert!(t.streams <= 2 && t.scan_parallel == 1 && t.transcode_max == 1 && t.download_parallel <= 2, "{t:?}");
        let t = compute(&Hardware { disk_free_gb: 4, ..hw(4, 16_384, Some(1000)) }, true, &BASE);
        assert!(t.scan_window_mib <= 1024, "the scan scratch file never takes more than a quarter of the free disk: {t:?}");
    }

    #[test]
    fn a_busy_machine_makes_scans_wait_their_turn() {
        let mut h = hw(8, 32_768, Some(1000));
        let calm = compute(&h, true, &BASE);
        h.load1 = 12.0;
        let busy = compute(&h, true, &BASE);
        assert!(calm.scan_parallel > 1 && busy.scan_parallel == 1 && busy.scan_nice > calm.scan_nice);
    }

    #[test]
    fn network_speed_comes_from_the_card_or_what_was_seen() {
        assert_eq!(hw(4, 4096, Some(1000)).net_mbps(), 1000);
        let mut h = hw(4, 4096, None);
        assert_eq!(h.net_mbps(), 100, "unknown stays modest");
        h.observed_mbps = 480.0;
        assert_eq!(h.net_mbps(), 480);
    }
}
