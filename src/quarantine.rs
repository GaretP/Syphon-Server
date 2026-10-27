//! The isolated review area.
//!
//! Everything that arrives from outside (uploads, downloads, imports) lands encrypted in
//! `quarantine/`. Items there are never streamed, never listed in the library, never advertised
//! to peers and never part of the catalog. They get a safety scan (container signature plus a
//! sandboxed ffprobe) and wait for the owner to approve or reject them.

use crate::db::get_item;
use crate::library::quarantine_path;
use crate::state::{App, Shared};
use crate::util::now;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

/// How much of the start of a file is shown to ffprobe.
pub const PROBE_BYTES: u64 = 32 << 20;

const VIDEO_EXTS: [&str; 14] = [
    "mp4", "m4v", "mov", "mkv", "webm", "avi", "ts", "m2ts", "ogv", "ogg", "flv", "mpg", "mpeg", "wmv",
];

/// Only video goes into Syphon: it is not a file server. True when the name ends like a video file.
pub fn is_video_name(name: &str) -> bool {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    name.contains('.') && VIDEO_EXTS.contains(&ext.as_str())
}

/// True when the first bytes look like a known video container.
pub fn looks_like_video(head: &[u8]) -> bool {
    sniff(head).is_some()
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ScanReport {
    pub ok: bool,
    pub container: Option<String>,
    pub extension_ok: bool,
    pub probed: bool,
    pub has_video: bool,
    pub duration: Option<f64>,
    pub format: Option<String>,
    pub sandbox: String,
    pub notes: Vec<String>,
    pub at: i64,
    /// something was found that can never be overridden (malware, a hidden program, a crashed decoder)
    #[serde(default)]
    pub hard: bool,
    #[serde(default)]
    pub findings: Vec<crate::scanner::Finding>,
    /// which layers ran: signatures, structure, blocklist, ffprobe, decode, clamav
    #[serde(default)]
    pub engines: Vec<String>,
    #[serde(default)]
    pub scanned_bytes: u64,
    /// false when a layer could only cover part of the file (large file, timeout)
    #[serde(default)]
    pub complete: bool,
}

/// Identify a media container from its first bytes.
pub fn sniff(h: &[u8]) -> Option<&'static str> {
    if h.len() >= 12 && (&h[4..8] == b"ftyp" || &h[4..8] == b"moov" || &h[4..8] == b"mdat" || &h[4..8] == b"wide" || &h[4..8] == b"free") {
        return Some("mp4/mov");
    }
    if h.len() >= 4 && h[..4] == [0x1A, 0x45, 0xDF, 0xA3] {
        return Some("matroska/webm");
    }
    if h.len() >= 12 && &h[..4] == b"RIFF" && &h[8..12] == b"AVI " {
        return Some("avi");
    }
    if h.len() >= 4 && &h[..4] == b"OggS" {
        return Some("ogg");
    }
    if h.len() >= 4 && &h[..3] == b"FLV" && h[3] == 1 {
        return Some("flv");
    }
    if h.len() >= 4 && h[..4] == [0, 0, 1, 0xBA] {
        return Some("mpeg-ps");
    }
    if h.len() >= 4 && h[..4] == [0x30, 0x26, 0xB2, 0x75] {
        return Some("asf/wmv");
    }
    if h.len() >= 377 && h[0] == 0x47 && h[188] == 0x47 && h[376] == 0x47 {
        return Some("mpeg-ts");
    }
    if h.len() >= 197 && h[4] == 0x47 && h[196] == 0x47 {
        return Some("m2ts");
    }
    None
}

fn which(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).exists();
    }
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

pub(crate) async fn run(argv: &[String], data: Vec<u8>) -> Result<(Vec<u8>, String, i32)> {
    use tokio::io::AsyncWriteExt;
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    let mut child = cmd.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
    tokio::spawn(async move {
        let _ = stdin.write_all(&data).await;
        let _ = stdin.shutdown().await;
    });
    let out = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .map_err(|_| anyhow!("ffprobe timed out"))??;
    Ok((out.stdout, String::from_utf8_lossy(&out.stderr).to_string(), out.status.code().unwrap_or(-1)))
}

/// Run ffprobe on `data` inside bubblewrap (no network, read-only filesystem) when available.
pub async fn probe(app: &App, data: Vec<u8>) -> (Option<serde_json::Value>, String, Vec<String>) {
    let mut notes = vec![];
    if !which(&app.cfg.ffprobe) {
        notes.push("ffprobe is not installed, so only the file signature was checked".into());
        return (None, "none".into(), notes);
    }
    let probe_args: Vec<String> = ["-v", "error", "-print_format", "json", "-show_format", "-show_streams", "-i", "pipe:0"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut attempts: Vec<(String, Vec<String>)> = vec![];
    let mut plain = vec![app.cfg.ffprobe.clone()];
    plain.extend(probe_args.clone());
    let (wrapped, label) = crate::scanner::sandboxed_in(plain.clone(), None);
    let sandboxed = label != "none";
    attempts.push((label, wrapped));
    if sandboxed {
        // the sandbox passed its start-up test, but if it still fails on this file, do not lose the probe
        attempts.push(("none".into(), plain));
    }
    for (label, argv) in attempts {
        match run(&argv, data.clone()).await {
            Ok((stdout, stderr, code)) => {
                if label.starts_with("bubblewrap") && stderr.contains("bwrap:") {
                    continue;
                }
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&stdout) {
                    if v.get("format").is_some() {
                        return (Some(v), label, notes);
                    }
                }
                if code != 0 || !stderr.is_empty() {
                    notes.push(format!("ffprobe: {}", stderr.lines().next().unwrap_or("could not read the stream headers")));
                }
                return (None, label, notes);
            }
            Err(e) => {
                notes.push(format!("probe failed: {e}"));
                return (None, label, notes);
            }
        }
    }
    (None, "none".into(), notes)
}

/// Where an item's encrypted file lives, by what state it is in.
pub fn item_path(app: &App, it: &crate::db::Item) -> std::path::PathBuf {
    match it.local.as_str() {
        "present" => crate::library::library_path(app, &it.id),
        "private" => crate::library::vault_path(app, &it.id),
        _ => quarantine_path(app, &it.id),
    }
}

pub async fn scan_path(app: &Shared, path: &Path, id: &str, filename: &str) -> Result<ScanReport> {
    let d = crate::scanner::deep_scan(app, path, id, filename).await?;
    let mut rep = ScanReport { at: now(), ..Default::default() };
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    rep.extension_ok = VIDEO_EXTS.contains(&ext.as_str());
    if !rep.extension_ok {
        rep.notes.push(format!("unusual file extension \".{ext}\""));
    }
    rep.container = d.container.clone();
    rep.probed = d.probed;
    rep.has_video = d.has_video;
    rep.duration = d.duration;
    rep.format = d.format.clone();
    rep.sandbox = d.sandbox.clone();
    rep.scanned_bytes = d.scanned_bytes;
    rep.complete = d.complete;
    rep.engines = d.engines.clone();
    rep.notes.extend(d.notes.clone());
    rep.hard = d.findings.iter().any(|f| f.level == "block");
    let warns = d.findings.iter().any(|f| f.level == "warn");
    let probe_expected = which(&app.cfg.ffprobe);
    let probe_ok = if probe_expected { rep.probed && rep.has_video } else { true };
    rep.ok = !rep.hard && !warns && rep.container.is_some() && probe_ok;
    rep.findings = d.findings;
    Ok(rep)
}

fn store(app: &App, id: &str, rep: &ScanReport) -> Result<()> {
    let json = serde_json::to_string(rep)?;
    app.db.with(|c| {
        c.execute("UPDATE items SET scan=?2 WHERE id=?1", rusqlite::params![id, json])?;
        Ok(())
    })
}

/// Scan an item that is waiting (review, blocked) and record the result.
pub async fn scan(app: &Shared, id: &str, filename: &str) -> Result<ScanReport> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    let path = item_path(app, &it);
    let rep = scan_path(app, &path, id, filename).await?;
    store(app, id, &rep)?;
    Ok(rep)
}

// ------------------------------------------------------------------ the background scan queue

/// Hand an item to the scanner. In normal running this only wakes the background worker and returns at once,
/// so an upload, a download or a sync never waits for (or is held up by) a scan. With `scan.background` off
/// (tests) the scan happens right here.
pub async fn schedule(app: &Shared, id: &str) -> Result<()> {
    if app.cfg.scan.background {
        app.scan_wake.notify_one();
        Ok(())
    } else {
        process_one(app, id).await
    }
}

/// Scan one waiting item and do what follows from the result.
pub async fn process_one(app: &Shared, id: &str) -> Result<()> {
    let Some(it) = app.db.with(|c| get_item(c, id))? else { return Ok(()) };
    if it.local != "quarantine" || it.scan.is_some() || it.deleted {
        return Ok(());
    }
    if it.catalog {
        admit_synced(app, id).await?;
        return Ok(());
    }
    let rep = scan(app, id, it.filename.as_deref().unwrap_or("")).await?;
    if app.cfg.auto_approve_imports && rep.ok && it.source.as_deref() == Some("import") {
        crate::library::approve(app, id, false)?;
    }
    // something that is not a video at all has no place here: throw it away instead of keeping it
    if rep.hard && rep.findings.iter().any(|f| f.engine == "type") {
        crate::library::reject(app, id)?;
    }
    Ok(())
}

fn next_to_scan(app: &App, skip: &std::collections::HashMap<String, (u32, i64)>, busy: &std::collections::HashSet<String>) -> Option<String> {
    let t = now();
    app.db
        .with(|c| {
            let mut st = c.prepare("SELECT id FROM items WHERE local='quarantine' AND scan IS NULL AND deleted=0 ORDER BY catalog DESC, added_at ASC")?;
            let ids = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(ids.into_iter().find(|i| !busy.contains(i) && skip.get(i).map(|(_, at)| *at <= t).unwrap_or(true)))
        })
        .ok()
        .flatten()
}

/// What to keep when a scan keeps failing for a reason that is not the file's fault (a missing tool, a read error):
/// a plain report instead of silence, so the owner sees it and can decide.
fn record_failure(app: &Shared, id: &str, why: &str) {
    let rep = ScanReport {
        at: now(),
        ok: false,
        notes: vec![format!("the safety scan could not run: {why}")],
        findings: vec![crate::scanner::Finding { level: "warn".into(), engine: "scan".into(), what: format!("the safety scan could not finish ({why}); scan it again from Review")}],
        ..Default::default()
    };
    let _ = store(app, id, &rep);
    if app.db.with(|c| get_item(c, id)).ok().flatten().map(|i| i.catalog).unwrap_or(false) {
        // a file from another node that this node could not inspect never joins the library
        let _ = crate::library::set_blocked(app, id);
    }
}

/// The scanner. Runs for the life of the node: scans whatever is waiting, whenever there is something to do and the
/// library is unlocked. A restart, an unlock, a failed attempt: it just carries on. How many files are scanned at
/// once comes from the performance tuning (one on a shared computer, more on a dedicated machine that can take it),
/// and is looked at again every time a scan finishes.
pub async fn run_worker(app: Shared) {
    let mut fails: std::collections::HashMap<String, (u32, i64)> = std::collections::HashMap::new();
    let mut busy: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut running: tokio::task::JoinSet<(String, Result<()>)> = tokio::task::JoinSet::new();
    loop {
        if app.is_shutting_down() {
            return;
        }
        // start as many scans as the limits allow
        while app.keyring.is_unlocked() && !app.is_shutting_down() {
            let cap = if app.perf_dedicated.load(std::sync::atomic::Ordering::Relaxed) { app.tuning().scan_parallel.max(1) as usize } else { 1 };
            if running.len() >= cap {
                break;
            }
            let Some(id) = next_to_scan(&app, &fails, &busy) else { break };
            busy.insert(id.clone());
            let a = app.clone();
            running.spawn(async move {
                let r = process_one(&a, &id).await;
                (id, r)
            });
        }
        crate::library::expire_uploads(&app);
        // wait for news: a finished scan, a new file, or the clock (to retry, and to notice an unlock)
        let finished = tokio::select! {
            Some(done) = running.join_next(), if !running.is_empty() => Some(done),
            _ = app.scan_wake.notified() => None,
            _ = crate::rest::sleep(&app, Duration::from_secs(15)) => None,
        };
        let mut done = vec![];
        if let Some(d) = finished {
            done.push(d);
        }
        while let Some(d) = running.try_join_next() {
            done.push(d);
        }
        for d in done {
            let Ok((id, res)) = d else { continue };
            busy.remove(&id);
            match res {
                Ok(()) => {
                    fails.remove(&id);
                }
                Err(e) => {
                    let n = fails.get(&id).map(|f| f.0).unwrap_or(0) + 1;
                    tracing::warn!("scan of {id} failed (attempt {n}): {e:#}");
                    if n >= 3 {
                        fails.remove(&id);
                        record_failure(&app, &id, &crate::util::friendly_error(&e));
                    } else {
                        fails.insert(id, (n, now() + 30 * n as i64));
                    }
                }
            }
        }
    }
}

/// A file that arrived from the mesh (or matches one in the catalog) is untrusted until THIS node
/// has scanned it: pass -> library, anything else -> blocked (or review if the owner asked for that).
pub async fn admit_synced(app: &Shared, id: &str) -> Result<ScanReport> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    let rep = scan(app, id, it.filename.as_deref().unwrap_or("")).await?;
    let a = app.clone();
    let id2 = id.to_string();
    let review = app.cfg.review_inbound;
    let ok = rep.ok;
    tokio::task::spawn_blocking(move || -> Result<()> {
        if !ok {
            crate::library::set_blocked(&a, &id2)?;
            tracing::warn!("item {id2} from the mesh failed the safety scan and was blocked");
        } else if !review {
            crate::library::approve(&a, &id2, false)?;
        }
        Ok(())
    })
    .await??;
    Ok(rep)
}

/// Re-scan an item already in the library; pulls it out (and stops sharing it) if it now fails hard.
pub async fn scan_library_item(app: &Shared, id: &str, filename: &str) -> Result<bool> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    let rep = scan_path(app, &item_path(app, &it), id, filename).await?;
    if rep.hard {
        store(app, id, &rep)?;
        let a = app.clone();
        let id2 = id.to_string();
        tokio::task::spawn_blocking(move || crate::library::set_blocked(&a, &id2)).await??;
        tracing::warn!("library item {id} now fails the safety scan and was blocked");
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_common_containers() {
        let mut mp4 = vec![0, 0, 0, 0x18];
        mp4.extend_from_slice(b"ftypmp42");
        mp4.extend_from_slice(&[0; 8]);
        assert_eq!(sniff(&mp4), Some("mp4/mov"));
        assert_eq!(sniff(&[0x1A, 0x45, 0xDF, 0xA3, 0, 0]), Some("matroska/webm"));
        assert_eq!(sniff(b"MZ\x90\x00 not a video at all"), None);
        assert_eq!(sniff(b"#!/bin/sh\necho hi"), None);
        assert_eq!(sniff(b""), None);
        let mut ts = vec![0u8; 400];
        for i in [0, 188, 376] {
            ts[i] = 0x47;
        }
        assert_eq!(sniff(&ts), Some("mpeg-ts"));
    }
}
