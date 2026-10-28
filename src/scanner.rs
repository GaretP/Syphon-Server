//! The malware scanner.
//!
//! A video file is data, but a hostile one can still hurt: a polyglot that is also an executable or
//! archive, a container crafted to crash a decoder, a hidden payload appended after the picture, or a
//! known-bad file. Every file that enters a node (upload, download, import, mesh sync, vault) goes
//! through all of these layers over its WHOLE length, not just the start:
//!
//!   1. signatures    - executables (PE, ELF, Mach-O, Java, LNK), scripts, archives, EICAR, anywhere in the file
//!   2. structure     - MP4 boxes and Matroska elements must be well formed, end where the file ends,
//!                      and Matroska attachments must be fonts or pictures
//!   3. blocklist     - the file's SHA-256 / content id against `blocklist.txt`
//!   4. ffprobe       - the container parses, has a video stream, has sane streams (sandboxed)
//!   5. decode        - ffmpeg decodes the stream; a decoder that crashes means an exploit attempt (sandboxed)
//!   6. ClamAV        - if installed (clamdscan or clamscan), the whole file is streamed through it
//!
//! "block" findings can never be overridden. "warn" findings need the owner's decision. Nothing here
//! can promise that a file is safe; it removes the cheap and the known ways of getting hurt.

use crate::keyring::{EncReader, CHUNK};
use crate::library::keys;
use crate::state::{App, Shared};
use aho_corasick::AhoCorasick;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Finding {
    /// "block" (cannot be overridden) or "warn" (the owner decides)
    pub level: String,
    pub engine: String,
    pub what: String,
}

#[derive(Default)]
pub struct Deep {
    pub findings: Vec<Finding>,
    pub engines: Vec<String>,
    pub notes: Vec<String>,
    pub scanned_bytes: u64,
    pub complete: bool,
    pub container: Option<String>,
    pub probed: bool,
    pub has_video: bool,
    pub duration: Option<f64>,
    pub format: Option<String>,
    pub sandbox: String,
}

impl Deep {
    fn block(&mut self, engine: &str, what: impl Into<String>) {
        self.findings.push(Finding { level: "block".into(), engine: engine.into(), what: what.into() });
    }
    fn warn(&mut self, engine: &str, what: impl Into<String>) {
        self.findings.push(Finding { level: "warn".into(), engine: engine.into(), what: what.into() });
    }
    fn hard(&self) -> bool {
        self.findings.iter().any(|f| f.level == "block")
    }
    fn engine(&mut self, e: &str) {
        if !self.engines.iter().any(|x| x == e) {
            self.engines.push(e.into());
        }
    }
}

// ------------------------------------------------------------------ 1. signatures

struct Sig {
    bytes: Vec<u8>,
    level: &'static str,
    what: &'static str,
}

fn signatures() -> Vec<Sig> {
    let mut v = vec![];
    fn add(v: &mut Vec<Sig>, b: &[u8], level: &'static str, what: &'static str) {
        v.push(Sig { bytes: b.to_vec(), level, what });
    }
    add(&mut v, b"This program cannot be run in DOS mode", "block", "a Windows program (.exe/.dll) is hidden inside the file");
    add(&mut v, b"This program must be run under Win32", "block", "a Windows program is hidden inside the file");
    add(&mut v, b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "block", "the standard antivirus test file (EICAR) is inside the file");
    // ELF: magic, 32/64 bit, endianness, version 1, SYSV/Linux ABI byte, then 8 zero bytes of padding
    for class in [1u8, 2] {
        for data in [1u8, 2] {
            let mut b = vec![0x7F, b'E', b'L', b'F', class, data, 1];
            b.extend_from_slice(&[0; 9]);
            v.push(Sig { bytes: b, level: "block", what: "a Linux program (ELF) is hidden inside the file" });
        }
    }
    for cpu in [[0x07u8, 0, 0, 1], [0x0C, 0, 0, 1]] {
        let mut b = vec![0xCF, 0xFA, 0xED, 0xFE];
        b.extend_from_slice(&cpu);
        v.push(Sig { bytes: b, level: "block", what: "a macOS program (Mach-O) is hidden inside the file" });
    }
    for minor in 0x34u8..=0x46 {
        v.push(Sig { bytes: vec![0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, minor], level: "block", what: "a Java class file is hidden inside the file" });
    }
    add(&mut v, &[0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46], "block", "a Windows shortcut (.lnk) is hidden inside the file");
    add(&mut v, b"#!/bin/sh", "block", "a shell script is hidden inside the file");
    add(&mut v, b"#!/bin/bash", "block", "a shell script is hidden inside the file");
    add(&mut v, b"#!/usr/bin/env", "block", "a script is hidden inside the file");
    add(&mut v, b"#!/usr/bin/python", "block", "a script is hidden inside the file");
    add(&mut v, b"WScript.Shell", "warn", "contains Windows script text (WScript.Shell)");
    add(&mut v, b"Invoke-Expression", "warn", "contains PowerShell text");
    add(&mut v, b"FromBase64String", "warn", "contains PowerShell/.NET decoding text");
    add(&mut v, b"powershell -", "warn", "contains a PowerShell command line");
    add(&mut v, b"cmd.exe /c", "warn", "contains a Windows command line");
    add(&mut v, b"<?php", "warn", "contains PHP code");
    add(&mut v, b"<script", "warn", "contains web script text");
    add(&mut v, b"<SCRIPT", "warn", "contains web script text");
    add(&mut v, b"Rar!\x1A\x07\x00", "warn", "a RAR archive is hidden inside the file");
    add(&mut v, b"Rar!\x1A\x07\x01\x00", "warn", "a RAR archive is hidden inside the file");
    add(&mut v, &[b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C], "warn", "a 7-Zip archive is hidden inside the file");
    add(&mut v, &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], "warn", "an old Office/installer document (OLE) is hidden inside the file");
    add(&mut v, b"%PDF-1.", "warn", "a PDF document is hidden inside the file");
    v
}

struct SigResult {
    sha256: String,
    hits: Vec<(String, &'static str, u64)>,
    bytes: u64,
}

/// One pass over the whole decrypted file: SHA-256 and every signature.
fn scan_signatures(r: &mut EncReader) -> Result<SigResult> {
    let sigs = signatures();
    let ac = AhoCorasick::new(sigs.iter().map(|s| s.bytes.as_slice()))?;
    let keep = sigs.iter().map(|s| s.bytes.len()).max().unwrap_or(1) - 1;
    let mut sha = Sha256::new();
    let mut seen: Vec<Option<u64>> = vec![None; sigs.len()];
    let mut carry: Vec<u8> = vec![];
    let mut pos = 0u64;
    while pos < r.len {
        let end = (pos + CHUNK as u64).min(r.len);
        let data = r.read_range(pos, end)?;
        sha.update(&data);
        let mut buf = std::mem::take(&mut carry);
        let base = pos - buf.len() as u64;
        let carried = buf.len();
        buf.extend_from_slice(&data);
        for m in ac.find_overlapping_iter(&buf) {
            if m.end() > carried && seen[m.pattern().as_usize()].is_none() {
                seen[m.pattern().as_usize()] = Some(base + m.start() as u64);
            }
        }
        let from = buf.len().saturating_sub(keep);
        carry = buf[from..].to_vec();
        pos = end;
    }
    let mut hits = vec![];
    let mut dedupe = std::collections::HashSet::new();
    for (i, s) in seen.iter().enumerate() {
        if let Some(off) = s {
            if dedupe.insert(sigs[i].what) {
                hits.push((sigs[i].what.to_string(), sigs[i].level, *off));
            }
        }
    }
    Ok(SigResult { sha256: hex::encode(sha.finalize()), hits, bytes: r.len })
}

/// A video whose last bytes are a valid ZIP end-of-archive record is also a ZIP (a classic polyglot).
fn zip_polyglot(r: &mut EncReader) -> Result<bool> {
    let tail_len = r.len.min(65_557);
    let tail = r.read_range(r.len - tail_len, r.len)?;
    let mut i = 0;
    while i + 22 <= tail.len() {
        if &tail[i..i + 4] == b"PK\x05\x06" {
            let clen = u16::from_le_bytes([tail[i + 20], tail[i + 21]]) as usize;
            if i + 22 + clen == tail.len() {
                return Ok(true);
            }
        }
        i += 1;
    }
    Ok(false)
}

// ------------------------------------------------------------------ 2. structure

/// Random access with a one-chunk cache, so walking thousands of small headers stays cheap.
struct Rd<'a> {
    r: &'a mut EncReader,
    idx: u64,
    buf: Vec<u8>,
}

impl<'a> Rd<'a> {
    fn new(r: &'a mut EncReader) -> Self {
        Rd { r, idx: u64::MAX, buf: vec![] }
    }
    fn len(&self) -> u64 {
        self.r.len
    }
    fn get(&mut self, off: u64, n: usize) -> Result<Vec<u8>> {
        let end = (off + n as u64).min(self.r.len);
        if off >= end {
            return Ok(vec![]);
        }
        let (a, b) = (off / CHUNK as u64, (end - 1) / CHUNK as u64);
        if a != b {
            return self.r.read_range(off, end);
        }
        if self.idx != a {
            let s = a * CHUNK as u64;
            self.buf = self.r.read_range(s, (s + CHUNK as u64).min(self.r.len))?;
            self.idx = a;
        }
        let s = (off - a * CHUNK as u64) as usize;
        Ok(self.buf[s..s + (end - off) as usize].to_vec())
    }
}

#[derive(Default, Debug)]
pub struct Mp4Walk {
    pub issues: Vec<String>,
    pub moov: Option<(u64, u64)>,
    pub ftyp: Option<(u64, u64)>,
    pub mdat_before_moov: bool,
}

const MP4_TOP: [&str; 24] = [
    "ftyp", "moov", "mdat", "free", "skip", "wide", "moof", "mfra", "sidx", "ssix", "styp", "uuid", "pnot", "meta", "udta", "pdin", "emsg", "prft", "mfro", "junk", "pad ", "cmov", "iods", "elst",
];

pub fn walk_mp4(r: &mut EncReader) -> Result<Mp4Walk> {
    let mut rd = Rd::new(r);
    let len = rd.len();
    let mut w = Mp4Walk::default();
    let mut pos = 0u64;
    let mut boxes = 0u32;
    let mut saw_mdat = false;
    while pos < len {
        if len - pos < 8 {
            if rd.get(pos, 8)?.iter().any(|b| *b != 0) {
                w.issues.push(format!("{} stray bytes at the end of the file", len - pos));
            }
            break;
        }
        let h = rd.get(pos, 16)?;
        let size32 = u32::from_be_bytes([h[0], h[1], h[2], h[3]]) as u64;
        let ty = &h[4..8];
        let printable = ty.iter().all(|c| (0x20..0x7F).contains(c) || *c == 0xA9);
        let (size, _hdr) = match size32 {
            0 => (len - pos, 8u64),
            1 if h.len() >= 16 => (u64::from_be_bytes(h[8..16].try_into().unwrap()), 16),
            n => (n, 8),
        };
        let name = String::from_utf8_lossy(ty).to_string();
        if !printable || size < 8 {
            w.issues.push(format!("after {} bytes the data is not part of the video structure (possible hidden payload)", pos));
            break;
        }
        if pos + size > len {
            w.issues.push(format!("the \"{name}\" section runs {} bytes past the end of the file (the file is cut off)", pos + size - len));
            break;
        }
        match name.as_str() {
            "moov" => {
                w.moov.get_or_insert((pos, size));
                w.mdat_before_moov = saw_mdat;
            }
            "ftyp" => {
                w.ftyp.get_or_insert((pos, size));
            }
            "mdat" => saw_mdat = true,
            _ => {}
        }
        if boxes > 8 && !MP4_TOP.contains(&name.as_str()) {
            w.issues.push(format!("unexpected section \"{name}\" in the video structure"));
        }
        boxes += 1;
        if boxes > 2_000_000 {
            w.issues.push("an absurd number of sections".into());
            break;
        }
        pos += size;
    }
    if w.moov.is_none() && w.issues.is_empty() {
        w.issues.push("no movie index (moov) found".into());
    }
    Ok(w)
}

fn ebml_vint(b: &[u8], keep_marker: bool) -> Option<(u64, usize, bool)> {
    let first = *b.first()?;
    if first == 0 {
        return None;
    }
    let n = first.leading_zeros() as usize + 1;
    if n > 8 || b.len() < n {
        return None;
    }
    let mut v = if keep_marker { first as u64 } else { (first as u64) & ((1u64 << (8 - n)) - 1) };
    let mut all_ones = (first as u64 | !((1u64 << (8 - n)) - 1) & 0xFF) == 0xFF;
    for x in &b[1..n] {
        v = (v << 8) | *x as u64;
        all_ones &= *x == 0xFF;
    }
    Some((v, n, all_ones))
}

const DANGEROUS_EXT: [&str; 20] = [
    "exe", "dll", "bat", "cmd", "com", "scr", "msi", "ps1", "vbs", "js", "jse", "wsf", "jar", "sh", "py", "pl", "lnk", "hta", "apk", "elf",
];
const HARMLESS_EXT: [&str; 12] = ["ttf", "otf", "ttc", "woff", "woff2", "jpg", "jpeg", "png", "webp", "gif", "svg", "bmp"];

pub struct MkvWalk {
    pub issues: Vec<String>,
    pub dangerous: Vec<String>,
}

pub fn walk_mkv(r: &mut EncReader) -> Result<MkvWalk> {
    let mut rd = Rd::new(r);
    let len = rd.len();
    let mut out = MkvWalk { issues: vec![], dangerous: vec![] };
    let mut pos = 0u64;
    let mut elements = 0u32;
    // top level: EBML header, then Segment(s)
    while pos < len {
        let h = rd.get(pos, 12)?;
        let Some((id, idn, _)) = ebml_vint(&h, true) else {
            out.issues.push(format!("after {pos} bytes the data is not part of the video structure (possible hidden payload)"));
            return Ok(out);
        };
        let Some((size, szn, unknown)) = ebml_vint(&h[idn.min(h.len())..], false) else {
            out.issues.push("a damaged section header".into());
            return Ok(out);
        };
        let body = pos + (idn + szn) as u64;
        let end = if unknown { len } else { body + size };
        if end > len {
            out.issues.push("the file is cut off (a section runs past the end)".into());
            return Ok(out);
        }
        if id == 0x18538067 {
            // Segment: look at its children
            let mut p = body;
            while p < end {
                elements += 1;
                if elements > 2_000_000 {
                    out.issues.push("an absurd number of sections".into());
                    return Ok(out);
                }
                let c = rd.get(p, 12)?;
                let Some((cid, cidn, _)) = ebml_vint(&c, true) else {
                    out.issues.push(format!("after {p} bytes the data is not part of the video structure (possible hidden payload)"));
                    return Ok(out);
                };
                let Some((csize, cszn, cunk)) = ebml_vint(&c[cidn.min(c.len())..], false) else {
                    out.issues.push("a damaged section header".into());
                    return Ok(out);
                };
                let cbody = p + (cidn + cszn) as u64;
                if cunk {
                    // live-streamed files use unknown-size clusters; we cannot walk past them cheaply
                    out.issues.push("the file uses open-ended sections; its structure was only partly checked".into());
                    return Ok(out);
                }
                let cend = cbody + csize;
                if cend > end {
                    out.issues.push("a section runs past the end of its parent (the file is cut off or damaged)".into());
                    return Ok(out);
                }
                if cid == 0x1941A469 {
                    // Attachments
                    if csize > 128 << 20 {
                        out.issues.push("an unusually large attachment area".into());
                    } else {
                        let data = rd.r.read_range(cbody, cend)?;
                        attachments(&data, &mut out);
                    }
                }
                p = cend;
            }
            if end < len {
                // data after the Segment that is not another valid element
                let rest = rd.get(end, 12)?;
                if ebml_vint(&rest, true).is_none() {
                    out.issues.push(format!("{} bytes of unexplained data follow the end of the video", len - end));
                    return Ok(out);
                }
            }
        }
        pos = end;
    }
    Ok(out)
}

fn attachments(data: &[u8], out: &mut MkvWalk) {
    // Attachments -> AttachedFile(61A7) -> FileName(466E), FileMediaType(4660), FileData(465C)
    let mut p = 0;
    while let Some((id, idn, _)) = data.get(p..).and_then(|d| ebml_vint(d, true)) {
        let Some((sz, szn, _)) = data.get(p + idn..).and_then(|d| ebml_vint(d, false)) else { return };
        let body = p + idn + szn;
        let end = (body + sz as usize).min(data.len());
        if id == 0x61A7 {
            let (mut name, mut mime) = (String::new(), String::new());
            let mut q = body;
            while q < end {
                let Some((cid, cidn, _)) = ebml_vint(&data[q..], true) else { break };
                let Some((csz, cszn, _)) = data.get(q + cidn..).and_then(|d| ebml_vint(d, false)) else { break };
                let cb = q + cidn + cszn;
                let ce = (cb + csz as usize).min(end);
                match cid {
                    0x466E => name = String::from_utf8_lossy(&data[cb..ce]).to_string(),
                    0x4660 => mime = String::from_utf8_lossy(&data[cb..ce]).to_string(),
                    _ => {}
                }
                q = ce.max(q + 1);
            }
            let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
            let mimel = mime.to_ascii_lowercase();
            if DANGEROUS_EXT.contains(&ext.as_str()) || mimel.contains("executable") || mimel.contains("msdownload") || mimel.contains("x-sh") {
                out.dangerous.push(format!("an attached file named \"{name}\" is a program or script"));
            } else if !(HARMLESS_EXT.contains(&ext.as_str()) || mimel.starts_with("font/") || mimel.starts_with("image/") || mimel.contains("font") || mimel.contains("opentype") || mimel.contains("truetype")) {
                out.issues.push(format!("the file carries an attachment \"{name}\" ({mime}) that is not a font or a picture"));
            }
        }
        p = end.max(p + 1);
    }
}

// ------------------------------------------------------------------ sandboxed helpers

fn which(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).exists();
    }
    std::env::var_os("PATH").map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file())).unwrap_or(false)
}

/// Whether programs can be run inside a bubblewrap sandbox on this machine. Tested once, by actually
/// starting one, because "bwrap is installed" does not mean it is allowed to work: virtual machines,
/// hardened kernels and some systemd settings (ProtectKernelTunables) stop it from creating namespaces
/// or mounting /proc. Several layouts are tried, and the first that works is used from then on.
pub struct Sandbox {
    pub ok: bool,
    prefix: Vec<String>,
    pub label: String,
    /// Why it does not work (empty when it does), in the words bwrap used.
    pub detail: String,
}

static SANDBOX: std::sync::OnceLock<Sandbox> = std::sync::OnceLock::new();

pub fn sandbox() -> &'static Sandbox {
    SANDBOX.get_or_init(|| {
        if !which("bwrap") {
            return Sandbox { ok: false, prefix: vec![], label: "none".into(), detail: "bubblewrap is not installed".into() };
        }
        let base: Vec<&str> = vec!["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev", "--tmpfs", "/tmp"];
        let layouts: Vec<(Vec<&str>, &str)> = vec![
            (vec!["--proc", "/proc"], "bubblewrap"),
            // services with ProtectKernelTunables cannot mount a fresh /proc; the programs run here do not need it
            (vec![], "bubblewrap (without /proc)"),
        ];
        let mut why = String::new();
        for (extra, label) in layouts {
            let mut argv: Vec<String> = base.iter().map(|s| s.to_string()).collect();
            argv.extend(extra.iter().map(|s| s.to_string()));
            let mut test = argv.clone();
            test.extend(["--".to_string(), "true".to_string()]);
            match std::process::Command::new(&test[0]).args(&test[1..]).env_clear().env("PATH", std::env::var("PATH").unwrap_or_default()).output() {
                Ok(o) if o.status.success() => {
                    argv.push("--".into());
                    return Sandbox { ok: true, prefix: argv, label: label.into(), detail: String::new() };
                }
                Ok(o) => {
                    if why.is_empty() {
                        why = String::from_utf8_lossy(&o.stderr).lines().next().unwrap_or("bubblewrap exited with an error").trim().to_string();
                    }
                }
                Err(e) => why = e.to_string(),
            }
        }
        Sandbox { ok: false, prefix: vec![], label: "none".into(), detail: why }
    })
}

/// Wrap a command in the sandbox when one works here, with an optional folder it may write to.
/// Without a sandbox the command still runs with an empty environment and nothing but the stream on stdin.
pub fn sandboxed_in(argv: Vec<String>, writable: Option<&Path>) -> (Vec<String>, String) {
    let sb = sandbox();
    let (mut v, label) = if !sb.ok {
        (argv, "none".to_string())
    } else {
        let mut v = sb.prefix.clone();
        v.pop(); // the trailing "--"
        if let Some(w) = writable {
            v.extend(["--bind".to_string(), w.display().to_string(), w.display().to_string()]);
        }
        v.push("--".into());
        v.extend(argv);
        (v, sb.label.clone())
    };
    // scanning is heavy and can wait: lower priority for the processor and the disk, set by the performance tuning
    let n = TUNE_NICE.load(std::sync::atomic::Ordering::Relaxed);
    if n > 0 {
        let mut pre: Vec<String> = vec![];
        if which("ionice") {
            pre.extend(["ionice", "-c2", "-n7"].map(String::from));
        }
        if which("nice") {
            pre.extend(["nice".to_string(), "-n".to_string(), n.to_string()]);
        }
        pre.extend(v);
        v = pre;
    }
    (v, label)
}

/// Set by the performance tuning (perf.rs): scanner priority, antivirus window and decode size. 0 = use the defaults / config.
pub static TUNE_NICE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
pub static TUNE_WINDOW_MIB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static TUNE_DECODE_MIB: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn sandboxed(argv: Vec<String>) -> (Vec<String>, String) {
    sandboxed_in(argv, None)
}

pub struct RunOut {
    pub stdout: Vec<u8>,
    pub stderr: String,
    /// None when the process was ended by a signal (a crash)
    pub code: Option<i32>,
    pub fed: u64,
    pub timed_out: bool,
}

/// Run a program with the decrypted file (bytes `start` up to `limit`) on its standard input.
async fn run_fed(argv: Vec<String>, path: PathBuf, key: [u8; 32], start: u64, limit: u64, timeout: Duration) -> Result<RunOut> {
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
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4);
    let feeder = tokio::task::spawn_blocking(move || -> Result<u64> {
        let mut r = EncReader::open(&path, &key)?;
        let end = r.len.min(limit);
        let mut pos = start.min(end);
        while pos < end {
            let e = (pos + CHUNK as u64).min(end);
            let d = r.read_range(pos, e)?;
            if tx.blocking_send(d).is_err() {
                break;
            }
            pos = e;
        }
        Ok(pos)
    });
    tokio::spawn(async move {
        while let Some(d) = rx.recv().await {
            if stdin.write_all(&d).await.is_err() {
                break;
            }
        }
        let _ = stdin.shutdown().await;
    });
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(o) => {
            let o = o?;
            let fed = feeder.await.ok().and_then(|r| r.ok()).unwrap_or(0);
            Ok(RunOut { stdout: o.stdout, stderr: String::from_utf8_lossy(&o.stderr).chars().take(60_000).collect(), code: o.status.code(), fed, timed_out: false })
        }
        Err(_) => Ok(RunOut { stdout: vec![], stderr: String::new(), code: Some(-1), fed: 0, timed_out: true }),
    }
}

// ------------------------------------------------------------------ the pipeline

fn blocklist(app: &App) -> std::collections::HashSet<String> {
    std::fs::read_to_string(app.dirs.root.join("blocklist.txt"))
        .map(|s| s.lines().map(|l| l.split('#').next().unwrap_or("").trim().to_ascii_lowercase()).filter(|l| !l.is_empty()).collect())
        .unwrap_or_default()
}

/// Scan one encrypted file completely. `id` is the content id (also checked against the blocklist).
pub async fn deep_scan(app: &Shared, path: &Path, id: &str, filename: &str) -> Result<Deep> {
    let key = keys(app)?.content_key();
    let mut d = Deep { sandbox: "none".into(), complete: true, ..Default::default() };
    let p = path.to_path_buf();

    // 1-3: signatures, structure, blocklist: one blocking pass
    let bl = blocklist(app);
    let (sig, zip, mp4, mkv, container, head, len) = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut r = EncReader::open(&p, &key)?;
        let head = r.read_range(0, r.len.min(4096))?;
        let container = crate::quarantine::sniff(&head);
        let sig = scan_signatures(&mut r)?;
        let zip = if r.len > 22 { zip_polyglot(&mut r)? } else { false };
        let mp4 = if container == Some("mp4/mov") { Some(walk_mp4(&mut r)?) } else { None };
        let mkv = if container == Some("matroska/webm") { Some(walk_mkv(&mut r)?) } else { None };
        let len = r.len;
        Ok((sig, zip, mp4, mkv, container, head, len))
    })
    .await??;
    let _ = head;
    d.container = container.map(|s| s.to_string());
    d.scanned_bytes = sig.bytes;
    d.engine("signatures");
    d.engine("blocklist");
    for (what, level, off) in &sig.hits {
        let msg = format!("{what} (at byte {off})");
        if *level == "block" { d.block("signatures", msg) } else { d.warn("signatures", msg) }
    }
    if zip {
        d.block("signatures", "the file is also a valid ZIP archive (a disguised file)");
    }
    if bl.contains(&sig.sha256) || bl.contains(&id.to_ascii_lowercase()) {
        d.block("blocklist", "this exact file is on your blocklist of known-bad files");
    }
    d.engine("structure");
    let mut moov_at_end: Option<(u64, u64, Option<(u64, u64)>)> = None;
    if let Some(w) = &mp4 {
        for i in &w.issues {
            d.warn("structure", i.clone());
        }
        if let (Some(m), true) = (w.moov, w.mdat_before_moov) {
            moov_at_end = Some((m.0, m.1, w.ftyp));
        }
    }
    if let Some(w) = &mkv {
        for i in &w.issues {
            d.warn("structure", i.clone());
        }
        for i in &w.dangerous {
            d.block("structure", i.clone());
        }
    }
    if container.is_none() {
        d.block("type", "this is not a video file (it does not start like any video container). Only video is allowed");
    }

    // 4: ffprobe on the start of the file (or ftyp+moov when the index sits at the end)
    if which(&app.cfg.ffprobe) {
        d.engine("ffprobe");
        let p = path.to_path_buf();
        let key2 = key;
        let data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            let mut r = EncReader::open(&p, &key2)?;
            if let Some((mo, ms, ft)) = moov_at_end {
                if ms <= 64 << 20 {
                    let mut v = vec![];
                    if let Some((fo, fs)) = ft {
                        v.extend(r.read_range(fo, fo + fs)?);
                    }
                    v.extend(r.read_range(mo, mo + ms)?);
                    return Ok(v);
                }
            }
            r.read_range(0, r.len.min(crate::quarantine::PROBE_BYTES))
        })
        .await??;
        if container.is_some() {
            let (json, sandbox, notes) = crate::quarantine::probe(app, data).await;
            d.sandbox = sandbox;
            d.notes.extend(notes);
            match json {
                Some(v) => {
                    d.probed = true;
                    d.format = v["format"]["format_name"].as_str().map(|s| s.to_string());
                    d.duration = v["format"]["duration"].as_str().and_then(|s| s.parse().ok());
                    let streams = v["streams"].as_array().cloned().unwrap_or_default();
                    d.has_video = streams.iter().any(|s| s["codec_type"] == "video");
                    if !d.has_video {
                        d.warn("ffprobe", "no video stream found");
                    }
                    if streams.len() > 64 {
                        d.warn("ffprobe", format!("an unusual number of streams ({})", streams.len()));
                    }
                    for s in &streams {
                        let t = s["codec_type"].as_str().unwrap_or("");
                        if !["video", "audio", "subtitle", "attachment", "data"].contains(&t) {
                            d.warn("ffprobe", format!("an unknown stream type \"{t}\""));
                        }
                        let (w, h) = (s["width"].as_u64().unwrap_or(0), s["height"].as_u64().unwrap_or(0));
                        if w > 16384 || h > 16384 {
                            d.warn("ffprobe", format!("an absurd picture size ({w}x{h}), a trick used to crash players"));
                        }
                    }
                }
                None => d.warn("ffprobe", "ffprobe could not read the video's headers"),
            }
        }
    } else {
        d.notes.push("ffprobe is not installed, so the container could not be inspected (install ffmpeg)".into());
    }

    // 5: ffmpeg. A full demux pass walks every packet of the whole file (fast, and it catches a container that
    // goes bad deep inside a long movie); a real decode runs over the first part. Both read the stream from a pipe,
    // so they are skipped when an MP4 keeps its index at the end.
    let max_mib = match TUNE_DECODE_MIB.load(std::sync::atomic::Ordering::Relaxed) {
        0 => app.cfg.scan.decode_max_mib,
        n => n,
    };
    if app.cfg.scan.decode && which(&app.cfg.ffmpeg) && container.is_some() {
        if moov_at_end.is_some() {
            d.notes.push("decode test skipped: this MP4 keeps its index at the end, so it cannot be streamed to the decoder".into());
        } else {
            d.engine("decode");
            let limit = max_mib.saturating_mul(1 << 20);
            let ff = |extra: &[&str]| -> Vec<String> {
                let mut v = vec![app.cfg.ffmpeg.clone(), "-nostdin".into(), "-v".into(), "error".into(), "-threads".into(), "2".into(), "-i".into(), "pipe:0".into()];
                v.extend(extra.iter().map(|s| s.to_string()));
                v
            };
            let (argv, sb) = sandboxed(ff(&["-map", "0:v:0?", "-map", "0:a:0?", "-sn", "-dn", "-f", "null", "-"]));
            d.sandbox = sb;
            let o = run_fed(argv, path.to_path_buf(), key, 0, limit, Duration::from_secs(app.cfg.scan.decode_timeout_secs)).await?;
            let partial = len > limit;
            let mut skipped = false;
            if o.timed_out {
                d.notes.push(format!("the decode test stopped after {} seconds", app.cfg.scan.decode_timeout_secs));
            } else if o.code.is_none() || o.code == Some(139) || o.code == Some(134) || o.code == Some(132) {
                d.block("decode", "the video decoder crashed while reading this file, which is how exploit files behave");
            } else {
                let errs = o.stderr.lines().filter(|l| !l.trim().is_empty()).count();
                if errs > if partial { 200 } else { 60 } {
                    d.warn("decode", format!("the stream is damaged or deliberately malformed ({errs} decoding errors)"));
                }
                if o.stderr.contains("moov atom not found") {
                    skipped = true;
                    d.notes.push("decode test skipped: the file cannot be streamed to the decoder".into());
                }
            }
            if partial && !skipped && !d.hard() {
                // everything past the decoded part still gets walked packet by packet
                let (argv, _) = sandboxed(ff(&["-map", "0:v?", "-map", "0:a?", "-c", "copy", "-f", "null", "-"]));
                let secs = 900 + (len >> 30) * 90;
                let o = run_fed(argv, path.to_path_buf(), key, 0, u64::MAX, Duration::from_secs(secs)).await?;
                if o.timed_out {
                    d.notes.push(format!("the full-file container walk stopped after {secs} seconds"));
                } else if o.code.is_none() || o.code == Some(139) || o.code == Some(134) || o.code == Some(132) {
                    d.block("decode", "the media tools crashed while walking this file, which is how exploit files behave");
                } else if o.stderr.lines().filter(|l| !l.trim().is_empty()).count() > 200 {
                    d.warn("decode", "the container is damaged further into the file");
                }
                d.notes.push(format!("every part of the container was walked; the first {max_mib} MiB were also fully decoded"));
            } else if partial {
                d.notes.push(format!("the first {max_mib} MiB were fully decoded"));
            }
        }
    } else if app.cfg.scan.decode {
        d.notes.push("ffmpeg is not installed, so the decode test was skipped".into());
    }

    // 6: ClamAV over the whole file. ClamAV cannot take a stream larger than a few GB, so a big file goes through
    // in overlapping windows (the overlap makes sure a signature on a boundary is still seen whole).
    if app.cfg.scan.clamav != "off" {
        if !(which("clamdscan") || which("clamscan")) {
            d.notes.push("ClamAV is not installed; install clamav for known-malware detection".into());
        } else {
            d.engine("clamav");
            let scratch = app.dirs.root.join("scan-tmp");
            let _ = std::fs::create_dir_all(&scratch);
            let (window, overlap) = match CLAM_WINDOW.load(std::sync::atomic::Ordering::Relaxed) {
                0 => match TUNE_WINDOW_MIB.load(std::sync::atomic::Ordering::Relaxed) {
                    0 => (1536u64 << 20, 8u64 << 20),
                    m => (m << 20, 8u64 << 20),
                },
                w => (w, w / 8), // tests shrink the window to try the boundaries
            };
            let mut start = 0u64;
            let mut all_answered = true;
            loop {
                let end = (start + window + overlap).min(len);
                match clam_window(app, path, key, start, end, len <= (24 << 20), &scratch, &mut d.notes).await {
                    Clam::Found(name) => {
                        // Generic heuristics (damaged files, limits) are advice; real signatures are verdicts.
                        if name.starts_with("Heuristics.") || name.starts_with("PUA.") {
                            d.warn("clamav", format!("ClamAV flagged this file as suspicious ({name})"));
                        } else {
                            d.block("clamav", format!("ClamAV identified this file as malware ({name})"));
                        }
                        break;
                    }
                    Clam::Clean => {}
                    Clam::Failed => {
                        all_answered = false;
                        break;
                    }
                }
                if end >= len {
                    break;
                }
                start += window;
            }
            let _ = std::fs::remove_dir_all(&scratch);
            if !all_answered {
                d.complete = false;
            }
        }
    }
    let _ = filename;
    Ok(d)
}

/// Size of one ClamAV pass in bytes; 0 means the normal 1.5 GiB. Only tests change it.
#[doc(hidden)]
pub static CLAM_WINDOW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

enum Clam {
    Clean,
    Found(String),
    Failed,
}

/// One ClamAV pass over bytes `start..end` of the file. Only a named signature counts as a finding: an exit
/// code on its own (a crashed scanner, a sandbox that would not start) is "could not scan", never "malware".
async fn clam_window(app: &Shared, path: &Path, key: [u8; 32], start: u64, end: u64, small: bool, scratch: &Path, notes: &mut Vec<String>) -> Clam {
    let mut tried: Vec<Vec<String>> = vec![];
    if small && which("clamdscan") {
        tried.push(vec!["clamdscan".to_string(), "--no-summary".into(), "--stream".into(), "-".into()]);
    }
    if which("clamscan") {
        tried.push(vec![
            "clamscan".into(),
            "--no-summary".into(),
            "--max-filesize=2047M".into(),
            "--max-scansize=4000M".into(),
            format!("--tempdir={}", scratch.display()),
            "-".into(),
        ]);
    }
    let _ = app;
    for argv in tried {
        let (sb, _) = sandboxed_in(argv.clone(), Some(scratch));
        let mut res = run_fed(sb, path.to_path_buf(), key, start, end, Duration::from_secs(3600)).await;
        // If the sandbox itself failed (bwrap exits with code 1 and a "bwrap:" message) that is not a verdict.
        if let Ok(o) = &res {
            if o.code == Some(1) && o.stderr.trim_start().starts_with("bwrap:") {
                res = run_fed(argv, path.to_path_buf(), key, start, end, Duration::from_secs(3600)).await;
            }
        }
        match res {
            Ok(o) => {
                let out = String::from_utf8_lossy(&o.stdout).to_string();
                if let Some(line) = out.lines().find(|l| l.trim_end().ends_with("FOUND")) {
                    let name = line.trim_end().trim_end_matches("FOUND").trim().rsplit(':').next().unwrap_or("").trim().to_string();
                    return Clam::Found(if name.is_empty() { "unnamed".into() } else { name });
                } else if o.code == Some(0) {
                    return Clam::Clean;
                } else {
                    let why = o.stderr.lines().find(|l| !l.trim().is_empty()).map(|s| s.to_string()).unwrap_or_else(|| out.lines().next().unwrap_or("error").to_string());
                    notes.push(format!("ClamAV could not scan this file (exit {:?}: {})", o.code, why.chars().take(160).collect::<String>()));
                }
            }
            Err(e) => notes.push(format!("ClamAV failed to start: {e}")),
        }
    }
    Clam::Failed
}

// ------------------------------------------------------------------ whole-library rescan

#[derive(Default, Clone, Serialize)]
pub struct Progress {
    pub running: bool,
    pub done: usize,
    pub total: usize,
    pub blocked: usize,
}

static PROGRESS: std::sync::Mutex<Progress> = std::sync::Mutex::new(Progress { running: false, done: 0, total: 0, blocked: 0 });

pub fn progress() -> Progress {
    PROGRESS.lock().unwrap().clone()
}

/// Scan everything this node holds again (new signatures, new ClamAV database). Anything that now
/// has a "block" finding is pulled out of the library, stops being shared, and shows up in Review.
pub fn start_library_rescan(app: &Shared) -> Result<()> {
    keys(app)?;
    {
        let mut p = PROGRESS.lock().unwrap();
        if p.running {
            return Err(anyhow!("a library scan is already running"));
        }
        *p = Progress { running: true, ..Default::default() };
    }
    let app = app.clone();
    tokio::spawn(async move {
        let ids: Vec<(String, Option<String>)> = app
            .db
            .with(|c| {
                let mut st = c.prepare("SELECT id,filename FROM items WHERE local='present' AND deleted=0")?;
                let v = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                Ok(v.collect::<rusqlite::Result<_>>()?)
            })
            .unwrap_or_default();
        PROGRESS.lock().unwrap().total = ids.len();
        for (id, name) in ids {
            if app.is_shutting_down() {
                break;
            }
            match crate::quarantine::scan_library_item(&app, &id, name.as_deref().unwrap_or("")).await {
                Ok(true) => PROGRESS.lock().unwrap().blocked += 1,
                Ok(false) => {}
                Err(e) => tracing::warn!("library scan of {id}: {e:#}"),
            }
            PROGRESS.lock().unwrap().done += 1;
        }
        PROGRESS.lock().unwrap().running = false;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(id: &[u8], body: &[u8]) -> Vec<u8> {
        let mut v = id.to_vec();
        v.push(0x80 | body.len() as u8);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn matroska_attachments_must_be_fonts_or_pictures() {
        let file = |name: &str, mime: &str| {
            let body = [element(&[0x46, 0x6E], name.as_bytes()), element(&[0x46, 0x60], mime.as_bytes())].concat();
            element(&[0x61, 0xA7], &body)
        };
        let mut w = MkvWalk { issues: vec![], dangerous: vec![] };
        attachments(&[file("font.ttf", "application/x-truetype-font"), file("cover.jpg", "image/jpeg")].concat(), &mut w);
        assert!(w.issues.is_empty() && w.dangerous.is_empty(), "{:?}", w.issues);
        attachments(&file("notes.txt", "text/plain"), &mut w);
        assert_eq!(w.issues.len(), 1);
        attachments(&file("update.exe", "application/x-msdownload"), &mut w);
        assert_eq!(w.dangerous.len(), 1);
    }

    #[test]
    fn vints_decode() {
        assert_eq!(ebml_vint(&[0x1A, 0x45, 0xDF, 0xA3], true).map(|x| (x.0, x.1)), Some((0x1A45DFA3, 4)));
        assert_eq!(ebml_vint(&[0x81], false).map(|x| (x.0, x.1)), Some((1, 1)));
        assert!(ebml_vint(&[0xFF], false).unwrap().2, "all ones means unknown size");
    }
}
