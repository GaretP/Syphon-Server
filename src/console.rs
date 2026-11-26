//! The owner's console in the web app.
//!
//! Two parts:
//! - **Syphon commands** (`status`, `users`, `storage`, `logs`, …): answered by the node itself, owner only.
//! - **The computer's terminal**: a real login on the node computer, only from the home network, and only after
//!   the owner types Syphon's password and an authenticator code again, every time. It reaches the computer's own
//!   `login` program through a root relay (see `shellpty.rs`), so a Linux account and its password are needed on
//!   top. It is off until the owner switches it on.

use crate::shellpty::{frame, take_frames, FRAME_DATA, FRAME_EXIT, FRAME_RESIZE};
use crate::state::{App, Shared};
use anyhow::{anyhow, bail, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SOCKET: &str = "/run/syphon-shell.sock";

// ------------------------------------------------------------------ the node's own log, for `logs`

static LOG: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
const LOG_LINES: usize = 600;

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            if it.peek() == Some(&'[') {
                it.next();
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Where the node's log lines go: standard error (the system journal) and a short memory for `logs`.
pub struct LogTee;
pub struct LogTeeWriter(Vec<u8>);

impl std::io::Write for LogTeeWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LogTeeWriter {
    fn drop(&mut self) {
        let _ = std::io::Write::write_all(&mut std::io::stderr(), &self.0);
        let text = String::from_utf8_lossy(&self.0);
        let mut l = LOG.lock().unwrap();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            l.push_back(strip_ansi(line));
            while l.len() > LOG_LINES {
                l.pop_front();
            }
        }
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogTee {
    type Writer = LogTeeWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LogTeeWriter(Vec::with_capacity(256))
    }
}

pub fn recent_log(n: usize) -> Vec<String> {
    let l = LOG.lock().unwrap();
    l.iter().skip(l.len().saturating_sub(n)).cloned().collect()
}

static STARTED: std::sync::OnceLock<i64> = std::sync::OnceLock::new();

pub fn mark_started() {
    let _ = STARTED.set(crate::util::now());
}

// ------------------------------------------------------------------ Syphon commands

pub const HELP: &str = "Syphon commands:
  status            how the node is doing
  users             who has an account, and their role
  devices           trusted devices per person
  storage           the drives and how full they are
  peers             the other nodes in your mesh
  gpu               the graphics card used for conversions
  logs [lines]      the node's latest log lines (default 40)
  update [check|now]  look for a new version, or install it
  restart           restart Syphon (the library stays unlocked)
  clear             clear the screen
The computer's own terminal is below the console, for when you need more.";

fn ago(t: i64) -> String {
    let d = crate::util::now() - t;
    match d {
        d if d < 90 => "just now".into(),
        d if d < 5400 => format!("{} min ago", d / 60),
        d if d < 129_600 => format!("{} h ago", d / 3600),
        d => format!("{} days ago", d / 86400),
    }
}

fn gb(b: u64) -> String {
    let g = b as f64 / 1e9;
    if g >= 1000.0 {
        format!("{:.1} TB", g / 1000.0)
    } else {
        format!("{g:.0} GB")
    }
}

fn status(app: &App) -> String {
    let t = app.tor.lock().unwrap().clone();
    let items: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM items WHERE local='present'", [], |r| r.get(0))?)).unwrap_or(0);
    let review: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM items WHERE local='quarantine'", [], |r| r.get(0))?)).unwrap_or(0);
    let peers: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM peers WHERE enabled=1", [], |r| r.get(0))?)).unwrap_or(0);
    let mut s = vec![
        format!("Node          {}", app.cfg.name),
        format!("Version       {}", crate::update::version()),
        format!("Running for   {}", STARTED.get().map(|t| ago(*t).replace(" ago", "")).unwrap_or_else(|| "?".into())),
        format!("Library       {}", if app.keyring.is_unlocked() { "unlocked" } else { "locked (sign in to unlock)" }),
        format!("Videos        {items} stored here, {review} waiting in Review"),
        format!("Mesh          {peers} other node(s)"),
        format!("Free space    {} on the system drive", gb(app.disk_free())),
        format!("Watching now  {} stream(s), {} conversion(s)", app.streams(), app.active_transcodes.load(std::sync::atomic::Ordering::Relaxed)),
    ];
    if app.cfg.transport == "tor" {
        s.push(format!("Tor           {}", if t.bootstrap >= 100 { "ready".to_string() } else { format!("starting ({}%)", t.bootstrap) }));
    }
    s.join("\n")
}

fn users(app: &App) -> String {
    match crate::auth::list_users(app) {
        Ok(v) if !v.is_empty() => v.into_iter().map(|(n, r)| format!("  {n:<24} {r}")).collect::<Vec<_>>().join("\n"),
        _ => "No accounts.".into(),
    }
}

fn devices(app: &App) -> String {
    let rows: Vec<(String, String, i64)> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT user, name, last_seen FROM devices ORDER BY user, last_seen DESC")?;
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(r.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap_or_default();
    if rows.is_empty() {
        return "No trusted devices.".into();
    }
    rows.into_iter().map(|(u, n, t)| format!("  {u:<18} {n:<32} last used {}", ago(t))).collect::<Vec<_>>().join("\n")
}

fn storage(app: &App) -> String {
    let c = crate::storage::cfg(app);
    let sys = crate::storage::probe_system(app);
    let mut out = vec![format!("  {:<20} {:>9} free of {:>9}  {}", "System drive", gb(sys.free), gb(sys.total), if c.system_enabled { "new videos" } else { "no new videos" })];
    for v in &c.volumes {
        let s = crate::storage::probe_volume(app, v);
        out.push(format!(
            "  {:<20} {:>9} free of {:>9}  {}{}",
            v.label,
            gb(s.free),
            gb(s.total),
            if s.online { "connected" } else { "NOT CONNECTED" },
            if v.enabled { "" } else { ", no new videos" }
        ));
    }
    out.join("\n")
}

fn peers(app: &App) -> String {
    let rows: Vec<(String, i64, Option<i64>, Option<String>)> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT name, enabled, last_ok, last_error FROM peers ORDER BY name")?;
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
            Ok(r.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap_or_default();
    if rows.is_empty() {
        return "No other nodes yet.".into();
    }
    rows.into_iter()
        .map(|(n, e, ok, er)| {
            let state = if e == 0 { "paused".to_string() } else { ok.map(|t| format!("last reached {}", ago(t))).unwrap_or_else(|| "never reached".into()) };
            let er = er.filter(|_| e != 0).map(|x| format!("  ({})", x.chars().take(80).collect::<String>())).unwrap_or_default();
            format!("  {n:<24} {state}{er}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn gpu(app: &App) -> String {
    let g = crate::gpu::state();
    if !g.checked {
        return "Still looking for a graphics card.".into();
    }
    let mut out = vec![];
    for c in &g.cards {
        out.push(format!("  found: {} {}", c.name, if c.device.is_empty() { String::new() } else { format!("({})", c.device) }));
    }
    match (&g.active, crate::gpu::enabled(app)) {
        (Some(e), true) => out.push(format!("  conversions run on {} via {:?} (H.264: {}, AV1: {})", e.name, e.api, if e.h264 { "yes" } else { "no" }, if e.av1 { "yes" } else { "no" })),
        (Some(_), false) => out.push("  the graphics card is switched off for conversions (Settings > Node > Playback)".into()),
        (None, _) => out.push("  conversions run on the processor".into()),
    }
    for n in &g.notes {
        out.push(format!("  note: {n}"));
    }
    if g.cards.is_empty() {
        out.insert(0, "  no graphics card found".into());
    }
    out.join("\n")
}

/// One line typed in the console. Returns the text to show, or `None` for "clear the screen".
/// `home`: the owner is on the home network. Installing, restarting and other changes to the computer are
/// only done from there, as in the settings.
pub async fn run(app: &Shared, line: &str, home: bool) -> Result<Option<String>> {
    let mut w = line.split_whitespace();
    let cmd = w.next().unwrap_or("").to_lowercase();
    let arg = w.next().map(|s| s.to_lowercase());
    let changes = cmd == "restart" || (cmd == "update" && arg.is_some());
    if changes && !home {
        return Ok(Some(format!("`{}` only works from your home network.", line.trim())));
    }
    let a = app.clone();
    let text = match cmd.as_str() {
        "" => String::new(),
        "help" | "?" => HELP.into(),
        "clear" | "cls" => return Ok(None),
        "status" => status(app),
        "users" => users(app),
        "devices" => devices(app),
        "storage" | "drives" => tokio::task::spawn_blocking(move || storage(&a)).await?,
        "peers" | "mesh" => peers(app),
        "gpu" => gpu(app),
        "logs" | "log" => {
            let n = arg.and_then(|n| n.parse::<usize>().ok()).unwrap_or(40).clamp(1, LOG_LINES);
            let l = recent_log(n);
            if l.is_empty() { "Nothing logged yet.".into() } else { l.join("\n") }
        }
        "update" => match arg.as_deref() {
            Some("now") | Some("apply") => {
                crate::update::request(app, "apply")?;
                "Installing the newest version. Syphon restarts when it is done; the library stays unlocked.".into()
            }
            Some("check") => {
                crate::update::request(app, "check")?;
                "Looking for a new version. Type `update` in a few seconds to see the result.".into()
            }
            _ => {
                let s = crate::update::status(app);
                let msg = s["message"].as_str().unwrap_or("").to_string();
                format!("This node runs {}. {}\n`update check` looks for a new version, `update now` installs it.", crate::update::version(), msg).trim().to_string()
            }
        },
        "restart" => {
            let a = app.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(400)).await;
                crate::lifecycle::shutdown(&a).await;
                // a non-zero code: systemd starts the node again in both persistence modes
                std::process::exit(75);
            });
            "Restarting. The page reconnects by itself in a few seconds.".into()
        }
        "sudo" | "apt" | "ls" | "cd" | "systemctl" | "journalctl" | "cat" | "df" | "top" | "htop" | "nano" | "bash" | "sh" => {
            format!("`{cmd}` is a command for the computer itself. Open the computer's terminal below the console for that.")
        }
        other => format!("Unknown command `{other}`. Type `help` for the list."),
    };
    Ok(Some(text))
}

// ------------------------------------------------------------------ the computer's terminal

struct Shell {
    /// the web session that opened it: nobody else can use it
    session: String,
    writer: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    reader: Option<tokio::net::unix::OwnedReadHalf>,
    last: Instant,
}

static SHELLS: Mutex<Option<HashMap<String, Shell>>> = Mutex::new(None);
static FAILS: Mutex<(u32, i64)> = Mutex::new((0, 0));
const IDLE: Duration = Duration::from_secs(30 * 60);

fn with_shells<T>(f: impl FnOnce(&mut HashMap<String, Shell>) -> T) -> T {
    let mut g = SHELLS.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    m.retain(|_, s| s.last.elapsed() < IDLE);
    f(m)
}

/// Whether the terminal relay is switched on (its socket exists).
pub fn available() -> bool {
    std::path::Path::new(SOCKET).exists()
}

/// Too many wrong passwords or codes: wait.
fn check_fails() -> Result<()> {
    let f = FAILS.lock().unwrap();
    if f.0 >= 5 && crate::util::now() - f.1 < 900 {
        bail!("Too many wrong tries. Wait 15 minutes, then try again.");
    }
    Ok(())
}

fn record(ok: bool) {
    let mut f = FAILS.lock().unwrap();
    if ok {
        *f = (0, 0);
    } else {
        *f = (f.0 + 1, crate::util::now());
    }
}

/// Open the computer's terminal for this web session, after the password and an authenticator code.
pub async fn open(app: &Shared, session: &str, user: &str, password: &str, code: &str) -> Result<String> {
    check_fails()?;
    let row: Option<(Option<String>, i64, i64)> = app.db.with(|c| {
        use rusqlite::OptionalExtension;
        Ok(c.query_row("SELECT totp_secret, totp_enabled, totp_last FROM users WHERE name=?1", [user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?)
    })?;
    let Some((secret, enabled, last)) = row else { bail!("no such account") };
    if enabled == 0 || secret.is_none() {
        bail!("The terminal needs the authenticator app. Set it up first: Settings > Account > Two-step sign-in.");
    }
    let a = app.clone();
    let pw = password.to_string();
    let pw_ok = tokio::task::spawn_blocking(move || a.keyring.verify_password(&pw)).await.unwrap_or(false);
    let step = crate::totp::verify(secret.as_deref().unwrap_or(""), code.trim(), crate::util::now(), last as u64);
    if !pw_ok || step.is_none() {
        record(false);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        bail!("The password or the code is not right.");
    }
    record(true);
    // a code works once
    let step = step.unwrap() as i64;
    let _ = app.db.with(|c| {
        c.execute("UPDATE users SET totp_last=?2 WHERE name=?1", rusqlite::params![user, step])?;
        Ok(())
    });
    if !available() {
        bail!("The computer's terminal is switched off. Switch it on first (the button above), then try again.");
    }
    let stream = tokio::net::UnixStream::connect(SOCKET).await.map_err(|e| anyhow!("Could not reach the terminal ({e}). Switch it off and on again."))?;
    let (r, w) = stream.into_split();
    let id = crate::util::random_hex(16);
    tracing::warn!("{user} opened the computer's terminal from the web app");
    with_shells(|m| {
        // one terminal per web session
        m.retain(|_, s| s.session != session);
        m.insert(id.clone(), Shell { session: session.to_string(), writer: Arc::new(tokio::sync::Mutex::new(w)), reader: Some(r), last: Instant::now() });
    });
    Ok(id)
}

fn owned(id: &str, session: &str) -> Result<()> {
    with_shells(|m| match m.get_mut(id) {
        Some(s) if s.session == session => {
            s.last = Instant::now();
            Ok(())
        }
        _ => Err(anyhow!("This terminal has ended. Open it again.")),
    })
}

/// Keys typed, or a new window size.
pub async fn input(id: &str, session: &str, data: Option<&str>, size: Option<(u16, u16)>) -> Result<()> {
    owned(id, session)?;
    let w = with_shells(|m| m.get(id).map(|s| s.writer.clone())).ok_or_else(|| anyhow!("This terminal has ended."))?;
    let mut w = w.lock().await;
    use tokio::io::AsyncWriteExt;
    if let Some((rows, cols)) = size {
        let mut p = rows.to_be_bytes().to_vec();
        p.extend_from_slice(&cols.to_be_bytes());
        w.write_all(&frame(FRAME_RESIZE, &p)).await?;
    }
    if let Some(d) = data {
        for part in d.as_bytes().chunks(16 * 1024) {
            w.write_all(&frame(FRAME_DATA, part)).await?;
        }
    }
    Ok(())
}

/// The terminal's output as a stream of bytes (raw terminal text). Can be taken once per terminal.
pub fn output(id: &str, session: &str) -> Result<impl futures_util::Stream<Item = std::io::Result<bytes::Bytes>>> {
    owned(id, session)?;
    let r = with_shells(|m| m.get_mut(id).and_then(|s| s.reader.take())).ok_or_else(|| anyhow!("This terminal is already open in another tab."))?;
    let id = id.to_string();
    Ok(futures_util::stream::unfold((r, Vec::<u8>::new(), false, id), |(mut r, mut buf, done, id)| async move {
        use tokio::io::AsyncReadExt;
        if done {
            return None;
        }
        let mut tmp = vec![0u8; 32 * 1024];
        loop {
            let n = match r.read(&mut tmp).await {
                Ok(0) | Err(_) => {
                    with_shells(|m| m.remove(&id));
                    return None;
                }
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            let mut out = vec![];
            let mut ended = false;
            for (k, p) in take_frames(&mut buf) {
                match k {
                    FRAME_DATA => out.extend_from_slice(&p),
                    FRAME_EXIT => ended = true,
                    _ => {}
                }
            }
            with_shells(|m| {
                if let Some(s) = m.get_mut(&id) {
                    s.last = Instant::now();
                }
            });
            if ended {
                with_shells(|m| m.remove(&id));
            }
            if !out.is_empty() || ended {
                return Some((Ok(bytes::Bytes::from(out)), (r, buf, ended, id)));
            }
        }
    }))
}

pub fn close(id: &str, session: &str) {
    with_shells(|m| {
        if m.get(id).map(|s| s.session == session).unwrap_or(false) {
            m.remove(id);
        }
    });
}

/// The terminal was switched off: everything open ends.
pub fn close_all() {
    with_shells(|m| m.clear());
}

/// Everything a web session had open ends when it signs out.
pub fn close_session(session: &str) {
    with_shells(|m| m.retain(|_, s| s.session != session));
}
