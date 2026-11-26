//! Tor integration.
//!
//! Each node runs one managed `tor` process with two v3 onion services:
//!   * **mesh**   – peer-to-peer only. Client authorization lets only the nodes you paired with
//!                  even fetch its descriptor, so strangers cannot find or probe it.
//!   * **access** – the UI/API for you and your devices, authorized per device.
//! Outbound peer traffic goes through tor's SOCKS port (socks5h, so .onion names resolve in tor).

use crate::config::{Config, Dirs};
use crate::state::{App, Shared};
use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE32_NOPAD;
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn b32(bytes: &[u8]) -> String {
    BASE32_NOPAD.encode(bytes)
}

/// The x25519 key this node presents to its peers' mesh onion services.
pub struct ClientKey {
    secret: StaticSecret,
}

impl ClientKey {
    pub fn load_or_create(path: &Path) -> Result<ClientKey> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let secret = if path.exists() {
            let raw = std::fs::read(path)?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| anyhow!("client_auth.key must be 32 bytes"))?;
            StaticSecret::from(arr)
        } else {
            let s = StaticSecret::random_from_rng(OsRng);
            std::fs::write(path, s.to_bytes())?;
            restrict_file(path);
            s
        };
        Ok(ClientKey { secret })
    }
    pub fn pub_b32(&self) -> String {
        b32(PublicKey::from(&self.secret).as_bytes())
    }
    pub fn priv_b32(&self) -> String {
        b32(&self.secret.to_bytes())
    }
}

fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let _ = path;
}

fn restrict_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub struct TorPaths {
    pub root: PathBuf,
}

impl TorPaths {
    pub fn new(dirs: &Dirs) -> Self {
        TorPaths { root: dirs.tor() }
    }
    pub fn data(&self) -> PathBuf { self.root.join("data") }
    pub fn hs_access(&self) -> PathBuf { self.root.join("hs_access") }
    pub fn hs_mesh(&self) -> PathBuf { self.root.join("hs_mesh") }
    pub fn client_auth(&self) -> PathBuf { self.root.join("client_auth") }
    pub fn torrc(&self) -> PathBuf { self.root.join("torrc") }
    pub fn pid(&self) -> PathBuf { self.root.join("tor.pid") }
}

fn port_of(bind: &str) -> u16 {
    bind.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(8098)
}

/// Validate one bridge line (as handed out by bridges.torproject.org) before it goes into torrc.
/// Returns it without a leading "Bridge ". A line is one line of printable text: anything else
/// could smuggle extra options into the Tor configuration.
pub fn clean_bridge_line(raw: &str) -> Result<String> {
    let l = raw.trim();
    let l = l.strip_prefix("Bridge ").or_else(|| l.strip_prefix("bridge ")).unwrap_or(l).trim();
    if l.is_empty() || l.len() > 1200 {
        bail!("that bridge line is empty or too long");
    }
    if !l.chars().all(|c| (' '..='~').contains(&c)) {
        bail!("a bridge line is one line of plain text");
    }
    let mut it = l.split_whitespace();
    let first = it.next().unwrap_or("");
    // either "TRANSPORT ADDR:PORT ..." or "ADDR:PORT [FINGERPRINT]"
    let (transport, addr) = if first.contains(':') || first.contains('.') || first.starts_with('[') {
        (None, first)
    } else {
        if !first.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            bail!("unrecognised bridge transport \"{first}\"");
        }
        (Some(first), it.next().unwrap_or(""))
    };
    if !addr.contains(':') && transport != Some("snowflake") && transport != Some("webtunnel") {
        bail!("a bridge line needs an address like 192.0.2.1:443");
    }
    let _ = transport;
    Ok(l.to_string())
}

/// The program Tor must run for a bridge transport.
fn transport_binary(t: &str) -> Option<&'static str> {
    match t {
        "obfs4" | "meek_lite" | "scramblesuit" | "obfs3" => Some("obfs4proxy"),
        "snowflake" => Some("snowflake-client"),
        "webtunnel" => Some("webtunnel-client"),
        _ => None,
    }
}

fn find_binary(name: &str) -> Option<String> {
    for d in ["/usr/bin", "/usr/local/bin", "/usr/sbin", "/usr/lib/obfs4proxy", "/usr/lib/snowflake"] {
        let p = format!("{d}/{name}");
        if std::path::Path::new(&p).is_file() {
            return Some(p);
        }
    }
    None
}

/// Transports used by the configured bridges, and which of their programs are missing.
pub fn bridge_transports(cfg: &Config) -> (Vec<String>, Vec<String>) {
    let mut used: Vec<String> = vec![];
    for l in &cfg.tor.bridges {
        if let Some(first) = l.split_whitespace().next() {
            if !first.contains(':') && !first.contains('.') && !used.iter().any(|u| u == first) {
                used.push(first.to_string());
            }
        }
    }
    let missing = used.iter().filter(|t| transport_binary(t).map(|b| find_binary(b).is_none()).unwrap_or(true)).cloned().collect();
    (used, missing)
}

fn torrc_bridges(cfg: &Config) -> String {
    if cfg.tor.bridges.is_empty() {
        return String::new();
    }
    let (used, _) = bridge_transports(cfg);
    let mut t = String::from("\n# bridges: for networks that block Tor, or to hide Tor use from the ISP\nUseBridges 1\n");
    // one plugin line per program, listing every transport it provides
    let mut by_bin: Vec<(&str, Vec<&str>)> = vec![];
    for tr in &used {
        if let Some(b) = transport_binary(tr) {
            match by_bin.iter_mut().find(|(x, _)| *x == b) {
                Some(e) => e.1.push(tr),
                None => by_bin.push((b, vec![tr])),
            }
        }
    }
    for (bin, trs) in by_bin {
        let path = find_binary(bin).unwrap_or_else(|| format!("/usr/bin/{bin}"));
        t.push_str(&format!("ClientTransportPlugin {} exec {}\n", trs.join(","), path));
    }
    for l in &cfg.tor.bridges {
        t.push_str(&format!("Bridge {l}\n"));
    }
    t
}

pub fn torrc_text(cfg: &Config, p: &TorPaths) -> String {
    let mut t = torrc_base(cfg, p);
    t.push_str(&torrc_bridges(cfg));
    if cfg.tor.system_wide {
        // transparent proxy for the whole computer; the firewall rules (syphon torify-rules)
        // send everything here and block whatever Tor cannot carry
        t.push_str(&format!(
            "\n# system-wide mode\nTransPort 127.0.0.1:{} IsolateClientAddr\nDNSPort 127.0.0.1:{}\nAutomapHostsOnResolve 1\nVirtualAddrNetworkIPv4 10.192.0.0/10\n",
            cfg.tor.trans_port, cfg.tor.dns_port
        ));
    }
    t
}

fn torrc_base(cfg: &Config, p: &TorPaths) -> String {
    let access = format!(
        "# access: UI/API for you and your devices\nHiddenServiceDir {}\nHiddenServiceVersion 3\nHiddenServicePort 80 127.0.0.1:{}\n",
        p.hs_access().display(),
        cfg.tor_access_port
    );
    format!(
        "DataDirectory {data}\n\
         PidFile {pid}\n\
         SocksPort 127.0.0.1:{socks}{socks_flags}\n\
         ClientOnionAuthDir {cauth}\n\
         Log notice stdout\n\
         \n\
         {access}\n\
         # mesh: peer-to-peer sync, authorised nodes only\n\
         HiddenServiceDir {hs_mesh}\n\
         HiddenServiceVersion 3\n\
         HiddenServicePort 80 127.0.0.1:{mesh_port}\n",
        data = p.data().display(),
        pid = p.pid().display(),
        socks = cfg.tor.socks_port,
        socks_flags = if supports_extended_errors(&cfg.tor.binary) { " ExtendedErrors" } else { "" },
        cauth = p.client_auth().display(),
        access = access,
        hs_mesh = p.hs_mesh().display(),
        mesh_port = port_of(&cfg.mesh_bind),
    )
}

pub fn prepare(app: &App) -> Result<PathBuf> {
    let p = TorPaths::new(&app.dirs);
    restrict_dir(&p.root)?;
    restrict_dir(&p.data())?;
    restrict_dir(&p.hs_access())?;
    restrict_dir(&p.hs_mesh())?;
    restrict_dir(&p.hs_access().join("authorized_clients"))?;
    restrict_dir(&p.hs_mesh().join("authorized_clients"))?;
    restrict_dir(&p.client_auth())?;
    crate::util::write_atomic(&p.torrc(), torrc_text(&app.cfg, &p).as_bytes())?;
    Ok(p.torrc())
}

pub fn onion_of(hs_dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(hs_dir.join("hostname")).ok()?;
    let s = s.trim();
    if s.ends_with(".onion") { Some(s.to_string()) } else { None }
}

/// Let a paired peer's client key reach our mesh onion service.
pub fn authorize_mesh_peer(app: &App, name: &str, peer_client_pub_b32: &str) -> Result<()> {
    validate_b32_key(peer_client_pub_b32)?;
    let p = TorPaths::new(&app.dirs);
    let dir = p.hs_mesh().join("authorized_clients");
    restrict_dir(&dir)?;
    std::fs::write(
        dir.join(format!("{}.auth", crate::util::sanitize_name(name))),
        format!("descriptor:x25519:{peer_client_pub_b32}\n"),
    )?;
    Ok(())
}

pub fn revoke_mesh_peer(app: &App, name: &str) {
    let p = TorPaths::new(&app.dirs);
    let n = crate::util::sanitize_name(name);
    let _ = std::fs::remove_file(p.hs_mesh().join("authorized_clients").join(format!("{n}.auth")));
    let _ = std::fs::remove_file(p.client_auth().join(format!("{n}.auth_private")));
}

/// Give our tor the key it needs to reach a peer's (authorised) mesh onion service.
pub fn install_peer_auth(app: &App, name: &str, peer_onion: &str) -> Result<()> {
    install_peer_auth_with(app, name, peer_onion, &app.client_key.priv_b32())
}

/// Same, with an explicit private key (used with the throwaway key carried in an invite).
pub fn install_peer_auth_with(app: &App, name: &str, peer_onion: &str, priv_b32: &str) -> Result<()> {
    validate_b32_key(priv_b32)?;
    let p = TorPaths::new(&app.dirs);
    let host = peer_onion.trim().trim_end_matches(".onion");
    if host.len() != 56 {
        bail!("not a v3 onion address");
    }
    let dir = p.client_auth();
    restrict_dir(&dir)?;
    let f = dir.join(format!("{}.auth_private", crate::util::sanitize_name(name)));
    std::fs::write(&f, format!("{host}:descriptor:x25519:{priv_b32}\n"))?;
    restrict_file(&f);
    Ok(())
}

/// A one-off keypair for an invite: (public, private) in tor's base32 form.
pub fn throwaway_keypair() -> (String, String) {
    let s = StaticSecret::random_from_rng(OsRng);
    (b32(PublicKey::from(&s).as_bytes()), b32(&s.to_bytes()))
}

fn validate_b32_key(k: &str) -> Result<()> {
    let raw = BASE32_NOPAD.decode(k.trim().as_bytes()).map_err(|_| anyhow!("client key is not valid base32"))?;
    if raw.len() != 32 {
        bail!("client key must be 32 bytes");
    }
    Ok(())
}

/// Authorise a new device on the access onion service. Returns the line the device must import
/// (Tor Browser: Settings > Connection > Onion Services Authentication).
pub fn add_access_device(app: &App, name: &str) -> Result<String> {
    let p = TorPaths::new(&app.dirs);
    let onion = onion_of(&p.hs_access()).ok_or_else(|| anyhow!("start the node once so tor can create the access onion address first"))?;
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let dir = p.hs_access().join("authorized_clients");
    restrict_dir(&dir)?;
    std::fs::write(
        dir.join(format!("{}.auth", crate::util::sanitize_name(name))),
        format!("descriptor:x25519:{}\n", b32(public.as_bytes())),
    )?;
    reload(app);
    Ok(format!("{}:descriptor:x25519:{}", onion.trim_end_matches(".onion"), b32(&secret.to_bytes())))
}

/// The devices that hold a key for the outside address (name, when the key was made). With none, the extra lock is off.
pub fn list_access_devices(app: &App) -> Vec<(String, i64)> {
    let p = TorPaths::new(&app.dirs);
    let mut v: Vec<(String, i64)> = std::fs::read_dir(p.hs_access().join("authorized_clients"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            let stem = n.strip_suffix(".auth")?.to_string();
            let t = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            Some((stem, t))
        })
        .collect();
    v.sort();
    v
}

/// Turn the extra lock off: remove every device key, so the outside address answers anyone who has it.
pub fn remove_all_access_devices(app: &App) -> usize {
    let names = list_access_devices(app);
    let p = TorPaths::new(&app.dirs);
    for (n, _) in &names {
        let _ = std::fs::remove_file(p.hs_access().join("authorized_clients").join(format!("{n}.auth")));
    }
    reload(app);
    names.len()
}

pub fn remove_access_device(app: &App, name: &str) {
    let p = TorPaths::new(&app.dirs);
    let _ = std::fs::remove_file(
        p.hs_access().join("authorized_clients").join(format!("{}.auth", crate::util::sanitize_name(name))),
    );
    reload(app);
}

/// Ask a running tor to re-read its authorized_clients directories (SIGHUP).
pub fn reload(app: &App) {
    let p = TorPaths::new(&app.dirs);
    if let Ok(pid) = std::fs::read_to_string(p.pid()) {
        let pid = pid.trim();
        if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
            let _ = std::process::Command::new("kill").args(["-HUP", pid]).status();
        }
    }
}

/// Ask the managed tor to exit cleanly (it closes its circuits and onion services), and wait briefly.
pub fn stop(app: &App) {
    let p = TorPaths::new(&app.dirs);
    let Ok(pid) = std::fs::read_to_string(p.pid()) else { return };
    let pid = pid.trim().to_string();
    if pid.is_empty() || !pid.chars().all(|c| c.is_ascii_digit()) {
        return;
    }
    let _ = std::process::Command::new("kill").args(["-TERM", &pid]).status();
    for _ in 0..40 {
        if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let _ = std::process::Command::new("kill").args(["-KILL", &pid]).status();
}

pub fn socks_url(cfg: &Config) -> String {
    format!("socks5h://127.0.0.1:{}", cfg.tor.socks_port)
}

// ------------------------------------------------------------------ keeping Tor alive and findable

/// Tor may spend this long connecting before Syphon restarts it (a bad moment on the network usually passes by itself).
const STUCK_AFTER: Duration = Duration::from_secs(600);
/// After a start, an onion address takes a few minutes to appear on the network: do not judge it before this.
const SETTLE: Duration = Duration::from_secs(900);
/// How often the node checks that its own address can be found.
const CHECK_EVERY: Duration = Duration::from_secs(300);
/// Faster checks while something looks wrong (or the computer has just woken up).
const CHECK_FAST: Duration = Duration::from_secs(60);
/// Not found this many checks in a row: restart Tor.
const STRIKES: u32 = 3;

/// Whether the installed Tor can report why a connection failed (0.4.3 and newer). Without it the address check is skipped.
pub fn supports_extended_errors(binary: &str) -> bool {
    static CACHE: std::sync::Mutex<Option<(String, bool)>> = std::sync::Mutex::new(None);
    let mut c = CACHE.lock().unwrap();
    if let Some((b, v)) = c.as_ref() {
        if b == binary {
            return *v;
        }
    }
    let v = std::process::Command::new(binary)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| parse_tor_version(&String::from_utf8_lossy(&o.stdout)))
        .map(|v| v >= (0, 4, 3))
        .unwrap_or(false);
    *c = Some((binary.to_string(), v));
    v
}

/// "Tor version 0.4.9.11." -> (0, 4, 9)
pub fn parse_tor_version(text: &str) -> Option<(u32, u32, u32)> {
    let rest = text.split("Tor version ").nth(1)?;
    let mut n = rest.split(|c: char| !c.is_ascii_digit() && c != '.').next()?.split('.').filter_map(|x| x.parse::<u32>().ok());
    Some((n.next()?, n.next()?, n.next()?))
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Listing {
    /// the Tor network can find the address (Tor even says it needs a key to go further)
    Listed,
    /// the Tor network has no listing for it
    NotListed,
    /// could not tell (no answer, an unusual error): never a reason to act
    Unknown,
}

/// What Tor's SOCKS port says after a connection attempt at our own address.
pub fn classify_reply(code: u8) -> Listing {
    match code {
        0x00 | 0xF4 | 0xF5 => Listing::Listed, // connected, or "this service needs a key": the listing was found
        0xF0 => Listing::NotListed,           // descriptor not found
        _ => Listing::Unknown,
    }
}

/// Ask our own Tor to open a connection to our own mesh address. We hold no key for it, so Tor stops as soon as it has
/// looked the address up: "needs a key" means it is listed, "not found" means it is not. Nothing is sent to the service.
pub async fn probe_listing(socks_port: u16, onion: &str) -> Listing {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let host = onion.trim();
    if host.len() > 255 || !host.ends_with(".onion") {
        return Listing::Unknown;
    }
    let run = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", socks_port)).await.ok()?;
        s.write_all(&[5, 1, 0]).await.ok()?;
        let mut m = [0u8; 2];
        s.read_exact(&mut m).await.ok()?;
        if m != [5, 0] {
            return None;
        }
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend(host.as_bytes());
        req.extend(80u16.to_be_bytes());
        s.write_all(&req).await.ok()?;
        let mut r = [0u8; 4];
        s.read_exact(&mut r).await.ok()?;
        Some(r[1])
    };
    match tokio::time::timeout(Duration::from_secs(150), run).await {
        Ok(Some(code)) => classify_reply(code),
        _ => Listing::Unknown,
    }
}

/// How long to wait before starting Tor again after the n-th restart in a row.
pub fn backoff(n: u32) -> Duration {
    Duration::from_secs([2, 5, 15, 30, 60, 120, 300][(n as usize).min(6)])
}

fn spawn_tor(app: &Shared, torrc: &Path) -> Result<tokio::process::Child> {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut child = tokio::process::Command::new(&app.cfg.tor.binary)
        .arg("-f")
        .arg(torrc)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting `{}` (is tor installed?)", app.cfg.tor.binary))?;
    {
        let mut t = app.tor.lock().unwrap();
        t.enabled = true;
        t.bootstrap = 0;
        t.error = None;
        t.listed = None;
    }
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no tor stdout"))?;
    let a = app.clone();
    tokio::spawn(async move {
        let re = regex::Regex::new(r"Bootstrapped (\d+)%").unwrap();
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(c) = re.captures(&line) {
                a.tor.lock().unwrap().bootstrap = c[1].parse().unwrap_or(0);
            }
            if line.contains("[err]") || line.contains("[warn]") && line.contains("Could not") {
                a.tor.lock().unwrap().error = Some(line.clone());
            }
            tracing::debug!(target: "tor", "{line}");
        }
    });
    Ok(child)
}

/// Stop a Tor we started: politely first, then for good.
async fn stop_child(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        let _ = tokio::process::Command::new("kill").args(["-TERM", &pid.to_string()]).status().await;
    }
    if tokio::time::timeout(Duration::from_secs(10), child.wait()).await.is_err() {
        let _ = child.kill().await;
    }
}

/// Start the managed tor process and keep the status (bootstrap %, onion addresses) up to date.
/// From here on Tor is supervised: if it exits, gets stuck connecting, or the node's address can no longer be found on the
/// Tor network, it is restarted by itself (same address: the keys stay where they are).
pub async fn start(app: &Shared) -> Result<()> {
    if app.cfg.transport != "tor" {
        return Ok(());
    }
    let torrc = prepare(app)?;
    let child = spawn_tor(app, &torrc)?;

    let a = app.clone();
    tokio::spawn(async move {
        let p = TorPaths::new(&a.dirs);
        for _ in 0..240 {
            let acc = onion_of(&p.hs_access());
            let mesh = onion_of(&p.hs_mesh());
            if acc.is_some() && mesh.is_some() {
                *a.mesh_addr.lock().unwrap() = mesh.clone().unwrap();
                let mut t = a.tor.lock().unwrap();
                t.access_onion = acc;
                t.mesh_onion = mesh;
                return;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        a.tor.lock().unwrap().error = Some("tor did not create its onion services in time".into());
    });

    tokio::spawn(supervise(app.clone(), child));
    Ok(())
}

/// Restart Tor now (the Settings button). Same address, new connections.
pub fn restart_now(app: &App) {
    app.tor_restart.notify_one();
}

fn record_restart(app: &App, why: &str) {
    let mut t = app.tor.lock().unwrap();
    t.restarts += 1;
    t.last_restart = Some(crate::util::now());
    t.last_restart_reason = Some(why.to_string());
    t.bootstrap = 0;
    t.listed = None;
    tracing::warn!("tor: restarting ({why})");
}

async fn supervise(app: Shared, first: tokio::process::Child) {
    let mut child = Some(first);
    let mut started = Instant::now();
    let mut failures = 0u32;
    loop {
        // run until something says Tor needs to start again
        let mut manual = false;
        let reason = match child.as_mut() {
            Some(c) => tokio::select! {
                st = c.wait() => format!("Tor stopped by itself ({})", st.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string())),
                r = watchdog(&app, started) => r,
                _ = app.tor_restart.notified() => { manual = true; "restarted from Settings".to_string() },
                _ = app.shutdown.notified() => return,
            },
            None => "Tor could not be started".to_string(),
        };
        if app.is_shutting_down() {
            return;
        }
        if let Some(mut c) = child.take() {
            stop_child(&mut c).await;
        }
        if app.is_shutting_down() {
            return;
        }
        if started.elapsed() > Duration::from_secs(900) {
            failures = 0; // it had been well for a good while
        }
        record_restart(&app, &reason);
        let wait = if manual { Duration::from_secs(1) } else { backoff(failures) };
        if !manual {
            failures += 1;
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = app.tor_restart.notified() => {}
            _ = app.shutdown.notified() => return,
        }
        if app.is_shutting_down() {
            return;
        }
        // read the settings again: bridges may have changed
        match prepare(&app).and_then(|t| spawn_tor(&app, &t)) {
            Ok(c) => {
                child = Some(c);
                started = Instant::now();
            }
            Err(e) => {
                app.tor.lock().unwrap().error = Some(format!("could not start tor: {e}"));
            }
        }
    }
}

/// Watches a running Tor. Returns why it should be restarted; never returns while all is well.
async fn watchdog(app: &Shared, started: Instant) -> String {
    let mut strikes = 0u32;
    let mut next_check = Instant::now() + SETTLE;
    loop {
        tokio::time::sleep(Duration::from_secs(20)).await;
        if app.is_shutting_down() {
            std::future::pending::<()>().await;
        }
        let (boot, onion) = {
            let t = app.tor.lock().unwrap();
            (t.bootstrap, t.mesh_onion.clone())
        };
        if boot < 100 {
            if started.elapsed() > STUCK_AFTER {
                return format!("Tor could not connect in {} minutes", STUCK_AFTER.as_secs() / 60);
            }
            continue;
        }
        if Instant::now() < next_check || started.elapsed() < SETTLE || !supports_extended_errors(&app.cfg.tor.binary) {
            continue;
        }
        let Some(onion) = onion else { continue };
        let r = probe_listing(app.cfg.tor.socks_port, &onion).await;
        {
            let mut t = app.tor.lock().unwrap();
            match r {
                Listing::Listed => t.listed = Some(true),
                Listing::NotListed => t.listed = Some(false),
                Listing::Unknown => {}
            }
            t.checked = Some(crate::util::now());
        }
        match r {
            Listing::NotListed => {
                strikes += 1;
                if strikes >= STRIKES {
                    return format!("the Tor network could not find this node's address in {strikes} checks in a row");
                }
            }
            Listing::Listed => strikes = 0,
            Listing::Unknown => {}
        }
        next_check = Instant::now() + if strikes > 0 { CHECK_FAST } else { CHECK_EVERY };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tor_versions_and_the_error_codes_that_say_whether_the_address_is_listed() {
        assert_eq!(parse_tor_version("Tor version 0.4.9.11.\n"), Some((0, 4, 9)));
        assert_eq!(parse_tor_version("Tor version 0.4.7.16 (git-abc)."), Some((0, 4, 7)));
        assert_eq!(parse_tor_version("nonsense"), None);
        assert!((0, 4, 9) >= (0, 4, 3) && (0, 3, 5) < (0, 4, 3));
        assert_eq!(classify_reply(0xF4), Listing::Listed, "needs a key: the listing exists");
        assert_eq!(classify_reply(0xF5), Listing::Listed);
        assert_eq!(classify_reply(0x00), Listing::Listed);
        assert_eq!(classify_reply(0xF0), Listing::NotListed);
        for other in [0x01u8, 0x04, 0xF1, 0xF2, 0xF3, 0xF7] {
            assert_eq!(classify_reply(other), Listing::Unknown, "{other:#x} is never a reason to restart");
        }
    }

    #[test]
    fn restarts_back_off_but_never_wait_long() {
        assert_eq!(backoff(0), Duration::from_secs(2));
        assert!(backoff(3) > backoff(1));
        assert_eq!(backoff(50), Duration::from_secs(300));
    }

    /// A stand-in for Tor's SOCKS port that answers like Tor does after looking an address up.
    async fn fake_socks(reply: Option<u8>) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut g = [0u8; 3];
                    if s.read_exact(&mut g).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[5, 0]).await;
                    let mut head = [0u8; 5];
                    if s.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    let mut rest = vec![0u8; head[4] as usize + 2];
                    let _ = s.read_exact(&mut rest).await;
                    match reply {
                        Some(code) => {
                            let _ = s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                        }
                        None => {} // hang up without an answer
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn probing_our_own_address_reads_tors_answer() {
        let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";
        assert_eq!(probe_listing(fake_socks(Some(0xF4)).await, onion).await, Listing::Listed);
        assert_eq!(probe_listing(fake_socks(Some(0xF0)).await, onion).await, Listing::NotListed);
        assert_eq!(probe_listing(fake_socks(Some(0x04)).await, onion).await, Listing::Unknown);
        assert_eq!(probe_listing(fake_socks(None).await, onion).await, Listing::Unknown, "no answer is not a verdict");
        // nothing listening at all
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        assert_eq!(probe_listing(closed, onion).await, Listing::Unknown);
        assert_eq!(probe_listing(closed, "example.com").await, Listing::Unknown, "only onion names are probed");
    }

    #[test]
    fn client_key_formats_for_tor() {
        let d = tempfile::tempdir().unwrap();
        let k = ClientKey::load_or_create(&d.path().join("k")).unwrap();
        assert_eq!(k.pub_b32().len(), 52); // 32 bytes -> 52 base32 chars, no padding
        assert_eq!(k.priv_b32().len(), 52);
        assert!(k.pub_b32().chars().all(|c| c.is_ascii_uppercase() || ('2'..='7').contains(&c)));
        let again = ClientKey::load_or_create(&d.path().join("k")).unwrap();
        assert_eq!(again.pub_b32(), k.pub_b32());
        assert!(validate_b32_key(&k.pub_b32()).is_ok());
        assert!(validate_b32_key("nope").is_err());
    }

    #[test]
    fn torrc_has_two_separate_onion_services() {
        let cfg = Config::default();
        let d = tempfile::tempdir().unwrap();
        let p = TorPaths::new(&Dirs::new(d.path()));
        let t = torrc_text(&cfg, &p);
        assert_eq!(t.matches("HiddenServiceDir").count(), 2);
        assert!(t.contains("HiddenServicePort 80 127.0.0.1:8097"));
        assert!(t.contains("HiddenServicePort 80 127.0.0.1:8098"));
        assert!(t.contains("ClientOnionAuthDir"));
        assert!(t.contains("SocksPort 127.0.0.1:9250"));
        assert_eq!(t.contains("ExtendedErrors"), supports_extended_errors(&cfg.tor.binary), "the flag is only asked for when this Tor knows it");
        assert!(!t.contains("TransPort"), "system-wide mode is off by default");
        let mut on = cfg.clone();
        on.tor.system_wide = true;
        let t = torrc_text(&on, &p);
        assert!(t.contains("TransPort 127.0.0.1:9251"));
        assert!(t.contains("DNSPort 127.0.0.1:9253"));
    }

    #[test]
    fn bridges_are_validated_and_written_to_torrc() {
        let fp = "0123456789ABCDEF0123456789ABCDEF01234567";
        let obfs = format!("obfs4 192.0.2.5:443 {fp} cert=AAAA iat-mode=0");
        assert_eq!(clean_bridge_line(&format!("Bridge {obfs}")).unwrap(), obfs);
        assert!(clean_bridge_line("192.0.2.9:9001").is_ok(), "a plain bridge without a transport");
        assert!(clean_bridge_line("obfs4 192.0.2.5:443\nSocksPort 0.0.0.0:9050").is_err(), "no extra torrc options");
        assert!(clean_bridge_line("").is_err());
        assert!(clean_bridge_line("ob;fs4 192.0.2.5:443").is_err());
        let mut cfg = Config::default();
        let d = tempfile::tempdir().unwrap();
        let p = TorPaths::new(&Dirs::new(d.path()));
        assert!(!torrc_text(&cfg, &p).contains("UseBridges"));
        cfg.tor.bridges = vec![obfs.clone(), "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72".into()];
        let t = torrc_text(&cfg, &p);
        assert!(t.contains("UseBridges 1"));
        assert!(t.contains(&format!("Bridge {obfs}")));
        assert!(t.contains("ClientTransportPlugin obfs4 exec "));
        assert!(t.contains("ClientTransportPlugin snowflake exec "));
        assert_eq!(bridge_transports(&cfg).0, vec!["obfs4", "snowflake"]);
    }
}
