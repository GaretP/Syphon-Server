use crate::config::{Config, Dirs, SyncPolicy};
use crate::db::Db;
use crate::tor::ClientKey;
use crate::util::{now, random_hex};
use crate::keyring::{KdfParams, Keyring};
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore};

pub type Shared = Arc<App>;

/// The node's signing identity. It authenticates this node to its peers (heartbeats, catalog
/// entries). It lives outside the keyring so a headless node can keep syncing while locked.
pub struct Identity {
    sk: SigningKey,
    pub id: String,
}

impl Identity {
    pub fn load_or_create(path: &std::path::Path) -> Result<Identity> {
        let sk = if path.exists() {
            let raw = std::fs::read(path)?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| anyhow!("identity.key must be 32 bytes"))?;
            SigningKey::from_bytes(&arr)
        } else {
            let sk = SigningKey::generate(&mut OsRng);
            crate::util::write_atomic(path, &sk.to_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            sk
        };
        let id = hex::encode(sk.verifying_key().to_bytes());
        Ok(Identity { sk, id })
    }

    pub fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.sk.sign(msg).to_bytes())
    }
}

pub fn verify_sig(pub_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pb) = hex::decode(pub_hex) else { return false };
    let Ok(pa) = <[u8; 32]>::try_from(pb.as_slice()) else { return false };
    let Ok(sb) = hex::decode(sig_hex) else { return false };
    let Ok(sa) = <[u8; 64]>::try_from(sb.as_slice()) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pa) else { return false };
    vk.verify(msg, &Signature::from_bytes(&sa)).is_ok()
}

#[derive(Clone, Debug)]
pub struct Session {
    pub user: String,
    pub role: String,
    pub zone: crate::security::Zone,
    pub expires: i64,
}

/// What this node last saw/did for a peer. Drives the live "heartbeat → need sync → request → answer" view.
#[derive(Default, Clone, Serialize, Debug)]
pub struct PeerLive {
    pub stage: String,
    pub detail: String,
    pub updated: i64,
    pub online: bool,
    pub their_enabled: Option<bool>,
    pub their_mode: Option<String>,
    /// the peer sleeps when idle: do not wake it for routine heartbeats before this time
    pub asleep_until: i64,
    pub need: usize,
}

#[derive(Clone, Serialize, Debug)]
pub struct Transfer {
    pub item: String,
    pub title: String,
    pub peer: String,
    pub chunks_done: u64,
    pub chunks_total: u64,
    pub state: String,
}

#[derive(Default, Clone, Serialize, Debug)]
pub struct TorStatus {
    pub enabled: bool,
    pub bootstrap: u8,
    pub access_onion: Option<String>,
    pub mesh_onion: Option<String>,
    pub error: Option<String>,
    /// how many times Syphon has restarted Tor on its own (or on request) since the node started
    pub restarts: u32,
    pub last_restart: Option<i64>,
    pub last_restart_reason: Option<String>,
    /// can the Tor network find this node's address right now? (None = not known yet)
    pub listed: Option<bool>,
    pub checked: Option<i64>,
}

/// Token-bucket limiter with one second of burst. Rate is passed per call so policy edits apply instantly.
pub struct Limiter(tokio::sync::Mutex<(f64, Instant)>);

impl Limiter {
    pub fn new() -> Self {
        Limiter(tokio::sync::Mutex::new((0.0, Instant::now())))
    }

    pub async fn take(&self, bytes: usize, kib_s: u32) {
        if kib_s == 0 {
            return;
        }
        let rate = kib_s as f64 * 1024.0;
        let wait = {
            let mut g = self.0.lock().await;
            let t = Instant::now();
            let el = t.duration_since(g.1).as_secs_f64();
            g.1 = t;
            g.0 = (g.0 + el * rate).min(rate);
            g.0 -= bytes as f64;
            if g.0 < 0.0 { Some(-g.0 / rate) } else { None }
        };
        if let Some(w) = wait {
            tokio::time::sleep(Duration::from_secs_f64(w)).await;
        }
    }
}

impl Default for Limiter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct App {
    pub cfg: Config,
    pub dirs: Dirs,
    pub db: Db,
    pub keyring: Keyring,
    pub id: Identity,
    pub client_key: ClientKey,
    pub policy: RwLock<SyncPolicy>,
    pub sessions: Mutex<HashMap<String, Session>>,
    pub up: Limiter,
    pub down: Limiter,
    pub active_serves: AtomicUsize,
    pub nonces: Mutex<HashMap<String, i64>>,
    pub login_fails: Mutex<HashMap<String, (u32, i64)>>,
    pub login_gate: Semaphore,
    pub tor: Mutex<TorStatus>,
    /// asks the Tor supervisor to restart Tor now
    pub tor_restart: Notify,
    pub mesh_addr: Mutex<String>,
    pub live: Mutex<HashMap<String, PeerLive>>,
    pub transfers: Mutex<HashMap<String, Transfer>>,
    pub wake: Notify,
    /// something is waiting to be scanned (the background scanner picks it up)
    pub scan_wake: Notify,
    /// people may reach this node from outside through Tor (its access onion); the mesh is not affected
    pub tor_access: std::sync::atomic::AtomicBool,
    /// uploads in progress: id -> state (resumable: the browser can ask how much arrived and carry on)
    pub uploads: Mutex<HashMap<String, Arc<crate::library::Upload>>>,
    /// downloads actually running (the limit comes from the performance tuning and can change while they run)
    pub running_downloads: AtomicUsize,
    pub active_transcodes: Arc<AtomicUsize>,
    /// video responses still being sent (a viewer is watching: the computer must not suspend)
    pub active_streams: Arc<AtomicUsize>,
    pub sanity_running: std::sync::atomic::AtomicBool,
    pub perf_dedicated: std::sync::atomic::AtomicBool,
    /// rest mode (see rest.rs)
    pub rest: crate::rest::Rest,
    pub sleep: crate::sleep::Sleep,
    /// which drives hold the files (see storage.rs)
    pub storage: RwLock<crate::storage::StorageCfg>,
    pub storage_wake: Notify,
    pub hw: RwLock<crate::perf::Hardware>,
    pub tuning: RwLock<crate::perf::Tuning>,
    pub active_downloads: Mutex<std::collections::HashSet<String>>,
    /// downloads the owner has cancelled; running ones stop at the next chunk
    pub cancelled: Mutex<std::collections::HashSet<String>>,
    /// Set once a shutdown has begun: no new work starts and running work winds down.
    pub shutting_down: std::sync::atomic::AtomicBool,
    pub shutdown: Notify,
}

impl App {
    pub fn open(dirs: Dirs, cfg: Config) -> Result<Shared> {
        dirs.create_all()?;
        let db = Db::open_with(&dirs.db(), cfg.persistent())?;
        let keyring = Keyring::open(&dirs.keyring())?;
        let id = Identity::load_or_create(&dirs.identity())?;
        let client_key = ClientKey::load_or_create(&dirs.tor().join("client_auth.key"))?;
        let policy = match db.get_setting("sync_policy")? {
            Some(s) => serde_json::from_str(&s).unwrap_or_else(|_| cfg.sync.clone()),
            None => cfg.sync.clone(),
        };
        let dedicated = match db.get_setting("perf_mode")? {
            Some(m) => m == "dedicated",
            None => cfg.perf.mode == "dedicated",
        };
        let storage = crate::storage::load(&db);
        let hw = crate::perf::detect(None);
        let base = crate::perf::Base { streams: policy.max_concurrent, download_parallel: cfg.acquire.max_parallel as u32, transcode_threads: policy.transcode_threads };
        let tuning = crate::perf::compute(&hw, dedicated, &base);
        Ok(Arc::new(App {
            cfg,
            dirs,
            db,
            keyring,
            id,
            client_key,
            policy: RwLock::new(policy),
            sessions: Mutex::new(HashMap::new()),
            up: Limiter::new(),
            down: Limiter::new(),
            active_serves: AtomicUsize::new(0),
            nonces: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()),
            login_gate: Semaphore::new(2),
            tor: Mutex::new(TorStatus::default()),
            tor_restart: Notify::new(),
            mesh_addr: Mutex::new(String::new()),
            live: Mutex::new(HashMap::new()),
            transfers: Mutex::new(HashMap::new()),
            wake: Notify::new(),
            scan_wake: Notify::new(),
            tor_access: std::sync::atomic::AtomicBool::new(true),
            uploads: Mutex::new(HashMap::new()),
            running_downloads: AtomicUsize::new(0),
            active_transcodes: Arc::new(AtomicUsize::new(0)),
            active_streams: Arc::new(AtomicUsize::new(0)),
            sanity_running: std::sync::atomic::AtomicBool::new(false),
            perf_dedicated: std::sync::atomic::AtomicBool::new(dedicated),
            rest: Default::default(),
            sleep: Default::default(),
            storage: RwLock::new(storage),
            storage_wake: Notify::new(),
            hw: RwLock::new(hw),
            tuning: RwLock::new(tuning),
            active_downloads: Mutex::new(Default::default()),
            cancelled: Mutex::new(Default::default()),
            shutting_down: std::sync::atomic::AtomicBool::new(false),
            shutdown: Notify::new(),
        }))
    }

    /// Create a brand-new node directory: config, keyring, identity and the owner account.
    pub fn init(dirs: &Dirs, mut cfg: Config, owner: &str, password: &str) -> Result<()> {
        dirs.create_all()?;
        if dirs.keyring().exists() {
            return Err(anyhow!("{} is already initialised", dirs.root.display()));
        }
        if cfg.name == "node" {
            cfg.name = hostname_or(&cfg.name);
        }
        cfg.save(dirs)?;
        let params = KdfParams { m_kib: cfg.kdf_m_kib, t: cfg.kdf_t, p: 1 };
        Keyring::create(&dirs.keyring(), password, params)?;
        let app = App::open(dirs.clone(), cfg)?;
        crate::auth::create_user(&app, owner, password, "owner")?;
        Ok(())
    }

    pub fn policy(&self) -> SyncPolicy {
        self.policy.read().unwrap().clone()
    }

    pub fn set_policy(&self, p: SyncPolicy) -> Result<()> {
        self.db.set_setting("sync_policy", &serde_json::to_string(&p)?)?;
        *self.policy.write().unwrap() = p;
        self.wake.notify_waiters();
        Ok(())
    }

    pub fn tuning(&self) -> crate::perf::Tuning {
        self.tuning.read().unwrap().clone()
    }

    /// Switch between shared and dedicated and size the limits again straight away.
    pub fn set_perf_dedicated(&self, on: bool) -> Result<()> {
        self.db.set_setting("perf_mode", if on { "dedicated" } else { "shared" })?;
        self.perf_dedicated.store(on, std::sync::atomic::Ordering::Relaxed);
        crate::perf::refresh(self);
        Ok(())
    }

    /// How many chunk transfers may run at once, to and from other nodes.
    pub fn streams(&self) -> usize {
        if self.perf_dedicated.load(std::sync::atomic::Ordering::Relaxed) {
            self.tuning.read().unwrap().streams as usize
        } else {
            self.policy().max_concurrent.clamp(1, 8) as usize
        }
    }

    /// Room for `extra` more bytes on at least one drive, keeping each drive's reserve free.
    pub fn disk_ok(&self, extra: u64) -> Result<(), String> {
        crate::storage::room_for(self, extra)
    }

    /// Free space on the system drive (the sum over all drives is in storage::totals).
    pub fn disk_free(&self) -> u64 {
        fs2::available_space(&self.dirs.root).unwrap_or(u64::MAX)
    }

    pub fn library_bytes(&self) -> u64 {
        self.db
            .with(|c| Ok(c.query_row("SELECT COALESCE(SUM(size),0) FROM items WHERE local='present'", [], |r| r.get::<_, i64>(0))?))
            .unwrap_or(0) as u64
    }

    /// Ok(()) when every cap currently allows sync work.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn gate(&self) -> Result<(), String> {
        if self.is_shutting_down() {
            return Err("this node is shutting down".into());
        }
        self.policy().gate(self.disk_free(), self.library_bytes(), now())
    }

    pub fn set_live(&self, peer: &str, stage: &str, detail: impl Into<String>) {
        let mut g = self.live.lock().unwrap();
        let e = g.entry(peer.to_string()).or_default();
        e.stage = stage.to_string();
        e.detail = detail.into();
        e.updated = now();
    }

    pub fn mesh_addr(&self) -> String {
        self.mesh_addr.lock().unwrap().clone()
    }

    pub fn new_session(&self, user: &str, role: &str, zone: crate::security::Zone) -> String {
        let tok = random_hex(32);
        let mut g = self.sessions.lock().unwrap();
        let t = now();
        g.retain(|_, s| s.expires > t);
        g.insert(tok.clone(), Session { user: user.into(), role: role.into(), zone, expires: t + 12 * 3600 });
        tok
    }

    pub fn session(&self, token: &str) -> Option<Session> {
        let mut g = self.sessions.lock().unwrap();
        match g.get(token) {
            Some(s) if s.expires > now() => Some(s.clone()),
            Some(_) => {
                g.remove(token);
                None
            }
            None => None,
        }
    }
}

fn hostname_or(default: &str) -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn limiter_enforces_rate() {
        let l = Limiter::new();
        let t = Instant::now();
        // 1 MiB/s cap: 3 MiB should take roughly 2s (first second of burst is free)
        for _ in 0..3 {
            l.take(1 << 20, 1024).await;
        }
        let el = t.elapsed().as_secs_f64();
        assert!(el > 1.5 && el < 4.0, "elapsed {el}");
        // unlimited returns immediately
        let t = Instant::now();
        l.take(100 << 20, 0).await;
        assert!(t.elapsed().as_millis() < 50);
    }

    #[test]
    fn signatures_verify() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(&dir.path().join("id.key")).unwrap();
        let sig = id.sign(b"hello");
        assert!(verify_sig(&id.id, b"hello", &sig));
        assert!(!verify_sig(&id.id, b"hullo", &sig));
        let again = Identity::load_or_create(&dir.path().join("id.key")).unwrap();
        assert_eq!(again.id, id.id);
    }
}
