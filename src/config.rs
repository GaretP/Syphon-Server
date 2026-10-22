use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const GIB: u64 = 1 << 30;

/// Runtime-adjustable sync switches and hardware caps. Stored in the database, edited from the UI.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct SyncPolicy {
    /// Master switch. Off = no heartbeats out, no requests out, every inbound request is denied,
    /// and running transfers stop at the next chunk.
    pub enabled: bool,
    /// How to answer inbound sync requests: "auto" grants if the caps allow, "ask" queues them for you.
    pub mode: String,
    /// Upload cap in KiB/s, 0 = unlimited.
    pub max_upload_kib_s: u32,
    /// Download cap in KiB/s, 0 = unlimited.
    pub max_download_kib_s: u32,
    /// Parallel chunk transfers (in and out). More streams helps over Tor, costs CPU and memory.
    pub max_concurrent: u32,
    /// Refuse to sync when free disk space would drop below this.
    pub min_free_gb: u32,
    /// Refuse to sync when the library is at least this big (0 = no cap).
    pub max_library_gb: u32,
    /// Hours (0-23) during which sync may run; start == end means any time.
    pub window_start: u8,
    pub window_end: u8,
    /// Hours added to UTC for the window above.
    pub utc_offset: i8,
    /// ffmpeg threads for on-the-fly transcodes.
    pub transcode_threads: u32,
    /// `nice` level for ffmpeg (0 = off).
    pub nice: i32,
    /// Only mirror these kinds (movie / series / anime). Empty = everything.
    pub mirror_kinds: Vec<String>,
    /// Maximum GiB requested per request (0 = no limit).
    pub batch_gb: u32,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        SyncPolicy {
            enabled: true,
            mode: "auto".into(),
            max_upload_kib_s: 0,
            max_download_kib_s: 0,
            max_concurrent: 3,
            min_free_gb: 5,
            max_library_gb: 0,
            window_start: 0,
            window_end: 0,
            utc_offset: 0,
            transcode_threads: 2,
            nice: 10,
            mirror_kinds: vec![],
            batch_gb: 50,
        }
    }
}

impl SyncPolicy {
    pub fn in_window(&self, now: i64) -> bool {
        if self.window_start == self.window_end {
            return true;
        }
        let hour = (((now / 3600) + self.utc_offset as i64).rem_euclid(24)) as u8;
        if self.window_start < self.window_end {
            hour >= self.window_start && hour < self.window_end
        } else {
            hour >= self.window_start || hour < self.window_end
        }
    }

    /// Checks every cap that can pause sync. `Err` carries a human-readable reason.
    pub fn gate(&self, free_bytes: u64, library_bytes: u64, now: i64) -> Result<(), String> {
        if !self.enabled {
            return Err("sync is switched off".into());
        }
        if !self.in_window(now) {
            return Err(format!(
                "outside the allowed sync window ({:02}:00-{:02}:00)",
                self.window_start, self.window_end
            ));
        }
        if self.min_free_gb > 0 && free_bytes < self.min_free_gb as u64 * GIB {
            return Err(format!("low disk space (below {} GiB free)", self.min_free_gb));
        }
        if self.max_library_gb > 0 && library_bytes >= self.max_library_gb as u64 * GIB {
            return Err(format!("library size cap reached ({} GiB)", self.max_library_gb));
        }
        Ok(())
    }

    pub fn wants_kind(&self, kind: &str) -> bool {
        self.mirror_kinds.is_empty() || self.mirror_kinds.iter().any(|k| k == kind)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct TorCfg {
    pub binary: String,
    pub socks_port: u16,
    /// Also run Tor's transparent proxy (TransPort + DNSPort) so the whole computer can be sent
    /// through Tor with the firewall rules from `syphon torify-rules` (see `syphon-ctl torify`).
    pub system_wide: bool,
    /// Tor bridges, one per entry, exactly as bridges.torproject.org gives them (obfs4, webtunnel,
    /// snowflake, meek). For networks that block Tor, or to hide from an ISP that Tor is in use.
    pub bridges: Vec<String>,
    pub trans_port: u16,
    pub dns_port: u16,
}

impl Default for TorCfg {
    fn default() -> Self {
        TorCfg { binary: "tor".into(), socks_port: 9250, system_wide: false, bridges: vec![], trans_port: 9251, dns_port: 9253 }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RssFeed {
    pub name: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct AcquireCfg {
    /// How downloads leave this machine: "auto" (Tor whenever this node uses Tor, the default),
    /// "tor" or "direct". Your own Plex/Jellyfin on the home network is always reached
    /// directly (Tor cannot reach private addresses, and nothing leaves your network).
    pub route: String,
    pub internet_archive: bool,
    /// Extra Lucene filter appended to Internet Archive searches.
    pub ia_filter: String,
    pub rss: Vec<RssFeed>,
    pub max_parallel: usize,
    /// Allow downloads from localhost / private addresses (off by default to block SSRF).
    pub allow_private_hosts: bool,
}

impl Default for AcquireCfg {
    fn default() -> Self {
        AcquireCfg {
            route: "auto".into(),
            internet_archive: true,
            ia_filter: " AND (collection:feature_films OR collection:classic_tv OR collection:animationandcartoons OR collection:opensource_movies)".into(),
            rss: vec![],
            max_parallel: 2,
            allow_private_hosts: false,
        }
    }
}

/// Cast, genres, descriptions and posters, looked up through Tor (the same route as downloads).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct MetadataCfg {
    pub enabled: bool,
    /// Optional free key from themoviedb.org: better movie details. Without it movies use Wikidata.
    pub tmdb_key: String,
    pub tvmaze: String,
    pub jikan: String,
    pub anilist: String,
    pub tmdb: String,
    pub tmdb_images: String,
    pub wikidata: String,
    pub wikipedia: String,
    pub commons: String,
    pub itunes: String,
    pub imdb: String,
}

impl Default for MetadataCfg {
    fn default() -> Self {
        MetadataCfg {
            enabled: true,
            tmdb_key: String::new(),
            tvmaze: "https://api.tvmaze.com".into(),
            jikan: "https://api.jikan.moe/v4".into(),
            anilist: "https://graphql.anilist.co".into(),
            tmdb: "https://api.themoviedb.org/3".into(),
            tmdb_images: "https://image.tmdb.org".into(),
            wikidata: "https://www.wikidata.org".into(),
            wikipedia: "https://en.wikipedia.org".into(),
            commons: "https://commons.wikimedia.org".into(),
            itunes: "https://itunes.apple.com".into(),
            imdb: "https://v3.sg.media-imdb.com".into(),
        }
    }
}

/// How hard the node works. "shared": small fixed limits (the computer does other things too).
/// "dedicated": sized from the machine and kept up to date. Can be changed from Settings at any time.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct PerfCfg {
    pub mode: String,
}

impl Default for PerfCfg {
    fn default() -> Self {
        PerfCfg { mode: "shared".into() }
    }
}

/// The malware scanner (see scanner.rs).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ScanCfg {
    /// Decode the video with ffmpeg (sandboxed) to catch files built to crash a decoder.
    pub decode: bool,
    /// How much of the file is fully decoded. The whole file is always walked, signature-scanned and given to ClamAV.
    pub decode_max_mib: u64,
    pub decode_timeout_secs: u64,
    /// "auto" uses clamdscan/clamscan when installed; "off" never runs ClamAV.
    pub clamav: String,
    /// Scan in a background queue that carries on by itself (after a restart, an unlock, a failure). Tests turn this off.
    pub background: bool,
}

impl Default for ScanCfg {
    fn default() -> Self {
        ScanCfg { decode: true, decode_max_mib: 2048, decode_timeout_secs: 1800, clamav: "auto".into(), background: true }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    pub name: String,
    /// "always_on": the node may lose power or crash at any time, so every write is flushed to disk
    /// and unfinished work resumes by itself. "on_demand": the node is switched off normally, so it
    /// shuts down cleanly and forgets unfinished transient work (queued downloads, half-received files).
    pub persistence: String,
    /// "tor" (onion services) or "direct" (plain HTTP, for development and tests).
    pub transport: String,
    /// UI/API listener. 0.0.0.0 lets phones and laptops on your home network reach this node; use
    /// 127.0.0.1 to keep it to this machine only. Visitors from public addresses count as "remote".
    pub access_bind: String,
    /// Local port that the *access* onion service forwards to.
    pub tor_access_port: u16,
    /// Local port that the *mesh* onion service forwards to (also the direct-mode peer address).
    pub mesh_bind: String,
    pub heartbeat_secs: u64,
    /// Folder watched for videos to import into the isolated review area ("" = off).
    pub import_dir: String,
    /// Remove a file from the import folder once its encrypted copy is stored (note: deletion does
    /// not securely erase flash storage).
    pub import_delete_source: bool,
    /// Skip manual review for videos imported from this machine.
    pub auto_approve_imports: bool,
    /// Videos synced from peers land in the review area before joining the library.
    pub review_inbound: bool,
    pub trash_days: u32,
    pub ffmpeg: String,
    pub ffprobe: String,
    pub kdf_m_kib: u32,
    pub kdf_t: u32,
    pub tor: TorCfg,
    pub sync: SyncPolicy,
    pub acquire: AcquireCfg,
    pub scan: ScanCfg,
    pub perf: PerfCfg,
    pub metadata: MetadataCfg,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            name: "node".into(),
            persistence: "always_on".into(),
            transport: "tor".into(),
            access_bind: "0.0.0.0:8096".into(),
            tor_access_port: 8097,
            mesh_bind: "127.0.0.1:8098".into(),
            heartbeat_secs: 90,
            import_dir: String::new(),
            import_delete_source: true,
            auto_approve_imports: false,
            review_inbound: false,
            trash_days: 30,
            ffmpeg: "ffmpeg".into(),
            ffprobe: "ffprobe".into(),
            kdf_m_kib: 65536,
            kdf_t: 3,
            tor: TorCfg::default(),
            sync: SyncPolicy::default(),
            acquire: AcquireCfg::default(),
            scan: ScanCfg::default(),
            perf: PerfCfg::default(),
            metadata: MetadataCfg::default(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Dirs {
    pub root: PathBuf,
}

impl Dirs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Dirs { root: root.into() }
    }
    pub fn config(&self) -> PathBuf { self.root.join("config.toml") }
    pub fn keyring(&self) -> PathBuf { self.root.join("keyring.json") }
    pub fn identity(&self) -> PathBuf { self.root.join("identity.key") }
    pub fn db(&self) -> PathBuf { self.root.join("syphon.db") }
    pub fn library(&self) -> PathBuf { self.root.join("library") }
    pub fn quarantine(&self) -> PathBuf { self.root.join("quarantine") }
    pub fn inbox(&self) -> PathBuf { self.root.join("inbox") }
    pub fn tor(&self) -> PathBuf { self.root.join("tor") }
    /// Private per-user vault files. Nothing in here is ever offered to other nodes.
    pub fn vault(&self) -> PathBuf { self.root.join("vault") }

    /// Nodes created before the rename to Syphon used other file names. Rename them in place.
    pub fn migrate_legacy(&self) {
        for (old, new) in [("vault.json", "keyring.json"), ("hearth.db", "syphon.db"), ("hearth.db-wal", "syphon.db-wal"), ("hearth.db-shm", "syphon.db-shm")] {
            let (o, n) = (self.root.join(old), self.root.join(new));
            if o.exists() && !n.exists() {
                let _ = std::fs::rename(&o, &n);
            }
        }
    }

    pub fn create_all(&self) -> Result<()> {
        self.migrate_legacy();
        for d in [self.root.clone(), self.library(), self.quarantine(), self.inbox(), self.tor(), self.vault()] {
            std::fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
        }
        Ok(())
    }
}

impl Config {
    pub fn persistent(&self) -> bool {
        self.persistence != "on_demand"
    }

    pub fn load(dirs: &Dirs) -> Result<Config> {
        let p = dirs.config();
        let raw = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn save(&self, dirs: &Dirs) -> Result<()> {
        crate::util::write_atomic(&dirs.config(), toml::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

pub fn path_str(p: &Path) -> String {
    p.to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_from_before_the_rename_are_picked_up() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("vault.json"), "k").unwrap();
        std::fs::write(d.path().join("hearth.db"), "d").unwrap();
        let dirs = Dirs::new(d.path());
        dirs.create_all().unwrap();
        assert!(dirs.keyring().exists() && dirs.db().exists());
        assert!(!d.path().join("vault.json").exists());
    }

    #[test]
    fn window_wraps_midnight() {
        let p = SyncPolicy { window_start: 22, window_end: 6, ..Default::default() };
        assert!(p.in_window(23 * 3600));
        assert!(p.in_window(3 * 3600));
        assert!(!p.in_window(12 * 3600));
        let always = SyncPolicy::default();
        assert!(always.in_window(12345));
    }

    #[test]
    fn gate_reports_reasons() {
        let mut p = SyncPolicy::default();
        assert!(p.gate(100 * GIB, 0, 0).is_ok());
        assert!(p.gate(GIB, 0, 0).unwrap_err().contains("disk"));
        p.max_library_gb = 10;
        assert!(p.gate(100 * GIB, 11 * GIB, 0).unwrap_err().contains("cap"));
        p.enabled = false;
        assert!(p.gate(100 * GIB, 0, 0).unwrap_err().contains("off"));
    }

    #[test]
    fn config_roundtrips_through_toml() {
        let c = Config::default();
        let s = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.sync, c.sync);
        assert_eq!(back.mesh_bind, c.mesh_bind);
    }
}
