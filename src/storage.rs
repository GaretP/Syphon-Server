//! Where this node keeps its files: the system drive plus any number of extra drives and network shares (NAS).
//!
//! Every drive holds the same four folders (library, quarantine, inbox, vault) under its own root, so a file is
//! always finished on the drive it started on and nothing is copied between drives while it is being received.
//! New files go to the drive with the most room above its reserve; each drive keeps some free space back for
//! updates, the database and other things. Everything on every drive is still encrypted.

use crate::state::{App, Shared};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const GIB: u64 = 1 << 30;
pub const KINDS: [&str; 4] = ["library", "quarantine", "inbox", "vault"];

/// A folder on a drive or share that Syphon reads existing videos from (the "dir layout").
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct ImportDir {
    /// relative to the drive's mount point
    pub sub: String,
    /// "" = work it out from the names, otherwise movie / series / anime
    #[serde(default)]
    pub kind: String,
    /// remove the original after it has been copied in (never on a NAS unless asked)
    #[serde(default)]
    pub delete_source: bool,
}

/// How a network share is attached. The password is never stored here.
#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
pub struct NasLink {
    /// "nfs", "smb", or "mounted" (you mounted it yourself)
    pub proto: String,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub share: String,
    #[serde(default)]
    pub user: String,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Volume {
    pub id: String,
    pub label: String,
    /// the folder Syphon keeps its files in on this drive
    pub path: String,
    /// "local" or "nas"
    pub kind: String,
    pub enabled: bool,
    /// free space to keep on this drive, in GB. None = pick a sensible amount from the drive's size
    #[serde(default)]
    pub reserve_gb: Option<u32>,
    /// the drive's mount point. When set, the drive only counts as connected while something is mounted there
    #[serde(default)]
    pub mount: String,
    #[serde(default)]
    pub nas: Option<NasLink>,
    #[serde(default)]
    pub imports: Vec<ImportDir>,
    /// added by "use every drive"
    #[serde(default)]
    pub auto: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct StorageCfg {
    /// "all" = this computer is a node: use every fixed drive. "selected" = only the drives listed
    pub mode: String,
    /// "most_free" (spread by free space) or "in_order" (fill the first drive, then the next)
    pub policy: String,
    pub system_enabled: bool,
    #[serde(default)]
    pub system_reserve_gb: Option<u32>,
    pub volumes: Vec<Volume>,
    /// folders on the system drive to pull existing videos from
    #[serde(default)]
    pub system_imports: Vec<ImportDir>,
}

impl Default for StorageCfg {
    fn default() -> Self {
        StorageCfg { mode: "selected".into(), policy: "most_free".into(), system_enabled: true, system_reserve_gb: None, volumes: vec![], system_imports: vec![] }
    }
}

pub fn load(db: &crate::db::Db) -> StorageCfg {
    db.get_setting("storage").ok().flatten().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

pub fn cfg(app: &App) -> StorageCfg {
    app.storage.read().unwrap().clone()
}

pub fn save(app: &App, c: StorageCfg) -> Result<()> {
    app.db.set_setting("storage", &serde_json::to_string(&c)?)?;
    *app.storage.write().unwrap() = c;
    Ok(())
}

// ------------------------------------------------------------------ small helpers

pub fn default_reserve(total: u64, system: bool) -> u64 {
    // room for updates, the database, the scanner's scratch space and the downloads in progress
    let (floor, pct, cap) = if system { (8 * GIB, 3, 50 * GIB) } else { (5 * GIB, 2, 100 * GIB) };
    let want = (total / 100 * pct).max(floor).min(cap);
    // a very small drive must still be usable
    want.min(total / 4)
}

pub fn reserve_bytes(app: &App, reserve_gb: Option<u32>, total: u64, system: bool) -> u64 {
    let mut r = match reserve_gb {
        Some(g) => g as u64 * GIB,
        None => default_reserve(total, system),
    };
    if system {
        r = r.max(app.policy().min_free_gb as u64 * GIB);
    }
    r
}

fn dev_of(p: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.dev())
}

/// True when something other than the parent folder's drive is mounted exactly at `p`.
pub fn is_mount(p: &Path) -> bool {
    let (Some(a), Some(parent)) = (dev_of(p), p.parent().and_then(dev_of)) else { return false };
    a != parent || p == Path::new("/")
}

fn writable(dir: &Path) -> bool {
    let t = dir.join(format!(".write-test-{}", crate::util::random_hex(4)));
    let ok = std::fs::write(&t, b"x").is_ok();
    let _ = std::fs::remove_file(&t);
    ok
}

fn make_private_dir(p: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

/// Folders that must never be used as a drive's Syphon folder.
pub fn forbidden_path(p: &Path) -> Option<&'static str> {
    if !p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Some("the folder must be a full path (starting with /) with no \"..\"");
    }
    let s = p.to_string_lossy();
    for bad in ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/root", "/run", "/sbin", "/sys", "/tmp", "/usr", "/var", "/home", "/opt"] {
        if s == bad {
            return Some("that is a system folder");
        }
    }
    for bad in ["/proc/", "/sys/", "/dev/", "/boot/", "/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/run/", "/root/"] {
        if s.starts_with(bad) {
            return Some("that is inside a system folder");
        }
    }
    None
}

// ------------------------------------------------------------------ where files are

pub fn dir_in(root: &Path, kind: &str) -> PathBuf {
    root.join(kind)
}

/// Every root a file might be on: the system drive first, then each extra drive.
pub fn roots(app: &App) -> Vec<(String, PathBuf)> {
    let mut v = vec![("system".to_string(), app.dirs.root.clone())];
    for vol in app.storage.read().unwrap().volumes.iter() {
        v.push((vol.id.clone(), PathBuf::from(&vol.path)));
    }
    v
}

/// The file called `name` inside the `kind` folder of whichever drive holds it.
pub fn locate(app: &App, kind: &str, name: &str) -> Option<PathBuf> {
    roots(app).into_iter().map(|(_, r)| dir_in(&r, kind).join(name)).find(|p| p.exists())
}

/// Every drive's `kind` folder that exists right now (for clean-up and scans).
pub fn all_dirs(app: &App, kind: &str) -> Vec<PathBuf> {
    roots(app).into_iter().map(|(_, r)| dir_in(&r, kind)).filter(|p| p.is_dir()).collect()
}

/// The same drive, another folder: `<root>/quarantine/x.enc` -> `<root>/library`.
pub fn sibling_dir(file_or_dir: &Path, kind: &str) -> PathBuf {
    file_or_dir.parent().and_then(|p| p.parent()).unwrap_or(Path::new("/")).join(kind)
}

#[derive(Clone, Serialize, Debug, Default)]
pub struct VolStatus {
    pub online: bool,
    pub writable: bool,
    pub total: u64,
    pub free: u64,
    pub reserve: u64,
    /// what can still be filled before the reserve is reached
    pub usable: u64,
    pub note: String,
}

fn probe_root(app: &App, path: &Path, mount: &str, reserve_gb: Option<u32>, system: bool) -> VolStatus {
    let mut st = VolStatus::default();
    if !mount.is_empty() && !is_mount(Path::new(mount)) {
        st.note = "Not connected: nothing is mounted at its mount point right now".into();
        return st;
    }
    if !path.exists() {
        if let Err(e) = make_private_dir(path) {
            st.online = true;
            st.note = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "Syphon is not allowed to write here yet".into()
            } else {
                format!("Cannot create the folder: {e}")
            };
            return st;
        }
    }
    st.online = true;
    st.writable = writable(path);
    if !st.writable {
        st.note = "Syphon is not allowed to write to this folder".into();
    }
    st.total = fs2::total_space(path).unwrap_or(0);
    st.free = fs2::available_space(path).unwrap_or(0);
    st.reserve = reserve_bytes(app, reserve_gb, st.total, system);
    st.usable = st.free.saturating_sub(st.reserve);
    st
}

pub fn probe_system(app: &App) -> VolStatus {
    let c = cfg(app);
    probe_root(app, &app.dirs.root, "", c.system_reserve_gb, true)
}

pub fn probe_volume(app: &App, v: &Volume) -> VolStatus {
    probe_root(app, Path::new(&v.path), &v.mount, v.reserve_gb, false)
}

/// Total and free space over every drive that can take files (for the hardware summary).
pub fn totals(app: &App) -> (u64, u64) {
    let c = cfg(app);
    let mut total = 0;
    let mut free = 0;
    let mut seen: HashSet<u64> = HashSet::new();
    let mut add = |p: &Path| {
        if let Some(d) = dev_of(p) {
            if seen.insert(d) {
                total += fs2::total_space(p).unwrap_or(0);
                free += fs2::available_space(p).unwrap_or(0);
            }
        }
    };
    add(&app.dirs.root);
    for v in c.volumes.iter().filter(|v| v.enabled) {
        if v.mount.is_empty() || is_mount(Path::new(&v.mount)) {
            add(Path::new(&v.path));
        }
    }
    (total, free)
}

/// Pick the drive for a new file of about `need` bytes and return its root. Errors when no drive has room.
pub fn place_root(app: &App, need: u64, skip: Option<&str>) -> Result<PathBuf> {
    let c = cfg(app);
    let mut cands: Vec<(PathBuf, u64, usize)> = vec![];
    let mut why: Vec<String> = vec![];
    if c.system_enabled && skip != Some("system") {
        let st = probe_system(app);
        if st.writable && st.usable >= need {
            cands.push((app.dirs.root.clone(), st.usable, 0));
        } else {
            why.push(format!("the system drive has {} GB to spare", st.usable >> 30));
        }
    }
    for (i, v) in c.volumes.iter().enumerate().filter(|(_, v)| v.enabled && skip != Some(v.id.as_str())) {
        let st = probe_volume(app, v);
        if st.online && st.writable && st.usable >= need {
            cands.push((PathBuf::from(&v.path), st.usable, i + 1));
        } else if !st.online || !st.writable {
            why.push(format!("{} is not available", v.label));
        } else {
            why.push(format!("{} has {} GB to spare", v.label, st.usable >> 30));
        }
    }
    if cands.is_empty() {
        let need_gb = (need >> 30).max(1);
        bail!("No drive has room for this ({need_gb} GB needed, and each drive keeps some space free). {}", why.join("; "));
    }
    if c.policy == "in_order" {
        cands.sort_by_key(|x| x.2);
    } else {
        cands.sort_by(|a, b| b.1.cmp(&a.1));
    }
    Ok(cands.remove(0).0)
}

/// The `kind` folder on the drive chosen for a new file (created if needed).
pub fn place_dir(app: &App, kind: &str, need: u64) -> Result<PathBuf> {
    let root = place_root(app, need, None)?;
    let d = dir_in(&root, kind);
    make_private_dir(&d).with_context(|| format!("cannot create {}", d.display()))?;
    Ok(d)
}

/// Can a new file of `need` bytes be stored anywhere right now?
pub fn room_for(app: &App, need: u64) -> Result<(), String> {
    place_root(app, need, None).map(|_| ()).map_err(|e| e.to_string())
}

/// Rename, or copy across drives when rename is not possible.
pub fn move_file(src: &Path, dst: &Path) -> Result<()> {
    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(18) => {
            let part = dst.with_extension("part");
            std::fs::copy(src, &part).with_context(|| format!("copying to {}", dst.display()))?;
            std::fs::File::open(&part)?.sync_all()?;
            std::fs::rename(&part, dst)?;
            std::fs::remove_file(src)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)?.flatten() {
        let (p, q) = (e.path(), dst.join(e.file_name()));
        if p.is_dir() {
            copy_dir(&p, &q)?;
        } else {
            std::fs::copy(&p, &q)?;
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ finding drives

#[derive(Clone, Serialize, Debug)]
pub struct Drive {
    pub source: String,
    pub mount: String,
    pub fstype: String,
    pub total: u64,
    pub free: u64,
    /// the drive Syphon's own data folder is on
    pub system: bool,
    pub network: bool,
    pub removable: bool,
    /// already one of this node's drives
    pub in_use: bool,
}

const LOCAL_FS: [&str; 16] = ["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "bcachefs", "ntfs", "ntfs3", "fuseblk", "exfat", "vfat", "ufs"];
const NET_FS: [&str; 6] = ["nfs", "nfs4", "cifs", "smb3", "smbfs", "ceph"];

fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() + 0 && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let n = u8::from_str_radix(&s[i + 1..i + 4], 8).unwrap_or(b'?');
            out.push(n);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

fn removable(source: &str) -> bool {
    let name = source.rsplit('/').next().unwrap_or("");
    // /dev/sdb1 -> sdb, /dev/nvme0n1p2 -> nvme0n1, /dev/mmcblk0p1 -> mmcblk0
    let base: String = if name.starts_with("nvme") || name.starts_with("mmcblk") {
        name.rsplit_once('p').map(|x| x.0.to_string()).unwrap_or(name.to_string())
    } else {
        name.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
    };
    std::fs::read_to_string(format!("/sys/block/{base}/removable")).map(|s| s.trim() == "1").unwrap_or(false)
}

fn skip_mount(target: &str) -> bool {
    const PRE: [&str; 14] = ["/boot", "/efi", "/snap", "/var/lib/docker", "/var/lib/containers", "/var/lib/snapd", "/run", "/sys", "/proc", "/dev", "/usr", "/tmp", "/var/log", "/etc"];
    PRE.iter().any(|p| target == *p || target.starts_with(&format!("{p}/")))
}

/// Drives mounted on this computer that could hold media. Pseudo file systems, boot partitions and containers are left out.
pub fn detect_drives(app: &App) -> Vec<Drive> {
    let raw = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let c = cfg(app);
    let sys_dev = dev_of(&app.dirs.root);
    let mut by_source: HashMap<String, Drive> = HashMap::new();
    for l in raw.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        if f.len() < 4 {
            continue;
        }
        let (source, target, fstype, opts) = (unescape_mount(f[0]), unescape_mount(f[1]), f[2], f[3]);
        let network = NET_FS.contains(&fstype);
        if !(network || LOCAL_FS.contains(&fstype)) || skip_mount(&target) {
            continue;
        }
        if opts.split(',').any(|o| o == "ro") {
            continue;
        }
        let total = fs2::total_space(&target).unwrap_or(0);
        if total < GIB {
            continue;
        }
        let system = sys_dev.is_some() && dev_of(Path::new(&target)) == sys_dev;
        let in_use = c.volumes.iter().any(|v| v.mount == target || Path::new(&v.path).starts_with(&target) && target != "/");
        let d = Drive {
            removable: !network && removable(&source),
            source: source.clone(),
            mount: target.clone(),
            fstype: fstype.to_string(),
            total,
            free: fs2::available_space(&target).unwrap_or(0),
            system,
            network,
            in_use,
        };
        // the same device can be mounted several times (bind mounts, btrfs subvolumes): keep the shortest path
        let key = if network { format!("{source}@{target}") } else { source };
        match by_source.get(&key) {
            Some(old) if old.mount.len() <= d.mount.len() => {}
            _ => {
                by_source.insert(key, d);
            }
        }
    }
    let mut v: Vec<Drive> = by_source.into_values().collect();
    v.sort_by(|a, b| a.mount.cmp(&b.mount));
    v
}

fn new_id() -> String {
    format!("d{}", crate::util::random_hex(4))
}

/// The Syphon folder for a drive mounted at `mount`.
pub fn volume_path_for(mount: &str) -> String {
    Path::new(mount).join("syphon").to_string_lossy().to_string()
}

/// "Use every drive" mode: add each fixed local drive that is not yet listed. Returns how many were added.
pub fn sync_all(app: &App) -> Result<usize> {
    let mut c = cfg(app);
    if c.mode != "all" {
        return Ok(0);
    }
    let mut added = 0;
    for d in detect_drives(app) {
        if d.system || d.network || d.removable || d.in_use || d.mount == "/" {
            continue;
        }
        let known = c.volumes.iter().any(|v| v.mount == d.mount);
        if known {
            continue;
        }
        let v = Volume {
            id: new_id(),
            label: Path::new(&d.mount).file_name().map(|n| n.to_string_lossy().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| d.source.clone()),
            path: volume_path_for(&d.mount),
            kind: "local".into(),
            enabled: true,
            reserve_gb: None,
            mount: d.mount.clone(),
            nas: None,
            imports: vec![],
            auto: true,
        };
        ensure_folder(app, &v);
        c.volumes.push(v);
        added += 1;
    }
    if added > 0 {
        save(app, c)?;
    }
    Ok(added)
}

/// Make the folder, or ask the root helper to when Syphon is not allowed to.
pub fn ensure_folder(app: &App, v: &Volume) {
    let p = Path::new(&v.path);
    if make_private_dir(p).is_ok() && writable(p) {
        return;
    }
    request_helper(app, "storage-allow", &[("path", v.path.as_str())]);
}

/// Drop a request for the root helper (syphon-update) in the shared requests folder.
pub fn request_helper(app: &App, action: &str, fields: &[(&str, &str)]) -> bool {
    request_helper_why(app, action, fields).is_ok()
}

/// Same, but says what went wrong (so the web page can show the real reason).
pub fn request_helper_why(app: &App, action: &str, fields: &[(&str, &str)]) -> Result<(), String> {
    if !Path::new("/usr/local/bin/syphon-update").exists() {
        return Err("The system helper (/usr/local/bin/syphon-update) is not installed on this computer.".into());
    }
    write_request(&app.dirs.root, action, fields)
}

/// Leave a request for the root helper: written beside the requests folder, then moved in, so the helper never
/// sees a half-written one. Errors say what failed and how to fix it.
pub fn write_request(root: &Path, action: &str, fields: &[(&str, &str)]) -> Result<(), String> {
    let upd = root.join("update");
    let dir = upd.join("requests");
    let fix = format!("On the computer, run: sudo chown -R syphon:syphon {}", upd.display());
    std::fs::create_dir_all(&dir).map_err(|e| format!("Syphon cannot create {} ({e}). {fix}", dir.display()))?;
    let mut body = format!("{action}\n");
    for (k, v) in fields {
        body.push_str(&format!("{k}={v}\n"));
    }
    let tmp = upd.join(format!(".{}.tmp", crate::util::random_hex(6)));
    std::fs::write(&tmp, body).map_err(|e| format!("Syphon cannot write to {} ({e}). {fix}", upd.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp, dir.join(format!("{}-{action}.req", crate::util::now()))).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("Could not hand the request to the helper ({e}). {fix}")
    })
}

// ------------------------------------------------------------------ moving a drive's files elsewhere

#[derive(Clone, Serialize, Debug, Default)]
pub struct DrainState {
    pub running: bool,
    pub done: u64,
    pub total: u64,
    pub error: String,
}

static DRAINS: Mutex<Option<HashMap<String, DrainState>>> = Mutex::new(None);

pub fn drain_state(id: &str) -> Option<DrainState> {
    DRAINS.lock().unwrap().as_ref().and_then(|m| m.get(id).cloned())
}

fn set_drain(id: &str, f: impl FnOnce(&mut DrainState)) {
    let mut g = DRAINS.lock().unwrap();
    f(g.get_or_insert_with(HashMap::new).entry(id.to_string()).or_default());
}

/// How many files and bytes the drive holds (not counting temporary files).
pub fn holdings(root: &Path) -> (u64, u64) {
    let (mut n, mut b) = (0, 0);
    for k in KINDS {
        if let Ok(rd) = std::fs::read_dir(dir_in(root, k)) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with("incoming-") || name.starts_with('.') {
                    continue;
                }
                n += 1;
                b += e.metadata().map(|m| if m.is_dir() { dir_size(&e.path()) } else { m.len() }).unwrap_or(0);
            }
        }
    }
    (n, b)
}

fn dir_size(p: &Path) -> u64 {
    std::fs::read_dir(p).map(|rd| rd.flatten().map(|e| e.metadata().map(|m| if m.is_dir() { dir_size(&e.path()) } else { m.len() }).unwrap_or(0)).sum()).unwrap_or(0)
}

/// Move everything on a drive to the other drives. The drive is switched off for new files first.
pub fn start_drain(app: &Shared, id: &str) -> Result<()> {
    let mut c = cfg(app);
    let root = if id == "system" {
        c.system_enabled = false;
        app.dirs.root.clone()
    } else {
        let v = c.volumes.iter_mut().find(|v| v.id == id).ok_or_else(|| anyhow!("no such drive"))?;
        v.enabled = false;
        PathBuf::from(&v.path)
    };
    if drain_state(id).map(|d| d.running).unwrap_or(false) {
        bail!("this drive is already being emptied");
    }
    save(app, c)?;
    let (n, _) = holdings(&root);
    set_drain(id, |d| *d = DrainState { running: true, done: 0, total: n, error: String::new() });
    let app = app.clone();
    let id = id.to_string();
    tokio::task::spawn_blocking(move || {
        let res = (|| -> Result<()> {
            for k in KINDS {
                let Ok(rd) = std::fs::read_dir(dir_in(&root, k)) else { continue };
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with("incoming-") || name.starts_with('.') {
                        continue;
                    }
                    let src = e.path();
                    let size = if src.is_dir() { dir_size(&src) } else { e.metadata().map(|m| m.len()).unwrap_or(0) };
                    let dest_root = place_root(&app, size, Some(&id))?;
                    let dest_dir = dir_in(&dest_root, k);
                    make_private_dir(&dest_dir)?;
                    let dst = dest_dir.join(&name);
                    if src.is_dir() {
                        copy_dir(&src, &dst)?;
                        std::fs::remove_dir_all(&src)?;
                    } else {
                        move_file(&src, &dst)?;
                    }
                    set_drain(&id, |d| d.done += 1);
                }
            }
            Ok(())
        })();
        set_drain(&id, |d| {
            d.running = false;
            if let Err(e) = &res {
                d.error = format!("{e:#}");
            }
        });
    });
    Ok(())
}

// ------------------------------------------------------------------ pulling existing videos from a NAS / folder layout

const VIDEO_EXTS: [&str; 10] = ["mp4", "m4v", "mov", "mkv", "webm", "avi", "ts", "m2ts", "ogv", "mpg"];

fn norm(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase()
}

/// Build the name the library should see for a file at `rel` (relative to the import folder), so that
/// `Shows/Some Show/Season 2/03.mkv` is understood as episode 3 of season 2 of Some Show.
pub fn import_name(rel: &Path) -> String {
    let parts: Vec<String> = rel.components().map(|c| c.as_os_str().to_string_lossy().to_string()).collect();
    let file = parts.last().cloned().unwrap_or_default();
    if parts.len() < 2 {
        return file;
    }
    let stem = file.rsplit_once('.').map(|x| x.0).unwrap_or(&file).to_string();
    let season_re = regex::Regex::new(r"(?i)^(?:season|series|staffel|s)[ ._-]*0*(\d{1,2})$").unwrap();
    let mut season: Option<u32> = None;
    let mut show: Option<String> = None;
    let dirs = &parts[..parts.len() - 1];
    for (i, d) in dirs.iter().enumerate().rev() {
        if season.is_none() {
            if let Some(c) = season_re.captures(d.trim()) {
                season = c[1].parse().ok();
                continue;
            }
        }
        if i == dirs.len() - 1 || season.is_some() {
            show = Some(d.clone());
            break;
        }
    }
    let Some(show) = show else { return file };
    let (a, b) = (norm(&show), norm(&stem));
    if a.is_empty() || b.contains(&a) || a.contains(&b) {
        return file;
    }
    match season {
        Some(n) => format!("{show} Season {n} - {file}"),
        None => format!("{show} - {file}"),
    }
}

fn walk_videos(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    if depth > 6 || out.len() > 5000 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with('.') || n.starts_with('@') || n == "syphon" || n == "#recycle" {
            continue;
        }
        if p.is_dir() {
            walk_videos(&p, depth + 1, out);
        } else if p.extension().map(|x| VIDEO_EXTS.contains(&x.to_string_lossy().to_ascii_lowercase().as_str())).unwrap_or(false) {
            out.push(p);
        }
    }
}

fn already_imported(app: &App, path: &Path, size: u64, mtime: i64) -> bool {
    let key = path.to_string_lossy().to_string();
    app.db
        .with(|c| Ok(c.query_row("SELECT 1 FROM imported WHERE path=?1 AND size=?2 AND mtime=?3", rusqlite::params![key, size as i64, mtime], |_| Ok(())).is_ok()))
        .unwrap_or(false)
}

fn mark_imported(app: &App, path: &Path, size: u64, mtime: i64) {
    let key = path.to_string_lossy().to_string();
    let _ = app.db.with(|c| {
        c.execute(
            "INSERT INTO imported(path,size,mtime,at) VALUES(?1,?2,?3,?4) ON CONFLICT(path) DO UPDATE SET size=excluded.size, mtime=excluded.mtime, at=excluded.at",
            rusqlite::params![key, size as i64, mtime, crate::util::now()],
        )?;
        Ok(())
    });
}

#[derive(Clone, Serialize, Debug, Default)]
pub struct ImportState {
    pub running: bool,
    pub found: u64,
    pub new: u64,
    pub imported: u64,
    pub failed: u64,
    pub last: String,
    pub finished: i64,
}

static IMPORT: Mutex<Option<ImportState>> = Mutex::new(None);

pub fn import_state() -> ImportState {
    IMPORT.lock().unwrap().clone().unwrap_or_default()
}

fn upd_import(f: impl FnOnce(&mut ImportState)) {
    let mut g = IMPORT.lock().unwrap();
    f(g.get_or_insert_with(Default::default));
}

/// (mount point or base folder, folder layout) for every place that has import folders and is connected.
fn import_sources(app: &App) -> Vec<(PathBuf, ImportDir)> {
    let c = cfg(app);
    let mut v = vec![];
    for d in &c.system_imports {
        v.push((PathBuf::from("/"), d.clone()));
    }
    for vol in c.volumes.iter().filter(|x| x.enabled) {
        if vol.mount.is_empty() || !is_mount(Path::new(&vol.mount)) {
            continue;
        }
        for d in &vol.imports {
            v.push((PathBuf::from(&vol.mount), d.clone()));
        }
    }
    v
}

/// One pass over every import folder. Videos that were already copied in (same path, size and date) are skipped.
pub async fn import_pass(app: &Shared) -> Result<()> {
    if !app.keyring.is_unlocked() {
        return Ok(());
    }
    upd_import(|s| {
        s.running = true;
        s.found = 0;
        s.new = 0;
        s.imported = 0;
        s.failed = 0;
    });
    for (base, d) in import_sources(app) {
        let root = base.join(d.sub.trim_start_matches('/'));
        let r2 = root.clone();
        let files = tokio::task::spawn_blocking(move || {
            let mut out = vec![];
            walk_videos(&r2, 0, &mut out);
            out
        })
        .await?;
        for p in files {
            let Ok(md) = std::fs::metadata(&p) else { continue };
            let size = md.len();
            let mtime = md.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0);
            upd_import(|s| s.found += 1);
            if already_imported(app, &p, size, mtime) {
                continue;
            }
            // still being copied onto the share
            if std::time::SystemTime::now().duration_since(md.modified().unwrap_or(std::time::UNIX_EPOCH)).map(|x| x < Duration::from_secs(30)).unwrap_or(true) {
                continue;
            }
            if app.shutting_down.load(std::sync::atomic::Ordering::SeqCst) || !app.keyring.is_unlocked() {
                upd_import(|s| s.running = false);
                return Ok(());
            }
            upd_import(|s| {
                s.new += 1;
                s.last = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            });
            let rel = p.strip_prefix(&root).unwrap_or(&p).to_path_buf();
            let name = import_name(&rel);
            match crate::library::import_path_named(app, &p, "import", &name, size).await {
                Ok(ing) => {
                    if !ing.dup && !d.kind.is_empty() && ["movie", "series", "anime"].contains(&d.kind.as_str()) {
                        let k = d.kind.clone();
                        let id = ing.id.clone();
                        let _ = app.db.with(|c| {
                            c.execute("UPDATE items SET kind=?2 WHERE id=?1 AND catalog=0", rusqlite::params![id, k])?;
                            Ok(())
                        });
                    }
                    mark_imported(app, &p, size, mtime);
                    upd_import(|s| s.imported += 1);
                    if d.delete_source {
                        let _ = std::fs::remove_file(&p);
                    }
                }
                Err(e) => {
                    tracing::warn!("importing {} failed: {e:#}", p.display());
                    upd_import(|s| s.failed += 1);
                    // a drive that is full stops the pass; try again later
                    if e.to_string().contains("No drive has room") {
                        break;
                    }
                }
            }
        }
    }
    upd_import(|s| {
        s.running = false;
        s.finished = crate::util::now();
    });
    Ok(())
}

/// Background loop: watch for new drives in "use every drive" mode and pull in videos from import folders.
pub async fn run(app: Shared) {
    let mut last_import = Instant::now() - Duration::from_secs(3600);
    loop {
        let a = app.clone();
        let _ = tokio::task::spawn_blocking(move || sync_all(&a)).await;
        let wake = app.storage_wake.notified();
        tokio::select! {
            _ = wake => { last_import = Instant::now() - Duration::from_secs(3600); }
            _ = crate::rest::sleep(&app, Duration::from_secs(60)) => {}
        }
        if app.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        if last_import.elapsed() > Duration::from_secs(600) && !import_sources(&app).is_empty() {
            last_import = Instant::now();
            if let Err(e) = import_pass(&app).await {
                tracing::warn!("import pass failed: {e:#}");
            }
        }
    }
}

// ------------------------------------------------------------------ checks used by the API

pub fn valid_label(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && t.len() <= 40 && t.chars().all(|c| c.is_alphanumeric() || " _.-".contains(c))
}

pub fn slug(s: &str) -> String {
    let t: String = s.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
    let t = t.trim_matches('-').to_string();
    if t.is_empty() { "nas".into() } else { t.chars().take(30).collect() }
}

pub fn valid_sub(s: &str) -> bool {
    !s.contains("..") && !s.contains('\0') && s.len() <= 300
}

pub fn valid_host(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.chars().all(|c| c.is_ascii_alphanumeric() || ".-:_".contains(c))
}

pub fn valid_share(s: &str) -> bool {
    !s.is_empty() && s.len() <= 200 && !s.contains("..") && s.chars().all(|c| c.is_alphanumeric() || " _.$/-".contains(c))
}

pub fn valid_cred(s: &str) -> bool {
    s.len() <= 200 && !s.contains(['\n', '\r', '\0'])
}

pub fn tool_present(name: &str) -> bool {
    ["/sbin", "/usr/sbin", "/bin", "/usr/bin", "/usr/local/bin"].iter().any(|d| Path::new(d).join(name).exists())
}

/// Subfolders of a drive's mount point, for picking import folders.
pub fn list_folders(base: &Path, sub: &str) -> Result<Vec<String>> {
    if !valid_sub(sub) {
        bail!("bad folder");
    }
    let dir = base.join(sub.trim_start_matches('/'));
    let mut v: Vec<String> = std::fs::read_dir(&dir)
        .with_context(|| format!("cannot open {}", dir.display()))?
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| !n.starts_with('.') && !n.starts_with('@') && n != "syphon" && n != "#recycle")
        .collect();
    v.sort();
    v.truncate(500);
    Ok(v)
}

pub fn new_volume_id() -> String {
    new_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_for_the_helper_lands_whole_and_a_failure_says_why() {
        let root = std::env::temp_dir().join(format!("syphon-req-{}", crate::util::random_hex(6)));
        std::fs::create_dir_all(&root).unwrap();
        write_request(&root, "sleep", &[("wake_secs", "3600")]).unwrap();
        let files: Vec<_> = std::fs::read_dir(root.join("update").join("requests")).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
        assert_eq!(std::fs::read_to_string(files[0].path()).unwrap(), "sleep\nwake_secs=3600\n");
        // no temp file is left behind
        assert!(std::fs::read_dir(root.join("update")).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with('.')));
        // a folder that cannot be made: the message names the folder and the fix
        std::fs::write(root.join("blocker"), "x").unwrap();
        let err = write_request(&root.join("blocker"), "check", &[]).unwrap_err();
        assert!(err.contains("blocker") && err.contains("chown"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn reserve_leaves_room_but_never_swallows_a_small_drive() {
        assert_eq!(default_reserve(1000 * GIB, false), 20 * GIB);
        assert_eq!(default_reserve(100 * GIB, false), 5 * GIB);
        assert_eq!(default_reserve(100 * GIB, true), 8 * GIB);
        assert_eq!(default_reserve(10 * GIB, true), 10 * GIB / 4);
        assert_eq!(default_reserve(20_000 * GIB, false), 100 * GIB);
    }

    #[test]
    fn folders_name_the_show_and_season() {
        assert_eq!(import_name(Path::new("Some Show/Season 2/03.mkv")), "Some Show Season 2 - 03.mkv");
        assert_eq!(import_name(Path::new("Some Show/03.mkv")), "Some Show - 03.mkv");
        assert_eq!(import_name(Path::new("Some Show/Some Show - 03.mkv")), "Some Show - 03.mkv");
        assert_eq!(import_name(Path::new("La La Land (2016)/La La Land.mkv")), "La La Land.mkv");
        assert_eq!(import_name(Path::new("Film.mkv")), "Film.mkv");
        assert_eq!(import_name(Path::new("Show/S3/ep.mkv")), "Show Season 3 - ep.mkv");
    }

    #[test]
    fn dangerous_folders_are_refused() {
        assert!(forbidden_path(Path::new("/")).is_some());
        assert!(forbidden_path(Path::new("/etc/x")).is_some());
        assert!(forbidden_path(Path::new("relative")).is_some());
        assert!(forbidden_path(Path::new("/mnt/disk2/../etc")).is_some());
        assert!(forbidden_path(Path::new("/mnt/disk2/syphon")).is_none());
    }

    #[test]
    fn mount_names_with_spaces_are_read_back() {
        assert_eq!(unescape_mount("/mnt/my\\040disk"), "/mnt/my disk");
    }

    #[test]
    fn nas_input_is_checked() {
        assert!(valid_host("nas.local") && valid_host("192.168.1.5") && !valid_host("a b") && !valid_host("x;rm"));
        assert!(valid_share("media/video") && !valid_share("../x") && !valid_share("a;b"));
        assert!(valid_label("Living room NAS") && !valid_label("bad/label"));
        assert_eq!(slug("Living Room NAS!"), "living-room-nas");
    }
}
