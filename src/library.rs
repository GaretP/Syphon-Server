use crate::catalog::{self, IdBody, MetaBody};
use crate::db::{get_item, Item};
use crate::state::{App, Shared};
use crate::util::{now, parse_filename};
use crate::keyring::{unseal, EncReader, EncWriter, Keys, CHUNK};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use futures_util::Stream;
use rusqlite::{params, OptionalExtension};
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Files can live on any of the node's drives (see storage.rs): these find the one that holds the file,
/// or give the system drive's path when it is not stored anywhere yet.
pub fn library_path(app: &App, id: &str) -> PathBuf {
    crate::storage::locate(app, "library", &format!("{id}.enc")).unwrap_or_else(|| app.dirs.library().join(format!("{id}.enc")))
}

pub fn vault_path(app: &App, id: &str) -> PathBuf {
    crate::storage::locate(app, "vault", &format!("{id}.enc")).unwrap_or_else(|| app.dirs.vault().join(format!("{id}.enc")))
}

pub fn quarantine_path(app: &App, id: &str) -> PathBuf {
    crate::storage::locate(app, "quarantine", &format!("{id}.enc")).unwrap_or_else(|| app.dirs.quarantine().join(format!("{id}.enc")))
}

/// Where the partly received chunks of an item are (on the drive chosen for it when the first chunk arrived).
pub fn inbox_dir(app: &App, id: &str) -> PathBuf {
    if let Some(p) = crate::storage::locate(app, "inbox", id) {
        return p;
    }
    let size = app.db.with(|c| Ok(c.query_row("SELECT size FROM items WHERE id=?1", [id], |r| r.get::<_, i64>(0))?)).unwrap_or(0).max(0) as u64;
    match crate::storage::place_dir(app, "inbox", size.saturating_mul(2)) {
        Ok(d) => d.join(id),
        Err(_) => app.dirs.inbox().join(id),
    }
}

/// A file that was written as `tmp` gets its final name on the same drive.
fn beside(tmp: &std::path::Path, name: &str) -> PathBuf {
    tmp.with_file_name(name)
}

pub fn keys(app: &App) -> Result<Arc<Keys>> {
    app.keyring.keys().ok_or_else(|| anyhow!("the library is locked: sign in as the owner to unlock it"))
}

pub struct Ingested {
    pub id: String,
    pub size: u64,
    /// true when this exact content was already known (nothing new was stored)
    pub dup: bool,
    /// the content was in the trash and this brought it back
    pub restored: bool,
}

/// Streams plaintext in and writes it encrypted into the isolated review area. Plaintext never touches disk.
pub struct IngestSession {
    w: EncWriter<BufWriter<File>>,
    tmp: PathBuf,
    name: String,
    source: String,
    /// Some(user) = this goes to that user's private vault instead of the review area
    vault_user: Option<String>,
}

impl IngestSession {
    /// Starts an upload into a user's private vault. Vault files are never scanned-for-sharing,
    /// never get a catalog entry and never leave this node.
    pub fn begin_vault(app: &App, name: &str, user: &str) -> Result<Self> {
        let k = keys(app)?;
        let tmp = crate::storage::place_dir(app, "vault", 0)?.join(format!("incoming-{}.tmp", crate::util::random_hex(8)));
        let f = File::create(&tmp)?;
        let w = EncWriter::new(BufWriter::with_capacity(1 << 16, f), &k.content_key())?;
        Ok(IngestSession { w, tmp, name: name.to_string(), source: "vault".into(), vault_user: Some(user.to_string()) })
    }

    pub fn begin(app: &App, name: &str, source: &str) -> Result<Self> {
        Self::begin_sized(app, name, source, 0)
    }

    /// `size` is how big the file is expected to be (0 = unknown); the drive with room for it is chosen.
    pub fn begin_sized(app: &App, name: &str, source: &str, size: u64) -> Result<Self> {
        let k = keys(app)?;
        let tmp = crate::storage::place_dir(app, "quarantine", size)?.join(format!("incoming-{}.tmp", crate::util::random_hex(8)));
        let f = File::create(&tmp)?;
        let w = EncWriter::new(BufWriter::with_capacity(1 << 16, f), &k.content_key())?;
        Ok(IngestSession { w, tmp, name: name.to_string(), source: source.to_string(), vault_user: None })
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        self.w.push(data)
    }

    pub fn bytes(&self) -> u64 {
        self.w.bytes_so_far()
    }

    pub fn abort(self) {
        let tmp = self.tmp.clone();
        drop(self);
        let _ = std::fs::remove_file(tmp);
    }

    pub fn finish(self, app: &App) -> Result<Ingested> {
        let IngestSession { w, tmp, name, source, vault_user } = self;
        let (bw, manifest) = match w.finish() {
            Ok(x) => x,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };
        // flush to the disk before the file gets its final name (a power cut must not leave a torn file)
        sync_writer(bw)?;
        if let Some(user) = vault_user {
            // random id: a vault file's identity must not reveal (or collide with) library content
            let id = format!("v{}", crate::util::random_hex(12));
            std::fs::rename(&tmp, beside(&tmp, &format!("{id}.enc")))?;
            let p = parse_filename(&name);
            app.db.with(|c| {
                c.execute(
                    "INSERT INTO items(id,title,kind,year,season,episode,size,chunk_hashes,author,added_at,catalog,deleted,local,filename,source,vault_user)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,0,'private',?11,'vault',?12)",
                    params![id, p.title, p.kind, p.year, p.season, p.episode, manifest.size as i64, serde_json::to_string(&manifest.chunk_hashes)?, app.id.id, now(), name, user],
                )?;
                Ok(())
            })?;
            tidy_item(app, &id);
            return Ok(Ingested { id, size: manifest.size, dup: false, restored: false });
        }
        let id = manifest.id();
        let existing = app.db.with(|c| get_item(c, &id))?;
        if let Some(it) = existing {
            // The same video is sitting in the trash: putting it back is what sending it again means.
            if it.catalog && it.deleted {
                if it.local == "present" {
                    let _ = std::fs::remove_file(&tmp);
                    restore_item(app, &id)?;
                    return Ok(Ingested { id, size: manifest.size, dup: true, restored: true });
                }
                if matches!(it.local.as_str(), "absent" | "syncing" | "assembling") {
                    std::fs::rename(&tmp, beside(&tmp, &format!("{id}.enc")))?;
                    app.db.with(|c| {
                        c.execute("UPDATE items SET local='quarantine', scan=NULL WHERE id=?1", [&id])?;
                        c.execute("DELETE FROM chunks WHERE item=?1", [&id])?;
                        Ok(())
                    })?;
                    let _ = std::fs::remove_dir_all(inbox_dir(app, &id));
                    restore_item(app, &id)?;
                    return Ok(Ingested { id, size: manifest.size, dup: false, restored: true });
                }
            }
            // Content we already know about but do not hold yet: adopt the local copy. Its id
            // commits to the same bytes the catalog already approved, so it can skip review.
            if it.catalog && matches!(it.local.as_str(), "absent" | "syncing" | "assembling") {
                // same bytes as a peer's approved item, but this node still scans them itself
                std::fs::rename(&tmp, beside(&tmp, &format!("{id}.enc")))?;
                app.db.with(|c| {
                    c.execute("UPDATE items SET local='quarantine', scan=NULL WHERE id=?1", [&id])?;
                    c.execute("DELETE FROM chunks WHERE item=?1", [&id])?;
                    Ok(())
                })?;
                let _ = std::fs::remove_dir_all(inbox_dir(app, &id));
                return Ok(Ingested { id, size: manifest.size, dup: false, restored: false });
            }
            let _ = std::fs::remove_file(&tmp);
            return Ok(Ingested { id, size: manifest.size, dup: true, restored: false });
        }
        std::fs::rename(&tmp, beside(&tmp, &format!("{id}.enc")))?;
        let p = parse_filename(&name);
        app.db.with(|c| {
            c.execute(
                "INSERT INTO items(id,title,kind,year,season,episode,size,chunk_hashes,author,added_at,catalog,deleted,local,filename,source)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,0,0,'quarantine',?11,?12)",
                params![
                    id,
                    p.title,
                    p.kind,
                    p.year,
                    p.season,
                    p.episode,
                    manifest.size as i64,
                    serde_json::to_string(&manifest.chunk_hashes)?,
                    app.id.id,
                    now(),
                    name,
                    source
                ],
            )?;
            Ok(())
        })?;
        tidy_item(app, &id);
        Ok(Ingested { id, size: manifest.size, dup: false, restored: false })
    }
}

/// A browser upload in progress. It lives on the node, so a dropped connection (or the whole page being closed
/// and reopened) can ask how much arrived and carry on from there instead of starting again.
pub struct Upload {
    pub user: String,
    pub name: String,
    pub kind: String,
    pub size: u64,
    /// bytes safely received so far (readable without waiting for a chunk that is still arriving)
    pub received: std::sync::atomic::AtomicU64,
    pub touched: std::sync::atomic::AtomicI64,
    /// a new request for the same upload tells an old, stuck one to let go
    pub takeover: tokio::sync::Notify,
    pub session: tokio::sync::Mutex<Option<IngestSession>>,
}

/// Drop uploads nobody has touched for half a day (and the partial files they hold).
pub fn expire_uploads(app: &App) {
    let cutoff = crate::util::now() - 12 * 3600;
    let stale: Vec<String> = app.uploads.lock().unwrap().iter().filter(|(_, u)| u.touched.load(std::sync::atomic::Ordering::Relaxed) < cutoff).map(|(k, _)| k.clone()).collect();
    for id in stale {
        let up = app.uploads.lock().unwrap().remove(&id);
        if let Some(up) = up {
            if let Ok(mut g) = up.session.try_lock() {
                if let Some(s) = g.take() {
                    s.abort();
                }
            }
        }
    }
}

/// Import a file from disk into the isolated review area, then scan it.
pub async fn import_path(app: &Shared, path: &std::path::Path, source: &str) -> Result<Ingested> {
    let name = path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "video".into());
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    import_path_named(app, path, source, &name, size).await
}

/// Like import_path, but the library is told a different name (built from the folders the file sat in).
pub async fn import_path_named(app: &Shared, path: &std::path::Path, source: &str, name: &str, size: u64) -> Result<Ingested> {
    let app2 = app.clone();
    let path = path.to_path_buf();
    let name = name.to_string();
    let source = source.to_string();
    let source_for_post = source.clone();
    let ing = tokio::task::spawn_blocking(move || -> Result<Ingested> {
        use std::io::Read;
        let mut s = IngestSession::begin_sized(&app2, &name, &source, size.saturating_mul(2))?;
        let mut f = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if let Err(e) = s.push(&buf[..n]) {
                s.abort();
                return Err(e);
            }
        }
        s.finish(&app2)
    })
    .await??;
    post_ingest(app, &ing, source_for_post).await?;
    Ok(ing)
}

/// Queue a fresh item for its safety scan (the scanner approves it afterwards when that is configured).
pub async fn post_ingest(app: &Shared, ing: &Ingested, _source: String) -> Result<()> {
    if ing.dup {
        return Ok(());
    }
    crate::quarantine::schedule(app, &ing.id).await
}

pub fn approve(app: &App, id: &str, override_scan: bool) -> Result<()> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if it.local != "quarantine" && it.local != "blocked" {
        bail!("item is not waiting in the review area");
    }
    if it.scan.as_ref().and_then(|s| s.get("hard")).and_then(|v| v.as_bool()).unwrap_or(false) {
        bail!("the safety scan found malware or a hidden program in this file; it cannot be approved. Reject it instead");
    }
    if it.local == "blocked" && !override_scan {
        bail!("this file failed the safety scan; read the report, or approve with override");
    }
    if !override_scan {
        let ok = it.scan.as_ref().and_then(|s| s.get("ok")).and_then(|v| v.as_bool()).unwrap_or(false);
        if !ok {
            bail!("the safety scan has not passed; read the report, or approve with override");
        }
    }
    let from = quarantine_path(app, id);
    let to_dir = crate::storage::sibling_dir(&from, "library");
    std::fs::create_dir_all(&to_dir)?;
    crate::storage::move_file(&from, &to_dir.join(format!("{id}.enc")))?;
    app.db.with(|c| {
        c.execute("UPDATE items SET local='present' WHERE id=?1", [id])?;
        c.execute("UPDATE downloads SET finished=?1 WHERE item=?2", rusqlite::params![crate::util::now(), id])?;
        if !it.catalog {
            catalog::emit_conn(c, &app.id, "add", &catalog::add_body(&it))?;
        }
        Ok(())
    })?;
    app.wake.notify_waiters();
    Ok(())
}

pub fn reject(app: &App, id: &str) -> Result<()> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if it.local != "quarantine" && it.local != "blocked" {
        bail!("item is not waiting in the review area");
    }
    let _ = std::fs::remove_file(quarantine_path(app, id));
    app.db.with(|c| {
        c.execute("UPDATE downloads SET finished=?1 WHERE item=?2", rusqlite::params![crate::util::now(), id])?;
        if it.catalog {
            c.execute("UPDATE items SET local='rejected' WHERE id=?1", [id])?;
        } else {
            c.execute("DELETE FROM items WHERE id=?1", [id])?;
        }
        Ok(())
    })
}

/// Pull an item out of circulation: it stops being served to peers or streamed, and waits (encrypted,
/// untouched) in the review area for the owner to look at the report.
pub fn set_blocked(app: &App, id: &str) -> Result<()> {
    let lib = library_path(app, id);
    if lib.exists() {
        let qd = crate::storage::sibling_dir(&lib, "quarantine");
        std::fs::create_dir_all(&qd)?;
        crate::storage::move_file(&lib, &qd.join(format!("{id}.enc")))?;
    }
    app.db.with(|c| {
        c.execute("UPDATE items SET local='blocked' WHERE id=?1 AND local IN ('present','quarantine','assembling','syncing','absent')", [id])?;
        Ok(())
    })
}

pub fn delete_item(app: &App, id: &str) -> Result<()> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if !it.catalog || it.deleted {
        bail!("item is not in the library");
    }
    catalog::emit(app, "delete", &IdBody { id: id.to_string() })?;
    Ok(())
}

pub fn restore_item(app: &App, id: &str) -> Result<()> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if !it.catalog || !it.deleted {
        bail!("item is not in the trash");
    }
    catalog::emit(app, "restore", &IdBody { id: id.to_string() })?;
    app.wake.notify_waiters();
    Ok(())
}

pub fn edit_meta(app: &App, m: MetaBody) -> Result<()> {
    let it = app.db.with(|c| get_item(c, &m.id))?.ok_or_else(|| anyhow!("no such item"))?;
    if !it.catalog {
        bail!("approve the item before editing its details");
    }
    if m.title.trim().is_empty() || m.title.len() > 200 {
        bail!("title must be 1-200 characters");
    }
    if !["movie", "series", "anime"].contains(&m.kind.as_str()) {
        bail!("kind must be movie, series or anime");
    }
    catalog::emit(app, "meta", &m)?;
    Ok(())
}

/// Drop the local copy of one trashed item now (or every trashed item, with `None`). The catalog entry stays deleted.
pub fn purge_now(app: &App, id: Option<&str>) -> Result<usize> {
    let ids: Vec<String> = app.db.with(|c| {
        let mut st = c.prepare("SELECT id FROM items WHERE catalog=1 AND deleted=1 AND local='present' AND (?1 IS NULL OR id=?1)")?;
        let v = st.query_map([id], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(v)
    })?;
    for i in &ids {
        let _ = std::fs::remove_file(library_path(app, i));
        app.db.with(|c| {
            c.execute("UPDATE items SET local='absent' WHERE id=?1", [i])?;
            c.execute("DELETE FROM chunks WHERE item=?1", [i])?;
            Ok(())
        })?;
    }
    Ok(ids.len())
}

/// Permanently drop the local copy of items that have sat in the trash past the retention period.
pub fn purge_trash(app: &App) -> Result<usize> {
    let cutoff = now() - app.cfg.trash_days as i64 * 86400;
    let ids: Vec<String> = app.db.with(|c| {
        let mut st = c.prepare("SELECT id FROM items WHERE deleted=1 AND local='present' AND deleted_at IS NOT NULL AND deleted_at<?1")?;
        let rows = st.query_map([cutoff], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    })?;
    for id in &ids {
        let _ = std::fs::remove_file(library_path(app, id));
        app.db.with(|c| {
            c.execute("UPDATE items SET local='absent' WHERE id=?1", [id])?;
            Ok(())
        })?;
    }
    Ok(ids.len())
}

/// Open an item that is still waiting in review, so the owner can watch it before deciding.
/// Review files are sealed with the same library key, so this is the one read path for them.
pub fn open_review_reader(app: &App, id: &str) -> Result<(Item, EncReader)> {
    let k = keys(app)?;
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if it.local != "quarantine" {
        bail!("item is not waiting in the review area");
    }
    let r = EncReader::open(&quarantine_path(app, id), &k.content_key())?;
    Ok((it, r))
}

/// Fix how a not-yet-approved item is identified (title, type, year, season, episode).
pub fn edit_review(app: &App, id: &str, title: Option<&str>, kind: Option<&str>, year: Option<Option<i32>>, season: Option<Option<i32>>, episode: Option<Option<i32>>) -> Result<()> {
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if it.local != "quarantine" {
        bail!("only items waiting in review can be edited here");
    }
    if let Some(t) = title {
        if t.trim().is_empty() || t.len() > 200 {
            bail!("title must be 1-200 characters");
        }
    }
    if let Some(k) = kind {
        if !["movie", "series", "anime"].contains(&k) {
            bail!("type must be movie, series or anime");
        }
    }
    app.db.with(|c| {
        if let Some(t) = title {
            c.execute("UPDATE items SET title=?1 WHERE id=?2", params![t.trim(), id])?;
        }
        if let Some(k) = kind {
            c.execute("UPDATE items SET kind=?1 WHERE id=?2", params![k, id])?;
            if k == "movie" {
                c.execute("UPDATE items SET season=NULL, episode=NULL WHERE id=?1", [id])?;
            }
        }
        if let Some(v) = year { c.execute("UPDATE items SET year=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = season { c.execute("UPDATE items SET season=?1 WHERE id=?2", params![v, id])?; }
        if let Some(v) = episode { c.execute("UPDATE items SET episode=?1 WHERE id=?2", params![v, id])?; }
        Ok(())
    })?;
    tidy_item(app, id);
    Ok(())
}

pub fn open_reader(app: &App, id: &str) -> Result<(Item, EncReader)> {
    let k = keys(app)?;
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    if it.local != "present" || it.deleted {
        bail!("item is not available on this node");
    }
    let r = EncReader::open(&library_path(app, id), &k.content_key())?;
    Ok((it, r))
}

// ------------------------------------------------------------- synced chunks -> library file

/// Turn fully received sealed chunks into a normal encrypted library file. Needs the keyring unlocked.
pub fn assemble_one(app: &App, id: &str) -> Result<()> {
    let k = keys(app)?;
    let it = app.db.with(|c| get_item(c, id))?.ok_or_else(|| anyhow!("no such item"))?;
    let dir = inbox_dir(app, id);
    let tmp = dir.with_file_name(format!("{id}.assemble"));
    let f = File::create(&tmp)?;
    let mut w = EncWriter::new(BufWriter::new(f), &k.content_key())?;
    for (i, want) in it.chunk_hashes.iter().enumerate() {
        let blob = std::fs::read(dir.join(i.to_string())).with_context(|| format!("missing chunk {i}"))?;
        let pt = unseal(k.sealed_secret(), &blob)?;
        if &blake3::hash(&pt).to_hex().to_string() != want {
            let _ = std::fs::remove_file(&tmp);
            bail!("chunk {i} does not match the catalog");
        }
        w.push(&pt)?;
    }
    let (bw, m) = w.finish()?;
    sync_writer(bw)?;
    if m.id() != id {
        let _ = std::fs::remove_file(&tmp);
        bail!("assembled content does not match its id");
    }
    // never straight into the library: a file from the mesh is scanned here before it counts as ours
    std::fs::rename(&tmp, quarantine_path(app, id))?;
    app.db.with(|c| {
        c.execute("UPDATE items SET local='quarantine', scan=NULL WHERE id=?1", [id])?;
        c.execute("DELETE FROM chunks WHERE item=?1", [id])?;
        Ok(())
    })?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

pub async fn assemble_pending(app: &Shared) -> Result<usize> {
    if !app.keyring.is_unlocked() {
        return Ok(0);
    }
    let ids: Vec<String> = app.db.with(|c| {
        let mut st = c.prepare("SELECT id FROM items WHERE local='assembling'")?;
        let rows = st.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<String>>>()?)
    })?;
    let mut n = 0;
    for id in ids {
        let a = app.clone();
        let id2 = id.clone();
        match tokio::task::spawn_blocking(move || assemble_one(&a, &id2)).await? {
            Ok(()) => {
                n += 1;
                if let Err(e) = crate::quarantine::schedule(app, &id).await {
                    tracing::warn!("scanning {id} failed: {e:#}");
                }
            }
            Err(e) => tracing::warn!("assembling {id} failed: {e:#}"),
        }
    }
    Ok(n)
}

// ------------------------------------------------------------------ streaming

pub fn mime_for(filename: &str) -> &'static str {
    match filename.rsplit('.').next().map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("mp4") | Some("m4v") => "video/mp4",
        Some("webm") => "video/webm",
        Some("mkv") => "video/x-matroska",
        Some("mov") => "video/quicktime",
        Some("avi") => "video/x-msvideo",
        Some("ogv") | Some("ogg") => "video/ogg",
        Some("ts") | Some("m2ts") => "video/mp2t",
        _ => "application/octet-stream",
    }
}

/// Decrypts [start, end_excl) one chunk at a time.
pub fn range_stream(reader: EncReader, start: u64, end_excl: u64) -> impl Stream<Item = std::io::Result<Bytes>> {
    futures_util::stream::unfold((Some(reader), start), move |(reader, pos)| async move {
        let reader = reader?;
        if pos >= end_excl {
            return None;
        }
        let step_end = end_excl.min((pos / CHUNK as u64 + 1) * CHUNK as u64);
        let res = tokio::task::spawn_blocking(move || {
            let mut r = reader;
            let out = r.read_range(pos, step_end);
            (r, out)
        })
        .await;
        match res {
            Ok((r, Ok(data))) => Some((Ok(Bytes::from(data)), (Some(r), step_end))),
            Ok((_, Err(e))) => Some((Err(std::io::Error::other(e.to_string())), (None, end_excl))),
            Err(e) => Some((Err(std::io::Error::other(e.to_string())), (None, end_excl))),
        }
    })
}

struct TranscodeGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for TranscodeGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

// ------------------------------------------------------------------ what a browser can play

#[derive(Clone, Debug, serde::Serialize)]
pub struct Playback {
    /// "direct" (play the file as it is), "remux" (same picture, browser-friendly container) or "transcode" (new picture)
    pub mode: String,
    pub reason: String,
    pub container: String,
    pub vcodec: String,
    pub acodec: String,
    pub width: u64,
    pub height: u64,
    pub duration: f64,
    /// false when the file could not be looked at (play it directly and let the browser say)
    pub known: bool,
}

/// The rule for what the browser needs. `ext` is the file's extension, the rest comes from ffprobe.
pub fn decide(ext: &str, format_name: &str, vcodec: &str, pix_fmt: &str, acodec: &str) -> (&'static str, String) {
    let video_ok = match vcodec {
        "h264" => matches!(pix_fmt, "yuv420p" | "yuvj420p" | ""),
        "vp8" | "vp9" | "av1" => true,
        _ => false,
    };
    if !video_ok {
        let why = if vcodec == "h264" { format!("the picture is {pix_fmt} (10-bit or unusual colour), which browsers cannot show") } else { format!("browsers cannot show {vcodec} video") };
        return ("transcode", why);
    }
    let webm = ext == "webm";
    let audio_ok = acodec.is_empty() || matches!(acodec, "aac" | "mp3" | "opus" | "flac") || (webm && acodec == "vorbis");
    let container_ok = (matches!(ext, "mp4" | "m4v" | "mov") && format_name.contains("mp4")) || (webm && format_name.contains("matroska"));
    if container_ok && audio_ok {
        return ("direct", String::new());
    }
    let why = if !container_ok { format!("browsers do not play .{ext} files directly") } else { format!("the sound is {acodec}, which browsers cannot play") };
    ("remux", why)
}

static PLAYBACK_CACHE: Mutex<Option<std::collections::HashMap<String, Playback>>> = Mutex::new(None);

/// Look inside a library video (it never leaves the node) and say how to play it in a browser.
pub async fn playback_info(app: &Shared, id: &str) -> Result<Playback> {
    if let Some(p) = PLAYBACK_CACHE.lock().unwrap().as_ref().and_then(|m| m.get(id).cloned()) {
        return Ok(p);
    }
    let a = app.clone();
    let id2 = id.to_string();
    let (it, data) = tokio::task::spawn_blocking(move || -> Result<(Item, Vec<u8>)> {
        let (it, mut r) = open_reader(&a, &id2)?;
        let n = r.len.min(crate::quarantine::PROBE_BYTES);
        let d = r.read_range(0, n)?;
        Ok((it, d))
    })
    .await??;
    let ext = it.filename.as_deref().unwrap_or("").rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let (json, _, _) = crate::quarantine::probe(app, data).await;
    let pb = match json {
        Some(v) => {
            let streams = v["streams"].as_array().cloned().unwrap_or_default();
            let vs = streams.iter().find(|s| s["codec_type"] == "video" && s["disposition"]["attached_pic"].as_i64().unwrap_or(0) == 0);
            let au = streams.iter().find(|s| s["codec_type"] == "audio");
            let vcodec = vs.and_then(|s| s["codec_name"].as_str()).unwrap_or("").to_string();
            let pix = vs.and_then(|s| s["pix_fmt"].as_str()).unwrap_or("").to_string();
            let acodec = au.and_then(|s| s["codec_name"].as_str()).unwrap_or("").to_string();
            let fmt = v["format"]["format_name"].as_str().unwrap_or("").to_string();
            let (mode, reason) = if vcodec.is_empty() { ("direct", String::new()) } else { decide(&ext, &fmt, &vcodec, &pix, &acodec) };
            Playback {
                mode: mode.into(),
                reason,
                container: fmt,
                vcodec,
                acodec,
                width: vs.and_then(|s| s["width"].as_u64()).unwrap_or(0),
                height: vs.and_then(|s| s["height"].as_u64()).unwrap_or(0),
                duration: v["format"]["duration"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0),
                known: true,
            }
        }
        None => Playback { mode: "direct".into(), reason: String::new(), container: String::new(), vcodec: String::new(), acodec: String::new(), width: 0, height: 0, duration: 0.0, known: false },
    };
    if pb.known {
        PLAYBACK_CACHE.lock().unwrap().get_or_insert_with(Default::default).insert(id.to_string(), pb.clone());
    }
    Ok(pb)
}

// ------------------------------------------------------------------ preview pictures

static FRAME_GATE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
const FRAME_BYTES: u64 = 24 << 20;

/// A small picture from near the start of a video, for the episode list. Made once, kept encrypted like posters.
pub async fn frame_jpeg(app: &Shared, id: &str) -> Result<Vec<u8>> {
    let key = format!("frame:{id}");
    if let Ok(b) = crate::metadata::poster_bytes(app, &key) {
        return Ok(b);
    }
    let _permit = FRAME_GATE.get_or_init(|| tokio::sync::Semaphore::new(2)).acquire().await?;
    if let Ok(b) = crate::metadata::poster_bytes(app, &key) {
        return Ok(b);
    }
    let a = app.clone();
    let id2 = id.to_string();
    let data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let (_, mut r) = open_reader(&a, &id2)?;
        let n = r.len.min(FRAME_BYTES);
        r.read_range(0, n)
    })
    .await??;
    let plain: Vec<String> = [app.cfg.ffmpeg.as_str(), "-hide_banner", "-loglevel", "error", "-nostdin", "-i", "pipe:0", "-an", "-sn", "-vf", "thumbnail=120,scale=320:-2", "-frames:v", "1", "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "5", "pipe:1"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let (wrapped, label) = crate::scanner::sandboxed_in(plain.clone(), None);
    let mut attempts = vec![(label.clone(), wrapped)];
    if label != "none" {
        attempts.push(("none".into(), plain));
    }
    for (label, argv) in attempts {
        let Ok((out, err, _)) = crate::quarantine::run(&argv, data.clone()).await else { continue };
        if label.starts_with("bubblewrap") && err.contains("bwrap:") {
            continue;
        }
        if out.len() > 200 && out.starts_with(&[0xFF, 0xD8]) {
            crate::metadata::save_poster(app, &key, &out)?;
            return Ok(out);
        }
    }
    bail!("no picture could be made from this video")
}

/// How a video is converted for the browser: how big, how sharp, how much sound data.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Quality {
    pub id: &'static str,
    pub label: &'static str,
    pub detail: &'static str,
    #[serde(skip)]
    pub height: Option<u32>,
    #[serde(skip)]
    pub crf: u8,
    #[serde(skip)]
    pub abr: u32,
    #[serde(skip)]
    pub preset: &'static str,
    /// cap on the video bit rate in kbit/s (0 = none): a stream that spikes above what the link carries stalls the player,
    /// which on Tor is far below what a home connection carries
    #[serde(skip)]
    pub maxrate: u32,
}

pub const QUALITIES: [Quality; 5] = [
    Quality { id: "low", label: "Low (480p)", detail: "Smallest. For slow links such as remote access over Tor.", height: Some(480), crf: 29, abr: 96, preset: "veryfast", maxrate: 1000 },
    Quality { id: "medium", label: "Medium (720p)", detail: "Good on a phone or a modest connection.", height: Some(720), crf: 26, abr: 128, preset: "veryfast", maxrate: 2800 },
    Quality { id: "high", label: "High (1080p)", detail: "Sharp on a TV or laptop. Needs a decent processor and connection.", height: Some(1080), crf: 23, abr: 160, preset: "veryfast", maxrate: 6500 },
    Quality { id: "very_high", label: "Very high (1440p)", detail: "Large screens. Heavy on the processor.", height: Some(1440), crf: 21, abr: 192, preset: "faster", maxrate: 11000 },
    Quality { id: "original", label: "Same size as the file", detail: "Keeps the picture size, only changes the format. Heaviest.", height: None, crf: 20, abr: 192, preset: "faster", maxrate: 0 },
];

pub fn quality_by_id(id: &str) -> Quality {
    QUALITIES.iter().find(|q| q.id == id).cloned().unwrap_or_else(|| QUALITIES[0].clone())
}

/// The quality this node uses when it has to convert a video (the owner picks it in Settings > Playback).
pub fn node_quality(app: &App) -> String {
    let q = app.db.get_setting("transcode_quality").ok().flatten().unwrap_or_default();
    if QUALITIES.iter().any(|x| x.id == q) { q } else { "medium".into() }
}

/// Which video format conversions produce. AV1 is smaller at the same sharpness (the owner's preference), H.264
/// plays on every device. The node falls back to H.264 when its ffmpeg has no AV1 encoder or the browser asking
/// cannot show AV1.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Codec {
    Av1(&'static str),
    H264,
}

/// The AV1 encoder this node's ffmpeg has, best first (SVT-AV1 is the only one fast enough for live conversion
/// on ordinary processors). Looked up once.
pub fn av1_encoder(app: &App) -> Option<&'static str> {
    static FOUND: std::sync::OnceLock<Option<&'static str>> = std::sync::OnceLock::new();
    *FOUND.get_or_init(|| {
        let out = std::process::Command::new(&app.cfg.ffmpeg).args(["-hide_banner", "-encoders"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        ["libsvtav1", "libaom-av1", "librav1e"].into_iter().find(|e| text.split_whitespace().any(|w| w == *e))
    })
}

/// "av1" (default) or "h264": what the owner prefers conversions to produce.
pub fn node_codec(app: &App) -> String {
    match app.db.get_setting("transcode_codec").ok().flatten().as_deref() {
        Some("h264") => "h264".into(),
        _ => "av1".into(),
    }
}

/// The codec to use for one request. `client` is what the browser said it can show ("av1", "h264" or nothing).
pub fn pick_codec(app: &App, client: Option<&str>) -> Codec {
    if node_codec(app) == "av1" && client != Some("h264") {
        if let Some(e) = av1_encoder(app) {
            return Codec::Av1(e);
        }
    }
    Codec::H264
}

fn av1_crf(q: &Quality) -> u8 {
    match q.id {
        "low" => 38,
        "medium" => 35,
        "high" => 32,
        "very_high" => 29,
        _ => 27,
    }
}

/// SVT-AV1 preset (higher is faster): small pictures can afford more effort.
fn av1_speed(q: &Quality) -> u8 {
    match q.id {
        "low" => 12,
        "medium" => 11,
        "high" => 10,
        _ => 9,
    }
}

/// What the browser has to be given for a video.
#[derive(Clone, Debug)]
pub enum Convert {
    /// keep the picture as it is, put it in a container the browser reads (sound is converted only if needed)
    Remux { copy_audio: bool },
    /// re-encode the picture
    Transcode(Quality, Codec),
}

/// Convert a video on the fly for the browser. Decrypted data only ever flows through a pipe.
pub fn transcode_stream(app: &App, reader: EncReader, start_secs: f64, how: Convert) -> Result<impl Stream<Item = std::io::Result<Bytes>>> {
    use tokio::io::AsyncWriteExt;
    use tokio::process::Command;
    let pol = app.policy();
    let t = app.tuning();
    let (cap, threads) = if app.perf_dedicated.load(std::sync::atomic::Ordering::Relaxed) { (t.transcode_max as usize, t.transcode_threads) } else { (t.transcode_max as usize, pol.transcode_threads) };
    let heavy = matches!(how, Convert::Transcode(..));
    // a few conversions at once are fine; past the machine's limit the answer is "busy", not a stalled server
    let active = if heavy { app.active_transcodes.fetch_add(1, std::sync::atomic::Ordering::SeqCst) } else { 0 };
    let guard = heavy.then(|| TranscodeGuard(app.active_transcodes.clone()));
    if heavy && active >= cap.max(1) {
        drop(guard);
        return Err(anyhow!("This node is already converting {} videos for others. Try again in a moment, or pick a lower quality.", cap.max(1)));
    }
    let mut args: Vec<String> = vec![];
    let mut cmd = if pol.nice > 0 {
        args.extend(["-n".into(), pol.nice.to_string(), app.cfg.ffmpeg.clone()]);
        Command::new("nice")
    } else {
        Command::new(&app.cfg.ffmpeg)
    };
    args.extend(["-hide_banner", "-loglevel", "error", "-nostdin"].map(String::from));
    if start_secs > 0.5 {
        args.extend(["-ss".into(), format!("{start_secs:.2}")]);
    }
    args.extend(["-i", "pipe:0", "-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn"].map(String::from));
    match &how {
        Convert::Remux { copy_audio } => {
            args.extend(["-c:v", "copy"].map(String::from));
            if *copy_audio {
                args.extend(["-c:a", "copy"].map(String::from));
            } else {
                args.extend(["-c:a", "aac", "-b:a", "160k", "-ac", "2"].map(String::from));
            }
        }
        Convert::Transcode(q, codec) => {
            let vf = match q.height {
                Some(h) => format!("scale=-2:'min({h},ih)'"),
                None => "scale=trunc(iw/2)*2:trunc(ih/2)*2".to_string(),
            };
            args.extend(["-vf".into(), vf]);
            match codec {
                Codec::H264 => {
                    args.extend(["-c:v".into(), "libx264".into(), "-preset".into(), q.preset.into(), "-crf".into(), q.crf.to_string()]);
                    // a picture every 2 seconds: the player can start after the first couple of seconds instead of the first ten
                    args.extend(["-force_key_frames".into(), "expr:gte(t,n_forced*2)".into()]);
                    if q.maxrate > 0 {
                        args.extend(["-maxrate".into(), format!("{}k", q.maxrate), "-bufsize".into(), format!("{}k", q.maxrate * 2)]);
                    }
                }
                Codec::Av1(enc) => {
                    // AV1 reaches the same look at a higher CRF number than H.264
                    let crf = av1_crf(q);
                    let speed = av1_speed(q);
                    match *enc {
                        "libsvtav1" => {
                            let mut params = format!("lp={}", threads.max(1));
                            if q.maxrate > 0 {
                                params += &format!(":mbr={}", q.maxrate);
                            }
                            args.extend(["-c:v".into(), "libsvtav1".into(), "-preset".into(), speed.to_string(), "-crf".into(), crf.to_string(), "-g".into(), "72".into(), "-svtav1-params".into(), params]);
                        }
                        "libaom-av1" => {
                            let cap = if q.maxrate > 0 { vec!["-b:v".to_string(), format!("{}k", q.maxrate), "-maxrate".into(), format!("{}k", q.maxrate)] } else { vec!["-b:v".to_string(), "0".into()] };
                            args.extend(["-c:v".into(), "libaom-av1".into(), "-cpu-used".into(), "8".into(), "-row-mt".into(), "1".into(), "-crf".into(), crf.to_string()]);
                            args.extend(cap);
                            args.extend(["-g".into(), "72".into()]);
                        }
                        _ => args.extend(["-c:v".into(), "librav1e".into(), "-speed".into(), "10".into(), "-qp".into(), (crf as u32 * 4).to_string(), "-g".into(), "72".into()]),
                    }
                }
            }
            args.extend(["-pix_fmt".into(), "yuv420p".into(), "-threads".into(), threads.max(1).to_string()]);
            args.extend(["-c:a".into(), "aac".into(), "-b:a".into(), format!("{}k", q.abr), "-ac".into(), "2".into()]);
        }
    }
    args.extend(["-movflags", "frag_keyframe+empty_moov+default_base_moof", "-f", "mp4", "pipe:1"].map(String::from));
    cmd.args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    let mut child = cmd.spawn().context("could not start ffmpeg (is it installed?)")?;
    let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;

    let nchunks = reader.nchunks;
    let shared = Arc::new(Mutex::new(reader));
    tokio::spawn(async move {
        for idx in 0..nchunks {
            let r = shared.clone();
            let chunk = tokio::task::spawn_blocking(move || r.lock().unwrap().read_chunk(idx)).await;
            match chunk {
                Ok(Ok(data)) => {
                    if stdin.write_all(&data).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
        let _ = stdin.shutdown().await;
    });
    tokio::spawn(async move {
        let _ = child.wait().await;
        drop(guard);
    });
    Ok(tokio_util::io::ReaderStream::with_capacity(stdout, 64 * 1024))
}

// ------------------------------------------------------------------ private vault

/// Only ever returns the caller's own vault items.
pub fn vault_list(app: &App, user: &str) -> Result<Vec<serde_json::Value>> {
    app.db.with(|c| {
        let mut st = c.prepare(
            "SELECT i.id,i.title,i.size,i.added_at,COALESCE(p.pos,0) FROM items i LEFT JOIN progress p ON p.item=i.id AND p.user=?1
             WHERE i.local='private' AND i.vault_user=?1 ORDER BY i.added_at DESC",
        )?;
        let rows = st.query_map([user], |r| {
            Ok(serde_json::json!({ "id": r.get::<_, String>(0)?, "title": r.get::<_, String>(1)?, "size": r.get::<_, i64>(2)?,
                                   "added_at": r.get::<_, i64>(3)?, "pos": r.get::<_, f64>(4)? }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

fn vault_item(app: &App, id: &str, user: &str) -> Result<Item> {
    app.db
        .with(|c| get_item(c, id))?
        .filter(|i| i.local == "private" && vault_owner(app, &i.id).as_deref() == Some(user))
        .ok_or_else(|| anyhow!("no such item"))
}

fn vault_owner(app: &App, id: &str) -> Option<String> {
    app.db.with(|c| Ok(c.query_row("SELECT vault_user FROM items WHERE id=?1", [id], |r| r.get::<_, Option<String>>(0))?)).ok().flatten()
}

pub fn open_vault_reader(app: &App, id: &str, user: &str) -> Result<(Item, EncReader)> {
    let k = keys(app)?;
    let it = vault_item(app, id, user)?;
    let r = EncReader::open(&vault_path(app, id), &k.content_key())?;
    Ok((it, r))
}

pub fn vault_delete(app: &App, id: &str, user: &str) -> Result<()> {
    vault_item(app, id, user)?;
    let _ = std::fs::remove_file(vault_path(app, id));
    app.db.with(|c| {
        c.execute("DELETE FROM items WHERE id=?1", [id])?;
        c.execute("DELETE FROM progress WHERE item=?1", [id])?;
        Ok(())
    })
}

pub fn vault_rename(app: &App, id: &str, user: &str, title: &str) -> Result<()> {
    vault_item(app, id, user)?;
    let t = title.trim();
    if t.is_empty() || t.len() > 200 {
        bail!("title must be 1-200 characters");
    }
    app.db.with(|c| {
        c.execute("UPDATE items SET title=?2 WHERE id=?1", params![id, t])?;
        Ok(())
    })?;
    tidy_item(app, id);
    Ok(())
}

/// Flush a buffered file writer all the way to disk.
fn sync_writer(bw: BufWriter<File>) -> Result<()> {
    let f = bw.into_inner().map_err(|e| anyhow!("flushing file: {}", e.error()))?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod playback_tests {
    use super::decide;

    #[test]
    fn browsers_get_what_they_can_play() {
        assert_eq!(decide("mp4", "mov,mp4,m4a,3gp,3g2,mj2", "h264", "yuv420p", "aac").0, "direct");
        assert_eq!(decide("mkv", "matroska,webm", "h264", "yuv420p", "aac").0, "remux");
        assert_eq!(decide("mkv", "matroska,webm", "h264", "yuv420p", "ac3").0, "remux");
        assert_eq!(decide("mkv", "matroska,webm", "hevc", "yuv420p10le", "aac").0, "transcode");
        assert_eq!(decide("mkv", "matroska,webm", "h264", "yuv420p10le", "aac").0, "transcode");
        assert_eq!(decide("webm", "matroska,webm", "vp9", "yuv420p", "opus").0, "direct");
        assert_eq!(decide("avi", "avi", "mpeg4", "yuv420p", "mp3").0, "transcode");
        assert_eq!(decide("mp4", "mov,mp4,m4a,3gp,3g2,mj2", "h264", "yuv420p", "ac3").0, "remux");
    }
}

/// Keep the stored file name equal to the title shown (see `util::tidy_name`). Only the label changes, never the bytes.
pub fn tidy_item(app: &App, id: &str) {
    let _ = app.db.with(|c| {
        let row: Option<(String, String, Option<i64>, Option<i64>, Option<i64>, Option<String>)> = c
            .query_row("SELECT title,kind,year,season,episode,filename FROM items WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .optional()?;
        if let Some((t, k, y, s, e, f)) = row {
            let ext = f.as_deref().and_then(|f| f.rsplit_once('.').map(|(_, x)| x.to_string())).unwrap_or_default();
            let want = crate::util::tidy_name(&t, &k, y, s, e, &ext);
            if f.as_deref() != Some(want.as_str()) {
                c.execute("UPDATE items SET filename=?2 WHERE id=?1", params![id, want])?;
            }
        }
        Ok(())
    });
}

/// Every item, once at start: names written by older versions (or by the file they arrived as) become tidy.
pub fn tidy_all(app: &App) {
    let ids: Vec<String> = app.db.with(|c| {
        let mut st = c.prepare("SELECT id FROM items")?;
        let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(v)
    }).unwrap_or_default();
    for id in ids {
        tidy_item(app, &id);
    }
}
