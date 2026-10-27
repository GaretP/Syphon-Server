use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS items(
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL, kind TEXT NOT NULL, year INTEGER, season INTEGER, episode INTEGER,
  size INTEGER NOT NULL, chunk_hashes TEXT NOT NULL,
  author TEXT NOT NULL, added_at INTEGER NOT NULL,
  catalog INTEGER NOT NULL DEFAULT 0,
  deleted INTEGER NOT NULL DEFAULT 0,
  deleted_at INTEGER,
  local TEXT NOT NULL,
  scan TEXT, filename TEXT, source TEXT
);
CREATE INDEX IF NOT EXISTS items_local ON items(local);
CREATE TABLE IF NOT EXISTS ops(
  node TEXT NOT NULL, seq INTEGER NOT NULL, lamport INTEGER NOT NULL, kind TEXT NOT NULL,
  item TEXT, body TEXT NOT NULL, sig TEXT NOT NULL, ts INTEGER NOT NULL,
  PRIMARY KEY(node, seq)
);
CREATE INDEX IF NOT EXISTS ops_item ON ops(item);
CREATE TABLE IF NOT EXISTS peers(
  node_id TEXT PRIMARY KEY, name TEXT NOT NULL, addr TEXT NOT NULL, client_pub TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_seen INTEGER, last_ok INTEGER, last_error TEXT,
  backoff_until INTEGER NOT NULL DEFAULT 0, fails INTEGER NOT NULL DEFAULT 0,
  added_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks(
  item TEXT NOT NULL, idx INTEGER NOT NULL, PRIMARY KEY(item, idx)
);
CREATE TABLE IF NOT EXISTS sync_requests(
  id TEXT PRIMARY KEY, peer TEXT NOT NULL, dir TEXT NOT NULL, items TEXT NOT NULL,
  bytes INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, reason TEXT, token TEXT,
  created INTEGER NOT NULL, expires INTEGER NOT NULL DEFAULT 0, remote_id TEXT
);
CREATE INDEX IF NOT EXISTS sync_requests_peer ON sync_requests(peer, dir, status);
CREATE TABLE IF NOT EXISTS users(
  name TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, role TEXT NOT NULL,
  totp_secret TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_last INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY, user TEXT NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL,
  created INTEGER NOT NULL, last_seen INTEGER NOT NULL, last_via TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, user TEXT NOT NULL, device_name TEXT NOT NULL, code TEXT NOT NULL,
  secret_hash TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pair_invites(
  id TEXT PRIMARY KEY, secret_hash TEXT NOT NULL, tmp_pub TEXT, label TEXT NOT NULL,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pair_requests(
  id TEXT PRIMARY KEY, invite TEXT NOT NULL, node_id TEXT NOT NULL, name TEXT NOT NULL, addr TEXT NOT NULL,
  client_pub TEXT, secret_hash TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL,
  delivered_at INTEGER
);
CREATE TABLE IF NOT EXISTS outgoing_pairs(
  id TEXT PRIMARY KEY, peer_node TEXT NOT NULL, peer_name TEXT NOT NULL, peer_addr TEXT NOT NULL,
  peer_client_pub TEXT, secret TEXT NOT NULL, status TEXT NOT NULL, detail TEXT, created INTEGER NOT NULL,
  invite_id TEXT NOT NULL, invite_secret TEXT NOT NULL, remote_id TEXT
);
CREATE TABLE IF NOT EXISTS sources(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, url TEXT NOT NULL,
  token_enc BLOB, enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS progress(
  user TEXT NOT NULL, item TEXT NOT NULL, pos REAL NOT NULL, updated INTEGER NOT NULL,
  PRIMARY KEY(user, item)
);
CREATE TABLE IF NOT EXISTS downloads(
  id TEXT PRIMARY KEY, provider TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL,
  status TEXT NOT NULL, got INTEGER NOT NULL DEFAULT 0, total INTEGER NOT NULL DEFAULT 0,
  error TEXT, created INTEGER NOT NULL, item TEXT
);
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
-- cast, genres, overview and poster per title (looked up through Tor); `key` is movie or show identity
CREATE TABLE IF NOT EXISTS meta(
  key TEXT PRIMARY KEY, status TEXT NOT NULL, json TEXT, poster INTEGER NOT NULL DEFAULT 0, fetched INTEGER NOT NULL
);
-- genres the owner typed in by hand for one file; they win over the looked-up ones
CREATE TABLE IF NOT EXISTS meta_user(item TEXT PRIMARY KEY, genres TEXT NOT NULL);
-- profile pictures: small images chosen by each user
-- videos already copied in from a drive or share folder (path + size + date), so they are not copied twice
CREATE TABLE IF NOT EXISTS imported(path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime INTEGER NOT NULL, at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS avatars(user TEXT PRIMARY KEY, mime TEXT NOT NULL, data BLOB NOT NULL, updated INTEGER NOT NULL);

"#;

impl Db {
    pub fn open(path: &Path) -> Result<Db> {
        Db::open_with(path, true)
    }

    /// `durable` = fsync on every commit (survives a power cut with nothing lost). Without it a
    /// power cut can lose the last few moments but never corrupts the database.
    pub fn open_with(path: &Path, durable: bool) -> Result<Db> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", if durable { "FULL" } else { "NORMAL" })?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Db(Arc::new(Mutex::new(conn))))
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&g)
    }

    pub fn get_setting(&self, k: &str) -> Result<Option<String>> {
        self.with(|c| Ok(c.query_row("SELECT v FROM settings WHERE k=?1", [k], |r| r.get(0)).optional()?))
    }

    pub fn set_setting(&self, k: &str, v: &str) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO settings(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                params![k, v],
            )?;
            Ok(())
        })
    }
}

fn has_col(c: &Connection, table: &str, col: &str) -> Result<bool> {
    let mut st = c.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = st.query_map([], |r| r.get::<_, String>(1))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.iter().any(|n| n == col))
}

/// Upgrades databases written by earlier builds (the original "Hearth" release) in place.
fn migrate(c: &Connection) -> Result<()> {
    for (col, ddl) in [
        ("totp_secret", "ALTER TABLE users ADD COLUMN totp_secret TEXT"),
        ("totp_enabled", "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0"),
        ("totp_last", "ALTER TABLE users ADD COLUMN totp_last INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !has_col(c, "users", col)? {
            c.execute(ddl, [])?;
        }
    }
    for (col, ddl) in [
        ("finished", "ALTER TABLE downloads ADD COLUMN finished INTEGER"),
        ("kind_hint", "ALTER TABLE downloads ADD COLUMN kind_hint TEXT"),
    ] {
        if !has_col(c, "downloads", col)? {
            c.execute(ddl, [])?;
        }
    }
    // a trusted device can be "remembered": an app on it may sign that person in again without the password
    if !has_col(c, "devices", "remember")? {
        c.execute("ALTER TABLE devices ADD COLUMN remember INTEGER NOT NULL DEFAULT 0", [])?;
    }
    // private-vault items belong to one user and are never part of the shared catalog
    if !has_col(c, "items", "vault_user")? {
        c.execute("ALTER TABLE items ADD COLUMN vault_user TEXT", [])?;
    }
    Ok(())
}

#[derive(Serialize, Clone, Debug)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub year: Option<i32>,
    pub season: Option<i32>,
    pub episode: Option<i32>,
    pub size: i64,
    #[serde(skip)]
    pub chunk_hashes: Vec<String>,
    pub author: String,
    pub added_at: i64,
    pub catalog: bool,
    pub deleted: bool,
    pub deleted_at: Option<i64>,
    pub local: String,
    pub scan: Option<serde_json::Value>,
    pub filename: Option<String>,
    pub source: Option<String>,
}

pub const ITEM_COLS: &str =
    "id,title,kind,year,season,episode,size,chunk_hashes,author,added_at,catalog,deleted,deleted_at,local,scan,filename,source";
/// Same columns without parsing the (large) chunk hash list.
pub const ITEM_LIGHT: &str =
    "id,title,kind,year,season,episode,size,'[]' AS chunk_hashes,author,added_at,catalog,deleted,deleted_at,local,scan,filename,source";

impl Item {
    pub fn from_row(r: &Row) -> rusqlite::Result<Item> {
        let hashes: String = r.get(7)?;
        let scan: Option<String> = r.get(14)?;
        Ok(Item {
            id: r.get(0)?,
            title: r.get(1)?,
            kind: r.get(2)?,
            year: r.get(3)?,
            season: r.get(4)?,
            episode: r.get(5)?,
            size: r.get(6)?,
            chunk_hashes: serde_json::from_str(&hashes).unwrap_or_default(),
            author: r.get(8)?,
            added_at: r.get(9)?,
            catalog: r.get::<_, i64>(10)? != 0,
            deleted: r.get::<_, i64>(11)? != 0,
            deleted_at: r.get(12)?,
            local: r.get(13)?,
            scan: scan.and_then(|s| serde_json::from_str(&s).ok()),
            filename: r.get(15)?,
            source: r.get(16)?,
        })
    }
}

pub fn get_item(c: &Connection, id: &str) -> Result<Option<Item>> {
    Ok(c
        .query_row(&format!("SELECT {ITEM_COLS} FROM items WHERE id=?1"), [id], Item::from_row)
        .optional()?)
}

#[derive(Serialize, Clone, Debug)]
pub struct Peer {
    pub node_id: String,
    pub name: String,
    pub addr: String,
    pub client_pub: Option<String>,
    pub enabled: bool,
    pub last_seen: Option<i64>,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    pub backoff_until: i64,
    pub fails: i64,
    pub added_at: i64,
}

impl Peer {
    pub fn from_row(r: &Row) -> rusqlite::Result<Peer> {
        Ok(Peer {
            node_id: r.get(0)?,
            name: r.get(1)?,
            addr: r.get(2)?,
            client_pub: r.get(3)?,
            enabled: r.get::<_, i64>(4)? != 0,
            last_seen: r.get(5)?,
            last_ok: r.get(6)?,
            last_error: r.get(7)?,
            backoff_until: r.get(8)?,
            fails: r.get(9)?,
            added_at: r.get(10)?,
        })
    }
}

pub const PEER_COLS: &str =
    "node_id,name,addr,client_pub,enabled,last_seen,last_ok,last_error,backoff_until,fails,added_at";

pub fn list_peers(c: &Connection) -> Result<Vec<Peer>> {
    let mut st = c.prepare(&format!("SELECT {PEER_COLS} FROM peers ORDER BY name"))?;
    let rows = st.query_map([], Peer::from_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get_peer(c: &Connection, node_id: &str) -> Result<Option<Peer>> {
    Ok(c
        .query_row(&format!("SELECT {PEER_COLS} FROM peers WHERE node_id=?1"), [node_id], Peer::from_row)
        .optional()?)
}

#[derive(Serialize, Clone, Debug)]
pub struct SyncRequest {
    pub id: String,
    pub peer: String,
    pub dir: String,
    pub items: Vec<String>,
    pub bytes: i64,
    pub status: String,
    pub reason: Option<String>,
    #[serde(skip)]
    pub token: Option<String>,
    pub created: i64,
    pub expires: i64,
    pub remote_id: Option<String>,
}

pub const REQ_COLS: &str = "id,peer,dir,items,bytes,status,reason,token,created,expires,remote_id";

impl SyncRequest {
    pub fn from_row(r: &Row) -> rusqlite::Result<SyncRequest> {
        let items: String = r.get(3)?;
        Ok(SyncRequest {
            id: r.get(0)?,
            peer: r.get(1)?,
            dir: r.get(2)?,
            items: serde_json::from_str(&items).unwrap_or_default(),
            bytes: r.get(4)?,
            status: r.get(5)?,
            reason: r.get(6)?,
            token: r.get(7)?,
            created: r.get(8)?,
            expires: r.get(9)?,
            remote_id: r.get(10)?,
        })
    }
}

pub fn get_request(c: &Connection, id: &str) -> Result<Option<SyncRequest>> {
    Ok(c
        .query_row(&format!("SELECT {REQ_COLS} FROM sync_requests WHERE id=?1"), [id], SyncRequest::from_row)
        .optional()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_and_settings() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("t.db")).unwrap();
        assert!(db.get_setting("x").unwrap().is_none());
        db.set_setting("x", "1").unwrap();
        db.set_setting("x", "2").unwrap();
        assert_eq!(db.get_setting("x").unwrap().as_deref(), Some("2"));
    }
}
