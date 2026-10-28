//! The replicated catalog.
//!
//! Every change (add / delete / restore / meta) is an operation signed by the node that made it
//! and numbered per node (`seq`). Nodes exchange "heads" (highest seq per author) in their
//! heartbeat and pull the operations they miss, from any peer, since every op is independently
//! verifiable. Item state is a pure fold over the set of operations (ordered by lamport clock,
//! then node id), so every node converges to the same catalog no matter the arrival order.

use crate::db::{Item, ITEM_COLS};
use crate::state::{verify_sig, App, Identity};
use crate::util::now;
use crate::keyring::manifest_id;
use anyhow::{bail, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Op {
    pub node: String,
    pub seq: i64,
    pub lamport: i64,
    pub kind: String,
    pub body: String,
    pub sig: String,
    pub ts: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AddBody {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub year: Option<i32>,
    pub season: Option<i32>,
    pub episode: Option<i32>,
    pub size: u64,
    pub chunk_hashes: Vec<String>,
    pub added_at: i64,
    pub filename: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IdBody {
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MetaBody {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub year: Option<i32>,
    pub season: Option<i32>,
    pub episode: Option<i32>,
}

fn signing_bytes(node: &str, seq: i64, lamport: i64, kind: &str, body: &str) -> Vec<u8> {
    format!("hearth-op-v1\n{node}\n{seq}\n{lamport}\n{kind}\n{body}").into_bytes()
}

fn item_of(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("id")?
        .as_str()
        .map(|s| s.to_string())
}

/// Create, sign, store and apply a new local operation.
pub fn emit_conn<T: Serialize>(c: &Connection, ident: &Identity, kind: &str, body: &T) -> Result<Op> {
    let body = serde_json::to_string(body)?;
    let tx = c.unchecked_transaction()?;
    let seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq),0)+1 FROM ops WHERE node=?1", [&ident.id], |r| r.get(0))?;
    let lamport: i64 = tx.query_row("SELECT COALESCE(MAX(lamport),0)+1 FROM ops", [], |r| r.get(0))?;
    let sig = ident.sign(&signing_bytes(&ident.id, seq, lamport, kind, &body));
    let op = Op { node: ident.id.clone(), seq, lamport, kind: kind.into(), body, sig, ts: now() };
    store(&tx, &op)?;
    tx.commit()?;
    Ok(op)
}

pub fn emit<T: Serialize>(app: &App, kind: &str, body: &T) -> Result<Op> {
    app.db.with(|c| emit_conn(c, &app.id, kind, body))
}

fn store(c: &Connection, op: &Op) -> Result<()> {
    let item = item_of(&op.body);
    let n = c.execute(
        "INSERT OR IGNORE INTO ops(node,seq,lamport,kind,item,body,sig,ts) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![op.node, op.seq, op.lamport, op.kind, item, op.body, op.sig, op.ts],
    )?;
    if n > 0 {
        if let Some(id) = item {
            refold(c, &id)?;
        }
    }
    Ok(())
}

/// Apply operations received from a peer. Returns how many were new.
/// Rejects bad signatures, unknown authors and gaps in an author's sequence.
pub fn apply_remote_conn(c: &Connection, own_id: &str, ops: &[Op]) -> Result<usize> {
    let mut applied = 0;
    let tx = c.unchecked_transaction()?;
    for op in ops {
        if op.node == own_id {
            continue;
        }
        let known: i64 = tx.query_row("SELECT COUNT(*) FROM peers WHERE node_id=?1", [&op.node], |r| r.get(0))?;
        if known == 0 {
            bail!("operation from unknown node {}", &op.node[..8.min(op.node.len())]);
        }
        if !matches!(op.kind.as_str(), "add" | "delete" | "restore" | "meta") {
            bail!("unknown operation kind {}", op.kind);
        }
        if !verify_sig(&op.node, &signing_bytes(&op.node, op.seq, op.lamport, &op.kind, &op.body), &op.sig) {
            bail!("bad signature on operation {}#{}", &op.node[..8.min(op.node.len())], op.seq);
        }
        let head: i64 = tx.query_row("SELECT COALESCE(MAX(seq),0) FROM ops WHERE node=?1", [&op.node], |r| r.get(0))?;
        if op.seq <= head {
            continue;
        }
        if op.seq != head + 1 {
            bail!("gap in operations from {} (have {}, got {})", &op.node[..8.min(op.node.len())], head, op.seq);
        }
        store(&tx, op)?;
        applied += 1;
    }
    tx.commit()?;
    Ok(applied)
}

pub fn apply_remote(app: &App, ops: &[Op]) -> Result<usize> {
    app.db.with(|c| apply_remote_conn(c, &app.id.id, ops))
}

pub fn heads(c: &Connection) -> Result<BTreeMap<String, i64>> {
    let mut st = c.prepare("SELECT node, MAX(seq) FROM ops GROUP BY node")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()?)
}

pub fn ops_after(c: &Connection, node: &str, after: i64, limit: i64) -> Result<Vec<Op>> {
    let mut st = c.prepare(
        "SELECT node,seq,lamport,kind,body,sig,ts FROM ops WHERE node=?1 AND seq>?2 ORDER BY seq LIMIT ?3",
    )?;
    let rows = st.query_map(params![node, after, limit], |r| {
        Ok(Op {
            node: r.get(0)?,
            seq: r.get(1)?,
            lamport: r.get(2)?,
            kind: r.get(3)?,
            body: r.get(4)?,
            sig: r.get(5)?,
            ts: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Recompute the replicated columns of one item from its operations.
pub fn refold(c: &Connection, id: &str) -> Result<()> {
    let mut st = c.prepare("SELECT node,kind,body,ts FROM ops WHERE item=?1 ORDER BY lamport, node, seq")?;
    let rows: Vec<(String, String, String, i64)> = st
        .query_map([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut add: Option<(String, AddBody)> = None;
    let mut deleted = false;
    let mut deleted_at: Option<i64> = None;
    let mut meta: Option<MetaBody> = None;
    for (node, kind, body, ts) in rows {
        match kind.as_str() {
            "add" => {
                if add.is_none() {
                    if let Ok(b) = serde_json::from_str::<AddBody>(&body) {
                        add = Some((node, b));
                    }
                }
            }
            "delete" => {
                deleted = true;
                deleted_at = Some(ts);
            }
            "restore" => {
                deleted = false;
                deleted_at = None;
            }
            "meta" => {
                if let Ok(m) = serde_json::from_str::<MetaBody>(&body) {
                    meta = Some(m);
                }
            }
            _ => {}
        }
    }
    let Some((author, a)) = add else { return Ok(()) };
    if manifest_id(a.size, &a.chunk_hashes) != a.id {
        return Ok(()); // malformed add: the id must commit to the manifest
    }
    let (title, kind, year, season, episode) = match meta {
        Some(m) => (m.title, m.kind, m.year, m.season, m.episode),
        None => (a.title.clone(), a.kind.clone(), a.year, a.season, a.episode),
    };
    c.execute(
        "INSERT INTO items(id,title,kind,year,season,episode,size,chunk_hashes,author,added_at,catalog,deleted,deleted_at,local,filename)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,1,?11,?12,'absent',?13)
         ON CONFLICT(id) DO UPDATE SET title=excluded.title, kind=excluded.kind, year=excluded.year,
           season=excluded.season, episode=excluded.episode, size=excluded.size,
           chunk_hashes=excluded.chunk_hashes, catalog=1, deleted=excluded.deleted, deleted_at=excluded.deleted_at",
        params![
            id,
            title,
            kind,
            year,
            season,
            episode,
            a.size as i64,
            serde_json::to_string(&a.chunk_hashes)?,
            author,
            a.added_at,
            deleted as i64,
            deleted_at,
            a.filename
        ],
    )?;
    Ok(())
}

/// What other nodes get to see instead of the original file name: the cleaned-up title plus a safe
/// extension. Names such as "Movie.2019.1080p.RARBG.mkv" (release groups, sources) never leave this node.
pub fn public_filename(it: &Item) -> String {
    let ext = it
        .filename
        .as_deref()
        .and_then(|f| f.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()))
        .filter(|e| ["mp4", "m4v", "mkv", "webm", "mov", "avi", "ogv", "ts", "m2ts", "mpg"].contains(&e.as_str()))
        .unwrap_or_else(|| "mp4".into());
    crate::util::tidy_name(&it.title, &it.kind, it.year.map(|v| v as i64), it.season.map(|v| v as i64), it.episode.map(|v| v as i64), &ext)
}

pub fn add_body(it: &Item) -> AddBody {
    AddBody {
        id: it.id.clone(),
        title: it.title.clone(),
        kind: it.kind.clone(),
        year: it.year,
        season: it.season,
        episode: it.episode,
        size: it.size as u64,
        chunk_hashes: it.chunk_hashes.clone(),
        added_at: it.added_at,
        filename: Some(public_filename(it)),
    }
}

/// Items that belong to the shared library (replicated, not deleted).
pub fn library_items(c: &Connection) -> Result<Vec<Item>> {
    let mut st = c.prepare(&format!("SELECT {ITEM_COLS} FROM items WHERE catalog=1 AND deleted=0"))?;
    let rows = st.query_map([], Item::from_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::keyring::Manifest;

    struct N {
        id: Identity,
        db: Db,
        _d: tempfile::TempDir,
    }

    fn node() -> N {
        let d = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(&d.path().join("id")).unwrap();
        let db = Db::open(&d.path().join("db")).unwrap();
        N { id, db, _d: d }
    }

    fn befriend(a: &N, b: &N) {
        for (x, y) in [(a, b), (b, a)] {
            x.db.with(|c| {
                c.execute(
                    "INSERT INTO peers(node_id,name,addr,added_at) VALUES(?1,'p','x',0)",
                    [&y.id.id],
                )?;
                Ok(())
            })
            .unwrap();
        }
    }

    fn add_op(n: &N, title: &str) -> (Op, String) {
        let m = Manifest { size: 5, chunk_hashes: vec![blake3::hash(title.as_bytes()).to_hex().to_string()] };
        let id = m.id();
        let body = AddBody {
            id: id.clone(),
            title: title.into(),
            kind: "movie".into(),
            year: Some(1999),
            season: None,
            episode: None,
            size: 5,
            chunk_hashes: m.chunk_hashes,
            added_at: 1,
            filename: None,
        };
        (n.db.with(|c| emit_conn(c, &n.id, "add", &body)).unwrap(), id)
    }

    fn item(n: &N, id: &str) -> Option<Item> {
        n.db.with(|c| crate::db::get_item(c, id)).unwrap()
    }

    #[test]
    fn ops_replicate_and_converge_in_any_order() {
        let (a, b, c) = (node(), node(), node());
        befriend(&a, &b);
        befriend(&a, &c);
        befriend(&b, &c);

        let (add, id) = add_op(&a, "Metropolis");
        let del = b.db.with(|cn| {
            // B learns of the add, then deletes it
            apply_remote_conn(cn, &b.id.id, &[add.clone()])?;
            emit_conn(cn, &b.id, "delete", &IdBody { id: id.clone() })
        }).unwrap();

        // C receives the delete BEFORE the add (out of causal order) and from different peers
        c.db.with(|cn| apply_remote_conn(cn, &c.id.id, &[del.clone()])).unwrap();
        assert!(item(&c, &id).is_none(), "no item row until the add arrives");
        c.db.with(|cn| apply_remote_conn(cn, &c.id.id, &[add.clone()])).unwrap();
        let it = item(&c, &id).unwrap();
        assert!(it.deleted && it.catalog && it.local == "absent");

        // restore wins because it is later in lamport order
        let res = b.db.with(|cn| emit_conn(cn, &b.id, "restore", &IdBody { id: id.clone() })).unwrap();
        c.db.with(|cn| apply_remote_conn(cn, &c.id.id, &[res])).unwrap();
        assert!(!item(&c, &id).unwrap().deleted);

        // heads reflect what each node holds
        let h = c.db.with(heads).unwrap();
        assert_eq!(h.get(&a.id.id), Some(&1));
        assert_eq!(h.get(&b.id.id), Some(&2));
    }

    #[test]
    fn rejects_forgery_gaps_and_strangers() {
        let (a, b) = (node(), node());
        befriend(&a, &b);
        let (add, _) = add_op(&a, "One");
        let (add2, _) = add_op(&a, "Two");

        let mut forged = add.clone();
        forged.body = forged.body.replace("One", "Evil");
        assert!(b.db.with(|c| apply_remote_conn(c, &b.id.id, &[forged])).is_err());

        // gap: seq 2 without seq 1
        assert!(b.db.with(|c| apply_remote_conn(c, &b.id.id, &[add2.clone()])).is_err());
        assert_eq!(b.db.with(|c| apply_remote_conn(c, &b.id.id, &[add.clone(), add2.clone()])).unwrap(), 2);
        // idempotent
        assert_eq!(b.db.with(|c| apply_remote_conn(c, &b.id.id, &[add, add2])).unwrap(), 0);

        // stranger
        let s = node();
        let (sadd, _) = add_op(&s, "Sneaky");
        assert!(b.db.with(|c| apply_remote_conn(c, &b.id.id, &[sadd])).is_err());
    }

    #[test]
    fn add_must_commit_to_its_manifest() {
        let (a, b) = (node(), node());
        befriend(&a, &b);
        let body = AddBody {
            id: "deadbeef".into(),
            title: "Fake".into(),
            kind: "movie".into(),
            year: None,
            season: None,
            episode: None,
            size: 1,
            chunk_hashes: vec!["00".into()],
            added_at: 1,
            filename: None,
        };
        let op = a.db.with(|c| emit_conn(c, &a.id, "add", &body)).unwrap();
        b.db.with(|c| apply_remote_conn(c, &b.id.id, &[op])).unwrap();
        assert!(item(&b, "deadbeef").is_none());
    }
}
