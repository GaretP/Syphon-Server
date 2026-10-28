//! The sync engine. One pass per peer follows the request-based flow:
//!
//!   heartbeat out -> compare heads -> pull missing catalog entries -> "do I need anything?"
//!   -> request sync -> yes / no / waiting for a human -> capped, verified chunk transfer.
//!
//! Nothing is pushed: a node only ever receives what it asked for and the other side agreed to
//! serve. Every cap in `SyncPolicy` is checked before a request is sent and again per chunk,
//! so the stop switch and the limits take effect mid-transfer.

use crate::catalog;
use crate::db::{get_peer, list_peers, Item, Peer, SyncRequest, REQ_COLS};
use crate::mesh::{HttpErr, PeerClient, SyncAnswer};
use crate::state::{App, Shared, Transfer};
use crate::util::{now, random_hex};
use crate::keyring::seal;
use anyhow::{anyhow, bail, Result};
use futures_util::stream::{self, StreamExt};
use rusqlite::{params, OptionalExtension};
use std::time::Duration;

/// Set when someone asked for something now: sleeping peers are woken for it.
static FORCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
/// How often a peer that sleeps when idle is checked on.
const SLEEPER_POLL_SECS: i64 = 1800;

pub async fn run(app: Shared) {
    let mut ticks = 0u64;
    loop {
        if app.is_shutting_down() {
            return;
        }
        cycle(&app).await;
        FORCE.store(false, std::sync::atomic::Ordering::SeqCst);
        ticks += 1;
        if ticks % 200 == 0 {
            let _ = crate::library::purge_trash(&app);
        }
        let wait = Duration::from_secs(app.cfg.heartbeat_secs.max(1));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = app.wake.notified() => { FORCE.store(true, std::sync::atomic::Ordering::SeqCst); }
            _ = app.shutdown.notified() => { return; }
        }
    }
}

/// One pass over every paired peer.
pub async fn cycle(app: &Shared) {
    let peers = match app.db.with(list_peers) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("listing peers: {e:#}");
            return;
        }
    };
    for p in peers.into_iter().filter(|p| p.enabled) {
        if let Err(e) = sync_peer(app, &p).await {
            tracing::debug!("sync with {}: {e:#}", p.name);
        }
    }
}

fn note_failure(app: &App, peer: &Peer, err: &str, offline: bool) {
    let fails = peer.fails + 1;
    let backoff = (15i64 * 2i64.pow(fails.min(6) as u32)).min(900);
    let _ = app.db.with(|c| {
        c.execute(
            "UPDATE peers SET last_error=?2, fails=?3, backoff_until=?4 WHERE node_id=?1",
            params![peer.node_id, err, fails, now() + backoff],
        )?;
        Ok(())
    });
    let mut g = app.live.lock().unwrap();
    let e = g.entry(peer.node_id.clone()).or_default();
    e.online = !offline;
    e.updated = now();
}

fn note_ok(app: &App, peer: &Peer) {
    let _ = app.db.with(|c| {
        c.execute(
            "UPDATE peers SET last_ok=?2, last_error=NULL, fails=0, backoff_until=0 WHERE node_id=?1",
            params![peer.node_id, now()],
        )?;
        Ok(())
    });
    app.live.lock().unwrap().entry(peer.node_id.clone()).or_default().online = true;
}

/// Items this node still wants (known from the catalog, not held locally).
fn needed(app: &App) -> Result<Vec<Item>> {
    let pol = app.policy();
    app.db.with(|c| {
        let mut st = c.prepare(&format!(
            "SELECT {} FROM items WHERE catalog=1 AND deleted=0 AND local IN ('absent','syncing') ORDER BY added_at",
            crate::db::ITEM_COLS
        ))?;
        let rows = st.query_map([], Item::from_row)?;
        let all = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(all.into_iter().filter(|i| pol.wants_kind(&i.kind)).collect())
    })
}

pub async fn sync_peer(app: &Shared, peer: &Peer) -> Result<()> {
    let pid = peer.node_id.clone();
    // Our own caps first: when sync is stopped we stay silent toward every peer.
    if let Err(reason) = app.gate() {
        app.set_live(&pid, "paused", format!("not syncing: {reason}"));
        return Ok(());
    }
    let peer = &app.db.with(|c| get_peer(c, &pid))?.ok_or_else(|| anyhow!("peer removed"))?;
    if peer.backoff_until > now() {
        return Ok(());
    }
    if !FORCE.load(std::sync::atomic::Ordering::SeqCst) {
        let until = app.live.lock().unwrap().get(&pid).map(|l| l.asleep_until).unwrap_or(0);
        if until > now() {
            app.set_live(&pid, "asleep", "sleeps when idle to save power; checked on every 30 minutes");
            return Ok(());
        }
    }
    let client = PeerClient::new(app, peer)?;

    // 1. heartbeat out
    app.set_live(&pid, "heartbeat", "sending heartbeat");
    let hb = match client.heartbeat().await {
        Ok(h) => h,
        Err(e) => {
            let offline = e.downcast_ref::<HttpErr>().is_none();
            note_failure(app, peer, &format!("{e:#}"), offline);
            app.set_live(&pid, if offline { "offline" } else { "refused" }, crate::util::friendly_error(&e));
            return Err(e);
        }
    };
    note_ok(app, peer);
    {
        let mut g = app.live.lock().unwrap();
        let l = g.entry(pid.clone()).or_default();
        l.online = true;
        l.their_enabled = Some(hb.enabled);
        l.their_mode = Some(hb.mode.clone());
        l.asleep_until = if hb.sleeper { now() + SLEEPER_POLL_SECS } else { 0 };
    }
    if !hb.enabled {
        app.set_live(&pid, "peer paused", hb.reason.clone().unwrap_or_else(|| "peer is not syncing".into()));
        return Ok(());
    }

    // 2. catalog: pull operations we are missing (from any author, verified by signature)
    let mine = app.db.with(catalog::heads)?;
    let paired: std::collections::HashSet<String> =
        app.db.with(list_peers)?.into_iter().map(|p| p.node_id).collect();
    for (node, theirs) in &hb.heads {
        if node == &app.id.id || !paired.contains(node) {
            continue; // only entries from nodes we paired with are trusted
        }
        let mut have = *mine.get(node).unwrap_or(&0);
        while have < *theirs {
            let ops = client.ops(node, have).await?;
            if ops.is_empty() {
                break;
            }
            let applied = catalog::apply_remote(app, &ops)?;
            let new_have = ops.iter().filter(|o| &o.node == node).map(|o| o.seq).max().unwrap_or(have);
            if applied == 0 && new_have <= have {
                break;
            }
            have = new_have;
        }
    }

    // 3. do we need anything?
    let mut want = needed(app)?;
    let bytes_cap = app.policy().batch_gb as u64 * (1 << 30);
    if bytes_cap > 0 {
        let mut total = 0u64;
        want.retain(|i| {
            total += i.size as u64;
            total <= bytes_cap || total == i.size as u64
        });
    }
    if want.is_empty() {
        app.set_live(&pid, "in sync", "nothing to fetch");
        app.live.lock().unwrap().entry(pid.clone()).or_default().need = 0;
        return Ok(());
    }
    app.live.lock().unwrap().entry(pid.clone()).or_default().need = want.len();
    app.set_live(&pid, "need sync", format!("{} item(s) missing", want.len()));
    let ids: Vec<String> = want.iter().map(|i| i.id.clone()).collect();

    // 4. is there a request we already sent that is still open?
    let open: Option<SyncRequest> = app.db.with(|c| {
        Ok(c.query_row(
            &format!("SELECT {REQ_COLS} FROM sync_requests WHERE peer=?1 AND dir='out' AND status IN ('pending','approved') AND expires>?2 ORDER BY created DESC LIMIT 1"),
            params![pid, now()],
            SyncRequest::from_row,
        )
        .optional()?)
    })?;

    let answer: SyncAnswer;
    let local_id: String;
    match open {
        Some(row) if row.remote_id.is_some() => {
            app.set_live(&pid, "waiting", "checking on the request we sent");
            answer = client.status(row.remote_id.as_deref().unwrap()).await?;
            local_id = row.id;
        }
        _ => {
            app.set_live(&pid, "requested", format!("asking for {} item(s)", ids.len()));
            answer = client.ask(&ids).await?;
            local_id = random_hex(8);
            app.db.with(|c| {
                c.execute(
                    "INSERT INTO sync_requests(id,peer,dir,items,bytes,status,reason,token,created,expires,remote_id) VALUES(?1,?2,'out',?3,?4,?5,?6,?7,?8,?9,?10)",
                    params![
                        local_id,
                        pid,
                        serde_json::to_string(&ids)?,
                        want.iter().map(|i| i.size).sum::<i64>(),
                        answer.status,
                        answer.reason,
                        answer.token,
                        now(),
                        answer.expires.max(now() + 3600),
                        answer.request_id
                    ],
                )?;
                Ok(())
            })?;
        }
    }
    app.db.with(|c| {
        c.execute(
            "UPDATE sync_requests SET status=?2, reason=?3, token=?4, expires=?5 WHERE id=?1",
            params![local_id, answer.status, answer.reason, answer.token, answer.expires.max(now() + 60)],
        )?;
        Ok(())
    })?;

    // 5. yes / no / not yet
    match answer.status.as_str() {
        "approved" => {
            let token = answer.token.clone().ok_or_else(|| anyhow!("approved without a token"))?;
            let todo: Vec<Item> = want.into_iter().filter(|i| answer.available.contains(&i.id)).collect();
            app.set_live(&pid, "approved", format!("{} item(s) approved, transferring", todo.len()));
            let res = transfer(app, &client, peer, &token, todo).await;
            app.db.with(|c| {
                c.execute("UPDATE sync_requests SET status='done' WHERE id=?1", [&local_id])?;
                Ok(())
            })?;
            match res {
                Ok(()) => app.set_live(&pid, "in sync", "transfer complete"),
                Err(e) => app.set_live(&pid, "interrupted", crate::util::friendly_error(&e)),
            }
        }
        "pending" => {
            app.set_live(&pid, "waiting", "waiting for the other side to say yes or no");
        }
        _ => {
            let why = answer.reason.unwrap_or_else(|| "no reason given".into());
            app.set_live(&pid, "declined", format!("the other side said no: {why}"));
            app.db.with(|c| {
                c.execute("UPDATE sync_requests SET status='denied' WHERE id=?1", [&local_id])?;
                c.execute(
                    "UPDATE peers SET backoff_until=?2 WHERE node_id=?1",
                    params![pid, now() + 600],
                )?;
                Ok(())
            })?;
        }
    }
    Ok(())
}

async fn transfer(app: &Shared, client: &PeerClient, peer: &Peer, token: &str, items: Vec<Item>) -> Result<()> {
    for it in items {
        if let Err(e) = fetch_item(app, client, peer, token, &it).await {
            app.transfers.lock().unwrap().remove(&it.id);
            return Err(e);
        }
    }
    Ok(())
}

fn chunk_file(app: &App, item: &str, idx: usize) -> std::path::PathBuf {
    crate::library::inbox_dir(app, item).join(idx.to_string())
}

async fn fetch_item(app: &Shared, client: &PeerClient, peer: &Peer, token: &str, it: &Item) -> Result<()> {
    let total = it.chunk_hashes.len() as u64;
    let dir = crate::library::inbox_dir(app, &it.id);
    std::fs::create_dir_all(&dir)?;
    let have: std::collections::HashSet<i64> = app.db.with(|c| {
        let mut st = c.prepare("SELECT idx FROM chunks WHERE item=?1")?;
        let rows = st.query_map([&it.id], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    })?;
    let missing: Vec<usize> = (0..it.chunk_hashes.len()).filter(|i| !have.contains(&(*i as i64))).collect();
    app.db.with(|c| {
        c.execute("UPDATE items SET local='syncing' WHERE id=?1 AND local='absent'", [&it.id])?;
        Ok(())
    })?;
    app.transfers.lock().unwrap().insert(
        it.id.clone(),
        Transfer {
            item: it.id.clone(),
            title: it.title.clone(),
            peer: peer.name.clone(),
            chunks_done: total - missing.len() as u64,
            chunks_total: total,
            state: "transferring".into(),
        },
    );

    let conc = app.streams();
    let sealed_pub = app.keyring.sealed_pub();
    let mut results = stream::iter(missing)
        .map(|idx| {
            let app = app.clone();
            let token = token.to_string();
            let item = it.id.clone();
            let want = it.chunk_hashes[idx].clone();
            async move { fetch_chunk(&app, client, &token, &item, idx, &want, sealed_pub).await }
        })
        .buffer_unordered(conc);

    while let Some(r) = results.next().await {
        let idx = r?;
        app.db.with(|c| {
            c.execute("INSERT OR IGNORE INTO chunks(item,idx) VALUES(?1,?2)", params![it.id, idx as i64])?;
            Ok(())
        })?;
        if let Some(t) = app.transfers.lock().unwrap().get_mut(&it.id) {
            t.chunks_done += 1;
        }
    }
    drop(results);

    app.db.with(|c| {
        c.execute("UPDATE items SET local='assembling' WHERE id=?1", [&it.id])?;
        Ok(())
    })?;
    app.transfers.lock().unwrap().remove(&it.id);
    if app.keyring.is_unlocked() {
        let a = app.clone();
        let id = it.id.clone();
        tokio::task::spawn_blocking(move || crate::library::assemble_one(&a, &id)).await??;
        // nothing from the mesh joins the library, or is shared onward, until this node has scanned it
        if let Err(e) = crate::quarantine::schedule(app, &it.id).await {
            tracing::warn!("scanning {} failed: {e:#}", it.id);
        }
    }
    Ok(())
}

async fn fetch_chunk(
    app: &Shared,
    client: &PeerClient,
    token: &str,
    item: &str,
    idx: usize,
    want_hash: &str,
    sealed_pub: [u8; 32],
) -> Result<usize> {
    let mut attempt = 0;
    loop {
        // caps are re-checked for every chunk, so "stop" and the window apply mid-transfer
        if let Err(r) = app.gate() {
            bail!("stopped: {r}");
        }
        match client.chunk(token, item, idx as u64).await {
            Ok(data) => {
                app.down.take(data.len(), app.policy().max_download_kib_s).await;
                if blake3::hash(&data).to_hex().as_str() != want_hash {
                    bail!("chunk {idx} failed verification against the catalog");
                }
                let blob = seal(&sealed_pub, &data)?;
                let path = chunk_file(app, item, idx);
                let tmp = path.with_extension("part");
                {
                    use tokio::io::AsyncWriteExt;
                    let mut f = tokio::fs::File::create(&tmp).await?;
                    f.write_all(&blob).await?;
                    if app.cfg.persistent() {
                        f.sync_all().await?; // a power cut must not leave a "received" chunk that is not on disk
                    }
                }
                tokio::fs::rename(&tmp, &path).await?;
                return Ok(idx);
            }
            Err(e) => {
                attempt += 1;
                let busy = matches!(e.downcast_ref::<HttpErr>(), Some(h) if h.0 == 429);
                let net = e.downcast_ref::<HttpErr>().is_none();
                if (busy || net) && attempt < 6 {
                    tokio::time::sleep(Duration::from_secs(if busy { 1 } else { 3 * attempt })).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

// ----------------------------------------------------- inbound requests waiting for a human

pub fn answer_inbound(app: &App, request_id: &str, approve: bool, reason: Option<&str>) -> Result<()> {
    let row = app
        .db
        .with(|c| crate::db::get_request(c, request_id))?
        .ok_or_else(|| anyhow!("no such request"))?;
    if row.dir != "in" || row.status != "pending" {
        bail!("this request is not waiting for an answer");
    }
    if approve {
        app.db.with(|c| {
            c.execute(
                "UPDATE sync_requests SET status='approved', token=?2, expires=?3, reason=NULL WHERE id=?1",
                params![request_id, random_hex(16), now() + crate::mesh::GRANT_SECS],
            )?;
            Ok(())
        })
    } else {
        app.db.with(|c| {
            c.execute(
                "UPDATE sync_requests SET status='denied', reason=?2 WHERE id=?1",
                params![request_id, reason.unwrap_or("declined by the owner")],
            )?;
            Ok(())
        })
    }
}
