//! Pairing two nodes with a request, the way a friend request works.
//!
//!   1. Node A (at home) creates an **invite code** and shares it any way it likes.
//!   2. Node B pastes the code. B sends A a signed *pair request* and starts waiting.
//!   3. A's owner sees "B wants to connect" (with B's fingerprint) and presses Accept.
//!   4. Both sides pair themselves automatically. Nobody has to click at the same moment, and
//!      either node may be offline in between: requests are stored and retried.
//!
//! Over Tor, A's mesh onion service only answers authorised clients. The invite therefore carries a
//! throwaway client key that lets B (and only B, once, with the invite secret) knock. It is revoked
//! shortly after B has learned the answer. The invite code is a capability: anyone holding it can
//! *ask*, but only A's owner can say yes.

use crate::state::{App, Shared};
use crate::util::{fingerprint, now, random_hex, sanitize_name};
use anyhow::{anyhow, bail, Result};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const INVITE_TTL: i64 = 24 * 3600;
const PREFIX: &str = "syphon1:";

/// What an invite code contains.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InviteData {
    pub v: u32,
    pub name: String,
    pub node_id: String,
    pub addr: String,
    pub client_pub: String,
    /// invite id and secret (the secret is only ever stored hashed on the inviting node)
    pub pid: String,
    pub ps: String,
    /// throwaway Tor client key (private half), empty in direct mode
    pub tk: String,
    pub exp: i64,
}

pub fn encode(d: &InviteData) -> String {
    format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(d).unwrap_or_default()))
}

pub fn decode(code: &str) -> Result<InviteData> {
    let c: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    let raw = c.strip_prefix(PREFIX).ok_or_else(|| anyhow!("That does not look like a Syphon invite code. It should start with \"syphon1:\"."))?;
    let bytes = URL_SAFE_NO_PAD.decode(raw).map_err(|_| anyhow!("The invite code is damaged. Copy it again in full."))?;
    let d: InviteData = serde_json::from_slice(&bytes).map_err(|_| anyhow!("The invite code is damaged. Copy it again in full."))?;
    if d.v != 1 {
        bail!("This invite comes from a different version of Syphon.");
    }
    Ok(d)
}

pub fn peer_file(name: &str, node_id: &str) -> String {
    format!("{}-{}", sanitize_name(name), &node_id[..6.min(node_id.len())])
}

fn hash(s: &str) -> String {
    blake3::hash(s.as_bytes()).to_hex().to_string()
}

fn check_identity(app: &App, node_id: &str, name: &str, addr: &str) -> Result<()> {
    if node_id.len() != 64 || hex::decode(node_id).is_err() {
        bail!("invalid node id");
    }
    if node_id == app.id.id {
        bail!("that is this node's own code");
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 40 || name.chars().any(|c| c.is_control()) {
        bail!("invalid name");
    }
    let tor = app.cfg.transport == "tor";
    if tor && !(addr.ends_with(".onion") && addr.len() == 62) {
        bail!("this node uses Tor, so the other node's address must be an .onion address");
    }
    if !tor && !addr.starts_with("http://") {
        bail!("direct mode needs an http:// address");
    }
    Ok(())
}

/// Add (or refresh) a peer and, in Tor mode, arrange the onion-service authorisation both ways.
pub fn add_peer(app: &App, node_id: &str, name: &str, addr: &str, client_pub: &str) -> Result<()> {
    check_identity(app, node_id, name, addr)?;
    app.db.with(|c| {
        c.execute(
            "INSERT INTO peers(node_id,name,addr,client_pub,added_at) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(node_id) DO UPDATE SET name=excluded.name, addr=excluded.addr, client_pub=excluded.client_pub, enabled=1, backoff_until=0, fails=0",
            params![node_id, name.trim(), addr, client_pub, now()],
        )?;
        Ok(())
    })?;
    if app.cfg.transport == "tor" {
        let f = peer_file(name, node_id);
        crate::tor::authorize_mesh_peer(app, &f, client_pub)?;
        crate::tor::install_peer_auth(app, &f, addr)?;
        crate::tor::reload(app);
    }
    app.wake.notify_waiters();
    Ok(())
}

pub fn remove_peer(app: &App, node_id: &str) -> Result<()> {
    let peer = app.db.with(|c| crate::db::get_peer(c, node_id))?.ok_or_else(|| anyhow!("no such peer"))?;
    app.db.with(|c| {
        c.execute("DELETE FROM peers WHERE node_id=?1", [node_id])?;
        c.execute("DELETE FROM sync_requests WHERE peer=?1 AND status IN ('pending','approved')", [node_id])?;
        Ok(())
    })?;
    if app.cfg.transport == "tor" {
        crate::tor::revoke_mesh_peer(app, &peer_file(&peer.name, &peer.node_id));
        crate::tor::reload(app);
    }
    app.live.lock().unwrap().remove(node_id);
    Ok(())
}

// ------------------------------------------------------------------ inviting side

pub struct NewInvite {
    pub id: String,
    pub code: String,
    pub expires: i64,
    pub fingerprint: String,
}

pub fn create_invite(app: &App, label: &str) -> Result<NewInvite> {
    let addr = app.mesh_addr();
    if addr.is_empty() {
        bail!("This node is still connecting to Tor. Give it a minute and try again.");
    }
    let open: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM pair_invites WHERE used=0 AND expires>?1", [now()], |r| r.get(0))?))?;
    if open >= 5 {
        bail!("You already have several unused invite codes. Cancel one first.");
    }
    let (id, secret) = (random_hex(8), random_hex(16));
    let (tmp_pub, tmp_priv) = if app.cfg.transport == "tor" { crate::tor::throwaway_keypair() } else { (String::new(), String::new()) };
    let exp = now() + INVITE_TTL;
    app.db.with(|c| {
        c.execute(
            "INSERT INTO pair_invites(id,secret_hash,tmp_pub,label,created,expires) VALUES(?1,?2,?3,?4,?5,?6)",
            params![id, hash(&secret), tmp_pub, label.chars().take(60).collect::<String>(), now(), exp],
        )?;
        Ok(())
    })?;
    if !tmp_pub.is_empty() {
        crate::tor::authorize_mesh_peer(app, &format!("invite-{id}"), &tmp_pub)?;
        crate::tor::reload(app);
    }
    let code = encode(&InviteData {
        v: 1,
        name: app.cfg.name.clone(),
        node_id: app.id.id.clone(),
        addr,
        client_pub: app.client_key.pub_b32(),
        pid: id.clone(),
        ps: secret,
        tk: tmp_priv,
        exp,
    });
    Ok(NewInvite { id, code, expires: exp, fingerprint: fingerprint(&app.id.id) })
}

pub fn cancel_invite(app: &App, id: &str) -> Result<()> {
    let n = app.db.with(|c| Ok(c.execute("DELETE FROM pair_invites WHERE id=?1", [id])?))?;
    if n == 0 {
        bail!("no such invite");
    }
    crate::tor::revoke_mesh_peer(app, &format!("invite-{id}"));
    crate::tor::reload(app);
    Ok(())
}

pub fn list_invites(app: &App) -> Result<Vec<Value>> {
    app.db.with(|c| {
        let mut st = c.prepare("SELECT id,created,expires FROM pair_invites WHERE used=0 AND expires>?1 ORDER BY created DESC")?;
        let rows = st.query_map([now()], |r| Ok(json!({ "id": r.get::<_, String>(0)?, "created": r.get::<_, i64>(1)?, "expires": r.get::<_, i64>(2)? })))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub fn incoming(app: &App) -> Result<Vec<Value>> {
    app.db.with(|c| {
        let mut st = c.prepare("SELECT id,node_id,name,created FROM pair_requests WHERE status='pending' ORDER BY created")?;
        let rows = st.query_map([], |r| {
            let node: String = r.get(1)?;
            Ok(json!({ "id": r.get::<_, String>(0)?, "fingerprint": fingerprint(&node), "name": r.get::<_, String>(2)?, "created": r.get::<_, i64>(3)? }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

/// The owner's answer. Accepting pairs this node with the requester immediately.
pub fn decide(app: &App, id: &str, accept: bool) -> Result<()> {
    let row: Option<(String, String, String, Option<String>, String)> = app.db.with(|c| {
        Ok(c.query_row("SELECT node_id,name,addr,client_pub,status FROM pair_requests WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?)
    })?;
    let Some((node, name, addr, cpub, status)) = row else { bail!("no such request") };
    if status != "pending" {
        bail!("that request was already answered");
    }
    if accept {
        add_peer(app, &node, &name, &addr, cpub.as_deref().unwrap_or(""))?;
    }
    app.db.with(|c| {
        c.execute("UPDATE pair_requests SET status=?2 WHERE id=?1", params![id, if accept { "approved" } else { "denied" }])?;
        Ok(())
    })
}

#[derive(Deserialize)]
struct ReqBody {
    pid: String,
    ps: String,
    name: String,
    addr: String,
    client_pub: String,
    secret: String,
}

fn nf() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" })))
}

/// `POST /mesh/pair/request`: signed by the asking node, authorised by the invite secret.
pub async fn http_request(State(app): State<Shared>, uri: Uri, h: HeaderMap, body: Bytes) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let node = crate::mesh::verify_signed(&app, "POST", &uri, &h, &body).map_err(|_| nf())?;
    let b: ReqBody = serde_json::from_slice(&body).map_err(|_| nf())?;
    check_identity(&app, &node, &b.name, &b.addr).map_err(|_| nf())?;
    if b.client_pub.len() != 52 || b.secret.len() < 16 || b.secret.len() > 128 {
        return Err(nf());
    }
    let inv: Option<(String, i64, i64)> = app
        .db
        .with(|c| Ok(c.query_row("SELECT secret_hash,expires,used FROM pair_invites WHERE id=?1", [&b.pid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).optional()?))
        .map_err(|_| nf())?;
    let Some((sh, exp, used)) = inv else { return Err(nf()) };
    if sh != hash(&b.ps) || exp < now() {
        return Err(nf());
    }
    // the same node asking again with the same secret just gets its existing request back
    let existing: Option<String> = app
        .db
        .with(|c| Ok(c.query_row("SELECT id FROM pair_requests WHERE invite=?1 AND node_id=?2 AND secret_hash=?3", params![b.pid, node, hash(&b.secret)], |r| r.get(0)).optional()?))
        .map_err(|_| nf())?;
    if let Some(id) = existing {
        return Ok(Json(json!({ "id": id })));
    }
    if used != 0 {
        return Err(nf());
    }
    let pending: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM pair_requests WHERE status='pending'", [], |r| r.get(0))?)).map_err(|_| nf())?;
    if pending >= 10 {
        return Err(nf());
    }
    let id = random_hex(8);
    app.db
        .with(|c| {
            c.execute(
                "INSERT INTO pair_requests(id,invite,node_id,name,addr,client_pub,secret_hash,status,created) VALUES(?1,?2,?3,?4,?5,?6,?7,'pending',?8)",
                params![id, b.pid, node, b.name.trim(), b.addr, b.client_pub, hash(&b.secret), now()],
            )?;
            c.execute("UPDATE pair_invites SET used=1 WHERE id=?1", [&b.pid])?;
            Ok(())
        })
        .map_err(|_| nf())?;
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
pub struct StatusQ {
    s: String,
}

/// `GET /mesh/pair/request/:id?s=secret`: how the asking node learns the answer.
pub async fn http_status(State(app): State<Shared>, uri: Uri, h: HeaderMap, Path(id): Path<String>, Query(q): Query<StatusQ>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let node = crate::mesh::verify_signed(&app, "GET", &uri, &h, &[]).map_err(|_| nf())?;
    let row: Option<(String, String)> = app
        .db
        .with(|c| Ok(c.query_row("SELECT status,secret_hash FROM pair_requests WHERE id=?1 AND node_id=?2", params![id, node], |r| Ok((r.get(0)?, r.get(1)?))).optional()?))
        .map_err(|_| nf())?;
    let Some((status, sh)) = row else { return Err(nf()) };
    if sh != hash(&q.s) {
        return Err(nf());
    }
    if status != "pending" {
        let _ = app.db.with(|c| {
            c.execute("UPDATE pair_requests SET delivered_at=?2 WHERE id=?1 AND delivered_at IS NULL", params![id, now()])?;
            Ok(())
        });
    }
    Ok(Json(json!({ "status": status })))
}

// ------------------------------------------------------------------ requesting side

/// Paste an invite code: starts a request that completes by itself once the other owner accepts.
pub fn request_join(app: &App, code: &str) -> Result<String> {
    let d = decode(code)?;
    if d.exp < now() {
        bail!("This invite code has expired. Ask for a new one.");
    }
    check_identity(app, &d.node_id, &d.name, &d.addr)?;
    if d.client_pub.len() != 52 || d.pid.is_empty() || d.ps.is_empty() {
        bail!("The invite code is incomplete.");
    }
    if app.mesh_addr().is_empty() {
        bail!("This node is still connecting to Tor. Give it a minute and try again.");
    }
    let known: Option<i64> = app.db.with(|c| Ok(c.query_row("SELECT 1 FROM peers WHERE node_id=?1", [&d.node_id], |r| r.get(0)).optional()?))?;
    if known.is_some() {
        bail!("You are already connected to {}.", d.name);
    }
    let active: Option<i64> =
        app.db.with(|c| Ok(c.query_row("SELECT 1 FROM outgoing_pairs WHERE peer_node=?1 AND status IN ('new','sent')", [&d.node_id], |r| r.get(0)).optional()?))?;
    if active.is_some() {
        bail!("You already asked {} to connect and are waiting for them.", d.name);
    }
    if app.cfg.transport == "tor" {
        let f = peer_file(&d.name, &d.node_id);
        // let their node reach ours once they accept, and use the throwaway key to knock for now
        crate::tor::authorize_mesh_peer(app, &f, &d.client_pub)?;
        crate::tor::install_peer_auth_with(app, &f, &d.addr, &d.tk)?;
        crate::tor::reload(app);
    }
    let id = random_hex(8);
    app.db.with(|c| {
        c.execute(
            "INSERT INTO outgoing_pairs(id,peer_node,peer_name,peer_addr,peer_client_pub,secret,status,detail,created,invite_id,invite_secret)
             VALUES(?1,?2,?3,?4,?5,?6,'new','Contacting them…',?7,?8,?9)",
            params![id, d.node_id, d.name.trim(), d.addr, d.client_pub, random_hex(16), now(), d.pid, d.ps],
        )?;
        Ok(())
    })?;
    app.wake.notify_waiters();
    Ok(id)
}

pub fn outgoing(app: &App) -> Result<Vec<Value>> {
    app.db.with(|c| {
        let mut st = c.prepare("SELECT id,peer_node,peer_name,status,detail,created FROM outgoing_pairs WHERE created>?1 ORDER BY created DESC LIMIT 10")?;
        let rows = st.query_map([now() - 7 * 86400], |r| {
            let node: String = r.get(1)?;
            Ok(json!({ "id": r.get::<_, String>(0)?, "fingerprint": fingerprint(&node), "name": r.get::<_, String>(2)?,
                       "status": r.get::<_, String>(3)?, "detail": r.get::<_, Option<String>>(4)?, "created": r.get::<_, i64>(5)? }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub fn cancel_outgoing(app: &App, id: &str) -> Result<()> {
    let row: Option<(String, String)> = app.db.with(|c| {
        Ok(c.query_row("SELECT peer_node,peer_name FROM outgoing_pairs WHERE id=?1 AND status IN ('new','sent')", [id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?)
    })?;
    let Some((node, name)) = row else { bail!("nothing to cancel") };
    app.db.with(|c| {
        c.execute("UPDATE outgoing_pairs SET status='cancelled', detail='Cancelled.' WHERE id=?1", [id])?;
        Ok(())
    })?;
    crate::tor::revoke_mesh_peer(app, &peer_file(&name, &node));
    crate::tor::reload(app);
    Ok(())
}

struct Out {
    id: String,
    node: String,
    name: String,
    addr: String,
    cpub: String,
    secret: String,
    status: String,
    invite_id: String,
    invite_secret: String,
    remote_id: Option<String>,
    created: i64,
}

fn set_out(app: &App, id: &str, status: &str, detail: &str) {
    let _ = app.db.with(|c| {
        c.execute("UPDATE outgoing_pairs SET status=?2, detail=?3 WHERE id=?1", params![id, status, detail])?;
        Ok(())
    });
}

async fn drive(app: &Shared, o: &Out) -> Result<()> {
    let client = crate::mesh::PeerClient::for_addr(app, &o.addr)?;
    if o.status == "new" {
        let body = serde_json::to_vec(&json!({
            "pid": o.invite_id, "ps": o.invite_secret, "name": app.cfg.name, "addr": app.mesh_addr(),
            "client_pub": app.client_key.pub_b32(), "secret": o.secret,
        }))?;
        let v = client.pair_request(body).await?;
        let rid = v["id"].as_str().ok_or_else(|| anyhow!("bad answer"))?.to_string();
        app.db.with(|c| {
            c.execute("UPDATE outgoing_pairs SET status='sent', remote_id=?2, detail=?3 WHERE id=?1", params![o.id, rid, format!("Waiting for {} to accept…", o.name)])?;
            Ok(())
        })?;
        return Ok(());
    }
    let rid = o.remote_id.clone().ok_or_else(|| anyhow!("no remote id"))?;
    let v = client.pair_status(&rid, &o.secret).await?;
    match v["status"].as_str().unwrap_or("") {
        "approved" => {
            add_peer(app, &o.node, &o.name, &o.addr, &o.cpub)?;
            set_out(app, &o.id, "done", &format!("Connected to {}.", o.name));
        }
        "denied" => {
            crate::tor::revoke_mesh_peer(app, &peer_file(&o.name, &o.node));
            crate::tor::reload(app);
            set_out(app, &o.id, "denied", &format!("{} declined the request.", o.name));
        }
        _ => {}
    }
    Ok(())
}

/// One pass of pairing housekeeping: send and poll outgoing requests, tidy up the invite keys.
pub async fn tick(app: &Shared) {
    let rows: Vec<Out> = app
        .db
        .with(|c| {
            let mut st = c.prepare(
                "SELECT id,peer_node,peer_name,peer_addr,COALESCE(peer_client_pub,''),secret,status,invite_id,invite_secret,remote_id,created FROM outgoing_pairs WHERE status IN ('new','sent')",
            )?;
            let r = st.query_map([], |r| {
                Ok(Out { id: r.get(0)?, node: r.get(1)?, name: r.get(2)?, addr: r.get(3)?, cpub: r.get(4)?, secret: r.get(5)?, status: r.get(6)?, invite_id: r.get(7)?, invite_secret: r.get(8)?, remote_id: r.get(9)?, created: r.get(10)? })
            })?;
            Ok(r.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap_or_default();
    for o in rows {
        if now() - o.created > 2 * INVITE_TTL {
            set_out(app, &o.id, "failed", "Gave up waiting. Ask for a new invite code.");
            crate::tor::revoke_mesh_peer(app, &peer_file(&o.name, &o.node));
            continue;
        }
        if let Err(e) = drive(app, &o).await {
            let m = e.to_string();
            let detail = if m.contains("answered 404") {
                "They could not accept that code (expired, already used, or not for this node). Ask for a new one.".to_string()
            } else {
                format!("Waiting for {} to come online…", o.name)
            };
            let st = if m.contains("answered 404") && o.status == "new" { "failed" } else { o.status.as_str() };
            set_out(app, &o.id, st, &detail);
        }
    }

    // inviting side: revoke the throwaway key shortly after the answer was delivered
    let done: Vec<String> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT invite FROM pair_requests WHERE delivered_at IS NOT NULL AND delivered_at>0 AND delivered_at<?1")?;
            let r = st.query_map([now() - 60], |r| r.get(0))?;
            Ok(r.collect::<rusqlite::Result<Vec<String>>>()?)
        })
        .unwrap_or_default();
    let expired: Vec<String> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT id FROM pair_invites WHERE expires<?1")?;
            let r = st.query_map([now()], |r| r.get(0))?;
            Ok(r.collect::<rusqlite::Result<Vec<String>>>()?)
        })
        .unwrap_or_default();
    let mut touched = false;
    for inv in done.iter().chain(expired.iter()) {
        crate::tor::revoke_mesh_peer(app, &format!("invite-{inv}"));
        let _ = app.db.with(|c| {
            c.execute("UPDATE pair_requests SET delivered_at=-1 WHERE invite=?1 AND delivered_at>0", [inv])?;
            c.execute("DELETE FROM pair_invites WHERE id=?1 AND expires<?2", params![inv, now()])?;
            Ok(())
        });
        touched = true;
    }
    let _ = app.db.with(|c| {
        c.execute("DELETE FROM pair_requests WHERE status='pending' AND created<?1", [now() - 7 * 86400])?;
        Ok(())
    });
    if touched {
        crate::tor::reload(app);
    }
}

pub async fn run(app: Shared) {
    loop {
        tick(&app).await;
        let busy: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM outgoing_pairs WHERE status IN ('new','sent')", [], |r| r.get(0))?)).unwrap_or(0);
        let wait = if busy > 0 { 5 } else { 20 };
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
            _ = app.wake.notified() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_codes_roundtrip_and_reject_junk() {
        let d = InviteData { v: 1, name: "Home".into(), node_id: "ab".repeat(32), addr: "x.onion".into(), client_pub: "C".repeat(52), pid: "p".into(), ps: "s".into(), tk: "".into(), exp: 5 };
        let c = encode(&d);
        assert!(c.starts_with("syphon1:"));
        assert_eq!(decode(&format!("  {}\n", c)).unwrap().name, "Home");
        assert!(decode("hello").is_err());
        assert!(decode("syphon1:!!!").is_err());
    }
}
