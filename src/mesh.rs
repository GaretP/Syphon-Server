//! Peer-to-peer protocol, served on the mesh listener (and the mesh onion service).
//!
//! Every request is signed with the sender's Ed25519 node key and checked against the paired
//! peers list; timestamps and nonces stop replays. The flow a syncing node follows:
//!
//!   1. `POST /mesh/heartbeat`        heads in, heads out ("here is what I have")
//!   2. `GET  /mesh/ops`              pull the catalog entries we are missing
//!   3. `POST /mesh/sync/request`     "I need these items" -> approved | denied | pending
//!   4. `GET  /mesh/sync/request/:id` poll while a human is deciding
//!   5. `GET  /mesh/chunk/:item/:i`   fetch chunks with the granted token, rate-limited

use crate::catalog::{self, Op};
use crate::db::{get_item, get_peer, get_request, Peer, SyncRequest, REQ_COLS};
use crate::state::{App, Shared};
use crate::util::{now, random_hex};
use anyhow::{anyhow, Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

const MAX_SKEW: i64 = 300;
pub const GRANT_SECS: i64 = 6 * 3600;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Heartbeat {
    pub heads: BTreeMap<String, i64>,
    pub free: u64,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HeartbeatReply {
    pub heads: BTreeMap<String, i64>,
    pub free: u64,
    pub name: String,
    /// false = this node is not syncing right now (switched off, outside window, low disk, ...)
    pub enabled: bool,
    pub reason: Option<String>,
    pub mode: String,
    pub locked: bool,
    /// older versions could suspend the computer when idle and said so here; this version never does (kept so old and new nodes still understand each other)
    #[serde(default)]
    pub sleeper: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SyncAsk {
    pub items: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SyncAnswer {
    /// approved | denied | pending | expired
    pub status: String,
    pub request_id: String,
    pub reason: Option<String>,
    pub token: Option<String>,
    pub expires: i64,
    pub available: Vec<String>,
    pub max_kib_s: u32,
}

// ------------------------------------------------------------------ errors

pub struct MeshErr(pub StatusCode, pub String);

impl IntoResponse for MeshErr {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for MeshErr {
    fn from(e: anyhow::Error) -> Self {
        MeshErr(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

type R<T> = Result<T, MeshErr>;

fn bad(msg: impl Into<String>) -> MeshErr {
    MeshErr(StatusCode::BAD_REQUEST, msg.into())
}

/// An HTTP-level failure from a peer, kept typed so callers can react to 403/423/429.
#[derive(Debug)]
pub struct HttpErr(pub u16, pub String);

impl std::fmt::Display for HttpErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer answered {}: {}", self.0, self.1)
    }
}

impl std::error::Error for HttpErr {}

// ------------------------------------------------------------------ request signing

pub(crate) fn signing_string(method: &str, pq: &str, ts: i64, nonce: &str, body: &[u8]) -> Vec<u8> {
    format!("hearth-req-v1\n{method}\n{pq}\n{ts}\n{nonce}\n{}", blake3::hash(body).to_hex()).into_bytes()
}

pub fn sign_headers(app: &App, method: &str, pq: &str, body: &[u8]) -> Vec<(&'static str, String)> {
    let ts = now();
    let nonce = random_hex(8);
    let sig = app.id.sign(&signing_string(method, pq, ts, &nonce, body));
    vec![
        ("x-syphon-node", app.id.id.clone()),
        ("x-syphon-ts", ts.to_string()),
        ("x-syphon-nonce", nonce),
        ("x-syphon-sig", sig),
    ]
}

fn hdr<'a>(h: &'a HeaderMap, k: &str) -> Option<&'a str> {
    h.get(k).and_then(|v| v.to_str().ok())
}

/// Every authentication failure looks the same from outside: a plain 404. A stranger probing the
/// mesh port learns nothing about what lives here, which peers exist, or why a request failed.
fn nf() -> MeshErr {
    MeshErr(StatusCode::NOT_FOUND, "not found".into())
}

/// Checks the signature, clock and nonce of a mesh request. Returns the claimed node id. It does
/// NOT check that the node is a paired peer (pairing requests come from nodes not yet paired).
pub(crate) fn verify_signed(app: &App, method: &str, uri: &Uri, h: &HeaderMap, body: &[u8]) -> R<String> {
    let node = hdr(h, "x-syphon-node").ok_or_else(nf)?;
    let ts: i64 = hdr(h, "x-syphon-ts").and_then(|s| s.parse().ok()).ok_or_else(nf)?;
    let nonce = hdr(h, "x-syphon-nonce").ok_or_else(nf)?;
    let sig = hdr(h, "x-syphon-sig").ok_or_else(nf)?;
    if (now() - ts).abs() > MAX_SKEW || nonce.len() > 64 {
        return Err(nf());
    }
    let pq = uri.path_and_query().map(|p| p.as_str()).unwrap_or_else(|| uri.path());
    if !crate::state::verify_sig(node, &signing_string(method, pq, ts, nonce, body), sig) {
        return Err(nf());
    }
    let mut n = app.nonces.lock().unwrap();
    let t = now();
    n.retain(|_, exp| *exp > t);
    let key = format!("{node}:{nonce}");
    if n.contains_key(&key) {
        return Err(nf());
    }
    n.insert(key, t + 2 * MAX_SKEW);
    Ok(node.to_string())
}

fn authenticate(app: &App, method: &str, uri: &Uri, h: &HeaderMap, body: &[u8]) -> R<Peer> {
    let node = verify_signed(app, method, uri, h, body)?;
    let peer = app.db.with(|c| get_peer(c, &node))?.ok_or_else(nf)?;
    if !peer.enabled {
        return Err(nf());
    }
    Ok(peer)
}

fn mark_seen(app: &App, node: &str) {
    let _ = app.db.with(|c| {
        c.execute("UPDATE peers SET last_seen=?2 WHERE node_id=?1", params![node, now()])?;
        Ok(())
    });
}

// ------------------------------------------------------------------ server

pub fn router(app: Shared) -> Router {
    Router::new()
        .route("/mesh/heartbeat", post(heartbeat))
        .route("/mesh/ops", get(ops))
        .route("/mesh/sync/request", post(sync_request))
        .route("/mesh/sync/request/:id", get(request_status))
        .route("/mesh/chunk/:item/:idx", get(chunk))
        .route("/mesh/pair/request", post(crate::pair::http_request))
        .route("/mesh/pair/request/:id", get(crate::pair::http_status))
        .fallback(|| async { nf() })
        .with_state(app)
}

async fn note_work(axum::extract::State(app): axum::extract::State<Shared>, req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    if crate::rest::mesh_counts(req.uri().path()) {
        crate::rest::touch_for(&app, &format!("another node: {}", req.uri().path()));
    }
    next.run(req).await
}

pub async fn serve(app: Shared, listener: tokio::net::TcpListener) -> Result<()> {
    let r = router(app.clone()).layer(axum::middleware::from_fn_with_state(app, note_work));
    axum::serve(listener, r).await?;
    Ok(())
}

async fn heartbeat(State(app): State<Shared>, uri: Uri, h: HeaderMap, body: Bytes) -> R<Json<HeartbeatReply>> {
    let peer = authenticate(&app, "POST", &uri, &h, &body)?;
    let _hb: Heartbeat = serde_json::from_slice(&body).map_err(|e| bad(format!("bad heartbeat: {e}")))?;
    mark_seen(&app, &peer.node_id);
    let pol = app.policy();
    let gate = app.gate();
    let heads = if gate.is_ok() { app.db.with(catalog::heads)? } else { BTreeMap::new() };
    Ok(Json(HeartbeatReply {
        heads,
        free: app.disk_free(),
        name: app.cfg.name.clone(),
        enabled: gate.is_ok(),
        reason: gate.err(),
        mode: pol.mode,
        locked: !app.keyring.is_unlocked(),
        sleeper: false,
    }))
}

#[derive(Deserialize)]
struct OpsQuery {
    node: String,
    after: i64,
    limit: Option<i64>,
}

async fn ops(State(app): State<Shared>, uri: Uri, h: HeaderMap, Query(q): Query<OpsQuery>) -> R<Json<serde_json::Value>> {
    authenticate(&app, "GET", &uri, &h, &[])?;
    if let Err(r) = app.gate() {
        return Err(MeshErr(StatusCode::FORBIDDEN, format!("sync paused: {r}")));
    }
    let ops = app.db.with(|c| catalog::ops_after(c, &q.node, q.after, q.limit.unwrap_or(500).clamp(1, 500)))?;
    Ok(Json(serde_json::json!({ "ops": ops })))
}

fn answer_from(r: &SyncRequest, available: Vec<String>, kib: u32) -> SyncAnswer {
    let live = r.status == "approved" && r.expires > now();
    SyncAnswer {
        status: if r.status == "approved" && !live { "expired".into() } else { r.status.clone() },
        request_id: r.id.clone(),
        reason: r.reason.clone(),
        token: if live { r.token.clone() } else { None },
        expires: r.expires,
        available,
        max_kib_s: kib,
    }
}

fn denied(reason: impl Into<String>) -> SyncAnswer {
    SyncAnswer { status: "denied".into(), reason: Some(reason.into()), ..Default::default() }
}

async fn sync_request(State(app): State<Shared>, uri: Uri, h: HeaderMap, body: Bytes) -> R<Json<SyncAnswer>> {
    let peer = authenticate(&app, "POST", &uri, &h, &body)?;
    let ask: SyncAsk = serde_json::from_slice(&body).map_err(|e| bad(format!("bad request: {e}")))?;
    mark_seen(&app, &peer.node_id);
    let pol = app.policy();
    if let Err(r) = app.gate() {
        return Ok(Json(denied(r)));
    }
    if !app.keyring.is_unlocked() {
        return Ok(Json(denied("this node is locked: its owner has not logged in since it started")));
    }
    let wanted: Vec<String> = ask.items.into_iter().take(500).collect();
    let (available, bytes) = app.db.with(|c| {
        let mut av = vec![];
        let mut total = 0i64;
        for id in &wanted {
            if let Some(it) = get_item(c, id)? {
                if it.catalog && !it.deleted && it.local == "present" {
                    total += it.size;
                    av.push(it.id);
                }
            }
        }
        Ok((av, total))
    })?;
    if available.is_empty() {
        return Ok(Json(denied("none of the requested items are available on this node")));
    }

    // Re-use a live request from the same peer instead of piling up duplicates.
    let existing: Option<SyncRequest> = app.db.with(|c| {
        Ok(c.query_row(
            &format!(
                "SELECT {REQ_COLS} FROM sync_requests WHERE peer=?1 AND dir='in' AND status IN ('pending','approved') AND expires>?2 ORDER BY created DESC LIMIT 1"
            ),
            params![peer.node_id, now()],
            SyncRequest::from_row,
        )
        .optional()?)
    })?;
    if let Some(ex) = existing {
        let covers = available.iter().all(|a| ex.items.contains(a));
        if ex.status == "pending" || covers {
            return Ok(Json(answer_from(&ex, available, pol.max_upload_kib_s)));
        }
    }

    let id = random_hex(8);
    let created = now();
    let auto = pol.mode != "ask";
    let (status, token, expires) = if auto {
        ("approved", Some(random_hex(16)), created + GRANT_SECS)
    } else {
        ("pending", None, created + 7 * 86400)
    };
    app.db.with(|c| {
        c.execute(
            "INSERT INTO sync_requests(id,peer,dir,items,bytes,status,reason,token,created,expires) VALUES(?1,?2,'in',?3,?4,?5,NULL,?6,?7,?8)",
            params![id, peer.node_id, serde_json::to_string(&available)?, bytes, status, token, created, expires],
        )?;
        Ok(())
    })?;
    let row = app.db.with(|c| get_request(c, &id))?.ok_or_else(|| anyhow!("request vanished"))?;
    Ok(Json(answer_from(&row, available, pol.max_upload_kib_s)))
}

async fn request_status(State(app): State<Shared>, uri: Uri, h: HeaderMap, Path(id): Path<String>) -> R<Json<SyncAnswer>> {
    let peer = authenticate(&app, "GET", &uri, &h, &[])?;
    let row = app
        .db
        .with(|c| get_request(c, &id))?
        .filter(|r| r.peer == peer.node_id && r.dir == "in")
        .ok_or_else(|| MeshErr(StatusCode::NOT_FOUND, "no such request".into()))?;
    if let Err(r) = app.gate() {
        if row.status != "denied" {
            return Ok(Json(denied(r)));
        }
    }
    let items = row.items.clone();
    Ok(Json(answer_from(&row, items, app.policy().max_upload_kib_s)))
}

struct ServeGuard<'a>(&'a App);
impl Drop for ServeGuard<'_> {
    fn drop(&mut self) {
        self.0.active_serves.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn chunk(State(app): State<Shared>, uri: Uri, h: HeaderMap, Path((item, idx)): Path<(String, u64)>) -> R<Response> {
    let peer = authenticate(&app, "GET", &uri, &h, &[])?;
    let token = hdr(&h, "x-syphon-token").ok_or_else(|| MeshErr(StatusCode::FORBIDDEN, "missing grant token".into()))?;
    let grant: Option<SyncRequest> = app.db.with(|c| {
        Ok(c.query_row(
            &format!("SELECT {REQ_COLS} FROM sync_requests WHERE token=?1 AND peer=?2 AND dir='in' AND status='approved' AND expires>?3"),
            params![token, peer.node_id, now()],
            SyncRequest::from_row,
        )
        .optional()?)
    })?;
    let grant = grant.ok_or_else(|| MeshErr(StatusCode::FORBIDDEN, "no valid grant for this token".into()))?;
    if !grant.items.contains(&item) {
        return Err(MeshErr(StatusCode::FORBIDDEN, "item not covered by this grant".into()));
    }
    // Stopping sync takes effect immediately, mid-transfer.
    if let Err(r) = app.gate() {
        return Err(MeshErr(StatusCode::FORBIDDEN, format!("sync paused: {r}")));
    }
    if !app.keyring.is_unlocked() {
        return Err(MeshErr(StatusCode::LOCKED, "node is locked".into()));
    }
    let pol = app.policy();
    let active = app.active_serves.fetch_add(1, Ordering::SeqCst);
    let _g = ServeGuard(&app);
    if active >= app.streams().max(1) {
        return Err(MeshErr(StatusCode::TOO_MANY_REQUESTS, "too many parallel transfers; retry shortly".into()));
    }
    let app2 = app.clone();
    let data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let (_, mut r) = crate::library::open_reader(&app2, &item)?;
        r.read_chunk(idx)
    })
    .await
    .map_err(|e| anyhow!("{e}"))??;
    app.up.take(data.len(), pol.max_upload_kib_s).await;
    let hash = blake3::hash(&data).to_hex().to_string();
    Ok(([("content-type", "application/octet-stream".to_string()), ("x-syphon-chunk-hash", hash)], data).into_response())
}

// ------------------------------------------------------------------ client

pub struct PeerClient {
    app: Shared,
    http: reqwest::Client,
    base: String,
}

pub fn base_url(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.trim_end_matches('/').to_string()
    } else {
        format!("http://{}", addr.trim_end_matches('/'))
    }
}

impl PeerClient {
    pub fn new(app: &Shared, peer: &Peer) -> Result<Self> {
        Self::for_addr(app, &peer.addr)
    }

    pub fn for_addr(app: &Shared, addr: &str) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(90))
            .timeout(Duration::from_secs(300))
            .user_agent("syphon");
        b = if app.cfg.transport == "tor" {
            b.proxy(reqwest::Proxy::all(crate::tor::socks_url(&app.cfg))?)
        } else {
            b.no_proxy()
        };
        Ok(PeerClient { app: app.clone(), http: b.build()?, base: base_url(addr) })
    }

    async fn call(&self, method: &str, pq: &str, body: Vec<u8>, token: Option<&str>) -> Result<reqwest::Response> {
        let m = reqwest::Method::from_bytes(method.as_bytes())?;
        let mut req = self.http.request(m, format!("{}{}", self.base, pq));
        for (k, v) in sign_headers(&self.app, method, pq, &body) {
            req = req.header(k, v);
        }
        if let Some(t) = token {
            req = req.header("x-syphon-token", t);
        }
        if method == "POST" {
            req = req.header("content-type", "application/json").body(body);
        }
        let resp = req.send().await.with_context(|| format!("could not reach {}", self.base))?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        let code = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let msg = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v["error"].as_str().map(|s| s.to_string()))
            .unwrap_or(text);
        Err(HttpErr(code, msg).into())
    }

    pub async fn pair_request(&self, body: Vec<u8>) -> Result<serde_json::Value> {
        Ok(self.call("POST", "/mesh/pair/request", body, None).await?.json().await?)
    }

    pub async fn pair_status(&self, id: &str, secret: &str) -> Result<serde_json::Value> {
        Ok(self.call("GET", &format!("/mesh/pair/request/{id}?s={secret}"), vec![], None).await?.json().await?)
    }

    pub async fn heartbeat(&self) -> Result<HeartbeatReply> {
        let hb = Heartbeat {
            heads: self.app.db.with(catalog::heads)?,
            free: self.app.disk_free(),
            name: self.app.cfg.name.clone(),
        };
        Ok(self.call("POST", "/mesh/heartbeat", serde_json::to_vec(&hb)?, None).await?.json().await?)
    }

    pub async fn ops(&self, node: &str, after: i64) -> Result<Vec<Op>> {
        let pq = format!("/mesh/ops?node={node}&after={after}&limit=500");
        let v: serde_json::Value = self.call("GET", &pq, vec![], None).await?.json().await?;
        Ok(serde_json::from_value(v["ops"].clone())?)
    }

    pub async fn ask(&self, items: &[String]) -> Result<SyncAnswer> {
        let body = serde_json::to_vec(&SyncAsk { items: items.to_vec() })?;
        Ok(self.call("POST", "/mesh/sync/request", body, None).await?.json().await?)
    }

    pub async fn status(&self, request_id: &str) -> Result<SyncAnswer> {
        Ok(self.call("GET", &format!("/mesh/sync/request/{request_id}"), vec![], None).await?.json().await?)
    }

    pub async fn chunk(&self, token: &str, item: &str, idx: u64) -> Result<Vec<u8>> {
        let resp = self.call("GET", &format!("/mesh/chunk/{item}/{idx}"), vec![], Some(token)).await?;
        Ok(resp.bytes().await?.to_vec())
    }
}
