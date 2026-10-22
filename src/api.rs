//! The UI and JSON API. Served on the home-network listener and on the access onion service.
//!
//! Every request is stamped with a *zone* before any handler runs: `lan` (home network, private
//! address, not via Tor) or `remote` (Tor, or a public address). A session only works in the zone it
//! was created in, and anything that changes who can reach the node is refused outside `lan`.

use crate::catalog::MetaBody;
use crate::config::SyncPolicy;
use crate::db::{get_item, list_peers, Item, ITEM_COLS};
use crate::library;
use crate::security::{self, LoginOutcome, LoginReq, Poll, Via, Zone};
use crate::state::Shared;
use crate::util::{fingerprint, now};
use anyhow::Result;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine;
use futures_util::StreamExt;
use rusqlite::params;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;

const INDEX: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const THEME_JS: &str = include_str!("../ui/theme.js");
const APP_CSS: &str = include_str!("../ui/app.css");
const FAVICON: &str = include_str!("../ui/favicon.svg");

pub struct ApiErr(StatusCode, String);

/// Error text can include file system paths; those never go to a browser.
fn scrub(msg: &str) -> String {
    msg.split(' ')
        .map(|w| {
            let t = w.trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == '(' || c == ')' || c == ',' || c == ':');
            if t.starts_with('/') && t.matches('/').count() >= 2 { "[path]".to_string() } else { w.to_string() }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiErr {
    fn from(e: anyhow::Error) -> Self {
        let msg = format!("{e:#}");
        let code = if msg.contains("library is locked") { StatusCode::LOCKED } else { StatusCode::BAD_REQUEST };
        tracing::debug!("api error: {msg}");
        ApiErr(code, scrub(&crate::util::friendly_error(&e)))
    }
}

type R<T> = Result<T, ApiErr>;

fn err(code: StatusCode, m: &str) -> ApiErr {
    ApiErr(code, m.to_string())
}

pub struct Ctx {
    pub user: String,
    pub role: String,
    pub zone: Zone,
}

fn rank(role: &str) -> u8 {
    match role {
        "owner" => 3,
        "contributor" => 2,
        _ => 1,
    }
}

fn cookie_of(h: &HeaderMap, name: &str) -> Option<String> {
    let c = h.get(header::COOKIE)?.to_str().ok()?;
    let pre = format!("{name}=");
    c.split(';').find_map(|kv| kv.trim().strip_prefix(pre.as_str()).map(|s| s.to_string()))
}

fn token_of(h: &HeaderMap) -> Option<String> {
    if let Some(a) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = a.strip_prefix("Bearer ") {
            return Some(t.to_string());
        }
    }
    cookie_of(h, "syphon")
}

/// Set by `stamp_zone` before the handlers run; a client cannot forge it (it is overwritten).
fn zone_of(h: &HeaderMap) -> Zone {
    match h.get("x-syphon-zone").and_then(|v| v.to_str().ok()) {
        Some("lan") => Zone::Lan,
        _ => Zone::Remote,
    }
}

/// Checks the session, the zone, the minimum role and, for changes, the CSRF header.
fn auth(app: &Shared, h: &HeaderMap, min: &str, mutating: bool) -> R<Ctx> {
    if mutating && h.get("x-requested-with").and_then(|v| v.to_str().ok()) != Some("syphon") {
        return Err(err(StatusCode::FORBIDDEN, "missing x-requested-with header"));
    }
    let tok = token_of(h).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))?;
    let s = app.session(&tok).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "session expired, sign in again"))?;
    let zone = zone_of(h);
    if s.zone != zone {
        return Err(err(StatusCode::UNAUTHORIZED, "session expired, sign in again"));
    }
    if rank(&s.role) < rank(min) {
        return Err(err(StatusCode::FORBIDDEN, "your role does not allow this"));
    }
    Ok(Ctx { user: s.user, role: s.role, zone })
}

/// Like `auth`, and additionally refuses anything that does not come from the home network.
fn auth_home(app: &Shared, h: &HeaderMap, min: &str, mutating: bool) -> R<Ctx> {
    let c = auth(app, h, min, mutating)?;
    security::require_local(c.zone).map_err(|e| err(StatusCode::FORBIDDEN, &e.to_string()))?;
    Ok(c)
}

async fn security_headers(req: Request, next: Next) -> Response {
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; media-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    );
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=(), interest-cohort=()"));
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.remove(header::SERVER);
    r
}

/// Decides the zone from how the request arrived and writes it into a header the handlers trust.
pub(crate) async fn stamp_zone(State(via): State<Via>, ConnectInfo(addr): ConnectInfo<SocketAddr>, mut req: Request, next: Next) -> Response {
    req.headers_mut().remove("x-syphon-zone");
    // a reverse proxy on this machine would make every visitor look local: treat it as remote
    let proxied = ["x-forwarded-for", "forwarded", "x-real-ip", "x-forwarded-host"].iter().any(|k| req.headers().contains_key(*k));
    let zone = if proxied { Zone::Remote } else { security::zone_for(via, Some(addr.ip())) };
    req.headers_mut().insert("x-syphon-zone", HeaderValue::from_static(zone.as_str()));
    next.run(req).await
}

pub fn router(app: Shared) -> Router {
    Router::new()
        .route("/", get(|| async { ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], INDEX) }))
        .route("/app.js", get(|| async { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], APP_JS) }))
        .route("/theme.js", get(|| async { ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], THEME_JS) }))
        .route("/app.css", get(|| async { ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS) }))
        .route("/favicon.svg", get(|| async { ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON) }))
        .route("/api/status", get(status))
        .route("/api/system", get(system_info))
        .route("/api/tor/restart", post(tor_restart))
        .route("/api/login", post(login))
        .route("/api/login/poll", post(login_poll))
        .route("/api/logout", post(logout))
        .route("/api/lock", post(lock))
        .route("/api/me", get(me))
        .route("/api/me/avatar", put(avatar_put).delete(avatar_delete))
        .route("/api/avatar/:user", get(avatar_get))
        .route("/api/connect", get(connect_info))
        .route("/api/approvals", get(approvals_list))
        .route("/api/approvals/:id/approve", post(approval_approve))
        .route("/api/approvals/:id/deny", post(approval_deny))
        .route("/api/my/devices", get(my_devices))
        .route("/api/my/devices/:id", delete(my_device_delete))
        .route("/api/totp/start", post(totp_start))
        .route("/api/totp/confirm", post(totp_confirm))
        .route("/api/totp/disable", post(totp_disable))
        .route("/api/library", get(library_list))
        .route("/api/sanity", get(sanity_get).post(sanity_run))
        .route("/api/trash", get(trash_list).delete(trash_empty))
        .route("/api/trash/:id", delete(trash_purge))
        .route("/api/items/:id", get(item_detail).patch(item_edit).delete(item_delete))
        .route("/api/items/:id/restore", post(item_restore))
        .route("/api/stream/:id", get(stream))
        .route("/api/progress/:id", put(progress_put))
        .route("/api/presence", post(presence))
        .route("/api/upload", put(upload))
        .route("/api/upload/start", post(upload_start))
        .route("/api/upload/:sid", get(upload_status).put(upload_chunk).delete(upload_cancel))
        .route("/api/upload/:sid/finish", post(upload_finish))
        .route("/api/vault", get(vault_list))
        .route("/api/vault/upload", put(vault_upload))
        .route("/api/vault/:id", delete(vault_delete).patch(vault_rename))
        .route("/api/vault/:id/stream", get(vault_stream))
        .route("/api/review", get(review_list))
        .route("/api/update", get(update_status).post(update_request))
        .route("/api/kill", post(kill_node))
        .route("/api/perf", get(perf_get).put(perf_set))
        .route("/api/items/:id/playback", get(item_playback))
        .route("/api/frame/:id", get(item_frame))
        .route("/api/playback", get(playback_get).put(playback_set))
        .route("/api/storage", get(storage_get).put(storage_put))
        .route("/api/storage/volumes", post(storage_volume_add))
        .route("/api/storage/volumes/:id", axum::routing::patch(storage_volume_patch).delete(storage_volume_delete))
        .route("/api/storage/volumes/:id/drain", post(storage_volume_drain))
        .route("/api/storage/volumes/:id/folders", get(storage_folders))
        .route("/api/storage/nas", post(storage_nas_add))
        .route("/api/storage/scan", post(storage_scan))
        .route("/api/poster/:id", get(poster))
        .route("/api/items/:id/genres", put(item_genres))
        .route("/api/metadata", get(metadata_status).post(metadata_refresh))
        .route("/api/scan/library", post(library_scan_start).get(library_scan_progress))
        .route("/api/review/:id/approve", post(review_approve))
        .route("/api/review/:id/stream", get(review_stream))
        .route("/api/review/:id", axum::routing::patch(review_edit))
        .route("/api/review/:id/reject", post(review_reject))
        .route("/api/review/:id/rescan", post(review_rescan))
        .route("/api/acquire/providers", get(acq_providers))
        .route("/api/acquire/search", get(acq_search))
        .route("/api/acquire/queue", post(acq_queue))
        .route("/api/sources", get(sources_list).post(sources_add))
        .route("/api/sources/:id", delete(sources_delete))
        .route("/api/downloads", get(downloads))
        .route("/api/downloads/clear", post(downloads_clear))
        .route("/api/downloads/:id", delete(download_remove))
        .route("/api/downloads/:id/cancel", post(download_cancel))
        .route("/api/downloads/:id/retry", post(download_retry))
        .route("/api/sync", get(sync_status))
        .route("/api/sync/policy", put(sync_policy))
        .route("/api/sync/now", post(sync_now))
        .route("/api/sync/requests/:id/approve", post(sync_approve))
        .route("/api/sync/requests/:id/deny", post(sync_deny))
        .route("/api/pair", get(pair_overview))
        .route("/api/pair/invite", post(pair_invite))
        .route("/api/pair/invite/:id", delete(pair_invite_cancel))
        .route("/api/pair/join", post(pair_join))
        .route("/api/pair/requests/:id/accept", post(pair_accept))
        .route("/api/pair/requests/:id/deny", post(pair_deny))
        .route("/api/pair/outgoing/:id", delete(pair_outgoing_cancel))
        .route("/api/peers/:id", delete(peer_delete))
        .route("/api/peers/:id/enabled", post(peer_enabled))
        .route("/api/access-keys", get(device_list).post(device_add).delete(device_clear))
        .route("/api/access-keys/:name", delete(device_remove))
        .route("/api/users", get(users_list).post(users_add))
        .route("/api/users/:name", delete(users_delete))
        .route("/api/password", post(password_change))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(app.clone(), note_use))
        .with_state(app)
}

/// Real use of the web interface wakes a resting node.
async fn note_use(State(app): State<Shared>, req: Request, next: Next) -> Response {
    if crate::rest::counts_as_use(req.method(), req.uri().path()) {
        crate::rest::touch_for(&app, &format!("web: {} {}", req.method(), req.uri().path()));
    }
    // A video is still being sent: someone is watching, even if the browser asked for most of it long ago.
    // Count the response until its body is finished or dropped, so rest mode never starts in the middle of a film.
    let watching = req.uri().path().starts_with("/api/stream");
    let res = next.run(req).await;
    if !watching {
        return res;
    }
    let guard = StreamGuard::new(app.active_streams.clone());
    let (parts, body) = res.into_parts();
    let body = Body::from_stream(body.into_data_stream().map(move |c| {
        let _held = &guard;
        c
    }));
    Response::from_parts(parts, body)
}

/// Counts one open video response; the count drops when the body is finished or the viewer goes away.
struct StreamGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl StreamGuard {
    fn new(c: std::sync::Arc<std::sync::atomic::AtomicUsize>) -> Self {
        c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        StreamGuard(c)
    }
}
impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

pub async fn serve(app: Shared, listener: tokio::net::TcpListener, via: Via) -> Result<()> {
    let r = router(app).layer(middleware::from_fn_with_state(via, stamp_zone));
    axum::serve(listener, r.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}

// ------------------------------------------------------------------ session

async fn status(State(app): State<Shared>, h: HeaderMap) -> Json<Value> {
    let zone = zone_of(&h);
    // Before anyone has signed in, outside the home network, nothing identifying is shown.
    let name = if zone == Zone::Lan { Some(app.cfg.name.clone()) } else { None };
    Json(json!({ "name": name, "locked": !app.keyring.is_unlocked(), "zone": zone.as_str() }))
}


/// Restart Tor now (same address, new connections). Owner, at home.
async fn tor_restart(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if app.cfg.transport != "tor" {
        return Err(bad("This node does not use Tor."));
    }
    crate::tor::restart_now(&app);
    Ok(Json(json!({ "ok": true })))
}

/// How this node is set up to survive power loss and how its traffic leaves (home network only).
async fn system_info(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "viewer", false)?;
    let t = app.tor.lock().unwrap().clone();
    let last_clean = app.db.get_setting("last_clean_shutdown").ok().flatten().and_then(|s| s.parse::<i64>().ok());
    Ok(Json(json!({
        "persistence": app.cfg.persistence,
        "route": crate::acquire::effective_route(&app.cfg),
        "tor": app.cfg.transport == "tor",
        "tor_ready": t.bootstrap >= 100,
        "tor_progress": t.bootstrap,
        "tor_health": { "restarts": t.restarts, "last_restart": t.last_restart, "last_reason": t.last_restart_reason, "listed": t.listed, "checked": t.checked },
        "system_wide_configured": app.cfg.tor.system_wide,
        "bridges": app.cfg.tor.bridges.len(),
        "bridge_missing": crate::tor::bridge_transports(&app.cfg).1,
        "last_clean_shutdown": last_clean,
        "version": crate::update::version(),
        "sandbox": { "ok": crate::scanner::sandbox().ok, "how": crate::scanner::sandbox().label, "why": crate::scanner::sandbox().detail },
    })))
}

#[derive(Deserialize)]
struct LoginBody {
    user: String,
    password: String,
    totp: Option<String>,
    device_name: Option<String>,
}

fn session_cookie(tok: &str) -> String {
    format!("syphon={tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200")
}

fn device_cookie(v: &str) -> String {
    format!("syphon_dev={v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000")
}

async fn login(State(app): State<Shared>, h: HeaderMap, Json(b): Json<LoginBody>) -> R<Response> {
    let zone = zone_of(&h);
    let dev = cookie_of(&h, "syphon_dev");
    let out = security::login(&app, zone, dev.as_deref(), LoginReq { user: b.user, password: b.password, totp: b.totp, device_name: b.device_name }).await;
    Ok(match out {
        LoginOutcome::Ok { user, role, session, device_cookie: dc } => {
            let mut r = Json(json!({ "user": user, "role": role, "zone": zone.as_str(), "locked": false })).into_response();
            r.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&session_cookie(&session)).unwrap());
            if let Some(c) = dc {
                r.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&device_cookie(&c)).unwrap());
            }
            r
        }
        LoginOutcome::NeedTotp => Json(json!({ "need": "totp" })).into_response(),
        LoginOutcome::Pending { id, secret, code } => (StatusCode::ACCEPTED, Json(json!({ "pending": { "id": id, "secret": secret, "code": code } }))).into_response(),
        LoginOutcome::Fail { status, msg } => ApiErr(StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED), msg).into_response(),
    })
}

#[derive(Deserialize)]
struct PollBody {
    id: String,
    secret: String,
}

async fn login_poll(State(app): State<Shared>, h: HeaderMap, Json(b): Json<PollBody>) -> R<Response> {
    if zone_of(&h) == Zone::Lan {
        return Err(err(StatusCode::BAD_REQUEST, "not needed at home"));
    }
    Ok(match security::approval_poll(&app, &b.id, &b.secret)? {
        Poll::Pending => Json(json!({ "state": "pending" })).into_response(),
        Poll::Denied => Json(json!({ "state": "denied" })).into_response(),
        Poll::Expired => Json(json!({ "state": "expired" })).into_response(),
        Poll::Approved { user, role, device_name } => {
            let (session, dev) = security::complete_approved(&app, &user, &role, &device_name)?;
            let mut r = Json(json!({ "state": "ok", "user": user, "role": role, "zone": "remote" })).into_response();
            r.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&session_cookie(&session)).unwrap());
            r.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&device_cookie(&dev)).unwrap());
            r
        }
    })
}

async fn logout(State(app): State<Shared>, h: HeaderMap) -> Response {
    if let Some(t) = token_of(&h) {
        app.sessions.lock().unwrap().remove(&t);
    }
    ([(header::SET_COOKIE, "syphon=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0".to_string())], Json(json!({"ok": true}))).into_response()
}

async fn lock(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    app.keyring.lock();
    app.sessions.lock().unwrap().clear();
    Ok(Json(json!({ "locked": true })))
}

async fn me(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", false)?;
    Ok(Json(json!({
        "user": c.user, "role": c.role, "zone": c.zone.as_str(), "locked": !app.keyring.is_unlocked(),
        "totp": security::totp_enabled(&app, &c.user),
        "avatar": avatar_version(&app, &c.user),
        "node": if c.zone == Zone::Lan { Some(app.cfg.name.clone()) } else { None },
    })))
}

fn avatar_version(app: &crate::state::App, user: &str) -> Option<i64> {
    app.db.with(|db| Ok(db.query_row("SELECT updated FROM avatars WHERE user=?1", [user], |r| r.get::<_, i64>(0)).ok())).ok().flatten()
}

/// A profile picture: a small PNG, JPEG or WebP. The page shrinks pictures before sending; the node
/// checks the real bytes and never trusts the file name or the content type the browser claims.
async fn avatar_put(State(app): State<Shared>, h: HeaderMap, body: axum::body::Bytes) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", true)?;
    if body.len() > 400 * 1024 {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "that picture is too large (400 KB at most)"));
    }
    let mime = crate::metadata::image_mime(&body);
    if mime == "application/octet-stream" {
        return Err(err(StatusCode::BAD_REQUEST, "choose a PNG, JPEG or WebP picture"));
    }
    app.db.with(|db| {
        db.execute(
            "INSERT INTO avatars(user,mime,data,updated) VALUES(?1,?2,?3,?4) ON CONFLICT(user) DO UPDATE SET mime=excluded.mime,data=excluded.data,updated=excluded.updated",
            params![c.user, mime, body.to_vec(), crate::util::now()],
        )?;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true, "avatar": avatar_version(&app, &c.user) })))
}

async fn avatar_delete(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", true)?;
    app.db.with(|db| Ok(db.execute("DELETE FROM avatars WHERE user=?1", [&c.user])?))?;
    Ok(Json(json!({ "ok": true })))
}

async fn avatar_get(State(app): State<Shared>, h: HeaderMap, Path(user): Path<String>) -> R<Response> {
    auth(&app, &h, "viewer", false)?;
    let row: Option<(String, Vec<u8>)> = app.db.with(|db| Ok(db.query_row("SELECT mime,data FROM avatars WHERE user=?1", [&user], |r| Ok((r.get(0)?, r.get(1)?))).ok()))?;
    let Some((mime, data)) = row else { return Err(err(StatusCode::NOT_FOUND, "no picture")) };
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .header(header::CACHE_CONTROL, "private, max-age=3600")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(data))
        .unwrap())
}

fn qr_data_url(text: &str) -> Option<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(220, 220).quiet_zone(true).build();
    Some(format!("data:image/svg+xml;base64,{}", base64::engine::general_purpose::STANDARD.encode(svg)))
}

/// How to reach this node: its home-network addresses (and, for the owner, the Tor address).
async fn connect_info(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", false)?;
    let exposed = !app.cfg.access_bind.starts_with("127.");
    let urls = security::lan_urls(&app.cfg.access_bind);
    let qr = urls.first().and_then(|u| qr_data_url(u));
    let onion = if c.role == "owner" { app.tor.lock().unwrap().access_onion.clone() } else { None };
    Ok(Json(json!({ "lan_urls": urls, "lan_enabled": exposed, "qr": qr, "onion": onion })))
}

// ------------------------------------------------------------------ sign-in approvals, devices, 2FA

async fn approvals_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", false)?;
    let only = if c.role == "owner" { None } else { Some(c.user.as_str()) };
    Ok(Json(json!({ "pending": security::approvals_pending(&app, only)? })))
}

async fn approval_approve(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    security::approval_decide(&app, &id, true, if c.role == "owner" { None } else { Some(c.user.as_str()) })?;
    Ok(Json(json!({ "ok": true })))
}

async fn approval_deny(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    security::approval_decide(&app, &id, false, if c.role == "owner" { None } else { Some(c.user.as_str()) })?;
    Ok(Json(json!({ "ok": true })))
}

async fn my_devices(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", false)?;
    let only = if c.role == "owner" { None } else { Some(c.user.as_str()) };
    let current = cookie_of(&h, "syphon_dev").and_then(|d| d.split_once('.').map(|(i, _)| i.to_string()));
    Ok(Json(json!({ "devices": security::list_devices(&app, only)?, "current": current })))
}

async fn my_device_delete(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", true)?;
    security::revoke_device(&app, &id, if c.role == "owner" { None } else { Some(c.user.as_str()) })?;
    Ok(Json(json!({ "ok": true })))
}

async fn totp_start(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    let (secret, uri) = security::totp_start(&app, &c.user)?;
    Ok(Json(json!({ "secret": secret, "uri": uri, "qr": qr_data_url(&uri) })))
}

#[derive(Deserialize)]
struct CodeIn {
    code: String,
}

async fn totp_confirm(State(app): State<Shared>, h: HeaderMap, Json(b): Json<CodeIn>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    security::totp_confirm(&app, &c.user, &b.code)?;
    Ok(Json(json!({ "ok": true })))
}

async fn totp_disable(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    security::totp_disable(&app, &c.user)?;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------------ library

#[derive(Deserialize, Default)]
struct LibQ {
    kind: Option<String>,
    q: Option<String>,
}

async fn library_list(State(app): State<Shared>, h: HeaderMap, Query(q): Query<LibQ>) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", false)?;
    let rows = app.db.with(|db| {
        let mut st = db.prepare(
            "SELECT i.id,i.title,i.kind,i.year,i.season,i.episode,i.size,i.local,i.added_at,COALESCE(p.pos,0),i.filename
             FROM items i LEFT JOIN progress p ON p.item=i.id AND p.user=?1
             WHERE i.catalog=1 AND i.deleted=0 AND (?2='' OR ?2<>'') AND (?3='' OR 1)
             ORDER BY i.title COLLATE NOCASE, i.season, i.episode",
        )?;
        let rows = st.query_map(params![c.user, "", q.q.clone().unwrap_or_default()], |r| {
            Ok(json!({
                "id": r.get::<_, String>(0)?, "title": r.get::<_, String>(1)?, "kind": r.get::<_, String>(2)?,
                "year": r.get::<_, Option<i64>>(3)?, "season": r.get::<_, Option<i64>>(4)?, "episode": r.get::<_, Option<i64>>(5)?,
                "size": r.get::<_, i64>(6)?, "local": r.get::<_, String>(7)?, "added_at": r.get::<_, i64>(8)?,
                "pos": r.get::<_, f64>(9)?,
                "filename": r.get::<_, Option<String>>(10)?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;
    // loose episodes of one show share a "group" however their names were spelled; details come from
    // the looked-up title, and genres the owner typed in win over them
    let metas = crate::metadata::load_all(&app);
    let mine = crate::metadata::user_genres(&app);
    let want = q.kind.clone().unwrap_or_default();
    let query = q.q.clone().unwrap_or_default();
    let rows: Vec<Value> = rows
        .into_iter()
        .filter_map(|mut v| {
            let mut kind = v["kind"].as_str().unwrap_or("movie").to_string();
            let title = v["title"].as_str().unwrap_or("").to_string();
            let key = crate::metadata::key_for(&title, &kind, v["year"].as_i64().map(|y| y as i32));
            let st = metas.get(&key);
            // the sources know it is anime even when the file names did not say so (a series, or a one-file "movie")
            let known_anime = st.and_then(|s| s.meta.as_ref()).map(|m| m.anime).unwrap_or(false);
            let stored_kind = kind.clone();
            if known_anime && kind != "anime" {
                kind = "anime".into();
                v["kind"] = json!("anime");
            }
            if !want.is_empty() && kind != want {
                return None;
            }
            if kind != "movie" {
                v["group"] = json!(crate::util::series_key(&title));
                // a season written into the title ("Show S2", stored before the parser knew) belongs to the episode
                let (base, sn) = crate::util::split_season_suffix(&title);
                if sn.is_some() {
                    v["title"] = json!(base);
                    if v["season"].is_null() {
                        v["season"] = json!(sn);
                    }
                }
                // a season released under its own name belongs to the show the source says it continues
                if let Some(m) = st.and_then(|s| s.meta.as_ref()) {
                    if let Some(fk) = &m.franchise {
                        v["group"] = json!(fk);
                        if let Some(ft) = &m.franchise_title {
                            v["title"] = json!(ft);
                        }
                        if v["season"].is_null() {
                            if let Some(fs) = m.franchise_season {
                                v["season"] = json!(fs);
                            }
                        }
                    }
                }
                if let (Some(m), Some(n)) = (st.and_then(|s| s.meta.as_ref()), v["episode"].as_i64()) {
                    let own = m.franchise_season.is_some() && v["season"].as_i64() == m.franchise_season.map(|s| s as i64);
                    if let Some(t) = m.episode_title(v["season"].as_i64(), n).or_else(|| if own { m.entry_episode_title(n) } else { None }) {
                        v["ep_title"] = json!(t);
                    }
                }
            }
            let _ = stored_kind;
            // the search looks at what is shown (the series name the sources gave, the episode's own title) as well as
            // what is stored (the title and the file name), so anything on a poster can be found by typing it
            if !query.is_empty() {
                let hay = format!("{} {} {} {} {}", v["title"].as_str().unwrap_or(""), title, v["ep_title"].as_str().unwrap_or(""), v["filename"].as_str().unwrap_or(""), v["year"].as_i64().map(|y| y.to_string()).unwrap_or_default());
                if !crate::util::search_matches(&query, &hay) {
                    return None;
                }
            }
            if let Some(o) = v.as_object_mut() {
                o.remove("filename");
            }
            let genres: Vec<String> = v["id"].as_str().and_then(|i| mine.get(i).cloned()).or_else(|| st.and_then(|s| s.meta.as_ref().map(|m| m.genres.clone()))).map(|g| crate::metadata::canon_genres(&g)).unwrap_or_default();
            v["genres"] = json!(genres);
            v["poster"] = json!(st.map(|s| s.poster).unwrap_or(false));
            Some(v)
        })
        .collect();
    Ok(Json(json!({ "items": rows })))
}

/// What a browser gets to know about an item. File names, sources, scan details and author ids are
/// only for the owner on the home network; everyone else sees title/kind/size.
fn item_json(it: &Item, full: bool) -> Value {
    let mut v = json!({
        "id": it.id, "title": it.title, "kind": it.kind, "year": it.year, "season": it.season, "episode": it.episode,
        "size": it.size, "added_at": it.added_at, "local": it.local, "deleted": it.deleted, "deleted_at": it.deleted_at,
    });
    if it.kind != "movie" {
        v["group"] = json!(crate::util::series_key(&it.title));
        let (base, sn) = crate::util::split_season_suffix(&it.title);
        if sn.is_some() {
            v["title"] = json!(base);
            if it.season.is_none() {
                v["season"] = json!(sn);
            }
        }
    }
    if full {
        v["filename"] = json!(it.filename);
        v["source"] = json!(it.source);
        v["scan"] = json!(it.scan);
    }
    v
}

async fn trash_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "contributor", false)?;
    let items: Vec<Item> = app.db.with(|db| {
        let mut st = db.prepare(&format!("SELECT {} FROM items WHERE catalog=1 AND deleted=1 ORDER BY deleted_at DESC", crate::db::ITEM_LIGHT))?;
        let rows = st.query_map([], Item::from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;
    let full = c.zone == Zone::Lan && c.role == "owner";
    let items: Vec<Value> = items.iter().map(|i| item_json(i, full)).collect();
    Ok(Json(json!({ "items": items, "retention_days": app.cfg.trash_days })))
}

async fn sanity_get(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    Ok(Json(crate::sanity::status(&app)))
}

async fn sanity_run(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let a = app.clone();
    let rep = tokio::task::spawn_blocking(move || crate::sanity::check(&a)).await.map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    match rep {
        Some(r) => Ok(Json(json!({ "ok": true, "report": r }))),
        None => Err(bad("The check is already running.")),
    }
}

async fn trash_purge(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let n = library::purge_now(&app, Some(&id))?;
    Ok(Json(json!({ "ok": true, "removed": n })))
}

async fn trash_empty(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let n = library::purge_now(&app, None)?;
    Ok(Json(json!({ "ok": true, "removed": n })))
}

async fn item_detail(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", false)?;
    let full = c.zone == Zone::Lan && c.role == "owner";
    let it = app.db.with(|db| get_item(db, &id))?.filter(|i| i.catalog).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such item"))?;
    let pos: f64 = app
        .db
        .with(|db| Ok(db.query_row("SELECT COALESCE((SELECT pos FROM progress WHERE user=?1 AND item=?2),0)", params![c.user, id], |r| r.get(0))?))?;
    let mut item = item_json(&it, full);
    let key = crate::metadata::key_of(&it);
    let meta = crate::metadata::stored_for(&app, &key);
    if it.kind != "anime" && meta.as_ref().map(|m| m.anime).unwrap_or(false) {
        item["kind"] = json!("anime");
        item["group"] = json!(crate::util::series_key(&it.title));
    }
    if it.kind != "movie" {
        if let Some(m) = meta.as_ref() {
            if let Some(fk) = &m.franchise {
                item["group"] = json!(fk);
                if let Some(ft) = &m.franchise_title {
                    item["title"] = json!(ft);
                }
                if item["season"].is_null() {
                    if let Some(fs) = m.franchise_season {
                        item["season"] = json!(fs);
                    }
                }
            }
        }
    }
    if let (Some(m), Some(n)) = (meta.as_ref(), it.episode) {
        let season = item["season"].as_i64();
        let own = m.franchise_season.is_some() && season == m.franchise_season.map(|s| s as i64);
        if let Some(t) = m.episode_title(season, n as i64).or_else(|| if own { m.entry_episode_title(n as i64) } else { None }) {
            item["ep_title"] = json!(t);
        }
    }
    let mine = crate::metadata::user_genres(&app).remove(&id);
    item["genres"] = json!(mine.or_else(|| meta.as_ref().map(|m| m.genres.clone())).map(|g| crate::metadata::canon_genres(&g)).unwrap_or_default());
    item["poster"] = json!(crate::metadata::load_all(&app).get(&key).map(|s| s.poster).unwrap_or(false));
    item["details"] = json!(meta.map(|m| json!({ "overview": m.overview, "cast": m.cast, "rating": m.rating, "source": m.source })));
    Ok(Json(json!({ "item": item, "pos": pos })))
}

#[derive(Deserialize)]
struct MetaIn {
    title: String,
    kind: String,
    year: Option<i32>,
    season: Option<i32>,
    episode: Option<i32>,
}

async fn item_edit(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(m): Json<MetaIn>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    library::edit_meta(&app, MetaBody { id, title: m.title.trim().to_string(), kind: m.kind, year: m.year, season: m.season, episode: m.episode })?;
    Ok(Json(json!({ "ok": true })))
}

async fn item_delete(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    library::delete_item(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

async fn item_restore(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    library::restore_item(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------------ playback

#[derive(Deserialize, Default)]
struct StreamQ {
    mode: Option<String>,
    start: Option<f64>,
    /// a quality id (see library::QUALITIES); blank = the node's setting
    q: Option<String>,
    /// for remux: the sound can be copied as it is
    audio_ok: Option<bool>,
    /// what the browser can show: "av1" or "h264" (blank: the node's preference)
    codec: Option<String>,
}

fn parse_range(h: &HeaderMap, len: u64) -> Option<Result<(u64, u64), ()>> {
    let v = h.get(header::RANGE)?.to_str().ok()?;
    let spec = v.strip_prefix("bytes=")?;
    let first = spec.split(',').next()?.trim();
    let (a, b) = first.split_once('-')?;
    if len == 0 {
        return Some(Err(()));
    }
    let res = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 { Err(()) } else { Ok((len.saturating_sub(n), len - 1)) }
    } else {
        let s: u64 = a.parse().ok()?;
        let e: u64 = if b.is_empty() { len - 1 } else { b.parse::<u64>().ok()?.min(len - 1) };
        if s > e || s >= len { Err(()) } else { Ok((s, e)) }
    };
    Some(res)
}

async fn stream(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Query(q): Query<StreamQ>) -> R<Response> {
    auth(&app, &h, "viewer", false)?;
    let a = app.clone();
    let (it, reader) = tokio::task::spawn_blocking(move || library::open_reader(&a, &id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    respond_stream(&app, &h, it.filename.as_deref().unwrap_or("x.mp4"), reader, q)
}

fn respond_stream(app: &Shared, h: &HeaderMap, filename: &str, reader: crate::keyring::EncReader, q: StreamQ) -> R<Response> {
    let mime = library::mime_for(filename);
    let len = reader.len;

    if let Some(m) = q.mode.as_deref().filter(|m| ["low", "remux", "transcode"].contains(m)) {
        let (how, label) = match m {
            "remux" => (library::Convert::Remux { copy_audio: q.audio_ok.unwrap_or(false) }, "remux".to_string()),
            "low" => (library::Convert::Transcode(library::quality_by_id("low"), library::pick_codec(app, q.codec.as_deref())), "low".to_string()),
            _ => {
                let qid = q.q.clone().unwrap_or_else(|| library::node_quality(app));
                let ql = library::quality_by_id(&qid);
                let id = ql.id.to_string();
                (library::Convert::Transcode(ql, library::pick_codec(app, q.codec.as_deref())), id)
            }
        };
        let codec = match &how {
            library::Convert::Transcode(_, library::Codec::Av1(_)) => "av1",
            library::Convert::Transcode(_, library::Codec::H264) => "h264",
            _ => "copy",
        };
        let s = library::transcode_stream(app, reader, q.start.unwrap_or(0.0), how)?;
        return Ok(Response::builder()
            .status(200)
            .header("x-syphon-codec", codec)
            .header(header::CONTENT_TYPE, "video/mp4")
            .header("x-syphon-transcode", label)
            .body(Body::from_stream(s))
            .unwrap());
    }

    match parse_range(h, len) {
        Some(Err(())) => Ok(Response::builder()
            .status(StatusCode::RANGE_NOT_SATISFIABLE)
            .header(header::CONTENT_RANGE, format!("bytes */{len}"))
            .body(Body::empty())
            .unwrap()),
        Some(Ok((s, e))) => Ok(Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, mime)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_RANGE, format!("bytes {s}-{e}/{len}"))
            .header(header::CONTENT_LENGTH, e - s + 1)
            .body(Body::from_stream(library::range_stream(reader, s, e + 1)))
            .unwrap()),
        None => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_LENGTH, len)
            .body(Body::from_stream(library::range_stream(reader, 0, len)))
            .unwrap()),
    }
}

// ------------------------------------------------------------------ private vault
//
// The vault is a part of the node that is never shared: its files have no catalog entry, are not
// offered to peers, and these endpoints only answer on the home network. Each user sees only
// their own vault.

async fn vault_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", false)?;
    Ok(Json(json!({ "items": library::vault_list(&app, &c.user)? })))
}

async fn vault_upload(State(app): State<Shared>, h: HeaderMap, Query(q): Query<UploadQ>, body: Body) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    require_video_name(&q.name)?;
    let mut session = library::IngestSession::begin_vault(&app, &q.name, &c.user)?;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                session.abort();
                return Err(err(StatusCode::BAD_REQUEST, &format!("upload interrupted: {e}")));
            }
        };
        if let Err(e) = session.push(&chunk) {
            session.abort();
            return Err(e.into());
        }
    }
    let ing = session.finish(&app)?;
    // the vault is private, but a hostile file would still run on this node: it gets the same scan
    let path = library::vault_path(&app, &ing.id);
    let rep = crate::quarantine::scan_path(&app, &path, &ing.id, &q.name).await?;
    if !rep.ok {
        let _ = library::vault_delete(&app, &ing.id, &c.user);
        let why: Vec<String> = rep.findings.iter().map(|f| f.what.clone()).collect();
        let why = if why.is_empty() { rep.notes.join("; ") } else { why.join("; ") };
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, &format!("the safety scan did not pass, so the file was not kept: {why}")));
    }
    Ok(Json(json!({ "id": ing.id, "size": ing.size })))
}

async fn library_scan_start(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::scanner::start_library_rescan(&app)?;
    Ok(Json(json!({ "ok": true })))
}

async fn library_scan_progress(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "owner", false)?;
    Ok(Json(json!(crate::scanner::progress())))
}

async fn vault_stream(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Query(q): Query<StreamQ>) -> R<Response> {
    let c = auth_home(&app, &h, "viewer", false)?;
    let a = app.clone();
    let (it, reader) = tokio::task::spawn_blocking(move || library::open_vault_reader(&a, &id, &c.user))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    respond_stream(&app, &h, it.filename.as_deref().unwrap_or("x.mp4"), reader, q)
}

async fn vault_delete(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    library::vault_delete(&app, &id, &c.user)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct TitleIn {
    title: String,
}

async fn vault_rename(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(b): Json<TitleIn>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    library::vault_rename(&app, &id, &c.user, &b.title)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PosIn {
    pos: f64,
}

/// "Someone is watching": the player sends this while a film plays. The middleware counts it as use; nothing else to do.
async fn presence(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "viewer", true)?;
    Ok(Json(json!({ "ok": true })))
}

async fn progress_put(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(p): Json<PosIn>) -> R<Json<Value>> {
    let c = auth(&app, &h, "viewer", true)?;
    let pos = if p.pos.is_finite() && p.pos >= 0.0 { p.pos } else { 0.0 };
    app.db.with(|db| {
        db.execute(
            "INSERT INTO progress(user,item,pos,updated) VALUES(?1,?2,?3,?4) ON CONFLICT(user,item) DO UPDATE SET pos=excluded.pos, updated=excluded.updated",
            params![c.user, id, pos, now()],
        )?;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------------ upload and review

#[derive(Deserialize)]
struct UploadQ {
    name: String,
    #[serde(default)]
    kind: String,
}

const NOT_VIDEO: &str = "Only video files can be added. Syphon is not a file server.";

/// Reject anything that does not even claim to be a video, before a single byte is stored.
fn require_video_name(name: &str) -> Result<(), ApiErr> {
    if crate::quarantine::is_video_name(name) {
        Ok(())
    } else {
        Err(err(StatusCode::UNSUPPORTED_MEDIA_TYPE, &format!("{NOT_VIDEO} \"{name}\" does not end like a video file (.mp4, .mkv, .avi ...).")))
    }
}

#[derive(Deserialize)]
struct UploadStartQ {
    name: String,
    #[serde(default)]
    kind: String,
    size: u64,
}

/// Step one of a resumable upload: tell the node what is coming, get an upload id back.
async fn upload_start(State(app): State<Shared>, h: HeaderMap, Query(q): Query<UploadStartQ>) -> R<Json<Value>> {
    let c = auth(&app, &h, "contributor", true)?;
    require_video_name(&q.name)?;
    if q.size == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "that file is empty"));
    }
    library::expire_uploads(&app);
    if let Err(m) = app.disk_ok(q.size) {
        return Err(err(StatusCode::INSUFFICIENT_STORAGE, &m));
    }
    if app.uploads.lock().unwrap().len() >= app.tuning().max_uploads as usize {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many uploads at once; wait for some to finish"));
    }
    let session = library::IngestSession::begin_sized(&app, &q.name, "upload", q.size.saturating_add(q.size / 64))?;
    let sid = crate::util::random_hex(12);
    let up = library::Upload {
        user: c.user.clone(),
        name: q.name.clone(),
        kind: q.kind.clone(),
        size: q.size,
        received: Default::default(),
        touched: std::sync::atomic::AtomicI64::new(now()),
        takeover: Default::default(),
        session: tokio::sync::Mutex::new(Some(session)),
    };
    app.uploads.lock().unwrap().insert(sid.clone(), std::sync::Arc::new(up));
    Ok(Json(json!({ "sid": sid, "received": 0 })))
}

fn find_upload(app: &Shared, sid: &str, user: &str) -> Result<std::sync::Arc<library::Upload>, ApiErr> {
    let up = app.uploads.lock().unwrap().get(sid).cloned().ok_or_else(|| err(StatusCode::NOT_FOUND, "this upload is no longer on the node; it will start again"))?;
    if up.user != user {
        return Err(err(StatusCode::FORBIDDEN, "this upload belongs to someone else"));
    }
    Ok(up)
}

async fn upload_status(State(app): State<Shared>, h: HeaderMap, Path(sid): Path<String>) -> R<Json<Value>> {
    let c = auth(&app, &h, "contributor", false)?;
    let up = find_upload(&app, &sid, &c.user)?;
    Ok(Json(json!({ "received": up.received.load(std::sync::atomic::Ordering::SeqCst), "size": up.size })))
}

#[derive(Deserialize)]
struct ChunkQ {
    offset: u64,
}

/// Step two, as often as needed: send the bytes from `offset` on. If the offset is not where the node is, the
/// answer says where it is, and the browser carries on from there.
async fn upload_chunk(State(app): State<Shared>, h: HeaderMap, Path(sid): Path<String>, Query(q): Query<ChunkQ>, body: Body) -> Result<Response, ApiErr> {
    use std::sync::atomic::Ordering;
    let c = auth(&app, &h, "contributor", true)?;
    let up = find_upload(&app, &sid, &c.user)?;
    up.takeover.notify_waiters(); // an older request for this upload, if it is still hanging on, lets go
    let mut guard = match tokio::time::timeout(Duration::from_secs(20), up.session.lock()).await {
        Ok(g) => g,
        Err(_) => return Ok((StatusCode::CONFLICT, Json(json!({ "error": "busy", "received": up.received.load(Ordering::SeqCst) }))).into_response()),
    };
    up.touched.store(now(), Ordering::Relaxed);
    let have = up.received.load(Ordering::SeqCst);
    if q.offset != have {
        return Ok((StatusCode::CONFLICT, Json(json!({ "error": "offset", "received": have }))).into_response());
    }
    if guard.is_none() {
        return Err(err(StatusCode::GONE, "this upload was cancelled"));
    }
    let mut stream = body.into_data_stream();
    let mut first = have == 0;
    loop {
        let next = tokio::select! {
            n = stream.next() => n,
            _ = up.takeover.notified() => break,
        };
        let Some(chunk) = next else { break };
        let chunk = match chunk {
            Ok(c) => c,
            Err(_) => break, // the connection dropped: what already arrived stays, the browser asks and continues
        };
        if first && chunk.len() >= 12 {
            first = false;
            if !crate::quarantine::looks_like_video(&chunk[..chunk.len().min(4096)]) {
                if let Some(s) = guard.take() {
                    s.abort();
                }
                app.uploads.lock().unwrap().remove(&sid);
                return Err(err(StatusCode::UNSUPPORTED_MEDIA_TYPE, &format!("{NOT_VIDEO} \"{}\" is not a video inside, whatever its name says.", up.name)));
            }
        }
        if up.received.load(Ordering::SeqCst) + chunk.len() as u64 > up.size {
            return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "more data arrived than the file's size"));
        }
        let session = guard.as_mut().unwrap();
        session.push(&chunk)?;
        up.received.fetch_add(chunk.len() as u64, Ordering::SeqCst);
        up.touched.store(now(), Ordering::Relaxed);
    }
    Ok(Json(json!({ "received": up.received.load(Ordering::SeqCst) })).into_response())
}

async fn upload_finish(State(app): State<Shared>, h: HeaderMap, Path(sid): Path<String>) -> R<Json<Value>> {
    use std::sync::atomic::Ordering;
    let c = auth(&app, &h, "contributor", true)?;
    let up = find_upload(&app, &sid, &c.user)?;
    let mut guard = up.session.lock().await;
    let have = up.received.load(Ordering::SeqCst);
    if have != up.size {
        return Err(err(StatusCode::CONFLICT, &format!("only {have} of {} bytes have arrived", up.size)));
    }
    let session = guard.take().ok_or_else(|| err(StatusCode::GONE, "this upload was cancelled"))?;
    drop(guard);
    app.uploads.lock().unwrap().remove(&sid);
    let ing = session.finish(&app)?;
    if !ing.dup && ["movie", "series", "anime"].contains(&up.kind.as_str()) {
        let _ = library::edit_review(&app, &ing.id, None, Some(&up.kind), None, None, None);
    }
    // scanning happens in the background: the upload is done, the file waits in Review and is checked there
    library::post_ingest(&app, &ing, "upload".into()).await?;
    Ok(Json(json!({ "id": ing.id, "size": ing.size, "duplicate": ing.dup && !ing.restored, "restored": ing.restored })))
}

async fn upload_cancel(State(app): State<Shared>, h: HeaderMap, Path(sid): Path<String>) -> R<Json<Value>> {
    let c = auth(&app, &h, "contributor", true)?;
    let up = find_upload(&app, &sid, &c.user)?;
    up.takeover.notify_waiters();
    let removed = app.uploads.lock().unwrap().remove(&sid);
    if removed.is_some() {
        if let Ok(mut g) = tokio::time::timeout(Duration::from_secs(5), up.session.lock()).await {
            if let Some(s) = g.take() {
                s.abort();
            }
        }
    }
    Ok(Json(json!({ "ok": true })))
}

async fn upload(State(app): State<Shared>, h: HeaderMap, Query(q): Query<UploadQ>, body: Body) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    require_video_name(&q.name)?;
    let mut session = library::IngestSession::begin(&app, &q.name, "upload")?;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                session.abort();
                return Err(err(StatusCode::BAD_REQUEST, &format!("upload interrupted: {e}")));
            }
        };
        if let Err(e) = session.push(&chunk) {
            session.abort();
            return Err(e.into());
        }
    }
    let ing = session.finish(&app)?;
    if !ing.dup && ["movie", "series", "anime"].contains(&q.kind.as_str()) {
        let _ = library::edit_review(&app, &ing.id, None, Some(&q.kind), None, None, None);
    }
    library::post_ingest(&app, &ing, "upload".into()).await?;
    Ok(Json(json!({ "id": ing.id, "size": ing.size, "duplicate": ing.dup && !ing.restored, "restored": ing.restored })))
}

async fn review_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "owner", false)?;
    let items: Vec<Item> = app.db.with(|db| {
        let mut st = db.prepare(&format!("SELECT {} FROM items WHERE local IN ('quarantine','blocked') ORDER BY added_at DESC", crate::db::ITEM_LIGHT))?;
        let rows = st.query_map([], Item::from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;
    let mine = crate::metadata::user_genres(&app);
    let items: Vec<Value> = items
        .iter()
        .map(|i| {
            let mut v = item_json(i, c.zone == Zone::Lan);
            v["genres"] = json!(mine.get(&i.id).cloned().unwrap_or_default());
            v
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize, Default)]
struct ApproveIn {
    #[serde(default, rename = "override")]
    override_scan: bool,
}

async fn review_approve(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, body: Option<Json<ApproveIn>>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let ov = body.map(|b| b.0.override_scan).unwrap_or(false);
    library::approve(&app, &id, ov)?;
    Ok(Json(json!({ "ok": true })))
}

async fn review_reject(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "owner", true)?;
    library::reject(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize, Default)]
struct ReviewEditIn {
    title: Option<String>,
    kind: Option<String>,
    genres: Option<Vec<String>>,
    #[serde(default, deserialize_with = "opt_opt")]
    year: Option<Option<i32>>,
    #[serde(default, deserialize_with = "opt_opt")]
    season: Option<Option<i32>>,
    #[serde(default, deserialize_with = "opt_opt")]
    episode: Option<Option<i32>>,
}

/// distinguishes "field absent" (leave alone) from "null" (clear it)
fn opt_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<i32>>, D::Error> {
    Ok(Some(Option::<i32>::deserialize(d)?))
}

async fn review_edit(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(b): Json<ReviewEditIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    library::edit_review(&app, &id, b.title.as_deref(), b.kind.as_deref(), b.year, b.season, b.episode)?;
    if let Some(g) = &b.genres {
        crate::metadata::set_user_genres(&app, &id, g)?;
    }
    Ok(Json(json!({ "ok": true })))
}

/// Watch an item while it is still in review. Owner only, and only from the home network.
async fn review_stream(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Query(q): Query<StreamQ>) -> R<Response> {
    auth_home(&app, &h, "owner", false)?;
    let a = app.clone();
    let (it, reader) = tokio::task::spawn_blocking(move || library::open_review_reader(&a, &id))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    respond_stream(&app, &h, it.filename.as_deref().unwrap_or("x.mp4"), reader, q)
}

async fn poster(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Response> {
    auth(&app, &h, "viewer", false)?;
    let it = app.db.with(|db| get_item(db, &id))?.filter(|i| i.catalog && !i.deleted).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such item"))?;
    let key = crate::metadata::key_of(&it);
    let a = app.clone();
    let bytes = tokio::task::spawn_blocking(move || crate::metadata::poster_bytes(&a, &key))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .map_err(|_| err(StatusCode::NOT_FOUND, "no poster"))?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, crate::metadata::image_mime(&bytes))
        .header(header::CACHE_CONTROL, "private, max-age=86400")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(bytes))
        .unwrap())
}

#[derive(Deserialize)]
struct GenresIn {
    genres: Vec<String>,
}

async fn item_genres(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(b): Json<GenresIn>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    app.db.with(|db| get_item(db, &id))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such item"))?;
    crate::metadata::set_user_genres(&app, &id, &b.genres)?;
    Ok(Json(json!({ "ok": true })))
}

async fn metadata_status(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "viewer", false)?;
    let (found, pending) = crate::metadata::counts(&app);
    Ok(Json(json!({ "enabled": app.cfg.metadata.enabled, "found": found, "pending": pending, "tmdb": !app.cfg.metadata.tmdb_key.is_empty() })))
}

#[derive(Deserialize, Default)]
struct RefreshIn {
    id: Option<String>,
}

async fn metadata_refresh(State(app): State<Shared>, h: HeaderMap, body: Option<Json<RefreshIn>>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if let Some(id) = body.and_then(|b| b.0.id) {
        let it = app.db.with(|db| get_item(db, &id))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such item"))?;
        let key = crate::metadata::key_of(&it);
        let found = crate::metadata::fetch_and_store_titles(&app, &key, &crate::metadata::lookup_titles(&it), &it.kind, it.year).await?;
        return Ok(Json(json!({ "found": found })));
    }
    let n = crate::metadata::retry_unknown(&app)?;
    Ok(Json(json!({ "retrying": n })))
}

async fn update_status(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    Ok(Json(crate::update::status(&app)))
}

#[derive(Deserialize)]
struct UpdateIn {
    action: String,
}

async fn update_request(State(app): State<Shared>, h: HeaderMap, Json(b): Json<UpdateIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::update::request(&app, &b.action)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct KillIn {
    password: String,
    /// the node's name, typed out by the owner
    name: String,
    /// must be exactly KILL NODE
    phrase: String,
}

/// Kill node: owner, at home, password again, node name typed, fixed phrase typed. The UI also walks through
/// several warnings before it ever sends this.
async fn kill_node(State(app): State<Shared>, h: HeaderMap, Json(b): Json<KillIn>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "owner", true)?;
    if b.phrase.trim() != "KILL NODE" || b.name.trim() != app.cfg.name {
        return Err(err(StatusCode::BAD_REQUEST, "The node name or the confirmation phrase does not match. Nothing was removed."));
    }
    let a2 = app.clone();
    let pw = b.password.clone();
    let ok = tokio::task::spawn_blocking(move || a2.keyring.verify_password(&pw)).await.unwrap_or(false);
    if !ok {
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        return Err(err(StatusCode::FORBIDDEN, "That password is not right. Nothing was removed."));
    }
    let mode = crate::update::kill(&app).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    tracing::warn!("kill node requested by {}", c.user);
    app.sessions.lock().unwrap().clear();
    Ok(Json(json!({ "ok": true, "mode": mode })))
}

/// What this node measured about itself and the limits it chose. Everyone who can upload learns the upload
/// parallelism; the hardware details are for the owner at home.
async fn perf_get(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "contributor", false)?;
    let t = app.tuning();
    if !(c.role == "owner" && c.zone == Zone::Lan) {
        return Ok(Json(json!({ "upload_parallel": t.upload_parallel })));
    }
    Ok(Json(json!({
        "dedicated": app.perf_dedicated.load(std::sync::atomic::Ordering::Relaxed),
        "hardware": app.hw.read().unwrap().clone(),
        "net_mbps": app.hw.read().unwrap().net_mbps(),
        "tuning": t,
        "upload_parallel": t.upload_parallel,
        "rest": { "mode": crate::rest::mode(&app).name(), "idle_min": crate::rest::idle_minutes(&app), "active": crate::rest::enabled(&app), "resting": crate::rest::is_resting(&app), "resting_secs": crate::rest::resting_for(&app), "activity": crate::rest::activity(&app) },
        "sanity": crate::sanity::status(&app),
    })))
}

#[derive(Deserialize)]
struct PerfIn {
    dedicated: Option<bool>,
    rest_mode: Option<String>,
    rest_idle_min: Option<u64>,
}

async fn perf_set(State(app): State<Shared>, h: HeaderMap, Json(b): Json<PerfIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if let Some(d) = b.dedicated {
        app.set_perf_dedicated(d).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    if let Some(m) = b.rest_mode {
        let m = crate::rest::Mode::parse(&m).ok_or_else(|| err(StatusCode::BAD_REQUEST, "rest mode is auto, on or off"))?;
        app.db.set_setting("rest_mode", m.name()).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    if let Some(n) = b.rest_idle_min {
        app.db.set_setting("rest_idle_min", &n.clamp(1, 1440).to_string()).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    }
    crate::rest::touch(&app);
    Ok(Json(json!({ "ok": true, "dedicated": app.perf_dedicated.load(std::sync::atomic::Ordering::Relaxed), "tuning": app.tuning() })))
}

async fn review_rescan(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let it = app.db.with(|db| get_item(db, &id))?.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such item"))?;
    let rep = crate::quarantine::scan(&app, &id, it.filename.as_deref().unwrap_or("")).await?;
    Ok(Json(json!({ "report": rep })))
}

// ------------------------------------------------------------------ acquire

async fn acq_providers(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "contributor", false)?;
    let p: Vec<Value> = crate::acquire::providers(&app).iter().map(|p| json!({ "id": p.id(), "label": p.label() })).collect();
    Ok(Json(json!({ "providers": p, "route": crate::acquire::effective_route(&app.cfg) })))
}

#[derive(Deserialize)]
struct SearchQ {
    q: String,
    provider: Option<String>,
}

async fn acq_search(State(app): State<Shared>, h: HeaderMap, Query(q): Query<SearchQ>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", false)?;
    let r = crate::acquire::search(&app, q.provider.as_deref().filter(|s| !s.is_empty()), &q.q).await?;
    Ok(Json(json!({ "results": r })))
}

#[derive(Deserialize)]
struct QueueIn {
    provider: String,
    url: String,
    title: String,
    #[serde(default)]
    kind: String,
}

async fn acq_queue(State(app): State<Shared>, h: HeaderMap, Json(b): Json<QueueIn>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    let id = crate::acquire::queue(&app, &b.provider, &b.url, &b.title, &b.kind).await?;
    Ok(Json(json!({ "id": id })))
}

async fn downloads(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "contributor", false)?;
    let t = now();
    let rows = app.db.with(|db| {
        // the status of a finished download follows what happened to its file in Review
        let mut st = db.prepare(
            "SELECT d.id,d.provider,d.title,d.status,d.got,d.total,d.error,d.item,d.created,COALESCE(d.finished,d.created),i.local,i.id IS NOT NULL
             FROM downloads d LEFT JOIN items i ON i.id=d.item
             ORDER BY d.created DESC LIMIT 60",
        )?;
        let rows = st.query_map([], |r| {
            let status: String = r.get(3)?;
            let local: Option<String> = r.get(10)?;
            let has_item: bool = r.get(11)?;
            let finished: i64 = r.get(9)?;
            let shown = if status == "review" {
                match (has_item, local.as_deref()) {
                    (false, _) => "rejected",
                    (true, Some("quarantine")) => "review",
                    (true, Some("blocked")) => "blocked",
                    (true, Some("rejected")) => "rejected",
                    _ => "approved",
                }
            } else {
                status.as_str()
            };
            Ok((shown.to_string(), finished, json!({
                "id": r.get::<_, String>(0)?, "provider": r.get::<_, String>(1)?, "title": r.get::<_, String>(2)?,
                "status": shown, "got": r.get::<_, i64>(4)?, "total": r.get::<_, i64>(5)?,
                "error": r.get::<_, Option<String>>(6)?, "item": r.get::<_, Option<String>>(7)?, "created": r.get::<_, i64>(8)?,
            })))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;
    // approved or rejected entries have done their job: they stay a few minutes, then disappear
    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|(s, fin, _)| !(matches!(s.as_str(), "approved" | "rejected") && t - fin > 600))
        .map(|(_, _, v)| v)
        .collect();
    Ok(Json(json!({ "downloads": rows })))
}

async fn download_cancel(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    crate::acquire::cancel(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

async fn download_retry(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    crate::acquire::retry(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

async fn download_remove(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    let n = app.db.with(|c| Ok(c.execute("DELETE FROM downloads WHERE id=?1 AND status IN ('failed','cancelled','duplicate','approved','rejected')", [&id])?))?;
    if n == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "only finished downloads can be removed from the list; cancel a running one first"));
    }
    Ok(Json(json!({ "ok": true })))
}

async fn downloads_clear(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "contributor", true)?;
    let n = crate::acquire::clear_finished(&app)?;
    Ok(Json(json!({ "removed": n })))
}

// ------------------------------------------------------------------ mesh and sync

async fn sync_status(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    let c = auth(&app, &h, "owner", false)?;
    let home = c.zone == Zone::Lan;
    let peers = app.db.with(list_peers)?;
    let live = app.live.lock().unwrap().clone();
    let peers_json: Vec<Value> = peers
        .iter()
        .map(|p| {
            json!({
                "node_id": p.node_id, "name": p.name, "addr": if home { Some(p.addr.clone()) } else { None }, "fingerprint": fingerprint(&p.node_id),
                "enabled": p.enabled, "last_seen": p.last_seen, "last_ok": p.last_ok, "last_error": p.last_error,
                "live": live.get(&p.node_id),
            })
        })
        .collect();
    let requests = app.db.with(|db| {
        let mut st = db.prepare(
            "SELECT r.id,r.peer,COALESCE(p.name,'(removed)'),r.dir,r.items,r.bytes,r.status,r.reason,r.created
             FROM sync_requests r LEFT JOIN peers p ON p.node_id=r.peer ORDER BY r.created DESC LIMIT 30",
        )?;
        let rows = st.query_map([], |r| {
            let items: String = r.get(4)?;
            let n = serde_json::from_str::<Vec<String>>(&items).map(|v| v.len()).unwrap_or(0);
            Ok(json!({
                "id": r.get::<_, String>(0)?, "peer": r.get::<_, String>(1)?, "peer_name": r.get::<_, String>(2)?,
                "dir": r.get::<_, String>(3)?, "count": n, "bytes": r.get::<_, i64>(5)?, "status": r.get::<_, String>(6)?,
                "reason": r.get::<_, Option<String>>(7)?, "created": r.get::<_, i64>(8)?,
            }))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })?;
    let tor = app.tor.lock().unwrap().clone();
    let transfers: Vec<_> = app.transfers.lock().unwrap().values().cloned().collect();
    Ok(Json(json!({
        "node": {
            "name": app.cfg.name, "fingerprint": fingerprint(&app.id.id), "transport": app.cfg.transport,
            "id": if home { Some(app.id.id.clone()) } else { None },
            "mesh_addr": if home { Some(app.mesh_addr()) } else { None },
            "access_onion": if home { tor.access_onion.clone() } else { None },
        },
        "locked": !app.keyring.is_unlocked(),
        "policy": app.policy(),
        "gate": app.gate().err(),
        "disk": { "free": app.disk_free(), "library": app.library_bytes() },
        "tor": { "enabled": tor.enabled, "bootstrap": tor.bootstrap, "error": if home { tor.error.clone() } else { None } },
        "peers": peers_json,
        "requests": requests,
        "transfers": transfers,
    })))
}

async fn sync_policy(State(app): State<Shared>, h: HeaderMap, Json(mut p): Json<SyncPolicy>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if p.mode != "auto" && p.mode != "ask" {
        return Err(err(StatusCode::BAD_REQUEST, "mode must be auto or ask"));
    }
    p.max_concurrent = p.max_concurrent.clamp(1, 8);
    p.window_start %= 24;
    p.window_end %= 24;
    p.utc_offset = p.utc_offset.clamp(-12, 14);
    p.transcode_threads = p.transcode_threads.clamp(1, 16);
    p.nice = p.nice.clamp(0, 19);
    p.mirror_kinds.retain(|k| ["movie", "series", "anime"].contains(&k.as_str()));
    app.set_policy(p.clone())?;
    Ok(Json(json!({ "policy": p })))
}

async fn sync_now(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "owner", true)?;
    app.wake.notify_waiters();
    Ok(Json(json!({ "ok": true })))
}

async fn sync_approve(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "owner", true)?;
    crate::sync::answer_inbound(&app, &id, true, None)?;
    Ok(Json(json!({ "ok": true })))
}

async fn sync_deny(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "owner", true)?;
    crate::sync::answer_inbound(&app, &id, false, None)?;
    Ok(Json(json!({ "ok": true })))
}

async fn pair_overview(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    Ok(Json(json!({
        "invites": crate::pair::list_invites(&app)?,
        "incoming": crate::pair::incoming(&app)?,
        "outgoing": crate::pair::outgoing(&app)?,
        "fingerprint": fingerprint(&app.id.id),
    })))
}

async fn pair_invite(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let inv = crate::pair::create_invite(&app, "")?;
    Ok(Json(json!({ "id": inv.id, "code": inv.code, "expires": inv.expires, "fingerprint": inv.fingerprint, "qr": qr_data_url(&inv.code) })))
}

async fn pair_invite_cancel(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::pair::cancel_invite(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct JoinIn {
    code: String,
}

async fn pair_join(State(app): State<Shared>, h: HeaderMap, Json(b): Json<JoinIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let id = crate::pair::request_join(&app, &b.code)?;
    app.wake.notify_waiters();
    Ok(Json(json!({ "id": id })))
}

async fn pair_accept(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::pair::decide(&app, &id, true)?;
    Ok(Json(json!({ "ok": true })))
}

async fn pair_deny(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::pair::decide(&app, &id, false)?;
    Ok(Json(json!({ "ok": true })))
}

async fn pair_outgoing_cancel(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::pair::cancel_outgoing(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

async fn peer_delete(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::pair::remove_peer(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct EnabledIn {
    enabled: bool,
}

async fn peer_enabled(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(b): Json<EnabledIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    app.db.with(|db| {
        db.execute("UPDATE peers SET enabled=?2 WHERE node_id=?1", params![id, b.enabled as i64])?;
        Ok(())
    })?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct DeviceIn {
    name: String,
}

async fn device_add(State(app): State<Shared>, h: HeaderMap, Json(b): Json<DeviceIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if app.cfg.transport != "tor" {
        return Err(err(StatusCode::BAD_REQUEST, "device keys are only used in Tor mode"));
    }
    let line = crate::tor::add_access_device(&app, &b.name)?;
    Ok(Json(json!({ "auth_line": line })))
}

/// The extra lock is "on" while at least one device key exists. Turning it off is always possible from the home network.
async fn device_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    let keys: Vec<Value> = crate::tor::list_access_devices(&app).into_iter().map(|(n, t)| json!({ "name": n, "created": t })).collect();
    Ok(Json(json!({ "keys": keys, "active": !keys.is_empty() })))
}

async fn device_remove(State(app): State<Shared>, h: HeaderMap, Path(name): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if !crate::tor::list_access_devices(&app).iter().any(|(n, _)| *n == name) {
        return Err(err(StatusCode::NOT_FOUND, "no such key"));
    }
    crate::tor::remove_access_device(&app, &name);
    Ok(Json(json!({ "ok": true })))
}

async fn device_clear(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let n = crate::tor::remove_all_access_devices(&app);
    Ok(Json(json!({ "ok": true, "removed": n })))
}

// ------------------------------------------------------------------ users

async fn users_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    let u: Vec<Value> = crate::auth::list_users(&app)?.into_iter().map(|(n, r)| { let av = avatar_version(&app, &n); json!({ "name": n, "role": r, "avatar": av }) }).collect();
    Ok(Json(json!({ "users": u })))
}

#[derive(Deserialize)]
struct UserIn {
    name: String,
    password: String,
    role: String,
}

async fn users_add(State(app): State<Shared>, h: HeaderMap, Json(b): Json<UserIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if b.role == "owner" {
        return Err(err(StatusCode::BAD_REQUEST, "there is exactly one owner"));
    }
    let a = app.clone();
    tokio::task::spawn_blocking(move || crate::auth::create_user(&a, &b.name, &b.password, &b.role))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    Ok(Json(json!({ "ok": true })))
}

async fn users_delete(State(app): State<Shared>, h: HeaderMap, Path(name): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::auth::delete_user(&app, &name)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PwIn {
    old: String,
    new: String,
}

async fn password_change(State(app): State<Shared>, h: HeaderMap, Json(b): Json<PwIn>) -> R<Json<Value>> {
    let c = auth_home(&app, &h, "viewer", true)?;
    let a = app.clone();
    tokio::task::spawn_blocking(move || crate::auth::change_user_password(&a, &c.user, &b.old, &b.new))
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))??;
    Ok(Json(json!({ "ok": true })))
}

// ------------------------------------------------------------------ sources

async fn sources_list(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    Ok(Json(json!({ "sources": crate::acquire::list_sources(&app)? })))
}

#[derive(Deserialize)]
struct SourceIn {
    kind: String,
    name: String,
    url: String,
    token: String,
}

async fn sources_add(State(app): State<Shared>, h: HeaderMap, Json(b): Json<SourceIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let id = crate::acquire::add_source(&app, &b.kind, &b.name, &b.url, &b.token)?;
    Ok(Json(json!({ "id": id })))
}

async fn sources_delete(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    crate::acquire::delete_source(&app, &id)?;
    Ok(Json(json!({ "ok": true })))
}

#[allow(dead_code)]
fn _unused(_: &str) -> &str {
    ITEM_COLS
}

#[allow(dead_code)]
const _M: Method = Method::GET;


// ------------------------------------------------------------------ storage (drives and NAS)

fn bad(m: &str) -> ApiErr {
    err(StatusCode::BAD_REQUEST, m)
}

fn storage_view(app: &crate::state::App) -> Value {
    use crate::storage as st;
    let c = st::cfg(app);
    let sys = st::probe_system(app);
    let (sn, sb) = st::holdings(&app.dirs.root);
    let mut vols = vec![];
    for v in &c.volumes {
        let s = st::probe_volume(app, v);
        let (n, b) = if s.online { st::holdings(std::path::Path::new(&v.path)) } else { (0, 0) };
        vols.push(json!({ "volume": v, "status": s, "files": n, "bytes": b, "drain": st::drain_state(&v.id) }));
    }
    json!({
        "mode": c.mode,
        "policy": c.policy,
        "system": { "enabled": c.system_enabled, "path": app.dirs.root.display().to_string(), "reserve_gb": c.system_reserve_gb,
                    "status": sys, "files": sn, "bytes": sb, "imports": c.system_imports, "drain": st::drain_state("system") },
        "volumes": vols,
        "drives": st::detect_drives(app),
        "helper": std::path::Path::new("/usr/local/bin/syphon-update").exists(),
        "tools": { "nfs": st::tool_present("mount.nfs"), "smb": st::tool_present("mount.cifs") },
        "import": st::import_state(),
    })
}

async fn storage_get(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", false)?;
    let a = app.clone();
    let v = tokio::task::spawn_blocking(move || storage_view(&a)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Json(v))
}

#[derive(Deserialize)]
struct StoragePut {
    mode: Option<String>,
    policy: Option<String>,
    system_enabled: Option<bool>,
    /// null clears it (a sensible amount is chosen); a number sets it
    #[serde(default, deserialize_with = "double_opt")]
    system_reserve_gb: Option<Option<u32>>,
    system_imports: Option<Vec<crate::storage::ImportDir>>,
}

fn double_opt<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::<T>::deserialize(d)?))
}

fn check_imports(v: &[crate::storage::ImportDir]) -> Result<(), ApiErr> {
    if v.len() > 20 {
        return Err(bad("too many folders"));
    }
    for d in v {
        if !crate::storage::valid_sub(&d.sub) {
            return Err(bad("a folder name is not valid"));
        }
        if !["", "movie", "series", "anime"].contains(&d.kind.as_str()) {
            return Err(bad("a folder's type must be movie, series, anime or blank"));
        }
    }
    Ok(())
}

async fn storage_put(State(app): State<Shared>, h: HeaderMap, Json(b): Json<StoragePut>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let mut c = crate::storage::cfg(&app);
    if let Some(m) = b.mode {
        if !["all", "selected"].contains(&m.as_str()) {
            return Err(bad("mode must be all or selected"));
        }
        c.mode = m;
    }
    if let Some(p) = b.policy {
        if !["most_free", "in_order"].contains(&p.as_str()) {
            return Err(bad("policy must be most_free or in_order"));
        }
        c.policy = p;
    }
    if let Some(r) = b.system_reserve_gb {
        if r.map(|g| g > 100_000).unwrap_or(false) {
            return Err(bad("that reserve is too large"));
        }
        c.system_reserve_gb = r;
    }
    if let Some(i) = b.system_imports {
        check_imports(&i)?;
        c.system_imports = i;
    }
    if let Some(e) = b.system_enabled {
        if !e && !c.volumes.iter().any(|v| v.enabled) {
            return Err(bad("turn on another drive before turning the system drive off for new files"));
        }
        c.system_enabled = e;
    }
    crate::storage::save(&app, c)?;
    let a = app.clone();
    tokio::task::spawn_blocking(move || crate::storage::sync_all(&a)).await.map_err(|e| anyhow::anyhow!("{e}"))??;
    app.storage_wake.notify_waiters();
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct VolumeIn {
    label: Option<String>,
    /// a drive's mount point (Syphon makes a "syphon" folder in it) or any folder you want to use
    path: String,
    reserve_gb: Option<u32>,
    #[serde(default)]
    imports: Vec<crate::storage::ImportDir>,
}

fn owning_mount(app: &crate::state::App, p: &std::path::Path) -> String {
    if crate::storage::is_mount(p) {
        return p.to_string_lossy().to_string();
    }
    crate::storage::detect_drives(app)
        .into_iter()
        .filter(|d| p.starts_with(&d.mount) && d.mount != "/")
        .max_by_key(|d| d.mount.len())
        .map(|d| d.mount)
        .unwrap_or_default()
}

fn add_volume_blocking(app: &crate::state::App, b: VolumeIn, kind: &str, nas: Option<crate::storage::NasLink>, force_path: Option<std::path::PathBuf>) -> Result<Value, ApiErr> {
    use crate::storage as st;
    let base = force_path.unwrap_or_else(|| std::path::PathBuf::from(b.path.trim()));
    if let Some(m) = st::forbidden_path(&base) {
        return Err(bad(&format!("{}: {m}", base.display())));
    }
    if !base.is_dir() {
        return Err(bad(&format!("{} is not a folder on this computer", base.display())));
    }
    let mut c = st::cfg(app);
    // a mount point gets its own "syphon" folder; another folder is used as it is
    let is_mp = st::is_mount(&base);
    let path = if is_mp && kind == "local" { st::volume_path_for(&base.to_string_lossy()) } else { base.to_string_lossy().to_string() };
    let pp = std::path::Path::new(&path);
    if pp.starts_with(&app.dirs.root) || app.dirs.root.starts_with(pp) {
        return Err(bad("that folder overlaps the node's own data folder"));
    }
    if c.volumes.iter().any(|v| v.path == path || std::path::Path::new(&v.path).starts_with(pp) || pp.starts_with(&v.path)) {
        return Err(bad("that drive or folder is already in use"));
    }
    check_imports(&b.imports)?;
    let label = b.label.clone().filter(|l| !l.trim().is_empty()).unwrap_or_else(|| base.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "Drive".into()));
    if !st::valid_label(&label) {
        return Err(bad("the name may use letters, numbers, spaces, - _ . (up to 40)"));
    }
    if c.volumes.iter().any(|v| v.label.eq_ignore_ascii_case(label.trim())) {
        return Err(bad("another drive already has that name"));
    }
    let mount = if kind == "nas" && nas.as_ref().map(|n| n.proto != "mounted").unwrap_or(false) { String::new() } else { owning_mount(app, &base) };
    let v = st::Volume { id: st::new_volume_id(), label: label.trim().to_string(), path, kind: kind.into(), enabled: true, reserve_gb: b.reserve_gb, mount, nas, imports: b.imports, auto: false };
    st::ensure_folder(app, &v);
    let id = v.id.clone();
    c.volumes.push(v);
    st::save(app, c)?;
    app.storage_wake.notify_waiters();
    Ok(json!({ "ok": true, "id": id }))
}

async fn storage_volume_add(State(app): State<Shared>, h: HeaderMap, Json(b): Json<VolumeIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let a = app.clone();
    let v = tokio::task::spawn_blocking(move || add_volume_blocking(&a, b, "local", None, None)).await.map_err(|e| anyhow::anyhow!("{e}"))??;
    Ok(Json(v))
}

#[derive(Deserialize)]
struct NasIn {
    /// "nfs", "smb" or "mounted"
    proto: String,
    label: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    share: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    password: String,
    /// folder inside the share where Syphon keeps its encrypted files
    #[serde(default)]
    sub: String,
    /// for "mounted": where you mounted it
    #[serde(default)]
    mount: String,
    reserve_gb: Option<u32>,
    #[serde(default)]
    imports: Vec<crate::storage::ImportDir>,
}

async fn storage_nas_add(State(app): State<Shared>, h: HeaderMap, Json(b): Json<NasIn>) -> R<Json<Value>> {
    use crate::storage as st;
    auth_home(&app, &h, "owner", true)?;
    if !["nfs", "smb", "mounted"].contains(&b.proto.as_str()) {
        return Err(bad("type must be nfs, smb or mounted"));
    }
    if !st::valid_label(&b.label) {
        return Err(bad("the name may use letters, numbers, spaces, - _ . (up to 40)"));
    }
    let sub = if b.sub.trim().is_empty() { "syphon".to_string() } else { b.sub.trim().trim_matches('/').to_string() };
    if !st::valid_sub(&sub) {
        return Err(bad("the Syphon folder name is not valid"));
    }
    let link = st::NasLink { proto: b.proto.clone(), host: b.host.trim().to_string(), share: b.share.trim().trim_start_matches('/').to_string(), user: b.user.clone() };
    let reserve = b.reserve_gb;
    let imports = b.imports.clone();
    let label = b.label.clone();
    if b.proto == "mounted" {
        let m = std::path::PathBuf::from(b.mount.trim());
        if !st::is_mount(&m) {
            return Err(bad("nothing is mounted at that folder yet. Mount the share first, then link it here"));
        }
        let p = m.join(&sub);
        let a = app.clone();
        let vin = VolumeIn { label: Some(label), path: p.to_string_lossy().to_string(), reserve_gb: reserve, imports };
        let mut res = tokio::task::spawn_blocking(move || add_volume_blocking(&a, vin, "nas", Some(link), Some(p))).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        // remember the real mount point, not the folder inside it
        if let Some(id) = res["id"].as_str() {
            let mut c = st::cfg(&app);
            if let Some(v) = c.volumes.iter_mut().find(|v| v.id == id) {
                v.mount = m.to_string_lossy().to_string();
            }
            st::save(&app, c)?;
        }
        res["note"] = json!("Linked.");
        return Ok(Json(res));
    }
    if !st::valid_host(&b.host.trim()) || !st::valid_share(b.share.trim().trim_start_matches('/')) {
        return Err(bad("the address or share name is not valid"));
    }
    if !st::valid_cred(&b.user) || !st::valid_cred(&b.password) {
        return Err(bad("the user name or password has characters that cannot be used"));
    }
    if !std::path::Path::new("/usr/local/bin/syphon-update").exists() {
        return Err(bad("this node was not installed with the helper that mounts shares. Mount the share yourself (see the README) and choose \"already mounted\""));
    }
    if (b.proto == "nfs" && !st::tool_present("mount.nfs")) || (b.proto == "smb" && !st::tool_present("mount.cifs")) {
        return Err(bad(if b.proto == "nfs" { "NFS support is missing on this computer. Install it first: sudo apt install nfs-common" } else { "SMB support is missing on this computer. Install it first: sudo apt install cifs-utils" }));
    }
    let c0 = st::cfg(&app);
    let slug = st::slug(&b.label);
    let mp = format!("/mnt/syphon/{slug}");
    if c0.volumes.iter().any(|v| v.mount == mp) {
        return Err(bad("a share with that name is already linked"));
    }
    let mountpoint = std::path::PathBuf::from(&mp);
    let vol_path = format!("{mp}/{sub}");
    if c0.volumes.iter().any(|v| v.label.eq_ignore_ascii_case(b.label.trim())) {
        return Err(bad("another drive already has that name"));
    }
    check_imports(&imports)?;
    let v = st::Volume { id: st::new_volume_id(), label: b.label.trim().to_string(), path: vol_path.clone(), kind: "nas".into(), enabled: true, reserve_gb: reserve, mount: mp.clone(), nas: Some(link), imports, auto: false };
    let id = v.id.clone();
    let mut c = c0;
    c.volumes.push(v);
    st::save(&app, c)?;
    let ok = st::request_helper(&app, "nas-add", &[("label", b.label.trim()), ("slug", &slug), ("proto", &b.proto), ("host", b.host.trim()), ("share", b.share.trim().trim_start_matches('/')), ("user", &b.user), ("pass", &b.password), ("mount", &mp), ("sub", &sub)]);
    let _ = mountpoint;
    if !ok {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "could not pass the request to the helper"));
    }
    app.storage_wake.notify_waiters();
    Ok(Json(json!({ "ok": true, "id": id, "note": "Connecting. This takes a few seconds; the drive shows as connected when it works." })))
}

#[derive(Deserialize)]
struct VolumePatch {
    label: Option<String>,
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "double_opt")]
    reserve_gb: Option<Option<u32>>,
    imports: Option<Vec<crate::storage::ImportDir>>,
}

async fn storage_volume_patch(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Json(b): Json<VolumePatch>) -> R<Json<Value>> {
    use crate::storage as st;
    auth_home(&app, &h, "owner", true)?;
    let mut c = st::cfg(&app);
    let others_on = c.volumes.iter().filter(|v| v.enabled && v.id != id).count();
    let sys_on = c.system_enabled;
    let v = c.volumes.iter_mut().find(|v| v.id == id).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such drive"))?;
    if let Some(l) = b.label {
        if !st::valid_label(&l) {
            return Err(bad("the name may use letters, numbers, spaces, - _ . (up to 40)"));
        }
        v.label = l.trim().to_string();
    }
    if let Some(e) = b.enabled {
        if !e && !sys_on && others_on == 0 {
            return Err(bad("at least one drive must stay on for new files"));
        }
        v.enabled = e;
    }
    if let Some(r) = b.reserve_gb {
        v.reserve_gb = r;
    }
    if let Some(i) = b.imports {
        check_imports(&i)?;
        v.imports = i;
    }
    st::save(&app, c)?;
    app.storage_wake.notify_waiters();
    Ok(Json(json!({ "ok": true })))
}

async fn storage_volume_drain(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    let c = crate::storage::cfg(&app);
    let others = c.volumes.iter().filter(|v| v.id != id).count() + usize::from(id != "system");
    if others == 0 {
        return Err(bad("there is no other drive to move the files to"));
    }
    crate::storage::start_drain(&app, &id).map_err(|e| bad(&e.to_string()))?;
    Ok(Json(json!({ "ok": true })))
}

async fn storage_volume_delete(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    use crate::storage as st;
    auth_home(&app, &h, "owner", true)?;
    let mut c = st::cfg(&app);
    let pos = c.volumes.iter().position(|v| v.id == id).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such drive"))?;
    let v = c.volumes[pos].clone();
    if st::drain_state(&id).map(|d| d.running).unwrap_or(false) {
        return Err(bad("its files are still being moved"));
    }
    let (n, _) = st::holdings(std::path::Path::new(&v.path));
    if n > 0 {
        return Err(err(StatusCode::CONFLICT, &format!("{} still holds {n} files. Move them to your other drives first (\"Move files off\"), then remove it.", v.label)));
    }
    c.volumes.remove(pos);
    st::save(&app, c)?;
    let mut note = "Removed.".to_string();
    if let Some(n) = &v.nas {
        if n.proto != "mounted" {
            st::request_helper(&app, "nas-remove", &[("slug", &st::slug(&v.label)), ("mount", &v.mount)]);
            note = "Removed. The share is being disconnected; the files on it were not touched.".into();
        }
    }
    Ok(Json(json!({ "ok": true, "note": note })))
}

#[derive(Deserialize)]
struct FoldersQ {
    #[serde(default)]
    sub: String,
}

async fn storage_folders(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>, Query(q): Query<FoldersQ>) -> R<Json<Value>> {
    use crate::storage as st;
    auth_home(&app, &h, "owner", false)?;
    let c = st::cfg(&app);
    let base = if id == "system" {
        std::path::PathBuf::from("/")
    } else {
        let v = c.volumes.iter().find(|v| v.id == id).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such drive"))?;
        if v.mount.is_empty() || !st::is_mount(std::path::Path::new(&v.mount)) {
            return Err(bad("this drive is not connected"));
        }
        std::path::PathBuf::from(&v.mount)
    };
    let sub = q.sub.clone();
    let list = tokio::task::spawn_blocking(move || st::list_folders(&base, &sub)).await.map_err(|e| anyhow::anyhow!("{e}"))?.map_err(|e| bad(&e.to_string()))?;
    Ok(Json(json!({ "folders": list })))
}

async fn storage_scan(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if !app.keyring.is_unlocked() {
        return Err(bad("sign in as the owner first so the library is unlocked"));
    }
    app.storage_wake.notify_waiters();
    Ok(Json(json!({ "ok": true })))
}


// ------------------------------------------------------------------ how a video is played

async fn item_playback(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Json<Value>> {
    auth(&app, &h, "viewer", false)?;
    let p = library::playback_info(&app, &id).await?;
    let audio_ok = matches!(p.acodec.as_str(), "aac" | "mp3" | "opus" | "flac" | "");
    Ok(Json(json!({ "playback": p, "audio_ok": audio_ok, "quality": library::node_quality(&app) })))
}

async fn playback_get(State(app): State<Shared>, h: HeaderMap) -> R<Json<Value>> {
    auth(&app, &h, "viewer", false)?;
    Ok(Json(json!({ "quality": library::node_quality(&app), "qualities": library::QUALITIES, "codec": library::node_codec(&app), "av1_encoder": library::av1_encoder(&app) })))
}

#[derive(Deserialize)]
struct PlaybackIn {
    quality: Option<String>,
    codec: Option<String>,
}

async fn playback_set(State(app): State<Shared>, h: HeaderMap, Json(b): Json<PlaybackIn>) -> R<Json<Value>> {
    auth_home(&app, &h, "owner", true)?;
    if let Some(q) = &b.quality {
        if !library::QUALITIES.iter().any(|x| x.id == q) {
            return Err(bad("unknown quality"));
        }
        app.db.set_setting("transcode_quality", q)?;
    }
    if let Some(c) = &b.codec {
        if c != "av1" && c != "h264" {
            return Err(bad("the format is av1 or h264"));
        }
        app.db.set_setting("transcode_codec", c)?;
    }
    Ok(Json(json!({ "ok": true, "quality": library::node_quality(&app), "codec": library::node_codec(&app) })))
}

/// A small preview picture for an episode (made on first request, then kept encrypted).
async fn item_frame(State(app): State<Shared>, h: HeaderMap, Path(id): Path<String>) -> R<Response> {
    auth(&app, &h, "viewer", false)?;
    let it = app.db.with(|db| get_item(db, &id))?.filter(|i| i.catalog && !i.deleted && i.local == "present").ok_or_else(|| err(StatusCode::NOT_FOUND, "no such item"))?;
    let bytes = library::frame_jpeg(&app, &it.id).await.map_err(|_| err(StatusCode::NOT_FOUND, "no preview"))?;
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "image/jpeg")
        .header(header::CACHE_CONTROL, "private, max-age=86400")
        .header("x-content-type-options", "nosniff")
        .body(Body::from(bytes))
        .unwrap())
}
