//! End-to-end tests. Nodes run in-process on loopback in "direct" transport mode; everything above
//! the transport (signing, catalog, request/answer flow, caps, encryption) is the real code path.

use syphon::config::{Config, Dirs};
use syphon::library::{self, IngestSession};
use syphon::state::{App, Shared};
use syphon::security::Via;
use syphon::{acquire, api, db, mesh, pair, sync};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const PW: &str = "correct horse battery";

struct TestNode {
    app: Shared,
    mesh_url: String,
    access_url: String,
    /// same API, but reached "through Tor": always the remote zone
    remote_url: String,
    _dir: tempfile::TempDir,
}

async fn node_with(name: &str, tweak: impl FnOnce(&mut Config)) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let dirs = Dirs::new(dir.path());
    let mut cfg = Config::default();
    cfg.name = name.into();
    cfg.transport = "direct".into();
    cfg.kdf_m_kib = 64;
    cfg.kdf_t = 1;
    cfg.heartbeat_secs = 3600;
    cfg.sync.min_free_gb = 0;
    cfg.acquire.allow_private_hosts = true;
    // the synthetic test files are structurally valid but not decodable video: use the file-level
    // layers (signatures, structure, blocklist) and leave the media tools to the tests that use real video
    cfg.ffprobe = "syphon-test-no-ffprobe".into();
    cfg.scan.decode = false;
    cfg.scan.clamav = "off".into();
    cfg.scan.background = false; // scans run inline, so a test can check the result right after the call
    tweak(&mut cfg);
    App::init(&dirs, cfg, "owner", PW).unwrap();
    let app = App::open(dirs.clone(), Config::load(&dirs).unwrap()).unwrap();
    // test machines can be nearly full: the drives' free-space reserve is tested on its own
    let mut sc = syphon::storage::cfg(&app);
    sc.system_reserve_gb = Some(0);
    syphon::storage::save(&app, sc).unwrap();
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let m = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let r = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_url = format!("http://{}", r.local_addr().unwrap());
    let mesh_url = format!("http://{}", m.local_addr().unwrap());
    let access_url = format!("http://{}", a.local_addr().unwrap());
    *app.mesh_addr.lock().unwrap() = mesh_url.clone();
    tokio::spawn(api::serve(app.clone(), a, Via::Lan));
    tokio::spawn(api::serve(app.clone(), r, Via::Tor));
    tokio::spawn(mesh::serve(app.clone(), m));
    app.keyring.unlock(PW).unwrap();
    TestNode { app, mesh_url, access_url, remote_url, _dir: dir }
}

async fn node(name: &str) -> TestNode {
    node_with(name, |_| {}).await
}

/// The real request flow: A invites, B asks, A accepts, B notices. One direction pairs both nodes.
async fn pair_up(a: &TestNode, b: &TestNode) {
    let inv = pair::create_invite(&a.app, "").unwrap();
    pair::request_join(&b.app, &inv.code).unwrap();
    pair::tick(&b.app).await; // B sends the request
    let req = pair::incoming(&a.app).unwrap();
    assert_eq!(req.len(), 1, "A sees exactly one request");
    pair::decide(&a.app, req[0]["id"].as_str().unwrap(), true).unwrap();
    pair::tick(&b.app).await; // B learns the answer and pairs itself
}

/// A well-formed MP4 skeleton (ftyp, an empty moov, then one mdat of random bytes). Not playable, but it
/// passes the structure checks the way a real file does.
fn fake_video(n: usize, seed: &str) -> Vec<u8> {
    let mut v = vec![0, 0, 0, 0x18];
    v.extend_from_slice(b"ftypmp42");
    v.extend_from_slice(&[0; 12]);
    v.extend_from_slice(&[0, 0, 0, 8]);
    v.extend_from_slice(b"moov");
    let body = n - v.len() - 8;
    v.extend_from_slice(&((body + 8) as u32).to_be_bytes());
    v.extend_from_slice(b"mdat");
    let mut xof = blake3::Hasher::new().update(seed.as_bytes()).finalize_xof();
    let mut rest = vec![0u8; body];
    xof.fill(&mut rest);
    v.extend(rest);
    v
}

fn add_video(n: &TestNode, name: &str, data: &[u8], approve: bool) -> String {
    let mut s = IngestSession::begin(&n.app, name, "test").unwrap();
    for c in data.chunks(300_000) {
        s.push(c).unwrap();
    }
    let ing = s.finish(&n.app).unwrap();
    if approve {
        library::approve(&n.app, &ing.id, true).unwrap();
    }
    ing.id
}

fn read_all(app: &Shared, id: &str) -> Vec<u8> {
    let (_, mut r) = library::open_reader(app, id).unwrap();
    let len = r.len;
    r.read_range(0, len).unwrap()
}

fn local_state(n: &TestNode, id: &str) -> Option<String> {
    n.app.db.with(|c| Ok(db::get_item(c, id)?.map(|i| i.local))).unwrap()
}

async fn sync_from(a: &TestNode, b: &TestNode) {
    let peer = a.app.db.with(|c| db::get_peer(c, &b.app.id.id)).unwrap().unwrap();
    sync::sync_peer(&a.app, &peer).await.unwrap();
}

fn stage(a: &TestNode, b: &TestNode) -> (String, String) {
    let g = a.app.live.lock().unwrap();
    let l = g.get(&b.app.id.id).cloned().unwrap_or_default();
    (l.stage, l.detail)
}

fn reset_backoff(a: &TestNode) {
    a.app
        .db
        .with(|c| {
            c.execute("UPDATE peers SET backoff_until=0, fails=0", [])?;
            Ok(())
        })
        .unwrap();
}

fn set_policy(n: &TestNode, f: impl FnOnce(&mut syphon::config::SyncPolicy)) {
    let mut p = n.app.policy();
    f(&mut p);
    n.app.set_policy(p).unwrap();
}

// ------------------------------------------------------------------ tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_nodes_replicate_a_video_and_keep_it_encrypted() {
    let (a, b, c) = (node("home").await, node("other-house").await, node("fiancee").await);
    pair_up(&a, &b).await;
    pair_up(&b, &c).await;
    pair_up(&a, &c).await;

    // a video waiting in the review area is invisible to the mesh
    let data = fake_video(2_500_000, "movie-one"); // 3 chunks
    let id = add_video(&a, "Metropolis.1927.mp4", &data, false);
    assert_eq!(local_state(&a, &id).as_deref(), Some("quarantine"));
    sync_from(&b, &a).await;
    assert!(local_state(&b, &id).is_none(), "review-area items must not reach peers");
    assert_eq!(stage(&b, &a).0, "in sync");

    // approving it publishes it: B notices (heartbeat), needs sync, requests, gets a yes, transfers
    library::approve(&a.app, &id, true).unwrap();
    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &id).as_deref(), Some("present"));
    assert_eq!(read_all(&b.app, &id), data, "content survives the trip bit for bit");

    // C fetches from B, not from A: catalog entries authored by A are verified by signature
    sync_from(&c, &b).await;
    assert_eq!(local_state(&c, &id).as_deref(), Some("present"));
    assert_eq!(read_all(&c.app, &id), data);

    // at rest the library file is ciphertext
    let raw = std::fs::read(library::library_path(&c.app, &id)).unwrap();
    let needle = &data[100..132];
    assert!(!raw.windows(needle.len()).any(|w| w == needle), "plaintext leaked into the stored file");
    // and the three copies are encrypted differently
    let raw_b = std::fs::read(library::library_path(&b.app, &id)).unwrap();
    assert_ne!(raw, raw_b);

    // metadata came from the filename
    let it = c.app.db.with(|d| db::get_item(d, &id)).unwrap().unwrap();
    assert_eq!((it.title.as_str(), it.year, it.kind.as_str()), ("Metropolis", Some(1927), "movie"));

    // heads converged
    let ha = a.app.db.with(syphon::catalog::heads).unwrap();
    let hc = c.app.db.with(syphon::catalog::heads).unwrap();
    assert_eq!(ha, hc);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn request_flow_ask_mode_stop_switch_and_denials() {
    let (a, b) = (node("a").await, node("b").await);
    pair_up(&a, &b).await;
    let d1 = fake_video(600_000, "one");
    let id1 = add_video(&a, "One.2001.mp4", &d1, true);

    // A answers requests by asking its owner first
    set_policy(&a, |p| p.mode = "ask".into());
    sync_from(&b, &a).await;
    assert_eq!(stage(&b, &a).0, "waiting");
    assert_ne!(local_state(&b, &id1).as_deref(), Some("present"));
    let pending: String = a
        .app
        .db
        .with(|c| Ok(c.query_row("SELECT id FROM sync_requests WHERE dir='in' AND status='pending'", [], |r| r.get(0))?))
        .unwrap();
    // asking again does not pile up duplicate requests
    sync_from(&b, &a).await;
    let n: i64 = a.app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM sync_requests WHERE dir='in'", [], |r| r.get(0))?)).unwrap();
    assert_eq!(n, 1);
    sync::answer_inbound(&a.app, &pending, true, None).unwrap();
    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &id1).as_deref(), Some("present"));
    assert_eq!(read_all(&b.app, &id1), d1);

    // owner says no
    set_policy(&a, |p| p.mode = "ask".into());
    let id2 = add_video(&a, "Two.2002.mp4", &fake_video(400_000, "two"), true);
    sync_from(&b, &a).await;
    let pending2: String = a
        .app
        .db
        .with(|c| Ok(c.query_row("SELECT id FROM sync_requests WHERE dir='in' AND status='pending'", [], |r| r.get(0))?))
        .unwrap();
    sync::answer_inbound(&a.app, &pending2, false, Some("not tonight")).unwrap();
    sync_from(&b, &a).await;
    let (st, detail) = stage(&b, &a);
    assert_eq!(st, "declined");
    assert!(detail.contains("not tonight"), "{detail}");
    assert_ne!(local_state(&b, &id2).as_deref(), Some("present"));
    set_policy(&a, |p| p.mode = "auto".into());
    reset_backoff(&b);

    // the stop switch: B switches sync off, nothing is sent
    set_policy(&b, |p| p.enabled = false);
    let out_before: i64 = b.app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM sync_requests WHERE dir='out'", [], |r| r.get(0))?)).unwrap();
    sync_from(&b, &a).await;
    assert_eq!(stage(&b, &a).0, "paused");
    let out_after: i64 = b.app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM sync_requests WHERE dir='out'", [], |r| r.get(0))?)).unwrap();
    assert_eq!(out_before, out_after);
    set_policy(&b, |p| p.enabled = true);

    // A switches off: B's heartbeat is answered "not syncing", and chunk requests are refused too
    set_policy(&a, |p| p.enabled = false);
    sync_from(&b, &a).await;
    assert_eq!(stage(&b, &a).0, "peer paused");
    set_policy(&a, |p| p.enabled = true);

    // low disk on A is reported as the reason
    set_policy(&a, |p| p.min_free_gb = u32::MAX);
    sync_from(&b, &a).await;
    let (st, detail) = stage(&b, &a);
    assert_eq!(st, "peer paused");
    assert!(detail.contains("disk"), "{detail}");
    set_policy(&a, |p| p.min_free_gb = 0);

    // a locked provider cannot decrypt, so it says no
    a.app.keyring.lock();
    sync_from(&b, &a).await;
    let (st, detail) = stage(&b, &a);
    assert!(st == "declined" && detail.contains("locked"), "{st}: {detail}");
    a.app.keyring.unlock(PW).unwrap();
    reset_backoff(&b);

    // and once everything is back, the second video arrives
    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &id2).as_deref(), Some("present"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn locked_receiver_stores_sealed_chunks_then_assembles_on_unlock() {
    let (a, b) = (node("a").await, node("b").await);
    pair_up(&a, &b).await;
    let data = fake_video(1_300_000, "sealed");
    let id = add_video(&a, "Sealed.1999.mp4", &data, true);

    b.app.keyring.lock();
    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &id).as_deref(), Some("assembling"));
    assert!(library::open_reader(&b.app, &id).is_err(), "locked node cannot read");
    // the inbox only holds ciphertext
    let chunk0 = std::fs::read(library::inbox_dir(&b.app, &id).join("0")).unwrap();
    assert!(!chunk0.windows(32).any(|w| w == &data[100..132]));

    b.app.keyring.unlock(PW).unwrap();
    assert_eq!(library::assemble_pending(&b.app).await.unwrap(), 1);
    assert_eq!(local_state(&b, &id).as_deref(), Some("present"));
    assert_eq!(read_all(&b.app, &id), data);
    assert!(!library::inbox_dir(&b.app, &id).exists(), "inbox cleaned up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bandwidth_cap_slows_the_transfer() {
    let (a, b) = (node("a").await, node("b").await);
    pair_up(&a, &b).await;
    let id = add_video(&a, "Slow.2000.mp4", &fake_video(3_300_000, "slow"), true); // ~3.1 MiB
    set_policy(&b, |p| p.max_download_kib_s = 1024);
    let t = Instant::now();
    sync_from(&b, &a).await;
    let el = t.elapsed();
    assert_eq!(local_state(&b, &id).as_deref(), Some("present"));
    assert!(el > Duration::from_millis(1500), "1 MiB/s cap should take a couple of seconds, took {el:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_goes_to_trash_and_restore_propagates() {
    let (a, b) = (node("a").await, node("b").await);
    pair_up(&a, &b).await;
    let id = add_video(&a, "Trash.1990.mp4", &fake_video(200_000, "trash"), true);
    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &id).as_deref(), Some("present"));

    library::delete_item(&b.app, &id).unwrap();
    sync_from(&a, &b).await;
    let it = a.app.db.with(|c| db::get_item(c, &id)).unwrap().unwrap();
    assert!(it.deleted, "delete propagates as a tombstone");
    assert!(library::library_path(&a.app, &id).exists(), "file stays in the trash, not erased");
    assert!(library::open_reader(&a.app, &id).is_err(), "deleted items are not playable");

    library::restore_item(&a.app, &id).unwrap();
    sync_from(&b, &a).await;
    assert!(!b.app.db.with(|c| db::get_item(c, &id)).unwrap().unwrap().deleted);
    assert!(library::open_reader(&b.app, &id).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mesh_endpoints_reject_strangers_forgeries_and_replays() {
    let (a, b, stranger) = (node("a").await, node("b").await, node("x").await);
    pair_up(&a, &b).await;
    let http = reqwest::Client::new();
    let body = serde_json::to_vec(&mesh::Heartbeat::default()).unwrap();

    // no signature
    let r = http.post(format!("{}/mesh/heartbeat", a.mesh_url)).body(body.clone()).send().await.unwrap();
    assert_eq!(r.status(), 404, "unsigned requests look like nothing is here");

    // signed, but by a node that was never paired
    let mut req = http.post(format!("{}/mesh/heartbeat", a.mesh_url)).body(body.clone());
    for (k, v) in mesh::sign_headers(&stranger.app, "POST", "/mesh/heartbeat", &body) {
        req = req.header(k, v);
    }
    assert_eq!(req.send().await.unwrap().status(), 404, "an unpaired node learns nothing, not even that it is unpaired");

    // a paired node, signed correctly: ok; the exact same request again: replay refused
    let headers = mesh::sign_headers(&b.app, "POST", "/mesh/heartbeat", &body);
    let send = |h: &Vec<(&'static str, String)>| {
        let mut r = http.post(format!("{}/mesh/heartbeat", a.mesh_url)).body(body.clone());
        for (k, v) in h {
            r = r.header(*k, v.clone());
        }
        r.send()
    };
    assert_eq!(send(&headers).await.unwrap().status(), 200);
    assert_eq!(send(&headers).await.unwrap().status(), 404, "replay");

    // a valid signature for a different path or body is worthless
    let mut r = http.post(format!("{}/mesh/sync/request", a.mesh_url)).body(body.clone());
    for (k, v) in mesh::sign_headers(&b.app, "POST", "/mesh/heartbeat", &body) {
        r = r.header(k, v);
    }
    assert_eq!(r.send().await.unwrap().status(), 404);

    // chunk without a grant token
    let id = add_video(&a, "Grant.2000.mp4", &fake_video(100_000, "g"), true);
    let pq = format!("/mesh/chunk/{id}/0");
    let mut r = http.get(format!("{}{}", a.mesh_url, pq));
    for (k, v) in mesh::sign_headers(&b.app, "GET", &pq, &[]) {
        r = r.header(k, v);
    }
    assert_eq!(r.send().await.unwrap().status(), 403);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn web_api_login_upload_review_stream_and_roles() {
    let n = node_with("web", |c| c.ffprobe = "ffprobe".into()).await;
    let http = reqwest::Client::new();
    let base = n.access_url.clone();

    let post = |path: &str, cookie: &str, body: Value, csrf: bool| {
        let mut r = http.post(format!("{base}{path}")).json(&body).header("cookie", cookie.to_string());
        if csrf {
            r = r.header("x-requested-with", "syphon");
        }
        r.send()
    };

    // wrong password, then the right one
    let r = post("/api/login", "", json!({"user": "owner", "password": "nope-nope"}), false).await.unwrap();
    assert_eq!(r.status(), 401);
    let r = post("/api/login", "", json!({"user": "owner", "password": PW}), false).await.unwrap();
    assert_eq!(r.status(), 200);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    assert!(r.headers()["set-cookie"].to_str().unwrap().contains("HttpOnly"));

    let get = |path: &str, cookie: &str| http.get(format!("{base}{path}")).header("cookie", cookie.to_string()).send();
    assert_eq!(get("/api/library", "").await.unwrap().status(), 401);

    // CSRF: changing things needs the header
    let r = post("/api/lock", &cookie, json!({}), false).await.unwrap();
    assert_eq!(r.status(), 403);

    // upload streams into the review area, not the library
    let data = fake_video(1_700_000, "web");
    let r = http
        .put(format!("{base}/api/upload?name=Test.Movie.1999.mp4"))
        .header("cookie", &cookie)
        .header("x-requested-with", "syphon")
        .body(data.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let id = r.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();
    let lib: Value = get("/api/library", &cookie).await.unwrap().json().await.unwrap();
    assert_eq!(lib["items"].as_array().unwrap().len(), 0, "unreviewed uploads are not in the library");
    let r = get(&format!("/api/stream/{id}"), &cookie).await.unwrap();
    assert!(!r.status().is_success(), "review-area items cannot be streamed");

    let rev: Value = get("/api/review", &cookie).await.unwrap().json().await.unwrap();
    let item = &rev["items"][0];
    assert_eq!(item["id"], id.as_str());
    assert_eq!(item["scan"]["container"], "mp4/mov");
    assert_eq!(item["scan"]["ok"], false, "a file ffprobe cannot parse does not pass the scan");
    assert_eq!(post(&format!("/api/review/{id}/approve"), &cookie, json!({}), true).await.unwrap().status(), 400);
    assert_eq!(post(&format!("/api/review/{id}/approve"), &cookie, json!({"override": true}), true).await.unwrap().status(), 200);

    let lib: Value = get("/api/library", &cookie).await.unwrap().json().await.unwrap();
    let it = &lib["items"][0];
    assert_eq!((it["title"].as_str(), it["year"].as_i64()), (Some("Test Movie"), Some(1999)));

    // ranged playback decrypts exactly the requested bytes, across a chunk boundary
    let range = |spec: &'static str| {
        http.get(format!("{base}/api/stream/{id}")).header("cookie", &cookie).header("range", spec).send()
    };
    let r = range("bytes=1048000-1049999").await.unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(r.headers()["content-range"], format!("bytes 1048000-1049999/{}", data.len()).as_str());
    assert_eq!(r.bytes().await.unwrap().as_ref(), &data[1_048_000..1_050_000]);
    let r = range("bytes=-50").await.unwrap();
    assert_eq!(r.bytes().await.unwrap().as_ref(), &data[data.len() - 50..]);
    assert_eq!(range("bytes=99999999-").await.unwrap().status(), 416);
    let full = get(&format!("/api/stream/{id}"), &cookie).await.unwrap();
    assert_eq!(full.status(), 200);
    assert_eq!(full.bytes().await.unwrap().as_ref(), data.as_slice());

    // progress is per user
    let r = http
        .put(format!("{base}/api/progress/{id}"))
        .header("cookie", &cookie)
        .header("x-requested-with", "syphon")
        .json(&json!({"pos": 123.5}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let lib: Value = get("/api/library", &cookie).await.unwrap().json().await.unwrap();
    assert_eq!(lib["items"][0]["pos"], 123.5);

    // a viewer can watch but cannot approve, delete, change sync or see the review area
    let r = post("/api/users", &cookie, json!({"name": "kid", "password": "kidpassword", "role": "viewer"}), true).await.unwrap();
    assert_eq!(r.status(), 200);
    let r = post("/api/login", "", json!({"user": "kid", "password": "kidpassword"}), false).await.unwrap();
    let kid = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    assert_eq!(get("/api/library", &kid).await.unwrap().status(), 200);
    assert_eq!(get(&format!("/api/stream/{id}"), &kid).await.unwrap().status(), 200);
    assert_eq!(get("/api/review", &kid).await.unwrap().status(), 403);
    assert_eq!(get("/api/sync", &kid).await.unwrap().status(), 403);
    let r = http.delete(format!("{base}/api/items/{id}")).header("cookie", &kid).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(r.status(), 403);

    // sync controls: validated and applied
    let r = http
        .put(format!("{base}/api/sync/policy"))
        .header("cookie", &cookie)
        .header("x-requested-with", "syphon")
        .json(&json!({"mode": "sometimes"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let mut pol = n.app.policy();
    pol.max_upload_kib_s = 512;
    pol.mode = "ask".into();
    let r = http
        .put(format!("{base}/api/sync/policy"))
        .header("cookie", &cookie)
        .header("x-requested-with", "syphon")
        .json(&pol)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(n.app.policy().max_upload_kib_s, 512);
    let s: Value = get("/api/sync", &cookie).await.unwrap().json().await.unwrap();
    assert_eq!(s["policy"]["mode"], "ask");
    assert!(s["node"]["fingerprint"].as_str().unwrap().split(' ').count() == 5);

    // locking the keyring ends every session and stops playback
    assert_eq!(post("/api/lock", &cookie, json!({}), true).await.unwrap().status(), 200);
    assert_eq!(get("/api/library", &cookie).await.unwrap().status(), 401);
    assert_eq!(get("/api/status", "").await.unwrap().json::<Value>().await.unwrap()["locked"], true);
    // a viewer cannot unlock it: only the owner's password does
    let r = post("/api/login", "", json!({"user": "kid", "password": "kidpassword"}), false).await.unwrap();
    assert_eq!(r.status(), 503);
    let r = post("/api/login", "", json!({"user": "owner", "password": PW}), false).await.unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mp4_passes_the_scan_and_plays_back_including_low_bitrate() {
    if std::process::Command::new("ffmpeg").arg("-version").output().is_err() {
        eprintln!("ffmpeg not installed: skipping");
        return;
    }
    let n = node_with("media", |c| {
        c.ffprobe = "ffprobe".into();
        c.scan.decode = true;
    })
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let mp4 = tmp.path().join("Clip.Test.2020.mp4");
    let ok = std::process::Command::new("ffmpeg")
        .args(["-v", "error", "-f", "lavfi", "-i", "testsrc=duration=3:size=320x240:rate=15", "-f", "lavfi", "-i", "sine=frequency=440:duration=3"])
        .args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", "-movflags", "+faststart"])
        .arg(&mp4)
        .status()
        .unwrap()
        .success();
    assert!(ok);

    let ing = library::import_path(&n.app, &mp4, "import").await.unwrap();
    let it = n.app.db.with(|c| db::get_item(c, &ing.id)).unwrap().unwrap();
    let scan = it.scan.expect("scan stored");
    assert_eq!(scan["ok"], true, "{scan}");
    assert_eq!(scan["has_video"], true);
    assert!(scan["duration"].as_f64().unwrap() > 2.0);
    library::approve(&n.app, &ing.id, false).unwrap(); // no override needed

    // log in and fetch the low-bitrate transcode
    let http = reqwest::Client::new();
    let r = http.post(format!("{}/api/login", n.access_url)).json(&json!({"user": "owner", "password": PW})).send().await.unwrap();
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let r = http.get(format!("{}/api/stream/{}?mode=low", n.access_url, ing.id)).header("cookie", &cookie).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "video/mp4");
    let bytes = r.bytes().await.unwrap();
    assert!(bytes.len() > 1000, "transcode produced {} bytes", bytes.len());
    assert_eq!(&bytes[4..8], b"ftyp");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acquisition_downloads_into_the_review_area_never_the_library() {
    use axum::routing::get;
    let video = fake_video(900_000, "downloaded");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let feed = format!(
        r#"<rss><channel><item><title>Night of the Test (1968)</title>
           <enclosure url="http://{addr}/v/Night.of.the.Test.1968.mp4" length="900000" type="video/mp4"/></item>
           <item><title>Something else</title><link>http://{addr}/other.mp4</link></item></channel></rss>"#
    );
    let v2 = video.clone();
    let srv = axum::Router::new()
        .route("/feed.xml", get(move || { let f = feed.clone(); async move { f } }))
        .route(
            "/v/Night.of.the.Test.1968.mp4",
            get(move || { let v = v2.clone(); async move { ([("content-type", "video/mp4")], v) } }),
        );
    tokio::spawn(async move { axum::serve(l, srv).await.unwrap() });

    let feed_url = format!("http://{addr}/feed.xml");
    let n = node_with("acq", |c| {
        c.acquire.internet_archive = false;
        c.acquire.rss = vec![syphon::config::RssFeed { name: "local".into(), url: feed_url.clone() }];
    })
    .await;

    let results = acquire::search(&n.app, None, "night test").await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].year, Some(1968));
    let dl = acquire::queue(&n.app, &results[0].provider, &results[0].url, &results[0].title, "").await.unwrap();

    let t = Instant::now();
    let status = loop {
        let st: String = n.app.db.with(|c| Ok(c.query_row("SELECT status FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
        if !matches!(st.as_str(), "queued" | "resolving" | "downloading") || t.elapsed() > Duration::from_secs(15) {
            break st;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(status, "review");
    let item_id: String = n.app.db.with(|c| Ok(c.query_row("SELECT item FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
    assert_eq!(local_state(&n, &item_id).as_deref(), Some("quarantine"), "downloads wait in the review area");
    library::approve(&n.app, &item_id, true).unwrap();
    assert_eq!(read_all(&n.app, &item_id), video);

    // private addresses are refused unless explicitly allowed (SSRF guard)
    let strict = node_with("strict", |c| {
        c.acquire.internet_archive = false;
        c.acquire.allow_private_hosts = false;
        c.acquire.rss = vec![syphon::config::RssFeed { name: "local".into(), url: feed_url.clone() }];
    })
    .await;
    let e = acquire::queue(&strict.app, "rss:local", &results[0].url, "x", "").await.unwrap_err();
    assert!(format!("{e:#}").contains("blocked"), "{e:#}");
}

// ------------------------------------------------------------------ round two: pairing, security, vault, sources

fn cookies_of(r: &reqwest::Response) -> String {
    r.headers().get_all("set-cookie").iter().map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string()).collect::<Vec<_>>().join("; ")
}

async fn login_at(base: &str, user: &str, pw: &str, extra_cookie: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/api/login"))
        .header("cookie", extra_cookie)
        .json(&json!({"user": user, "password": pw, "device_name": "test phone"}))
        .send()
        .await
        .unwrap()
}

async fn api_post(base: &str, path: &str, cookie: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new().post(format!("{base}{path}")).header("cookie", cookie).header("x-requested-with", "syphon").json(&body).send().await.unwrap()
}

async fn api_get(base: &str, path: &str, cookie: &str) -> reqwest::Response {
    reqwest::Client::new().get(format!("{base}{path}")).header("cookie", cookie).send().await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_is_a_request_that_completes_without_anyone_clicking_at_the_same_time() {
    let (a, b, c) = (node("home").await, node("other").await, node("nosy").await);
    let inv = pair::create_invite(&a.app, "").unwrap();
    let d = pair::decode(&inv.code).unwrap();
    assert_eq!(d.node_id, a.app.id.id);

    // B pastes the code. Nothing reaches A until B's node sends it, and A is not required to be online
    // at that moment: the request waits in B's database.
    pair::request_join(&b.app, &inv.code).unwrap();
    assert!(pair::incoming(&a.app).unwrap().is_empty());
    assert!(pair::request_join(&b.app, &inv.code).unwrap_err().to_string().contains("already asked"));
    pair::tick(&b.app).await;
    let inc = pair::incoming(&a.app).unwrap();
    assert_eq!(inc.len(), 1);
    assert_eq!(inc[0]["name"], "other");
    assert_eq!(inc[0]["fingerprint"].as_str().unwrap(), syphon::util::fingerprint(&b.app.id.id));
    assert_eq!(pair::outgoing(&b.app).unwrap()[0]["status"], "sent");

    // the invite is one-use: a second node holding the same code cannot also ask
    pair::request_join(&c.app, &inv.code).unwrap();
    pair::tick(&c.app).await;
    assert_eq!(pair::outgoing(&c.app).unwrap()[0]["status"], "failed");
    assert_eq!(pair::incoming(&a.app).unwrap().len(), 1);

    // A accepts. A is paired at that instant; B pairs itself on its next look.
    pair::decide(&a.app, inc[0]["id"].as_str().unwrap(), true).unwrap();
    assert!(a.app.db.with(|c| syphon::db::get_peer(c, &b.app.id.id)).unwrap().is_some());
    assert!(b.app.db.with(|c| syphon::db::get_peer(c, &a.app.id.id)).unwrap().is_none());
    pair::tick(&b.app).await;
    assert!(b.app.db.with(|c| syphon::db::get_peer(c, &a.app.id.id)).unwrap().is_some());
    assert_eq!(pair::outgoing(&b.app).unwrap()[0]["status"], "done");

    // and they really can talk, in both directions
    let id = add_video(&a, "Paired.2020.mp4", &fake_video(200_000, "p"), true);
    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &id).as_deref(), Some("present"));
    let id2 = add_video(&b, "Back.2021.mp4", &fake_video(200_000, "q"), true);
    sync_from(&a, &b).await;
    assert_eq!(local_state(&a, &id2).as_deref(), Some("present"));

    // a declined request leaves no trace on the owner's side
    let inv2 = pair::create_invite(&a.app, "").unwrap();
    let c2 = node("third").await;
    pair::request_join(&c2.app, &inv2.code).unwrap();
    pair::tick(&c2.app).await;
    let r = pair::incoming(&a.app).unwrap();
    pair::decide(&a.app, r[0]["id"].as_str().unwrap(), false).unwrap();
    assert!(a.app.db.with(|c| syphon::db::get_peer(c, &c2.app.id.id)).unwrap().is_none());
    pair::tick(&c2.app).await;
    assert_eq!(pair::outgoing(&c2.app).unwrap()[0]["status"], "denied");
    assert!(c2.app.db.with(|c| syphon::db::get_peer(c, &a.app.id.id)).unwrap().is_none());

    // damaged, foreign and expired codes give plain-language errors
    assert!(pair::decode("hello").unwrap_err().to_string().contains("syphon1:"));
    let mut old = pair::decode(&pair::create_invite(&a.app, "").unwrap().code).unwrap();
    old.exp = 5;
    let e = pair::request_join(&node("late").await.app, &pair::encode(&old)).unwrap_err();
    assert!(e.to_string().contains("expired"), "{e}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outside_the_home_network_a_password_alone_is_not_enough() {
    let n = node("web").await;
    let (lan, rem) = (n.access_url.clone(), n.remote_url.clone());

    // at home: password only, and the device becomes trusted
    let r = login_at(&lan, "owner", PW, "").await;
    assert_eq!(r.status(), 200);
    let home = cookies_of(&r);
    assert!(home.contains("syphon_dev="), "a trusted-device cookie is issued");
    let st: Value = api_get(&lan, "/api/status", "").await.json().await.unwrap();
    assert_eq!((st["zone"].as_str(), st["name"].as_str()), (Some("lan"), Some("web")));
    let st: Value = api_get(&rem, "/api/status", "").await.json().await.unwrap();
    assert_eq!((st["zone"].as_str(), st["name"].is_null()), (Some("remote"), true), "no node name shown to outsiders");

    // outside: the right password only opens a waiting request, never a session
    let r = login_at(&rem, "owner", PW, "").await;
    assert_eq!(r.status(), 202);
    assert!(r.headers().get("set-cookie").is_none());
    let p: Value = r.json().await.unwrap();
    let (pid, psecret, code) = (p["pending"]["id"].as_str().unwrap().to_string(), p["pending"]["secret"].as_str().unwrap().to_string(), p["pending"]["code"].as_str().unwrap().to_string());
    let poll = |id: String, secret: String| {
        let rem = rem.clone();
        async move { api_post(&rem, "/api/login/poll", "", json!({"id": id, "secret": secret})).await }
    };
    assert_eq!(poll(pid.clone(), psecret.clone()).await.json::<Value>().await.unwrap()["state"], "pending");
    assert_eq!(poll(pid.clone(), "wrong".into()).await.json::<Value>().await.unwrap()["state"], "expired", "the poll secret matters");

    // the request shows up at home with the same short code, and can only be approved from home
    let list: Value = api_get(&lan, "/api/approvals", &home).await.json().await.unwrap();
    assert_eq!(list["pending"][0]["code"], code.as_str());
    assert_eq!(api_get(&rem, "/api/approvals", &home).await.status(), 401, "a home session is not valid outside");
    assert_eq!(api_post(&lan, &format!("/api/approvals/{pid}/approve"), &home, json!({})).await.status(), 200);

    let r = poll(pid.clone(), psecret.clone()).await;
    let away = cookies_of(&r);
    let j: Value = r.json().await.unwrap();
    assert_eq!(j["state"], "ok");
    assert!(away.contains("syphon=") && away.contains("syphon_dev="));
    assert_eq!(poll(pid, psecret).await.json::<Value>().await.unwrap()["state"], "expired", "an approval is single-use");

    // that session works outside, and only outside
    assert_eq!(api_get(&rem, "/api/library", &away).await.status(), 200);
    assert_eq!(api_get(&lan, "/api/library", &away).await.status(), 401);
    // the approved device signs in directly next time
    let dev = away.split("; ").find(|c| c.starts_with("syphon_dev=")).unwrap().to_string();
    assert_eq!(login_at(&rem, "owner", PW, &dev).await.status(), 200);

    // things that change who can reach the node refuse to work from outside
    for (path, body) in [
        ("/api/users", json!({"name": "x", "password": "longenough", "role": "viewer"})),
        ("/api/pair/invite", json!({})),
        ("/api/totp/start", json!({})),
        ("/api/password", json!({"old": PW, "new": "another long one"})),
        ("/api/sources", json!({"kind": "plex", "name": "p", "url": "http://x", "token": "t"})),
    ] {
        let r = api_post(&rem, path, &away, body).await;
        assert_eq!(r.status(), 403, "{path} must be home-only");
    }
    assert_eq!(api_get(&rem, "/api/vault", &away).await.status(), 403);
    assert_eq!(api_get(&rem, "/api/connect", &away).await.status(), 403);
    // the owner can still see sync status outside, but without addresses
    let s: Value = api_get(&rem, "/api/sync", &away).await.json().await.unwrap();
    assert!(s["node"]["mesh_addr"].is_null() && s["node"]["id"].is_null() && s["node"]["access_onion"].is_null());

    // a proxy in front of the home listener cannot make outsiders look local
    let r = reqwest::Client::new().get(format!("{lan}/api/status")).header("x-forwarded-for", "8.8.8.8").send().await.unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["zone"], "remote");
    // the zone header cannot be forged either
    let r = reqwest::Client::new().get(format!("{rem}/api/status")).header("x-syphon-zone", "lan").send().await.unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["zone"], "remote");

    // unknown user and wrong password are indistinguishable
    let a = login_at(&rem, "nobody", "whatever-123", "").await;
    let b = login_at(&rem, "owner", "whatever-123", "").await;
    assert_eq!((a.status().as_u16(), b.status().as_u16()), (401, 401));
    assert_eq!(a.text().await.unwrap(), b.text().await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lockouts_are_per_zone_and_authenticator_codes_work_once() {
    let n = node("web").await;
    let (lan, rem) = (n.access_url.clone(), n.remote_url.clone());
    for _ in 0..5 {
        assert_eq!(login_at(&rem, "owner", "bad-password-1", "").await.status(), 401);
    }
    assert_eq!(login_at(&rem, "owner", PW, "").await.status(), 429, "even the right password waits during a lockout");
    let r = login_at(&lan, "owner", PW, "").await;
    assert_eq!(r.status(), 200, "a remote attacker cannot lock the owner out at home");
    let home = cookies_of(&r);

    // enrol an authenticator from home
    let s: Value = api_post(&lan, "/api/totp/start", &home, json!({})).await.json().await.unwrap();
    let secret = s["secret"].as_str().unwrap().to_string();
    assert!(s["uri"].as_str().unwrap().starts_with("otpauth://totp/"));
    assert!(s["qr"].as_str().unwrap().starts_with("data:image/svg+xml;base64,"));
    let step = syphon::util::now() as u64 / 30;
    let code = syphon::totp::code_for(&secret, step).unwrap();
    assert_eq!(api_post(&lan, "/api/totp/confirm", &home, json!({"code": "000000"})).await.status(), 400);
    assert_eq!(api_post(&lan, "/api/totp/confirm", &home, json!({"code": code})).await.status(), 200);

    // outside, a new device now needs a code instead of waiting for approval (use another user to avoid the lockout)
    api_post(&lan, "/api/users", &home, json!({"name": "kid", "password": "kidpassword", "role": "viewer"})).await;
    let kid = cookies_of(&login_at(&lan, "kid", "kidpassword", "").await);
    let s: Value = api_post(&lan, "/api/totp/start", &kid, json!({})).await.json().await.unwrap();
    let ksecret = s["secret"].as_str().unwrap().to_string();
    let kcode = syphon::totp::code_for(&ksecret, step - 1).unwrap(); // inside the allowed drift window
    assert_eq!(api_post(&lan, "/api/totp/confirm", &kid, json!({"code": kcode})).await.status(), 200);

    let r = login_at(&rem, "kid", "kidpassword", "").await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().await.unwrap()["need"], "totp");
    let with = |c: &str| {
        let rem = rem.clone();
        let body = json!({"user": "kid", "password": "kidpassword", "totp": c, "device_name": "cafe laptop"});
        async move { reqwest::Client::new().post(format!("{rem}/api/login")).json(&body).send().await.unwrap() }
    };
    assert_eq!(with("123456").await.status(), 401);
    let next = syphon::totp::code_for(&ksecret, step).unwrap();
    let ok = with(&next).await;
    assert_eq!(ok.status(), 200);
    assert!(cookies_of(&ok).contains("syphon="));
    assert_eq!(with(&next).await.status(), 401, "the same code cannot be used twice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_vault_is_private_per_user_home_only_and_never_synced() {
    let (a, b) = (node("home").await, node("other").await);
    pair_up(&a, &b).await;
    let lan = a.access_url.clone();
    let owner = cookies_of(&login_at(&lan, "owner", PW, "").await);
    api_post(&lan, "/api/users", &owner, json!({"name": "kid", "password": "kidpassword", "role": "viewer"})).await;
    let kid = cookies_of(&login_at(&lan, "kid", "kidpassword", "").await);

    let secret_video = fake_video(1_300_000, "vault-secret");
    let r = reqwest::Client::new()
        .put(format!("{lan}/api/vault/upload?name=Private.Holiday.2023.mp4"))
        .header("cookie", &owner)
        .header("x-requested-with", "syphon")
        .body(secret_video.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let vid = r.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();

    let l: Value = api_get(&lan, "/api/vault", &owner).await.json().await.unwrap();
    assert_eq!(l["items"].as_array().unwrap().len(), 1);
    // plays back, with ranges
    let r = reqwest::Client::new().get(format!("{lan}/api/vault/{vid}/stream")).header("cookie", &owner).header("range", "bytes=1000-1999").send().await.unwrap();
    assert_eq!(r.status(), 206);
    assert_eq!(r.bytes().await.unwrap().as_ref(), &secret_video[1000..2000]);

    // other users cannot list or read it; it is not in the shared library or the review area either
    let kl: Value = api_get(&lan, "/api/vault", &kid).await.json().await.unwrap();
    assert_eq!(kl["items"].as_array().unwrap().len(), 0);
    assert!(!api_get(&lan, &format!("/api/vault/{vid}/stream"), &kid).await.status().is_success());
    assert!(!api_get(&lan, &format!("/api/stream/{vid}"), &owner).await.status().is_success());
    let lib: Value = api_get(&lan, "/api/library", &owner).await.json().await.unwrap();
    assert_eq!(lib["items"].as_array().unwrap().len(), 0);
    let rev: Value = api_get(&lan, "/api/review", &owner).await.json().await.unwrap();
    assert_eq!(rev["items"].as_array().unwrap().len(), 0);
    assert_eq!(api_get(&a.remote_url, "/api/vault", &owner).await.status(), 401);

    // it never reaches the mesh: no catalog entry, nothing offered, nothing fetched
    assert!(a.app.db.with(syphon::catalog::heads).unwrap().is_empty(), "the vault writes no catalog operations");
    sync_from(&b, &a).await;
    assert!(local_state(&b, &vid).is_none());
    let asks = mesh::PeerClient::new(&b.app, &b.app.db.with(|c| syphon::db::get_peer(c, &a.app.id.id)).unwrap().unwrap()).unwrap();
    let ans = asks.ask(&[vid.clone()]).await.unwrap();
    assert_eq!(ans.status, "denied", "peers cannot even request a vault item by id");
    assert!(ans.token.is_none());

    // encrypted at rest
    let raw = std::fs::read(library::vault_path(&a.app, &vid)).unwrap();
    let needle = &secret_video[200..232];
    assert!(!raw.windows(needle.len()).any(|w| w == needle));

    // rename and delete work, and delete really removes the file
    assert_eq!(api_post(&lan, &format!("/api/vault/{vid}"), &owner, json!({})).await.status(), 405);
    let r = reqwest::Client::new().patch(format!("{lan}/api/vault/{vid}")).header("cookie", &owner).header("x-requested-with", "syphon").json(&json!({"title": "Trip"})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = reqwest::Client::new().delete(format!("{lan}/api/vault/{vid}")).header("cookie", &owner).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(!library::vault_path(&a.app, &vid).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_identifying_leaves_through_the_catalog_or_the_web_api() {
    let (a, b) = (node("home").await, node("other").await);
    pair_up(&a, &b).await;
    let id = add_video(&a, "Big.Movie.1999.1080p.BluRay.x264-SOMEGROUP.mkv", &fake_video(300_000, "m"), true);

    // what other nodes receive: a clean name, never the release-group file name
    let ops = a.app.db.with(|c| syphon::catalog::ops_after(c, &a.app.id.id, 0, 100)).unwrap();
    let all = serde_json::to_string(&ops).unwrap();
    assert!(!all.contains("SOMEGROUP") && !all.contains("1080p") && !all.contains("BluRay"), "{all}");
    sync_from(&b, &a).await;
    let it = b.app.db.with(|c| syphon::db::get_item(c, &id)).unwrap().unwrap();
    assert_eq!(it.filename.as_deref(), Some("Big Movie (1999).mkv"));
    assert!(it.source.is_none(), "where a file came from stays on the node that fetched it");

    // what a browser receives: no file names, sources or scan details unless you are the owner at home
    let lan = a.access_url.clone();
    let owner = cookies_of(&login_at(&lan, "owner", PW, "").await);
    api_post(&lan, "/api/users", &owner, json!({"name": "kid", "password": "kidpassword", "role": "contributor"})).await;
    let kid = cookies_of(&login_at(&lan, "kid", "kidpassword", "").await);
    let d: Value = api_get(&lan, &format!("/api/items/{id}"), &kid).await.json().await.unwrap();
    for k in ["filename", "source", "scan", "author"] {
        assert!(d["item"].get(k).is_none(), "{k} leaked to a non-owner: {d}");
    }
    let t: Value = api_get(&lan, "/api/trash", &kid).await.json().await.unwrap();
    assert!(t["items"].as_array().unwrap().iter().all(|i| i.get("filename").is_none()));
    let d: Value = api_get(&lan, &format!("/api/items/{id}"), &owner).await.json().await.unwrap();
    assert!(d["item"].get("filename").is_some(), "the owner at home still sees details");

    // response headers
    let r = api_get(&lan, "/api/status", "").await;
    let h = r.headers();
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["cross-origin-resource-policy"], "same-origin");
    assert!(h.get("server").is_none() && h.get("x-powered-by").is_none());
    assert!(h["content-security-policy"].to_str().unwrap().contains("default-src 'none'"));
    // errors never carry file system paths
    let r = api_get(&lan, "/api/stream/doesnotexist", &owner).await;
    assert!(!r.text().await.unwrap().contains("/tmp"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plex_and_jellyfin_sources_keep_their_tokens_encrypted_and_download_into_review() {
    use axum::http::HeaderMap;
    use axum::routing::get;
    let video = fake_video(500_000, "from-plex");
    let jvideo = fake_video(400_000, "from-jf");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (v1, v2) = (video.clone(), jvideo.clone());
    let srv = axum::Router::new()
        .route(
            "/hubs/search",
            get(|h: HeaderMap| async move {
                if h.get("x-plex-token").and_then(|v| v.to_str().ok()) != Some("plex-secret-token") {
                    return (axum::http::StatusCode::UNAUTHORIZED, String::new());
                }
                (axum::http::StatusCode::OK, r#"{"MediaContainer":{"Hub":[{"type":"movie","Metadata":[
                    {"type":"movie","title":"Plex Film","year":2001,"Media":[{"Part":[{"key":"/library/parts/7/1/file.mkv","container":"mkv","size":500000}]}]}]}]}}"#.to_string())
            }),
        )
        .route(
            "/library/parts/7/1/file.mkv",
            get(move |h: HeaderMap| { let v = v1.clone(); async move {
                if h.get("x-plex-token").and_then(|v| v.to_str().ok()) != Some("plex-secret-token") { return (axum::http::StatusCode::UNAUTHORIZED, vec![]); }
                (axum::http::StatusCode::OK, v)
            } }),
        )
        .route(
            "/Items",
            get(|h: HeaderMap| async move {
                if h.get("x-emby-token").and_then(|v| v.to_str().ok()) != Some("jf-secret-key") {
                    return (axum::http::StatusCode::UNAUTHORIZED, String::new());
                }
                (axum::http::StatusCode::OK, r#"{"Items":[{"Id":"abc123","Type":"Episode","SeriesName":"Jelly Show","ParentIndexNumber":2,"IndexNumber":5,"MediaSources":[{"Container":"mp4","Size":400000}]}]}"#.to_string())
            }),
        )
        .route(
            "/Items/abc123/Download",
            get(move |h: HeaderMap| { let v = v2.clone(); async move {
                if h.get("x-emby-token").and_then(|v| v.to_str().ok()) != Some("jf-secret-key") { return (axum::http::StatusCode::UNAUTHORIZED, vec![]); }
                (axum::http::StatusCode::OK, v)
            } }),
        );
    tokio::spawn(async move { axum::serve(l, srv).await.unwrap() });

    // private addresses stay blocked for pasted links, but a source the owner added is trusted
    let n = node_with("src", |c| {
        c.acquire.internet_archive = false;
        c.acquire.allow_private_hosts = false;
    })
    .await;
    let lan = n.access_url.clone();
    let owner = cookies_of(&login_at(&lan, "owner", PW, "").await);
    let base = format!("http://{addr}");
    let r = api_post(&lan, "/api/sources", &owner, json!({"kind": "plex", "name": "Den Plex", "url": base, "token": "plex-secret-token"})).await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let r = api_post(&lan, "/api/sources", &owner, json!({"kind": "jellyfin", "name": "Jelly", "url": base, "token": "jf-secret-key"})).await;
    assert_eq!(r.status(), 200);
    assert_eq!(api_post(&lan, "/api/sources", &owner, json!({"kind": "kodi", "name": "x", "url": base, "token": "t"})).await.status(), 400);
    assert_eq!(api_post(&lan, "/api/sources", &owner, json!({"kind": "plex", "name": "x", "url": "ftp://x", "token": "t"})).await.status(), 400);

    // the token is never returned, and not stored in the clear
    let listed = api_get(&lan, "/api/sources", &owner).await.text().await.unwrap();
    assert!(!listed.contains("plex-secret-token") && !listed.contains("jf-secret-key"));
    let blobs: Vec<Vec<u8>> = n.app.db.with(|c| {
        let mut st = c.prepare("SELECT token_enc FROM sources")?;
        let r = st.query_map([], |r| r.get(0))?;
        Ok(r.collect::<rusqlite::Result<Vec<_>>>()?)
    }).unwrap();
    assert_eq!(blobs.len(), 2);
    for b in &blobs {
        assert!(!b.windows(6).any(|w| w == b"secret"), "token stored in the clear");
    }
    let provs: Value = api_get(&lan, "/api/acquire/providers", &owner).await.json().await.unwrap();
    let labels: Vec<String> = provs["providers"].as_array().unwrap().iter().map(|p| p["label"].as_str().unwrap().to_string()).collect();
    assert!(labels.iter().any(|l| l == "Den Plex (Plex)") && labels.iter().any(|l| l == "Jelly (Jellyfin)") && labels.iter().any(|l| l == "Paste a link"), "{labels:?}");

    for (q, title, hint) in [("plex film", "Plex Film", &video), ("jelly", "Jelly Show S02E05", &jvideo)] {
        let res: Value = api_get(&lan, &format!("/api/acquire/search?q={}", q.replace(' ', "%20")), &owner).await.json().await.unwrap();
        let hit = res["results"].as_array().unwrap().iter().find(|r| r["title"] == title).unwrap_or_else(|| panic!("no {title} in {res}")).clone();
        let r = api_post(&lan, "/api/acquire/queue", &owner, json!({"provider": hit["provider"], "url": hit["url"], "title": hit["title"]})).await;
        assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
        let dl = r.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();
        let t = Instant::now();
        let st = loop {
            let st: String = n.app.db.with(|c| Ok(c.query_row("SELECT status FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
            if !matches!(st.as_str(), "queued" | "resolving" | "downloading") || t.elapsed() > Duration::from_secs(15) { break st; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(st, "review");
        let item: String = n.app.db.with(|c| Ok(c.query_row("SELECT item FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
        assert_eq!(local_state(&n, &item).as_deref(), Some("quarantine"));
        library::approve(&n.app, &item, true).unwrap();
        assert_eq!(&read_all(&n.app, &item), hint);
    }

    // pasted links to private addresses are still refused
    let r = api_post(&lan, "/api/acquire/queue", &owner, json!({"provider": "link", "url": format!("{base}/library/parts/7/1/file.mkv"), "title": "x"})).await;
    assert_eq!(r.status(), 400);

    // locked node: the sources are unusable (tokens are encrypted with the library key)
    n.app.keyring.lock();
    assert!(acquire::load_sources(&n.app).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn episodes_named_differently_are_grouped_as_one_show_and_movies_are_not() {
    let a = node("A").await;
    let v = |s: &str| fake_video(2000, s);
    for (i, name) in ["Some.Show.S01E01.1080p.mkv", "some show - 1x02.mp4", "The Some Show (2019) Season 2 Episode 3.mkv", "Other Show S01E01.mp4", "Some Film 1999.mp4"].iter().enumerate() {
        add_video(&a, name, &v(&format!("g{i}")), true);
    }
    let r = login_at(&a.access_url, "owner", PW, "").await;
    let cookie = cookies_of(&r);
    let d: Value = api_get(&a.access_url, "/api/library", &cookie).await.json().await.unwrap();
    let items = d["items"].as_array().unwrap();
    let group = |t: &str| items.iter().find(|i| i["title"].as_str().unwrap().to_lowercase().contains(t)).and_then(|i| i["group"].as_str().map(String::from));
    let some: Vec<_> = items.iter().filter(|i| i["title"].as_str().unwrap().to_lowercase().contains("some show")).collect();
    assert_eq!(some.len(), 3);
    assert!(some.iter().all(|i| i["group"] == "someshow"), "three spellings, one show");
    assert_ne!(group("other show"), group("some show"));
    let film = items.iter().find(|i| i["kind"] == "movie").unwrap();
    assert!(film.get("group").is_none(), "movies are never grouped");
    // changing the title of every episode moves them together (this is what "combine" does)
    for i in &some {
        let r = reqwest::Client::new()
            .patch(format!("{}/api/items/{}", a.access_url, i["id"].as_str().unwrap()))
            .header("cookie", &cookie)
            .header("x-requested-with", "syphon")
            .json(&json!({"title": "Renamed Show", "kind": "series", "year": null, "season": 1, "episode": i["episode"]}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
    }
    let d: Value = api_get(&a.access_url, "/api/library", &cookie).await.json().await.unwrap();
    let renamed: Vec<_> = d["items"].as_array().unwrap().iter().filter(|i| i["group"] == "renamedshow").collect();
    assert_eq!(renamed.len(), 3);
}

// ------------------------------------------------------------------ round four

/// A server that cuts the connection halfway the first time, then honours Range requests.
#[tokio::test]
async fn a_dropped_connection_resumes_and_the_kind_hint_and_cancel_work() {
    use axum::{body::Body, http::{HeaderMap, StatusCode}, response::Response, routing::get};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    let video = fake_video(3 << 20, "resume");
    let hits = Arc::new(AtomicUsize::new(0));
    let (v2, h2) = (video.clone(), hits.clone());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let srv = axum::Router::new()
        .route("/v/%5BGrp%5D%20Show%20-%2001%20%5BABCD1234%5D.mkv", get(move |hd: HeaderMap| {
            let (v, hits) = (v2.clone(), h2.clone());
            async move {
                let n = hits.fetch_add(1, Ordering::SeqCst);
                let start = hd.get("range").and_then(|r| r.to_str().ok()).and_then(|r| r.strip_prefix("bytes=")).and_then(|r| r.trim_end_matches('-').parse::<usize>().ok()).unwrap_or(0);
                let rest = v[start..].to_vec();
                let total = v.len();
                let mut b = Response::builder().header("content-type", "video/x-matroska").header("accept-ranges", "bytes");
                if start > 0 {
                    b = b.status(StatusCode::PARTIAL_CONTENT).header("content-range", format!("bytes {start}-{}/{total}", total - 1));
                }
                let b = b.header("content-length", rest.len());
                if n == 0 {
                    let half = rest[..rest.len() / 2].to_vec();
                    let s = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(axum::body::Bytes::from(half)), Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "cut"))]);
                    b.body(Body::from_stream(s)).unwrap()
                } else {
                    b.body(Body::from(rest)).unwrap()
                }
            }
        }));
    tokio::spawn(async move { axum::serve(l, srv).await.unwrap() });
    let n = node("resume").await;
    let url = format!("http://{addr}/v/%5BGrp%5D%20Show%20-%2001%20%5BABCD1234%5D.mkv");
    let dl = acquire::queue(&n.app, "link", &url, "Show", "").await.unwrap();
    let t = Instant::now();
    let st = loop {
        let st: String = n.app.db.with(|c| Ok(c.query_row("SELECT status FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
        if matches!(st.as_str(), "review" | "failed") || t.elapsed() > Duration::from_secs(40) { break st; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let why: Option<String> = n.app.db.with(|c| Ok(c.query_row("SELECT error FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
    assert_eq!(st, "review", "download should survive a dropped connection: {why:?}");
    assert!(hits.load(Ordering::SeqCst) >= 2);
    let item: String = n.app.db.with(|c| Ok(c.query_row("SELECT item FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
    let kind: String = n.app.db.with(|c| Ok(c.query_row("SELECT kind FROM items WHERE id=?1", [&item], |r| r.get(0))?)).unwrap();
    assert_eq!(kind, "anime", "a fansub-style name is not filed as a movie");

    // editing in review, then approving marks the download finished
    library::edit_review(&n.app, &item, Some("Show"), Some("series"), None, Some(Some(1)), Some(Some(1))).unwrap();
    library::approve(&n.app, &item, true).unwrap();
    assert_eq!(read_all(&n.app, &item), video, "resumed file is byte-identical");
    let fin: Option<i64> = n.app.db.with(|c| Ok(c.query_row("SELECT finished FROM downloads WHERE id=?1", [&dl], |r| r.get(0))?)).unwrap();
    assert!(fin.is_some());

    // cancel a queued item and clear it
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a2 = l2.local_addr().unwrap();
    let slow = axum::Router::new().route("/slow.mp4", get(|| async {
        let s = futures_util::stream::unfold(0, |i| async move { tokio::time::sleep(Duration::from_millis(200)).await; Some((Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![0u8; 1024])), i + 1)) });
        Response::builder().header("content-length", 100_000_000).body(Body::from_stream(s)).unwrap()
    }));
    tokio::spawn(async move { axum::serve(l2, slow).await.unwrap() });
    let d2 = acquire::queue(&n.app, "link", &format!("http://{a2}/slow.mp4"), "Slow", "movie").await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    acquire::cancel(&n.app, &d2).unwrap();
    let t = Instant::now();
    loop {
        let st: String = n.app.db.with(|c| Ok(c.query_row("SELECT status FROM downloads WHERE id=?1", [&d2], |r| r.get(0))?)).unwrap();
        if st == "cancelled" && !n.app.active_downloads.lock().unwrap().contains(&d2) { break; }
        assert!(t.elapsed() < Duration::from_secs(10), "stuck in {st}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(acquire::clear_finished(&n.app).unwrap() >= 2);
}

// ------------------------------------------------------------------ round five: the malware scanner

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn with_payload(seed: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = fake_video(3_000_000, seed);
    v[2_500_000..2_500_000 + payload.len()].copy_from_slice(payload);
    v
}

/// What a compromised peer could do: put a file straight into its library and announce it.
fn plant_in_library(n: &TestNode, id: &str) {
    std::fs::rename(library::quarantine_path(&n.app, id), library::library_path(&n.app, id)).unwrap();
    n.app
        .db
        .with(|c| {
            c.execute("UPDATE items SET local='present' WHERE id=?1", [id])?;
            let it = db::get_item(c, id)?.unwrap();
            syphon::catalog::emit_conn(c, &n.app.id, "add", &syphon::catalog::add_body(&it))?;
            Ok(())
        })
        .unwrap();
}

async fn scan_of(n: &TestNode, id: &str) -> Value {
    let it = n.app.db.with(|c| db::get_item(c, id)).unwrap().unwrap();
    it.scan.unwrap_or(Value::Null)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hidden_programs_and_known_malware_are_found_anywhere_in_the_file_and_cannot_be_approved() {
    let n = node("scan").await;
    let mut elf = vec![0x7F, b'E', b'L', b'F', 2, 1, 1];
    elf.extend_from_slice(&[0; 9]);
    elf.extend_from_slice(&[0xAA; 40]);
    let mut zip = fake_video(3_000_000, "zip");
    let eocd: Vec<u8> = [b"PK\x05\x06".to_vec(), vec![0; 18]].concat();
    zip.extend_from_slice(&eocd);
    // a valid-looking MP4 with data glued on after the last box
    let mut trailing = fake_video(3_000_000, "trail");
    trailing.extend_from_slice(b"this is not part of any video box, but it is here anyway........");

    for (name, data, hard) in [
        ("Eicar.2020.mp4", with_payload("eicar", EICAR), true),
        ("Elf.2020.mp4", with_payload("elf", &elf), true),
        ("Zip.2020.mp4", zip, true),
        ("Trailing.2020.mp4", trailing, false),
    ] {
        let id = add_video(&n, name, &data, false);
        let it = n.app.db.with(|c| db::get_item(c, &id)).unwrap().unwrap();
        library::post_ingest(&n.app, &library::Ingested { id: id.clone(), size: data.len() as u64, dup: false, restored: false }, "upload".into()).await.unwrap();
        let _ = it;
        let sc = scan_of(&n, &id).await;
        assert_eq!(sc["ok"], false, "{name}: {sc}");
        assert_eq!(sc["hard"], hard, "{name}: {sc}");
        assert!(!sc["findings"].as_array().unwrap().is_empty(), "{name} explains itself");
        let e = library::approve(&n.app, &id, true);
        if hard {
            assert!(e.is_err(), "{name} must not be approvable even with an override");
            assert_eq!(local_state(&n, &id).as_deref(), Some("quarantine"));
        } else {
            e.unwrap(); // a soft finding is the owner's call
        }
    }
    // a clean file still passes
    let ok = add_video(&n, "Clean.2020.mp4", &fake_video(3_000_000, "clean"), false);
    library::post_ingest(&n.app, &library::Ingested { id: ok.clone(), size: 3_000_000, dup: false, restored: false }, "upload".into()).await.unwrap();
    assert_eq!(scan_of(&n, &ok).await["ok"], true);
    library::approve(&n.app, &ok, false).unwrap();

    // the blocklist: a clean file becomes unapprovable once its hash is listed
    let data = fake_video(3_000_000, "listed");
    let sha = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&data))
    };
    std::fs::write(n.app.dirs.root.join("blocklist.txt"), format!("# known bad\n{sha}\n")).unwrap();
    let id = add_video(&n, "Listed.2020.mp4", &data, false);
    library::post_ingest(&n.app, &library::Ingested { id: id.clone(), size: 3_000_000, dup: false, restored: false }, "upload".into()).await.unwrap();
    let sc = scan_of(&n, &id).await;
    assert_eq!(sc["hard"], true, "{sc}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_infected_file_from_a_peer_is_blocked_and_never_passed_on() {
    let a = node("evil").await;
    let b = node("victim").await;
    let c = node("bystander").await;
    pair_up(&a, &b).await;
    pair_up(&b, &c).await;
    pair_up(&a, &c).await;
    let bad = with_payload("peer-eicar", EICAR);
    let good = fake_video(2_000_000, "peer-good");
    let bad_id = add_video(&a, "Bad.2020.mp4", &bad, false);
    plant_in_library(&a, &bad_id); // a compromised node ignores its own scanner
    let good_id = add_video(&a, "Good.2021.mp4", &good, true);

    sync_from(&b, &a).await;
    assert_eq!(local_state(&b, &good_id).as_deref(), Some("present"), "clean files still sync");
    assert_eq!(local_state(&b, &bad_id).as_deref(), Some("blocked"), "the infected file is held back on arrival");
    assert!(!library::library_path(&b.app, &bad_id).exists(), "it never reached the library folder");
    assert!(library::open_reader(&b.app, &bad_id).is_err(), "and cannot be streamed");
    assert!(library::approve(&b.app, &bad_id, true).is_err(), "and cannot be approved");

    // the victim does not become a carrier: the bystander gets the clean file but not the infected one
    sync_from(&c, &b).await;
    assert_eq!(local_state(&c, &good_id).as_deref(), Some("present"));
    assert_ne!(local_state(&c, &bad_id).as_deref(), Some("present"));
    assert!(!library::library_path(&c.app, &bad_id).exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rescanning_the_library_pulls_out_files_that_now_fail_and_the_vault_scans_too() {
    let n = node("rescan").await;
    let id = add_video(&n, "Late.2020.mp4", &with_payload("late", EICAR), false);
    plant_in_library(&n, &id);
    assert_eq!(local_state(&n, &id).as_deref(), Some("present"));
    syphon::scanner::start_library_rescan(&n.app).unwrap();
    let t = Instant::now();
    while syphon::scanner::progress().running {
        assert!(t.elapsed() < Duration::from_secs(30));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(syphon::scanner::progress().blocked, 1);
    assert_eq!(local_state(&n, &id).as_deref(), Some("blocked"));

    // vault upload of the same hostile bytes is refused
    let r = login_at(&n.access_url, "owner", PW, "").await;
    let cookie = cookies_of(&r);
    let r = reqwest::Client::new()
        .put(format!("{}/api/vault/upload?name=Secret.mp4", n.access_url))
        .header("cookie", &cookie)
        .header("x-requested-with", "syphon")
        .body(with_payload("vault-eicar", EICAR))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422, "{}", r.text().await.unwrap());
    let r = reqwest::Client::new()
        .put(format!("{}/api/vault/upload?name=Mine.mp4", n.access_url))
        .header("cookie", &cookie)
        .header("x-requested-with", "syphon")
        .body(fake_video(1_000_000, "vault-ok"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_files_with_the_index_at_the_end_and_matroska_files_pass_every_layer() {
    if std::process::Command::new("ffmpeg").arg("-version").output().is_err() {
        eprintln!("ffmpeg not installed: skipping");
        return;
    }
    let n = node_with("real", |c| {
        c.ffprobe = "ffprobe".into();
        c.scan.decode = true;
    })
    .await;
    let tmp = tempfile::tempdir().unwrap();
    for (name, extra) in [("Endindex.2020.mp4", vec![]), ("Matroska.2020.mkv", vec!["-f", "matroska"])] {
        let path = tmp.path().join(name);
        let ok = std::process::Command::new("ffmpeg")
            .args(["-v", "error", "-f", "lavfi", "-i", "testsrc=duration=3:size=320x240:rate=15", "-f", "lavfi", "-i", "sine=frequency=440:duration=3"])
            .args(["-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest"])
            .args(&extra)
            .arg(&path)
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let ing = library::import_path(&n.app, &path, "import").await.unwrap();
        let sc = scan_of(&n, &ing.id).await;
        assert_eq!(sc["ok"], true, "{name}: {sc}");
        assert_eq!(sc["has_video"], true, "{name}: {sc}");
        let engines = sc["engines"].to_string();
        assert!(engines.contains("signatures") && engines.contains("structure") && engines.contains("ffprobe"), "{engines}");
    }
}

// ------------------------------------------------------------------ round five: details (cast, genres, posters)

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn details_are_fetched_stored_encrypted_and_served_as_genres_cast_and_poster() {
    use axum::{extract::Query, routing::get, Json};
    use std::collections::HashMap;
    let png: Vec<u8> = [b"\x89PNG\r\n\x1a\n".to_vec(), vec![7u8; 500]].concat();
    let p2 = png.clone();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let base = format!("http://{addr}");
    let b2 = base.clone();
    let srv = axum::Router::new()
        .route("/search/shows", get(|Query(q): Query<HashMap<String, String>>| async move {
            let name = q.get("q").cloned().unwrap_or_default();
            let id = if name.to_lowercase().contains("moon") { 2 } else if name.to_lowercase().contains("space") { 1 } else { 99 };
            if id == 99 {
                return Json(json!([]));
            }
            Json(json!([{ "score": 1.0, "show": { "id": id, "name": if id == 2 { "Moon Quest" } else { "Space Show" } } }]))
        }))
        .route("/shows/1", get(move || { let b = b2.clone(); async move {
            Json(json!({"id":1,"name":"Space Show","premiered":"2015-01-01","genres":["Comedy","Science-Fiction"],"summary":"<p>A <b>funny</b> show.</p>",
                "image":{"original": format!("{b}/img.png")}, "rating":{"average":8.1},
                "_embedded":{"cast":[{"person":{"name":"Ada Actor"},"character":{"name":"Captain"}}],
                "episodes":[{"season":1,"number":1,"name":"Pilot Light"},{"season":1,"number":2,"name":"Second Wind"}]}}))
        }}))
        // TVmaze files this one as anime, whatever its file names looked like
        .route("/shows/2", get(|| async { Json(json!({"id":2,"name":"Moon Quest","premiered":"2020-01-01","genres":["Anime","Action","Thriller"],"language":"Japanese","type":"Animation","summary":"<p>A moon adventure.</p>",
            "_embedded":{"cast":[],"episodes":[{"season":1,"number":1,"name":"Wrong Name From TVmaze"}]}})) }))
        .route("/anime", get({ let b = base.clone(); move |Query(q): Query<HashMap<String, String>>| { let b = b.clone(); async move {
            let name = q.get("q").cloned().unwrap_or_default().to_lowercase();
            let png = format!("{b}/img.png");
            if name.contains("moon") {
                Json(json!({"data":[{"mal_id":7,"title":"Moon Quest","type":"TV","episodes":12,"synopsis":"Anime synopsis","genres":[{"name":"Action"},{"name":"Fantasy"}],"themes":[],"score":8.0,"year":2020,"images":{"jpg":{"large_image_url": png}}}]}))
            } else if name.contains("trinity") {
                // the official name is longer than the file's, and the first hit is something else
                Json(json!({"data":[{"mal_id":8,"title":"Seven Deadly Sins","type":"TV"},{"mal_id":9,"title":"Trinity Seven: Heavens Library & Crimson Lord","title_english":"Trinity Seven","type":"TV","episodes":24,"synopsis":"A magic academy.","genres":[{"name":"Action"},{"name":"Ecchi"}],"themes":[],"score":7.3,"year":2014,"images":{"jpg":{"large_image_url": png}}}]}))
            } else if name.contains("kimi") {
                Json(json!({"data":[{"mal_id":10,"title":"Kimi Test","type":"Movie","episodes":1,"synopsis":"A film from Japan.","genres":[{"name":"Drama"}],"themes":[],"score":8.4,"year":2016,"images":{"jpg":{"large_image_url": png}}}]}))
            } else {
                Json(json!({"data":[]}))
            }
        } } }))
        .route("/anime/7/characters", get(|| async { Json(json!({"data":[{"character":{"name":"Luna"},"voice_actors":[{"language":"Japanese","person":{"name":"Voice Person"}}]}]})) }))
        .route("/anime/7/episodes", get(|| async { Json(json!({"data":[{"mal_id":1,"title":"The Moon Rises"},{"mal_id":2,"title":"A Second Night"}],"pagination":{"has_next_page":false}})) }))
        .route("/anime/9/characters", get(|| async { Json(json!({"data":[]})) }))
        .route("/anime/9/episodes", get(|| async { Json(json!({"data":[{"mal_id":1,"title":"Seven Sins"}],"pagination":{"has_next_page":false}})) }))
        .route("/anime/10/characters", get(|| async { Json(json!({"data":[]})) }))
        .route("/img.png", get(move || { let p = p2.clone(); async move { ([("content-type", "image/png")], p) } }))
        .route("/w/api.php", get(|Query(q): Query<HashMap<String, String>>| async move {
            match q.get("action").map(|s| s.as_str()) {
                Some("wbsearchentities") => {
                    if q.get("search").map(|s| s.to_lowercase().contains("night terror")).unwrap_or(false) {
                        Json(json!({"search":[{"id":"Q1","label":"Night Terror","description":"2001 horror film by someone"}]}))
                    } else {
                        Json(json!({"search":[]}))
                    }
                }
                Some("wbgetentities") if q["ids"] == "Q1" => Json(json!({"entities":{"Q1":{"claims":{
                    "P136":[{"mainsnak":{"datavalue":{"value":{"id":"Q10"}}}}],
                    "P161":[{"mainsnak":{"datavalue":{"value":{"id":"Q20"}}}}]}}}})),
                _ => Json(json!({"entities":{"Q10":{"labels":{"en":{"value":"horror film"}}},"Q20":{"labels":{"en":{"value":"Bela Scary"}}}}})),
            }
        }));
    tokio::spawn(async move { axum::serve(l, srv).await.unwrap() });

    let n = node_with("meta", |c| {
        c.metadata.tvmaze = base.clone();
        c.metadata.jikan = base.clone();
        c.metadata.wikidata = base.clone();
        c.metadata.wikipedia = base.clone();
        c.metadata.commons = base.clone();
        c.metadata.itunes = base.clone();
        c.metadata.imdb = base.clone();
    })
    .await;
    let show = add_video(&n, "Space.Show.S01E01.mp4", &fake_video(1_200_000, "m1"), true);
    let movie = add_video(&n, "Night.Terror.2001.mp4", &fake_video(1_200_000, "m2"), true);
    // named like an ordinary series, but the sources know it is anime
    let moon = add_video(&n, "Moon.Quest.S01E01.mp4", &fake_video(1_200_000, "m3"), true);
    // the way an anime site names its files: the site, the tags, a dub marker; and the official title is longer
    let trinity = add_video(&n, "AnimePahe_Trinity_Seven_-_01_BD_1080p_Eng_Dub.mp4", &fake_video(1_200_000, "m4"), true);
    // an anime film that landed in the movie slot, named exactly like the anime
    let kimi = add_video(&n, "Kimi Test (2016).mp4", &fake_video(1_200_000, "m5"), true);
    for it in [&show, &movie, &moon, &trinity, &kimi] {
        let it = n.app.db.with(|c| db::get_item(c, it)).unwrap().unwrap();
        let key = syphon::metadata::key_of(&it);
        assert!(syphon::metadata::fetch_and_store_titles(&n.app, &key, &syphon::metadata::lookup_titles(&it), &it.kind, it.year).await.unwrap(), "{}", it.title);
    }
    let r = login_at(&n.access_url, "owner", PW, "").await;
    let cookie = cookies_of(&r);
    let lib: Value = api_get(&n.access_url, "/api/library", &cookie).await.json().await.unwrap();
    let find = |t: &str| lib["items"].as_array().unwrap().iter().find(|i| i["title"] == t).cloned().unwrap();
    let s = find("Space Show");
    assert_eq!(s["genres"], json!(["Comedy", "Sci-Fi"]));
    assert_eq!(s["ep_title"], "Pilot Light", "episode names come from the source");
    assert_eq!(s["kind"], "series");
    assert_eq!(s["poster"], true);
    let m = find("Night Terror");
    assert_eq!(m["genres"], json!(["Horror"]));
    // detected as anime from the sources: shown and filtered as anime, with the anime source's details and episode names
    let a = find("Moon Quest");
    assert_eq!(a["kind"], "anime");
    assert_eq!(a["ep_title"], "The Moon Rises");
    let t = find("Trinity Seven");
    assert_eq!(t["kind"], "anime", "{t}");
    assert_eq!(t["ep_title"], "Seven Sins");
    let k = find("Kimi Test");
    assert_eq!(k["kind"], "anime", "a one-file anime film in the movie slot is recognised: {k}");
    assert_eq!(k["genres"], json!(["Drama"]));
    let only: Value = api_get(&n.access_url, "/api/library?kind=anime", &cookie).await.json().await.unwrap();
    assert_eq!(only["items"].as_array().unwrap().len(), 3);
    let only: Value = api_get(&n.access_url, "/api/library?kind=series", &cookie).await.json().await.unwrap();
    assert_eq!(only["items"].as_array().unwrap().len(), 1, "the anime is no longer listed as a series");
    let d: Value = api_get(&n.access_url, &format!("/api/items/{show}"), &cookie).await.json().await.unwrap();
    assert_eq!(d["item"]["details"]["cast"][0]["name"], "Ada Actor");
    assert_eq!(d["item"]["details"]["overview"], "A funny show.");
    let r = api_get(&n.access_url, &format!("/api/poster/{show}"), &cookie).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "image/png");
    assert_eq!(r.bytes().await.unwrap().to_vec(), png);
    // the poster sits on disk as ciphertext
    let on_disk = std::fs::read_dir(n.app.dirs.root.join("artwork")).unwrap().next().unwrap().unwrap().path();
    assert!(!std::fs::read(on_disk).unwrap().windows(100).any(|w| w == &png[10..110]));

    // genres typed in by hand win over looked-up ones
    let r = reqwest::Client::new().put(format!("{}/api/items/{movie}/genres", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"genres":["Comedy"]})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let lib: Value = api_get(&n.access_url, "/api/library", &cookie).await.json().await.unwrap();
    let m = lib["items"].as_array().unwrap().iter().find(|i| i["title"] == "Night Terror").unwrap();
    assert_eq!(m["genres"], json!(["Comedy"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_user_can_set_and_remove_their_own_profile_picture() {
    let n = node("avatars").await;
    let owner = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let r = api_post(&n.access_url, "/api/users", &owner, json!({"name": "sam", "password": "sams-password-1", "role": "viewer"})).await;
    assert_eq!(r.status(), 200);
    let sam = cookies_of(&login_at(&n.access_url, "sam", "sams-password-1", "").await);
    let me: Value = api_get(&n.access_url, "/api/me", &sam).await.json().await.unwrap();
    assert!(me["avatar"].is_null());
    let png: Vec<u8> = [b"\x89PNG\r\n\x1a\n".to_vec(), vec![1u8; 300]].concat();
    let put = |body: Vec<u8>, cookie: String| {
        let url = format!("{}/api/me/avatar", n.access_url);
        async move { reqwest::Client::new().put(url).header("cookie", cookie).header("x-requested-with", "syphon").body(body).send().await.unwrap() }
    };
    assert_eq!(put(png.clone(), sam.clone()).await.status(), 200);
    assert_eq!(put(b"<svg onload=alert(1)></svg>".to_vec(), sam.clone()).await.status(), 400, "only real raster pictures");
    assert_eq!(put(vec![0xFF, 0xD8, 0xFF, 0xE0].into_iter().chain(vec![0u8; 500_000]).collect(), sam.clone()).await.status(), 413);
    let me: Value = api_get(&n.access_url, "/api/me", &sam).await.json().await.unwrap();
    assert!(me["avatar"].is_number());
    // other signed-in people can see it; strangers cannot
    let r = api_get(&n.access_url, "/api/avatar/sam", &owner).await;
    assert_eq!((r.status().as_u16(), r.headers()["content-type"].to_str().unwrap().to_string()), (200, "image/png".into()));
    assert_eq!(api_get(&n.access_url, "/api/avatar/sam", "").await.status(), 401);
    // changing it for someone else is not possible: the endpoint only ever touches the caller's own
    assert_eq!(put(png.clone(), owner.clone()).await.status(), 200);
    let r = reqwest::Client::new().delete(format!("{}/api/me/avatar", n.access_url)).header("cookie", &sam).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(api_get(&n.access_url, "/api/avatar/sam", &owner).await.status(), 404);
    assert_eq!(api_get(&n.access_url, "/api/avatar/owner", &owner).await.status(), 200);

    // updates are off until configured; the page cannot make the node run anything
    let r = api_post(&n.access_url, "/api/update", &owner, json!({"action": "apply"})).await;
    assert_eq!(r.status(), 400);
    let r = api_post(&n.access_url, "/api/update", &sam, json!({"action": "apply"})).await;
    assert!(r.status().as_u16() == 403 || r.status().as_u16() == 401);
}

// two tests below change the process-wide PATH, so they take turns
static PATH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// ClamAV must only ever block when it names a signature. An exit code on its own (a crashed
/// scanner, a sandbox that would not start) is "could not scan", never "this is malware".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clamav_only_blocks_when_it_names_a_signature() {
    let _path_guard = PATH_LOCK.lock().await; // these tests change the process-wide PATH, so they take turns
    use std::os::unix::fs::PermissionsExt;
    let bin = tempfile::tempdir().unwrap();
    let script = bin.path().join("clamscan");
    std::fs::write(
        &script,
        "#!/bin/sh\ncat > /tmp/syphon-fake-clam.$$\nif grep -q CLAMTEST-VIRUS /tmp/syphon-fake-clam.$$; then rm -f /tmp/syphon-fake-clam.$$; echo 'stream: Win.Test.Fake-1 FOUND'; exit 1; fi\nif grep -q CLAMTEST-BROKEN /tmp/syphon-fake-clam.$$; then rm -f /tmp/syphon-fake-clam.$$; echo 'ERROR: something went wrong' >&2; exit 1; fi\nrm -f /tmp/syphon-fake-clam.$$\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let old = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", bin.path().display(), old));

    let n = node_with("clam", |c| c.scan.clamav = "auto".into()).await;
    let mut results = vec![];
    for (name, marker) in [("Clean.2020.mp4", ""), ("Broken.2020.mp4", "CLAMTEST-BROKEN"), ("Virus.2020.mp4", "CLAMTEST-VIRUS")] {
        let data = with_payload(name, marker.as_bytes());
        let id = add_video(&n, name, &data, false);
        library::post_ingest(&n.app, &library::Ingested { id: id.clone(), size: data.len() as u64, dup: false, restored: false }, "upload".into()).await.unwrap();
        results.push((name, scan_of(&n, &id).await));
    }
    std::env::set_var("PATH", old);
    let (_, clean) = &results[0];
    assert_eq!(clean["hard"], false, "{clean}");
    assert_eq!(clean["ok"], true, "{clean}");
    let (_, broken) = &results[1];
    assert_eq!(broken["hard"], false, "a scanner failure is not a verdict: {broken}");
    assert!(!broken.to_string().contains("identified this file as malware"), "{broken}");
    let (_, virus) = &results[2];
    assert_eq!(virus["hard"], true, "{virus}");
    assert!(virus.to_string().contains("Win.Test.Fake-1"), "the signature is named: {virus}");
}

/// A big movie goes to ClamAV in overlapping windows; a signature that sits across a window boundary is still found.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clamav_sees_the_whole_file_even_when_it_is_fed_in_windows() {
    let _path_guard = PATH_LOCK.lock().await; // these tests change the process-wide PATH, so they take turns
    use std::os::unix::fs::PermissionsExt;
    let bin = tempfile::tempdir().unwrap();
    let script = bin.path().join("clamscan");
    std::fs::write(&script, "#!/bin/sh\ncat > /tmp/syphon-fake-clam2.$$\nif grep -q CLAMTEST-VIRUS /tmp/syphon-fake-clam2.$$; then rm -f /tmp/syphon-fake-clam2.$$; echo 'stream: Win.Test.Fake-2 FOUND'; exit 1; fi\nrm -f /tmp/syphon-fake-clam2.$$\nexit 0\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let old = std::env::var("PATH").unwrap_or_default();
    std::env::set_var("PATH", format!("{}:{}", bin.path().display(), old));
    syphon::scanner::CLAM_WINDOW.store(512 * 1024, std::sync::atomic::Ordering::Relaxed);

    let n = node_with("clamwin", |c| c.scan.clamav = "auto".into()).await;
    let mut data = fake_video(3_000_000, "window");
    let marker = b"CLAMTEST-VIRUS";
    let at = 3 * 512 * 1024 - 7; // straddles the boundary between two windows
    data[at..at + marker.len()].copy_from_slice(marker);
    let id = add_video(&n, "Straddle.2020.mp4", &data, false);
    library::post_ingest(&n.app, &library::Ingested { id: id.clone(), size: data.len() as u64, dup: false, restored: false }, "upload".into()).await.unwrap();
    let sc = scan_of(&n, &id).await;
    syphon::scanner::CLAM_WINDOW.store(0, std::sync::atomic::Ordering::Relaxed);
    std::env::set_var("PATH", old);
    assert_eq!(sc["hard"], true, "{sc}");
    assert!(sc.to_string().contains("Win.Test.Fake-2"), "{sc}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_videos_are_accepted_and_uploads_resume_where_they_stopped() {
    let n = node("videos").await;
    let base = n.access_url.clone();
    let r = login_at(&base, "owner", PW, "").await;
    assert_eq!(r.status(), 200);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().split(';').next().unwrap().to_string();
    let http = reqwest::Client::new();
    let put = |path: String, body: Vec<u8>| http.put(format!("{base}{path}")).header("cookie", cookie.clone()).header("x-requested-with", "syphon").body(body).send();
    let post = |path: String| http.post(format!("{base}{path}")).header("cookie", cookie.clone()).header("x-requested-with", "syphon").send();

    // a name that is not a video is refused on every upload route
    assert_eq!(put("/api/upload?name=notes.txt".into(), b"hello".to_vec()).await.unwrap().status(), 415);
    assert_eq!(put("/api/vault/upload?name=notes.txt".into(), b"hello".to_vec()).await.unwrap().status(), 415);
    assert_eq!(post("/api/upload/start?name=readme.txt&size=10".into()).await.unwrap().status(), 415);
    // a video name over text is caught by what is inside
    let r = post("/api/upload/start?name=fake.mp4&size=100".into()).await.unwrap();
    let sid = r.json::<Value>().await.unwrap()["sid"].as_str().unwrap().to_string();
    assert_eq!(put(format!("/api/upload/{sid}?offset=0"), b"this is just a text file pretending to be a movie".to_vec().repeat(2)).await.unwrap().status(), 415);

    // a real upload in two pieces, with a wrong offset in between
    let data = fake_video(2_000_000, "resumable");
    let r = post(format!("/api/upload/start?name=Resumable.Movie.2020.mp4&size={}", data.len())).await.unwrap();
    assert_eq!(r.status(), 200);
    let sid = r.json::<Value>().await.unwrap()["sid"].as_str().unwrap().to_string();
    let half = 900_000;
    let r = put(format!("/api/upload/{sid}?offset=0"), data[..half].to_vec()).await.unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["received"], half);
    // the browser lost track and sends from the wrong place: the node says where it is
    let r = put(format!("/api/upload/{sid}?offset=0"), data[..half].to_vec()).await.unwrap();
    assert_eq!(r.status(), 409);
    assert_eq!(r.json::<Value>().await.unwrap()["received"], half);
    let st = api_get(&base, &format!("/api/upload/{sid}"), &cookie).await.json::<Value>().await.unwrap();
    assert_eq!(st["received"], half);
    // finishing too early is refused, then the rest goes in
    assert_eq!(post(format!("/api/upload/{sid}/finish")).await.unwrap().status(), 409);
    assert_eq!(put(format!("/api/upload/{sid}?offset={half}"), data[half..].to_vec()).await.unwrap().status(), 200);
    let r = post(format!("/api/upload/{sid}/finish")).await.unwrap();
    assert_eq!(r.status(), 200);
    let id = r.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();
    let it = n.app.db.with(|c| db::get_item(c, &id)).unwrap().unwrap();
    assert_eq!(it.local, "quarantine");
    assert!(it.scan.is_some(), "the scan ran (inline in this test): local={} dup={:?}", it.local, it.filename);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_background_scanner_picks_up_waiting_files_by_itself() {
    let n = node_with("bg", |c| c.scan.background = true).await;
    let a = add_video(&n, "Alpha.Movie.2019.mp4", &fake_video(1_500_000, "bg-a"), false);
    let b = add_video(&n, "Beta.Movie.2020.mp4", &fake_video(1_500_000, "bg-b"), false);
    assert!(scan_of(&n, &a).await.is_null() && scan_of(&n, &b).await.is_null());
    tokio::spawn(syphon::quarantine::run_worker(n.app.clone()));
    n.app.scan_wake.notify_one();
    let t = Instant::now();
    loop {
        if !scan_of(&n, &a).await.is_null() && !scan_of(&n, &b).await.is_null() {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(30), "the worker never scanned the waiting files");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // a file added later, with the worker already idle, is found too (this is the "it stopped and I had to click" case)
    let c = add_video(&n, "Gamma.Movie.2021.mp4", &fake_video(1_500_000, "bg-c"), false);
    n.app.scan_wake.notify_one();
    let t = Instant::now();
    while scan_of(&n, &c).await.is_null() {
        assert!(t.elapsed() < Duration::from_secs(30), "a later file was never scanned");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_film_missing_from_one_catalogue_is_found_in_another_and_hyphenated_names_work() {
    use axum::{extract::Query, routing::get, Json};
    use std::collections::HashMap;
    let png: Vec<u8> = [b"\x89PNG\r\n\x1a\n".to_vec(), vec![9u8; 400]].concat();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let b2 = base.clone();
    let srv = axum::Router::new()
        // Wikidata knows nothing; iTunes has the text and genre; IMDb has the cast and a poster
        .route("/search", get(|Query(q): Query<HashMap<String, String>>| async move {
            if q.get("term").map(|t| t.to_lowercase().contains("la la land")).unwrap_or(false) {
                Json(json!({"results":[{"kind":"feature-movie","trackName":"La La Land","releaseDate":"2016-12-09T08:00:00Z","longDescription":"A pianist and an actress fall in love in Los Angeles.","primaryGenreName":"Drama"}]}))
            } else { Json(json!({"results":[]})) }
        }))
        .route("/suggestion/l/la%20la%20land.json", get(move || { let b = b2.clone(); async move {
            Json(json!({"d":[{"id":"tt3783958","l":"La La Land","qid":"movie","y":2016,"s":"Ryan Gosling, Emma Stone","i":{"imageUrl": format!("{b}/p.png")}}]}))
        }}))
        .route("/p.png", get(move || { let p = png.clone(); async move { ([("content-type", "image/png")], p) } }))
        .route("/w/api.php", get(|| async { Json(json!({"search": [], "query": {"search": []}})) }));
    tokio::spawn(async move { axum::serve(l, srv).await.unwrap() });
    let n = node_with("film", |c| {
        c.metadata.wikidata = base.clone();
        c.metadata.wikipedia = base.clone();
        c.metadata.itunes = base.clone();
        c.metadata.imdb = base.clone();
        c.metadata.tvmaze = base.clone();
        c.metadata.jikan = base.clone();
        c.metadata.anilist = format!("{base}/graphql");
    })
    .await;
    let id = add_video(&n, "La-La-Land.2016.1080p.BluRay.mp4", &fake_video(1_200_000, "lll"), true);
    let it = n.app.db.with(|c| db::get_item(c, &id)).unwrap().unwrap();
    assert_eq!(it.title, "La La Land");
    let key = syphon::metadata::key_of(&it);
    assert!(syphon::metadata::fetch_and_store_titles(&n.app, &key, &syphon::metadata::lookup_titles(&it), &it.kind, it.year).await.unwrap());
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let d: Value = api_get(&n.access_url, &format!("/api/items/{id}"), &cookie).await.json().await.unwrap();
    assert_eq!(d["item"]["details"]["overview"], "A pianist and an actress fall in love in Los Angeles.");
    assert_eq!(d["item"]["details"]["cast"][0]["name"], "Ryan Gosling");
    assert_eq!(d["item"]["genres"], json!(["Drama"]));
    assert_eq!(d["item"]["poster"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seasons_written_into_the_title_join_one_show() {
    let n = node("seasons").await;
    for (i, name) in ["[Grp] Youjo Senki - 01 [1080p].mkv", "[Grp] Youjo Senki - 02 [1080p].mkv", "[Grp] Youjo Senki S2 - 01 [1080p].mkv"].iter().enumerate() {
        add_video(&n, name, &fake_video(1_200_000, &format!("ys{i}")), true);
    }
    // a file stored the old way, with the season in its title
    let old = add_video(&n, "[Grp] Youjo Senki S2 - 02 [1080p].mkv", &fake_video(1_200_000, "ys9"), true);
    n.app.db.with(|c| { c.execute("UPDATE items SET title='Youjo Senki S2', season=NULL WHERE id=?1", [&old])?; Ok(()) }).unwrap();
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let lib: Value = api_get(&n.access_url, "/api/library", &cookie).await.json().await.unwrap();
    let items = lib["items"].as_array().unwrap();
    assert_eq!(items.len(), 4);
    assert!(items.iter().all(|i| i["title"] == "Youjo Senki" && i["group"] == items[0]["group"]), "{items:?}");
    let s2 = items.iter().filter(|i| i["season"] == 2).count();
    assert_eq!(s2, 2, "both season-two episodes carry season 2: {items:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_can_switch_between_shared_and_dedicated_and_the_limits_follow() {
    let n = node("perf").await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let http = reqwest::Client::new();
    let d: Value = api_get(&n.access_url, "/api/perf", &cookie).await.json().await.unwrap();
    assert_eq!(d["dedicated"], false);
    assert_eq!(d["tuning"]["scan_parallel"], 1);
    assert_eq!(d["tuning"]["streams"], 3, "shared keeps the owner's own number");
    assert!(d["hardware"]["cores"].as_u64().unwrap() >= 1 && d["hardware"]["ram_mb"].as_u64().unwrap() > 0);
    let r = http.put(format!("{}/api/perf", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"dedicated": true})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let d: Value = api_get(&n.access_url, "/api/perf", &cookie).await.json().await.unwrap();
    assert_eq!(d["dedicated"], true);
    assert_eq!(d["tuning"]["dedicated"], true);
    assert!(n.app.streams() >= 2);
    // the choice is remembered with the node's data
    assert_eq!(n.app.db.get_setting("perf_mode").unwrap().as_deref(), Some("dedicated"));
    // and back
    n.app.set_perf_dedicated(false).unwrap();
    assert_eq!(n.app.streams(), 3);
}

/// Seasons that have their own names join one show, but a different series with a similar name stays separate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seasons_with_their_own_names_join_one_show_but_other_series_stay_apart() {
    use axum::{extract::Query, routing::get, routing::post, Json};
    use std::collections::HashMap;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    // AniList: ids 1..4 are DxD seasons (each lists the earlier one as its prequel); 10 is Beyblade, 20 is Metal Fusion (an alternate version, not a sequel)
    let media = |id: i64| -> serde_json::Value {
        let (title, mal, prev, rel): (&str, i64, i64, &str) = match id {
            1 => ("Highschool DxD", 11617, 0, ""),
            2 => ("Highschool DxD New", 15451, 1, "PREQUEL"),
            3 => ("Highschool DxD BorN", 20000, 2, "PREQUEL"),
            4 => ("Highschool DxD Hero", 30000, 3, "PREQUEL"),
            10 => ("Bakuten Shoot Beyblade", 200, 0, ""),
            _ => ("Beyblade: Metal Fusion", 300, 10, "ALTERNATIVE"),
        };
        let edges = if prev == 0 { json!([]) } else { json!([{ "relationType": rel, "node": { "id": prev, "type": "ANIME", "format": "TV", "title": { "romaji": "x" } } }]) };
        json!({ "id": id, "idMal": mal, "format": "TV", "title": { "romaji": title, "english": title }, "relations": { "edges": edges } })
    };
    let srv = axum::Router::new()
        .route("/anime", get(|Query(q): Query<HashMap<String, String>>| async move {
            let n = q.get("q").cloned().unwrap_or_default().to_lowercase();
            let (mal, t) = if n.contains("hero") { (30000, "Highschool DxD Hero") } else if n.contains("dxd") { (11617, "Highschool DxD") } else if n.contains("metal") { (300, "Beyblade: Metal Fusion") } else if n.contains("beyblade") { (200, "Bakuten Shoot Beyblade") } else { return Json(json!({"data": []})) };
            Json(json!({"data":[{"mal_id":mal,"title":t,"title_english":t,"title_synonyms":["Beyblade"],"type":"TV","episodes":1,"synopsis":"s","genres":[],"themes":[],"score":7.0,"year":2012}]}))
        }))
        .route("/anime/:id/characters", get(|| async { Json(json!({"data":[]})) }))
        .route("/anime/:id/episodes", get(|| async { Json(json!({"data":[],"pagination":{"has_next_page":false}})) }))
        .route("/graphql", post(move |Json(b): Json<serde_json::Value>| { let media = media.clone(); async move {
            let q = b["query"].as_str().unwrap_or("");
            let id = b["variables"]["id"].as_i64().unwrap_or(0);
            let al = if q.contains("idMal:") { match id { 11617 => 1, 30000 => 4, 200 => 10, 300 => 20, _ => 0 } } else { id };
            Json(json!({"data": {"Media": media(al)}}))
        } }));
    tokio::spawn(async move { axum::serve(l, srv).await.unwrap() });
    let n = node_with("franchise", |c| {
        c.metadata.jikan = base.clone();
        c.metadata.tvmaze = base.clone();
        c.metadata.anilist = format!("{base}/graphql");
    })
    .await;
    let a = add_video(&n, "[Grp] Highschool DxD - 01 [1080p].mkv", &fake_video(1_200_000, "d1"), true);
    let b = add_video(&n, "[Grp] Highschool DxD Hero - 01 [1080p].mkv", &fake_video(1_200_000, "d4"), true);
    let c1 = add_video(&n, "[Grp] Beyblade - 01 [1080p].mkv", &fake_video(1_200_000, "b1"), true);
    let c2 = add_video(&n, "[Grp] Beyblade Metal Fusion - 01 [1080p].mkv", &fake_video(1_200_000, "b2"), true);
    for id in [&a, &b, &c1, &c2] {
        let it = n.app.db.with(|c| db::get_item(c, id)).unwrap().unwrap();
        // anime-looking names are filed as anime by the parser; make sure the lookup goes to the anime sources
        let key = syphon::metadata::key_of(&it);
        assert!(syphon::metadata::fetch_and_store_titles(&n.app, &key, &syphon::metadata::lookup_titles(&it), "anime", it.year).await.unwrap_or_else(|e| panic!("{}: {e:#} {:?}", it.title, syphon::metadata::lookup_titles(&it))), "{}", it.title);
    }
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let lib: Value = api_get(&n.access_url, "/api/library", &cookie).await.json().await.unwrap();
    let items = lib["items"].as_array().unwrap();
    let get = |id: &str| items.iter().find(|i| i["id"] == id).cloned().unwrap();
    let (ia, ib, ic1, ic2) = (get(&a), get(&b), get(&c1), get(&c2));
    assert_eq!(ia["group"], ib["group"], "{ia} {ib}");
    assert_eq!(ib["title"], "Highschool DxD");
    assert_eq!(ib["season"], 4, "the fourth season, although its name does not say so");
    assert_ne!(ic1["group"], ic2["group"], "an alternate version is a different show: {ic1} {ic2}");
}

#[test]
fn second_halves_do_not_count_as_new_seasons() {
    use syphon::metadata::{is_second_cour, number_chain};
    assert!(is_second_cour("Re:Zero 2nd Season Part 2") && is_second_cour("Show Cour 2") && !is_second_cour("Show 2nd Season"));
    let chain: Vec<(String, String, i64)> = [("TV", "A", 1), ("MOVIE", "A Movie", 2), ("TV", "A 2nd Season", 3), ("TV", "A 2nd Season Part 2", 4), ("TV", "A 3rd Season", 5)]
        .iter().map(|(f, t, i)| (f.to_string(), t.to_string(), *i)).collect();
    let (root, nums) = number_chain(&chain);
    assert_eq!(root, 0);
    assert_eq!(nums, vec![Some(1), None, Some(2), Some(2), Some(3)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn videos_go_to_the_drive_chosen_stay_playable_and_can_be_moved_off() {
    let n = node("drives").await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let http = reqwest::Client::new();
    let extra = tempfile::tempdir().unwrap();
    let disk2 = extra.path().join("disk2");
    std::fs::create_dir_all(&disk2).unwrap();
    let call = |method: reqwest::Method, path: String, body: Value| {
        let (http, base, cookie) = (http.clone(), n.access_url.clone(), cookie.clone());
        async move { http.request(method, format!("{base}{path}")).header("cookie", &cookie).header("x-requested-with", "syphon").json(&body).send().await.unwrap() }
    };
    // dangerous places are refused
    let r = call(reqwest::Method::POST, "/api/storage/volumes".into(), json!({"path": "/etc", "label": "bad"})).await;
    assert_eq!(r.status(), 400);
    let r = call(reqwest::Method::POST, "/api/storage/volumes".into(), json!({"path": disk2.to_str().unwrap(), "label": "Disk two", "reserve_gb": 0})).await;
    assert_eq!(r.status(), 200, "{:?}", r.text().await);
    // only the new drive takes new videos
    let r = call(reqwest::Method::PUT, "/api/storage".into(), json!({"system_enabled": false})).await;
    assert_eq!(r.status(), 200);
    let id = add_video(&n, "On.Disk.Two.2020.mp4", &fake_video(1_300_000, "dd1"), true);
    assert!(disk2.join("library").join(format!("{id}.enc")).exists(), "the file was placed on the chosen drive");
    assert!(!n.app.dirs.library().join(format!("{id}.enc")).exists());
    // and it plays from there
    let r = api_get(&n.access_url, &format!("/api/stream/{id}"), &cookie).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().len(), 1_300_000);
    // the view reports it
    let v: Value = api_get(&n.access_url, "/api/storage", &cookie).await.json().await.unwrap();
    assert_eq!(v["volumes"][0]["files"], 1);
    assert_eq!(v["volumes"][0]["status"]["writable"], true);
    // a drive with files will not just be removed
    let vid = v["volumes"][0]["volume"]["id"].as_str().unwrap().to_string();
    let r = call(reqwest::Method::DELETE, format!("/api/storage/volumes/{vid}"), json!({})).await;
    assert_eq!(r.status(), 409);
    // move everything off it, then remove it
    let r = call(reqwest::Method::PUT, "/api/storage".into(), json!({"system_enabled": true})).await;
    assert_eq!(r.status(), 200);
    let r = call(reqwest::Method::POST, format!("/api/storage/volumes/{vid}/drain"), json!({})).await;
    assert_eq!(r.status(), 200);
    for _ in 0..50 {
        let v: Value = api_get(&n.access_url, "/api/storage", &cookie).await.json().await.unwrap();
        if v["volumes"][0]["drain"]["running"] == false {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(n.app.dirs.library().join(format!("{id}.enc")).exists(), "moved to the system drive");
    assert!(!disk2.join("library").join(format!("{id}.enc")).exists());
    let r = api_get(&n.access_url, &format!("/api/stream/{id}"), &cookie).await;
    assert_eq!(r.bytes().await.unwrap().len(), 1_300_000);
    let r = call(reqwest::Method::DELETE, format!("/api/storage/volumes/{vid}"), json!({})).await;
    assert_eq!(r.status(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drive_without_room_is_not_used_and_the_reserve_is_kept() {
    let n = node("reserve").await;
    // a reserve larger than the disk means "no room anywhere"
    let mut sc = syphon::storage::cfg(&n.app);
    sc.system_reserve_gb = Some(100_000);
    syphon::storage::save(&n.app, sc).unwrap();
    assert!(n.app.disk_ok(1000).is_err());
    let mut sc = syphon::storage::cfg(&n.app);
    sc.system_reserve_gb = Some(0);
    syphon::storage::save(&n.app, sc).unwrap();
    assert!(n.app.disk_ok(1000).is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_can_set_extra_lock_keys_and_turn_the_lock_off() {
    let n = node("lock").await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let v: Value = api_get(&n.access_url, "/api/access-keys", &cookie).await.json().await.unwrap();
    assert_eq!(v["active"], false);
    let dir = n.app.dirs.tor().join("hs_access").join("authorized_clients");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("phone.auth"), "descriptor:x25519:AAAA\n").unwrap();
    std::fs::write(dir.join("laptop.auth"), "descriptor:x25519:BBBB\n").unwrap();
    let v: Value = api_get(&n.access_url, "/api/access-keys", &cookie).await.json().await.unwrap();
    assert_eq!(v["active"], true);
    assert_eq!(v["keys"].as_array().unwrap().len(), 2);
    let http = reqwest::Client::new();
    let r = http.delete(format!("{}/api/access-keys/phone", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = http.delete(format!("{}/api/access-keys", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = api_get(&n.access_url, "/api/access-keys", &cookie).await.json().await.unwrap();
    assert_eq!(v["active"], false, "the lock is off again");
}

/// MKV with HEVC or 10-bit video: the browser would play the sound only. The node says so and converts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matroska_with_video_a_browser_cannot_show_is_converted_and_gets_a_preview_picture() {
    if std::process::Command::new("ffmpeg").arg("-version").output().is_err() {
        eprintln!("ffmpeg not installed: skipping");
        return;
    }
    let n = node_with("mkv", |c| {
        c.ffprobe = "ffprobe".into();
        c.scan.decode = false;
    })
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let make = |name: &str, vcodec: &[&str]| {
        let p = tmp.path().join(name);
        let ok = std::process::Command::new("ffmpeg")
            .args(["-v", "error", "-f", "lavfi", "-i", "testsrc=duration=3:size=320x240:rate=15", "-f", "lavfi", "-i", "sine=frequency=440:duration=3"])
            .args(vcodec)
            .args(["-c:a", "aac", "-shortest"])
            .arg(&p)
            .status()
            .unwrap()
            .success();
        assert!(ok, "could not make {name}");
        p
    };
    let hevc = make("Hevc.Test.2020.mkv", &["-c:v", "libx265", "-pix_fmt", "yuv420p10le", "-x265-params", "log-level=none"]);
    let h264 = make("H264.Test.2020.mkv", &["-c:v", "libx264", "-pix_fmt", "yuv420p"]);
    let mut ids = vec![];
    for p in [&hevc, &h264] {
        let ing = library::import_path(&n.app, p, "import").await.unwrap();
        library::approve(&n.app, &ing.id, true).unwrap();
        ids.push(ing.id);
    }
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let pb = |i: usize| { let (u, c, id) = (n.access_url.clone(), cookie.clone(), ids[i].clone()); async move { api_get(&u, &format!("/api/items/{id}/playback"), &c).await.json::<Value>().await.unwrap() } };
    let a = pb(0).await;
    assert_eq!(a["playback"]["mode"], "transcode", "{a}");
    assert_eq!(a["playback"]["vcodec"], "hevc");
    let b = pb(1).await;
    assert_eq!(b["playback"]["mode"], "remux", "{b}");

    let probe = |bytes: &[u8]| {
        let f = tmp.path().join(format!("out-{}.mp4", bytes.len()));
        std::fs::write(&f, bytes).unwrap();
        let o = std::process::Command::new("ffprobe").args(["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=codec_name,pix_fmt", "-of", "csv=p=0"]).arg(&f).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    };
    // same picture, new wrapper
    let r = api_get(&n.access_url, &format!("/api/stream/{}?mode=remux&audio_ok=true", ids[1]), &cookie).await;
    assert_eq!(r.status(), 200);
    assert_eq!(probe(&r.bytes().await.unwrap()), "h264,yuv420p");
    // new picture, at the quality asked for
    let r = api_get(&n.access_url, &format!("/api/stream/{}?mode=transcode&q=high&codec=h264", ids[0]), &cookie).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-syphon-transcode"], "high");
    assert_eq!(r.headers()["x-syphon-codec"], "h264");
    assert_eq!(probe(&r.bytes().await.unwrap()), "h264,yuv420p", "10-bit HEVC becomes 8-bit H.264 for a browser that cannot show AV1");
    // by default conversions are AV1 (when this ffmpeg can make it)
    let r = api_get(&n.access_url, &format!("/api/stream/{}?mode=transcode&q=low", ids[0]), &cookie).await;
    assert_eq!(r.status(), 200);
    let want = if library::av1_encoder(&n.app).is_some() { "av1" } else { "h264" };
    assert_eq!(r.headers()["x-syphon-codec"], want);
    let got = probe(&r.bytes().await.unwrap());
    assert_eq!(got, format!("{want},yuv420p"));
    // the owner can choose H.264 for the whole node
    let http = reqwest::Client::new();
    let r = http.put(format!("{}/api/playback", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"codec": "h264"})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = api_get(&n.access_url, &format!("/api/stream/{}?mode=transcode&q=low", ids[0]), &cookie).await;
    assert_eq!(r.headers()["x-syphon-codec"], "h264");
    let r = http.put(format!("{}/api/playback", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"codec": "av1"})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    // the owner sets the node's quality; viewers get the list
    let http = reqwest::Client::new();
    let r = http.put(format!("{}/api/playback", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"quality": "high"})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let q: Value = api_get(&n.access_url, "/api/playback", &cookie).await.json().await.unwrap();
    assert_eq!(q["quality"], "high");
    assert_eq!(q["qualities"].as_array().unwrap().len(), 5);
    let r = http.put(format!("{}/api/playback", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"quality": "nonsense"})).send().await.unwrap();
    assert_eq!(r.status(), 400);
    // preview picture: a JPEG, made once and kept encrypted
    let r = api_get(&n.access_url, &format!("/api/frame/{}", ids[0]), &cookie).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "image/jpeg");
    let jpg = r.bytes().await.unwrap();
    assert_eq!(&jpg[..2], &[0xFF, 0xD8]);
    let again = api_get(&n.access_url, &format!("/api/frame/{}", ids[0]), &cookie).await.bytes().await.unwrap();
    assert_eq!(jpg, again);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_node_rests_and_the_first_real_request_wakes_it() {
    let n = node_with("rest", |_| {}).await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let http = reqwest::Client::new();
    // the owner turns it on and sets the idle time; the setting shows in the performance panel
    let r = http.put(format!("{}/api/perf", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"rest_mode": "on", "rest_idle_min": 3})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = http.put(format!("{}/api/perf", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({"rest_mode": "sometimes"})).send().await.unwrap();
    assert_eq!(r.status(), 400);
    let p: Value = api_get(&n.access_url, "/api/perf", &cookie).await.json().await.unwrap();
    assert_eq!(p["rest"]["mode"], "on");
    assert_eq!(p["rest"]["idle_min"], 3);
    assert_eq!(p["rest"]["resting"], false);

    syphon::rest::enter(&n.app);
    assert!(syphon::rest::is_resting(&n.app));
    // a tab polling in the background does not count as use
    let _ = api_get(&n.access_url, "/api/status", &cookie).await;
    assert!(syphon::rest::is_resting(&n.app), "polling must not wake the node");
    // a loop waiting while the node rests comes back the moment someone uses it
    let app = n.app.clone();
    let waiter = tokio::spawn(async move {
        let t = std::time::Instant::now();
        syphon::rest::sleep(&app, std::time::Duration::from_secs(10)).await;
        t.elapsed()
    });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let _ = api_get(&n.access_url, "/api/library", &cookie).await;
    let waited = tokio::time::timeout(std::time::Duration::from_secs(5), waiter).await.expect("woke up").unwrap();
    assert!(waited < std::time::Duration::from_secs(3), "{waited:?}");
    assert!(!syphon::rest::is_resting(&n.app));
}

/// A browser can fetch most of a film in the first minutes and then play it for hours without asking again. While the
/// response is still open somebody is watching, so rest mode must not start; when they leave it may.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_mode_never_starts_while_a_video_is_still_being_sent() {
    use std::sync::atomic::Ordering;
    let n = node_with("watching", |_| {}).await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let data = fake_video(40_000_000, "watch");
    let id = add_video(&n, "Long.Movie.2001.mp4", &data, true);
    assert_eq!(n.app.active_streams.load(Ordering::Relaxed), 0);
    assert!(!syphon::rest::busy(&n.app));
    let r = reqwest::Client::new().get(format!("{}/api/stream/{id}", n.access_url)).header("cookie", &cookie).send().await.unwrap();
    assert_eq!(r.status(), 200);
    // the headers are here, the body has not been read: the viewer is mid-film
    assert_eq!(n.app.active_streams.load(Ordering::Relaxed), 1);
    assert!(syphon::rest::busy(&n.app), "an open video must keep the computer awake");
    drop(r);
    for _ in 0..50 {
        if n.app.active_streams.load(Ordering::Relaxed) == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(n.app.active_streams.load(Ordering::Relaxed), 0, "leaving ends it");
    assert!(!syphon::rest::busy(&n.app));
}

/// Tor dying, or being told to restart, never leaves the node without Tor: it comes back by itself, with the same keys.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_is_restarted_by_itself_and_on_request() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::Ordering;
    let d = tempfile::tempdir().unwrap();
    let pidf = d.path().join("pid");
    let script = d.path().join("faketor");
    std::fs::write(
        &script,
        format!("#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo \"Tor version 0.4.9.11.\"; exit 0; fi\necho $$ > \"{}\"\necho \"Bootstrapped 100% (done): Done\"\nexec sleep 3600\n", pidf.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = script.to_string_lossy().to_string();
    let n = node_with("torheal", |c| {
        c.transport = "tor".into();
        c.tor.binary = bin.clone();
    })
    .await;
    let pid = || std::fs::read_to_string(&pidf).unwrap_or_default().trim().to_string();
    let until = |what: &'static str, f: Box<dyn Fn() -> bool>| async move {
        for _ in 0..200 {
            if f() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("timed out waiting for: {what}");
    };
    syphon::tor::start(&n.app).await.unwrap();
    let a = n.app.clone();
    until("tor connected", Box::new(move || a.tor.lock().unwrap().bootstrap == 100)).await;
    let first = pid();
    assert!(!first.is_empty());

    // 1. it dies: it comes back, and the page can say so
    let _ = std::process::Command::new("kill").args(["-9", &first]).status();
    let (a, old, pf) = (n.app.clone(), first.clone(), pidf.clone());
    until("restart after a crash", Box::new(move || a.tor.lock().unwrap().restarts == 1 && a.tor.lock().unwrap().bootstrap == 100 && std::fs::read_to_string(&pf).map(|p| p.trim() != old).unwrap_or(false))).await;
    let second = pid();
    assert_ne!(first, second);
    let why = n.app.tor.lock().unwrap().last_restart_reason.clone().unwrap();
    assert!(why.contains("stopped by itself"), "{why}");

    // 2. the Restart Tor button
    syphon::tor::restart_now(&n.app);
    let (a, old, pf) = (n.app.clone(), second.clone(), pidf.clone());
    until("restart on request", Box::new(move || a.tor.lock().unwrap().restarts == 2 && a.tor.lock().unwrap().bootstrap == 100 && std::fs::read_to_string(&pf).map(|p| p.trim() != old).unwrap_or(false))).await;
    assert!(n.app.tor.lock().unwrap().last_restart_reason.clone().unwrap().contains("Settings"));
    let third = pid();

    // 3. a node that is shutting down does not bring Tor back
    n.app.shutting_down.store(true, Ordering::SeqCst);
    n.app.shutdown.notify_waiters();
    let _ = std::process::Command::new("kill").args(["-9", &third]).status();
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    assert_eq!(n.app.tor.lock().unwrap().restarts, 2, "no restart during shutdown");
    assert_eq!(pid(), third);
}

/// The player says "someone is watching" now and then; that keeps a resting node awake even when no video bytes are moving
/// (the film is buffered, or paused for a little while).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_player_saying_someone_is_watching_keeps_the_node_awake() {
    let n = node_with("presence", |_| {}).await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let http = reqwest::Client::new();
    syphon::rest::enter(&n.app);
    assert!(syphon::rest::is_resting(&n.app));
    let r = http.post(format!("{}/api/presence", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").json(&json!({})).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(!syphon::rest::is_resting(&n.app), "someone is watching, so the node is awake");
    // the call itself needs a signed-in viewer
    let r = http.post(format!("{}/api/presence", n.access_url)).header("x-requested-with", "syphon").json(&json!({})).send().await.unwrap();
    assert!(r.status().as_u16() == 401 || r.status().as_u16() == 403, "{}", r.status());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_library_key_survives_an_update_restart_only_when_armed_and_fresh() {
    use std::os::unix::fs::PermissionsExt;
    let n = node_with("handoff", |_| {}).await;
    assert!(n.app.keyring.is_unlocked(), "the test node starts unlocked");
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

    // nothing armed: a normal shutdown leaves no key behind
    assert!(!syphon::handoff::save_to(&n.app, dir.path()));
    assert!(!dir.path().join("key").exists());

    // the helper arms it right before the restart: the key is left (private) and the arm file is used up
    std::fs::write(dir.path().join("arm"), "").unwrap();
    assert!(syphon::handoff::save_to(&n.app, dir.path()));
    assert!(!dir.path().join("arm").exists());
    let mode = std::fs::metadata(dir.path().join("key")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // the next start unlocks with it and removes it
    n.app.keyring.lock();
    assert!(!n.app.keyring.is_unlocked());
    assert!(syphon::handoff::restore_from(&n.app, dir.path()));
    assert!(n.app.keyring.is_unlocked());
    assert!(!dir.path().join("key").exists(), "the key is deleted once used");

    // a key left over from long ago is ignored and removed
    std::fs::write(dir.path().join("arm"), "").unwrap();
    assert!(syphon::handoff::save_to(&n.app, dir.path()));
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    std::fs::File::options().write(true).open(dir.path().join("key")).unwrap().set_modified(old).unwrap();
    n.app.keyring.lock();
    assert!(!syphon::handoff::restore_from(&n.app, dir.path()));
    assert!(!n.app.keyring.is_unlocked());
    assert!(!dir.path().join("key").exists());

    // a key file anyone else could read is ignored
    std::fs::write(dir.path().join("arm"), "").unwrap();
    n.app.keyring.unlock(PW).unwrap();
    assert!(syphon::handoff::save_to(&n.app, dir.path()));
    std::fs::set_permissions(dir.path().join("key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    n.app.keyring.lock();
    assert!(!syphon::handoff::restore_from(&n.app, dir.path()));
    assert!(!n.app.keyring.is_unlocked());

    // a key that does not belong to this library is refused
    std::fs::write(dir.path().join("key"), "ab".repeat(32)).unwrap();
    std::fs::set_permissions(dir.path().join("key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!syphon::handoff::restore_from(&n.app, dir.path()));
    assert!(!n.app.keyring.is_unlocked());

    // a locked node has nothing to leave
    std::fs::write(dir.path().join("arm"), "").unwrap();
    assert!(!syphon::handoff::save_to(&n.app, dir.path()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_snapshot_taken_before_an_update_is_a_complete_usable_copy() {
    let n = node_with("snapshot", |_| {}).await;
    n.app.db.set_setting("marker", "before-update").unwrap();
    let to = tempfile::tempdir().unwrap();
    let files = syphon::lifecycle::snapshot(&n.app.dirs.root, to.path()).unwrap();
    assert!(files >= 2, "database plus the key and identity files");
    assert!(to.path().join("keyring.json").exists());
    let c = rusqlite::Connection::open(to.path().join("syphon.db")).unwrap();
    let v: String = c.query_row("SELECT v FROM settings WHERE k='marker'", [], |r| r.get(0)).unwrap();
    assert_eq!(v, "before-update");
    let ok: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(ok, "ok");
    // the running node is not disturbed
    n.app.db.set_setting("marker", "after").unwrap();
    assert_eq!(n.app.db.get_setting("marker").unwrap().as_deref(), Some("after"));
}

/// What is typed is matched against what is shown, the stored title and the stored file name; the file name is the
/// shown title; sending a video that is in the trash brings it back; and the periodic check reports what is wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_finds_what_is_displayed_names_are_tidy_the_trash_is_reversible_and_the_check_reports() {
    let n = node("tidy").await;
    let spider = add_video(&n, "Spider-Man.No.Way.Home.2021.1080p.BluRay.x264-GRP.mkv", &fake_video(900_000, "sp"), true);
    let old = add_video(&n, "[Grp] Youjo Senki S2 - 02 [1080p].mkv", &fake_video(900_000, "ys"), true);
    n.app.db.with(|c| { c.execute("UPDATE items SET title='Youjo Senki S2', season=NULL WHERE id=?1", [&old])?; Ok(()) }).unwrap();
    syphon::library::tidy_all(&n.app);
    let name_of = |id: &str| n.app.db.with(|c| db::get_item(c, id)).unwrap().unwrap().filename.unwrap();
    let f = name_of(&spider);
    assert!(f.ends_with(".mkv") && !f.contains("1080p") && !f.contains("GRP") && f.contains("(2021)"), "{f}");
    assert!(f.starts_with(&n.app.db.with(|c| db::get_item(c, &spider)).unwrap().unwrap().title), "the stored name starts with the shown title: {f}");

    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let find = |q: &str| {
        let url = format!("/api/library?q={}", q.replace(' ', "%20"));
        let cookie = cookie.clone();
        let base = n.access_url.clone();
        async move { api_get(&base, &url, &cookie).await.json::<Value>().await.unwrap()["items"].as_array().unwrap().len() }
    };
    assert_eq!(find("spiderman no way home").await, 1, "punctuation does not matter");
    assert_eq!(find("SPIDER-MAN").await, 1);
    assert_eq!(find("youjo senki").await, 1, "the shown title");
    assert_eq!(find("youjo senki s2").await, 1, "the stored title");
    assert_eq!(find("batman").await, 0);

    // delete, then send the same video again: it comes back instead of being silently called a duplicate
    let data = fake_video(900_000, "sp");
    library::delete_item(&n.app, &spider).unwrap();
    assert_eq!(find("spider").await, 0, "a trashed video is not on the shelf");
    let mut s = IngestSession::begin(&n.app, "Spider-Man.No.Way.Home.2021.mkv", "upload").unwrap();
    for c in data.chunks(300_000) { s.push(c).unwrap(); }
    let ing = s.finish(&n.app).unwrap();
    assert!(ing.restored && ing.id == spider);
    assert!(!n.app.db.with(|c| db::get_item(c, &spider)).unwrap().unwrap().deleted);
    assert_eq!(find("spider").await, 1);
    // the trash view can put back and empty
    library::delete_item(&n.app, &spider).unwrap();
    let t: Value = api_get(&n.access_url, "/api/trash", &cookie).await.json().await.unwrap();
    assert_eq!(t["items"].as_array().unwrap().len(), 1);
    let http = reqwest::Client::new();
    let r = http.delete(format!("{}/api/trash", n.access_url)).header("cookie", &cookie).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(local_state(&n, &spider).as_deref(), Some("absent"));

    // the periodic check
    let rep = syphon::sanity::check(&n.app).expect("ran");
    assert_eq!(rep["ok"], true, "{rep}");
    std::fs::remove_file(library::library_path(&n.app, &old)).unwrap();
    let rep = syphon::sanity::check(&n.app).unwrap();
    assert_eq!(rep["ok"], false);
    assert!(rep["issues"][0].as_str().unwrap().contains("missing"), "{rep}");
    assert_eq!(syphon::sanity::last(&n.app).unwrap()["at"], rep["at"]);
    let s: Value = api_get(&n.access_url, "/api/perf", &cookie).await.json().await.unwrap();
    assert_eq!(s["sanity"]["every_hours"], 6, "it runs every six hours");
}

/// Routine traffic from other nodes must not keep a node awake, a forgotten upload must not hold it for hours, and
/// the owner can see what is holding it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_routine_keeps_the_node_awake_and_the_owner_can_see_what_does() {
    let n = node("why").await;
    assert!(syphon::rest::busy_reason(&n.app).is_none());
    // a forgotten upload (untouched for an hour) is not "someone is uploading"
    let up = syphon::library::Upload {
        user: "owner".into(), name: "x.mp4".into(), kind: "movie".into(), size: 10,
        received: Default::default(), touched: std::sync::atomic::AtomicI64::new(syphon::util::now() - 3600),
        takeover: Default::default(), session: tokio::sync::Mutex::new(None),
    };
    n.app.uploads.lock().unwrap().insert("old".into(), std::sync::Arc::new(up));
    assert!(syphon::rest::busy_reason(&n.app).is_none(), "an hour-old upload does not hold the node awake");
    n.app.uploads.lock().unwrap().values().for_each(|u| u.touched.store(syphon::util::now(), std::sync::atomic::Ordering::Relaxed));
    assert_eq!(syphon::rest::busy_reason(&n.app).as_deref(), Some("an upload is in progress"));
    n.app.uploads.lock().unwrap().clear();
    // the last real use is remembered and shown
    syphon::rest::touch_for(&n.app, "web: GET /api/library");
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let p: Value = api_get(&n.access_url, "/api/perf", &cookie).await.json().await.unwrap();
    assert!(p["rest"]["activity"]["last_use"].as_str().unwrap().starts_with("web: "), "{p}");
}


/// Privacy: a visitor who does not sign in gets no cookie, every page forbids outside sites, and the page's own files
/// never name one (no web fonts, no scripts from elsewhere).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_site_sets_no_cookie_without_a_sign_in_and_never_names_an_outside_site() {
    let n = node_with("privacy", |_| {}).await;
    let http = reqwest::Client::new();
    for path in ["/", "/app.js", "/app.css", "/tv.js", "/tv.css", "/theme.js", "/favicon.svg", "/api/status"] {
        let r = http.get(format!("{}{}", n.access_url, path)).send().await.unwrap();
        assert!(!r.headers().contains_key("set-cookie"), "{path} must not set a cookie");
        let csp = r.headers()["content-security-policy"].to_str().unwrap().to_string();
        assert!(csp.contains("default-src 'none'") && csp.contains("connect-src 'self'") && !csp.contains("http"), "{path}: {csp}");
    }
    for f in ["index.html", "app.js", "app.css", "tv.js", "tv.css", "theme.js"] {
        let t = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui").join(f)).unwrap();
        for (i, line) in t.lines().enumerate() {
            for m in line.match_indices("http") {
                let rest = &line[m.0..];
                let allowed = rest.starts_with("http://www.w3.org/") || rest.starts_with("http://192.168.") || rest.starts_with("https://") && line.contains("placeholder");
                assert!(!(rest.starts_with("http://") || rest.starts_with("https://")) || allowed, "{f}:{} names an outside address: {line}", i + 1);
            }
        }
    }
}

/// "Who's watching?": a device told to remember someone signs them in without the password; one that was not told, a
/// wrong device, or a removed device cannot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remembered_device_signs_in_without_the_password_until_it_is_removed() {
    let n = node_with("remember", |_| {}).await;
    let first = login_at(&n.access_url, "owner", PW, "").await;
    let cookies = cookies_of(&first);
    let dev = cookies.split("; ").find(|c| c.starts_with("syphon_dev=")).unwrap().to_string();
    let quick = |cookie: String| {
        let base = n.access_url.clone();
        async move { reqwest::Client::new().post(format!("{base}/api/login/remembered")).header("cookie", cookie).json(&json!({"user": "owner"})).send().await.unwrap() }
    };
    // trusted but not remembered: no
    assert_eq!(quick(dev.clone()).await.status(), 401);
    assert_eq!(api_post(&n.access_url, "/api/devices/current/remember", &cookies, json!({"remember": true})).await.status(), 200);
    let r = quick(dev.clone()).await;
    assert_eq!(r.status(), 200);
    let session = cookies_of(&r);
    assert!(session.starts_with("syphon=") && !session.contains("syphon_dev"));
    let me: Value = reqwest::Client::new().get(format!("{}/api/me", n.access_url)).header("cookie", &session).send().await.unwrap().json().await.unwrap();
    assert_eq!(me["user"], "owner");
    // someone else's name, or a made-up device: no
    let other = reqwest::Client::new().post(format!("{}/api/login/remembered", n.access_url)).header("cookie", dev.clone()).json(&json!({"user": "nobody"})).send().await.unwrap();
    assert_eq!(other.status(), 401);
    assert_eq!(quick("syphon_dev=aaaa.bbbb".into()).await.status(), 401);
    // the device list says so, and removing the device ends it
    let list: Value = reqwest::Client::new().get(format!("{}/api/my/devices", n.access_url)).header("cookie", &cookies).send().await.unwrap().json().await.unwrap();
    let d = list["devices"].as_array().unwrap().iter().find(|d| d["remember"] == true).expect("marked as remembered").clone();
    let del = reqwest::Client::new().delete(format!("{}/api/my/devices/{}", n.access_url, d["id"].as_str().unwrap())).header("cookie", &cookies).header("x-requested-with", "syphon").send().await.unwrap();
    assert_eq!(del.status(), 200);
    assert_eq!(quick(dev).await.status(), 401);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_app_finds_the_node_on_the_home_network() {
    let n = node_with("findme", |c| c.access_bind = "0.0.0.0:0".into()).await;
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    drop(server);
    tokio::spawn(syphon::discovery::run(n.app.clone(), port));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut buf = [0u8; 512];
    sock.send_to(b"hello", ("127.0.0.1", port)).await.unwrap();
    sock.send_to(syphon::discovery::ASK, ("127.0.0.1", port)).await.unwrap();
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await.expect("an answer").unwrap();
    let v: Value = serde_json::from_slice(&buf[..len]).unwrap();
    assert_eq!(v["syphon"], 1);
    assert_eq!(v["name"], "findme");
    assert!(v["port"].as_u64().is_some());
}


/// Visitors through the owner's VPN box come from outside, though the box sits at home; and Tor access from outside
/// can be switched off without touching anything else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vpn_box_visitors_are_outside_and_tor_access_can_be_switched_off() {
    let n = node("outside").await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let d: Value = api_get(&n.access_url, "/api/outside", &cookie).await.json().await.unwrap();
    assert_eq!((d["vpn_boxes"].as_array().unwrap().len(), d["tor_access"].as_bool()), (0, Some(true)));
    // only home-network addresses, and not the owner's own device
    for bad in ["8.8.8.8", "not an address", "127.0.0.1"] {
        assert_eq!(api_post(&n.access_url, "/api/outside", &cookie, json!({"vpn_boxes": [bad]})).await.status(), 400, "{bad}");
    }
    assert!(api_post(&n.access_url, "/api/outside", &cookie, json!({"vpn_boxes": ["192.168.1.30", " 192.168.1.30 "]})).await.status().is_success());
    let d: Value = api_get(&n.access_url, "/api/outside", &cookie).await.json().await.unwrap();
    assert_eq!(d["vpn_boxes"], json!(["192.168.1.30"]));
    assert_eq!(n.app.db.get_setting("vpn_boxes").unwrap().as_deref(), Some("192.168.1.30"), "kept across restarts");
    // nobody from outside may change it
    assert!(!api_post(&n.remote_url, "/api/outside", &cookie, json!({"vpn_boxes": []})).await.status().is_success());

    // a box at 127.0.0.2 (a stand-in: the real one has a home-network address)
    syphon::security::set_vpn_boxes(vec!["127.0.0.2".parse().unwrap()]);
    let via_box = reqwest::Client::builder().local_address(Some("127.0.0.2".parse().unwrap())).build().unwrap();
    let st: Value = via_box.get(format!("{}/api/status", n.access_url)).send().await.unwrap().json().await.unwrap();
    let home: Value = api_get(&n.access_url, "/api/status", "").await.json().await.unwrap();
    assert!(st["name"].is_null() && home["name"] == "outside", "through the box looks like outside: {st} / {home}");
    let r = via_box.get(format!("{}/api/outside", n.access_url)).header("cookie", &cookie).send().await.unwrap();
    assert!(!r.status().is_success(), "home-only settings are closed to VPN visitors");
    let away = format!("syphon={}", n.app.new_session("owner", "owner", syphon::security::Zone::Remote));
    let me: Value = via_box.get(format!("{}/api/me", n.access_url)).header("cookie", &away).send().await.unwrap().json().await.unwrap();
    assert_eq!((me["zone"].as_str(), me["fast"].as_bool()), (Some("remote"), Some(true)), "outside, but fast: the player starts at full quality: {me}");
    let me: Value = api_get(&n.remote_url, "/api/me", &away).await.json().await.unwrap();
    assert_eq!((me["zone"].as_str(), me["fast"].as_bool()), (Some("remote"), Some(false)), "through Tor it starts low: {me}");
    let login: Value = via_box.post(format!("{}/api/login", n.access_url)).json(&json!({"user": "owner", "password": PW, "device_name": "laptop away"})).send().await.unwrap().json().await.unwrap();
    assert!(login["pending"].is_object(), "a new device through the box needs the outside extra step: {login}");
    syphon::security::set_vpn_boxes(vec![]);

    // Tor access off: the outside address refuses people; the home network is untouched
    assert!(api_get(&n.remote_url, "/api/status", "").await.status().is_success());
    assert!(api_post(&n.access_url, "/api/outside", &cookie, json!({"tor_access": false})).await.status().is_success());
    assert_eq!(api_get(&n.remote_url, "/api/status", "").await.status(), 403);
    assert!(api_get(&n.access_url, "/api/status", "").await.status().is_success());
    assert_eq!(n.app.db.get_setting("tor_access").unwrap().as_deref(), Some("off"));
    assert!(api_post(&n.access_url, "/api/outside", &cookie, json!({"tor_access": true})).await.status().is_success());
    assert!(api_get(&n.remote_url, "/api/status", "").await.status().is_success());
}

/// Syphon manages a real syphon-vpn box through the link. Run by tests/vpnbox_e2e.sh (it sets up the box in a network
/// namespace and passes its link code); skipped otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn the_owner_manages_a_real_vpn_box_through_the_link() {
    let code = std::env::var("SYPHON_TEST_VPNBOX_CODE").expect("run by tests/vpnbox_e2e.sh");
    let n = node("linked").await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let v: Value = api_get(&n.access_url, "/api/vpnbox", &cookie).await.json().await.unwrap();
    assert_eq!(v["linked"], false);
    // a damaged key is refused, and nothing is saved
    let mut bad = syphon::vpnbox::decode_link(&code).unwrap();
    bad.key = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [1u8; 32]);
    let bad_code = format!("SYPHON-VPNBOX-1:{}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, serde_json::to_vec(&bad).unwrap()));
    let r = api_post(&n.access_url, "/api/vpnbox/link", &cookie, json!({"code": bad_code})).await;
    assert_eq!(r.status(), 502, "a wrong key gets no usable answer");
    assert_eq!(api_get(&n.access_url, "/api/vpnbox", &cookie).await.json::<Value>().await.unwrap()["linked"], false);
    // the real code links, and the box's address now counts as outside
    let r: Value = api_post(&n.access_url, "/api/vpnbox/link", &cookie, json!({"code": code})).await.json().await.unwrap();
    assert_eq!(r["ok"], true, "{r}");
    let o: Value = api_get(&n.access_url, "/api/outside", &cookie).await.json().await.unwrap();
    assert!(o["vpn_boxes"].as_array().unwrap().iter().any(|x| x == "192.168.50.1"), "{o}");
    // a device: a code for its app, listed as waiting, then removed
    let r: Value = api_post(&n.access_url, "/api/vpnbox/devices", &cookie, json!({"name": "Mia's laptop"})).await.json().await.unwrap();
    assert!(r["code"].as_str().unwrap_or("").starts_with("SYPHON-VPN-1:"), "{r}");
    let v: Value = api_get(&n.access_url, "/api/vpnbox", &cookie).await.json().await.unwrap();
    assert_eq!((v["devices"][0]["name"].as_str(), v["devices"][0]["state"].as_str()), (Some("Mia's laptop"), Some("waiting")), "{v}");
    let r: Value = api_post(&n.access_url, "/api/vpnbox/devices", &cookie, json!({"name": "mia's LAPTOP"})).await.json().await.unwrap();
    assert!(r["error"].as_str().unwrap_or("").contains("already"), "names are unique: {r}");
    assert!(api_post(&n.access_url, "/api/vpnbox/devices/remove", &cookie, json!({"name": "Mia's laptop"})).await.status().is_success());
    let v: Value = api_get(&n.access_url, "/api/vpnbox", &cookie).await.json().await.unwrap();
    assert_eq!(v["devices"].as_array().map(|a| a.len()), Some(0), "{v}");
    // from outside, none of this is open
    assert!(!api_post(&n.remote_url, "/api/vpnbox/devices", &cookie, json!({"name": "x"})).await.status().is_success());
}

/// The owner sets when the node sleeps; the app gets what it needs to wake it at home, and nobody outside does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sleep_settings_are_kept_and_the_wake_address_stays_at_home() {
    let n = node("sleepy").await;
    let cookie = cookies_of(&login_at(&n.access_url, "owner", PW, "").await);
    let d: Value = api_get(&n.access_url, "/api/sleep", &cookie).await.json().await.unwrap();
    assert_eq!((d["idle"].as_bool(), d["now"].as_str()), (Some(false), Some("sleep is off")), "{d}");
    let d: Value = api_post(&n.access_url, "/api/sleep", &cookie, json!({"idle": true, "idle_min": 2, "sleep_at": "1:30", "wake_at": "07:00"})).await.json().await.unwrap();
    assert_eq!((d["idle"].as_bool(), d["idle_min"].as_u64(), d["sleep_at"].as_str(), d["wake_at"].as_str()), (Some(true), Some(5), Some("01:30"), Some("07:00")), "at least 5 minutes, times tidied: {d}");
    assert!(d["now"].as_str().unwrap().starts_with("awake"), "just started, so it stays up: {d}");
    assert_eq!(api_post(&n.access_url, "/api/sleep", &cookie, json!({"sleep_at": "25:00"})).await.status(), 400);
    let d: Value = api_post(&n.access_url, "/api/sleep", &cookie, json!({"sleep_at": "", "wake_at": "", "idle": false})).await.json().await.unwrap();
    assert_eq!((d["sleep_at"].is_null(), d["now"].as_str()), (true, Some("sleep is off")));
    // only the owner at home changes it; the wake address only goes to people at home
    assert!(!api_post(&n.remote_url, "/api/sleep", &cookie, json!({"idle": true})).await.status().is_success());
    assert!(api_get(&n.access_url, "/api/wake", &cookie).await.status().is_success());
    let away = format!("syphon={}", n.app.new_session("owner", "owner", syphon::security::Zone::Remote));
    assert_eq!(api_get(&n.remote_url, "/api/wake", &away).await.status(), 403);
}
