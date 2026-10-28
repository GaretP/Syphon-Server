use syphon::config::{Config, Dirs};
use syphon::lifecycle;
use syphon::state::{App, Shared};

const PW: &str = "correct horse battery";

fn make(persistence: &str) -> (tempfile::TempDir, Dirs, Shared) {
    let dir = tempfile::tempdir().unwrap();
    let dirs = Dirs::new(dir.path());
    let mut cfg = Config::default();
    cfg.transport = "direct".into();
    cfg.persistence = persistence.into();
    cfg.kdf_m_kib = 64;
    cfg.kdf_t = 1;
    App::init(&dirs, cfg, "owner", PW).unwrap();
    let app = App::open(dirs.clone(), Config::load(&dirs).unwrap()).unwrap();
    (dir, dirs, app)
}

fn dirty(app: &Shared, dirs: &Dirs) {
    // what a power cut leaves behind
    std::fs::write(dirs.quarantine().join("incoming-aa.tmp"), b"half").unwrap();
    std::fs::write(dirs.root.join("keyring.json.tmp"), b"half").unwrap();
    let inbox = dirs.inbox().join("item1");
    std::fs::create_dir_all(&inbox).unwrap();
    std::fs::write(inbox.join("0"), b"ok").unwrap();
    std::fs::write(inbox.join("1.part"), b"half").unwrap();
    app.db
        .with(|c| {
            c.execute("INSERT INTO items(id,title,kind,size,chunk_hashes,author,added_at,catalog,deleted,local) VALUES('item1','t','movie',10,'[]','x',0,1,0,'syncing')", [])?;
            c.execute("INSERT INTO chunks(item,idx) VALUES('item1',0),('item1',1)", [])?; // chunk 1 never made it to disk
            c.execute("INSERT INTO downloads(id,provider,title,url,status,created) VALUES('d1','link','x','http://e.x/a.mp4','downloading',0)", [])?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn always_on_node_cleans_up_after_a_power_cut_and_keeps_work_to_resume() {
    let (_d, dirs, app) = make("always_on");
    dirty(&app, &dirs);
    let r = lifecycle::recover_on_start(&app).unwrap();
    assert!(r.database_ok);
    assert_eq!(r.stale_files, 3);
    assert_eq!(r.chunk_rows_fixed, 1, "only the chunk whose file is missing is forgotten");
    assert_eq!(r.downloads_paused, 1);
    assert!(!dirs.quarantine().join("incoming-aa.tmp").exists());
    assert!(dirs.inbox().join("item1/0").exists(), "intact received chunks are kept");
    let (status, local, chunks): (String, String, i64) = app
        .db
        .with(|c| {
            Ok((
                c.query_row("SELECT status FROM downloads WHERE id='d1'", [], |r| r.get(0))?,
                c.query_row("SELECT local FROM items WHERE id='item1'", [], |r| r.get(0))?,
                c.query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))?,
            ))
        })
        .unwrap();
    assert_eq!(status, "waiting");
    assert_eq!(local, "absent");
    assert_eq!(chunks, 1);
}

#[tokio::test]
async fn on_demand_node_forgets_transient_work() {
    let (_d, dirs, app) = make("on_demand");
    dirty(&app, &dirs);
    lifecycle::recover_on_start(&app).unwrap();
    let (status, chunks): (String, i64) = app
        .db
        .with(|c| Ok((c.query_row("SELECT status FROM downloads WHERE id='d1'", [], |r| r.get(0))?, c.query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))?)))
        .unwrap();
    assert_eq!(status, "failed");
    assert_eq!(chunks, 0);
    assert!(!dirs.inbox().join("item1").exists());
}

#[tokio::test]
async fn graceful_shutdown_stops_work_locks_the_library_and_is_repeatable() {
    let (_d, dirs, app) = make("always_on");
    app.keyring.unlock(PW).unwrap();
    app.new_session("owner", "owner", syphon::security::Zone::Lan);
    assert!(app.gate().is_ok());
    lifecycle::shutdown(&app).await;
    assert!(app.is_shutting_down());
    assert!(app.gate().is_err(), "no new sync work after shutdown starts");
    assert!(!app.keyring.is_unlocked(), "keys are wiped from memory");
    assert!(app.sessions.lock().unwrap().is_empty());
    assert!(app.db.get_setting("last_clean_shutdown").unwrap().is_some());
    lifecycle::shutdown(&app).await; // second call is harmless
    // everything is folded into the main database file: no write-ahead log left behind
    let wal = dirs.root.join("syphon.db-wal");
    assert!(!wal.exists() || std::fs::metadata(&wal).unwrap().len() == 0);
}

#[tokio::test]
async fn a_cut_power_during_a_key_change_cannot_leave_a_torn_keyring() {
    let (_d, dirs, app) = make("always_on");
    app.keyring.unlock(PW).unwrap();
    app.keyring.change_password(PW, "another long password").unwrap();
    assert!(!dirs.root.join("keyring.json.tmp").exists(), "written to a temp file and renamed into place");
    let again = syphon::keyring::Keyring::open(&dirs.keyring()).unwrap();
    again.unlock("another long password").unwrap();
}

#[test]
fn downloads_follow_tor_by_default() {
    use syphon::acquire::effective_route;
    let mut c = Config::default();
    assert_eq!(c.acquire.route, "auto");
    c.transport = "tor".into();
    assert_eq!(effective_route(&c), "tor");
    c.transport = "direct".into();
    assert_eq!(effective_route(&c), "direct");
    c.transport = "tor".into();
    c.acquire.route = "direct".into();
    assert_eq!(effective_route(&c), "direct", "an explicit choice is respected");
    c.acquire.route = "proxy".into(); // the removed option: fall back to Tor, never to direct
    assert_eq!(effective_route(&c), "tor");
}

/// The updater and release.sh compare `syphon --version` with the release name (v1.2.3), so the program must print
/// that name, not the bare crate version.
#[test]
fn the_program_reports_its_release_name() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_syphon")).arg("--version").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let v = text.split_whitespace().nth(1).unwrap_or("");
    assert_eq!(v, env!("SYPHON_VERSION"), "{text}");
}
