//! Syphon: a mesh media server. Encrypted library, request-based sync between trusted nodes,
//! reachable only through Tor onion services (or plain HTTP in development mode).

pub mod acquire;
pub mod api;
pub mod auth;
pub mod catalog;
pub mod config;
pub mod discovery;
pub mod db;
pub mod sanity;
pub mod handoff;
pub mod library;
pub mod lifecycle;
pub mod mesh;
pub mod metadata;
pub mod pair;
pub mod perf;
pub mod rest;
pub mod storage;
pub mod quarantine;
pub mod scanner;
pub mod security;
pub mod sleep;
pub mod state;
pub mod sync;
pub mod totp;
pub mod tor;
pub mod torify;
pub mod update;
pub mod util;
pub mod vpnbox;
pub mod keyring;

use anyhow::Result;
use state::Shared;
use std::time::Duration;
use tokio::net::TcpListener;

/// Start every listener and background task of a node. Returns once they are running.
pub async fn run_node(app: Shared) -> Result<()> {
    handoff::restore(&app);
    library::tidy_all(&app);
    let rec = lifecycle::recover_on_start(&app)?;
    if rec.stale_files + rec.chunk_rows_fixed + rec.downloads_paused > 0 {
        tracing::info!(
            "recovered after an unclean stop: {} leftover files removed, {} chunk records repaired, {} downloads paused",
            rec.stale_files, rec.chunk_rows_fixed, rec.downloads_paused
        );
    }
    security::load_outside_settings(&app);
    let access = TcpListener::bind(&app.cfg.access_bind).await?;
    let mesh_l = TcpListener::bind(&app.cfg.mesh_bind).await?;
    tracing::info!("UI/API on http://{}", access.local_addr()?);

    if app.cfg.transport == "tor" {
        let tor_access = TcpListener::bind(("127.0.0.1", app.cfg.tor_access_port)).await?;
        tokio::spawn(api::serve(app.clone(), tor_access, security::Via::Tor));
        tor::start(&app).await?;
        // the mesh address becomes known once tor has created the onion service
        if let Some(o) = tor::onion_of(&tor::TorPaths::new(&app.dirs).hs_mesh()) {
            *app.mesh_addr.lock().unwrap() = o;
        }
    } else {
        *app.mesh_addr.lock().unwrap() = format!("http://{}", mesh_l.local_addr()?);
    }
    tokio::spawn(api::serve(app.clone(), access, security::Via::Lan));
    tokio::spawn(pair::run(app.clone()));
    tokio::spawn(mesh::serve(app.clone(), mesh_l));
    tokio::spawn(sync::run(app.clone()));
    tokio::spawn(watch_imports(app.clone()));
    tokio::spawn(metadata::run(app.clone()));
    tokio::spawn(perf::run(app.clone()));
    tokio::spawn(storage::run(app.clone()));
    tokio::spawn(rest::run(app.clone()));
    tokio::spawn(sleep::run(app.clone()));
    tokio::spawn(discovery::run(app.clone(), app.db.get_setting("discovery_port").ok().flatten().and_then(|p| p.parse().ok()).unwrap_or(discovery::PORT)));
    // an older version could suspend the computer; if it left its network-wake setting behind, have the helper remove it
    if std::path::Path::new("/etc/systemd/system/syphon-wol.service").exists() {
        storage::request_helper(&app, "cleanup-sleep", &[]);
    }
    tokio::spawn(sanity::run(app.clone()));
    if app.cfg.scan.background {
        tokio::spawn(quarantine::run_worker(app.clone()));
    }
    Ok(())
}

const IMPORT_EXTS: [&str; 10] = ["mp4", "m4v", "mov", "mkv", "webm", "avi", "ts", "m2ts", "ogv", "mpg"];

/// Videos dropped into `import_dir` are encrypted into the review area (needs the keyring unlocked).
pub async fn watch_imports(app: Shared) {
    if app.cfg.import_dir.is_empty() {
        return;
    }
    let dir = std::path::PathBuf::from(&app.cfg.import_dir);
    loop {
        rest::sleep(&app, Duration::from_secs(10)).await;
        if !app.keyring.is_unlocked() {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let ext = p.extension().map(|x| x.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
            if !p.is_file() || !IMPORT_EXTS.contains(&ext.as_str()) {
                continue;
            }
            // skip files still being copied in
            let settled = e
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| t.elapsed().map(|d| d > Duration::from_secs(8)).unwrap_or(false))
                .unwrap_or(false);
            if !settled {
                continue;
            }
            match library::import_path(&app, &p, "import").await {
                Ok(ing) => {
                    tracing::info!("imported {} into the review area", p.display());
                    if app.cfg.import_delete_source && std::fs::remove_file(&p).is_err() {
                        tracing::warn!("could not remove {} after import", p.display());
                    }
                    let _ = ing;
                }
                Err(e) => tracing::warn!("import of {} failed: {e:#}", p.display()),
            }
        }
    }
}
