use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use syphon::config::{Config, Dirs};
use syphon::state::App;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "syphon", version = env!("SYPHON_VERSION"), about = "Mesh media server over Tor onion services")]
struct Cli {
    /// Node data directory
    #[arg(long, global = true, env = "SYPHON_DIR")]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new node: config, encrypted keyring, node identity and the owner account
    Init {
        #[arg(long)]
        name: Option<String>,
        /// "tor" (onion services) or "direct" (plain HTTP, development only)
        #[arg(long, default_value = "tor")]
        transport: String,
        /// What the owner of this node wants to be called (asked interactively when left out)
        #[arg(long, env = "SYPHON_OWNER")]
        owner: Option<String>,
        /// "always_on" (may lose power or crash: keep everything safe on disk) or "on_demand"
        #[arg(long, default_value = "always_on")]
        persistence: String,
    },
    /// Run the node (UI, mesh, sync, Tor)
    Run,
    /// Create an invite code to give to another node's owner
    Invite,
    /// Ask to connect to another node using its invite code (they accept, then you are paired)
    Join { code: String },
    /// Authorise a device (phone, laptop) on the access onion service
    Device {
        name: String,
        /// remove this device's key instead ("all" turns the extra lock off completely)
        #[arg(long)]
        remove: bool,
    },
    /// Encrypt video files into the isolated review area
    Import { path: PathBuf },
    /// Show node id, fingerprint and onion addresses
    Info,
    /// Save a consistent copy of the database and the small key and settings files (used by the updater before it installs anything)
    Snapshot {
        #[arg(long)]
        to: PathBuf,
    },
    /// Show what this computer has (processor, memory, network) and the limits Syphon would pick on it
    Perf,
    /// List the drives on this computer and which ones Syphon is using
    Drives,
    /// Change a setting: persistence (always_on|on_demand), system-wide (on|off), route (auto|tor|direct), bridge (a bridge line, or "clear")
    Set { key: String, value: String },
    /// Print the firewall rules that send this computer's traffic through Tor (read by `syphon-ctl torify`)
    TorifyRules {
        /// The account Tor runs as (it must be exempt from the rules)
        #[arg(long)]
        uid: u32,
    },
}

fn data_dir(cli: &Cli) -> PathBuf {
    cli.dir.clone().unwrap_or_else(|| {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let new = home.as_ref().map(|h| h.join(".local/share/syphon"));
        let old = home.as_ref().map(|h| h.join(".local/share/hearth"));
        match (new, old) {
            (Some(n), Some(o)) if !n.exists() && o.exists() => o, // a node made before the rename
            (Some(n), _) => n,
            _ => PathBuf::from("./syphon-data"),
        }
    })
}

fn password(prompt: &str, confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("SYPHON_PASSWORD") {
        return Ok(p);
    }
    let p = rpassword::prompt_password(prompt)?;
    if confirm {
        let q = rpassword::prompt_password("Repeat password: ")?;
        if p != q {
            bail!("passwords do not match");
        }
    }
    Ok(p)
}

fn open(dirs: &Dirs) -> Result<syphon::state::Shared> {
    let cfg = Config::load(dirs).with_context(|| format!("no node found in {} (run `syphon init`)", dirs.root.display()))?;
    let app = App::open(dirs.clone(), cfg)?;
    if app.cfg.transport == "tor" {
        if let Some(o) = syphon::tor::onion_of(&syphon::tor::TorPaths::new(&app.dirs).hs_mesh()) {
            *app.mesh_addr.lock().unwrap() = o;
        }
    }
    Ok(app)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "syphon=info".into()))
        .init();
    let cli = Cli::parse();
    let dirs = Dirs::new(data_dir(&cli));
    match cli.cmd {
        Cmd::Init { name, transport, owner, persistence } => {
            if persistence != "always_on" && persistence != "on_demand" {
                bail!("persistence must be always_on or on_demand");
            }
            if transport != "tor" && transport != "direct" {
                bail!("transport must be tor or direct");
            }
            let owner = match owner {
                Some(o) if !o.trim().is_empty() => o.trim().to_string(),
                _ => {
                    use std::io::Write;
                    print!("What should we call you? ");
                    std::io::stdout().flush()?;
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    let l = line.trim().to_string();
                    if l.is_empty() {
                        bail!("please tell us what to call you (use --owner NAME)");
                    }
                    l
                }
            };
            let pw = password("Choose a password (it also protects your library): ", true)?;
            if pw.len() < 8 {
                bail!("use at least 8 characters");
            }
            let mut cfg = Config { transport, persistence, ..Config::default() };
            if let Some(n) = name {
                cfg.name = n;
            }
            App::init(&dirs, cfg, &owner, &pw)?;
            println!("Node created for {owner} in {}", dirs.root.display());
            println!("Start it with: syphon run");
        }
        Cmd::Run => {
            let app = open(&dirs)?;
            syphon::run_node(app.clone()).await?;
            println!("Syphon is running.");
            println!("  On this machine:  http://127.0.0.1:{}", app.cfg.access_bind.rsplit(':').next().unwrap_or("8096"));
            for u in syphon::security::lan_urls(&app.cfg.access_bind) {
                println!("  On your network:  {u}");
            }
            println!("Sign in with your name and password to unlock the library.");
            println!(
                "Mode: {}.",
                if app.cfg.persistent() { "always on (safe against power loss; unfinished work resumes)" } else { "on demand (shuts down cleanly and forgets unfinished work)" }
            );
            syphon::lifecycle::wait_for_stop_signal().await;
            println!("shutting down cleanly...");
            syphon::lifecycle::shutdown(&app).await;
            println!("stopped.");
        }
        Cmd::Set { key, value } => {
            let mut cfg = Config::load(&dirs).with_context(|| format!("no node found in {}", dirs.root.display()))?;
            let on = matches!(value.as_str(), "on" | "true" | "yes" | "1");
            if matches!(key.as_str(), "storage" | "storage-add") {
                // drives are kept with the node's data (Settings > Storage shows the same list)
                let app = open(&dirs)?;
                let mut sc = syphon::storage::cfg(&app);
                if key == "storage" {
                    match value.as_str() {
                        "all" | "selected" => sc.mode = value.clone(),
                        _ => bail!("storage is all (use every drive on this computer) or selected (only the drives you add)"),
                    }
                    syphon::storage::save(&app, sc)?;
                    let n = syphon::storage::sync_all(&app)?;
                    println!("saved. {n} drive(s) added.");
                } else {
                    let p = std::path::PathBuf::from(&value);
                    if let Some(m) = syphon::storage::forbidden_path(&p) { bail!("{}: {m}", p.display()); }
                    if !p.is_dir() { bail!("{} is not a folder", p.display()); }
                    let mp = syphon::storage::is_mount(&p);
                    let path = if mp { syphon::storage::volume_path_for(&value) } else { value.clone() };
                    std::fs::create_dir_all(&path).with_context(|| format!("cannot create {path}"))?;
                    if !sc.volumes.iter().any(|v| v.path == path) {
                        sc.volumes.push(syphon::storage::Volume {
                            id: syphon::storage::new_volume_id(),
                            label: p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "Drive".into()),
                            path, kind: "local".into(), enabled: true, reserve_gb: None,
                            mount: if mp { value.clone() } else { String::new() }, nas: None, imports: vec![], auto: false,
                        });
                    }
                    syphon::storage::save(&app, sc)?;
                    println!("saved.");
                }
                return Ok(());
            }
            match key.as_str() {
                "persistence" => {
                    cfg.persistence = match value.as_str() {
                        "always_on" | "on" => "always_on".into(),
                        "on_demand" | "off" => "on_demand".into(),
                        _ => bail!("persistence is on (always_on) or off (on_demand)"),
                    }
                }
                "system-wide" => cfg.tor.system_wide = on,
                "perf" | "performance" => {
                    cfg.perf.mode = match value.as_str() {
                        "dedicated" => "dedicated".into(),
                        "shared" => "shared".into(),
                        _ => bail!("performance is dedicated (this computer only runs Syphon) or shared"),
                    }
                }
                "bridge" => {
                    if value == "clear" {
                        cfg.tor.bridges.clear();
                    } else {
                        let line = syphon::tor::clean_bridge_line(&value)?;
                        if !cfg.tor.bridges.contains(&line) {
                            cfg.tor.bridges.push(line);
                        }
                    }
                }
                "route" => match value.as_str() {
                    "auto" | "tor" | "direct" => cfg.acquire.route = value.clone(),
                    _ => bail!("route is auto, tor or direct"),
                },
                _ => bail!("unknown setting {key} (persistence, system-wide, route, perf)"),
            }
            cfg.save(&dirs)?;
            if matches!(key.as_str(), "perf" | "performance") {
                // a choice made in Settings is stored with the node's data; this one replaces it
                let app = open(&dirs)?;
                app.db.set_setting("perf_mode", &value)?;
            }
            println!("saved. Restart Syphon for it to take effect (sudo systemctl restart syphon).");
        }
        Cmd::TorifyRules { uid } => {
            let cfg = Config::load(&dirs).unwrap_or_default();
            print!("{}", syphon::torify::nft_rules(uid, cfg.tor.trans_port, cfg.tor.dns_port));
        }
        Cmd::Invite => {
            let app = open(&dirs)?;
            let inv = syphon::pair::create_invite(&app, "")?;
            println!("{}", inv.code);
            eprintln!("\nGive this code to the other node's owner. It works once and expires in 24 hours.");
            eprintln!("Your fingerprint (they can check it when they ask to connect): {}", inv.fingerprint);
            eprintln!("Then accept their request in the Mesh tab (the node must be running).");
        }
        Cmd::Join { code } => {
            let app = open(&dirs)?;
            let d = syphon::pair::decode(&code)?;
            println!("Asking \"{}\" to connect (fingerprint {})", d.name, syphon::util::fingerprint(&d.node_id));
            syphon::pair::request_join(&app, &code)?;
            println!("Request saved. With the node running, it is sent automatically; you are paired as soon as they accept.");
        }
        Cmd::Device { name, remove } => {
            let app = open(&dirs)?;
            if remove {
                if name == "all" {
                    println!("removed {} key(s); the extra lock is off.", syphon::tor::remove_all_access_devices(&app));
                } else {
                    syphon::tor::remove_access_device(&app, &name);
                    println!("removed the key for {name}.");
                }
                return Ok(());
            }
            let line = syphon::tor::add_access_device(&app, &name)?;
            println!("Import this line on the device (Tor Browser > Settings > Connection > Onion Services Authentication):\n\n{line}\n");
        }
        Cmd::Import { path } => {
            let app = open(&dirs)?;
            app.keyring.unlock(&password("Owner password: ", false)?)?;
            let mut files = vec![];
            if path.is_dir() {
                for e in std::fs::read_dir(&path)?.flatten() {
                    if e.path().is_file() {
                        files.push(e.path());
                    }
                }
            } else {
                files.push(path);
            }
            for f in files {
                match syphon::library::import_path(&app, &f, "import").await {
                    Ok(i) => println!("{} -> review area ({}){}", f.display(), &i.id[..12], if i.dup { " [already known]" } else { "" }),
                    Err(e) => eprintln!("{}: {e:#}", f.display()),
                }
            }
            println!("Approve imported videos in the Review tab of the UI.");
        }
        Cmd::Drives => {
            let app = open(&dirs)?;
            let c = syphon::storage::cfg(&app);
            println!("mode: {} ({})", c.mode, if c.mode == "all" { "every fixed drive is used" } else { "only the drives you chose" });
            for d in syphon::storage::detect_drives(&app) {
                let tag = if d.system { "system drive" } else if d.network { "network" } else if d.removable { "removable" } else { "internal" };
                println!("{:<24} {:>8} GB ({:>7} GB free)  {:<12} {}{}", d.mount, d.total >> 30, d.free >> 30, tag, d.source, if d.in_use { "   [in use]" } else { "" });
            }
        }
        Cmd::Snapshot { to } => {
            let n = syphon::lifecycle::snapshot(&dirs.root, &to)?;
            println!("saved {n} files to {}", to.display());
        }
        Cmd::Perf => {
            let hw = syphon::perf::detect(None);
            let base = syphon::perf::Base { streams: 3, download_parallel: 2, transcode_threads: 2 };
            println!("processor cores: {}", hw.cores);
            println!("memory:          {} MB ({} MB free right now)", hw.ram_mb, hw.ram_avail_mb);
            match hw.link_mbps {
                Some(n) => println!("network:         {} Mb/s (the network card's own speed)", n),
                None => println!("network:         speed not reported by this computer; Syphon will measure it while it runs"),
            }
            for (label, ded) in [("shared computer", false), ("dedicated node", true)] {
                let t = syphon::perf::compute(&hw, ded, &base);
                println!("\nif this is a {label}:");
                println!("  {} parallel transfers, {} downloads, {} low-bitrate streams, {} scan(s) at once", t.streams, t.download_parallel, t.transcode_max, t.scan_parallel);
            }
        }
        Cmd::Info => {
            let app = open(&dirs)?;
            println!("name:        {}", app.cfg.name);
            println!("node id:     {}", app.id.id);
            println!("fingerprint: {}", syphon::util::fingerprint(&app.id.id));
            let tp = syphon::tor::TorPaths::new(&app.dirs);
            println!("mesh onion:   {}", syphon::tor::onion_of(&tp.hs_mesh()).unwrap_or_else(|| "(not created yet: run the node once)".into()));
            println!("access onion: {}", syphon::tor::onion_of(&tp.hs_access()).unwrap_or_else(|| "(not created yet: run the node once)".into()));
        }
    }
    Ok(())
}
