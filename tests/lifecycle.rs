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
    assert!(!dirs.quarantine().join("incoming-aa.tmp").exists());
    assert!(dirs.inbox().join("item1/0").exists(), "intact received chunks are kept");
    let (local, chunks): (String, i64) = app
        .db
        .with(|c| Ok((c.query_row("SELECT local FROM items WHERE id='item1'", [], |r| r.get(0))?, c.query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))?)))
        .unwrap();
    assert_eq!(local, "absent");
    assert_eq!(chunks, 1);
}

#[tokio::test]
async fn on_demand_node_forgets_transient_work() {
    let (_d, dirs, app) = make("on_demand");
    dirty(&app, &dirs);
    lifecycle::recover_on_start(&app).unwrap();
    let chunks: i64 = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM chunks", [], |r| r.get(0))?)).unwrap();
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
fn lookups_follow_tor_by_default() {
    use syphon::net::effective_route;
    let mut c = Config::default();
    assert_eq!(c.lookups.route, "auto");
    c.transport = "tor".into();
    assert_eq!(effective_route(&c), "tor");
    c.transport = "direct".into();
    assert_eq!(effective_route(&c), "direct");
    c.transport = "tor".into();
    c.lookups.route = "direct".into();
    assert_eq!(effective_route(&c), "direct", "an explicit choice is respected");
    c.lookups.route = "proxy".into(); // the removed option: fall back to Tor, never to direct
    assert_eq!(effective_route(&c), "tor");
    // older config files keep their choice: the [acquire] section is read as the lookup route
    let old: Config = toml::from_str("[acquire]\nroute = \"direct\"\ninternet_archive = true\nrss = []\n").unwrap();
    assert_eq!(old.lookups.route, "direct");
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

#[test]
fn unmounted_drives_are_found_and_system_parts_are_left_out() {
    // shaped like lsblk -J -b from util-linux 2.39: a system disk, a media disk nothing mounted, an empty disk,
    // an encrypted one, a FAT32 stick and a Windows disk with its hidden parts
    let json = r#"{"blockdevices":[
      {"name":"nvme0n1","path":"/dev/nvme0n1","size":512110190592,"fstype":null,"label":null,"uuid":null,"mountpoints":[null],"type":"disk","rm":false,"model":"Fast SSD","parttype":null,
       "children":[
         {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","size":536870912,"fstype":"vfat","label":null,"uuid":"AAAA-BBBB","mountpoints":["/boot/efi"],"type":"part","rm":false,"model":null,"parttype":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b"},
         {"name":"nvme0n1p2","path":"/dev/nvme0n1p2","size":511000000000,"fstype":"ext4","label":null,"uuid":"1111","mountpoints":["/"],"type":"part","rm":false,"model":null,"parttype":"0fc63daf-8483-4772-8e79-3d69d8477de4"}]},
      {"name":"sda","path":"/dev/sda","size":4000787030016,"fstype":null,"label":null,"uuid":null,"mountpoints":[null],"type":"disk","rm":false,"model":"Big Disk","parttype":null,
       "children":[{"name":"sda1","path":"/dev/sda1","size":4000785960960,"fstype":"ext4","label":"Movies","uuid":"2222-aaaa","mountpoints":[null],"type":"part","rm":false,"model":null,"parttype":"0fc63daf-8483-4772-8e79-3d69d8477de4"}]},
      {"name":"sdb","path":"/dev/sdb","size":2000398934016,"fstype":null,"label":null,"uuid":null,"mountpoints":[null],"type":"disk","rm":false,"model":"New Disk","parttype":null},
      {"name":"sdc","path":"/dev/sdc","size":1000204886016,"fstype":"crypto_LUKS","label":null,"uuid":"3333","mountpoints":[null],"type":"disk","rm":false,"model":"Locked","parttype":null},
      {"name":"sdd","path":"/dev/sdd","size":32000000000,"fstype":null,"label":null,"uuid":null,"mountpoints":[null],"type":"disk","rm":true,"model":"Stick","parttype":null,
       "children":[{"name":"sdd1","path":"/dev/sdd1","size":31999000000,"fstype":"vfat","label":"STICK","uuid":"4444-5555","mountpoints":[null],"type":"part","rm":true,"model":null,"parttype":"0xc"}]},
      {"name":"sde","path":"/dev/sde","size":1000204886016,"fstype":null,"label":null,"uuid":null,"mountpoints":[null],"type":"disk","rm":false,"model":"Win Disk","parttype":null,
       "children":[
         {"name":"sde1","path":"/dev/sde1","size":16777216,"fstype":null,"label":null,"uuid":null,"mountpoints":[null],"type":"part","rm":false,"model":null,"parttype":"e3c9e316-0b5c-4db8-817d-f92df00215ae"},
         {"name":"sde2","path":"/dev/sde2","size":999000000000,"fstype":"ntfs","label":"Data","uuid":"5555AAAA","mountpoints":[null],"type":"part","rm":false,"model":null,"parttype":"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"},
         {"name":"sde3","path":"/dev/sde3","size":5368709120,"fstype":"ntfs","label":null,"uuid":"6666","mountpoints":[null],"type":"part","rm":false,"model":null,"parttype":"de94bba4-06d1-4d40-a16a-bfd50179d6ac"}]},
      {"name":"loop0","path":"/dev/loop0","size":60000000000,"fstype":"squashfs","label":null,"uuid":null,"mountpoints":["/snap/x"],"type":"loop","rm":false,"model":null,"parttype":null},
      {"name":"sdf","path":"/dev/sdf","size":8000000000,"fstype":"swap","label":null,"uuid":"7777","mountpoints":[null],"type":"disk","rm":false,"model":null,"parttype":null}
    ]}"#;
    let v = syphon::storage::parse_lsblk(json);
    let names: Vec<&str> = v.iter().map(|d| d.device.as_str()).collect();
    assert_eq!(names, vec!["/dev/sda1", "/dev/sdb", "/dev/sdc", "/dev/sdd1", "/dev/sde2"], "{v:#?}");
    let by = |n: &str| v.iter().find(|d| d.device == n).unwrap();
    assert!(by("/dev/sda1").usable && by("/dev/sda1").label == "Movies" && by("/dev/sda1").model == "Big Disk");
    assert!(by("/dev/sde2").usable && by("/dev/sde2").fstype == "ntfs");
    assert!(!by("/dev/sdb").usable && by("/dev/sdb").note.contains("never erases"));
    assert!(!by("/dev/sdc").usable && by("/dev/sdc").note.contains("Locked"));
    assert!(!by("/dev/sdd1").usable && by("/dev/sdd1").removable);
    assert_eq!(syphon::storage::drive_name(by("/dev/sdb")), "New Disk");

    // older lsblk (before 2.37) has MOUNTPOINT, and gives numbers and flags as text
    let old = r#"{"blockdevices":[{"name":"sdb1","path":"/dev/sdb1","size":"5000000000","fstype":"xfs","label":null,"uuid":"8888","mountpoint":null,"type":"part","rm":"0","model":null},
      {"name":"sdc1","path":"/dev/sdc1","size":"5000000000","fstype":"xfs","label":null,"uuid":"9999","mountpoint":"/data","type":"part","rm":"0","model":null}]}"#;
    let v = syphon::storage::parse_lsblk(old);
    assert_eq!(v.len(), 1);
    assert!(v[0].usable && v[0].uuid == "8888");
    assert!(syphon::storage::parse_lsblk("not json").is_empty());
}

#[test]
fn graphics_cards_are_found_and_used_for_conversion() {
    use syphon::gpu::{Api, Encoder};
    use syphon::library::{ffmpeg_args, quality_by_id, Codec, Convert};
    // a fake /sys with an Intel and an AMD render node, and an unknown vendor that is ignored
    let t = tempfile::tempdir().unwrap();
    for (n, vendor) in [("renderD128", "0x8086\n"), ("renderD129", "0x1002\n"), ("renderD130", "0x1234\n")] {
        let d = t.path().join("sys/class/drm").join(n).join("device");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("vendor"), vendor).unwrap();
    }
    std::fs::create_dir_all(t.path().join("dev/dri")).unwrap();
    std::fs::write(t.path().join("dev/dri/renderD128"), b"").unwrap();
    let cards = syphon::gpu::find_cards(&t.path().join("sys"), &t.path().join("dev"));
    assert_eq!(cards.iter().map(|c| c.vendor.as_str()).collect::<Vec<_>>(), vec!["intel", "amd"]);
    assert!(cards[0].allowed, "a device the service user can open");
    assert!(!cards[1].allowed, "no device file: it can't be opened");
    assert!(cards[0].device.ends_with("/dev/dri/renderD128"));
    // an NVIDIA card with only its own driver's device
    std::fs::write(t.path().join("dev/nvidia0"), b"").unwrap();
    let cards = syphon::gpu::find_cards(&t.path().join("sys"), &t.path().join("dev"));
    assert!(cards.iter().any(|c| c.vendor == "nvidia" && c.device.is_empty()));

    let q = quality_by_id("medium");
    let tr = Convert::Transcode(q.clone(), Codec::H264);
    let has = |a: &[String], w: &[&str]| a.windows(w.len()).any(|x| x.iter().map(|s| s.as_str()).eq(w.iter().copied()));
    // on the processor, as before
    let cpu = ffmpeg_args(0.0, &tr, 2, None);
    assert!(has(&cpu, &["-c:v", "libx264"]));
    // VA-API (Intel, AMD): decoded on the card where it can, scaled, uploaded, encoded on the card
    let va = Encoder { api: Api::Vaapi, vendor: "intel".into(), name: "Intel graphics".into(), device: "/dev/dri/renderD128".into(), h264: true, av1: true };
    let a = ffmpeg_args(12.0, &tr, 2, Some(&va));
    assert!(has(&a, &["-hwaccel", "vaapi", "-hwaccel_device", "/dev/dri/renderD128"]));
    assert!(has(&a, &["-c:v", "h264_vaapi"]));
    assert!(a.iter().any(|x| x.contains("min(720,ih)") && x.ends_with("format=nv12,hwupload")));
    assert!(a.iter().position(|x| x == "-hwaccel").unwrap() < a.iter().position(|x| x == "-i").unwrap(), "hardware decoding is set before the input");
    assert!(!a.iter().any(|x| x == "libx264"));
    let a = ffmpeg_args(0.0, &Convert::Transcode(q.clone(), Codec::Av1("gpu")), 2, Some(&va));
    assert!(has(&a, &["-c:v", "av1_vaapi"]));
    // NVIDIA
    let nv = Encoder { api: Api::Nvenc, vendor: "nvidia".into(), name: "NVIDIA graphics".into(), device: String::new(), h264: true, av1: false };
    let a = ffmpeg_args(0.0, &tr, 2, Some(&nv));
    assert!(has(&a, &["-hwaccel", "cuda"]) && has(&a, &["-c:v", "h264_nvenc"]) && has(&a, &["-maxrate", "2800k"]));
    // Quick Sync
    let qs = Encoder { api: Api::Qsv, ..va.clone() };
    let a = ffmpeg_args(0.0, &tr, 2, Some(&qs));
    assert!(has(&a, &["-c:v", "h264_qsv"]) && a.iter().any(|x| x.starts_with("vaapi=va:/dev/dri/renderD128")));
    // a remux never touches the card
    let r = ffmpeg_args(0.0, &Convert::Remux { copy_audio: true }, 2, Some(&va));
    assert!(has(&r, &["-c:v", "copy"]) && !r.iter().any(|x| x.contains("vaapi")));
}

#[tokio::test]
async fn the_console_answers_and_keeps_changes_at_home() {
    let (_d, _dirs, app) = make("always_on");
    let run = |l: &'static str, home: bool| {
        let a = app.clone();
        async move { syphon::console::run(&a, l, home).await.unwrap() }
    };
    let s = run("status", false).await.unwrap();
    assert!(s.contains("Version") && s.contains("Library"), "{s}");
    assert!(run("users", false).await.unwrap().contains("owner"));
    assert!(run("help", false).await.unwrap().contains("restart"));
    assert!(run("gpu", false).await.unwrap().len() > 5);
    assert!(run("frobnicate", true).await.unwrap().contains("Unknown command"));
    assert!(run("sudo apt update", true).await.unwrap().contains("terminal"));
    assert_eq!(run("clear", true).await, None);
    // restarting and installing only from home
    assert!(run("restart", false).await.unwrap().contains("only works from your home network"));
    assert!(run("update now", false).await.unwrap().contains("only works from your home network"));
    // looking at the update state is fine from anywhere
    assert!(run("update", false).await.unwrap().contains("This node runs"));
}

#[test]
fn terminal_frames_survive_being_split() {
    use syphon::shellpty::{frame, take_frames};
    let mut wire = frame(b'd', b"hello");
    wire.extend(frame(b'r', &[0, 40, 0, 120]));
    wire.extend(frame(b'x', b""));
    // arriving a byte at a time
    let mut buf = vec![];
    let mut got = vec![];
    for b in wire {
        buf.push(b);
        got.extend(take_frames(&mut buf));
    }
    assert!(buf.is_empty());
    assert_eq!(got, vec![(b'd', b"hello".to_vec()), (b'r', vec![0, 40, 0, 120]), (b'x', vec![])]);
}
