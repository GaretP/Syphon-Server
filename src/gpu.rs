//! Graphics cards for video conversion.
//!
//! Syphon looks for Intel, AMD and NVIDIA graphics at start, checks which of ffmpeg's hardware encoders really
//! work on them (a short test encode, not just "the encoder is compiled in"), and then converts on the card.
//! Intel and AMD go through VA-API (Intel can also use Quick Sync), NVIDIA through NVENC. Decoding uses the card
//! too where it can, and falls back to the processor by itself for formats the card does not know. When nothing
//! works, conversions run on the processor exactly as before.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

/// A graphics card found in this computer.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Card {
    /// "intel", "amd" or "nvidia"
    pub vendor: String,
    pub name: String,
    /// its render node, for example /dev/dri/renderD128 (empty for an NVIDIA card without one)
    pub device: String,
    /// the service user may open the device
    pub allowed: bool,
}

/// How the card is driven.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Api {
    Nvenc,
    Vaapi,
    Qsv,
}

/// The card Syphon converts on, and what it can make.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Encoder {
    pub api: Api,
    pub vendor: String,
    pub name: String,
    pub device: String,
    pub h264: bool,
    pub av1: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct State {
    pub checked: bool,
    pub cards: Vec<Card>,
    pub active: Option<Encoder>,
    /// what is missing when a card was found but can't be used, in plain words
    pub notes: Vec<String>,
}

static STATE: RwLock<Option<State>> = RwLock::new(None);

pub fn state() -> State {
    STATE.read().unwrap().clone().unwrap_or_default()
}

/// The encoder to use, if the owner left the graphics card on.
pub fn active(app: &crate::state::App) -> Option<Encoder> {
    if !enabled(app) {
        return None;
    }
    state().active
}

pub fn enabled(app: &crate::state::App) -> bool {
    app.db.get_setting("gpu_use").ok().flatten().as_deref() != Some("off")
}

fn vendor_of(id: &str) -> Option<&'static str> {
    match id.trim().to_lowercase().as_str() {
        "0x8086" => Some("intel"),
        "0x1002" | "0x1022" => Some("amd"),
        "0x10de" => Some("nvidia"),
        _ => None,
    }
}

fn pretty(vendor: &str) -> &'static str {
    match vendor {
        "intel" => "Intel graphics",
        "amd" => "AMD graphics",
        _ => "NVIDIA graphics",
    }
}

fn can_open(p: &Path) -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open(p).is_ok()
}

/// The card's name from lspci when it is installed ("Intel Corporation UHD Graphics 630"), else a generic one.
fn card_name(slot: &str, vendor: &str) -> String {
    if !slot.is_empty() {
        if let Ok(o) = std::process::Command::new("lspci").args(["-mm", "-s", slot]).output() {
            // "00:02.0" "VGA compatible controller" "Intel Corporation" "UHD Graphics 630" ...
            let t = String::from_utf8_lossy(&o.stdout);
            let f: Vec<&str> = t.split('"').filter(|s| !s.trim().is_empty()).collect();
            if f.len() >= 4 {
                let name = f[3].trim();
                if !name.is_empty() {
                    let short = name.split(['[', '(']).next().unwrap_or(name).trim();
                    return format!("{} {}", pretty(vendor).split(' ').next().unwrap_or(""), if short.is_empty() { name } else { short });
                }
            }
        }
    }
    pretty(vendor).to_string()
}

/// Graphics cards under `sys` (normally /sys) with their render nodes under `dev` (normally /dev).
pub fn find_cards(sys: &Path, dev: &Path) -> Vec<Card> {
    let mut out: Vec<Card> = vec![];
    let mut nodes: Vec<PathBuf> = std::fs::read_dir(sys.join("class/drm"))
        .map(|r| r.flatten().map(|e| e.path()).filter(|p| p.file_name().map(|n| n.to_string_lossy().starts_with("renderD")).unwrap_or(false)).collect())
        .unwrap_or_default();
    nodes.sort();
    for n in nodes {
        let Ok(v) = std::fs::read_to_string(n.join("device/vendor")) else { continue };
        let Some(vendor) = vendor_of(&v) else { continue };
        let slot = std::fs::read_link(n.join("device")).ok().and_then(|p| p.file_name().map(|s| s.to_string_lossy().to_string())).unwrap_or_default();
        let device = dev.join("dri").join(n.file_name().unwrap());
        out.push(Card { vendor: vendor.into(), name: card_name(&slot, vendor), allowed: can_open(&device), device: device.to_string_lossy().to_string() });
    }
    // NVIDIA's own driver may run without a render node
    if !out.iter().any(|c| c.vendor == "nvidia") && dev.join("nvidia0").exists() {
        out.push(Card { vendor: "nvidia".into(), name: pretty("nvidia").into(), device: String::new(), allowed: can_open(&dev.join("nvidia0")) });
    }
    out
}

/// ffmpeg's arguments to put a hardware encoder to work, for the live conversion and the start-up test alike.
/// `decode` is what goes before the input, `filter` is appended to the picture filters, `codec` follows them.
pub struct HwArgs {
    pub decode: Vec<String>,
    pub filter: String,
    pub codec: Vec<String>,
}

fn v(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// `av1` picks the AV1 encoder, otherwise H.264. `crf` is the quality number of the processor encoder (lower is
/// sharper); hardware encoders get the closest setting they understand. `maxrate` caps the bit rate (kbit/s, 0 = none).
pub fn hw_args(e: &Encoder, av1: bool, crf: u8, maxrate: u32, decode_on_card: bool) -> HwArgs {
    let cap = |out: &mut Vec<String>| {
        if maxrate > 0 {
            out.extend(["-maxrate".into(), format!("{maxrate}k"), "-bufsize".into(), format!("{}k", maxrate * 2)]);
        }
    };
    match e.api {
        Api::Nvenc => {
            let mut codec = v(&["-c:v", if av1 { "av1_nvenc" } else { "h264_nvenc" }, "-preset", "p4", "-tune", "ll", "-rc", "vbr", "-cq", &crf.to_string(), "-b:v", "0"]);
            cap(&mut codec);
            codec.extend(v(&["-bf", "0"]));
            if !av1 {
                codec.extend(v(&["-profile:v", "high"]));
            }
            // decoded on the card, handed back as ordinary frames: the scale filter and odd formats keep working
            HwArgs { decode: if decode_on_card { v(&["-hwaccel", "cuda"]) } else { vec![] }, filter: "format=yuv420p".into(), codec }
        }
        Api::Vaapi => {
            let mut decode = v(&["-vaapi_device", &e.device]);
            if decode_on_card {
                decode = v(&["-hwaccel", "vaapi", "-hwaccel_device", &e.device, "-vaapi_device", &e.device]);
            }
            // VBR with a cap where there is one, else constant quality: the two modes every Intel and AMD driver has.
            // AV1's quality scale runs to 255 instead of 51.
            let mut codec = v(&["-c:v", if av1 { "av1_vaapi" } else { "h264_vaapi" }]);
            if maxrate > 0 {
                codec.extend(["-rc_mode".into(), "VBR".into(), "-b:v".into(), format!("{}k", maxrate * 7 / 10)]);
                cap(&mut codec);
            } else {
                codec.extend(["-rc_mode".into(), "CQP".into(), "-qp".into(), (if av1 { crf as u32 * 4 } else { crf as u32 }).to_string()]);
            }
            if !av1 {
                codec.extend(v(&["-profile:v", "high"]));
            }
            HwArgs { decode, filter: "format=nv12,hwupload".into(), codec }
        }
        Api::Qsv => {
            // Quick Sync sits on top of the VA-API device on Linux
            let decode = v(&["-init_hw_device", &format!("vaapi=va:{}", e.device), "-init_hw_device", "qsv=hw@va", "-filter_hw_device", "hw"]);
            let mut codec = v(&["-c:v", if av1 { "av1_qsv" } else { "h264_qsv" }, "-preset", "veryfast", "-global_quality", &crf.to_string()]);
            cap(&mut codec);
            HwArgs { decode, filter: "format=nv12,hwupload=extra_hw_frames=64,format=qsv".into(), codec }
        }
    }
}

fn encoders(ffmpeg: &str) -> String {
    std::process::Command::new(ffmpeg).args(["-hide_banner", "-encoders"]).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
}

fn has(list: &str, enc: &str) -> bool {
    list.split_whitespace().any(|w| w == enc)
}

/// A one-second test picture through the encoder. Many encoders are compiled into ffmpeg but only work with the
/// right driver, so this is the only honest check.
fn try_encode(ffmpeg: &str, e: &Encoder, av1: bool) -> bool {
    let a = hw_args(e, av1, 28, 2000, false);
    let mut args = v(&["-hide_banner", "-loglevel", "error", "-nostdin"]);
    args.extend(a.decode);
    args.extend(v(&["-f", "lavfi", "-i", "testsrc2=size=640x360:rate=25", "-frames:v", "25", "-vf", &a.filter]));
    args.extend(a.codec);
    args.extend(v(&["-f", "null", "-"]));
    let Ok(mut child) = std::process::Command::new(ffmpeg).args(&args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() else {
        return false;
    };
    let until = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if std::time::Instant::now() < until => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn driver_hint(vendor: &str) -> String {
    match vendor {
        "intel" => "Install Intel's video driver: sudo apt install intel-media-va-driver-non-free (on Debian, from the non-free section; older Intel chips use i965-va-driver). Then choose \"Check again\".".into(),
        "amd" => "Install the video driver: sudo apt install mesa-va-drivers. Then choose \"Check again\".".into(),
        _ => "Install NVIDIA's own driver (it includes the video encoder; the open \"nouveau\" driver can't convert video). Then choose \"Check again\".".into(),
    }
}

/// Look for cards and test them. Blocking: takes up to a few seconds per card.
pub fn detect(ffmpeg: &str) -> State {
    let cards = find_cards(Path::new("/sys"), Path::new("/dev"));
    let list = encoders(ffmpeg);
    let mut notes = vec![];
    let mut active = None;
    // NVIDIA first (a separate card is usually the stronger one), then Intel, then AMD
    let mut order = cards.clone();
    order.sort_by_key(|c| match c.vendor.as_str() {
        "nvidia" => 0,
        "intel" => 1,
        _ => 2,
    });
    for c in &order {
        if !c.allowed {
            notes.push(format!("{} was found, but Syphon's service user may not use it. On the computer run: sudo usermod -aG render,video syphon && sudo systemctl restart syphon", c.name));
            continue;
        }
        let mut tries: Vec<Api> = vec![];
        match c.vendor.as_str() {
            "nvidia" => tries.push(Api::Nvenc),
            "intel" => tries.extend([Api::Vaapi, Api::Qsv]),
            _ => tries.push(Api::Vaapi),
        }
        let mut worked = false;
        for api in tries {
            let (h, a) = match api {
                Api::Nvenc => ("h264_nvenc", "av1_nvenc"),
                Api::Vaapi => ("h264_vaapi", "av1_vaapi"),
                Api::Qsv => ("h264_qsv", "av1_qsv"),
            };
            if !has(&list, h) {
                continue;
            }
            let mut e = Encoder { api, vendor: c.vendor.clone(), name: c.name.clone(), device: c.device.clone(), h264: false, av1: false };
            e.h264 = try_encode(ffmpeg, &e, false);
            e.av1 = has(&list, a) && try_encode(ffmpeg, &e, true);
            if e.h264 || e.av1 {
                worked = true;
                if active.is_none() {
                    active = Some(e);
                }
                break;
            }
        }
        if !worked {
            if !["h264_nvenc", "h264_vaapi", "h264_qsv"].iter().any(|x| has(&list, x)) {
                notes.push(format!("{} was found, but this computer's ffmpeg was built without hardware encoding. Install your distribution's regular ffmpeg package.", c.name));
            } else {
                notes.push(format!("{} was found, but its video encoder didn't work in a test. {}", c.name, driver_hint(&c.vendor)));
            }
        }
    }
    State { checked: true, cards, active, notes }
}

/// Run the check now and remember the result.
pub fn refresh(ffmpeg: &str) -> State {
    let s = detect(ffmpeg);
    if let Some(e) = &s.active {
        tracing::info!("graphics card for conversions: {} via {:?} (H.264: {}, AV1: {})", e.name, e.api, e.h264, e.av1);
    } else if !s.cards.is_empty() {
        tracing::info!("graphics card found but not used for conversions: {}", s.notes.join(" "));
    }
    *STATE.write().unwrap() = Some(s.clone());
    s
}

/// Test results for the tests: set what the check would have found.
pub fn set_for_test(s: State) {
    *STATE.write().unwrap() = Some(s);
}
