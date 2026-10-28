//! The link to the owner's VPN box (syphon-vpn, a separate device at home): Syphon lists the box's devices, makes
//! codes for new ones and removes old ones, so the owner never has to log in to the box for that.
//!
//! The box prints a link code (`sudo syphon-vpn link`): its home-network address and a 32-byte key. Every request and
//! answer is sealed with that key (XChaCha20-Poly1305), time-stamped and carries a fresh nonce, and an answer is bound
//! to its request. The box only listens to this node's address. The format matches syphon-vpn's `manage.rs`.

use crate::state::App;
use anyhow::{anyhow, bail, Result};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const LINK_PREFIX: &str = "SYPHON-VPNBOX-1:";
const AAD_REQ: &[u8] = b"syphon-vpn-manage request v1";
const AAD_RESP: &str = "syphon-vpn-manage response v1|";
const SETTING: &str = "vpn_box_link";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Link {
    pub v: u32,
    pub name: String,
    /// the box on the home network, "192.168.1.30:51822"
    #[serde(rename = "box")]
    pub addr: String,
    pub key: String,
}

impl Link {
    fn key(&self) -> Result<[u8; 32]> {
        b64().decode(&self.key).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| anyhow!("the saved link to the VPN box is damaged; link it again"))
    }
    pub fn ip(&self) -> Option<std::net::IpAddr> {
        self.addr.parse::<std::net::SocketAddr>().ok().map(|a| a.ip())
    }
}

pub fn decode_link(s: &str) -> Result<Link> {
    let damaged = || anyhow!("The link code is damaged. Copy it again, all of it.");
    let s = s.trim();
    if s.starts_with("SYPHON-VPN-1:") {
        bail!("That is a code for a device's Syphon app. The link code comes from the box: sudo syphon-vpn link");
    }
    let body = s.strip_prefix(LINK_PREFIX).ok_or_else(|| anyhow!("That is not a link code from a VPN box. On the box, run: sudo syphon-vpn link"))?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body.trim()).map_err(|_| damaged())?;
    let l: Link = serde_json::from_slice(&raw).map_err(|_| damaged())?;
    if l.v != 1 {
        bail!("This link code is from a newer VPN box. Update Syphon.");
    }
    let ip = l.ip().ok_or_else(damaged)?;
    if !crate::security::is_private_ip(ip) || ip.is_loopback() {
        bail!("The link code names {ip}, which is not a home-network address. Run sudo syphon-vpn link on the box again.");
    }
    l.key()?;
    Ok(l)
}

pub fn saved(app: &App) -> Option<Link> {
    serde_json::from_str(&app.db.get_setting(SETTING).ok()??).ok()
}

pub fn save(app: &App, l: Option<&Link>) -> Result<()> {
    app.db.set_setting(SETTING, &l.map(|l| serde_json::to_string(l).expect("serialises")).unwrap_or_default())
}

fn seal(k: &[u8; 32], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut n = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
    let c = XChaCha20Poly1305::new(k.into()).encrypt(XNonce::from_slice(&n), Payload { msg: plain, aad }).expect("seals");
    [n.to_vec(), c].concat()
}

fn open(k: &[u8; 32], aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 40 {
        bail!("too short");
    }
    XChaCha20Poly1305::new(k.into()).decrypt(XNonce::from_slice(&data[..24]), Payload { msg: &data[24..], aad }).map_err(|_| anyhow!("not sealed with the link key"))
}

/// One request to the box: "status", "list", "add" (with a name) or "remove" (with a name).
pub async fn call(l: &Link, cmd: &str, name: Option<&str>) -> Result<Value> {
    let k = l.key()?;
    let mut n = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
    let nonce: String = n.iter().map(|b| format!("{b:02x}")).collect();
    let plain = json!({ "ts": crate::util::now(), "nonce": nonce, "cmd": cmd, "name": name }).to_string();
    let body = b64().encode(seal(&k, AAD_REQ, plain.as_bytes()));
    let c = reqwest::Client::builder().no_proxy().connect_timeout(std::time::Duration::from_secs(4)).timeout(std::time::Duration::from_secs(20)).build()?;
    let r = c.post(format!("http://{}/manage", l.addr)).body(body).send().await.map_err(|e| {
        anyhow!("The VPN box at {} did not answer ({}). Is it on, and is syphon-vpn up to date on it?", l.addr, if e.is_timeout() || e.is_connect() { "no connection" } else { "connection failed" })
    })?;
    let status = r.status();
    let text = r.text().await.unwrap_or_default();
    if status.as_u16() == 403 {
        bail!("The VPN box refused: {}", text.chars().take(200).collect::<String>());
    }
    if !status.is_success() {
        bail!("The VPN box answered {status}. Is syphon-vpn up to date on it?");
    }
    let raw = b64().decode(text.trim()).map_err(|_| anyhow!("The VPN box's answer is damaged."))?;
    let plain = open(&k, format!("{AAD_RESP}{nonce}").as_bytes(), &raw).map_err(|_| anyhow!("The VPN box's answer is not sealed with the link key. Link the box again (sudo syphon-vpn link)."))?;
    let v: Value = serde_json::from_slice(&plain)?;
    if v["ok"] != true {
        bail!("{}", v["error"].as_str().unwrap_or("The VPN box could not do that."));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_codes_are_read_and_wrong_ones_explained() {
        let l = Link { v: 1, name: "Living Room".into(), addr: "192.168.1.30:51822".into(), key: b64().encode([3u8; 32]) };
        let code = format!("{LINK_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&l).unwrap()));
        assert_eq!(decode_link(&format!(" {code}\n")).unwrap(), l);
        assert!(decode_link("SYPHON-VPN-1:abc").unwrap_err().to_string().contains("device's Syphon app"));
        assert!(decode_link(&code[..code.len() - 5]).is_err());
        let public = Link { addr: "8.8.8.8:51822".into(), ..l.clone() };
        let code = format!("{LINK_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&public).unwrap()));
        assert!(decode_link(&code).is_err(), "only a home-network box");
    }

    #[test]
    fn sealing_matches_both_ways() {
        let k = [5u8; 32];
        let s = seal(&k, AAD_REQ, b"hello");
        assert_eq!(open(&k, AAD_REQ, &s).unwrap(), b"hello");
        assert!(open(&k, b"other", &s).is_err() && open(&[6u8; 32], AAD_REQ, &s).is_err());
    }
}
