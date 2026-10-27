//! Sign-in security.
//!
//! Two zones decide how much a request is trusted:
//!   * **Lan**    : arrived on the home-network listener from a private address.
//!   * **Remote** : arrived through the Tor access onion service (or from a public address).
//!
//! Over Tor the node cannot see the visitor's IP address (that is Tor's whole point), so an IP
//! allow-list cannot work there. The same idea is applied to *devices* instead: a device becomes
//! trusted when it signs in from the home network, or when a remote sign-in is confirmed by an
//! authenticator code (TOTP) or approved from a signed-in device at home. A password alone never
//! creates a session from outside the home network on a device the node does not recognise.

use crate::auth::{check_pw, hash_pw};
use crate::state::{App, Shared};
use crate::totp;
use crate::util::{now, random_hex};
use anyhow::{anyhow, bail, Result};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Via {
    Lan,
    Tor,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    Lan,
    Remote,
}

impl Zone {
    pub fn as_str(&self) -> &'static str {
        match self {
            Zone::Lan => "lan",
            Zone::Remote => "remote",
        }
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        o => o,
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        o => o,
    }
}

/// The home-network addresses of the owner's VPN boxes (syphon-vpn). Their visitors come from outside, even though
/// the box itself sits at home: requests from these addresses are Remote.
static VPN_BOXES: std::sync::RwLock<Vec<IpAddr>> = std::sync::RwLock::new(Vec::new());

pub fn set_vpn_boxes(v: Vec<IpAddr>) {
    *VPN_BOXES.write().unwrap() = v.into_iter().map(plain).collect();
}
pub fn vpn_boxes() -> Vec<IpAddr> {
    VPN_BOXES.read().unwrap().clone()
}
pub fn is_vpn_box(ip: IpAddr) -> bool {
    VPN_BOXES.read().unwrap().contains(&plain(ip))
}
pub fn set_tor_access(app: &App, on: bool) {
    app.tor_access.store(on, std::sync::atomic::Ordering::Relaxed);
}
pub fn tor_access(app: &App) -> bool {
    app.tor_access.load(std::sync::atomic::Ordering::Relaxed)
}

/// Read the two settings above from the database (at start).
pub fn load_outside_settings(app: &App) {
    let boxes = app.db.get_setting("vpn_boxes").ok().flatten().unwrap_or_default();
    set_vpn_boxes(boxes.split(',').filter_map(|x| x.trim().parse().ok()).collect());
    set_tor_access(app, app.db.get_setting("tor_access").ok().flatten().as_deref() != Some("off"));
}

/// Everything that arrives through Tor is Remote. A visitor on the home listener is only trusted as
/// "at home" when their address is a private one: a port-forwarded public visitor is Remote, and so is anyone coming
/// through the owner's VPN box.
pub fn zone_for(via: Via, ip: Option<IpAddr>) -> Zone {
    if via == Via::Lan && ip.map(|i| is_private_ip(i) && !is_vpn_box(i)).unwrap_or(false) {
        Zone::Lan
    } else {
        Zone::Remote
    }
}

/// Actions that change who can reach the node (pairing, people, passwords, security) only work from home.
pub fn require_local(zone: Zone) -> Result<()> {
    if zone == Zone::Lan {
        Ok(())
    } else {
        bail!("For your safety this can only be done from your home network, not from outside.")
    }
}

/// Addresses other devices on the home network can use to open this node ("" bind = nothing).
pub fn lan_urls(access_bind: &str) -> Vec<String> {
    let port: u16 = access_bind.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(8096);
    if access_bind.starts_with("127.") {
        return vec![];
    }
    let mut urls = vec![];
    if let Ok(ifs) = if_addrs::get_if_addrs() {
        for i in ifs {
            let ip = i.ip();
            if ip.is_ipv4() && !ip.is_loopback() && is_private_ip(ip) {
                urls.push(format!("http://{ip}:{port}"));
            }
        }
    }
    urls
}

// ------------------------------------------------------------------ lockouts

fn delay_for(fails: u32) -> i64 {
    if fails < 5 { 0 } else { (30 * (fails as i64 - 4)).min(900) }
}

fn lock_key(zone: Zone, user: &str) -> String {
    format!("{}:{}", zone.as_str(), user.trim().to_lowercase())
}

fn lock_remaining(app: &App, key: &str) -> Option<i64> {
    let g = app.login_fails.lock().unwrap();
    let (n, last) = *g.get(key)?;
    if now() - last > 3600 {
        return None;
    }
    let d = delay_for(n);
    if d > 0 && now() < last + d { Some(last + d - now()) } else { None }
}

fn record_fail(app: &App, key: &str) {
    let mut g = app.login_fails.lock().unwrap();
    if g.len() > 5000 {
        let t = now();
        g.retain(|_, (_, last)| t - *last < 3600);
    }
    let e = g.entry(key.to_string()).or_insert((0, 0));
    if now() - e.1 > 3600 {
        e.0 = 0;
    }
    e.0 += 1;
    e.1 = now();
}

fn clear_fails(app: &App, key: &str) {
    app.login_fails.lock().unwrap().remove(key);
}

fn human(secs: i64) -> String {
    if secs >= 90 { format!("{} minutes", (secs + 59) / 60) } else { format!("{secs} seconds") }
}

// ------------------------------------------------------------------ trusted devices

fn dev_hash(secret: &str) -> String {
    blake3::hash(secret.as_bytes()).to_hex().to_string()
}

pub fn find_device(app: &App, user: &str, cookie: &str) -> Option<String> {
    let (id, secret) = cookie.split_once('.')?;
    let want = dev_hash(secret);
    app.db
        .with(|c| Ok(c.query_row("SELECT token_hash FROM devices WHERE id=?1 AND user=?2", params![id, user], |r| r.get::<_, String>(0)).optional()?))
        .ok()
        .flatten()
        .filter(|h| *h == want)
        .map(|_| id.to_string())
}

/// Registers a trusted device and returns the cookie value that identifies it.
pub fn new_device(app: &App, user: &str, name: &str, zone: Zone) -> Result<String> {
    let id = random_hex(8);
    let secret = random_hex(24);
    app.db.with(|c| {
        c.execute(
            "INSERT INTO devices(id,user,name,token_hash,created,last_seen,last_via) VALUES(?1,?2,?3,?4,?5,?5,?6)",
            params![id, user, name, dev_hash(&secret), now(), zone.as_str()],
        )?;
        Ok(())
    })?;
    Ok(format!("{id}.{secret}"))
}

fn touch_device(app: &App, id: &str, zone: Zone) {
    let _ = app.db.with(|c| {
        c.execute("UPDATE devices SET last_seen=?2,last_via=?3 WHERE id=?1", params![id, now(), zone.as_str()])?;
        Ok(())
    });
}

#[derive(Serialize, Clone, Debug)]
pub struct DeviceInfo {
    pub id: String,
    pub user: String,
    pub name: String,
    pub created: i64,
    pub last_seen: i64,
    pub last_via: String,
    /// an app on this device may sign this person in again without the password
    pub remember: bool,
}

pub fn list_devices(app: &App, user: Option<&str>) -> Result<Vec<DeviceInfo>> {
    app.db.with(|c| {
        let mut st = c.prepare("SELECT id,user,name,created,last_seen,last_via,remember FROM devices WHERE (?1 IS NULL OR user=?1) ORDER BY last_seen DESC")?;
        let rows = st.query_map([user], |r| {
            Ok(DeviceInfo { id: r.get(0)?, user: r.get(1)?, name: r.get(2)?, created: r.get(3)?, last_seen: r.get(4)?, last_via: r.get(5)?, remember: r.get::<_, i64>(6)? != 0 })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

/// Remember (or forget) the device this cookie belongs to, for its own user. Remembered means an app on that device may
/// sign the person in again without the password ("Who's watching?" on a TV or a shared computer).
pub fn set_remember(app: &App, user: &str, dev_cookie: &str, on: bool) -> Result<()> {
    let id = find_device(app, user, dev_cookie).ok_or_else(|| anyhow::anyhow!("this browser is not a trusted device yet"))?;
    app.db.with(|c| {
        c.execute("UPDATE devices SET remember=?2 WHERE id=?1", params![id, on as i64])?;
        Ok(())
    })
}

/// Sign in on a remembered device without the password. Removing the device under Trusted devices ends this at once.
pub fn login_remembered(app: &App, zone: Zone, dev_cookie: Option<&str>, user: &str) -> LoginOutcome {
    let fail = |status: u16, msg: &str| LoginOutcome::Fail { status, msg: msg.to_string() };
    let key = lock_key(zone, user);
    if let Some(s) = lock_remaining(app, &key) {
        return fail(429, &format!("Too many attempts. Please try again in {}.", human(s)));
    }
    let Some(id) = dev_cookie.and_then(|c| find_device(app, user, c)) else {
        record_fail(app, &key);
        return fail(401, "This device no longer remembers that person. Sign in with the password.");
    };
    let remembered = app.db.with(|c| Ok(c.query_row("SELECT remember FROM devices WHERE id=?1", [&id], |r| r.get::<_, i64>(0))?)).unwrap_or(0) != 0;
    let role: Option<String> = app.db.with(|c| Ok(c.query_row("SELECT role FROM users WHERE name=?1", [user], |r| r.get(0)).optional()?)).unwrap_or(None);
    let (true, Some(role)) = (remembered, role) else {
        record_fail(app, &key);
        return fail(401, "This device no longer remembers that person. Sign in with the password.");
    };
    if !app.keyring.is_unlocked() {
        return fail(503, "This node was restarted and is waiting for its owner to sign in with the password first.");
    }
    clear_fails(app, &key);
    touch_device(app, &id, zone);
    let session = app.new_session(user, &role, zone);
    LoginOutcome::Ok { user: user.to_string(), role, session, device_cookie: None }
}

/// Removing a device means it has to be approved again the next time it signs in remotely.
pub fn revoke_device(app: &App, id: &str, only_user: Option<&str>) -> Result<()> {
    let n = app.db.with(|c| Ok(c.execute("DELETE FROM devices WHERE id=?1 AND (?2 IS NULL OR user=?2)", params![id, only_user])?))?;
    if n == 0 {
        bail!("no such device");
    }
    Ok(())
}

// ------------------------------------------------------------------ approvals

const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
pub const APPROVAL_TTL: i64 = 600;

fn short_code() -> String {
    use rand::Rng;
    let mut r = rand::rngs::OsRng;
    let s: String = (0..6).map(|_| CODE_ALPHABET[r.gen_range(0..CODE_ALPHABET.len())] as char).collect();
    format!("{}-{}", &s[..3], &s[3..])
}

/// A remote sign-in from an unrecognised device waits here until a signed-in device at home says yes.
pub fn approval_create(app: &App, user: &str, device_name: &str) -> Result<(String, String, String)> {
    if !app.keyring.is_unlocked() {
        bail!("This node was restarted and is waiting for its owner. Sign in once from your home network to unlock it.");
    }
    let pending: i64 = app.db.with(|c| {
        Ok(c.query_row("SELECT COUNT(*) FROM approvals WHERE user=?1 AND status='pending' AND created>?2", params![user, now() - APPROVAL_TTL], |r| r.get(0))?)
    })?;
    if pending >= 3 {
        bail!("Several sign-in requests are already waiting. Approve or wait for them to expire.");
    }
    let (id, secret, code) = (random_hex(8), random_hex(16), short_code());
    app.db.with(|c| {
        c.execute("DELETE FROM approvals WHERE created<?1", [now() - 86400])?;
        c.execute(
            "INSERT INTO approvals(id,user,device_name,code,secret_hash,status,created) VALUES(?1,?2,?3,?4,?5,'pending',?6)",
            params![id, user, device_name, code, dev_hash(&secret), now()],
        )?;
        Ok(())
    })?;
    Ok((id, secret, code))
}

#[derive(Serialize, Clone, Debug)]
pub struct ApprovalInfo {
    pub id: String,
    pub user: String,
    pub device_name: String,
    pub code: String,
    pub created: i64,
}

pub fn approvals_pending(app: &App, only_user: Option<&str>) -> Result<Vec<ApprovalInfo>> {
    app.db.with(|c| {
        let mut st = c.prepare(
            "SELECT id,user,device_name,code,created FROM approvals WHERE status='pending' AND created>?1 AND (?2 IS NULL OR user=?2) ORDER BY created",
        )?;
        let rows = st.query_map(params![now() - APPROVAL_TTL, only_user], |r| {
            Ok(ApprovalInfo { id: r.get(0)?, user: r.get(1)?, device_name: r.get(2)?, code: r.get(3)?, created: r.get(4)? })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

pub fn approval_decide(app: &App, id: &str, approve: bool, only_user: Option<&str>) -> Result<()> {
    let n = app.db.with(|c| {
        Ok(c.execute(
            "UPDATE approvals SET status=?2 WHERE id=?1 AND status='pending' AND created>?3 AND (?4 IS NULL OR user=?4)",
            params![id, if approve { "approved" } else { "denied" }, now() - APPROVAL_TTL, only_user],
        )?)
    })?;
    if n == 0 {
        bail!("that request is no longer waiting");
    }
    Ok(())
}

pub enum Poll {
    Pending,
    Denied,
    Expired,
    Approved { user: String, role: String, device_name: String },
}

/// The remote device polls with the secret it was given. An approval can be redeemed exactly once.
pub fn approval_poll(app: &App, id: &str, secret: &str) -> Result<Poll> {
    let row: Option<(String, String, String, String, i64, i64)> = app.db.with(|c| {
        Ok(c.query_row("SELECT user,secret_hash,status,device_name,created,consumed FROM approvals WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
        })
        .optional()?)
    })?;
    let Some((user, hash, status, device_name, created, consumed)) = row else { return Ok(Poll::Expired) };
    if hash != dev_hash(secret) || consumed != 0 || now() - created > APPROVAL_TTL {
        return Ok(Poll::Expired);
    }
    match status.as_str() {
        "pending" => Ok(Poll::Pending),
        "denied" => Ok(Poll::Denied),
        "approved" => {
            let role: Option<String> = app.db.with(|c| Ok(c.query_row("SELECT role FROM users WHERE name=?1", [&user], |r| r.get(0)).optional()?))?;
            let Some(role) = role else { return Ok(Poll::Expired) };
            // single use: only the call that flips `consumed` wins
            let n = app.db.with(|c| Ok(c.execute("UPDATE approvals SET consumed=1 WHERE id=?1 AND consumed=0", [id])?))?;
            if n == 0 {
                return Ok(Poll::Expired);
            }
            Ok(Poll::Approved { user, role, device_name })
        }
        _ => Ok(Poll::Expired),
    }
}

/// Turn a redeemed approval into a session plus a trusted-device cookie.
pub fn complete_approved(app: &App, user: &str, role: &str, device_label: &str) -> Result<(String, String)> {
    let cookie = new_device(app, user, device_label, Zone::Remote)?;
    Ok((app.new_session(user, role, Zone::Remote), cookie))
}

// ------------------------------------------------------------------ TOTP management

pub fn totp_enabled(app: &App, user: &str) -> bool {
    app.db
        .with(|c| Ok(c.query_row("SELECT totp_enabled FROM users WHERE name=?1", [user], |r| r.get::<_, i64>(0))?))
        .map(|v| v != 0)
        .unwrap_or(false)
}

/// Starts enrolment: stores a fresh secret that stays inactive until confirmed with a code.
pub fn totp_start(app: &App, user: &str) -> Result<(String, String)> {
    let secret = totp::new_secret();
    let n = app.db.with(|c| Ok(c.execute("UPDATE users SET totp_secret=?2, totp_enabled=0, totp_last=0 WHERE name=?1", params![user, secret])?))?;
    if n == 0 {
        bail!("no such user");
    }
    let uri = totp::uri(user, &secret);
    Ok((secret, uri))
}

pub fn totp_confirm(app: &App, user: &str, code: &str) -> Result<()> {
    let secret: Option<String> = app.db.with(|c| Ok(c.query_row("SELECT totp_secret FROM users WHERE name=?1", [user], |r| r.get(0))?))?;
    let secret = secret.ok_or_else(|| anyhow!("start the setup first"))?;
    let step = totp::verify(&secret, code, now(), 0).ok_or_else(|| anyhow!("That code did not match. Check the clock on your phone and try the next code."))?;
    app.db.with(|c| {
        c.execute("UPDATE users SET totp_enabled=1, totp_last=?2 WHERE name=?1", params![user, step as i64])?;
        Ok(())
    })
}

pub fn totp_disable(app: &App, user: &str) -> Result<()> {
    app.db.with(|c| {
        c.execute("UPDATE users SET totp_secret=NULL, totp_enabled=0, totp_last=0 WHERE name=?1", [user])?;
        Ok(())
    })
}

// ------------------------------------------------------------------ the sign-in

pub struct LoginReq {
    pub user: String,
    pub password: String,
    pub totp: Option<String>,
    pub device_name: Option<String>,
}

pub enum LoginOutcome {
    Ok { user: String, role: String, session: String, device_cookie: Option<String> },
    NeedTotp,
    Pending { id: String, secret: String, code: String },
    Fail { status: u16, msg: String },
}

/// Same message for "no such user" and "wrong password", so the sign-in cannot be used to find names.
pub const GENERIC_FAIL: &str = "Those details did not work. Check the name and password and try again.";

fn clean_label(s: Option<&str>) -> String {
    let t: String = s.unwrap_or("").chars().filter(|c| !c.is_control()).take(60).collect();
    let t = t.trim().to_string();
    if t.is_empty() { "Unnamed device".into() } else { t }
}

struct UserRow {
    name: String,
    pw_hash: String,
    role: String,
    totp_secret: Option<String>,
    totp_enabled: bool,
    totp_last: i64,
}

pub async fn login(app: &Shared, zone: Zone, dev_cookie: Option<&str>, req: LoginReq) -> LoginOutcome {
    let fail = |status: u16, msg: &str| LoginOutcome::Fail { status, msg: msg.to_string() };
    let name_in = req.user.trim().to_string();
    if name_in.is_empty() || req.password.is_empty() || name_in.len() > 80 || req.password.len() > 1024 {
        return fail(401, GENERIC_FAIL);
    }
    let key = lock_key(zone, &name_in);
    if let Some(s) = lock_remaining(app, &key) {
        return fail(429, &format!("Too many attempts. Please try again in {}.", human(s)));
    }
    let Ok(_permit) = app.login_gate.acquire().await else { return fail(503, "Busy, try again") };

    let row: Option<UserRow> = app
        .db
        .with(|c| {
            Ok(c.query_row("SELECT name,pw_hash,role,totp_secret,totp_enabled,totp_last FROM users WHERE name=?1", [&name_in], |r| {
                Ok(UserRow { name: r.get(0)?, pw_hash: r.get(1)?, role: r.get(2)?, totp_secret: r.get(3)?, totp_enabled: r.get::<_, i64>(4)? != 0, totp_last: r.get(5)? })
            })
            .optional()?)
        })
        .unwrap_or(None);

    let pw = req.password.clone();
    let a2 = app.clone();
    let probe = row.as_ref().map(|r| (r.pw_hash.clone(), r.role.clone()));
    let pw_ok = tokio::task::spawn_blocking(move || match probe {
        Some((h, role)) => {
            // After a restart only the owner's password can be checked (it also unlocks the library).
            if role == "owner" && !a2.keyring.is_unlocked() { a2.keyring.verify_password(&pw) } else { check_pw(&h, &pw) }
        }
        None => {
            let _ = hash_pw(&pw); // comparable work for unknown names
            false
        }
    })
    .await
    .unwrap_or(false);
    let Some(row) = row.filter(|_| pw_ok) else {
        record_fail(app, &key);
        return fail(401, GENERIC_FAIL);
    };

    let label = clean_label(req.device_name.as_deref());
    let trusted = dev_cookie.and_then(|c| find_device(app, &row.name, c));
    let mut device_id = trusted.clone();
    let mut new_cookie: Option<String> = None;
    if trusted.is_none() {
        match zone {
            // a new device on your home network is trusted straight away
            Zone::Lan => {
                if let Ok(c) = new_device(app, &row.name, &label, zone) {
                    device_id = c.split_once('.').map(|(i, _)| i.to_string());
                    new_cookie = Some(c);
                }
            }
            Zone::Remote => {
                if row.totp_enabled {
                    let secret = row.totp_secret.clone().unwrap_or_default();
                    match req.totp.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
                        None => return LoginOutcome::NeedTotp,
                        Some(code) => match totp::verify(&secret, code, now(), row.totp_last as u64) {
                            Some(step) => {
                                let _ = app.db.with(|c| {
                                    c.execute("UPDATE users SET totp_last=?2 WHERE name=?1", params![row.name, step as i64])?;
                                    Ok(())
                                });
                                if let Ok(c) = new_device(app, &row.name, &label, zone) {
                                    device_id = c.split_once('.').map(|(i, _)| i.to_string());
                                    new_cookie = Some(c);
                                }
                            }
                            None => {
                                record_fail(app, &key);
                                return fail(401, GENERIC_FAIL);
                            }
                        },
                    }
                } else {
                    return match approval_create(app, &row.name, &label) {
                        Ok((id, secret, code)) => LoginOutcome::Pending { id, secret, code },
                        Err(e) => fail(429, &e.to_string()),
                    };
                }
            }
        }
    }

    if !app.keyring.is_unlocked() {
        if row.role != "owner" {
            return fail(503, "This node was restarted and is waiting for its owner to sign in first.");
        }
        let (a3, pw3) = (app.clone(), req.password.clone());
        let ok = tokio::task::spawn_blocking(move || a3.keyring.unlock(&pw3).is_ok()).await.unwrap_or(false);
        if !ok {
            return fail(500, "Could not unlock the library");
        }
        let a4 = app.clone();
        tokio::spawn(async move {
            crate::lifecycle::on_unlock(&a4).await;
        });
    }
    clear_fails(app, &key);
    if let Some(id) = &device_id {
        touch_device(app, id, zone);
    }
    let session = app.new_session(&row.name, &row.role, zone);
    LoginOutcome::Ok { user: row.name, role: row.role, session, device_cookie: new_cookie }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_addresses() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.9", "172.16.5.5", "169.254.1.1", "100.100.1.1", "::1", "fd12::1", "fe80::1", "::ffff:192.168.1.5"] {
            assert!(is_private_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "93.184.216.34", "100.1.1.1", "2606:4700::1111"] {
            assert!(!is_private_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn zones_depend_on_listener_and_address() {
        let lan: IpAddr = "192.168.1.20".parse().unwrap();
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(zone_for(Via::Lan, Some(lan)), Zone::Lan);
        assert_eq!(zone_for(Via::Lan, Some(public)), Zone::Remote, "a port-forwarded public visitor is remote");
        assert_eq!(zone_for(Via::Tor, Some("127.0.0.1".parse().unwrap())), Zone::Remote, "everything via Tor is remote");
        assert_eq!(zone_for(Via::Lan, None), Zone::Remote);
        set_vpn_boxes(vec!["192.168.1.30".parse().unwrap()]);
        assert_eq!(zone_for(Via::Lan, Some("192.168.1.30".parse().unwrap())), Zone::Remote, "visitors through the VPN box come from outside");
        assert_eq!(zone_for(Via::Lan, Some("::ffff:192.168.1.30".parse().unwrap())), Zone::Remote, "also as an IPv6-mapped address");
        assert_eq!(zone_for(Via::Lan, Some("192.168.1.31".parse().unwrap())), Zone::Lan);
        set_vpn_boxes(vec![]);
        assert!(require_local(Zone::Lan).is_ok() && require_local(Zone::Remote).is_err());
    }

    #[test]
    fn backoff_grows_after_five_failures() {
        assert_eq!(delay_for(4), 0);
        assert_eq!(delay_for(5), 30);
        assert_eq!(delay_for(6), 60);
        assert_eq!(delay_for(100), 900);
        assert_eq!(short_code().len(), 7);
    }
}
