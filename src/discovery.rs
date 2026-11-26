//! Finding this node on the home network, for the Syphon app: the app sends `SYPHON-DISCOVER 1` as a broadcast on UDP
//! port 8095 and every node answers with its name and the port of its web app. Only devices on a home network get an
//! answer (private, link-local or loopback addresses), and nothing secret is in it: the app still has to sign in.
//! A broadcast does not cross into another network segment (VLAN); the app then lets you type the address instead.

use crate::state::Shared;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const PORT: u16 = 8095;
pub const ASK: &[u8] = b"SYPHON-DISCOVER 1";

fn home_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// The answer: who this is and where its web app listens.
pub fn answer(app: &Shared) -> String {
    let port: u16 = app.cfg.access_bind.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(8096);
    serde_json::json!({ "syphon": 1, "name": app.cfg.name, "id": app.id.id.chars().take(16).collect::<String>(), "port": port }).to_string()
}

/// Answer discovery requests until the node stops. Does nothing when the web app only listens on this computer.
pub async fn run(app: Shared, port: u16) {
    if app.cfg.access_bind.starts_with("127.") {
        return;
    }
    let sock = match tokio::net::UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("the app cannot find this node by itself (UDP port {port}: {e}); type its address in the app instead");
            return;
        }
    };
    tracing::info!("the Syphon app can find this node on the home network (UDP {port})");
    let mut buf = [0u8; 64];
    let mut recent: Vec<(SocketAddr, Instant)> = vec![];
    loop {
        let (n, from) = tokio::select! {
            r = sock.recv_from(&mut buf) => match r { Ok(x) => x, Err(_) => { tokio::time::sleep(Duration::from_millis(200)).await; continue } },
            _ = app.shutdown.notified() => return,
        };
        if &buf[..n] != ASK || !home_address(from.ip()) {
            continue;
        }
        // a handful of answers per second at most, whatever floods the port
        recent.retain(|(_, t)| t.elapsed() < Duration::from_secs(1));
        if recent.len() >= 20 {
            continue;
        }
        recent.push((from, Instant::now()));
        let _ = sock.send_to(answer(&app).as_bytes(), from).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_home_networks_are_answered() {
        for ok in ["192.168.1.5", "10.0.0.2", "172.16.4.4", "127.0.0.1", "169.254.1.1", "fe80::1", "fd00::5"] {
            assert!(home_address(ok.parse().unwrap()), "{ok}");
        }
        for no in ["8.8.8.8", "100.64.0.1", "2001:db8::1"] {
            assert!(!home_address(no.parse().unwrap()), "{no}");
        }
    }
}
