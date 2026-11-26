//! "System-wide VPN → Tor": firewall rules that send this computer's own traffic through Tor.
//!
//! This is a transparent Tor proxy, not a VPN tunnel. Everything the computer itself starts goes to
//! Tor's TransPort (TCP) and DNSPort (DNS). Traffic Tor cannot carry (UDP, IPv6) is rejected rather
//! than leaked. The home network, the loopback interface and the account that runs Syphon/Tor are
//! left alone. Generated as an nftables script so it can be read before it is loaded.

use std::fmt::Write;

pub const TABLE: &str = "syphon_torify";

pub fn nft_rules(uid: u32, trans_port: u16, dns_port: u16) -> String {
    let lan4 = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }";
    let lan6 = "{ fc00::/7, fe80::/10 }";
    let mut s = String::new();
    let _ = writeln!(s, "# Syphon system-wide Tor. Load with: nft -f -   Remove with: nft delete table inet {TABLE}");
    let _ = writeln!(s, "table inet {TABLE} {{");
    // 1. redirect new connections to Tor
    let _ = writeln!(s, "  chain redirect_out {{");
    let _ = writeln!(s, "    type nat hook output priority -100; policy accept;");
    let _ = writeln!(s, "    meta skuid {uid} return");
    let _ = writeln!(s, "    oifname \"lo\" return");
    let _ = writeln!(s, "    ip daddr {lan4} return");
    let _ = writeln!(s, "    ip6 daddr {lan6} return");
    let _ = writeln!(s, "    udp dport 53 redirect to :{dns_port}");
    let _ = writeln!(s, "    meta nfproto ipv4 tcp flags & (fin|syn|rst|ack) == syn redirect to :{trans_port}");
    let _ = writeln!(s, "  }}");
    // 2. kill switch: only what is allowed above may leave
    let _ = writeln!(s, "  chain filter_out {{");
    let _ = writeln!(s, "    type filter hook output priority 0; policy accept;");
    let _ = writeln!(s, "    meta skuid {uid} accept");
    let _ = writeln!(s, "    oifname \"lo\" accept");
    let _ = writeln!(s, "    ct state established,related accept");
    let _ = writeln!(s, "    ip daddr {lan4} accept");
    let _ = writeln!(s, "    ip6 daddr {lan6} accept");
    let _ = writeln!(s, "    # the clock must stay right for Tor to work; this is the one thing allowed around Tor");
    let _ = writeln!(s, "    udp dport 123 accept");
    let _ = writeln!(s, "    reject with icmpx type admin-prohibited");
    let _ = writeln!(s, "  }}");
    let _ = writeln!(s, "}}");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_redirect_to_tor_and_fail_closed() {
        let r = nft_rules(998, 9251, 9253);
        assert!(r.contains("meta skuid 998 return"), "tor's own account must be exempt or it loops");
        assert!(r.contains("udp dport 53 redirect to :9253"));
        assert!(r.contains("redirect to :9251"));
        assert!(r.contains("192.168.0.0/16"), "the home network stays reachable");
        let kill = r.rfind("reject").unwrap();
        let last_accept = r.rfind("accept").unwrap();
        assert!(kill > last_accept, "the reject must come after every accept");
        assert!(r.trim_end().ends_with('}'));
    }
}
