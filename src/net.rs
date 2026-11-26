//! How this node's own lookups leave the machine: cast, genres, descriptions and posters for titles in the library.
//! Only a title (and year) is sent, through Tor when this node uses Tor (the default), so the sites can't see the
//! node's address. Nothing else on the node fetches from the internet (the mesh has its own connections).

use crate::state::App;
use anyhow::Result;
use std::time::Duration;

/// What the route setting really means: "auto" is Tor on a Tor node and direct otherwise.
pub fn effective_route(cfg: &crate::config::Config) -> &str {
    match cfg.lookups.route.as_str() {
        "auto" | "" => {
            if cfg.transport == "tor" {
                "tor"
            } else {
                "direct"
            }
        }
        "proxy" => "tor", // a removed option: never fall back to direct
        other => other,
    }
}

/// An HTTP client that follows the lookup route.
pub fn client_for(app: &App, timeout: Option<Duration>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder().user_agent("Mozilla/5.0 (compatible; syphon)").connect_timeout(Duration::from_secs(45));
    if let Some(t) = timeout {
        b = b.timeout(t);
    }
    b = match effective_route(&app.cfg) {
        "tor" => b.proxy(reqwest::Proxy::all(crate::tor::socks_url(&app.cfg))?),
        _ => b.no_proxy(),
    };
    Ok(b.build()?)
}
