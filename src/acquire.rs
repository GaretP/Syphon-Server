//! Search and download.
//!
//! A `Provider` knows how to search one source and resolve a result to a downloadable file.
//! Providers shipped here: Internet Archive (public collections, filter configurable) and RSS
//! feeds you configure yourself. Adding a source means implementing the trait; the queue, the
//! network route (direct / Tor), encryption and the review area are shared.
//! Downloads never go straight into the library: they land in the isolated review area.

use crate::config::RssFeed;
use crate::library::{post_ingest, IngestSession};
use crate::state::{App, Shared};
use crate::util::{now, random_hex};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use regex::Regex;
use rusqlite::params;
use serde::Serialize;
use std::time::Duration;

#[derive(Serialize, Clone, Debug)]
pub struct Candidate {
    pub provider: String,
    pub title: String,
    pub year: Option<i32>,
    /// opaque to the UI: handed back to `resolve`
    pub url: String,
    pub size: Option<u64>,
    pub note: Option<String>,
    /// what the source says it is (movie, series, anime) when it knows; the UI passes it back when queuing
    pub kind: Option<String>,
}

#[derive(Default)]
pub struct Resolved {
    pub url: String,
    pub filename: String,
    /// extra request headers (tokens for Plex / Jellyfin); never shown to the UI
    pub headers: Vec<(String, String)>,
    /// the address was chosen by the owner when adding the source, so private addresses are allowed
    pub trusted: bool,
}

#[async_trait]
pub trait Provider: Send + Sync {
    fn id(&self) -> String;
    fn label(&self) -> String;
    async fn search(&self, http: &reqwest::Client, q: &str) -> Result<Vec<Candidate>>;
    async fn resolve(&self, http: &reqwest::Client, url: &str) -> Result<Resolved>;
    /// True for the owner's own server on the home network (reached directly, not through Tor).
    fn on_lan(&self) -> bool {
        false
    }
}

pub fn providers(app: &App) -> Vec<Box<dyn Provider>> {
    let mut v: Vec<Box<dyn Provider>> = vec![];
    if app.cfg.acquire.internet_archive {
        v.push(Box::new(InternetArchive { filter: app.cfg.acquire.ia_filter.clone() }));
    }
    for f in &app.cfg.acquire.rss {
        v.push(Box::new(RssProvider { feed: f.clone() }));
    }
    for src in load_sources(app) {
        match src.kind.as_str() {
            "plex" => v.push(Box::new(PlexProvider { src })),
            "jellyfin" => v.push(Box::new(JellyfinProvider { src })),
            _ => {}
        }
    }
    v.push(Box::new(DirectLink));
    v
}

// -------------------------------------------------------------- your own servers (Plex, Jellyfin)

#[derive(Clone, Debug)]
pub struct Source {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub url: String,
    pub token: String,
}

/// Sources saved by the owner. Their tokens are encrypted with the library key, so they are only
/// usable while the node is unlocked.
pub fn load_sources(app: &App) -> Vec<Source> {
    let Some(k) = app.keyring.keys() else { return vec![] };
    let rows: Vec<(String, String, String, String, Option<Vec<u8>>)> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT id,kind,name,url,token_enc FROM sources WHERE enabled=1 ORDER BY created")?;
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
            Ok(r.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap_or_default();
    rows.into_iter()
        .map(|(id, kind, name, url, enc)| {
            let token = enc.and_then(|b| crate::keyring::decrypt_blob(&k.content_key(), &b).ok()).and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();
            Source { id, kind, name, url, token }
        })
        .collect()
}

pub fn add_source(app: &App, kind: &str, name: &str, url: &str, token: &str) -> Result<String> {
    if !["plex", "jellyfin"].contains(&kind) {
        bail!("source type must be plex or jellyfin");
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 40 {
        bail!("give the source a short name");
    }
    let u = reqwest::Url::parse(url.trim()).context("that does not look like a web address")?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        bail!("the address must start with http:// or https://");
    }
    let k = app.keyring.keys().ok_or_else(|| anyhow!("the library is locked: sign in as the owner to unlock it"))?;
    let enc = crate::keyring::encrypt_blob(&k.content_key(), token.trim().as_bytes())?;
    let id = random_hex(4);
    let base = url.trim().trim_end_matches('/').to_string();
    app.db.with(|c| {
        c.execute("INSERT INTO sources(id,kind,name,url,token_enc,created) VALUES(?1,?2,?3,?4,?5,?6)", params![id, kind, name, base, enc, now()])?;
        Ok(())
    })?;
    Ok(id)
}

pub fn delete_source(app: &App, id: &str) -> Result<()> {
    let n = app.db.with(|c| Ok(c.execute("DELETE FROM sources WHERE id=?1", [id])?))?;
    if n == 0 {
        bail!("no such source");
    }
    Ok(())
}

pub fn list_sources(app: &App) -> Result<Vec<serde_json::Value>> {
    app.db.with(|c| {
        let mut st = c.prepare("SELECT id,kind,name,url,token_enc IS NOT NULL FROM sources ORDER BY created")?;
        let r = st.query_map([], |r| {
            Ok(serde_json::json!({ "id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?, "url": r.get::<_, String>(3)?, "has_token": r.get::<_, bool>(4)? }))
        })?;
        Ok(r.collect::<rusqlite::Result<Vec<_>>>()?)
    })
}

fn ext_of(container: &str) -> String {
    let c = container.to_ascii_lowercase();
    if ["mp4", "mkv", "webm", "mov", "avi", "m4v", "ts", "ogv", "mpg"].contains(&c.as_str()) { c } else { "mkv".into() }
}

fn file_title(t: &str) -> String {
    t.chars().map(|c| if c.is_alphanumeric() || c == ' ' || c == '-' || c == '\'' { c } else { ' ' }).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Plex and Jellyfin know which shelf an item sits on; "Anime" in a genre, tag or library name wins.
fn plex_kind(m: &serde_json::Value, ty: &str) -> String {
    let hay = format!(
        "{} {}",
        m["librarySectionTitle"].as_str().unwrap_or(""),
        m["Genre"].as_array().map(|g| g.iter().filter_map(|x| x["tag"].as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default()
    )
    .to_lowercase();
    if hay.contains("anime") {
        "anime".into()
    } else if ty == "episode" {
        "series".into()
    } else {
        "movie".into()
    }
}

fn jellyfin_kind(it: &serde_json::Value) -> String {
    let list = |k: &str| it[k].as_array().map(|g| g.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default();
    let hay = format!("{} {}", list("Genres"), list("Tags")).to_lowercase();
    if hay.contains("anime") {
        "anime".into()
    } else if it["Type"] == "Episode" {
        "series".into()
    } else {
        "movie".into()
    }
}

pub struct PlexProvider {
    pub src: Source,
}

#[async_trait]
impl Provider for PlexProvider {
    fn on_lan(&self) -> bool {
        host_is_private(&self.src.url)
    }
    fn id(&self) -> String {
        format!("src:{}", self.src.id)
    }
    fn label(&self) -> String {
        format!("{} (Plex)", self.src.name)
    }
    async fn search(&self, http: &reqwest::Client, q: &str) -> Result<Vec<Candidate>> {
        let v: serde_json::Value = http
            .get(format!("{}/hubs/search", self.src.url))
            .query(&[("query", q), ("limit", "20")])
            .header("X-Plex-Token", &self.src.token)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut out = vec![];
        for hub in v["MediaContainer"]["Hub"].as_array().cloned().unwrap_or_default() {
            for m in hub["Metadata"].as_array().cloned().unwrap_or_default() {
                let ty = m["type"].as_str().unwrap_or("");
                if ty != "movie" && ty != "episode" {
                    continue;
                }
                let Some(part) = m["Media"][0]["Part"][0].as_object() else { continue };
                let Some(key) = part.get("key").and_then(|k| k.as_str()) else { continue };
                let title = if ty == "episode" {
                    format!("{} S{:02}E{:02}", file_title(m["grandparentTitle"].as_str().unwrap_or("Episode")), m["parentIndex"].as_u64().unwrap_or(0), m["index"].as_u64().unwrap_or(0))
                } else {
                    file_title(m["title"].as_str().unwrap_or("Untitled"))
                };
                let ext = ext_of(part.get("container").and_then(|c| c.as_str()).unwrap_or("mkv"));
                out.push(Candidate {
                    provider: self.id(),
                    title,
                    year: m["year"].as_i64().map(|y| y as i32),
                    url: format!("plex:{ext}:{key}"),
                    size: part.get("size").and_then(|s| s.as_u64()),
                    note: Some(self.src.name.clone()),
                    kind: Some(plex_kind(&m, ty)),
                });
            }
        }
        Ok(out)
    }
    async fn resolve(&self, _http: &reqwest::Client, url: &str) -> Result<Resolved> {
        let rest = url.strip_prefix("plex:").ok_or_else(|| anyhow!("not a Plex item"))?;
        let (ext, key) = rest.split_once(':').ok_or_else(|| anyhow!("not a Plex item"))?;
        if !key.starts_with("/library/parts/") || key.contains("..") {
            bail!("unexpected Plex path");
        }
        Ok(Resolved {
            url: format!("{}{}?download=1", self.src.url, key),
            filename: format!("plex-item.{}", ext_of(ext)),
            headers: vec![("X-Plex-Token".into(), self.src.token.clone())],
            trusted: true,
        })
    }
}

pub struct JellyfinProvider {
    pub src: Source,
}

#[async_trait]
impl Provider for JellyfinProvider {
    fn on_lan(&self) -> bool {
        host_is_private(&self.src.url)
    }
    fn id(&self) -> String {
        format!("src:{}", self.src.id)
    }
    fn label(&self) -> String {
        format!("{} (Jellyfin)", self.src.name)
    }
    async fn search(&self, http: &reqwest::Client, q: &str) -> Result<Vec<Candidate>> {
        let v: serde_json::Value = http
            .get(format!("{}/Items", self.src.url))
            .query(&[("searchTerm", q), ("Recursive", "true"), ("IncludeItemTypes", "Movie,Episode"), ("Fields", "MediaSources,Genres,Tags"), ("Limit", "20")])
            .header("X-Emby-Token", &self.src.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut out = vec![];
        for it in v["Items"].as_array().cloned().unwrap_or_default() {
            let Some(id) = it["Id"].as_str().filter(|i| i.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')) else { continue };
            let title = if it["Type"] == "Episode" {
                format!("{} S{:02}E{:02}", file_title(it["SeriesName"].as_str().unwrap_or("Episode")), it["ParentIndexNumber"].as_u64().unwrap_or(0), it["IndexNumber"].as_u64().unwrap_or(0))
            } else {
                file_title(it["Name"].as_str().unwrap_or("Untitled"))
            };
            let ext = ext_of(it["MediaSources"][0]["Container"].as_str().unwrap_or("mkv"));
            out.push(Candidate {
                provider: self.id(),
                title,
                year: it["ProductionYear"].as_i64().map(|y| y as i32),
                url: format!("jf:{ext}:{id}"),
                size: it["MediaSources"][0]["Size"].as_u64(),
                note: Some(self.src.name.clone()),
                kind: Some(jellyfin_kind(&it)),
            });
        }
        Ok(out)
    }
    async fn resolve(&self, _http: &reqwest::Client, url: &str) -> Result<Resolved> {
        let rest = url.strip_prefix("jf:").ok_or_else(|| anyhow!("not a Jellyfin item"))?;
        let (ext, id) = rest.split_once(':').ok_or_else(|| anyhow!("not a Jellyfin item"))?;
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            bail!("unexpected Jellyfin id");
        }
        Ok(Resolved {
            url: format!("{}/Items/{}/Download", self.src.url, id),
            filename: format!("jellyfin-item.{}", ext_of(ext)),
            headers: vec![("X-Emby-Token".into(), self.src.token.clone())],
            trusted: true,
        })
    }
}

/// "Paste a link": a direct http(s) link to a video file.
pub struct DirectLink;

#[async_trait]
impl Provider for DirectLink {
    fn id(&self) -> String {
        "link".into()
    }
    fn label(&self) -> String {
        "Paste a link".into()
    }
    async fn search(&self, _http: &reqwest::Client, q: &str) -> Result<Vec<Candidate>> {
        let q = q.trim();
        if !(q.starts_with("http://") || q.starts_with("https://")) {
            return Ok(vec![]);
        }
        let name = q.split(['?', '#']).next().unwrap_or(q).rsplit('/').next().unwrap_or("video").to_string();
        Ok(vec![Candidate { provider: "link".into(), title: if name.is_empty() { "Linked video".into() } else { name }, year: None, url: q.to_string(), size: None, note: Some("Direct link".into()), kind: None }])
    }
    async fn resolve(&self, _http: &reqwest::Client, url: &str) -> Result<Resolved> {
        let name = url.split(['?', '#']).next().unwrap_or(url).rsplit('/').next().unwrap_or("video").to_string();
        Ok(Resolved { url: url.to_string(), filename: if name.is_empty() { "video".into() } else { name }, ..Default::default() })
    }
}

/// HTTP client that follows the configured route for acquisition traffic.
pub fn http_for(app: &App, timeout: Option<Duration>) -> Result<reqwest::Client> {
    client_for(app, timeout, false)
}

/// What "route" really means: "auto" is Tor on a Tor node and direct otherwise.
pub fn effective_route(cfg: &crate::config::Config) -> &str {
    match cfg.acquire.route.as_str() {
        "auto" | "" => {
            if cfg.transport == "tor" {
                "tor"
            } else {
                "direct"
            }
        }
        "proxy" => "tor", // the old generic proxy option is gone; never fall back to direct
        other => other,
    }
}

/// `local` = the server is the owner's own machine on the home network: it is reached directly
/// (Tor cannot reach private addresses, and the traffic never leaves the network).
pub fn client_for(app: &App, timeout: Option<Duration>, local: bool) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; syphon)")
        .connect_timeout(Duration::from_secs(45));
    if let Some(t) = timeout {
        b = b.timeout(t);
    }
    if local {
        return Ok(b.no_proxy().build()?);
    }
    b = match effective_route(&app.cfg) {
        "tor" => b.proxy(reqwest::Proxy::all(crate::tor::socks_url(&app.cfg))?),
        _ => b.no_proxy(),
    };
    Ok(b.build()?)
}

fn http_for_provider(app: &App, p: &dyn Provider, timeout: Option<Duration>) -> Result<reqwest::Client> {
    client_for(app, timeout, p.on_lan())
}

/// Downloads that go through Tor wait for Tor to finish connecting instead of failing.
async fn wait_for_route(app: &App, local: bool, tries: u32) -> Result<()> {
    if local || effective_route(&app.cfg) != "tor" || app.cfg.transport != "tor" {
        return Ok(());
    }
    for _ in 0..tries {
        if app.is_shutting_down() {
            bail!("this node is shutting down");
        }
        if app.tor.lock().unwrap().bootstrap >= 100 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    bail!(
        "Tor is still connecting ({}%), so nothing was sent (downloads never go around Tor). Try again in a minute.",
        app.tor.lock().unwrap().bootstrap
    )
}

fn host_is_private(url: &str) -> bool {
    reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(|h| is_private_host(h))).unwrap_or(false)
}

// -------------------------------------------------------------- Internet Archive

pub struct InternetArchive {
    pub filter: String,
}

fn lucene_safe(q: &str) -> String {
    q.chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '\'')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Choose the file to download from an Internet Archive item's file list.
pub fn pick_ia_file(meta: &serde_json::Value) -> Option<String> {
    let files = meta["files"].as_array()?;
    let mut best: Option<(i32, u64, String)> = None;
    for f in files {
        let name = f["name"].as_str()?.to_string();
        let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let rank = match ext.as_str() {
            "mp4" | "m4v" => 3,
            "webm" => 2,
            "mkv" | "ogv" | "avi" | "mov" => 1,
            _ => continue,
        };
        if name.contains("_thumb") || name.to_ascii_lowercase().contains("sample") {
            continue;
        }
        let size: u64 = f["size"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
        let cand = (rank, size, name);
        if best.as_ref().map(|b| (cand.0, cand.1) > (b.0, b.1)).unwrap_or(true) {
            best = Some(cand);
        }
    }
    best.map(|b| b.2)
}

#[async_trait]
impl Provider for InternetArchive {
    fn id(&self) -> String {
        "internet_archive".into()
    }
    fn label(&self) -> String {
        "Internet Archive".into()
    }

    async fn search(&self, http: &reqwest::Client, q: &str) -> Result<Vec<Candidate>> {
        let q = lucene_safe(q);
        if q.is_empty() {
            return Ok(vec![]);
        }
        let query = format!("({q}) AND mediatype:movies{}", self.filter);
        let v: serde_json::Value = http
            .get("https://archive.org/advancedsearch.php")
            .query(&[
                ("q", query.as_str()),
                ("fl[]", "identifier"),
                ("fl[]", "title"),
                ("fl[]", "year"),
                ("rows", "25"),
                ("output", "json"),
                ("sort[]", "downloads desc"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let docs = v["response"]["docs"].as_array().cloned().unwrap_or_default();
        Ok(docs
            .iter()
            .filter_map(|d| {
                let id = d["identifier"].as_str()?;
                Some(Candidate {
                    provider: self.id(),
                    title: d["title"].as_str().unwrap_or(id).to_string(),
                    year: d["year"].as_str().and_then(|y| y.parse().ok()).or_else(|| d["year"].as_i64().map(|y| y as i32)),
                    url: format!("ia:{id}"),
                    size: None,
                    note: Some("archive.org".into()),
                    kind: None,
                })
            })
            .collect())
    }

    async fn resolve(&self, http: &reqwest::Client, url: &str) -> Result<Resolved> {
        let id = url.strip_prefix("ia:").ok_or_else(|| anyhow!("not an Internet Archive result"))?;
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
            bail!("invalid Internet Archive identifier");
        }
        let meta: serde_json::Value = http
            .get(format!("https://archive.org/metadata/{id}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let name = pick_ia_file(&meta).ok_or_else(|| anyhow!("no playable video file in this item"))?;
        let mut u = reqwest::Url::parse("https://archive.org/download/")?;
        {
            let mut seg = u.path_segments_mut().map_err(|_| anyhow!("bad url"))?;
            seg.pop_if_empty().push(id);
            for part in name.split('/') {
                seg.push(part);
            }
        }
        Ok(Resolved { url: u.to_string(), filename: name.rsplit('/').next().unwrap_or(&name).to_string(), ..Default::default() })
    }
}

// -------------------------------------------------------------------- RSS

pub struct RssProvider {
    pub feed: RssFeed,
}

#[derive(Debug, PartialEq)]
pub struct RssItem {
    pub title: String,
    pub url: String,
    pub size: Option<u64>,
}

fn unescape(s: &str) -> String {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix("<![CDATA[").and_then(|x| x.strip_suffix("]]>")) {
        return inner.trim().to_string(); // CDATA is literal text
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .trim()
        .to_string()
}

pub fn parse_rss(xml: &str) -> Vec<RssItem> {
    let item_re = Regex::new(r"(?s)<item[\s>].*?</item>").unwrap();
    let title_re = Regex::new(r"(?s)<title>(.*?)</title>").unwrap();
    let enc_re = Regex::new(r#"(?s)<enclosure\s[^>]*?url=["']([^"']+)["'][^>]*>"#).unwrap();
    let len_re = Regex::new(r#"length=["'](\d+)["']"#).unwrap();
    let link_re = Regex::new(r"(?s)<link>(.*?)</link>").unwrap();
    item_re
        .find_iter(xml)
        .filter_map(|m| {
            let it = m.as_str();
            let title = unescape(&title_re.captures(it)?[1]);
            let (url, size) = if let Some(c) = enc_re.captures(it) {
                let tag = c.get(0).unwrap().as_str();
                (unescape(&c[1]), len_re.captures(tag).and_then(|l| l[1].parse().ok()))
            } else {
                (unescape(&link_re.captures(it)?[1]), None)
            };
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return None;
            }
            Some(RssItem { title, url, size })
        })
        .collect()
}

#[async_trait]
impl Provider for RssProvider {
    fn id(&self) -> String {
        format!("rss:{}", self.feed.name)
    }
    fn label(&self) -> String {
        format!("{} (RSS)", self.feed.name)
    }

    async fn search(&self, http: &reqwest::Client, q: &str) -> Result<Vec<Candidate>> {
        let body = http.get(&self.feed.url).send().await?.error_for_status()?.text().await?;
        if body.len() > 8 << 20 {
            bail!("feed is too large");
        }
        let words: Vec<String> = q.to_lowercase().split_whitespace().map(|s| s.to_string()).collect();
        Ok(parse_rss(&body)
            .into_iter()
            .filter(|i| {
                let t = i.title.to_lowercase();
                words.iter().all(|w| t.contains(w))
            })
            .take(50)
            .map(|i| Candidate {
                provider: self.id(),
                year: crate::util::parse_filename(&i.title).year,
                title: i.title,
                url: i.url,
                size: i.size,
                note: Some(self.feed.name.clone()),
                kind: None,
            })
            .collect())
    }

    async fn resolve(&self, _http: &reqwest::Client, url: &str) -> Result<Resolved> {
        let name = url.split(['?', '#']).next().unwrap_or(url).rsplit('/').next().unwrap_or("video").to_string();
        Ok(Resolved { url: url.to_string(), filename: if name.is_empty() { "video".into() } else { name }, ..Default::default() })
    }
}

// ------------------------------------------------------------- download queue

fn is_private_host(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") || h.ends_with(".internal") {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1])
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
        };
    }
    false
}

fn check_url(app: &App, url: &str) -> Result<()> {
    let u = reqwest::Url::parse(url).context("not a valid URL")?;
    if !matches!(u.scheme(), "http" | "https") {
        bail!("only http and https downloads are supported");
    }
    if !app.cfg.acquire.allow_private_hosts {
        let host = u.host_str().unwrap_or("");
        if is_private_host(host) {
            bail!("downloads from local or private addresses are blocked");
        }
    }
    Ok(())
}

pub async fn search(app: &Shared, provider: Option<&str>, q: &str) -> Result<Vec<Candidate>> {
    let mut out = vec![];
    let mut errors = vec![];
    for p in providers(app) {
        if provider.map(|x| x != p.id()).unwrap_or(false) {
            continue;
        }
        if let Err(e) = wait_for_route(app, p.on_lan(), 4).await {
            errors.push(format!("{}: {}", p.label(), crate::util::friendly_error(&e)));
            continue;
        }
        let http = http_for_provider(app, p.as_ref(), Some(Duration::from_secs(60)))?;
        match p.search(&http, q).await {
            Ok(mut r) => out.append(&mut r),
            Err(e) => errors.push(format!("{}: {}", p.label(), crate::util::friendly_error(&e))),
        }
    }
    if out.is_empty() && !errors.is_empty() {
        bail!("{}", errors.join("; "));
    }
    Ok(out)
}

/// Queue a download. The file is fetched over the configured route and lands in the review area.
/// `kind` ("movie", "series", "anime") is what the owner or the source says it is; empty = work it out from the name.
pub async fn queue(app: &Shared, provider: &str, url: &str, title: &str, kind: &str) -> Result<String> {
    if !app.keyring.is_unlocked() {
        bail!("the library is locked: sign in as the owner to unlock it");
    }
    if !providers(app).iter().any(|p| p.id() == provider) {
        bail!("unknown provider");
    }
    if !url.starts_with("ia:") && !url.starts_with("plex:") && !url.starts_with("jf:") {
        check_url(app, url)?;
    }
    if let Err(m) = app.disk_ok(0) {
        bail!("{m}");
    }
    let kind = if ["movie", "series", "anime"].contains(&kind) { Some(kind) } else { None };
    let id = random_hex(6);
    app.db.with(|c| {
        c.execute(
            "INSERT INTO downloads(id,provider,title,url,status,created,kind_hint) VALUES(?1,?2,?3,?4,'queued',?5,?6)",
            params![id, provider, title.chars().take(200).collect::<String>(), url, now(), kind],
        )?;
        Ok(())
    })?;
    spawn_download(app, id.clone(), provider.to_string(), url.to_string());
    Ok(id)
}

fn is_cancelled(app: &App, id: &str) -> bool {
    app.cancelled.lock().unwrap().contains(id)
}

struct SlotGuard(Shared);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.running_downloads.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn spawn_download(app: &Shared, id: String, provider: String, url: String) {
    if !app.active_downloads.lock().unwrap().insert(id.clone()) {
        return; // already running
    }
    let a = app.clone();
    tokio::spawn(async move {
        // waiting for a free slot: a cancel can arrive here too
        // the number of downloads allowed at once comes from the performance tuning, so it can change while others wait
        let _slot = loop {
            let cap = if a.perf_dedicated.load(std::sync::atomic::Ordering::Relaxed) { a.tuning().download_parallel as usize } else { a.cfg.acquire.max_parallel.max(1) };
            let r = a.running_downloads.load(std::sync::atomic::Ordering::SeqCst);
            if r < cap && a.running_downloads.compare_exchange(r, r + 1, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst).is_ok() {
                break SlotGuard(a.clone());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            if is_cancelled(&a, &id) || a.is_shutting_down() {
                a.active_downloads.lock().unwrap().remove(&id);
                a.cancelled.lock().unwrap().remove(&id);
                return;
            }
        };
        if a.is_shutting_down() || is_cancelled(&a, &id) {
            a.active_downloads.lock().unwrap().remove(&id);
            a.cancelled.lock().unwrap().remove(&id);
            return;
        }
        let res = run_download(&a, &id, &provider, &url).await;
        a.active_downloads.lock().unwrap().remove(&id);
        let was_cancelled = a.cancelled.lock().unwrap().remove(&id);
        if let Err(e) = res {
            if was_cancelled {
                set_status(&a, &id, "cancelled", Some("cancelled"));
            } else if a.is_shutting_down() {
                // interrupted by a shutdown, not a real failure: a node that keeps its state picks it up again
                set_status(&a, &id, if a.cfg.persistent() { "waiting" } else { "failed" }, Some("interrupted by a shutdown"));
            } else {
                tracing::info!("download {id} failed: {e:#}");
                set_status(&a, &id, "failed", Some(&crate::util::friendly_error(&e)));
            }
        }
    });
}

/// Stop a queued or running download. Running ones stop at the next piece of data.
pub fn cancel(app: &Shared, id: &str) -> Result<()> {
    let st: Option<String> = app.db.with(|c| Ok(c.query_row("SELECT status FROM downloads WHERE id=?1", [id], |r| r.get(0)).ok()))?;
    match st.as_deref() {
        None => bail!("no such download"),
        Some("queued" | "resolving" | "downloading" | "retrying" | "waiting") => {}
        Some(_) => bail!("this download is not running or waiting any more"),
    }
    if app.active_downloads.lock().unwrap().contains(id) {
        app.cancelled.lock().unwrap().insert(id.to_string());
    }
    set_status(app, id, "cancelled", Some("cancelled"));
    Ok(())
}

/// Start a failed or cancelled download again from the beginning.
pub fn retry(app: &Shared, id: &str) -> Result<()> {
    if !app.keyring.is_unlocked() {
        bail!("the library is locked: sign in as the owner to unlock it");
    }
    let row: Option<(String, String, String)> = app.db.with(|c| {
        Ok(c.query_row("SELECT status,provider,url FROM downloads WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok())
    })?;
    let Some((status, provider, url)) = row else { bail!("no such download") };
    if !matches!(status.as_str(), "failed" | "cancelled") {
        bail!("only a failed or cancelled download can be tried again");
    }
    app.cancelled.lock().unwrap().remove(id);
    app.db.with(|c| {
        c.execute("UPDATE downloads SET status='queued', error=NULL, got=0, total=0, finished=NULL WHERE id=?1", [id])?;
        Ok(())
    })?;
    spawn_download(app, id.to_string(), provider, url);
    Ok(())
}

/// Remove finished entries from the list (not the files): everything that is not still working or waiting for review.
pub fn clear_finished(app: &App) -> Result<usize> {
    app.db.with(|c| {
        Ok(c.execute(
            "DELETE FROM downloads WHERE status IN ('failed','cancelled','duplicate','approved','rejected')
               OR (status='review' AND (item IS NULL OR item NOT IN (SELECT id FROM items WHERE local='quarantine')))",
            [],
        )?)
    })
}

/// Downloads that were interrupted (power cut, crash, shutdown) start again from the beginning.
/// Needs the library unlocked, so it runs at start-up if possible and again after sign-in.
pub fn resume_downloads(app: &Shared) -> usize {
    if !app.keyring.is_unlocked() || !app.cfg.persistent() {
        return 0;
    }
    let rows: Vec<(String, String, String)> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT id,provider,url FROM downloads WHERE status IN ('waiting','queued','resolving','downloading','retrying')")?;
            let r = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            Ok(r.collect::<rusqlite::Result<_>>()?)
        })
        .unwrap_or_default();
    let n = rows.len();
    for (id, p, u) in rows {
        spawn_download(app, id, p, u);
    }
    n
}

fn set_status(app: &App, id: &str, status: &str, err: Option<&str>) {
    let terminal = matches!(status, "review" | "duplicate" | "failed" | "cancelled" | "approved" | "rejected");
    let _ = app.db.with(|c| {
        c.execute(
            "UPDATE downloads SET status=?2, error=?3, finished=CASE WHEN ?4 THEN ?5 ELSE NULL END WHERE id=?1",
            params![id, status, err, terminal, now()],
        )?;
        Ok(())
    });
}

fn set_progress(app: &App, id: &str, got: i64, total: Option<i64>) {
    let _ = app.db.with(|c| {
        match total {
            Some(t) => c.execute("UPDATE downloads SET got=?2, total=?3 WHERE id=?1", params![id, got, t])?,
            None => c.execute("UPDATE downloads SET got=?2 WHERE id=?1", params![id, got])?,
        };
        Ok(())
    });
}

const MAX_RETRIES: u32 = 6;
const STALL_SECS: u64 = 90;

/// A name the importer can read a title and episode from, when the source only gave a placeholder.
fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() + 0 && i + 2 <= b.len() - 1 {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).replace(['/', '\\'], "_")
}

fn download_filename(resolved: &str, title: &str) -> String {
    let resolved = &pct_decode(resolved);
    let generic = resolved.starts_with("plex-item.") || resolved.starts_with("jellyfin-item.");
    if !generic {
        return resolved.to_string();
    }
    let ext = resolved.rsplit('.').next().unwrap_or("mkv");
    let t: String = title.chars().filter(|c| !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')).collect();
    format!("{}.{ext}", t.trim())
}

async fn send_get(http: &reqwest::Client, r: &Resolved, range: Option<(u64, Option<&str>)>) -> Result<reqwest::Response> {
    let mut req = http.get(&r.url);
    for (k, v) in &r.headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some((from, validator)) = range {
        req = req.header("Range", format!("bytes={from}-"));
        if let Some(v) = validator {
            req = req.header("If-Range", v);
        }
    }
    Ok(req.send().await?.error_for_status()?)
}

async fn sleep_unless_cancelled(app: &App, id: &str, secs: u64) -> Result<()> {
    for _ in 0..secs {
        if is_cancelled(app, id) {
            bail!("cancelled");
        }
        if app.is_shutting_down() {
            bail!("interrupted by a shutdown");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

async fn run_download(app: &Shared, id: &str, provider: &str, url: &str) -> Result<()> {
    set_status(app, id, "resolving", None);
    let (title, kind_hint): (String, Option<String>) = app
        .db
        .with(|c| Ok(c.query_row("SELECT title,kind_hint FROM downloads WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))?))?;
    let prov = providers(app)
        .into_iter()
        .find(|p| p.id() == provider)
        .ok_or_else(|| anyhow!("that source has been removed from Settings"))?;
    wait_for_route(app, prov.on_lan(), 90).await?;
    let http = http_for_provider(app, prov.as_ref(), None)?;

    // 1. resolve and open the file, retrying while the network is flaky
    let mut attempt = 0u32;
    let (resolved, first) = loop {
        if is_cancelled(app, id) {
            bail!("cancelled");
        }
        let step = async {
            let resolved = prov.resolve(&http, url).await?;
            if !resolved.trusted {
                check_url(app, &resolved.url)?;
            }
            let resp = send_get(&http, &resolved, None).await?;
            Ok::<_, anyhow::Error>((resolved, resp))
        }
        .await;
        match step {
            Ok(x) => break x,
            Err(e) if attempt < MAX_RETRIES && crate::util::is_transient(&e) => {
                attempt += 1;
                set_status(app, id, "retrying", Some(&format!("{} Trying again ({attempt}/{MAX_RETRIES})…", crate::util::friendly_error(&e))));
                sleep_unless_cancelled(app, id, 5 * attempt as u64).await?;
            }
            Err(e) => return Err(e),
        }
    };

    // 2. stream it in; if the connection drops, ask for the rest (or start over if the server cannot)
    let filename = download_filename(&resolved.filename, &title);
    let mut total = first.content_length().unwrap_or(0);
    let validator = first.headers().get("etag").or_else(|| first.headers().get("last-modified")).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    set_progress(app, id, 0, Some(total as i64));
    set_status(app, id, "downloading", None);
    let mut session = IngestSession::begin(app, &filename, "download")?;
    let mut resp = Some(first);
    let mut attempt = 0u32;
    'outer: loop {
        let r = resp.take().expect("a response to read");
        let mut stream = r.bytes_stream();
        let mut last = std::time::Instant::now();
        let failure: anyhow::Error = loop {
            if app.is_shutting_down() {
                session.abort();
                bail!("interrupted by a shutdown");
            }
            if is_cancelled(app, id) {
                session.abort();
                bail!("cancelled");
            }
            match tokio::time::timeout(Duration::from_secs(STALL_SECS), stream.next()).await {
                Err(_) => break anyhow!("the download stalled (no data for {STALL_SECS} seconds)"),
                Ok(None) => {
                    if total > 0 && (session.bytes()) < total {
                        break anyhow!("the connection closed before the whole file arrived");
                    }
                    break 'outer; // complete
                }
                Ok(Some(Err(e))) => break e.into(),
                Ok(Some(Ok(chunk))) => {
                    if let Err(e) = session.push(&chunk) {
                        session.abort();
                        return Err(e);
                    }
                    attempt = 0; // progress resets the retry budget
                    if last.elapsed() > Duration::from_secs(1) {
                        last = std::time::Instant::now();
                        set_progress(app, id, session.bytes() as i64, None);
                    }
                }
            }
        };

        // the connection broke: decide whether to resume
        if !crate::util::is_transient(&failure) || attempt >= MAX_RETRIES {
            session.abort();
            return Err(failure);
        }
        loop {
            attempt += 1;
            let have = session.bytes();
            set_progress(app, id, have as i64, None);
            set_status(app, id, "retrying", Some(&format!("{} Resuming ({attempt}/{MAX_RETRIES})…", crate::util::friendly_error(&failure))));
            if let Err(e) = sleep_unless_cancelled(app, id, 3 * attempt as u64).await {
                session.abort();
                return Err(e);
            }
            match send_get(&http, &resolved, Some((have, validator.as_deref()))).await {
                Ok(r) if r.status().as_u16() == 206 && range_starts_at(&r, have) => {
                    resp = Some(r);
                    set_status(app, id, "downloading", None);
                    continue 'outer;
                }
                Ok(r) if r.status().as_u16() == 200 => {
                    // the server cannot resume (or the file changed): start this file again from byte 0
                    session.abort();
                    total = r.content_length().unwrap_or(0);
                    set_progress(app, id, 0, Some(total as i64));
                    session = IngestSession::begin(app, &filename, "download")?;
                    resp = Some(r);
                    set_status(app, id, "downloading", None);
                    continue 'outer;
                }
                Ok(r) if r.status().as_u16() == 416 && total > 0 && have >= total => break 'outer,
                Ok(r) => {
                    session.abort();
                    bail!("the server answered {} when asked to resume", r.status().as_u16());
                }
                Err(e) if attempt < MAX_RETRIES && crate::util::is_transient(&e) => continue,
                Err(e) => {
                    session.abort();
                    return Err(e);
                }
            }
        }
    }

    // 3. done: it waits in Review
    let got = session.bytes() as i64;
    let ing = session.finish(app)?;
    app.db.with(|c| {
        c.execute("UPDATE downloads SET got=?2, total=?2, item=?3 WHERE id=?1", params![id, got, ing.id])?;
        Ok(())
    })?;
    set_status(app, id, if ing.dup { "duplicate" } else { "review" }, None);
    if !ing.dup {
        if let Some(k) = kind_hint {
            let _ = app.db.with(|c| {
                c.execute("UPDATE items SET kind=?2 WHERE id=?1 AND local='quarantine'", params![ing.id, k])?;
                Ok(())
            });
        }
    }
    post_ingest(app, &ing, "download".into()).await?;
    Ok(())
}

fn range_starts_at(r: &reqwest::Response, from: u64) -> bool {
    r.headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes "))
        .and_then(|v| v.split('-').next())
        .and_then(|v| v.parse::<u64>().ok())
        == Some(from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rss_enclosures_and_links() {
        let xml = r#"<?xml version="1.0"?><rss><channel>
          <item><title>Night of the Living Dead (1968)</title>
            <enclosure url="https://example.org/files/notld.mp4?x=1&amp;y=2" length="12345" type="video/mp4"/></item>
          <item><title><![CDATA[Plan 9 &amp; Friends]]></title><link>https://example.org/p9.mkv</link></item>
          <item><title>No url here</title></item>
          <item><title>Bad scheme</title><link>ftp://example.org/x.mp4</link></item>
        </channel></rss>"#;
        let items = parse_rss(xml);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].title, "Night of the Living Dead (1968)");
        assert_eq!(items[0].url, "https://example.org/files/notld.mp4?x=1&y=2");
        assert_eq!(items[0].size, Some(12345));
        assert_eq!(items[1].title, "Plan 9 &amp; Friends"); // CDATA content is taken literally
        assert_eq!(items[1].url, "https://example.org/p9.mkv");
    }

    #[test]
    fn picks_best_ia_file() {
        let meta = serde_json::json!({"files": [
            {"name": "a_thumb.mp4", "size": "10"},
            {"name": "a.ogv", "size": "900"},
            {"name": "a.mp4", "size": "500"},
            {"name": "a_512kb.mp4", "size": "100"},
            {"name": "a.txt", "size": "1"},
        ]});
        assert_eq!(pick_ia_file(&meta).as_deref(), Some("a.mp4"));
        assert_eq!(pick_ia_file(&serde_json::json!({"files": []})), None);
    }

    #[test]
    fn blocks_private_hosts() {
        for h in ["localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.1.1", "[::1]", "printer.local"] {
            assert!(is_private_host(h), "{h}");
        }
        for h in ["archive.org", "93.184.216.34"] {
            assert!(!is_private_host(h), "{h}");
        }
        assert_eq!(lucene_safe("a:b (c) \"d\" -e"), "ab c d -e");
    }
}
