//! Cast, genres, descriptions and posters, the way Jellyfin shows them, fetched through Tor.
//!
//! Only a title (and year) leaves the node, over the same route downloads use, so the sites cannot see
//! who is asking. Series use TVmaze, anime uses Jikan (MyAnimeList), movies use TMDB when you give a free
//! key and Wikidata otherwise. Anime tries Jikan, then AniList, then TVmaze. Nothing needs an account. Posters are kept encrypted like everything else.
//! If a lookup finds nothing, the title just has no details; you can still type genres in by hand.

use crate::db::Item;
use crate::keyring::{EncReader, EncWriter};
use crate::library::keys;
use crate::state::{App, Shared};
use crate::util::{now, series_key};
use anyhow::{anyhow, bail, Result};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Person {
    pub name: String,
    pub role: Option<String>,
}

/// One episode's name. `season` is None when the source numbers episodes straight through (anime).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Ep {
    pub season: Option<i32>,
    pub number: i32,
    pub title: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Meta {
    pub overview: Option<String>,
    pub genres: Vec<String>,
    pub cast: Vec<Person>,
    pub rating: Option<f64>,
    pub year: Option<i32>,
    pub source: String,
    /// The sources say this is anime, whatever the file names looked like.
    #[serde(default)]
    pub anime: bool,
    #[serde(default)]
    pub episodes: Vec<Ep>,
    /// the name the source knows it by (it may differ from the file's name)
    #[serde(default)]
    pub matched: Option<String>,
    /// the franchise lookup has been done for this title (found or not)
    #[serde(default)]
    pub fc: bool,
    /// Shared by every entry of one story: a season that is released under its own name ("Highschool DxD Hero")
    /// still belongs to the same franchise as the first one, because the source lists it as a sequel.
    #[serde(default)]
    pub franchise: Option<String>,
    #[serde(default)]
    pub franchise_title: Option<String>,
    /// which season of the franchise this entry is
    #[serde(default)]
    pub franchise_season: Option<i32>,
}

impl Meta {
    /// The name of an episode counted inside this entry (a season released under its own name restarts at 1).
    pub fn entry_episode_title(&self, number: i64) -> Option<&str> {
        self.episodes.iter().find(|e| e.season.is_none() && e.number == number as i32).map(|e| e.title.as_str())
    }

    /// The name of one episode, if the source listed it.
    pub fn episode_title(&self, season: Option<i64>, number: i64) -> Option<&str> {
        let n = number as i32;
        if let Some(s) = season {
            if let Some(e) = self.episodes.iter().find(|e| e.season == Some(s as i32) && e.number == n) {
                return Some(&e.title);
            }
        }
        // numbered straight through: only the first season of a file set can safely use it
        if season.map(|s| s <= 1).unwrap_or(true) {
            if let Some(e) = self.episodes.iter().find(|e| e.season.is_none() && e.number == n) {
                return Some(&e.title);
            }
            if season.is_none() {
                return self.episodes.iter().find(|e| e.season == Some(1) && e.number == n).map(|e| e.title.as_str());
            }
        }
        None
    }
}

/// What identifies "the same title" for lookups: a movie by name and year, a show by name.
pub fn key_for(title: &str, kind: &str, year: Option<i32>) -> String {
    if kind == "movie" {
        format!("m:{}:{}", crate::util::plain_key(title), year.unwrap_or(0))
    } else {
        format!("s:{}", series_key(title))
    }
}

pub fn key_of(it: &Item) -> String {
    key_for(&it.title, &it.kind, it.year)
}

fn artwork_path(app: &App, key: &str) -> std::path::PathBuf {
    app.dirs.root.join("artwork").join(format!("{}.enc", &blake3::hash(key.as_bytes()).to_hex()[..32]))
}

pub struct Stored {
    pub meta: Option<Meta>,
    pub poster: bool,
}

/// Every stored lookup, keyed by title identity. The table is small, so listings load it in one go.
pub fn load_all(app: &App) -> HashMap<String, Stored> {
    app.db
        .with(|c| {
            let mut st = c.prepare("SELECT key,json,poster FROM meta WHERE status='found'")?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, bool>(2)?)))?;
            Ok(rows.filter_map(|r| r.ok()).map(|(k, j, p)| (k, Stored { meta: j.and_then(|j| serde_json::from_str(&j).ok()), poster: p })).collect())
        })
        .unwrap_or_default()
}

pub fn user_genres(app: &App) -> HashMap<String, Vec<String>> {
    app.db
        .with(|c| {
            let mut st = c.prepare("SELECT item,genres FROM meta_user")?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
            Ok(rows.filter_map(|r| r.ok()).map(|(i, g)| (i, g.split('|').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect())).collect())
        })
        .unwrap_or_default()
}

pub fn set_user_genres(app: &App, item: &str, genres: &[String]) -> Result<()> {
    let typed: Vec<String> = genres.iter().map(|g| g.trim().chars().filter(|c| *c != '|').take(30).collect::<String>()).filter(|g| !g.is_empty()).collect();
    let clean: Vec<String> = canon_genres(&typed).into_iter().take(8).collect();
    app.db.with(|c| {
        if clean.is_empty() {
            c.execute("DELETE FROM meta_user WHERE item=?1", [item])?;
        } else {
            c.execute("INSERT INTO meta_user(item,genres) VALUES(?1,?2) ON CONFLICT(item) DO UPDATE SET genres=excluded.genres", params![item, clean.join("|")])?;
        }
        Ok(())
    })
}

pub fn poster_bytes(app: &App, key: &str) -> Result<Vec<u8>> {
    let k = keys(app)?;
    let mut r = EncReader::open(&artwork_path(app, key), &k.content_key())?;
    let n = r.len;
    r.read_range(0, n)
}

pub fn save_poster(app: &App, key: &str, bytes: &[u8]) -> Result<()> {
    let k = keys(app)?;
    let p = artwork_path(app, key);
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    let mut w = EncWriter::new(std::io::BufWriter::new(std::fs::File::create(&tmp)?), &k.content_key())?;
    w.push(bytes)?;
    let (bw, _) = w.finish()?;
    drop(bw.into_inner().map_err(|e| anyhow!("{e}"))?);
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

pub fn image_mime(b: &[u8]) -> &'static str {
    if b.starts_with(&[0xFF, 0xD8]) {
        "image/jpeg"
    } else if b.starts_with(b"\x89PNG") {
        "image/png"
    } else if b.len() > 12 && &b[..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

// ------------------------------------------------------------------ lookups

fn strip_html(s: &str) -> String {
    let mut out = String::new();
    let mut tag = false;
    for c in s.chars() {
        match c {
            '<' => tag = true,
            '>' => tag = false,
            c if !tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&nbsp;", " ").trim().chars().take(1200).collect()
}

fn pretty_genre(g: &str) -> String {
    let g = g.trim().to_lowercase();
    let g = g.trim_end_matches(" film").trim_end_matches(" movie").trim_end_matches(" television series").to_string();
    match g.as_str() {
        "science fiction" | "sci-fi" => "Sci-Fi".into(),
        "romantic comedy" => "Romance".into(),
        "romance" | "romantic" => "Romance".into(),
        _ => {
            let mut cs = g.chars();
            cs.next().map(|f| f.to_uppercase().collect::<String>() + cs.as_str()).unwrap_or_default()
        }
    }
}


/// The shelves the Library builds rows from. Every source names things a little differently
/// ("Science Fiction", "sci-fi film", "Slasher"), so they are all folded into one familiar list.
pub const MAIN_GENRES: &[&str] = &[
    "Action", "Adventure", "Animation", "Comedy", "Crime", "Documentary", "Drama", "Family", "Fantasy", "History",
    "Horror", "Music", "Mystery", "Romance", "Sci-Fi", "Sports", "Thriller", "War", "Western",
];

pub fn canon_genres(input: &[String]) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let mut push = |g: &str| {
        if !out.iter().any(|x| x.eq_ignore_ascii_case(g)) {
            out.push(g.to_string());
        }
    };
    for raw in input {
        let low = raw.trim().to_lowercase();
        let low = low.trim_end_matches(" film").trim_end_matches(" movie").trim_end_matches(" series").trim_end_matches(" show").trim().to_string();
        let mapped: Vec<&str> = match low.as_str() {
            "" => vec![],
            "action" | "action film" | "martial arts" | "superhero" | "spy" => vec!["Action"],
            "action-adventure" | "action/adventure" | "action & adventure" | "action and adventure" => vec!["Action", "Adventure"],
            "adventure" | "swashbuckler" => vec!["Adventure"],
            "animation" | "animated" | "cartoon" | "anime" | "kids animation" => vec!["Animation"],
            "comedy" | "romantic comedy" | "black comedy" | "dark comedy" | "sitcom" | "parody" | "satire" | "slapstick" | "comedy drama" | "stand-up" | "gag humor" | "comedy-drama" => {
                if low.contains("romantic") { vec!["Comedy", "Romance"] } else if low.contains("drama") { vec!["Comedy", "Drama"] } else { vec!["Comedy"] }
            }
            "crime" | "heist" | "gangster" | "mafia" | "detective" | "film noir" | "noir" => vec!["Crime"],
            "documentary" | "docuseries" | "docudrama" | "biography" | "biographical" | "true crime" | "reality" | "reality-tv" => vec!["Documentary"],
            "drama" | "melodrama" | "psychological drama" | "legal drama" | "medical" | "soap" | "coming-of-age" | "slice of life" => vec!["Drama"],
            "family" | "children" | "kids" | "children's" | "childrens" => vec!["Family"],
            "fantasy" | "high fantasy" | "dark fantasy" | "isekai" | "magic" | "mythology" | "fairy tale" | "sword and sorcery" | "supernatural" => vec!["Fantasy"],
            "history" | "historical" | "period" | "period drama" | "historical drama" => vec!["History"],
            "horror" | "slasher" | "zombie" | "supernatural horror" | "psychological horror" | "monster" | "gore" | "splatter" | "body horror" | "found footage" | "survival horror" | "gothic" | "vampire" | "ghost" => vec!["Horror"],
            "music" | "musical" | "concert" | "music video" => vec!["Music"],
            "mystery" | "whodunit" | "suspense" => vec!["Mystery"],
            "romance" | "romantic" | "love" | "romantic drama" | "harem" | "shoujo" => vec!["Romance"],
            "science fiction" | "science-fiction" | "sci-fi" | "scifi" | "sci-fi & fantasy" | "sci fi" | "cyberpunk" | "space opera" | "mecha" | "dystopian" | "post-apocalyptic" | "time travel" => vec!["Sci-Fi"],
            "sports" | "sport" | "sports drama" => vec!["Sports"],
            "thriller" | "psychological thriller" | "spy thriller" | "political thriller" | "techno-thriller" => vec!["Thriller"],
            "war" | "war drama" | "military" | "war & politics" => vec!["War"],
            "western" | "spaghetti western" => vec!["Western"],
            _ => vec![],
        };
        if mapped.is_empty() {
            // not on the main list: keep it, tidied up (so "slice of life" style tags still show on the title page)
            let mut cs = low.chars();
            if let Some(f) = cs.next() {
                push(&(f.to_uppercase().collect::<String>() + cs.as_str()));
            }
        } else {
            for m in mapped {
                push(m);
            }
        }
    }
    // the familiar genres first, so a title's first rows are the ones people look for
    out.sort_by_key(|g| if MAIN_GENRES.contains(&g.as_str()) { 0 } else { 1 });
    out
}

async fn get_json(http: &reqwest::Client, url: &str) -> Result<Option<Value>> {
    let r = http.get(url).header("accept", "application/json").send().await?;
    if r.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(r.error_for_status()?.json().await?))
}

async fn post_json(http: &reqwest::Client, url: &str, body: &Value) -> Result<Option<Value>> {
    let r = http.post(url).header("accept", "application/json").json(body).send().await?;
    if r.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(r.error_for_status()?.json().await?))
}

async fn get_bytes(http: &reqwest::Client, url: &str) -> Option<Vec<u8>> {
    let r = http.get(url).send().await.ok()?.error_for_status().ok()?;
    if r.content_length().map(|n| n > 6 << 20).unwrap_or(false) {
        return None;
    }
    let b = r.bytes().await.ok()?;
    (b.len() < 6 << 20 && image_mime(&b) != "application/octet-stream").then(|| b.to_vec())
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// What one source found: the details, a picture to fetch, how well its title matched ours, and a few facts
/// the choice of "is this really anime" depends on.
struct Cand {
    meta: Meta,
    poster: Option<String>,
    score: f64,
    japanese: bool,
}

/// A source's title only counts when it is close to ours.
const ACCEPT: f64 = 0.75;

fn best_of<T>(query: &str, items: &[T], names: impl Fn(&T) -> Vec<String>) -> Option<(usize, f64)> {
    let mut best: Option<(usize, f64)> = None;
    for (i, it) in items.iter().enumerate() {
        let s = names(it).iter().map(|n| crate::util::title_similarity(query, n)).fold(0.0, f64::max);
        if s > best.map(|b| b.1).unwrap_or(0.0) {
            best = Some((i, s));
        }
    }
    best.filter(|b| b.1 >= ACCEPT)
}

async fn tvmaze(app: &App, http: &reqwest::Client, title: &str) -> Result<Option<Cand>> {
    let base = &app.cfg.metadata.tvmaze;
    let Some(list) = get_json(http, &format!("{base}/search/shows?q={}", enc(title))).await? else { return Ok(None) };
    let shows: Vec<Value> = list.as_array().map(|a| a.iter().map(|x| x["show"].clone()).collect()).unwrap_or_default();
    let Some((i, score)) = best_of(title, &shows, |s| vec![s["name"].as_str().unwrap_or("").to_string()]) else { return Ok(None) };
    let Some(id) = shows[i]["id"].as_u64() else { return Ok(None) };
    let Some(v) = get_json(http, &format!("{base}/shows/{id}?embed[]=cast&embed[]=episodes")).await? else { return Ok(None) };
    let cast = v["_embedded"]["cast"].as_array().map(|a| a.iter().take(10).filter_map(|c| Some(Person { name: c["person"]["name"].as_str()?.to_string(), role: c["character"]["name"].as_str().map(|s| s.to_string()) })).collect()).unwrap_or_default();
    let episodes: Vec<Ep> = v["_embedded"]["episodes"]
        .as_array()
        .map(|a| a.iter().filter_map(|e| Some(Ep { season: Some(e["season"].as_i64()? as i32), number: e["number"].as_i64()? as i32, title: e["name"].as_str()?.to_string() })).take(2000).collect())
        .unwrap_or_default();
    let genres: Vec<String> = v["genres"].as_array().map(|a| a.iter().filter_map(|g| g.as_str()).map(pretty_genre).collect()).unwrap_or_default();
    // TVmaze files anime under its own genre, or as Japanese animation
    let japanese = v["language"].as_str() == Some("Japanese");
    let anime = genres.iter().any(|g| g.eq_ignore_ascii_case("anime")) || (japanese && v["type"].as_str() == Some("Animation"));
    let m = Meta {
        overview: v["summary"].as_str().map(strip_html).filter(|s| !s.is_empty()),
        genres,
        cast,
        rating: v["rating"]["average"].as_f64(),
        year: v["premiered"].as_str().and_then(|s| s.get(..4)).and_then(|s| s.parse().ok()),
        source: "TVmaze".into(),
        anime,
        episodes,
        matched: v["name"].as_str().map(|s| s.to_string()),
        ..Default::default()
    };
    let poster = v["image"]["original"].as_str().or(v["image"]["medium"].as_str()).map(|s| s.to_string());
    Ok(Some(Cand { meta: m, poster, score, japanese }))
}

async fn jikan(app: &App, http: &reqwest::Client, title: &str) -> Result<Option<Cand>> {
    let base = &app.cfg.metadata.jikan;
    let Some(v) = get_json(http, &format!("{base}/anime?q={}&limit=10&sfw=true", enc(title))).await? else { return Ok(None) };
    let list: Vec<Value> = v["data"].as_array().cloned().unwrap_or_default();
    let names = |a: &Value| -> Vec<String> {
        let mut n: Vec<String> = ["title", "title_english", "title_japanese"].iter().filter_map(|k| a[*k].as_str().map(|s| s.to_string())).collect();
        n.extend(a["titles"].as_array().into_iter().flatten().filter_map(|t| t["title"].as_str().map(|s| s.to_string())));
        n.extend(a["title_synonyms"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(|s| s.to_string())));
        n
    };
    let Some((i, score)) = best_of(title, &list, names) else { return Ok(None) };
    let a = &list[i];
    let mut cast = vec![];
    let mut episodes = vec![];
    if let Some(id) = a["mal_id"].as_u64() {
        tokio::time::sleep(Duration::from_millis(1100)).await; // their rate limit
        if let Ok(Some(c)) = get_json(http, &format!("{base}/anime/{id}/characters")).await {
            for ch in c["data"].as_array().into_iter().flatten().take(8) {
                let name = ch["character"]["name"].as_str().unwrap_or("").to_string();
                let va = ch["voice_actors"].as_array().and_then(|v| v.iter().find(|x| x["language"] == "Japanese")).and_then(|x| x["person"]["name"].as_str()).map(|s| s.to_string());
                if !name.is_empty() {
                    cast.push(Person { name, role: va });
                }
            }
        }
        if a["episodes"].as_i64().map(|n| n != 1).unwrap_or(true) {
            for page in 1..=4 {
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let Ok(Some(e)) = get_json(http, &format!("{base}/anime/{id}/episodes?page={page}")).await else { break };
                for ep in e["data"].as_array().into_iter().flatten() {
                    if let (Some(n), Some(t)) = (ep["mal_id"].as_i64(), ep["title"].as_str()) {
                        episodes.push(Ep { season: None, number: n as i32, title: t.to_string() });
                    }
                }
                if e["pagination"]["has_next_page"].as_bool() != Some(true) {
                    break;
                }
            }
        }
    }
    let mut genres: Vec<String> = a["genres"].as_array().map(|g| g.iter().filter_map(|x| x["name"].as_str()).map(pretty_genre).collect()).unwrap_or_default();
    genres.extend(a["themes"].as_array().into_iter().flatten().filter_map(|x| x["name"].as_str()).take(2).map(pretty_genre));
    let m = Meta {
        overview: a["synopsis"].as_str().map(|s| s.chars().take(1200).collect()),
        genres,
        cast,
        rating: a["score"].as_f64(),
        year: a["year"].as_i64().map(|y| y as i32),
        source: "MyAnimeList".into(),
        anime: true,
        episodes,
        matched: a["title_english"].as_str().or(a["title"].as_str()).map(|s| s.to_string()),
        ..Default::default()
    };
    let mut m = m;
    if let Some(id) = a["mal_id"].as_i64() {
        // MyAnimeList numbers are also known to AniList, which lists how entries are related
        let f = franchise_of(app, http, "idMal", id).await.ok().flatten();
        apply_franchise(&mut m, f);
    }
    let poster = a["images"]["jpg"]["large_image_url"].as_str().or(a["images"]["jpg"]["image_url"].as_str()).map(|s| s.to_string());
    Ok(Some(Cand { meta: m, poster, score, japanese: true }))
}

// ------------------------------------------------------------------ anime franchises
//
// Some anime give every season its own name (Highschool DxD, Highschool DxD New, ... Hero). Other, different
// series share a name (the first Beyblade and Beyblade: Metal Fusion are different stories). The title alone cannot
// tell these apart, so Syphon asks AniList how the entries are related: only a PREQUEL/SEQUEL chain means "the same
// story continues". Spin-offs, alternate versions and reboots stay separate shows.

pub struct Franchise {
    pub key: String,
    pub title: String,
    pub season: Option<i32>,
}

const MEDIA_FIELDS: &str = "id idMal format title{romaji english} relations{edges{relationType(version:2) node{id type format title{romaji english}}}}";

async fn media_by(app: &App, http: &reqwest::Client, by: &str, id: i64) -> Result<Option<Value>> {
    let query = format!("query($id:Int){{Media({by}:$id,type:ANIME){{{MEDIA_FIELDS}}}}}");
    let body = serde_json::json!({ "query": query, "variables": { "id": id } });
    Ok(post_json(http, &app.cfg.metadata.anilist, &body).await?.map(|v| v["data"]["Media"].clone()).filter(|m| m.is_object()))
}

fn media_title(m: &Value) -> String {
    m["title"]["english"].as_str().or(m["title"]["romaji"].as_str()).unwrap_or("").to_string()
}

fn is_season_format(f: &str) -> bool {
    matches!(f, "TV" | "TV_SHORT" | "ONA")
}

/// "Part 2", "2nd Cour": the second half of a season, not a new one.
pub fn is_second_cour(title: &str) -> bool {
    let re = regex::Regex::new(r"(?i)\b(part|cour)\s*(2|ii|two)\b|\b(2nd|second)\s+(cour|part)\b").unwrap();
    re.is_match(title)
}

/// Walk the prequel chain back to the first season and number this entry. Pure: takes the chain, oldest first.
pub fn number_chain(chain: &[(String, String, i64)]) -> (usize, Vec<Option<i32>>) {
    // chain items: (format, title, id)
    let mut n = 0;
    let mut out = vec![];
    for (f, t, _) in chain {
        if is_season_format(f) {
            if !is_second_cour(t) || n == 0 {
                n += 1;
            }
            out.push(Some(n));
        } else {
            out.push(None);
        }
    }
    let root = chain.iter().position(|(f, _, _)| is_season_format(f)).unwrap_or(0);
    (root, out)
}

/// Where does this anime sit in its franchise? `by` is "id" (AniList) or "idMal".
pub async fn franchise_of(app: &App, http: &reqwest::Client, by: &str, id: i64) -> Result<Option<Franchise>> {
    let Some(first) = media_by(app, http, by, id).await? else { return Ok(None) };
    let mut walked: Vec<Value> = vec![first.clone()];
    let mut seen = std::collections::HashSet::new();
    seen.insert(first["id"].as_i64().unwrap_or(0));
    let mut cur = first;
    for _ in 0..14 {
        let prev = cur["relations"]["edges"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["relationType"] == "PREQUEL" && e["node"]["type"] == "ANIME")
            .and_then(|e| e["node"]["id"].as_i64());
        let Some(pid) = prev else { break };
        if !seen.insert(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(700)).await;
        let Some(m) = media_by(app, http, "id", pid).await? else { break };
        walked.push(m.clone());
        cur = m;
    }
    walked.reverse(); // oldest first
    let chain: Vec<(String, String, i64)> = walked.iter().map(|m| (m["format"].as_str().unwrap_or("").to_string(), media_title(m), m["id"].as_i64().unwrap_or(0))).collect();
    let (root_i, nums) = number_chain(&chain);
    let root = &walked[root_i];
    let me = nums.last().copied().flatten();
    Ok(Some(Franchise { key: format!("al{}", root["id"].as_i64().unwrap_or(0)), title: media_title(root), season: me }))
}

fn apply_franchise(m: &mut Meta, f: Option<Franchise>) {
    m.fc = true;
    if let Some(f) = f {
        // a lone season 1 with no sequel needs no franchise: it groups by its own name
        m.franchise = Some(f.key);
        m.franchise_title = Some(f.title);
        m.franchise_season = f.season;
    }
}

/// AniList: a second anime source, used when MyAnimeList's Jikan does not answer (it often limits shared Tor exits).
async fn anilist(app: &App, http: &reqwest::Client, title: &str) -> Result<Option<Cand>> {
    let query = "query($s:String){Page(perPage:8){media(search:$s,type:ANIME,sort:SEARCH_MATCH){id idMal title{romaji english native} synonyms format description(asHtml:false) genres seasonYear averageScore \
        coverImage{extraLarge large} streamingEpisodes{title} \
        characters(perPage:8,sort:ROLE){edges{node{name{full}} voiceActors(language:JAPANESE){name{full}}}}}}}";
    let body = serde_json::json!({ "query": query, "variables": { "s": title } });
    let Some(v) = post_json(http, &app.cfg.metadata.anilist, &body).await? else { return Ok(None) };
    let list: Vec<Value> = v["data"]["Page"]["media"].as_array().cloned().unwrap_or_default();
    let names = |a: &Value| -> Vec<String> {
        let mut n: Vec<String> = ["romaji", "english", "native"].iter().filter_map(|k| a["title"][*k].as_str().map(|s| s.to_string())).collect();
        n.extend(a["synonyms"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(|s| s.to_string())));
        n
    };
    let Some((i, score)) = best_of(title, &list, names) else { return Ok(None) };
    let a = &list[i];
    let cast: Vec<Person> = a["characters"]["edges"]
        .as_array()
        .map(|e| e.iter().filter_map(|x| Some(Person { name: x["node"]["name"]["full"].as_str()?.to_string(), role: x["voiceActors"][0]["name"]["full"].as_str().map(|s| s.to_string()) })).collect())
        .unwrap_or_default();
    // streamingEpisodes read "Episode 7 - The Name"
    let episodes: Vec<Ep> = a["streamingEpisodes"]
        .as_array()
        .map(|e| {
            e.iter()
                .filter_map(|x| {
                    let t = x["title"].as_str()?;
                    let rest = t.strip_prefix("Episode ")?;
                    let (n, name) = rest.split_once(" - ")?;
                    Some(Ep { season: None, number: n.trim().parse().ok()?, title: name.trim().to_string() })
                })
                .collect()
        })
        .unwrap_or_default();
    let m = Meta {
        overview: a["description"].as_str().map(strip_html).filter(|s| !s.is_empty()),
        genres: a["genres"].as_array().map(|g| g.iter().filter_map(|x| x.as_str()).map(pretty_genre).collect()).unwrap_or_default(),
        cast,
        rating: a["averageScore"].as_f64().map(|s| s / 10.0),
        year: a["seasonYear"].as_i64().map(|y| y as i32),
        source: "AniList".into(),
        anime: true,
        episodes,
        matched: a["title"]["english"].as_str().or(a["title"]["romaji"].as_str()).map(|s| s.to_string()),
        ..Default::default()
    };
    let mut m = m;
    if let Some(id) = a["id"].as_i64() {
        let f = franchise_of(app, http, "id", id).await.ok().flatten();
        apply_franchise(&mut m, f);
    }
    let poster = a["coverImage"]["extraLarge"].as_str().or(a["coverImage"]["large"].as_str()).map(|s| s.to_string());
    Ok(Some(Cand { meta: m, poster, score, japanese: true }))
}

async fn tmdb(app: &App, http: &reqwest::Client, title: &str, year: Option<i32>) -> Result<Option<Cand>> {
    let cfg = &app.cfg.metadata;
    let mut url = format!("{}/search/movie?api_key={}&query={}", cfg.tmdb, enc(&cfg.tmdb_key), enc(title));
    if let Some(y) = year {
        url.push_str(&format!("&year={y}"));
    }
    let Some(v) = get_json(http, &url).await? else { return Ok(None) };
    let list: Vec<Value> = v["results"].as_array().cloned().unwrap_or_default();
    let Some((i, score)) = best_of(title, &list, |m| vec![m["title"].as_str().unwrap_or("").to_string(), m["original_title"].as_str().unwrap_or("").to_string()]) else { return Ok(None) };
    let Some(id) = list[i]["id"].as_u64() else { return Ok(None) };
    let Some(d) = get_json(http, &format!("{}/movie/{id}?api_key={}&append_to_response=credits", cfg.tmdb, enc(&cfg.tmdb_key))).await? else { return Ok(None) };
    let m = Meta {
        overview: d["overview"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()),
        genres: d["genres"].as_array().map(|g| g.iter().filter_map(|x| x["name"].as_str()).map(pretty_genre).collect()).unwrap_or_default(),
        cast: d["credits"]["cast"].as_array().map(|a| a.iter().take(10).filter_map(|c| Some(Person { name: c["name"].as_str()?.to_string(), role: c["character"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string()) })).collect()).unwrap_or_default(),
        rating: d["vote_average"].as_f64().filter(|r| *r > 0.0),
        year: d["release_date"].as_str().and_then(|s| s.get(..4)).and_then(|s| s.parse().ok()),
        source: "TMDB".into(),
        matched: d["title"].as_str().map(|s| s.to_string()),
        ..Default::default()
    };
    let poster = d["poster_path"].as_str().map(|p| format!("{}/t/p/w500{p}", cfg.tmdb_images));
    Ok(Some(Cand { meta: m, poster, score, japanese: d["original_language"].as_str() == Some("ja") }))
}

async fn wikidata_movie(app: &App, http: &reqwest::Client, title: &str, year: Option<i32>) -> Result<Option<Cand>> {
    let c = &app.cfg.metadata;
    let url = format!("{}/w/api.php?action=wbsearchentities&search={}&language=en&type=item&limit=10&format=json", c.wikidata, enc(title));
    let Some(v) = get_json(http, &url).await? else { return Ok(None) };
    let found: Vec<Value> = v["search"].as_array().cloned().unwrap_or_default().into_iter().filter(|e| e["description"].as_str().map(|d| d.to_lowercase().contains("film")).unwrap_or(false)).collect();
    // among equally good titles, the one released in the year we were told
    let scored: Vec<(usize, f64)> = found
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let s = crate::util::title_similarity(title, e["label"].as_str().unwrap_or(""));
            let yr = year.map(|y| e["description"].as_str().unwrap_or("").contains(&y.to_string())).unwrap_or(false);
            (i, s + if yr { 0.05 } else { 0.0 })
        })
        .collect();
    let Some(&(i, score)) = scored.iter().filter(|(_, s)| *s >= ACCEPT).max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)) else { return Ok(None) };
    let Some(id) = found[i]["id"].as_str() else { return Ok(None) };
    let label = found[i]["label"].as_str().map(|s| s.to_string());
    let url = format!("{}/w/api.php?action=wbgetentities&ids={id}&props=claims|sitelinks&sitefilter=enwiki&format=json", c.wikidata);
    let Some(e) = get_json(http, &url).await? else { return Ok(None) };
    let ent = &e["entities"][id];
    let ids = |prop: &str, n: usize| -> Vec<String> {
        ent["claims"][prop].as_array().map(|a| a.iter().filter_map(|c| c["mainsnak"]["datavalue"]["value"]["id"].as_str()).take(n).map(|s| s.to_string()).collect()).unwrap_or_default()
    };
    let (genre_ids, cast_ids) = (ids("P136", 6), ids("P161", 10));
    let japanese = ids("P495", 4).iter().any(|c| c == "Q17"); // country of origin: Japan
    let all: Vec<String> = genre_ids.iter().chain(cast_ids.iter()).cloned().collect();
    let mut labels: HashMap<String, String> = HashMap::new();
    if !all.is_empty() {
        let url = format!("{}/w/api.php?action=wbgetentities&ids={}&props=labels&languages=en&format=json", c.wikidata, all.join("|"));
        if let Some(l) = get_json(http, &url).await? {
            for (k, v) in l["entities"].as_object().into_iter().flatten() {
                if let Some(t) = v["labels"]["en"]["value"].as_str() {
                    labels.insert(k.clone(), t.to_string());
                }
            }
        }
    }
    let genres: Vec<String> = genre_ids.iter().filter_map(|g| labels.get(g)).map(|g| pretty_genre(g)).collect();
    let cast: Vec<Person> = cast_ids.iter().filter_map(|g| labels.get(g)).map(|n| Person { name: n.clone(), role: None }).collect();
    let mut overview = None;
    let mut poster = None;
    if let Some(t) = ent["sitelinks"]["enwiki"]["title"].as_str() {
        if let Some(s) = get_json(http, &format!("{}/api/rest_v1/page/summary/{}", c.wikipedia, enc(&t.replace(' ', "_")))).await? {
            overview = s["extract"].as_str().map(|x| x.chars().take(1200).collect::<String>());
            poster = s["thumbnail"]["source"].as_str().map(|x| x.to_string());
        }
    }
    let file = |prop: &str| ent["claims"][prop].as_array().and_then(|a| a.first()).and_then(|c| c["mainsnak"]["datavalue"]["value"].as_str()).map(|s| s.to_string());
    if let Some(f) = file("P3383").or_else(|| file("P18")) {
        poster = Some(format!("{}/wiki/Special:FilePath/{}?width=500", c.commons, enc(&f.replace(' ', "_"))));
    }
    let date = ent["claims"]["P577"].as_array().and_then(|a| a.first()).and_then(|c| c["mainsnak"]["datavalue"]["value"]["time"].as_str()).and_then(|t| t.get(1..5)).and_then(|y| y.parse().ok());
    if genres.is_empty() && cast.is_empty() && overview.is_none() && poster.is_none() {
        return Ok(None);
    }
    Ok(Some(Cand { meta: Meta { overview, genres, cast, rating: None, year: date, source: "Wikidata".into(), matched: label, ..Default::default() }, poster, score, japanese }))
}

/// Try every name for the title against one source; the first acceptable match wins. A source that fails is
/// remembered (so the lookup can be retried later) but does not stop the others.
macro_rules! try_names {
    ($names:expr, $err:expr, $n:ident => $e:expr) => {{
        let mut hit: Option<Cand> = None;
        for $n in $names {
            match $e.await {
                Ok(Some(c)) => {
                    hit = Some(c);
                    break;
                }
                Ok(None) => {}
                Err(e) => *$err = Some(e),
            }
        }
        hit
    }};
}

/// Look one title up. `titles` are the names to try (the name from the file first). The sources are chosen from what
/// the file looks like, but the answer decides what it is: a "movie" that MyAnimeList knows by that exact name is anime.
/// Ok(None) means no source knows it.
pub async fn lookup(app: &App, titles: &[String], kind: &str, year: Option<i32>) -> Result<Option<(Meta, Option<Vec<u8>>)>> {
    let http = crate::acquire::client_for(app, Some(Duration::from_secs(60)), false)?;
    let mut names: Vec<String> = vec![];
    for t in titles {
        for v in crate::util::title_variants(t) {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(&v)) {
                names.push(v);
            }
        }
    }
    let mut err: Option<anyhow::Error> = None;
    let http = &http;

    #[allow(unused_assignments)]
    let mut found: Option<Cand> = None;
    match kind {
        "anime" => {
            found = try_names!(names.iter(), &mut err, n => anime_src(app, http, n));
            if found.is_none() {
                found = try_names!(names.iter(), &mut err, n => tvmaze(app, http, n));
                if let Some(c) = found.as_mut() {
                    c.meta.anime = true; // the file said anime, and a show by that name exists
                }
            }
            if found.is_none() {
                found = try_names!(names.iter(), &mut err, n => film(app, http, n, year));
                if let Some(c) = found.as_mut() {
                    c.meta.anime = true;
                }
            }
        }
        "series" => {
            found = try_names!(names.iter(), &mut err, n => tvmaze(app, http, n));
            let flagged = found.as_ref().map(|c| c.meta.anime).unwrap_or(false);
            if found.is_none() || flagged {
                // not on TVmaze, or TVmaze says it is anime: the anime sources know it better
                let better = try_names!(names.iter(), &mut err, n => anime_src(app, http, n));
                if let Some(mut b) = better {
                    if b.meta.episodes.is_empty() {
                        if let Some(tv) = &found {
                            b.meta.episodes = tv.meta.episodes.clone();
                        }
                    }
                    found = Some(b);
                }
            }
            if found.is_none() {
                found = try_names!(names.iter(), &mut err, n => film(app, http, n, year));
            }
        }
        _ => {
            found = try_names!(names.iter(), &mut err, n => film(app, http, n, year));
            // Is the film really an anime film? Only when its own record says Japan, or when no film by that name exists.
            let japanese_film = found.as_ref().map(|c| c.japanese).unwrap_or(false);
            if found.is_none() || japanese_film {
                let a = try_names!(names.iter(), &mut err, n => anime_src(app, http, n));
                let year_ok = |c: &Cand| match (year, c.meta.year) {
                    (Some(y), Some(cy)) => (y - cy).abs() <= 1,
                    _ => true,
                };
                if let Some(a) = a.filter(|a| a.score >= 0.85 && year_ok(a)) {
                    found = Some(a);
                }
            }
            if found.is_none() {
                found = try_names!(names.iter(), &mut err, n => tvmaze(app, http, n));
            }
        }
    }
    let Some(c) = found else {
        return match err {
            Some(e) => Err(e),
            None => Ok(None),
        };
    };
    let poster = match &c.poster {
        Some(u) => get_bytes(http, u).await,
        None => None,
    };
    Ok(Some((c.meta, poster)))
}

/// Jikan (MyAnimeList) first, then AniList. One failing does not stop the other.
async fn anime_src(app: &App, http: &reqwest::Client, title: &str) -> Result<Option<Cand>> {
    match jikan(app, http, title).await {
        Ok(Some(c)) => Ok(Some(c)),
        Ok(None) => anilist(app, http, title).await,
        Err(e) => match anilist(app, http, title).await {
            Ok(Some(c)) => Ok(Some(c)),
            _ => Err(e),
        },
    }
}

/// Pick the best of several candidate films: the title must be close, and the year (when we know it) breaks ties
/// and rules out remakes from other decades.
fn pick_film<T>(query: &str, items: &[T], year: Option<i32>, names: impl Fn(&T) -> Vec<String>, year_of: impl Fn(&T) -> Option<i32>) -> Option<(usize, f64)> {
    let mut best: Option<(usize, f64, f64)> = None;
    for (i, it) in items.iter().enumerate() {
        let s = names(it).iter().map(|n| crate::util::title_similarity(query, n)).fold(0.0, f64::max);
        if s < ACCEPT {
            continue;
        }
        let adj = match (year, year_of(it)) {
            (Some(y), Some(cy)) if (y - cy).abs() <= 1 => 0.05,
            (Some(_), Some(_)) => -0.15,
            _ => 0.0,
        };
        if best.map(|b| s + adj > b.2).unwrap_or(true) {
            best = Some((i, s, s + adj));
        }
    }
    best.map(|b| (b.0, b.1))
}

/// Apple's catalogue: no key needed, covers a lot of niche and older films, with a good poster and a long description.
async fn itunes(app: &App, http: &reqwest::Client, title: &str, year: Option<i32>) -> Result<Option<Cand>> {
    let url = format!("{}/search?term={}&media=movie&entity=movie&limit=15&country=us", app.cfg.metadata.itunes, enc(title));
    let Some(v) = get_json(http, &url).await? else { return Ok(None) };
    let list: Vec<Value> = v["results"].as_array().cloned().unwrap_or_default();
    let yr = |m: &Value| m["releaseDate"].as_str().and_then(|s| s.get(..4)).and_then(|s| s.parse::<i32>().ok());
    let Some((i, score)) = pick_film(title, &list, year, |m| vec![m["trackName"].as_str().unwrap_or("").to_string()], yr) else { return Ok(None) };
    let m = &list[i];
    let poster = m["artworkUrl100"].as_str().map(|u| u.replace("100x100bb", "600x600bb"));
    let meta = Meta {
        overview: m["longDescription"].as_str().or(m["shortDescription"].as_str()).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        genres: m["primaryGenreName"].as_str().map(|g| vec![pretty_genre(g)]).unwrap_or_default(),
        year: yr(m),
        source: "iTunes".into(),
        matched: m["trackName"].as_str().map(|s| s.to_string()),
        ..Default::default()
    };
    Ok(Some(Cand { meta, poster, score, japanese: false }))
}

/// IMDb's public search suggestions: very wide coverage of titles, with year, lead cast and a poster.
async fn imdb(app: &App, http: &reqwest::Client, title: &str, year: Option<i32>) -> Result<Option<Cand>> {
    let q: String = title.to_lowercase().chars().filter(|c| c.is_alphanumeric() || *c == ' ').collect();
    let q = q.split_whitespace().collect::<Vec<_>>().join("%20");
    if q.is_empty() {
        return Ok(None);
    }
    let first = q.chars().next().unwrap_or('a');
    let url = format!("{}/suggestion/{}/{q}.json", app.cfg.metadata.imdb, if first.is_ascii_alphabetic() { first } else { 'x' });
    let Some(v) = get_json(http, &url).await? else { return Ok(None) };
    let list: Vec<Value> = v["d"].as_array().cloned().unwrap_or_default().into_iter().filter(|e| matches!(e["qid"].as_str(), Some("movie") | Some("tvMovie") | Some("video"))).collect();
    let Some((i, score)) = pick_film(title, &list, year, |m| vec![m["l"].as_str().unwrap_or("").to_string()], |m| m["y"].as_i64().map(|y| y as i32)) else { return Ok(None) };
    let m = &list[i];
    let cast: Vec<Person> = m["s"].as_str().unwrap_or("").split(',').map(|n| n.trim()).filter(|n| !n.is_empty()).take(8).map(|n| Person { name: n.to_string(), role: None }).collect();
    let meta = Meta { cast, year: m["y"].as_i64().map(|y| y as i32), source: "IMDb".into(), matched: m["l"].as_str().map(|s| s.to_string()), ..Default::default() };
    Ok(Some(Cand { meta, poster: m["i"]["imageUrl"].as_str().map(|s| s.to_string()), score, japanese: false }))
}

/// Wikipedia itself: for the films that are only in an encyclopedia. Search, then the page summary (text and image).
async fn wikipedia_film(app: &App, http: &reqwest::Client, title: &str, year: Option<i32>) -> Result<Option<Cand>> {
    let c = &app.cfg.metadata;
    let q = match year {
        Some(y) => format!("{title} {y} film"),
        None => format!("{title} film"),
    };
    let url = format!("{}/w/api.php?action=query&list=search&srsearch={}&srlimit=6&format=json", c.wikipedia, enc(&q));
    let Some(v) = get_json(http, &url).await? else { return Ok(None) };
    let list: Vec<Value> = v["query"]["search"].as_array().cloned().unwrap_or_default();
    // "La La Land (film)" and "Titanic (1997 film)" are the pages we want, named like the film
    let clean = |t: &str| -> String {
        let mut s = t.to_string();
        if let Some(i) = s.rfind(" (") {
            if s.ends_with(" film)") || s.ends_with("(film)") {
                s.truncate(i);
            }
        }
        s
    };
    let is_film = |m: &Value| m["snippet"].as_str().map(|x| x.to_lowercase().contains("film")).unwrap_or(false) || m["title"].as_str().map(|t| t.contains("film)")).unwrap_or(false);
    let list: Vec<Value> = list.into_iter().filter(|m| is_film(m)).collect();
    let Some((i, score)) = pick_film(title, &list, None, |m| vec![clean(m["title"].as_str().unwrap_or(""))], |_| None) else { return Ok(None) };
    let page = list[i]["title"].as_str().unwrap_or("").to_string();
    let Some(s) = get_json(http, &format!("{}/api/rest_v1/page/summary/{}", c.wikipedia, enc(&page.replace(' ', "_")))).await? else { return Ok(None) };
    let overview = s["extract"].as_str().filter(|x| !x.is_empty()).map(|x| x.chars().take(1200).collect::<String>());
    let poster = s["thumbnail"]["source"].as_str().map(|x| x.to_string());
    if overview.is_none() && poster.is_none() {
        return Ok(None);
    }
    Ok(Some(Cand { meta: Meta { overview, source: "Wikipedia".into(), matched: Some(page), year, ..Default::default() }, poster, score, japanese: false }))
}

/// Fill what one source lacks from another, keeping the first source's answers where it has them.
fn fill(mut base: Cand, other: Cand) -> Cand {
    if base.meta.overview.is_none() {
        base.meta.overview = other.meta.overview;
    }
    if base.meta.genres.is_empty() {
        base.meta.genres = other.meta.genres;
    }
    if base.meta.cast.is_empty() {
        base.meta.cast = other.meta.cast;
    }
    if base.meta.rating.is_none() {
        base.meta.rating = other.meta.rating;
    }
    if base.meta.year.is_none() {
        base.meta.year = other.meta.year;
    }
    if base.poster.is_none() {
        base.poster = other.poster;
    }
    base.japanese |= other.japanese;
    base
}

fn complete(c: &Cand) -> bool {
    c.meta.overview.is_some() && !c.meta.genres.is_empty() && c.poster.is_some() && !c.meta.cast.is_empty()
}

/// Movies: several sources, because no single catalogue has everything. The first one that knows the film leads;
/// the others only fill in what it lacks (a poster, the cast, a description), and we stop once nothing is missing.
async fn film(app: &App, http: &reqwest::Client, title: &str, year: Option<i32>) -> Result<Option<Cand>> {
    let mut got: Option<Cand> = None;
    let mut last_err: Option<anyhow::Error> = None;
    macro_rules! step {
        ($call:expr) => {
            if got.as_ref().map(complete).unwrap_or(false) {
            } else {
                match $call.await {
                    Ok(Some(c)) => got = Some(match got.take() { Some(g) => fill(g, c), None => c }),
                    Ok(None) => {}
                    Err(e) => last_err = Some(e),
                }
            }
        };
    }
    if !app.cfg.metadata.tmdb_key.is_empty() {
        step!(tmdb(app, http, title, year));
    }
    step!(wikidata_movie(app, http, title, year));
    step!(itunes(app, http, title, year));
    step!(imdb(app, http, title, year));
    step!(wikipedia_film(app, http, title, year));
    match (got, last_err) {
        (Some(g), _) => Ok(Some(g)),
        (None, Some(e)) => Err(e),
        (None, None) => Ok(None),
    }
}

/// Look a title up and remember the answer (including "nothing found", so we do not keep asking).
pub async fn fetch_and_store(app: &Shared, key: &str, title: &str, kind: &str, year: Option<i32>) -> Result<bool> {
    fetch_and_store_titles(app, key, &[title.to_string()], kind, year).await
}

/// The names to look an item up by: what the file name says now (cleaned of site names, dub tags and the like),
/// then the title it was stored with (which may be something the owner typed in).
pub fn lookup_titles(it: &Item) -> Vec<String> {
    let mut v: Vec<String> = vec![];
    if let Some(f) = it.filename.as_deref() {
        let p = crate::util::parse_filename(f);
        if !p.title.is_empty() {
            v.push(p.title);
        }
    }
    if !v.iter().any(|t| t.eq_ignore_ascii_case(&it.title)) {
        v.push(it.title.clone());
    }
    v
}

pub async fn fetch_and_store_titles(app: &Shared, key: &str, titles: &[String], kind: &str, year: Option<i32>) -> Result<bool> {
    let title = titles.first().cloned().unwrap_or_default();
    let _ = &title;
    match lookup(app, titles, kind, year).await {
        Ok(Some((meta, poster))) => {
            if let Some(p) = &poster {
                save_poster(app, key, p)?;
            }
            let json = serde_json::to_string(&meta)?;
            app.db.with(|c| {
                c.execute(
                    "INSERT INTO meta(key,status,json,poster,fetched) VALUES(?1,'found',?2,?3,?4) ON CONFLICT(key) DO UPDATE SET status='found',json=excluded.json,poster=excluded.poster,fetched=excluded.fetched",
                    params![key, json, poster.is_some(), now()],
                )?;
                Ok(())
            })?;
            Ok(true)
        }
        Ok(None) => {
            app.db.with(|c| {
                c.execute("INSERT INTO meta(key,status,fetched) VALUES(?1,'none',?2) ON CONFLICT(key) DO UPDATE SET status='none',fetched=excluded.fetched", params![key, now()])?;
                Ok(())
            })?;
            Ok(false)
        }
        Err(e) => {
            // a network failure is not "unknown title": try again later
            app.db.with(|c| {
                c.execute("INSERT INTO meta(key,status,fetched) VALUES(?1,'error',?2) ON CONFLICT(key) DO UPDATE SET status='error',fetched=excluded.fetched", params![key, now()])?;
                Ok(())
            })?;
            bail!("{}", crate::util::friendly_error(&e))
        }
    }
}

/// Titles in the library with no stored answer yet (or an old unanswered one).
fn pending(app: &App) -> Vec<(String, Vec<String>, String, Option<i32>)> {
    // (status, when, has the newer fields). Answers saved before episode names and anime detection existed are asked for again once.
    let known: HashMap<String, (String, i64, bool)> = app
        .db
        .with(|c| {
            let mut st = c.prepare("SELECT key,status,fetched,COALESCE(json,'') LIKE '%\"matched\"%' AND (COALESCE(json,'') NOT LIKE '%\"anime\":true%' OR COALESCE(json,'') LIKE '%\"fc\":true%') FROM meta")?;
            let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, (r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, bool>(3)?))))?;
            Ok(rows.filter_map(|r| r.ok()).collect())
        })
        .unwrap_or_default();
    let items: Vec<Item> = app
        .db
        .with(|c| {
            let mut st = c.prepare(&format!("SELECT {} FROM items WHERE catalog=1 AND deleted=0 AND local='present' ORDER BY added_at DESC", crate::db::ITEM_LIGHT))?;
            let rows = st.query_map([], Item::from_row)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .unwrap_or_default();
    let t = now();
    let mut seen = std::collections::HashSet::new();
    let mut out = vec![];
    for it in items {
        let key = key_of(&it);
        if !seen.insert(key.clone()) {
            continue;
        }
        let due = match known.get(&key) {
            None => true,
            Some((s, at, _)) if s == "error" => t - at > 6 * 3600,
            Some((s, at, _)) if s == "none" => t - at > 14 * 86400,
            Some((s, _, current)) if s == "found" => !current,
            _ => false,
        };
        if due {
            let yr = it.year.or_else(|| it.filename.as_deref().and_then(|f| crate::util::parse_filename(f).year));
            out.push((key, lookup_titles(&it), it.kind.clone(), yr));
        }
    }
    out
}

/// Forget "not found" answers so the next pass looks again (after fixing a title, say).
pub fn retry_unknown(app: &App) -> Result<usize> {
    app.db.with(|c| Ok(c.execute("DELETE FROM meta WHERE status IN ('none','error')", [])?))
}

pub fn counts(app: &App) -> (usize, usize) {
    let found = app.db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM meta WHERE status='found'", [], |r| r.get::<_, i64>(0))?)).unwrap_or(0) as usize;
    (found, pending(app).len())
}

/// Background worker: wait for Tor and the unlocked library, then fill in details a few titles at a time.
pub async fn run(app: Shared) {
    // better lookups arrived: titles that were "not found" under the old rules get another try, by themselves
    const LOOKUP_VERSION: &str = "3";
    if app.db.get_setting("meta_lookup_version").ok().flatten().as_deref() != Some(LOOKUP_VERSION) {
        let _ = retry_unknown(&app);
        let _ = app.db.set_setting("meta_lookup_version", LOOKUP_VERSION);
    }
    loop {
        crate::rest::sleep(&app, Duration::from_secs(20)).await;
        if app.is_shutting_down() {
            return;
        }
        if !app.cfg.metadata.enabled || !app.keyring.is_unlocked() {
            continue;
        }
        if app.cfg.transport == "tor" && crate::acquire::effective_route(&app.cfg) == "tor" && app.tor.lock().unwrap().bootstrap < 100 {
            continue;
        }
        // lookups are the lowest priority: while files are being downloaded, uploaded or scanned, they wait
        if !app.active_downloads.lock().unwrap().is_empty() || !app.uploads.lock().unwrap().is_empty() || scan_backlog(&app) {
            continue;
        }
        for (key, titles, kind, year) in pending(&app).into_iter().take(4) {
            if app.is_shutting_down() {
                return;
            }
            if let Err(e) = fetch_and_store_titles(&app, &key, &titles, &kind, year).await {
                tracing::debug!("details for {titles:?}: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

fn scan_backlog(app: &App) -> bool {
    app.db.with(|c| Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM items WHERE local='quarantine' AND scan IS NULL AND deleted=0)", [], |r| r.get::<_, bool>(0))?)).unwrap_or(false)
}

pub fn stored_for(app: &App, key: &str) -> Option<Meta> {
    app.db
        .with(|c| Ok(c.query_row("SELECT json FROM meta WHERE key=?1 AND status='found'", [key], |r| r.get::<_, Option<String>>(0)).optional()?.flatten()))
        .ok()
        .flatten()
        .and_then(|j| serde_json::from_str(&j).ok())
}

#[cfg(test)]
mod genre_tests {
    use super::*;
    fn g(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn names_from_every_source_land_on_the_familiar_shelves() {
        assert_eq!(canon_genres(&g(&["horror film", "slasher film"])), g(&["Horror"]));
        assert_eq!(canon_genres(&g(&["Science Fiction", "comedy film"])), g(&["Sci-Fi", "Comedy"]));
        assert_eq!(canon_genres(&g(&["Action & Adventure", "anime"])), g(&["Action", "Adventure", "Animation"]));
        assert_eq!(canon_genres(&g(&["Romantic comedy"])), g(&["Comedy", "Romance"]));
        // things off the list are kept, and sorted after the familiar ones
        assert_eq!(canon_genres(&g(&["school", "drama"])), g(&["Drama", "School"]));
    }
}
