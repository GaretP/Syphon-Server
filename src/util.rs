use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Human-checkable fingerprint of a node id (hex public key): 5 groups of 4 hex chars.
pub fn fingerprint(node_id_hex: &str) -> String {
    let h = blake3::hash(node_id_hex.as_bytes());
    let hex = hex::encode(&h.as_bytes()[..10]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn sanitize_name(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let out = out.trim_matches('_').to_string();
    if out.is_empty() { "unnamed".into() } else { out.chars().take(48).collect() }
}

/// Fold case, accents' base letters and punctuation away, so "Spider-Man: No Way Home" is found by "spiderman no way home".
fn fold(s: &str) -> String {
    s.chars().map(|c| if c.is_alphanumeric() { c.to_lowercase().next().unwrap_or(c) } else { ' ' }).collect()
}

/// Does `hay` contain what was typed? Every typed word must appear (as a start of a word or anywhere inside the
/// text with punctuation and spaces removed), in any order.
pub fn search_matches(query: &str, hay: &str) -> bool {
    let q = fold(query);
    let words: Vec<&str> = q.split_whitespace().collect();
    if words.is_empty() {
        return true;
    }
    let h = fold(hay);
    let squashed: String = h.split_whitespace().collect();
    let all_squashed: String = words.concat();
    squashed.contains(&all_squashed) || words.iter().all(|w| h.contains(w))
}

/// The name a video is kept under: the title as shown, then the year (movies) or season and episode (shows),
/// then its own extension. What is displayed and what is stored agree, and nothing of the release group,
/// resolution or site that the file arrived with is kept.
pub fn tidy_name(title: &str, kind: &str, year: Option<i64>, season: Option<i64>, episode: Option<i64>, ext: &str) -> String {
    let mut t: String = title
        .chars()
        .map(|c| if c.is_control() || "/\\:*?\"<>|".contains(c) { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    t = t.trim_matches(|c: char| c == '.' || c == ' ').chars().take(120).collect::<String>().trim().to_string();
    if t.is_empty() {
        t = "Untitled".into();
    }
    let ext = ext.trim_matches('.').to_ascii_lowercase();
    let ext = if ext.is_empty() || ext.len() > 5 || !ext.chars().all(|c| c.is_ascii_alphanumeric()) { "mp4".to_string() } else { ext };
    let tag = match (kind, season, episode) {
        ("movie", ..) => year.filter(|y| (1850..=2100).contains(y)).map(|y| format!(" ({y})")).unwrap_or_default(),
        (_, Some(sn), Some(ep)) => format!(" S{sn:02}E{ep:02}"),
        (_, None, Some(ep)) => format!(" - {ep:02}"),
        _ => String::new(),
    };
    format!("{t}{tag}.{ext}")
}

pub fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Parsed {
    pub title: String,
    pub year: Option<i32>,
    pub season: Option<i32>,
    pub episode: Option<i32>,
    /// movie | series | anime
    pub kind: String,
}

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static regex"))
}

/// Best-effort title/year/season/episode extraction from a media filename.
pub fn parse_filename(name: &str) -> Parsed {
    static BRACKETS: OnceLock<Regex> = OnceLock::new();
    static SXXEYY: OnceLock<Regex> = OnceLock::new();
    static NXMM: OnceLock<Regex> = OnceLock::new();
    static LONGSE: OnceLock<Regex> = OnceLock::new();
    static EPONLY: OnceLock<Regex> = OnceLock::new();
    static DASHEP: OnceLock<Regex> = OnceLock::new();
    static YEAR: OnceLock<Regex> = OnceLock::new();

    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let stem = match base.rsplit_once('.') {
        Some((s, ext)) if ext.len() <= 5 && !s.is_empty() => s,
        _ => base,
    };
    let anime_tag = looks_like_anime(stem);
    let no_brackets = re(&BRACKETS, r"\[[^\]]*\]").replace_all(stem, " ").to_string();
    // (Dual Audio), (BD 1080p) and the like are release tags; a (2019) is kept, it is the year
    static PARENS: OnceLock<Regex> = OnceLock::new();
    let no_brackets = re(&PARENS, r"\(([^)]*)\)").replace_all(&no_brackets, |c: &regex::Captures| {
        let inner = c[1].trim();
        if inner.len() == 4 && inner.chars().all(|ch| ch.is_ascii_digit()) { format!("({inner})") } else { " ".to_string() }
    }).to_string();
    let s = no_brackets.replace(['.', '_'], " ");
    // a site or fansub group name stuck on the front ("AnimePahe Trinity Seven ...") is not part of the title
    static SITES: OnceLock<Regex> = OnceLock::new();
    let s = re(&SITES, &format!(r"(?i)^\s*(?:www\s?\S+\s*[-:]*\s*|(?:{})\b[\s\-:]*)+", SITE_WORDS)).replace(&s, "").to_string();

    let mut p = Parsed { kind: "movie".into(), ..Default::default() };
    let mut title_end = s.len();

    if let Some(c) = re(&SXXEYY, r"(?i)\bS(\d{1,2})\s?E(\d{1,3})\b").captures(&s) {
        p.season = c[1].parse().ok();
        p.episode = c[2].parse().ok();
        p.kind = "series".into();
        title_end = c.get(0).map(|m| m.start()).unwrap_or(title_end);
    } else if let Some(c) = re(&LONGSE, r"(?i)\bseason\s?(\d{1,2})\W{1,4}(?:episode|ep)\s?(\d{1,3})\b").captures(&s) {
        p.season = c[1].parse().ok();
        p.episode = c[2].parse().ok();
        p.kind = "series".into();
        title_end = c.get(0).map(|m| m.start()).unwrap_or(title_end);
    } else if let Some(c) = re(&NXMM, r"(?i)\b(\d{1,2})x(\d{2,3})\b").captures(&s) {
        p.season = c[1].parse().ok();
        p.episode = c[2].parse().ok();
        p.kind = "series".into();
        title_end = c.get(0).map(|m| m.start()).unwrap_or(title_end);
    } else if let Some(c) = re(&EPONLY, r"(?i)\b(?:episode|ep)\s?(\d{1,3})\b").captures(&s) {
        p.episode = c[1].parse().ok();
        p.kind = "series".into();
        title_end = c.get(0).map(|m| m.start()).unwrap_or(title_end);
    } else if let Some(c) = re(&DASHEP, r"\s-\s(\d{1,3})(?:v\d)?\b").captures(&s) {
        p.episode = c[1].parse().ok();
        p.kind = "series".into();
        title_end = c.get(0).map(|m| m.start()).unwrap_or(title_end);
    }

    let head = s[..title_end].to_string();
    let mut title = head.clone();
    if let Some(c) = re(&YEAR, r"\(?\b((?:19|20)\d{2})\b\)?").captures(&head) {
        let y: i32 = c[1].parse().unwrap_or(0);
        let m = c.get(0).unwrap();
        // only treat as year when something precedes it (avoid titles like "2012")
        if m.start() > 0 {
            p.year = Some(y);
            title = head[..m.start()].to_string();
        }
    } else if p.kind == "movie" {
        // a year may sit after the title in a movie name with trailing quality tags
        if let Some(c) = re(&YEAR, r"\(?\b((?:19|20)\d{2})\b\)?").captures(&s) {
            let m = c.get(0).unwrap();
            if m.start() > 0 {
                p.year = c[1].parse().ok();
                title = s[..m.start()].to_string();
            }
        }
    }
    let title = cut_release_tags(&title);
    let title = title.split_whitespace().collect::<Vec<_>>().join(" ");
    let title = title.trim_matches(|c: char| c == '-' || c == ' ' || c == '(').to_string();
    // "La-La-Land": hyphens used as spaces (two or more, and no real spaces) are spaces
    let title = if !title.contains(' ') && title.matches('-').count() >= 2 { title.replace('-', " ") } else { title };
    p.title = if title.is_empty() { stem.to_string() } else { title };
    if p.kind != "movie" || anime_tag {
        let (base, sn) = split_season_suffix(&p.title);
        if sn.is_some() && !base.is_empty() {
            p.title = base;
            if p.season.is_none() {
                p.season = sn;
            }
        }
    }
    if anime_tag {
        // fansub-style names are anime whether or not an episode number was found (OVAs and
        // anime films have none); a SxxExx name without any such sign stays a plain series
        p.kind = "anime".into();
    }
    p
}

/// Signs a filename is anime: a leading [Group] tag that is not a movie-release group, a [CRC32]
/// checksum tag, or words like OVA / NCED / "dual audio". A trailing [YTS] style tag does not count.
fn looks_like_anime(stem: &str) -> bool {
    static CRC: OnceLock<Regex> = OnceLock::new();
    static WORDS: OnceLock<Regex> = OnceLock::new();
    static LEAD: OnceLock<Regex> = OnceLock::new();
    let t = stem.trim_start();
    if re(&CRC, r"[\[(][0-9A-Fa-f]{8}[\])]").is_match(t) {
        return true;
    }
    if re(&WORDS, r"(?i)(?:^|[\s._\[(-])(ova|ovas|oad|ona|nced|ncop|dual[\s._-]?audio|multi[\s._-]?subs?|batch|dub|dubbed|english[\s._-]?dub|eng[\s._-]?dub)(?:$|[\s._\])-])").is_match(t) {
        return true;
    }
    static SITE: OnceLock<Regex> = OnceLock::new();
    if re(&SITE, &format!(r"(?i)(?:^|[\s._\[(-])(?:{})(?:$|[\s._\])-])", SITE_WORDS)).is_match(t) {
        return true;
    }
    if let Some(c) = re(&LEAD, r"^\[([^\]]{1,40})\]").captures(t) {
        let g = c[1].to_lowercase();
        let movie_groups = ["yts", "yify", "rarbg", "ettv", "eztv", "etrg", "tgx", "psa", "galaxyrg", "ion10", "mx"];
        let looks_movie = movie_groups.iter().any(|m| g == *m || g.starts_with(&format!("{m}.")) || g.starts_with(&format!("{m} ")));
        return !looks_movie;
    }
    false
}

/// Sites and fansub groups that only ever distribute anime. Seeing one is proof enough.
const SITE_WORDS: &str = r"animepahe|anime[\s._-]?pahe|subsplease|erai[\s._-]?raws|horriblesubs|gogoanime|9anime|kissanime|aniwave|hianime|nyaa|tsundere[\s._-]?raws|anidl|animetosho|ohys[\s._-]?raws|animekisa|animeland|animeheaven";

/// Words that start the "release junk" tail of a name: resolution, codec, source, language and dub tags.
const RELEASE_WORDS: &[&str] = &[
    "1080p", "720p", "2160p", "480p", "360p", "1080i", "4k", "uhd", "hdr", "hdr10", "dv", "x264", "x265", "h264", "h265", "hevc", "avc", "av1", "10bit", "10bits", "8bit",
    "aac", "ac3", "eac3", "ddp5", "dd5", "dts", "flac", "opus", "atmos", "bluray", "blu-ray", "bd", "bdrip", "brrip", "bdremux", "remux", "webrip", "web-dl", "webdl", "web", "hdtv", "dvdrip",
    "dvd", "proper", "repack", "complete", "batch", "uncensored", "uncut", "eng", "english", "dub", "dubbed", "sub", "subs", "subbed", "esub", "engsub", "multi", "multisub", "dual", "audio",
    "jpn", "jap", "japanese", "hindi", "nf", "amzn", "dsnp", "hmax",
];

/// Cut a title where the release tags begin ("Trinity Seven Eng Dub 1080p" -> "Trinity Seven"). The first word is
/// never cut, so a title that happens to start with such a word survives.
fn cut_release_tags(title: &str) -> String {
    let words: Vec<&str> = title.split_whitespace().collect();
    let cut = words.iter().enumerate().skip(1).find(|(_, w)| RELEASE_WORDS.contains(&w.trim_matches(|c: char| !c.is_alphanumeric() && c != '-').to_lowercase().as_str())).map(|(i, _)| i).unwrap_or(words.len());
    words[..cut].join(" ")
}

// ------------------------------------------------------------------ comparing titles

fn tokens(s: &str) -> Vec<String> {
    let low = s.to_lowercase().replace('&', " and ");
    let mut v: Vec<String> = low.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(|w| w.to_string()).collect();
    if v.first().map(|w| w == "the" || w == "a" || w == "an").unwrap_or(false) && v.len() > 1 {
        v.remove(0);
    }
    v
}

fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i];
        for j in 1..=b.len() {
            let c = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur.push((prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + c));
        }
        prev = cur;
    }
    prev[b.len()]
}

fn same_word(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let n = a.chars().count().min(b.chars().count());
    // a typo or a spelling variant ("Trinty", "Shippuuden"): tolerate one slip in a longer word, two in a long one
    let allow = if n >= 9 { 2 } else if n >= 5 { 1 } else { 0 };
    allow > 0 && edit_distance(a, b) <= allow
}

/// How alike two titles are, 0.0 to 1.0. Case, punctuation, a leading "The" and small typos do not matter;
/// extra words on one side cost a little when the shorter title is wholly inside the longer one.
pub fn title_similarity(a: &str, b: &str) -> f64 {
    let (ta, tb) = (tokens(a), tokens(b));
    if ta.is_empty() || tb.is_empty() {
        return 0.0;
    }
    let (small, large) = if ta.len() <= tb.len() { (&ta, &tb) } else { (&tb, &ta) };
    let mut used = vec![false; large.len()];
    let mut inter = 0usize;
    for w in small {
        if let Some(j) = (0..large.len()).find(|j| !used[*j] && same_word(w, &large[*j])) {
            used[j] = true;
            inter += 1;
        }
    }
    let jacc = inter as f64 / large.len() as f64;
    if inter == small.len() && small.len() >= 2 {
        // "Trinity Seven" inside "Trinity Seven Heavens Library"
        return jacc.max(0.8);
    }
    jacc
}

/// Other names worth trying for the same title: without a season or part suffix, before a colon or dash subtitle.
pub fn title_variants(title: &str) -> Vec<String> {
    static SEASON: OnceLock<Regex> = OnceLock::new();
    static TAIL: OnceLock<Regex> = OnceLock::new();
    let mut out: Vec<String> = vec![title.trim().to_string()];
    let mut push = |s: String| {
        let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
        if !s.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(&s)) {
            out.push(s);
        }
    };
    let base = re(&SEASON, r"(?i)[\s:-]+(?:season\s*\d+|\d+(?:st|nd|rd|th)\s+season|s\d{1,2}|part\s*\d+|cour\s*\d+|ii|iii|iv|v|final\s+season)\s*$").replace(title, "").to_string();
    push(base.clone());
    // "La-La-Land": hyphens standing in for spaces
    if !base.contains(' ') && base.matches('-').count() >= 1 {
        push(base.replace('-', " "));
    }
    for sep in [':', '–', '—'] {
        if let Some((a, _)) = base.split_once(sep) {
            push(a.to_string());
        }
    }
    if let Some((a, _)) = base.split_once(" - ") {
        push(a.to_string());
    }
    push(re(&TAIL, r"(?i)\s+(?:the\s+)?(?:movie|film|ova|ona|oad|special|specials|tv)\s*$").replace(&base, "").to_string());
    out
}

/// "Youjo Senki S2", "Overlord Season 3", "Re:Zero 2nd Season", "Mushoku Tensei II": the show's own name and
/// the season the suffix points to. Only meant for series and anime, never for movies ("Rocky II").
pub fn split_season_suffix(title: &str) -> (String, Option<i32>) {
    static SUF: OnceLock<Regex> = OnceLock::new();
    let r = re(&SUF, r"(?i)^(.*?\S)[\s:\-]+(?:s(\d{1,2})|season\s*(\d{1,2})|(\d{1,2})(?:st|nd|rd|th)\s+season|(ii|iii|iv|vi|vii|viii|ix))\s*$");
    if let Some(c) = r.captures(title.trim()) {
        let n = c.get(2).or(c.get(3)).or(c.get(4)).and_then(|m| m.as_str().parse::<i32>().ok()).or_else(|| {
            c.get(5).map(|m| match m.as_str().to_lowercase().as_str() { "ii" => 2, "iii" => 3, "iv" => 4, "vi" => 6, "vii" => 7, "viii" => 8, _ => 9 })
        });
        // a lone word before the suffix is kept whole ("Ii" is not a show), and season 0 or 1 adds nothing
        if let Some(n) = n.filter(|n| *n >= 1) {
            return (c[1].trim().to_string(), Some(n));
        }
    }
    (title.trim().to_string(), None)
}

/// What makes two episodes "the same show": the title with case, punctuation, a trailing year and
/// a leading "the" ignored. Used to gather loose episodes into one series ("Some.Show", "some show"
/// and "The Some Show (2019)" all become "someshow"). Never used for movies.
pub fn series_key(title: &str) -> String {
    plain_key(&split_season_suffix(title).0)
}

/// Like `series_key` but a trailing "II" or "S2" stays part of the name (movies: "Rocky II" is not "Rocky").
pub fn plain_key(title: &str) -> String {
    static YEAR: OnceLock<Regex> = OnceLock::new();
    let t = title.to_lowercase().replace('&', " and ");
    let t = re(&YEAR, r"[\(\[]?\b(?:19|20)\d{2}\b[\)\]]?\s*$").replace(&t, "").to_string();
    let t = t.trim_start().strip_prefix("the ").unwrap_or(t.trim_start()).to_string();
    t.chars().filter(|c| c.is_alphanumeric()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seasons_named_in_the_title_become_seasons_of_one_show() {
        for (name, season) in [("[Group] Youjo Senki S2 - 03 [1080p].mkv", Some(2)), ("[Group] Youjo Senki - 03 [1080p].mkv", None), ("Overlord Season 3 - 04.mkv", Some(3)), ("Re Zero 2nd Season - 01.mkv", Some(2))] {
            let p = parse_filename(name);
            assert_eq!(p.season, season, "{name}");
            assert!(p.title == "Youjo Senki" || p.title == "Overlord" || p.title == "Re Zero", "{name}: {}", p.title);
        }
        assert_eq!(series_key("Youjo Senki S2"), series_key("Youjo Senki"));
        assert_eq!(split_season_suffix("Youjo Senki S2"), ("Youjo Senki".to_string(), Some(2)));
        // a movie sequel keeps its name
        assert_eq!(parse_filename("Rocky.II.1979.mp4").title, "Rocky II");
        let l = parse_filename("La-La-Land.2016.1080p.mp4");
        assert_eq!((l.title.as_str(), l.year), ("La La Land", Some(2016)));
        assert_eq!(parse_filename("Spider-Man.2002.mp4").title, "Spider-Man");
    }

    #[test]
    fn episodes_of_one_show_share_a_key_however_they_are_named() {
        let names = [
            "Some.Show.S01E01.1080p.WEB-DL.mkv",
            "some show - 1x02.mp4",
            "The Some Show (2019) Season 2 Episode 3.mkv",
            "Some_Show_S03E10_720p.mp4",
        ];
        let keys: Vec<_> = names.iter().map(|n| series_key(&parse_filename(n).title)).collect();
        assert!(keys.iter().all(|k| k == "someshow"), "{keys:?}");
        let p = parse_filename("The Some Show (2019) Season 2 Episode 3.mkv");
        assert_eq!((p.season, p.episode, p.kind.as_str()), (Some(2), Some(3), "series"));
        let q = parse_filename("Another Show Episode 12.mkv");
        assert_eq!((q.title.as_str(), q.season, q.episode), ("Another Show", None, Some(12)));
        assert_ne!(series_key("Show A"), series_key("Show B"));
    }

    #[test]
    fn parses_movies_series_anime() {
        let m = parse_filename("The.Great.Movie.1999.1080p.BluRay.x264.mkv");
        assert_eq!((m.title.as_str(), m.year, m.kind.as_str()), ("The Great Movie", Some(1999), "movie"));

        let s = parse_filename("Some Show S02E07 Title.mp4");
        assert_eq!((s.title.as_str(), s.season, s.episode, s.kind.as_str()), ("Some Show", Some(2), Some(7), "series"));

        let a = parse_filename("[Group] Cool Anime - 05 [1080p].mkv");
        assert_eq!((a.title.as_str(), a.episode, a.kind.as_str()), ("Cool Anime", Some(5), "anime"));

        let n = parse_filename("clip.mp4");
        assert_eq!(n.title, "clip");
    }

    #[test]
    fn release_names_from_anime_sites_and_dubs_become_clean_titles() {
        for (n, title, ep) in [
            ("AnimePahe_Trinity_Seven_-_01_BD_1080p_Eng_Dub.mp4", "Trinity Seven", Some(1)),
            ("[AnimePahe] Trinity Seven - 12 [BD 720p][Eng Dub].mkv", "Trinity Seven", Some(12)),
            ("AnimePahe Trinity Seven Eng Dub.mp4", "Trinity Seven", None),
            ("Trinity.Seven.Dubbed.1080p.BluRay.mkv", "Trinity Seven", None),
            ("[Erai-raws] Trinity Seven - 03 [1080p][Multiple Subtitle].mkv", "Trinity Seven", Some(3)),
        ] {
            let p = parse_filename(n);
            assert_eq!((p.title.as_str(), p.episode, p.kind.as_str()), (title, ep, "anime"), "{n} -> {p:?}");
        }
        // a plain movie that merely has "web" or "dual" later on stays a movie
        let m = parse_filename("Dual.Survival.2019.1080p.WEB-DL.mkv");
        assert_eq!((m.title.as_str(), m.kind.as_str()), ("Dual Survival", "movie"));
    }

    #[test]
    fn titles_that_are_not_one_to_one_still_match() {
        assert!(title_similarity("Trinity Seven", "Trinity Seven") > 0.99);
        assert!(title_similarity("Trinty Seven", "Trinity Seven") > 0.9, "a typo");
        assert!(title_similarity("Trinity Seven", "Trinity Seven: Heavens Library & Crimson Lord") >= 0.8, "a longer official title");
        assert!(title_similarity("Naruto Shippuden", "Naruto: Shippuuden") > 0.9);
        assert!(title_similarity("Attack on Titan", "Shingeki no Kyojin") < 0.3);
        assert!(title_similarity("Up", "Upgrade") < 0.5);
        let v = title_variants("Trinity Seven Season 2");
        assert!(v.contains(&"Trinity Seven".to_string()), "{v:?}");
        let v = title_variants("Fate/stay night: Unlimited Blade Works");
        assert!(v.iter().any(|x| x == "Fate/stay night"), "{v:?}");
    }

    #[test]
    fn fingerprint_shape() {
        let f = fingerprint("abcd");
        assert_eq!(f.split(' ').count(), 5);
    }

    #[test]
    fn anime_is_recognised_without_catching_ordinary_movies() {
        for n in [
            "[SubsPlease] Frieren - 07 (1080p) [A1B2C3D4].mkv",
            "[Group] Some Show Movie [BD 1080p].mkv",
            "Cool Anime OVA 2.mkv",
            "Cool.Anime.S01E03.Dual.Audio.1080p.mkv",
            "Spirited Away (2001) [DEADBEEF].mkv",
        ] {
            assert_eq!(parse_filename(n).kind, "anime", "{n}");
        }
        assert_eq!(parse_filename("[SubsPlease] Frieren - 07 (1080p) [A1B2C3D4].mkv").title, "Frieren");
        assert_eq!(parse_filename("[SubsPlease] Frieren - 07 (1080p) [A1B2C3D4].mkv").episode, Some(7));
        assert_eq!(parse_filename("The.Great.Movie.1999.1080p.BluRay.x264-[YTS].mkv").kind, "movie");
        assert_eq!(parse_filename("[YTS.MX] Great Movie (2010).mp4").kind, "movie");
        assert_eq!(parse_filename("Some Show S02E07 Title.mp4").kind, "series");
    }
}

/// Write a file so that a power cut leaves either the old or the new content, never half of one:
/// write to a temporary sibling, flush it to disk, rename over the target, flush the directory.
pub fn write_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// True when retrying later is likely to work: a dropped connection, a stall, a busy server.
pub fn is_transient(e: &anyhow::Error) -> bool {
    for cause in e.chain() {
        if let Some(r) = cause.downcast_ref::<reqwest::Error>() {
            if r.is_timeout() || r.is_connect() || r.is_body() || r.is_decode() || r.is_request() {
                return true;
            }
            if let Some(s) = r.status() {
                return s.as_u16() == 429 || s.is_server_error();
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            if matches!(io.kind(), ConnectionReset | ConnectionAborted | BrokenPipe | TimedOut | UnexpectedEof | NotConnected | Interrupted) {
                return true;
            }
        }
    }
    let m = format!("{e:#}").to_lowercase();
    ["close_notify", "unexpected eof", "connection reset", "connection closed", "broken pipe", "error reading a body", "error decoding response body", "timed out", "stalled", "socks", "tor circuit"]
        .iter()
        .any(|k| m.contains(k))
}

/// Turn a technical error into something a person can act on. Messages that are already written
/// for people (everything this program raises itself) pass through unchanged.
pub fn friendly_error(e: &anyhow::Error) -> String {
    let full = format!("{e:#}");
    let m = full.to_lowercase();
    for cause in e.chain() {
        if let Some(r) = cause.downcast_ref::<reqwest::Error>() {
            if let Some(s) = r.status() {
                return match s.as_u16() {
                    401 | 403 => "The site refused access (the link may need a sign-in, or has expired).".into(),
                    404 | 410 => "That file was not found. It may have been moved or removed.".into(),
                    429 => "The site is limiting requests. Wait a few minutes and try again.".into(),
                    c if c >= 500 => format!("The site had a problem on its side ({c}). Try again later."),
                    c => format!("The site answered with an error ({c})."),
                };
            }
            if r.is_timeout() {
                return "The site took too long to answer.".into();
            }
        }
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::PermissionDenied {
                return "Syphon is not allowed to write to its data folder.".into();
            }
        }
    }
    if m.contains("no space left") || m.contains("disk quota") || m.contains("storage full") {
        return "This node is out of disk space. Free some space and try again.".into();
    }
    if m.contains("close_notify") || m.contains("unexpected eof") || m.contains("connection reset") || m.contains("error reading a body") || m.contains("error decoding response body") || m.contains("broken pipe") || m.contains("connection closed") {
        return "The connection dropped in the middle of the download.".into();
    }
    if m.contains("socks") || m.contains("host unreachable") || m.contains("ttl expired") || m.contains("general failure") {
        return "Tor could not reach that site right now. Tor circuits can be slow or blocked; try again.".into();
    }
    if m.contains("error trying to connect") || m.contains("connection refused") || m.contains("dns error") || m.contains("failed to lookup") || m.contains("tcp connect error") || m.contains("network is unreachable") {
        return "Could not connect. Check the internet connection (and that Tor is connected).".into();
    }
    if m.contains("certificate") || m.contains("tls") || m.contains("handshake") {
        return "A secure connection to that site could not be set up.".into();
    }
    if m.contains("database is locked") || m.contains("database is busy") {
        return "The node is busy for a moment. Try again.".into();
    }
    // our own messages are already plain; keep them, but do not let a long technical chain through
    let first = full.split(": ").next().unwrap_or(&full);
    let short = if full.len() > 220 { first.to_string() } else { full };
    short.chars().take(220).collect()
}

#[cfg(test)]
mod tidy_tests {
    use super::*;

    #[test]
    fn typing_what_is_shown_finds_it() {
        assert!(search_matches("spiderman no way home", "Spider-Man: No Way Home (2021)"));
        assert!(search_matches("way home spider", "Spider-Man: No Way Home"));
        assert!(search_matches("  ", "anything"));
        assert!(!search_matches("batman", "Spider-Man"));
        assert!(search_matches("trinity seven", "Trinity Seven S01E02.mkv"));
    }

    #[test]
    fn stored_names_are_the_shown_title_and_still_read_back_the_same() {
        for raw in [
            "Movie.Name.2019.1080p.BluRay.x264-RARBG.mkv",
            "Some Show S02E05 720p WEB.mp4",
            "[Group] Trinity Seven - 07 [1080p].mkv",
            "Plain Title.avi",
        ] {
            let p = parse_filename(raw);
            let ext = raw.rsplit('.').next().unwrap();
            let n = tidy_name(&p.title, &p.kind, p.year.map(|y| y as i64), p.season.map(|v| v as i64), p.episode.map(|v| v as i64), ext);
            let q = parse_filename(&n);
            // the type is stored separately (anime is told apart by the tag that is dropped from the name)
            assert_eq!((&q.title, q.year, q.season, q.episode), (&p.title, p.year, p.season, p.episode), "{raw} -> {n}");
            assert!(n.ends_with(&format!(".{ext}")));
        }
        assert_eq!(tidy_name("A/B: C?", "movie", Some(2001), None, None, "MKV"), "A B C (2001).mkv");
        assert_eq!(tidy_name("", "movie", None, None, None, "exe!"), "Untitled.mp4");
    }
}
