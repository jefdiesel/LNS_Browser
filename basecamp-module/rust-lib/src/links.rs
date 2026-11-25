//! Per-folder `lns-links/1` parser, formatter, URL normalizer, and nested folder resolver.
//!
//! Mirrors `lns-browser/basecamp/qml/logic.mjs` verbatim:
//! - Line 1 must be `# lns-links/1`.
//! - Optional `# index <name>` (default `index.html`) and `# title <text>`.
//! - Files: `<name> <cid>[ <sha256>]`
//! - Subfolders: `<name>/ <cid>[ <sha256>]`
//! - Names are single path segments (no `/`, `\`, `.`, `..`, whitespace, `?`, `#`, or control chars).
//! - Duplicate names (including file/subfolder collision) reject the whole list.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use crate::storage::is_valid_cid;

pub const LINKS_HEADER: &str = "# lns-links/1";
pub const LINKS_CONTENT_TYPE: &str = "text/vnd.logos.lns-links";
pub const MAX_ONCHAIN_LINKS_BYTES: usize = 10 * 1024;
pub const MAX_LINKS_DEPTH: usize = 32;
pub const MAX_LINKS_LIST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_LINKS_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedLinksList {
    pub list: LinksList,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Dir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinksEntry {
    pub name: String,
    pub kind: EntryKind,
    pub cid: String,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinksList {
    pub index: String,
    pub title: Option<String>,
    pub entries: Vec<LinksEntry>,
    pub by_name: BTreeMap<String, LinksEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPath {
    pub path: String,
    pub segments: Vec<String>,
    pub trailing_slash: bool,
    pub fragment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlKind {
    Lns,
    Cid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub kind: UrlKind,
    pub host: String, // LNS name or CID
    pub path: String,
    pub site_base: String,
    pub canonical: String,
    pub fragment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedLink {
    pub entry: LinksEntry,
    pub resolved_path: String,
    pub canonical_url_path: String,
    pub canonical_dir: String,
    pub folder_entries: Vec<LinksEntry>,
    pub folder_title: Option<String>,
    pub fragment: Option<String>,
    pub folders_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveOutcome {
    Found(ResolvedLink),
    NotFound {
        requested_path: String,
        is_directory: bool,
        canonical_url_path: Option<String>,
        folder_entries: Vec<LinksEntry>,
    },
}

pub fn is_valid_lns_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 32 {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'-')
}

pub fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn is_valid_segment_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 || name == "." || name == ".." {
        return false;
    }
    !name.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, '/' | '\\' | '?' | '#')
    })
}

pub fn is_links_content_type(ct: &str) -> bool {
    ct.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .eq_ignore_ascii_case(LINKS_CONTENT_TYPE)
}

pub fn is_links_list_text(text: &str) -> bool {
    text.lines()
        .next()
        .map(|l| l.trim_end_matches('\r').trim() == LINKS_HEADER)
        .unwrap_or(false)
}

pub fn normalize_links_path(raw: &str) -> Result<NormalizedPath, String> {
    if raw.chars().any(|c| c.is_control()) {
        return Err("Path contains control characters".to_owned());
    }
    let (without_frag, fragment) = match raw.find('#') {
        Some(idx) => (&raw[..idx], Some(raw[idx..].to_owned())),
        None => (raw, None),
    };
    let path_part = match without_frag.find('?') {
        Some(idx) => &without_frag[..idx],
        None => without_frag,
    };
    let had_trailing_slash = path_part.is_empty() || path_part.ends_with('/');
    let mut segments: Vec<String> = Vec::new();
    for seg in path_part.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            segments.pop();
            continue;
        }
        segments.push(seg.to_owned());
    }
    if segments.is_empty() {
        return Ok(NormalizedPath {
            path: "/".to_owned(),
            segments,
            trailing_slash: true,
            fragment,
        });
    }
    let mut path = format!("/{}", segments.join("/"));
    if had_trailing_slash {
        path.push('/');
    }
    Ok(NormalizedPath {
        path,
        segments,
        trailing_slash: had_trailing_slash,
        fragment,
    })
}

pub fn parse_url(raw: &str) -> Result<ParsedUrl, String> {
    let s = raw.trim();
    if s.is_empty() {
        return Err("Enter an LNS URL (e.g. lns://jef) or CID (cid://...)".to_owned());
    }
    if s.chars().any(|c| c.is_control()) {
        return Err("URL contains invalid control characters".to_owned());
    }
    if s.len() >= 6 && s[..6].eq_ignore_ascii_case("cid://") {
        let rest = &s[6..];
        let sep = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let cid = &rest[..sep];
        let tail = if sep == rest.len() { "/" } else { &rest[sep..] };
        if !is_valid_cid(cid) {
            return Err("Invalid CID format".to_owned());
        }
        let norm_input = if tail.starts_with('/') {
            tail.to_owned()
        } else {
            format!("/{tail}")
        };
        let norm = normalize_links_path(&norm_input)?;
        let site_base = format!("cid://{cid}");
        let canonical = if norm.path == "/" {
            site_base.clone()
        } else {
            format!("{site_base}{}", norm.path)
        };
        return Ok(ParsedUrl {
            kind: UrlKind::Cid,
            host: cid.to_owned(),
            path: norm.path,
            site_base,
            canonical,
            fragment: norm.fragment,
        });
    }

    let mut body = s;
    if body.len() >= 6 && body[..6].eq_ignore_ascii_case("lns://") {
        body = &body[6..];
    } else if body.len() >= 4 && body[..4].eq_ignore_ascii_case("lns:") {
        body = &body[4..];
    }
    if let Some(stripped) = body.strip_prefix('@') {
        body = stripped;
    }

    let sep = body.find(['/', '?', '#']).unwrap_or(body.len());
    let mut host = body[..sep].to_ascii_lowercase();
    if host.len() > 4 && host.ends_with(".lez") {
        host.truncate(host.len() - 4);
    }
    let tail = if sep == body.len() { "/" } else { &body[sep..] };

    if !is_valid_lns_name(&host) {
        return Err(format!("Invalid LNS name: {host}"));
    }
    let norm_input = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    let norm = normalize_links_path(&norm_input)?;
    let site_base = format!("lns://{host}");
    let canonical = if norm.path == "/" {
        site_base.clone()
    } else {
        format!("{site_base}{}", norm.path)
    };
    Ok(ParsedUrl {
        kind: UrlKind::Lns,
        host,
        path: norm.path,
        site_base,
        canonical,
        fragment: norm.fragment,
    })
}

pub fn parse_links_list(text: &str) -> Result<LinksList, String> {
    if text.len() > MAX_LINKS_LIST_BYTES {
        return Err(format!(
            "Links list exceeds maximum size of {MAX_LINKS_LIST_BYTES} bytes"
        ));
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err("Links list contains invalid control characters".to_owned());
    }
    let mut lines = text.split('\n');
    let first = lines.next().unwrap_or("").trim_end_matches('\r').trim();
    if first != LINKS_HEADER {
        return Err(format!("Links list must start with '{LINKS_HEADER}'"));
    }

    let mut index_name = "index.html".to_owned();
    let mut has_index_directive = false;
    let mut title: Option<String> = None;
    let mut by_name: BTreeMap<String, LinksEntry> = BTreeMap::new();

    for (idx, raw_line) in lines.enumerate() {
        let line_no = idx + 2;
        let trimmed = raw_line.trim_end_matches('\r').trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix('#') {
            let rest = comment.trim();
            if rest == "index" || rest.starts_with("index ") || rest.starts_with("index\t") {
                let val = rest[5..].trim();
                if !is_valid_segment_name(val) {
                    return Err(format!("Line {line_no}: invalid # index name '{val}'"));
                }
                if has_index_directive {
                    return Err(format!("Line {line_no}: duplicate # index directive"));
                }
                index_name = val.to_owned();
                has_index_directive = true;
            } else if rest.starts_with("title ") || rest.starts_with("title\t") {
                let val: String = rest[5..]
                    .replace('\t', " ")
                    .trim()
                    .chars()
                    .take(200)
                    .collect();
                if !val.is_empty() {
                    title = Some(val);
                }
            }
            continue;
        }

        if by_name.len() >= MAX_LINKS_ENTRIES {
            return Err(format!(
                "Links list exceeds maximum of {MAX_LINKS_ENTRIES} entries"
            ));
        }

        let parts: Vec<&str> = trimmed
            .split(|c| c == ' ' || c == '\t')
            .filter(|p| !p.is_empty())
            .collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!(
                "Line {line_no}: expected '<name>[/] <cid>[ <sha256>]'"
            ));
        }
        let raw_name = parts[0];
        let cid = parts[1];
        let (kind, name) = if let Some(stripped) = raw_name.strip_suffix('/') {
            (EntryKind::Dir, stripped)
        } else {
            (EntryKind::File, raw_name)
        };
        if !is_valid_segment_name(name) {
            return Err(format!("Line {line_no}: invalid entry name '{raw_name}'"));
        }
        if !is_valid_cid(cid) {
            return Err(format!("Line {line_no}: invalid CID '{cid}'"));
        }
        let sha256 = if parts.len() == 3 {
            if !is_valid_sha256(parts[2]) {
                return Err(format!("Line {line_no}: invalid SHA-256 '{}'", parts[2]));
            }
            Some(parts[2].to_ascii_lowercase())
        } else {
            None
        };
        if by_name.contains_key(name) {
            return Err(format!("Line {line_no}: duplicate entry '{name}'"));
        }
        by_name.insert(
            name.to_owned(),
            LinksEntry {
                name: name.to_owned(),
                kind,
                cid: cid.to_owned(),
                sha256,
            },
        );
    }

    let entries: Vec<LinksEntry> = by_name.values().cloned().collect();
    Ok(LinksList {
        index: index_name,
        title,
        entries,
        by_name,
    })
}

pub fn format_links_list(list: &LinksList) -> Result<String, String> {
    let mut out = vec![LINKS_HEADER.to_owned()];
    if let Some(ref t) = list.title {
        let clean: String = t
            .replace(['\r', '\n', '\t'], " ")
            .trim()
            .chars()
            .take(200)
            .collect();
        if clean.chars().any(|c| c.is_control()) {
            return Err("Title contains control characters".to_owned());
        }
        if !clean.is_empty() {
            out.push(format!("# title {clean}"));
        }
    }
    if !list.index.is_empty() {
        if !is_valid_segment_name(&list.index) {
            return Err(format!("Invalid index name '{}'", list.index));
        }
        out.push(format!("# index {}", list.index));
    }

    let mut sorted: BTreeMap<String, LinksEntry> = BTreeMap::new();
    for entry in &list.entries {
        if !is_valid_segment_name(&entry.name) {
            return Err(format!("Invalid entry name '{}'", entry.name));
        }
        if !is_valid_cid(&entry.cid) {
            return Err(format!("Invalid CID for '{}'", entry.name));
        }
        if let Some(ref sha) = entry.sha256 {
            if !is_valid_sha256(sha) {
                return Err(format!("Invalid SHA-256 for '{}'", entry.name));
            }
        }
        if sorted.contains_key(&entry.name) {
            return Err(format!("Duplicate entry '{}'", entry.name));
        }
        sorted.insert(entry.name.clone(), entry.clone());
    }

    for entry in sorted.values() {
        let suffix = if entry.kind == EntryKind::Dir { "/" } else { "" };
        let mut line = format!("{}{} {}", entry.name, suffix, entry.cid);
        if let Some(ref sha) = entry.sha256 {
            if !sha.is_empty() {
                line.push(' ');
                line.push_str(&sha.to_ascii_lowercase());
            }
        }
        out.push(line);
    }

    Ok(format!("{}\n", out.join("\n")))
}

pub fn resolve_links_tree<F>(
    root: &LinksList,
    raw_path: &str,
    cache: &mut HashMap<String, CachedLinksList>,
    mut load_folder: F,
) -> Result<ResolveOutcome, String>
where
    F: FnMut(&str, Option<&str>) -> Result<CachedLinksList, String>,
{
    let norm = normalize_links_path(raw_path)?;
    let mut current = root.clone();
    let mut idx: usize = 0;
    let mut depth: usize = 0;
    let mut folders_verified = true;

    loop {
        if idx >= norm.segments.len() {
            let canonical_dir = if norm.segments.is_empty() {
                "/".to_owned()
            } else {
                format!("/{}/", norm.segments.join("/"))
            };
            if let Some(index_entry) = current.by_name.get(&current.index) {
                if index_entry.kind == EntryKind::File {
                    return Ok(ResolveOutcome::Found(ResolvedLink {
                        entry: index_entry.clone(),
                        resolved_path: format!("{canonical_dir}{}", index_entry.name),
                        canonical_url_path: canonical_dir.clone(),
                        canonical_dir,
                        folder_entries: current.entries.clone(),
                        folder_title: current.title.clone(),
                        fragment: norm.fragment.clone(),
                        folders_verified,
                    }));
                }
            }
            return Ok(ResolveOutcome::NotFound {
                requested_path: norm.path,
                is_directory: true,
                canonical_url_path: Some(canonical_dir),
                folder_entries: current.entries,
            });
        }

        let seg = &norm.segments[idx];
        let is_last = idx + 1 == norm.segments.len();
        let Some(entry) = current.by_name.get(seg).cloned() else {
            return Ok(ResolveOutcome::NotFound {
                requested_path: norm.path,
                is_directory: false,
                canonical_url_path: None,
                folder_entries: Vec::new(),
            });
        };

        if entry.kind == EntryKind::Dir {
            depth += 1;
            if depth > MAX_LINKS_DEPTH {
                return Err(format!("Folder nesting exceeds limit ({MAX_LINKS_DEPTH})"));
            }
            let expected_sha = entry.sha256.as_deref().filter(|s| !s.is_empty());
            if expected_sha.is_none() {
                folders_verified = false;
            }
            let cached_hit = match cache.get(&entry.cid) {
                Some(cached) => match expected_sha {
                    Some(exp) => match cached.sha256.as_deref().filter(|s| !s.is_empty()) {
                        Some(actual) if actual.eq_ignore_ascii_case(exp) => {
                            Some(cached.list.clone())
                        }
                        Some(actual) => {
                            return Err(format!(
                                "SHA-256 mismatch for cached folder CID {}: expected {}, got {}",
                                entry.cid,
                                exp.to_ascii_lowercase(),
                                actual.to_ascii_lowercase()
                            ));
                        }
                        None => None,
                    },
                    None => Some(cached.list.clone()),
                },
                None => None,
            };
            let next_list = if let Some(list) = cached_hit {
                list
            } else {
                let loaded = load_folder(&entry.cid, expected_sha)?;
                if let Some(exp) = expected_sha {
                    if let Some(actual) = loaded.sha256.as_deref().filter(|s| !s.is_empty()) {
                        if !actual.eq_ignore_ascii_case(exp) {
                            return Err(format!(
                                "SHA-256 mismatch for folder CID {}: expected {}, got {}",
                                entry.cid,
                                exp.to_ascii_lowercase(),
                                actual.to_ascii_lowercase()
                            ));
                        }
                    } else {
                        return Err(format!(
                            "Folder loader did not verify SHA-256 for CID {}",
                            entry.cid
                        ));
                    }
                }
                let list = loaded.list.clone();
                cache.insert(entry.cid.clone(), loaded);
                list
            };
            current = next_list;
            idx += 1;
            continue;
        }

        // Exact file entry
        if !is_last || norm.trailing_slash {
            return Ok(ResolveOutcome::NotFound {
                requested_path: norm.path,
                is_directory: false,
                canonical_url_path: None,
                folder_entries: Vec::new(),
            });
        }

        let resolved_path = format!("/{}", norm.segments.join("/"));
        let canonical_dir = if norm.segments.len() <= 1 {
            "/".to_owned()
        } else {
            format!("/{}/", norm.segments[..norm.segments.len() - 1].join("/"))
        };
        return Ok(ResolveOutcome::Found(ResolvedLink {
            entry,
            resolved_path: resolved_path.clone(),
            canonical_url_path: resolved_path,
            canonical_dir,
            folder_entries: current.entries,
            folder_title: current.title,
            fragment: norm.fragment,
            folders_verified,
        }));
    }
}

pub fn is_binary_download_path(path: &str) -> bool {
    let clean = path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    let file = clean.rsplit('/').next().unwrap_or("");
    let Some((_, ext)) = file.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext,
        "lgx"
            | "wasm"
            | "zip"
            | "tar"
            | "gz"
            | "tgz"
            | "xz"
            | "bz2"
            | "bin"
            | "dmg"
            | "deb"
            | "rpm"
            | "appimage"
            | "exe"
            | "msi"
            | "apk"
            | "pdf"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID_ROOT: &str = "z4W2jRootList00000000000000000000000000000000000";
    const CID_HOME: &str = "z4W2jHomeHtml00000000000000000000000000000000000";
    const CID_BROWSER_DIR: &str = "z4W2jBrowserDir000000000000000000000000000000000";
    const CID_BROWSER_HTML: &str = "z4W2jBrowserHtml00000000000000000000000000000000";
    const CID_SHOT_PNG: &str = "z4W2jShotPng000000000000000000000000000000000000";
    const CID_FILES_DIR: &str = "z4W2jFilesDir00000000000000000000000000000000000";
    const CID_LGX: &str = "z4W2jBrowserLgx000000000000000000000000000000000";
    const HASH_LGX: &str = "3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b";

    #[test]
    fn parse_url_supports_bare_name_path_and_rejects_bad_inputs() {
        let u1 = parse_url("nameswallet/browser").unwrap();
        assert_eq!(u1.kind, UrlKind::Lns);
        assert_eq!(u1.host, "nameswallet");
        assert_eq!(u1.path, "/browser");
        assert_eq!(u1.canonical, "lns://nameswallet/browser");

        let u2 = parse_url("lns://NamesWallet.lez/browser/files/../files/x.lgx?v=1#dl").unwrap();
        assert_eq!(u2.host, "nameswallet");
        assert_eq!(u2.path, "/browser/files/x.lgx");
        assert_eq!(u2.fragment.as_deref(), Some("#dl"));

        let u3 = parse_url("@alice/../../etc/passwd").unwrap();
        assert_eq!(u3.host, "alice");
        assert_eq!(u3.path, "/etc/passwd");

        let u4 = parse_url(&format!("cid://{CID_LGX}")).unwrap();
        assert_eq!(u4.kind, UrlKind::Cid);
        assert_eq!(u4.host, CID_LGX);
        assert_eq!(u4.path, "/");

        // Reject subnames/dots, control chars, NUL
        assert!(parse_url("sub.nameswallet/browser").is_err());
        assert!(parse_url("nameswallet/bad\0path").is_err());
        assert!(parse_url("nameswallet/bad\npath").is_err());
    }

    #[test]
    fn parse_and_format_per_folder_links_list() {
        let raw = format!(
            "# lns-links/1\n# title Names Wallet\n# index index.html\n\n# comment\nbrowser/ {CID_BROWSER_DIR}\nindex.html {CID_HOME}\n"
        );
        let parsed = parse_links_list(&raw).unwrap();
        assert_eq!(parsed.title.as_deref(), Some("Names Wallet"));
        assert_eq!(parsed.index, "index.html");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "browser");
        assert_eq!(parsed.entries[0].kind, EntryKind::Dir);
        assert_eq!(parsed.entries[1].name, "index.html");
        assert_eq!(parsed.entries[1].kind, EntryKind::File);

        let formatted = format_links_list(&parsed).unwrap();
        assert_eq!(
            formatted,
            format!(
                "# lns-links/1\n# title Names Wallet\n# index index.html\nbrowser/ {CID_BROWSER_DIR}\nindex.html {CID_HOME}\n"
            )
        );
        assert_eq!(parse_links_list(&formatted).unwrap(), parsed);
    }

    #[test]
    fn parse_links_list_rejects_bad_lines_duplicates_and_traversal() {
        assert!(parse_links_list("index.html z4W2jHomeHtml00000000000000000000000000000000000\n").is_err());
        assert!(parse_links_list("# lns-links/2\n").is_err());
        assert!(parse_links_list(&format!("# lns-links/1\n../escape {CID_HOME}\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\n.. {CID_HOME}\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\n. {CID_HOME}\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\nsub/file.html {CID_HOME}\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\n/index.html {CID_HOME}\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\nindex.html bad!cid\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\nindex.html {CID_HOME} nothex\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\nindex.html {CID_HOME} {HASH_LGX} extra\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\nonlyone\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\n# index ../bad\n")).is_err());
        // Duplicate file/file and file/dir collision
        assert!(parse_links_list(&format!("# lns-links/1\na.html {CID_HOME}\na.html {CID_SHOT_PNG}\n")).is_err());
        assert!(parse_links_list(&format!("# lns-links/1\nbrowser {CID_HOME}\nbrowser/ {CID_BROWSER_DIR}\n")).is_err());
        // Control chars / NUL
        assert!(parse_links_list(&format!("# lns-links/1\na\0b {CID_HOME}\n")).is_err());
    }

    #[test]
    fn resolve_links_tree_walks_nested_folders_handles_index_trailing_slash_cache_and_404() {
        let root = parse_links_list(&format!(
            "# lns-links/1\n# index index.html\nbrowser/ {CID_BROWSER_DIR}\nindex.html {CID_HOME}\n"
        ))
        .unwrap();
        let browser = parse_links_list(&format!(
            "# lns-links/1\n# index home.html\nfiles/ {CID_FILES_DIR}\nhome.html {CID_BROWSER_HTML}\nshot.png {CID_SHOT_PNG}\n"
        ))
        .unwrap();
        let files = parse_links_list(&format!(
            "# lns-links/1\nlns-browser-0.2.8.lgx {CID_LGX} {HASH_LGX}\n"
        ))
        .unwrap();

        let mut store = HashMap::new();
        store.insert(
            CID_ROOT.to_owned(),
            CachedLinksList {
                list: root.clone(),
                sha256: None,
            },
        );
        store.insert(
            CID_BROWSER_DIR.to_owned(),
            CachedLinksList {
                list: browser,
                sha256: None,
            },
        );
        store.insert(
            CID_FILES_DIR.to_owned(),
            CachedLinksList {
                list: files,
                sha256: None,
            },
        );

        let mut cache: HashMap<String, CachedLinksList> = HashMap::new();
        let mut fetches = 0usize;

        // 1. Root `/`
        let r0 = resolve_links_tree(&root, "/", &mut cache, |cid, _| {
            fetches += 1;
            store.get(cid).cloned().ok_or_else(|| "missing".to_owned())
        })
        .unwrap();
        match r0 {
            ResolveOutcome::Found(f) => {
                assert_eq!(f.entry.cid, CID_HOME);
                assert_eq!(f.resolved_path, "/index.html");
                assert_eq!(f.canonical_url_path, "/");
                assert!(f.folders_verified);
            }
            _ => panic!("expected root found"),
        }
        assert_eq!(fetches, 0);

        // 2. Folder without trailing slash canonicalizes with trailing slash and uses custom `# index home.html`
        let r1 = resolve_links_tree(&root, "/browser", &mut cache, |cid, _| {
            fetches += 1;
            store.get(cid).cloned().ok_or_else(|| "missing".to_owned())
        })
        .unwrap();
        match r1 {
            ResolveOutcome::Found(f) => {
                assert_eq!(f.entry.cid, CID_BROWSER_HTML);
                assert_eq!(f.resolved_path, "/browser/home.html");
                assert_eq!(f.canonical_url_path, "/browser/");
                // Intermediate `browser/` had no pinned sha256
                assert!(!f.folders_verified);
            }
            _ => panic!("expected browser found"),
        }
        assert_eq!(fetches, 1);

        // 3. Deep file path reuses cached `browser/` list and fetches only `files/`
        let r2 = resolve_links_tree(&root, "/browser/files/lns-browser-0.2.8.lgx", &mut cache, |cid, _| {
            fetches += 1;
            store.get(cid).cloned().ok_or_else(|| "missing".to_owned())
        })
        .unwrap();
        match r2 {
            ResolveOutcome::Found(f) => {
                assert_eq!(f.entry.cid, CID_LGX);
                assert_eq!(f.entry.sha256.as_deref(), Some(HASH_LGX));
                assert_eq!(f.resolved_path, "/browser/files/lns-browser-0.2.8.lgx");
                assert_eq!(f.canonical_url_path, "/browser/files/lns-browser-0.2.8.lgx");
                assert!(!f.folders_verified);
            }
            _ => panic!("expected lgx found"),
        }
        assert_eq!(fetches, 2); // browser/ came from cache!

        // 4. Exact file with trailing slash returns NotFound
        let r3 = resolve_links_tree(&root, "/browser/shot.png/", &mut cache, |cid, _| {
            fetches += 1;
            store.get(cid).cloned().ok_or_else(|| "missing".to_owned())
        })
        .unwrap();
        assert!(matches!(r3, ResolveOutcome::NotFound { is_directory: false, .. }));

        // 5. Directory with no index file returns NotFound with is_directory = true
        let r4 = resolve_links_tree(&root, "/browser/files/", &mut cache, |cid, _| {
            fetches += 1;
            store.get(cid).cloned().ok_or_else(|| "missing".to_owned())
        })
        .unwrap();
        assert!(matches!(r4, ResolveOutcome::NotFound { is_directory: true, .. }));

        // 6. Missing path returns NotFound
        let r5 = resolve_links_tree(&root, "/nope/page.html", &mut cache, |cid, _| {
            fetches += 1;
            store.get(cid).cloned().ok_or_else(|| "missing".to_owned())
        })
        .unwrap();
        assert!(matches!(r5, ResolveOutcome::NotFound { is_directory: false, .. }));
    }

    #[test]
    fn cid_cache_checks_expected_sha256_and_tracks_folders_verified() {
        let good_sha = "a".repeat(64);
        let bad_sha = "b".repeat(64);
        let sub = parse_links_list(&format!("# lns-links/1\nindex.html {CID_BROWSER_HTML}\n")).unwrap();
        let unpinned_root =
            parse_links_list(&format!("# lns-links/1\nsub/ {CID_BROWSER_DIR}\n")).unwrap();
        let pinned_root_good = parse_links_list(&format!(
            "# lns-links/1\nsub/ {CID_BROWSER_DIR} {good_sha}\n"
        ))
        .unwrap();
        let pinned_root_bad = parse_links_list(&format!(
            "# lns-links/1\nsub/ {CID_BROWSER_DIR} {bad_sha}\n"
        ))
        .unwrap();

        let mut cache: HashMap<String, CachedLinksList> = HashMap::new();
        // First load without a pinned sha256 populates cache with actual sha256
        let r1 = resolve_links_tree(&unpinned_root, "/sub/", &mut cache, |_, _| {
            Ok(CachedLinksList {
                list: sub.clone(),
                sha256: Some(good_sha.clone()),
            })
        })
        .unwrap();
        assert!(matches!(r1, ResolveOutcome::Found(f) if !f.folders_verified));

        // Pinned load with matching sha256 hits cache and marks folders_verified = true
        let mut hits = 0usize;
        let r2 = resolve_links_tree(&pinned_root_good, "/sub/", &mut cache, |_, _| {
            hits += 1;
            Ok(CachedLinksList {
                list: sub.clone(),
                sha256: Some(good_sha.clone()),
            })
        })
        .unwrap();
        assert_eq!(hits, 0);
        assert!(matches!(r2, ResolveOutcome::Found(f) if f.folders_verified));

        // Pinned load with mismatched sha256 MUST fail even on cache hit
        let r3 = resolve_links_tree(&pinned_root_bad, "/sub/", &mut cache, |_, _| {
            panic!("should fail on cached hash mismatch")
        });
        assert!(r3.is_err());
        assert!(r3.unwrap_err().contains("SHA-256 mismatch"));
    }

    #[test]
    fn parity_fixes_binary_path_title_tab_roundtrip_and_list_limits() {
        // Finding 12: bare "pdf" without dot is NOT a binary download path
        assert!(!is_binary_download_path("pdf"));
        assert!(!is_binary_download_path("/dir.pdf/readme"));
        assert!(is_binary_download_path("doc.pdf"));
        assert!(is_binary_download_path("/browser/files/app.lgx"));

        // Finding 12: `# title` containing `\t` round-trips cleanly
        let tabbed = format!("# lns-links/1\n# title A\tB\nindex.html {CID_HOME}\n");
        let parsed = parse_links_list(&tabbed).unwrap();
        assert_eq!(parsed.title.as_deref(), Some("A B"));
        let formatted = format_links_list(&parsed).unwrap();
        assert!(formatted.contains("# title A B\n"));
        assert_eq!(parse_links_list(&formatted).unwrap(), parsed);

        // Finding 9: oversized list (> 2 MiB) and > 10,000 entries rejected
        let huge = format!("# lns-links/1\n{}", " ".repeat(MAX_LINKS_LIST_BYTES + 1));
        assert!(parse_links_list(&huge).is_err());

        let mut many = String::from("# lns-links/1\n");
        for i in 0..=MAX_LINKS_ENTRIES {
            many.push_str(&format!("f{i}.txt {CID_HOME}\n"));
        }
        assert!(parse_links_list(&many).is_err());
    }
}
