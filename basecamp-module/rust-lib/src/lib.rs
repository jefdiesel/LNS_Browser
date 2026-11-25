//! `lns_browser_core`: Basecamp core module for the native LNS + CID Web Browser.
//!
//! Fetches CIDs from the user's local Logos Storage node, verifies SHA-256 commitments against
//! the on-chain LNS record, sanitizes HTML/Markdown into safe zero-JS Qt RichText with `lns://`,
//! `cid://`, and click-to-confirm `https://` links plus safe colors and inline SVG graphics, and
//! publishes local files/folders to Logos Storage CIDs.

mod links;
mod sanitize;
mod server;
mod storage;

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::links::{
    is_binary_download_path, is_links_list_text, is_valid_sha256, parse_links_list,
    resolve_links_tree, CachedLinksList, EntryKind, LinksEntry, LinksList, ResolveOutcome,
};
use crate::sanitize::{
    base64_encode, markdown_to_safe_html, normalize_site_path, sanitize_html, DownloadLink,
    RenderBlock,
};
use crate::server::{BasecampDownloader, SiteServerManager, SiteSpec};
use crate::storage::{
    mime_for_path, sniff_content_type, try_parse_manifest, StorageClient, DEFAULT_STORAGE_API,
};

/// The trait `logos-module-builder` generates Qt/C++ bindings from.
pub trait LnsBrowserCoreModule: Send + 'static {
    /// Fetches `cid` from Logos Storage, verifies `expected_sha256` (if non-empty),
    /// resolves `path` if the CID is a v1 site manifest, and returns sanitized Qt RichText,
    /// safe page colors, and ordered render blocks ready to render natively inside Basecamp.
    fn fetch_site(
        &mut self,
        cid: String,
        expected_sha256: String,
        site_base: String,
        path: String,
    ) -> String;

    /// Sanitizes raw on-chain HTML (`SetPage`) into the same safe RichText + palette + blocks JSON.
    fn render_html(&mut self, html: String, site_base: String, path: String) -> String;

    /// Uploads a local file or directory to Logos Storage (creating a v1 manifest for dirs)
    /// and returns `{mode, root_cid, sha256, size, files}`.
    fn publish_path(&mut self, local_path: String, title: String) -> String;

    /// Uploads raw HTML text directly to Logos Storage and returns `{mode, root_cid, sha256, size}`.
    fn publish_html(&mut self, html: String, title: String) -> String;

    /// Opens a strictly validated `https://` URL in the system default web browser.
    fn open_external_url(&mut self, url: String) -> String;

    /// Calls Basecamp's `storage_module.connect(peerId, peerAddresses)` through `logos-rust-sdk`
    /// with a real `Vec<String>` JSON array (avoiding QML bridge array marshalling limitations).
    fn storage_connect_peer(&mut self, peer_id: String, addrs_json: String) -> String;

    /// Calls `storage_module.downloadChunks(cid, local, chunkSize, isPrivate, advertise)` via
    /// `logos-rust-sdk` with real Rust bool/integer arguments (QML passes strings).
    fn storage_download_chunks(
        &mut self,
        cid: String,
        local: String,
        chunk_size: String,
        is_private: String,
        advertise: String,
    ) -> String;

    /// Calls `storage_module.downloadToUrl(cid, filePath, local, chunkSize, isPrivate, advertise)`
    /// via `logos-rust-sdk` with real Rust bool/integer arguments (QML passes strings).
    fn storage_download_to_url(
        &mut self,
        cid: String,
        file_path: String,
        local: String,
        chunk_size: String,
        is_private: String,
        advertise: String,
    ) -> String;

    /// Verifies the SHA-256 of a file saved inside `$HOME/Downloads` and deletes it on mismatch.
    fn verify_saved_file(&mut self, file_path: String, expected_sha256: String) -> String;

    /// Calls `storage_module.uploadUrl(filePath, chunkSize, advertise)` via `logos-rust-sdk`
    /// with real Rust integer/bool arguments (QML passes strings).
    fn storage_upload_url(
        &mut self,
        file_path: String,
        chunk_size: String,
        advertise: String,
    ) -> String;

    /// Calls `storage_module.uploadInit(filename, chunkSize, advertise)` via `logos-rust-sdk`
    /// with real Rust integer/bool arguments (QML passes strings).
    fn storage_upload_init(
        &mut self,
        filename: String,
        chunk_size: String,
        advertise: String,
    ) -> String;

    /// Checks whether the configured local Logos Storage node is reachable.
    fn storage_status(&mut self) -> String;

    /// Returns `{storage_api, storage_peers, storage_peers_text}`.
    fn config_get(&mut self) -> String;

    /// Updates local settings (`storage_api`, `storage_peers` / `storage_peers_text`) and persists
    /// them to `~/.config/lns-browser/config.json`.
    fn config_set(&mut self, settings_json: String) -> String;

    /// Opens (or reuses) a per-site loopback HTTP/1.1 server bound to `127.0.0.1:0` with a random
    /// 128-bit token prefix and strict CSP/security headers. Returns `{origin, port, token, entry_url, ...}`.
    fn site_open(&mut self, spec_json: String) -> String;

    /// Shuts down the loopback server identified by `token`.
    fn site_close(&mut self, token: String) -> String;

    /// Shuts down all active loopback servers (called when the Basecamp app unloads).
    fn site_close_all(&mut self) -> String;

    /// Notifies the loopback server that `storage_module.downloadToUrl` completed for `cid`.
    fn site_blob_ready(&mut self, cid: String, tmp_path: String, ok: String, err: String)
        -> String;

    /// Returns verified file list, root CID/SHA-256, CSP, and current status for `token`.
    fn site_stats(&mut self, token: String) -> String;

    /// Drains queued `/_ext`, `/_lns`, `/_dl`, and error events plus updated `stats` for `token`.
    fn site_poll_events(&mut self, token: String) -> String;

    /// Downloads a verified file from the active site into `$HOME/Downloads` through the core.
    fn site_download_file(
        &mut self,
        token: String,
        cid: String,
        rel_path: String,
        filename: String,
    ) -> String;

    /// Returns persisted bookmarks from `~/.config/lns-browser/bookmarks.json`.
    fn bookmarks_get(&mut self) -> String;

    /// Replaces and persists bookmarks to `~/.config/lns-browser/bookmarks.json`.
    fn bookmarks_set(&mut self, bookmarks_json: String) -> String;

    /// Returns persisted browsing history from `~/.config/lns-browser/history.json`.
    fn history_get(&mut self) -> String;

    /// Prepends a visited page entry to `~/.config/lns-browser/history.json`.
    fn history_add(&mut self, entry_json: String) -> String;

    /// Clears persisted browsing history.
    fn history_clear(&mut self) -> String;

    /// Returns persisted browser window geometry and preferences from `~/.config/lns-browser/state.json`.
    fn browser_state_get(&mut self) -> String;

    /// Persists browser window geometry and preferences to `~/.config/lns-browser/state.json`.
    fn browser_state_set(&mut self, state_json: String) -> String;

    /// Called once the module is wired to the Basecamp host.
    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

#[cfg(not(test))]
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[cfg(test)]
pub struct RustModuleContext;

struct LnsBrowser {
    storage_api: String,
    storage_peers: Vec<String>,
    config_path: Option<PathBuf>,
    folder_cache: HashMap<String, CachedLinksList>,
    servers: SiteServerManager,
}

fn default_basecamp_downloader() -> BasecampDownloader {
    Arc::new(|cid: &str, tmp_path: &Path| {
        let target_str = tmp_path.to_string_lossy().into_owned();
        let args = json!([cid, target_str, false, 65536i64, false, true]);
        let reply = invoke_storage_module("downloadToUrl", &args)?;
        if reply["success"].as_bool() == Some(false) {
            let detail = reply["error"]
                .as_str()
                .or_else(|| reply["message"].as_str())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| reply.to_string());
            return Err(format!("storage_module.downloadToUrl refused: {detail}"));
        }
        Ok(())
    })
}

impl Default for LnsBrowser {
    fn default() -> Self {
        let config_path = default_config_path();
        let mut me = Self {
            storage_api: DEFAULT_STORAGE_API.to_owned(),
            storage_peers: Vec::new(),
            config_path,
            folder_cache: HashMap::new(),
            servers: SiteServerManager::new(default_basecamp_downloader()),
        };
        me.load_config_from_disk();
        me
    }
}

fn default_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config").join("lns-browser").join("config.json"))
}

fn default_downloads_dir() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "HOME environment variable is not set (no /tmp fallback allowed)".to_owned())?;
    let home_path = PathBuf::from(home);
    let dl_dir = home_path.join("Downloads");
    if !dl_dir.exists() && home_path.is_dir() {
        let _ = fs::create_dir(&dl_dir);
    }
    Ok(dl_dir)
}

fn validate_download_filename(name: &str) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(format!("Unsafe download filename `{name}`"));
    }
    if name.starts_with('.') {
        return Err(format!("Hidden dotfile download names are not allowed: `{name}`"));
    }
    if name.len() > 255 {
        return Err("Download filename exceeds 255 bytes".to_owned());
    }
    if name.chars().any(|c| {
        c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }) {
        return Err("Download filename contains forbidden or control characters".to_owned());
    }
    Ok(())
}

fn resolve_path_in_downloads(
    file_path: &str,
    downloads_dir: &Path,
    must_not_exist: bool,
) -> Result<PathBuf, String> {
    let trimmed = file_path.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control()) {
        return Err("file_path is empty or contains control characters".to_owned());
    }
    let path = Path::new(trimmed);
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("Download path must not contain parent traversal (`..`)".to_owned());
    }
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| "Invalid download filename".to_owned())?;
    validate_download_filename(fname)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "Downloads must be saved inside your Downloads folder".to_owned())?;
    let canon_downloads = fs::canonicalize(downloads_dir)
        .map_err(|e| format!("Downloads directory is unavailable: {e}"))?;
    let canon_parent = fs::canonicalize(parent)
        .map_err(|_| "Download target parent directory does not exist".to_owned())?;
    if canon_parent != canon_downloads {
        return Err("Downloads may only be saved directly inside your Downloads folder".to_owned());
    }
    let target = canon_downloads.join(fname);
    if must_not_exist && (target.exists() || fs::symlink_metadata(&target).is_ok()) {
        return Err(format!(
            "Refused to overwrite existing file `{fname}` in Downloads"
        ));
    }
    Ok(target)
}

fn verify_saved_file_in_dir(
    file_path: &str,
    expected_sha256: &str,
    downloads_dir: &Path,
) -> Result<Value, String> {
    let target = resolve_path_in_downloads(file_path, downloads_dir, false)?;
    let meta = fs::symlink_metadata(&target)
        .map_err(|e| format!("Saved file does not exist: {e}"))?;
    if !meta.file_type().is_file() {
        return Err("Saved download target is not a regular file".to_owned());
    }
    let mut file = fs::File::open(&target).map_err(|e| format!("Cannot read saved file: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Error hashing saved file: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut actual = String::with_capacity(64);
    for b in digest {
        actual.push_str(&format!("{b:02x}"));
    }

    let exp = expected_sha256.trim();
    if !exp.is_empty() {
        if !is_valid_sha256(exp) {
            let _ = fs::remove_file(&target);
            return Err(format!(
                "Invalid pinned SHA-256 `{exp}`; deleted unverified file"
            ));
        }
        let exp_lower = exp.to_ascii_lowercase();
        if actual != exp_lower {
            let _ = fs::remove_file(&target);
            return Err(format!(
                "SHA-256 mismatch for saved file: expected {exp_lower}, got {actual} (deleted tampered file)"
            ));
        }
        return Ok(json!({
            "verified": true,
            "sha256": actual,
            "path": target.to_string_lossy(),
        }));
    }
    Ok(json!({
        "verified": false,
        "sha256": actual,
        "path": target.to_string_lossy(),
    }))
}

pub(crate) fn escape_html_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn is_port_8080_url(url: &str) -> bool {
    let low = url.trim().to_ascii_lowercase();
    low.starts_with("http://127.0.0.1:8080")
        || low.starts_with("https://127.0.0.1:8080")
        || low.starts_with("http://localhost:8080")
        || low.starts_with("https://localhost:8080")
}

pub(crate) fn is_safe_external_https_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.len() < 12 || trimmed.len() > 1024 {
        return false;
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    if !trimmed.to_ascii_lowercase().starts_with("https://") {
        return false;
    }
    let rest = &trimmed[8..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty() && !authority.contains('@') && authority.contains('.')
}

fn clean_peer_lines(lines: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(format!(
                "Storage peers line {} must be `peerId /ip4/…/tcp/…`",
                idx + 1
            ));
        }
        let peer_id = parts[0];
        if !(16..=128).contains(&peer_id.len()) || !peer_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!(
                "Storage peers line {}: invalid peerId `{peer_id}`",
                idx + 1
            ));
        }
        for addr in &parts[1..] {
            if !addr.starts_with('/') || addr.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "Storage peers line {}: invalid multiaddr `{addr}` (expected /ip4/…/tcp/…)",
                    idx + 1
                ));
            }
        }
        out.push(parts.join(" "));
    }
    Ok(out)
}

fn ok(value: Value) -> String {
    json!({ "success": true, "value": value, "error": Value::Null }).to_string()
}

fn err(msg: impl Into<String>) -> String {
    json!({ "success": false, "value": Value::Null, "error": msg.into() }).to_string()
}

fn is_allowed_storage_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.starts_with("http://127.0.0.1")
        || lower.starts_with("http://localhost")
        || lower.starts_with("https://")
}

struct RenderedDoc {
    kind: String,
    title: Option<String>,
    html: Option<String>,
    truncated: bool,
    bg_color: Option<String>,
    fg_color: Option<String>,
    link_color: Option<String>,
    blocks: Vec<RenderBlock>,
    downloads: Vec<DownloadLink>,
}

fn blocks_to_json(blocks: &[RenderBlock]) -> Vec<Value> {
    blocks
        .iter()
        .map(|b| {
            let ops: Vec<Value> = b
                .ops
                .iter()
                .map(|op| {
                    json!({
                        "op": op.op,
                        "d": op.d,
                        "x": op.x,
                        "y": op.y,
                        "w": op.w,
                        "h": op.h,
                        "r": op.r,
                        "points": op.points,
                        "fill": op.fill,
                        "opacity": op.opacity,
                    })
                })
                .collect();
            json!({
                "kind": b.kind,
                "html": b.html,
                "data_uri": b.data_uri,
                "src_cid": b.src_cid,
                "src_path": b.src_path,
                "alt": b.alt,
                "width": b.width,
                "height": b.height,
                "vb_x": b.vb_x,
                "vb_y": b.vb_y,
                "vb_w": b.vb_w,
                "vb_h": b.vb_h,
                "ops": ops,
            })
        })
        .collect()
}

fn downloads_to_json(downloads: &[DownloadLink]) -> Vec<Value> {
    downloads
        .iter()
        .map(|d| {
            json!({
                "href": d.href,
                "cid": d.cid,
                "path": d.path,
                "filename": d.filename,
                "label": d.label,
            })
        })
        .collect()
}

fn folder_entries_to_json(dir_prefix: &str, entries: &[LinksEntry]) -> Vec<Value> {
    let base = dir_prefix.trim_end_matches('/');
    entries
        .iter()
        .map(|e| {
            let suffix = if e.kind == EntryKind::Dir { "/" } else { "" };
            let path = if base.is_empty() {
                format!("/{}{suffix}", e.name)
            } else {
                format!("{base}/{}{suffix}", e.name)
            };
            json!({
                "path": path,
                "name": e.name,
                "kind": if e.kind == EntryKind::Dir { "dir" } else { "file" },
                "cid": e.cid,
                "sha256": e.sha256,
            })
        })
        .collect()
}

fn sniff_raster_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 8
        && bytes[0] == 0x89
        && bytes[1] == 0x50
        && bytes[2] == 0x4e
        && bytes[3] == 0x47
    {
        return Some("image/png");
    }
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return Some("image/jpeg");
    }
    if bytes.len() >= 6 && &bytes[..4] == b"GIF8" {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    None
}

fn resolve_image_blocks_from_storage(
    blocks: &mut [RenderBlock],
    client: &StorageClient,
    links_root: Option<&LinksList>,
    folder_cache: &mut HashMap<String, CachedLinksList>,
) {
    const MAX_INLINE_IMAGE_BYTES: usize = 4 * 1024 * 1024;
    for block in blocks.iter_mut() {
        if block.kind != "image" || block.data_uri.is_some() {
            continue;
        }
        let target: Option<(String, Option<String>)> = if let Some(ref cid) = block.src_cid {
            Some((cid.clone(), None))
        } else if let (Some(ref img_path), Some(root)) = (&block.src_path, links_root) {
            let outcome = resolve_links_tree(root, img_path, folder_cache, |dir_cid, dir_sha| {
                let blob = client.download(dir_cid, dir_sha, None)?;
                let text = String::from_utf8(blob.bytes)
                    .map_err(|e| format!("invalid UTF-8 in subfolder {dir_cid}: {e}"))?;
                let list = parse_links_list(&text)?;
                Ok(CachedLinksList {
                    list,
                    sha256: Some(blob.sha256),
                })
            });
            match outcome {
                Ok(ResolveOutcome::Found(found)) => Some((found.entry.cid, found.entry.sha256)),
                _ => None,
            }
        } else {
            None
        };

        let Some((cid, expected_sha)) = target else {
            continue;
        };
        if let Ok(dl) = client.download(&cid, expected_sha.as_deref(), None) {
            if dl.bytes.len() <= MAX_INLINE_IMAGE_BYTES {
                if let Some(mime) = sniff_raster_image_mime(&dl.bytes) {
                    block.data_uri = Some(format!("data:{mime};base64,{}", base64_encode(&dl.bytes)));
                }
            }
        }
    }
}

impl LnsBrowser {
    fn client(&self) -> StorageClient {
        StorageClient::new(&self.storage_api)
    }

    fn load_config_from_disk(&mut self) {
        let Some(ref path) = self.config_path else {
            return;
        };
        let Ok(raw) = fs::read_to_string(path) else {
            return;
        };
        let Ok(val) = serde_json::from_str::<Value>(&raw) else {
            return;
        };
        if let Some(api) = val["storage_api"].as_str() {
            let trimmed = api.trim();
            if !trimmed.is_empty() && is_allowed_storage_url(trimmed) && !is_port_8080_url(trimmed) {
                self.storage_api = trimmed.trim_end_matches('/').to_owned();
            }
        }
        if let Some(arr) = val["storage_peers"].as_array() {
            let lines: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect();
            if let Ok(clean) = clean_peer_lines(&lines) {
                self.storage_peers = clean;
            }
        }
    }

    fn save_config_to_disk(&self) -> Result<(), String> {
        let Some(ref path) = self.config_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("cannot create config dir: {e}"))?;
        }
        let body = serde_json::to_string_pretty(&json!({
            "storage_api": self.storage_api,
            "storage_peers": self.storage_peers,
        }))
        .map_err(|e| format!("cannot serialize config: {e}"))?;
        fs::write(path, body + "\n").map_err(|e| format!("cannot write config: {e}"))
    }

    fn config_dir(&self) -> Option<PathBuf> {
        self.config_path.as_ref()?.parent().map(Path::to_path_buf)
    }

    fn read_persisted_json(&self, filename: &str) -> Option<Value> {
        let dir = self.config_dir()?;
        let raw = fs::read_to_string(dir.join(filename)).ok()?;
        serde_json::from_str::<Value>(&raw).ok()
    }

    fn write_persisted_json(&self, filename: &str, value: &Value) -> Result<(), String> {
        let Some(dir) = self.config_dir() else {
            return Ok(());
        };
        fs::create_dir_all(&dir).map_err(|e| format!("cannot create config dir: {e}"))?;
        let body = serde_json::to_string_pretty(value)
            .map_err(|e| format!("cannot serialize {filename}: {e}"))?;
        fs::write(dir.join(filename), body + "\n")
            .map_err(|e| format!("cannot write {filename}: {e}"))
    }

    fn render_bytes(
        bytes: &[u8],
        content_type: &str,
        site_base: &str,
        current_path: &str,
    ) -> RenderedDoc {
        let lower = content_type.to_ascii_lowercase();
        if lower.contains("html") {
            let text = String::from_utf8_lossy(bytes);
            let s = sanitize_html(&text, site_base, current_path);
            RenderedDoc {
                kind: "html".to_owned(),
                title: s.title,
                html: Some(s.html),
                truncated: s.truncated,
                bg_color: s.bg_color,
                fg_color: s.fg_color,
                link_color: s.link_color,
                blocks: s.blocks,
                downloads: s.downloads,
            }
        } else if lower.contains("markdown") {
            let text = String::from_utf8_lossy(bytes);
            let s = markdown_to_safe_html(&text, site_base, current_path);
            RenderedDoc {
                kind: "markdown".to_owned(),
                title: s.title,
                html: Some(s.html),
                truncated: s.truncated,
                bg_color: s.bg_color,
                fg_color: s.fg_color,
                link_color: s.link_color,
                blocks: s.blocks,
                downloads: s.downloads,
            }
        } else if lower.starts_with("text/") || lower.contains("json") {
            let text = String::from_utf8_lossy(bytes);
            let escaped = text
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            let html = format!("<pre><code>{escaped}</code></pre>");
            RenderedDoc {
                kind: "text".to_owned(),
                title: None,
                blocks: vec![RenderBlock {
                    kind: "html".to_owned(),
                    html: Some(html.clone()),
                    data_uri: None,
                    src_cid: None,
                    src_path: None,
                    alt: None,
                    width: None,
                    height: None,
                    vb_x: None,
                    vb_y: None,
                    vb_w: None,
                    vb_h: None,
                    ops: Vec::new(),
                }],
                html: Some(html),
                truncated: false,
                bg_color: None,
                fg_color: None,
                link_color: None,
                downloads: Vec::new(),
            }
        } else {
            let safe_ct = escape_html_text(content_type);
            let html = format!(
                "<p>Binary asset ({} bytes, <code>{}</code>) — verified by SHA-256.</p>",
                bytes.len(),
                safe_ct
            );
            RenderedDoc {
                kind: "binary".to_owned(),
                title: None,
                blocks: vec![RenderBlock {
                    kind: "html".to_owned(),
                    html: Some(html.clone()),
                    data_uri: None,
                    src_cid: None,
                    src_path: None,
                    alt: None,
                    width: None,
                    height: None,
                    vb_x: None,
                    vb_y: None,
                    vb_w: None,
                    vb_h: None,
                    ops: Vec::new(),
                }],
                html: Some(html),
                truncated: false,
                bg_color: None,
                fg_color: None,
                link_color: None,
                downloads: Vec::new(),
            }
        }
    }
}

impl LnsBrowserCoreModule for LnsBrowser {
    fn fetch_site(
        &mut self,
        cid: String,
        expected_sha256: String,
        site_base: String,
        path: String,
    ) -> String {
        let client = self.client();
        let exp = if expected_sha256.trim().is_empty() {
            None
        } else {
            Some(expected_sha256.trim())
        };
        let root = match client.download(cid.trim(), exp, None) {
            Ok(d) => d,
            Err(e) => return err(e),
        };

        // 1. Per-folder `lns-links/1` root list
        let root_text = String::from_utf8_lossy(&root.bytes);
        if is_links_list_text(&root_text) {
            let root_list = match parse_links_list(&root_text) {
                Ok(l) => l,
                Err(e) => return err(format!("invalid lns-links/1 list: {e}")),
            };
            let req_path = if path.trim().is_empty() { "/" } else { path.trim() };
            let outcome = match resolve_links_tree(
                &root_list,
                req_path,
                &mut self.folder_cache,
                |dir_cid, dir_sha| {
                    let blob = client.download(dir_cid, dir_sha, None)?;
                    let txt = String::from_utf8(blob.bytes)
                        .map_err(|e| format!("invalid UTF-8 in folder CID {dir_cid}: {e}"))?;
                    let list = parse_links_list(&txt)?;
                    Ok(CachedLinksList {
                        list,
                        sha256: Some(blob.sha256),
                    })
                },
            ) {
                Ok(o) => o,
                Err(e) => return err(e),
            };

            match outcome {
                ResolveOutcome::NotFound {
                    requested_path,
                    is_directory,
                    canonical_url_path,
                    folder_entries,
                } => {
                    let dir_prefix = canonical_url_path.as_deref().unwrap_or("/");
                    return ok(json!({
                        "mode": "links",
                        "kind": "not_found",
                        "not_found": true,
                        "single_page": false,
                        "is_directory": is_directory,
                        "path": requested_path,
                        "site_base": site_base,
                        "root_cid": cid.trim(),
                        "root_sha256": root.sha256,
                        "verified": root.verified,
                        "blocks": [],
                        "downloads": [],
                        "files": folder_entries_to_json(dir_prefix, &folder_entries),
                    }));
                }
                ResolveOutcome::Found(resolved) => {
                    let files_list =
                        folder_entries_to_json(&resolved.canonical_dir, &resolved.folder_entries);
                    if is_binary_download_path(&resolved.resolved_path) {
                        let filename = resolved.entry.name.clone();
                        return ok(json!({
                            "mode": "links",
                            "kind": "binary",
                            "can_save": true,
                            "filename": filename,
                            "title": filename,
                            "path": resolved.resolved_path,
                            "canonical_path": resolved.canonical_url_path,
                            "cid": resolved.entry.cid,
                            "root_cid": cid.trim(),
                            "sha256": resolved.entry.sha256.clone().unwrap_or_default(),
                            "root_sha256": root.sha256,
                            "verified": root.verified && resolved.folders_verified && resolved.entry.sha256.is_some(),
                            "content_type": mime_for_path(&resolved.resolved_path),
                            "html": "",
                            "blocks": [],
                            "downloads": [{
                                "href": format!("cid://{}", resolved.entry.cid),
                                "cid": resolved.entry.cid,
                                "path": resolved.resolved_path,
                                "filename": resolved.entry.name,
                                "label": resolved.entry.name,
                            }],
                            "truncated": false,
                            "files": files_list,
                        }));
                    }

                    let asset = match client.download(
                        &resolved.entry.cid,
                        resolved.entry.sha256.as_deref(),
                        None,
                    ) {
                        Ok(d) => d,
                        Err(e) => return err(e),
                    };
                    let ct = sniff_content_type(&asset.bytes, mime_for_path(&resolved.resolved_path));
                    let mut doc = Self::render_bytes(
                        &asset.bytes,
                        &ct,
                        &site_base,
                        &resolved.resolved_path,
                    );
                    resolve_image_blocks_from_storage(
                        &mut doc.blocks,
                        &client,
                        Some(&root_list),
                        &mut self.folder_cache,
                    );
                    return ok(json!({
                        "mode": "links",
                        "kind": doc.kind,
                        "title": doc.title.or(resolved.folder_title),
                        "path": resolved.resolved_path,
                        "canonical_path": resolved.canonical_url_path,
                        "cid": resolved.entry.cid,
                        "root_cid": cid.trim(),
                        "sha256": asset.sha256,
                        "root_sha256": root.sha256,
                        "verified": root.verified && resolved.folders_verified && asset.verified,
                        "content_type": ct,
                        "html": doc.html,
                        "bg_color": doc.bg_color,
                        "fg_color": doc.fg_color,
                        "link_color": doc.link_color,
                        "blocks": blocks_to_json(&doc.blocks),
                        "downloads": downloads_to_json(&doc.downloads),
                        "truncated": doc.truncated,
                        "files": files_list,
                    }));
                }
            }
        }

        // 2. Legacy v1 JSON `lns-site-manifest`
        let manifest = match try_parse_manifest(&root.bytes) {
            Ok(m) => m,
            Err(e) => return err(e),
        };

        if let Some(manifest) = manifest {
            let files_list: Vec<Value> = manifest
                .files
                .iter()
                .map(|(p, entry)| {
                    json!({
                        "path": p,
                        "cid": entry.cid,
                        "sha256": entry.sha256,
                        "size": entry.size,
                        "content_type": entry.content_type,
                    })
                })
                .collect();

            let req_path = normalize_site_path(if path.trim().is_empty() { "/" } else { &path });
            let Some((resolved_path, entry)) = manifest.resolve(&req_path) else {
                return ok(json!({
                    "mode": "manifest",
                    "kind": "not_found",
                    "not_found": true,
                    "single_page": false,
                    "path": req_path,
                    "site_base": site_base,
                    "root_cid": cid.trim(),
                    "root_sha256": root.sha256,
                    "verified": root.verified,
                    "blocks": [],
                    "downloads": [],
                    "files": files_list,
                }));
            };
            let asset = match client.download(&entry.cid, entry.sha256.as_deref(), entry.size) {
                Ok(d) => d,
                Err(e) => return err(e),
            };
            let mut doc =
                Self::render_bytes(&asset.bytes, &entry.content_type, &site_base, resolved_path);
            let mut empty_cache = HashMap::new();
            resolve_image_blocks_from_storage(&mut doc.blocks, &client, None, &mut empty_cache);
            return ok(json!({
                "mode": "manifest",
                "kind": doc.kind,
                "title": doc.title.or(manifest.title.clone()),
                "path": resolved_path,
                "cid": entry.cid,
                "root_cid": cid.trim(),
                "sha256": asset.sha256,
                "root_sha256": root.sha256,
                "verified": root.verified && asset.verified,
                "content_type": entry.content_type,
                "html": doc.html,
                "bg_color": doc.bg_color,
                "fg_color": doc.fg_color,
                "link_color": doc.link_color,
                "blocks": blocks_to_json(&doc.blocks),
                "downloads": downloads_to_json(&doc.downloads),
                "truncated": doc.truncated,
                "files": files_list,
            }));
        }

        // 3. Single-file CID
        let req_path = normalize_site_path(if path.trim().is_empty() { "/" } else { &path });
        if req_path != "/" && req_path != "/index.html" {
            return ok(json!({
                "mode": "single",
                "kind": "not_found",
                "not_found": true,
                "single_page": true,
                "path": req_path,
                "site_base": site_base,
                "root_cid": cid.trim(),
                "root_sha256": root.sha256,
                "verified": root.verified,
                "blocks": [],
                "downloads": [],
                "files": [],
            }));
        }
        let ct = sniff_content_type(&root.bytes, &root.content_type);
        let mut doc = Self::render_bytes(&root.bytes, &ct, &site_base, "/");
        let mut empty_cache = HashMap::new();
        resolve_image_blocks_from_storage(&mut doc.blocks, &client, None, &mut empty_cache);
        ok(json!({
            "mode": "single",
            "kind": doc.kind,
            "title": doc.title,
            "path": "/",
            "cid": cid.trim(),
            "root_cid": cid.trim(),
            "sha256": root.sha256,
            "root_sha256": root.sha256,
            "verified": root.verified,
            "content_type": ct,
            "html": doc.html,
            "bg_color": doc.bg_color,
            "fg_color": doc.fg_color,
            "link_color": doc.link_color,
            "blocks": blocks_to_json(&doc.blocks),
            "downloads": downloads_to_json(&doc.downloads),
            "truncated": doc.truncated,
            "files": [],
        }))
    }

    fn render_html(&mut self, html: String, site_base: String, path: String) -> String {
        let req_path = normalize_site_path(if path.trim().is_empty() { "/" } else { &path });
        let ct = sniff_content_type(html.as_bytes(), "text/html; charset=utf-8");
        let doc = Self::render_bytes(html.as_bytes(), &ct, &site_base, &req_path);
        ok(json!({
            "mode": "onchain-page",
            "kind": doc.kind,
            "title": doc.title,
            "path": req_path,
            "cid": "",
            "root_cid": "",
            "sha256": "",
            "root_sha256": "",
            "verified": true,
            "content_type": ct,
            "html": doc.html,
            "bg_color": doc.bg_color,
            "fg_color": doc.fg_color,
            "link_color": doc.link_color,
            "blocks": blocks_to_json(&doc.blocks),
            "downloads": downloads_to_json(&doc.downloads),
            "truncated": doc.truncated,
            "files": [],
        }))
    }

    fn publish_path(&mut self, local_path: String, title: String) -> String {
        let p = local_path.trim();
        if p.is_empty() {
            return err("provide a file or folder path to publish");
        }
        let t = if title.trim().is_empty() { None } else { Some(title.as_str()) };
        match self.client().publish_path(Path::new(p), t) {
            Ok(v) => ok(v),
            Err(e) => err(e),
        }
    }

    fn publish_html(&mut self, html: String, title: String) -> String {
        if html.trim().is_empty() {
            return err("HTML content is empty");
        }
        let client = self.client();
        match client.upload("index.html", "text/html; charset=utf-8", html.as_bytes()) {
            Ok((cid, hash)) => ok(json!({
                "mode": "single",
                "title": title.trim(),
                "root_cid": cid,
                "sha256": hash,
                "size": html.len(),
                "files": [{ "path": "/index.html", "cid": cid, "sha256": hash, "size": html.len() }],
            })),
            Err(e) => err(e),
        }
    }

    fn open_external_url(&mut self, url: String) -> String {
        let trimmed = url.trim().to_owned();
        if !is_safe_external_https_url(&trimmed) {
            return err("Only well-formed https:// URLs without credentials can be opened.");
        }
        #[cfg(target_os = "macos")]
        let res = Command::new("/usr/bin/open").arg(&trimmed).spawn();
        #[cfg(target_os = "linux")]
        let res = Command::new("xdg-open").arg(&trimmed).spawn();
        #[cfg(target_os = "windows")]
        let res = Command::new("cmd").args(["/C", "start", "", &trimmed]).spawn();
        match res {
            Ok(_) => ok(json!({ "opened": true, "url": trimmed })),
            Err(e) => err(format!("Could not launch system browser: {e}")),
        }
    }

    fn storage_connect_peer(&mut self, peer_id: String, addrs_json: String) -> String {
        let clean_id = peer_id.trim().to_owned();
        if !(16..=128).contains(&clean_id.len())
            || !clean_id.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return err(format!("invalid peerId `{clean_id}`"));
        }
        let addrs: Vec<String> = match serde_json::from_str::<Vec<String>>(&addrs_json) {
            Ok(list) => list
                .into_iter()
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(e) => return err(format!("invalid addrs_json (expected JSON string array): {e}")),
        };
        if addrs.is_empty() {
            return err("peerAddresses must contain at least one multiaddr (e.g. /ip4/…/tcp/…)");
        }
        for addr in &addrs {
            if !addr.starts_with('/') || addr.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return err(format!("invalid multiaddr `{addr}`"));
            }
        }
        match invoke_storage_module("connect", &json!([clean_id, addrs])) {
            Ok(reply) => {
                eprintln!(
                    "lns_browser_core: storage_module.connect({clean_id}, {addrs:?}) -> {reply}"
                );
                if reply["success"].as_bool() == Some(false) {
                    let detail = reply["error"]
                        .as_str()
                        .or_else(|| reply["message"].as_str())
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| reply.to_string());
                    return err(format!("storage_module.connect refused: {detail}"));
                }
                ok(json!({
                    "sent": true,
                    "peer_id": clean_id,
                    "addrs": addrs,
                    "reply": reply,
                }))
            }
            Err(e) => {
                eprintln!(
                    "lns_browser_core: storage_module.connect({clean_id}, {addrs:?}) FAILED: {e}"
                );
                err(e)
            }
        }
    }

    fn storage_download_chunks(
        &mut self,
        cid: String,
        local: String,
        chunk_size: String,
        is_private: String,
        advertise: String,
    ) -> String {
        let clean_cid = cid.trim().to_owned();
        if !crate::storage::is_valid_cid(&clean_cid) {
            return err(format!("invalid CID `{clean_cid}`"));
        }
        let local_b = parse_bool_arg(&local, false);
        let chunk_i = parse_chunk_size_arg(&chunk_size, 65536);
        let priv_b = parse_bool_arg(&is_private, false);
        let adv_b = parse_bool_arg(&advertise, true);
        let args = json!([clean_cid, local_b, chunk_i, priv_b, adv_b]);
        relay_storage_result("downloadChunks", &args)
    }

    fn storage_download_to_url(
        &mut self,
        cid: String,
        file_path: String,
        local: String,
        chunk_size: String,
        is_private: String,
        advertise: String,
    ) -> String {
        let clean_cid = cid.trim().to_owned();
        if !crate::storage::is_valid_cid(&clean_cid) {
            return err(format!("invalid CID `{clean_cid}`"));
        }
        let downloads_dir = match default_downloads_dir() {
            Ok(d) => d,
            Err(e) => return err(e),
        };
        let target = match resolve_path_in_downloads(&file_path, &downloads_dir, true) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let target_str = target.to_string_lossy().into_owned();
        let local_b = parse_bool_arg(&local, false);
        let chunk_i = parse_chunk_size_arg(&chunk_size, 65536);
        let priv_b = parse_bool_arg(&is_private, false);
        let adv_b = parse_bool_arg(&advertise, true);
        let args = json!([clean_cid, target_str, local_b, chunk_i, priv_b, adv_b]);
        relay_storage_result("downloadToUrl", &args)
    }

    fn verify_saved_file(&mut self, file_path: String, expected_sha256: String) -> String {
        let downloads_dir = match default_downloads_dir() {
            Ok(d) => d,
            Err(e) => return err(e),
        };
        match verify_saved_file_in_dir(&file_path, &expected_sha256, &downloads_dir) {
            Ok(v) => ok(v),
            Err(e) => err(e),
        }
    }

    fn storage_upload_url(
        &mut self,
        file_path: String,
        chunk_size: String,
        advertise: String,
    ) -> String {
        let clean_path = file_path.trim().to_owned();
        if clean_path.is_empty() {
            return err("file_path must not be empty");
        }
        let chunk_i = parse_chunk_size_arg(&chunk_size, 65536);
        let adv_b = parse_bool_arg(&advertise, true);
        let args = json!([clean_path, chunk_i, adv_b]);
        relay_storage_result("uploadUrl", &args)
    }

    fn storage_upload_init(
        &mut self,
        filename: String,
        chunk_size: String,
        advertise: String,
    ) -> String {
        let clean_name = if filename.trim().is_empty() {
            "index.html".to_owned()
        } else {
            filename.trim().to_owned()
        };
        let chunk_i = parse_chunk_size_arg(&chunk_size, 65536);
        let adv_b = parse_bool_arg(&advertise, true);
        let args = json!([clean_name, chunk_i, adv_b]);
        relay_storage_result("uploadInit", &args)
    }

    fn storage_status(&mut self) -> String {
        if self.storage_api.trim().is_empty() {
            return ok(json!({
                "online": false,
                "configured": false,
                "storage_api": "",
                "storage_peers": self.storage_peers,
                "storage_peers_text": self.storage_peers.join("\n"),
                "reason": "No external Logos Storage API URL configured (use Basecamp's built-in Storage module or set one in Settings).",
            }));
        }
        match self.client().debug_info() {
            Ok(info) => ok(json!({
                "online": true,
                "configured": true,
                "storage_api": self.storage_api,
                "storage_peers": self.storage_peers,
                "storage_peers_text": self.storage_peers.join("\n"),
                "peer_id": info["id"],
                "mock": info["mock"].as_bool().unwrap_or(false) || info["id"].as_str() == Some("16Uiu2HAmLocalLogosStorageSeed"),
            })),
            Err(e) => ok(json!({
                "online": false,
                "configured": true,
                "storage_api": self.storage_api,
                "storage_peers": self.storage_peers,
                "storage_peers_text": self.storage_peers.join("\n"),
                "reason": e,
            })),
        }
    }

    fn config_get(&mut self) -> String {
        let downloads_dir = std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Downloads").to_string_lossy().into_owned())
            .unwrap_or_default();
        ok(json!({
            "storage_api": self.storage_api,
            "storage_peers": self.storage_peers,
            "storage_peers_text": self.storage_peers.join("\n"),
            "downloads_dir": downloads_dir,
        }))
    }

    fn config_set(&mut self, settings_json: String) -> String {
        let Ok(parsed) = serde_json::from_str::<Value>(&settings_json) else {
            return err("settings_json must be valid JSON");
        };
        if let Some(api) = parsed["storage_api"].as_str() {
            let trimmed = api.trim();
            if trimmed.is_empty() {
                self.storage_api.clear();
            } else {
                if is_port_8080_url(trimmed) {
                    return err("Port 8080 is used by the Logos Blockchain node, not Logos Storage.");
                }
                if !is_allowed_storage_url(trimmed) {
                    return err("storage_api must start with http://127.0.0.1, http://localhost, or https://");
                }
                self.storage_api = trimmed.trim_end_matches('/').to_owned();
            }
        }
        if let Some(peers_text) = parsed["storage_peers_text"].as_str() {
            let lines: Vec<String> = peers_text.lines().map(ToOwned::to_owned).collect();
            match clean_peer_lines(&lines) {
                Ok(clean) => self.storage_peers = clean,
                Err(e) => return err(e),
            }
        } else if let Some(arr) = parsed["storage_peers"].as_array() {
            let lines: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect();
            match clean_peer_lines(&lines) {
                Ok(clean) => self.storage_peers = clean,
                Err(e) => return err(e),
            }
        }
        if let Err(e) = self.save_config_to_disk() {
            return err(e);
        }
        self.config_get()
    }

    fn site_open(&mut self, spec_json: String) -> String {
        let Ok(v) = serde_json::from_str::<Value>(&spec_json) else {
            return err("spec_json must be valid JSON");
        };
        let kind = v["kind"].as_str().unwrap_or("lns").trim().to_owned();
        let host = v["host"].as_str().unwrap_or("").trim().to_owned();
        let site_base = v["site_base"]
            .as_str()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if kind == "cid" {
                    format!("cid://{host}")
                } else {
                    format!("lns://{host}")
                }
            });
        let onchain_html = v["html"].as_str().map(ToOwned::to_owned);
        let onchain_links = v["links_text"].as_str().map(ToOwned::to_owned);
        let root_cid = v["root_cid"].as_str().unwrap_or("").trim().to_owned();
        let root_sha256 = v["root_sha256"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let site_type = v["site_type"].as_str().unwrap_or("").trim().to_owned();
        let mode = v["mode"]
            .as_str()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if onchain_html.is_some() {
                    "onchain-page".to_owned()
                } else if onchain_links.is_some() {
                    "onchain-links".to_owned()
                } else {
                    "cid".to_owned()
                }
            });

        let storage_api = v["storage_api"]
            .as_str()
            .map(|s| s.trim().trim_end_matches('/').to_owned())
            .filter(|s| !s.is_empty() && is_allowed_storage_url(s) && !is_port_8080_url(s))
            .unwrap_or_else(|| self.storage_api.clone());

        let backend = v["backend"]
            .as_str()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| matches!(s.as_str(), "basecamp" | "http" | "memory"))
            .unwrap_or_else(|| {
                if mode == "onchain-page" {
                    "memory".to_owned()
                } else if !storage_api.is_empty() {
                    "http".to_owned()
                } else {
                    "basecamp".to_owned()
                }
            });

        let initial_path = v["path"].as_str().unwrap_or("/").trim().to_owned();
        let title = v["title"]
            .as_str()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());

        let spec = SiteSpec {
            kind,
            host,
            site_base,
            mode,
            root_cid,
            root_sha256,
            site_type,
            backend,
            storage_api,
            onchain_html,
            onchain_links,
            title,
            initial_path,
        };
        match self.servers.site_open(spec) {
            Ok(info) => ok(info),
            Err(e) => err(e),
        }
    }

    fn site_close(&mut self, token: String) -> String {
        let closed = self.servers.site_close(&token);
        ok(json!({ "closed": closed, "token": token.trim() }))
    }

    fn site_close_all(&mut self) -> String {
        let count = self.servers.site_close_all();
        ok(json!({ "closed_count": count }))
    }

    fn site_blob_ready(
        &mut self,
        cid: String,
        tmp_path: String,
        ok_flag: String,
        err_msg: String,
    ) -> String {
        let is_ok = parse_bool_arg(&ok_flag, false);
        let matched = self
            .servers
            .site_blob_ready(cid.trim(), tmp_path.trim(), is_ok, err_msg.trim());
        ok(json!({ "matched": matched, "cid": cid.trim() }))
    }

    fn site_stats(&mut self, token: String) -> String {
        match self.servers.site_stats(&token) {
            Ok(v) => ok(v),
            Err(e) => err(e),
        }
    }

    fn site_poll_events(&mut self, token: String) -> String {
        match self.servers.site_poll_events(&token) {
            Ok(v) => ok(v),
            Err(e) => err(e),
        }
    }

    fn site_download_file(
        &mut self,
        token: String,
        cid: String,
        rel_path: String,
        filename: String,
    ) -> String {
        let (resolved_cid, expected_sha, final_name, backend, storage_api) =
            if !token.trim().is_empty() {
                match self
                    .servers
                    .resolve_site_download(&token, &cid, &rel_path, &filename)
                {
                    Ok(t) => t,
                    Err(e) => return err(e),
                }
            } else {
                let clean_cid = cid.trim().to_owned();
                if !crate::storage::is_valid_cid(&clean_cid) {
                    return err(format!("invalid CID `{clean_cid}`"));
                }
                let fname = if filename.trim().is_empty() {
                    format!("{}.bin", &clean_cid[..clean_cid.len().min(12)])
                } else {
                    filename.trim().to_owned()
                };
                let b = if !self.storage_api.is_empty() {
                    "http".to_owned()
                } else {
                    "basecamp".to_owned()
                };
                (clean_cid, String::new(), fname, b, self.storage_api.clone())
            };

        let downloads_dir = match default_downloads_dir() {
            Ok(d) => d,
            Err(e) => return err(e),
        };
        if let Err(e) = validate_download_filename(&final_name) {
            return err(e);
        }
        let candidate = downloads_dir.join(&final_name);
        let target = match resolve_path_in_downloads(&candidate.to_string_lossy(), &downloads_dir, true) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let target_str = target.to_string_lossy().into_owned();

        if backend == "http" && !storage_api.is_empty() {
            let client = StorageClient::new(&storage_api);
            let exp_opt = if expected_sha.is_empty() {
                None
            } else {
                Some(expected_sha.as_str())
            };
            let dl = match client.download(&resolved_cid, exp_opt, None) {
                Ok(d) => d,
                Err(e) => return err(e),
            };
            if let Err(e) = fs::write(&target, &dl.bytes) {
                return err(format!("Failed to write download to {target_str}: {e}"));
            }
            return ok(json!({
                "mode": "http",
                "done": true,
                "cid": resolved_cid,
                "sha256": dl.sha256,
                "verified": dl.verified,
                "path": target_str,
                "filename": final_name,
                "size": dl.bytes.len(),
            }));
        }

        // Basecamp storage_module mode: invoke downloadToUrl directly from Rust core
        let args = json!([resolved_cid, target_str, false, 65536i64, false, true]);
        match invoke_storage_module("downloadToUrl", &args) {
            Ok(reply) => {
                if reply["success"].as_bool() == Some(false) {
                    let detail = reply["error"]
                        .as_str()
                        .or_else(|| reply["message"].as_str())
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| reply.to_string());
                    return err(format!("storage_module.downloadToUrl refused: {detail}"));
                }
                ok(json!({
                    "mode": "basecamp",
                    "done": false,
                    "cid": resolved_cid,
                    "sha256": expected_sha,
                    "path": target_str,
                    "filename": final_name,
                }))
            }
            Err(e) => err(e),
        }
    }

    fn bookmarks_get(&mut self) -> String {
        let items = self
            .read_persisted_json("bookmarks.json")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        ok(Value::Array(items))
    }

    fn bookmarks_set(&mut self, bookmarks_json: String) -> String {
        let Ok(parsed) = serde_json::from_str::<Value>(&bookmarks_json) else {
            return err("bookmarks_json must be valid JSON");
        };
        let Some(arr) = parsed.as_array() else {
            return err("bookmarks_json must be a JSON array");
        };
        let mut clean = Vec::with_capacity(arr.len().min(500));
        for item in arr.iter().take(500) {
            let Some(url) = item["url"].as_str().map(str::trim).filter(|s| !s.is_empty()) else {
                continue;
            };
            if url.len() > 1024 || url.chars().any(|c| c.is_control()) {
                continue;
            }
            let title: String = item["title"]
                .as_str()
                .unwrap_or("")
                .trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            let name: String = item["name"]
                .as_str()
                .unwrap_or("")
                .trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(128)
                .collect();
            let added_at = item["added_at"].as_u64().or_else(|| item["addedAt"].as_u64()).unwrap_or(0);
            clean.push(json!({
                "url": url,
                "title": title,
                "name": name,
                "added_at": added_at,
            }));
        }
        let val = Value::Array(clean);
        if let Err(e) = self.write_persisted_json("bookmarks.json", &val) {
            return err(e);
        }
        ok(val)
    }

    fn history_get(&mut self) -> String {
        let items = self
            .read_persisted_json("history.json")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        ok(Value::Array(items))
    }

    fn history_add(&mut self, entry_json: String) -> String {
        let Ok(item) = serde_json::from_str::<Value>(&entry_json) else {
            return err("entry_json must be valid JSON");
        };
        let Some(url) = item["url"].as_str().map(str::trim).filter(|s| !s.is_empty()) else {
            return err("history entry requires non-empty `url`");
        };
        if url.len() > 1024 || url.chars().any(|c| c.is_control()) {
            return err("invalid history url");
        }
        let title: String = item["title"]
            .as_str()
            .unwrap_or("")
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        let name: String = item["name"]
            .as_str()
            .unwrap_or("")
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(128)
            .collect();
        let visited_at = item["visited_at"]
            .as_u64()
            .or_else(|| item["visitedAt"].as_u64())
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            });

        let mut existing = self
            .read_persisted_json("history.json")
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        existing.retain(|e| e["url"].as_str() != Some(url));
        existing.insert(
            0,
            json!({
                "url": url,
                "title": title,
                "name": name,
                "visited_at": visited_at,
            }),
        );
        existing.truncate(500);
        let val = Value::Array(existing);
        if let Err(e) = self.write_persisted_json("history.json", &val) {
            return err(e);
        }
        ok(val)
    }

    fn history_clear(&mut self) -> String {
        let empty = Value::Array(Vec::new());
        if let Err(e) = self.write_persisted_json("history.json", &empty) {
            return err(e);
        }
        ok(empty)
    }

    fn browser_state_get(&mut self) -> String {
        let state = self.read_persisted_json("state.json").unwrap_or_else(|| {
            json!({
                "window": { "x": 120, "y": 80, "width": 1120, "height": 760 },
                "reader_mode": false,
            })
        });
        ok(state)
    }

    fn browser_state_set(&mut self, state_json: String) -> String {
        let Ok(parsed) = serde_json::from_str::<Value>(&state_json) else {
            return err("state_json must be valid JSON");
        };
        let mut current = self.read_persisted_json("state.json").unwrap_or_else(|| {
            json!({
                "window": { "x": 120, "y": 80, "width": 1120, "height": 760 },
                "reader_mode": false,
            })
        });
        if let Some(win) = parsed.get("window").and_then(Value::as_object) {
            let x = win
                .get("x")
                .and_then(Value::as_i64)
                .unwrap_or(120)
                .clamp(-4000, 8000);
            let y = win
                .get("y")
                .and_then(Value::as_i64)
                .unwrap_or(80)
                .clamp(0, 4000);
            let w = win
                .get("width")
                .and_then(Value::as_i64)
                .unwrap_or(1120)
                .clamp(720, 4096);
            let h = win
                .get("height")
                .and_then(Value::as_i64)
                .unwrap_or(760)
                .clamp(480, 2560);
            current["window"] = json!({ "x": x, "y": y, "width": w, "height": h });
        }
        if let Some(rm) = parsed.get("reader_mode").and_then(Value::as_bool) {
            current["reader_mode"] = Value::Bool(rm);
        }
        if let Err(e) = self.write_persisted_json("state.json", &current) {
            return err(e);
        }
        ok(current)
    }
}

fn parse_bool_arg(raw: &str, default: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => true,
        "false" | "0" | "no" => false,
        _ => default,
    }
}

fn parse_chunk_size_arg(raw: &str, default: i64) -> i64 {
    raw.trim()
        .parse::<i64>()
        .ok()
        .filter(|&n| n >= 1024 && n <= 16 * 1024 * 1024)
        .unwrap_or(default)
}

fn relay_storage_result(method: &str, args: &Value) -> String {
    match invoke_storage_module(method, args) {
        Ok(reply) => {
            eprintln!("lns_browser_core: storage_module.{method}({args}) -> {reply}");
            if reply["success"].as_bool() == Some(false) {
                let detail = reply["error"]
                    .as_str()
                    .or_else(|| reply["message"].as_str())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| reply.to_string());
                return err(format!("storage_module.{method} refused: {detail}"));
            }
            // Unwrap StdLogosResult { success: true, value } cleanly for QML callers
            if reply["success"].as_bool() == Some(true) && reply.get("value").is_some() {
                ok(reply["value"].clone())
            } else {
                ok(reply)
            }
        }
        Err(e) => {
            eprintln!("lns_browser_core: storage_module.{method}({args}) FAILED: {e}");
            err(e)
        }
    }
}

#[cfg(not(test))]
fn invoke_storage_module(method: &str, args: &Value) -> Result<Value, String> {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    thread_local! {
        static STORAGE_CLIENT: RefCell<Option<Rc<logos_rust_sdk::PluginProxy>>> = const { RefCell::new(None) };
    }

    let proxy = STORAGE_CLIENT.with(|cell| {
        let mut slot = cell.borrow_mut();
        if let Some(ref existing) = *slot {
            Rc::clone(existing)
        } else {
            let created = Rc::new(logos_rust_sdk::LogosModuleSDK::new().plugin("storage_module"));
            *slot = Some(Rc::clone(&created));
            created
        }
    });

    proxy
        .call_json_with_timeout(method, args, Duration::from_secs(15))
        .map_err(|e| format!("storage_module.{method} SDK error: {e}"))
}

#[cfg(test)]
fn invoke_storage_module(method: &str, args: &Value) -> Result<Value, String> {
    Ok(json!({ "success": true, "value": format!("mock-{method}"), "args": args }))
}

#[cfg(not(test))]
#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<LnsBrowser>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sanitize::resolve_safe_link;

    #[test]
    fn sanitizer_strips_scripts_and_unsafe_links_but_allows_lns_relative_and_https() {
        let html = r#"
            <html><head><title>My Site</title><script>fetch('https://evil.com')</script></head>
            <body>
              <h1>Hello</h1>
              <p><a href="about.html">About</a> | <a href="lns://logos">Logos</a> | <a href="https://nameswallet.app/browser">Web</a> | <a href="javascript:alert(1)">XSS</a></p>
            </body></html>
        "#;
        let s = sanitize_html(html, "lns://jef", "/index.html");
        assert_eq!(s.title.as_deref(), Some("My Site"));
        assert!(!s.html.contains("script"));
        assert!(!s.html.contains("evil.com"));
        assert!(!s.html.contains("javascript:"));
        assert!(s.html.contains(r#"href="lns://jef/about.html""#));
        assert!(s.html.contains(r#"href="lns://logos""#));
        assert!(s.html.contains(r#"href="https://nameswallet.app/browser""#));
    }

    #[test]
    fn relative_link_resolution_blocks_traversal_and_unsafe_schemes() {
        assert_eq!(
            resolve_safe_link("../secret.html", "lns://jef", "/docs/guide.html").as_deref(),
            Some("lns://jef/secret.html")
        );
        assert_eq!(
            resolve_safe_link("https://nameswallet.app/browser", "lns://jef", "/").as_deref(),
            Some("https://nameswallet.app/browser")
        );
        assert_eq!(resolve_safe_link("http://example.com", "lns://jef", "/"), None);
        assert_eq!(resolve_safe_link("https://user:pass@example.com", "lns://jef", "/"), None);
        assert_eq!(resolve_safe_link("data:text/html,hi", "lns://jef", "/"), None);
    }

    #[test]
    fn render_html_returns_palette_and_blocks() {
        let mut m = LnsBrowser::default();
        let raw = m.render_html(
            r##"<html><head><title>Hi</title><style>body{background:#fff;color:#111} a{color:#0055ff}</style></head><body><img src="cid://z4W2jShot00000000000000000000000000000000000000" alt="Shot"><p><a href="https://nameswallet.app/browser">Go</a> <a href="cid://z4W2jLgx000000000000000000000000000000000000000" download="app.lgx">Save</a></p></body></html>"##.to_owned(),
            "lns://helloworld".to_owned(),
            "/".to_owned(),
        );
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["value"]["bg_color"], "#ffffff");
        assert_eq!(parsed["value"]["fg_color"], "#111111");
        assert_eq!(parsed["value"]["link_color"], "#0055ff");
        assert_eq!(parsed["value"]["mode"], "onchain-page");
        assert_eq!(
            parsed["value"]["blocks"][0]["src_cid"],
            "z4W2jShot00000000000000000000000000000000000000"
        );
        assert_eq!(parsed["value"]["downloads"][0]["filename"], "app.lgx");
    }

    #[test]
    fn finding4_render_bytes_escapes_untrusted_content_type() {
        let doc = LnsBrowser::render_bytes(
            b"\x00\x01\x02\x03",
            r#"application/octet-stream<img src="https://evil.example/leak.png">"#,
            "lns://demo",
            "/",
        );
        let html = doc.html.unwrap();
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;img src=&quot;https://evil.example/leak.png&quot;&gt;"));
    }

    #[test]
    fn finding5_download_path_validation_blocks_traversal_dotfiles_overwrite_and_verifies_sha256() {
        let unique = format!(
            "lns-dl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        let dl_dir = base.join("Downloads");
        let outside_dir = base.join("Outside");
        fs::create_dir_all(&dl_dir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        // Reject traversal, `.`, `..`, dotfiles, control chars, outside Downloads
        assert!(resolve_path_in_downloads(&format!("{}/..", dl_dir.display()), &dl_dir, true).is_err());
        assert!(resolve_path_in_downloads(&format!("{}/.", dl_dir.display()), &dl_dir, true).is_err());
        assert!(resolve_path_in_downloads(&format!("{}/.bashrc", dl_dir.display()), &dl_dir, true).is_err());
        assert!(resolve_path_in_downloads(&format!("{}/bad\x07name.lgx", dl_dir.display()), &dl_dir, true).is_err());
        assert!(resolve_path_in_downloads(&format!("{}/../Outside/x.lgx", dl_dir.display()), &dl_dir, true).is_err());
        assert!(resolve_path_in_downloads(&format!("{}/evil.lgx", outside_dir.display()), &dl_dir, true).is_err());
        assert!(resolve_path_in_downloads("/tmp/evil.lgx", &dl_dir, true).is_err());

        // Accept clean non-existing file inside Downloads
        let ok_path = dl_dir.join("lns-browser-0.2.8.lgx");
        let resolved = resolve_path_in_downloads(&ok_path.to_string_lossy(), &dl_dir, true).unwrap();
        assert_eq!(resolved, fs::canonicalize(&dl_dir).unwrap().join("lns-browser-0.2.8.lgx"));

        // Write file and verify overwrite is refused
        let payload = b"REAL-LGX-BYTES";
        fs::write(&ok_path, payload).unwrap();
        assert!(resolve_path_in_downloads(&ok_path.to_string_lossy(), &dl_dir, true).is_err());

        // Matching SHA-256 passes verification and keeps file
        let good_sha = crate::storage::sha256_hex(payload);
        let ok_res = verify_saved_file_in_dir(&ok_path.to_string_lossy(), &good_sha, &dl_dir).unwrap();
        assert_eq!(ok_res["verified"], true);
        assert_eq!(ok_res["sha256"], good_sha);
        assert!(ok_path.exists());

        // Mismatched SHA-256 fails AND deletes the tampered file
        let bad_sha = "0".repeat(64);
        let bad_res = verify_saved_file_in_dir(&ok_path.to_string_lossy(), &bad_sha, &dl_dir);
        assert!(bad_res.is_err());
        assert!(bad_res.unwrap_err().contains("SHA-256 mismatch"));
        assert!(!ok_path.exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn round6_site_api_and_persistence_bookmarks_history_window_state() {
        let unique = format!(
            "lns-r6-core-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let cfg_dir = std::env::temp_dir().join(unique);
        let mut m = LnsBrowser {
            storage_api: String::new(),
            storage_peers: Vec::new(),
            config_path: Some(cfg_dir.join("config.json")),
            folder_cache: HashMap::new(),
            servers: SiteServerManager::with_cache_dir(
                cfg_dir.join("cache"),
                default_basecamp_downloader(),
            ),
        };

        // 1. site_open / site_stats / site_poll_events / site_close
        let open_raw = m.site_open(
            json!({
                "kind": "lns",
                "host": "helloworld",
                "site_base": "lns://helloworld",
                "mode": "onchain-page",
                "html": "<html><head><title>Hello</title></head><body><h1>World</h1></body></html>",
                "path": "/"
            })
            .to_string(),
        );
        let open_v: Value = serde_json::from_str(&open_raw).unwrap();
        assert_eq!(open_v["success"], true);
        let tok = open_v["value"]["token"].as_str().unwrap().to_owned();
        assert_eq!(tok.len(), 32);
        assert!(open_v["value"]["entry_url"]
            .as_str()
            .unwrap()
            .starts_with("http://127.0.0.1:"));

        let stats_v: Value = serde_json::from_str(&m.site_stats(tok.clone())).unwrap();
        assert_eq!(stats_v["success"], true);
        assert_eq!(stats_v["value"]["mode"], "onchain-page");
        assert_eq!(stats_v["value"]["verified"], true);

        let close_v: Value = serde_json::from_str(&m.site_close(tok.clone())).unwrap();
        assert_eq!(close_v["success"], true);
        assert_eq!(close_v["value"]["closed"], true);
        assert_eq!(m.servers.active_count(), 0);

        // 2. Bookmarks persistence
        let bm_set: Value = serde_json::from_str(&m.bookmarks_set(
            json!([
                { "url": "lns://nameswallet", "title": "Names Wallet", "name": "nameswallet", "added_at": 1700000000 }
            ])
            .to_string(),
        ))
        .unwrap();
        assert_eq!(bm_set["success"], true);
        let bm_get: Value = serde_json::from_str(&m.bookmarks_get()).unwrap();
        assert_eq!(bm_get["value"].as_array().unwrap().len(), 1);
        assert_eq!(bm_get["value"][0]["url"], "lns://nameswallet");

        // 3. History persistence + deduplication + clear
        let _ = m.history_add(
            json!({ "url": "lns://nameswallet", "title": "Home", "name": "nameswallet", "visited_at": 100 }).to_string(),
        );
        let _ = m.history_add(
            json!({ "url": "lns://nameswallet/browser/", "title": "Browser", "name": "nameswallet", "visited_at": 200 }).to_string(),
        );
        let _ = m.history_add(
            json!({ "url": "lns://nameswallet", "title": "Home Updated", "name": "nameswallet", "visited_at": 300 }).to_string(),
        );
        let hist: Value = serde_json::from_str(&m.history_get()).unwrap();
        let arr = hist["value"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["url"], "lns://nameswallet");
        assert_eq!(arr[0]["title"], "Home Updated");
        let cleared: Value = serde_json::from_str(&m.history_clear()).unwrap();
        assert_eq!(cleared["value"].as_array().unwrap().len(), 0);

        // 4. Browser window geometry & reader_mode persistence + clamping
        let st_set: Value = serde_json::from_str(&m.browser_state_set(
            json!({
                "window": { "x": 240, "y": 90, "width": 1280, "height": 840 },
                "reader_mode": true
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(st_set["success"], true);
        let st_get: Value = serde_json::from_str(&m.browser_state_get()).unwrap();
        assert_eq!(st_get["value"]["window"]["width"], 1280);
        assert_eq!(st_get["value"]["window"]["height"], 840);
        assert_eq!(st_get["value"]["reader_mode"], true);

        let _ = fs::remove_dir_all(&cfg_dir);
    }
}
