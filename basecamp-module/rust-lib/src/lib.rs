//! `lns_browser_core`: Basecamp core module for the native LNS + CID Web Browser.
//!
//! Fetches CIDs from the user's local Logos Storage node, verifies SHA-256 commitments against
//! the on-chain LNS record, sanitizes HTML/Markdown into safe zero-JS Qt RichText with `lns://`,
//! `cid://`, and click-to-confirm `https://` links plus safe colors and inline SVG graphics, and
//! publishes local files/folders to Logos Storage CIDs.

mod sanitize;
mod storage;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::sanitize::{markdown_to_safe_html, normalize_site_path, sanitize_html, RenderBlock};
use crate::storage::{sniff_content_type, try_parse_manifest, StorageClient, DEFAULT_STORAGE_API};

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

    /// Checks whether the configured local Logos Storage node is reachable.
    fn storage_status(&mut self) -> String;

    /// Returns `{storage_api, storage_peers, storage_peers_text}`.
    fn config_get(&mut self) -> String;

    /// Updates local settings (`storage_api`, `storage_peers` / `storage_peers_text`) and persists
    /// them to `~/.config/lns-browser/config.json`.
    fn config_set(&mut self, settings_json: String) -> String;

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
}

impl Default for LnsBrowser {
    fn default() -> Self {
        let config_path = default_config_path();
        let mut me = Self {
            storage_api: DEFAULT_STORAGE_API.to_owned(),
            storage_peers: Vec::new(),
            config_path,
        };
        me.load_config_from_disk();
        me
    }
}

fn default_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config").join("lns-browser").join("config.json"))
}

fn is_port_8080_url(url: &str) -> bool {
    let low = url.trim().to_ascii_lowercase();
    low.starts_with("http://127.0.0.1:8080")
        || low.starts_with("https://127.0.0.1:8080")
        || low.starts_with("http://localhost:8080")
        || low.starts_with("https://localhost:8080")
}

fn is_safe_external_https_url(url: &str) -> bool {
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
            }
        } else {
            let html = format!(
                "<p>Binary asset ({} bytes, <code>{}</code>) — verified by SHA-256.</p>",
                bytes.len(),
                content_type
            );
            RenderedDoc {
                kind: "binary".to_owned(),
                title: None,
                blocks: vec![RenderBlock {
                    kind: "html".to_owned(),
                    html: Some(html.clone()),
                    data_uri: None,
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
                return err(format!("{req_path} not found in site manifest"));
            };
            let asset = match client.download(&entry.cid, entry.sha256.as_deref(), entry.size) {
                Ok(d) => d,
                Err(e) => return err(e),
            };
            let doc =
                Self::render_bytes(&asset.bytes, &entry.content_type, &site_base, resolved_path);
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
                "truncated": doc.truncated,
                "files": files_list,
            }));
        }

        let ct = sniff_content_type(&root.bytes, &root.content_type);
        let doc = Self::render_bytes(&root.bytes, &ct, &site_base, "/");
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
        match invoke_storage_connect(&clean_id, &addrs) {
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
        ok(json!({
            "storage_api": self.storage_api,
            "storage_peers": self.storage_peers,
            "storage_peers_text": self.storage_peers.join("\n"),
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
}

#[cfg(not(test))]
fn invoke_storage_connect(peer_id: &str, addrs: &[String]) -> Result<Value, String> {
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

    let args = json!([peer_id, addrs]);
    proxy
        .call_json_with_timeout("connect", &args, Duration::from_secs(10))
        .map_err(|e| format!("storage_module.connect SDK error: {e}"))
}

#[cfg(test)]
fn invoke_storage_connect(peer_id: &str, addrs: &[String]) -> Result<Value, String> {
    Ok(json!({ "success": true, "peer_id": peer_id, "addrs": addrs }))
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
            r##"<html><head><title>Hi</title><style>body{background:#fff;color:#111} a{color:#0055ff}</style></head><body><p><a href="https://nameswallet.app/browser">Go</a></p></body></html>"##.to_owned(),
            "lns://helloworld".to_owned(),
            "/".to_owned(),
        );
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["value"]["bg_color"], "#ffffff");
        assert_eq!(parsed["value"]["fg_color"], "#111111");
        assert_eq!(parsed["value"]["link_color"], "#0055ff");
        assert_eq!(parsed["value"]["mode"], "onchain-page");
    }
}
