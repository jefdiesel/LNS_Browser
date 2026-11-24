//! `lns_browser_core`: Basecamp core module for the native LNS + CID Web Browser.
//!
//! Fetches CIDs from the user's local Logos Storage node, verifies SHA-256 commitments against
//! the on-chain LNS record, sanitizes HTML/Markdown into safe zero-JS Qt RichText with `lns://`,
//! `cid://`, and click-to-confirm `https://` links plus safe colors and inline SVG graphics, and
//! publishes local files/folders to Logos Storage CIDs.

mod sanitize;
mod storage;

use std::path::Path;

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

    /// Checks whether the configured local Logos Storage node is reachable.
    fn storage_status(&mut self) -> String;

    /// Returns `{storage_api}`.
    fn config_get(&mut self) -> String;

    /// Updates `storage_api` (must be `http://127.0.0.1...`, `http://localhost...`, or `https://...`).
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
}

impl Default for LnsBrowser {
    fn default() -> Self {
        Self {
            storage_api: DEFAULT_STORAGE_API.to_owned(),
        }
    }
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
            json!({
                "kind": b.kind,
                "html": b.html,
                "data_uri": b.data_uri,
                "alt": b.alt,
                "width": b.width,
                "height": b.height,
            })
        })
        .collect()
}

impl LnsBrowser {
    fn client(&self) -> StorageClient {
        StorageClient::new(&self.storage_api)
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

    fn storage_status(&mut self) -> String {
        if self.storage_api.trim().is_empty() {
            return ok(json!({
                "online": false,
                "configured": false,
                "storage_api": "",
                "reason": "No external Logos Storage API URL configured (use Basecamp's built-in Storage module or set one in Settings).",
            }));
        }
        match self.client().debug_info() {
            Ok(info) => ok(json!({
                "online": true,
                "configured": true,
                "storage_api": self.storage_api,
                "peer_id": info["id"],
                "mock": info["mock"].as_bool().unwrap_or(false) || info["id"].as_str() == Some("16Uiu2HAmLocalLogosStorageSeed"),
            })),
            Err(e) => ok(json!({
                "online": false,
                "configured": true,
                "storage_api": self.storage_api,
                "reason": e,
            })),
        }
    }

    fn config_get(&mut self) -> String {
        ok(json!({ "storage_api": self.storage_api }))
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
                if !is_allowed_storage_url(trimmed) {
                    return err("storage_api must start with http://127.0.0.1, http://localhost, or https://");
                }
                self.storage_api = trimmed.trim_end_matches('/').to_owned();
            }
        }
        self.config_get()
    }
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
