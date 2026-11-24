//! Logos Storage REST client (API v0.5.3) + v1 site manifest parser & publisher.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::sanitize::normalize_site_path;

pub const DEFAULT_STORAGE_API: &str = "http://127.0.0.1:8080/api/storage/v1";
pub const MANIFEST_KIND: &str = "lns-site-manifest";
pub const MANIFEST_MIME: &str = "application/vnd.logos.site-manifest+json";
pub const MAX_DOWNLOAD_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

#[derive(Debug, Clone)]
pub struct Downloaded {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub content_type: String,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct ManifestEntry {
    pub cid: String,
    pub sha256: Option<String>,
    pub size: Option<usize>,
    pub content_type: String,
}

#[derive(Debug, Clone)]
pub struct SiteManifest {
    pub title: Option<String>,
    pub index: String,
    pub files: BTreeMap<String, ManifestEntry>,
}

pub fn is_valid_cid(cid: &str) -> bool {
    (8..=128).contains(&cid.len()) && cid.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn mime_for_path(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        _ => "application/octet-stream",
    }
}

pub fn sniff_content_type(bytes: &[u8], fallback: &str) -> String {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
    let trimmed = head.trim_start().to_ascii_lowercase();
    if trimmed.starts_with("<!doctype html")
        || trimmed.starts_with("<html")
        || trimmed.starts_with("<head")
        || trimmed.starts_with("<body")
        || trimmed.starts_with("<h1")
    {
        return "text/html; charset=utf-8".to_owned();
    }
    fallback.to_owned()
}

pub fn try_parse_manifest(bytes: &[u8]) -> Result<Option<SiteManifest>, String> {
    if bytes.is_empty() || bytes.len() > 2 * 1024 * 1024 {
        return Ok(None);
    }
    let first = bytes.iter().copied().find(|b| !b.is_ascii_whitespace());
    if first != Some(b'{') {
        return Ok(None);
    }
    let Ok(val) = serde_json::from_slice::<Value>(bytes) else {
        return Ok(None);
    };
    if val["kind"].as_str() != Some(MANIFEST_KIND) || val["version"].as_u64() != Some(1) {
        return Ok(None);
    }
    let Some(obj) = val["files"].as_object() else {
        return Err("manifest is missing a `files` object".to_owned());
    };
    let mut files = BTreeMap::new();
    for (raw_path, entry) in obj {
        let clean = normalize_site_path(raw_path);
        let cid = entry["cid"]
            .as_str()
            .filter(|c| is_valid_cid(c))
            .ok_or_else(|| format!("manifest entry {raw_path} has an invalid CID"))?
            .to_owned();
        let sha256 = entry["sha256"]
            .as_str()
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .map(|h| h.to_ascii_lowercase());
        let size = entry["size"].as_u64().map(|n| n as usize);
        let content_type = entry["contentType"]
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| mime_for_path(&clean).to_owned());
        files.insert(
            clean,
            ManifestEntry {
                cid,
                sha256,
                size,
                content_type,
            },
        );
    }
    let index = val["index"]
        .as_str()
        .map(normalize_site_path)
        .unwrap_or_else(|| "/index.html".to_owned());
    let title = val["title"].as_str().map(ToOwned::to_owned);
    Ok(Some(SiteManifest { title, index, files }))
}

impl SiteManifest {
    pub fn resolve(&self, raw_path: &str) -> Option<(&str, &ManifestEntry)> {
        let clean = normalize_site_path(raw_path);
        if clean == "/" {
            return self
                .files
                .get_key_value(&self.index)
                .or_else(|| self.files.get_key_value("/index.html"))
                .map(|(k, v)| (k.as_str(), v));
        }
        if let Some((k, v)) = self.files.get_key_value(&clean) {
            return Some((k.as_str(), v));
        }
        let with_index = format!("{}/index.html", clean.trim_end_matches('/'));
        self.files
            .get_key_value(&with_index)
            .map(|(k, v)| (k.as_str(), v))
    }
}

pub struct StorageClient {
    base: String,
    agent: ureq::Agent,
}

impl StorageClient {
    pub fn new(base: &str) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(30))
            .redirects(0)
            .build();
        Self {
            base: base.trim_end_matches('/').to_owned(),
            agent,
        }
    }

    pub fn debug_info(&self) -> Result<Value, String> {
        let resp = self
            .agent
            .get(&format!("{}/debug/info", self.base))
            .call()
            .map_err(|e| format!("Storage node unreachable: {e}"))?;
        resp.into_json::<Value>()
            .map_err(|e| format!("Storage /debug/info bad JSON: {e}"))
    }

    pub fn download(
        &self,
        cid: &str,
        expected_sha256: Option<&str>,
        expected_size: Option<usize>,
    ) -> Result<Downloaded, String> {
        if !is_valid_cid(cid) {
            return Err(format!("invalid CID: {cid}"));
        }
        let endpoints = [
            format!("{}/data/{cid}/network/stream", self.base),
            format!("{}/data/{cid}", self.base),
        ];
        let mut last_err = String::from("Storage node unreachable");
        for url in endpoints {
            match self.agent.get(&url).call() {
                Ok(resp) => {
                    let content_type = resp
                        .header("Content-Type")
                        .unwrap_or("application/octet-stream")
                        .to_owned();
                    let mut bytes = Vec::new();
                    resp.into_reader()
                        .take((MAX_DOWNLOAD_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                        .map_err(|e| format!("Storage read failed: {e}"))?;
                    if bytes.len() > MAX_DOWNLOAD_BYTES {
                        return Err(format!("CID {cid} exceeds {MAX_DOWNLOAD_BYTES} byte limit"));
                    }
                    if let Some(exp_sz) = expected_size {
                        if bytes.len() != exp_sz {
                            return Err(format!(
                                "integrity mismatch for {cid}: expected {exp_sz} bytes, got {}",
                                bytes.len()
                            ));
                        }
                    }
                    let actual = sha256_hex(&bytes);
                    let mut verified = false;
                    if let Some(exp) = expected_sha256.filter(|s| !s.is_empty()) {
                        let exp_lower = exp.to_ascii_lowercase();
                        if actual != exp_lower {
                            return Err(format!(
                                "SHA-256 mismatch for {cid}: expected {exp_lower}, got {actual}"
                            ));
                        }
                        verified = true;
                    }
                    return Ok(Downloaded {
                        bytes,
                        sha256: actual,
                        content_type,
                        verified,
                    });
                }
                Err(ureq::Error::Status(code, _)) => {
                    last_err = format!("Storage returned HTTP {code} for {cid}");
                }
                Err(e) => {
                    last_err = format!("Storage request failed: {e}");
                }
            }
        }
        Err(last_err)
    }

    pub fn upload(&self, filename: &str, mime: &str, bytes: &[u8]) -> Result<(String, String), String> {
        let safe_name: String = filename
            .chars()
            .map(|c| if matches!(c, '"' | '\r' | '\n' | '/' | '\\') { '_' } else { c })
            .collect();
        let resp = self
            .agent
            .post(&format!("{}/data", self.base))
            .set("Content-Type", mime)
            .set("Content-Disposition", &format!("attachment; filename=\"{safe_name}\""))
            .send_bytes(bytes)
            .map_err(|e| format!("Storage upload failed: {e}"))?;
        let cid = resp
            .into_string()
            .map_err(|e| format!("Storage upload bad reply: {e}"))?
            .trim()
            .to_owned();
        if !is_valid_cid(&cid) {
            return Err(format!("Storage returned unexpected CID: {cid:?}"));
        }
        Ok((cid, sha256_hex(bytes)))
    }

    pub fn publish_path(&self, local_path: &Path, title: Option<&str>) -> Result<Value, String> {
        let meta = fs::metadata(local_path).map_err(|e| format!("cannot read path: {e}"))?;
        if meta.is_file() {
            let bytes = fs::read(local_path).map_err(|e| format!("cannot read file: {e}"))?;
            let fname = local_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("index.html");
            let mime = mime_for_path(fname);
            let (cid, hash) = self.upload(fname, mime, &bytes)?;
            return Ok(json!({
                "mode": "single",
                "root_cid": cid,
                "sha256": hash,
                "size": bytes.len(),
                "files": [{ "path": format!("/{fname}"), "cid": cid, "sha256": hash, "size": bytes.len(), "contentType": mime }],
            }));
        }
        if !meta.is_dir() {
            return Err("path must be a file or directory".to_owned());
        }

        let mut rel_files = Vec::new();
        walk_dir(local_path, "", &mut rel_files)?;
        if rel_files.is_empty() {
            return Err("directory is empty".to_owned());
        }
        rel_files.sort();

        let mut files_map = serde_json::Map::new();
        let mut files_list = Vec::new();
        for rel in &rel_files {
            let abs = local_path.join(rel);
            let bytes = fs::read(&abs).map_err(|e| format!("cannot read {rel}: {e}"))?;
            let site_path = normalize_site_path(&format!("/{rel}"));
            let mime = mime_for_path(&site_path);
            let fname = site_path.rsplit('/').next().unwrap_or("blob");
            let (cid, hash) = self.upload(fname, mime, &bytes)?;
            files_map.insert(
                site_path.clone(),
                json!({ "cid": cid, "sha256": hash, "size": bytes.len(), "contentType": mime }),
            );
            files_list.push(json!({ "path": site_path, "cid": cid, "sha256": hash, "size": bytes.len(), "contentType": mime }));
        }

        let index = if files_map.contains_key("/index.html") {
            "/index.html".to_owned()
        } else {
            files_list[0]["path"].as_str().unwrap_or("/index.html").to_owned()
        };
        let mut manifest = json!({
            "kind": MANIFEST_KIND,
            "version": 1,
            "index": index,
            "files": files_map,
        });
        if let Some(t) = title.filter(|s| !s.trim().is_empty()) {
            manifest["title"] = Value::String(t.trim().to_owned());
        }
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
        let (root_cid, root_hash) =
            self.upload("lns-site-manifest.json", MANIFEST_MIME, &manifest_bytes)?;
        Ok(json!({
            "mode": "manifest",
            "root_cid": root_cid,
            "sha256": root_hash,
            "size": manifest_bytes.len(),
            "files": files_list,
        }))
    }
}

fn walk_dir(root: &Path, prefix: &str, out: &mut Vec<String>) -> Result<(), String> {
    let dir = if prefix.is_empty() { root.to_path_buf() } else { root.join(prefix) };
    for entry in fs::read_dir(&dir).map_err(|e| format!("cannot list dir: {e}"))? {
        let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let rel = if prefix.is_empty() { name } else { format!("{prefix}/{name}") };
        let ft = entry.file_type().map_err(|e| format!("file type error: {e}"))?;
        if ft.is_dir() {
            walk_dir(root, &rel, out)?;
        } else if ft.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}
