//! Per-site loopback HTTP/1.1 server for `lns_browser_core`.
//!
//! Security & isolation guarantees (PLAN5 §§1-2, ROUND6):
//! - Binds strictly `127.0.0.1:0` (ephemeral port per active site, true Same-Origin Policy isolation).
//! - Requires a random 128-bit hex path prefix `/<token>/...` checked in constant time (`403` on mismatch).
//! - Rejects missing/mismatched/duplicate `Host` headers (`403`, anti-DNS-rebinding).
//! - Allows `GET` and `HEAD` only (`405 Method Not Allowed` with `Allow: GET, HEAD` for everything else).
//! - Refuses path traversal (`..`, `%2e%2e`, `%2f`, `%5c`, `\`, NUL/control chars) with `400 Bad Request`.
//! - Sends strict CSP and security headers on EVERY response; never emits `Set-Cookie`, ignores `Cookie`.
//! - Serves ONLY verified bytes: every file fetched from Storage (HTTP or Basecamp `storage_module`)
//!   is checked by CID + pinned SHA-256 before caching/serving; tampered bytes are refused (`502`).
//! - Rewrites HTML/CSS on serve: strips `<meta http-equiv="refresh">`, injects `<head>` prelude
//!   stubbing `window.open` and `document.cookie`, rewrites `https://` -> `/_ext`, `lns://` -> `/_lns`,
//!   `<a download>`/`.lgx` -> `/_dl`, `cid://` -> `/_cid/<cid>` (allowlisted per site), and
//!   root-relative paths `/` -> `/<token>/`.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::links::{
    is_binary_download_path, is_links_list_text, is_valid_sha256, normalize_links_path,
    parse_links_list, parse_url, resolve_links_tree, CachedLinksList, EntryKind, LinksEntry,
    LinksList, ResolveOutcome,
};
use crate::storage::{
    is_valid_cid, mime_for_path, sha256_hex, sniff_content_type, try_parse_manifest, SiteManifest,
    StorageClient, MAX_DOWNLOAD_BYTES,
};

pub const MAX_ACTIVE_SITES: usize = 8;
const MAX_CONNS_PER_SITE: usize = 32;
const MAX_REQ_HEADER_BYTES: usize = 16 * 1024;
const MAX_CACHE_ENTRIES: usize = 128;
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
const BASECAMP_BLOB_TIMEOUT_SECS: u64 = 30;
const MAX_SITE_EVENTS: usize = 64;

pub const STRICT_CSP: &str = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; media-src 'self' blob:; connect-src 'self'; worker-src 'self'; child-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'";

pub type BasecampDownloader = Arc<dyn Fn(&str, &Path) -> Result<(), String> + Send + Sync>;

#[derive(Debug, Clone)]
pub struct SiteSpec {
    pub kind: String,        // "lns" | "cid"
    pub host: String,        // LNS name or CID
    pub site_base: String,   // "lns://<name>" | "cid://<cid>"
    pub mode: String,        // "onchain-page" | "onchain-links" | "cid"
    pub root_cid: String,    // Root Logos Storage CID (empty for on-chain modes)
    pub root_sha256: String, // Optional pinned 64-hex SHA-256
    pub site_type: String,   // Optional "links" | "manifest" | "single"
    pub backend: String,     // "basecamp" | "http" | "memory"
    pub storage_api: String, // External HTTP storage URL when backend == "http"
    pub onchain_html: Option<String>,
    pub onchain_links: Option<String>,
    pub title: Option<String>,
    pub initial_path: String,
}

impl SiteSpec {
    fn reuse_key(&self) -> (String, String, String, String, String, String, String) {
        (
            self.kind.clone(),
            self.host.clone(),
            self.mode.clone(),
            self.root_cid.clone(),
            self.root_sha256.clone(),
            self.backend.clone(),
            self.storage_api.clone(),
        )
    }
}

#[derive(Debug, Clone)]
struct VerifiedFileInfo {
    path: String,
    cid: String,
    sha256: String,
    size: usize,
    content_type: String,
    verified: bool,
}

#[derive(Debug, Clone)]
struct SiteErrorInfo {
    kind: String, // "not_found" | "storage_error" | "tampered"
    cid: String,
    path: String,
    message: String,
}

#[derive(Clone)]
enum RootSource {
    Unloaded,
    OnChainHtml {
        bytes: Vec<u8>,
        sha256: String,
    },
    Links {
        root_list: LinksList,
        root_verified: bool,
    },
    Manifest {
        manifest: SiteManifest,
        root_verified: bool,
    },
    SingleCid {
        bytes: Vec<u8>,
        content_type: String,
        sha256: String,
        verified: bool,
    },
}

struct SiteState {
    root: RootSource,
    folder_cache: HashMap<String, CachedLinksList>,
    allowed_cids: HashSet<String>,
    known_cid_sha256: HashMap<String, String>,
    verified_files: BTreeMap<String, VerifiedFileInfo>,
    folder_files: Vec<Value>,
    current_path: String,
    resolved_mode: String,
    root_sha256: String,
    root_verified: bool,
    title: Option<String>,
    last_error: Option<SiteErrorInfo>,
    events: VecDeque<Value>,
    last_used: Instant,
}

struct CachedBlobMeta {
    disk_path: PathBuf,
    sha256: String,
    size: usize,
    last_used: Instant,
}

#[derive(Debug, Clone)]
struct BlobReadySignal {
    ok: bool,
    tmp_path: PathBuf,
    err: String,
}

struct InFlightBlob {
    tmp_path: PathBuf,
    result: Mutex<Option<BlobReadySignal>>,
    cvar: Condvar,
}

pub struct VerifiedBlobCache {
    cache_dir: PathBuf,
    seq: AtomicU64,
    entries: Mutex<HashMap<String, CachedBlobMeta>>,
    total_bytes: AtomicUsize,
    in_flight: Mutex<HashMap<String, Arc<InFlightBlob>>>,
    basecamp_downloader: BasecampDownloader,
}

impl VerifiedBlobCache {
    pub fn new(cache_dir: PathBuf, basecamp_downloader: BasecampDownloader) -> Self {
        let _ = create_private_dir(&cache_dir);
        Self {
            cache_dir,
            seq: AtomicU64::new(1),
            entries: Mutex::new(HashMap::new()),
            total_bytes: AtomicUsize::new(0),
            in_flight: Mutex::new(HashMap::new()),
            basecamp_downloader,
        }
    }

    fn next_tmp_path(&self, cid: &str) -> PathBuf {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let prefix: String = cid
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(16)
            .collect();
        let _ = create_private_dir(&self.cache_dir);
        self.cache_dir.join(format!("dl-{n}-{prefix}.tmp"))
    }

    fn cache_path_for(&self, cid: &str, sha256: &str) -> PathBuf {
        let prefix: String = cid
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(24)
            .collect();
        let h: String = sha256.chars().take(16).collect();
        self.cache_dir.join(format!("blob-{prefix}-{h}.bin"))
    }

    fn get_cached(
        &self,
        cid: &str,
        expected_sha256: Option<&str>,
    ) -> Result<Option<(Vec<u8>, String, bool)>, String> {
        let disk_info = {
            let mut map = self.entries.lock().unwrap();
            if let Some(meta) = map.get_mut(cid) {
                if let Some(exp) = expected_sha256.filter(|s| !s.is_empty()) {
                    if !meta.sha256.eq_ignore_ascii_case(exp) {
                        return Err(format!(
                            "SHA-256 mismatch for cached CID {cid}: expected {}, got {}",
                            exp.to_ascii_lowercase(),
                            meta.sha256
                        ));
                    }
                }
                meta.last_used = Instant::now();
                Some((meta.disk_path.clone(), meta.sha256.clone()))
            } else {
                None
            }
        };
        let Some((path, sha)) = disk_info else {
            return Ok(None);
        };
        match fs::read(&path) {
            Ok(bytes) => {
                let actual = sha256_hex(&bytes);
                if actual != sha {
                    let _ = fs::remove_file(&path);
                    let mut map = self.entries.lock().unwrap();
                    if let Some(old) = map.remove(cid) {
                        self.total_bytes.fetch_sub(old.size.min(self.total_bytes.load(Ordering::Relaxed)), Ordering::Relaxed);
                    }
                    return Err(format!(
                        "Cache integrity mismatch for CID {cid}: expected {sha}, got {actual}"
                    ));
                }
                let verified = expected_sha256
                    .filter(|s| !s.is_empty())
                    .map(|exp| actual.eq_ignore_ascii_case(exp))
                    .unwrap_or(false);
                Ok(Some((bytes, actual, verified)))
            }
            Err(_) => {
                let mut map = self.entries.lock().unwrap();
                if let Some(old) = map.remove(cid) {
                    self.total_bytes.fetch_sub(old.size.min(self.total_bytes.load(Ordering::Relaxed)), Ordering::Relaxed);
                }
                Ok(None)
            }
        }
    }

    fn put_cached(&self, cid: &str, bytes: &[u8], sha256: &str) {
        if bytes.len() > MAX_CACHE_BYTES / 2 {
            return;
        }
        let _ = create_private_dir(&self.cache_dir);
        let disk_path = self.cache_path_for(cid, sha256);
        if fs::write(&disk_path, bytes).is_err() {
            return;
        }
        let mut map = self.entries.lock().unwrap();
        if let Some(old) = map.insert(
            cid.to_owned(),
            CachedBlobMeta {
                disk_path,
                sha256: sha256.to_ascii_lowercase(),
                size: bytes.len(),
                last_used: Instant::now(),
            },
        ) {
            let prev = self.total_bytes.load(Ordering::Relaxed);
            self.total_bytes
                .store(prev.saturating_sub(old.size), Ordering::Relaxed);
        }
        self.total_bytes.fetch_add(bytes.len(), Ordering::Relaxed);

        // Evict LRU entries while over count or byte budget
        while map.len() > MAX_CACHE_ENTRIES
            || self.total_bytes.load(Ordering::Relaxed) > MAX_CACHE_BYTES
        {
            let oldest_key = map
                .iter()
                .min_by_key(|(_, m)| m.last_used)
                .map(|(k, _)| k.clone());
            let Some(k) = oldest_key else {
                break;
            };
            if let Some(evicted) = map.remove(&k) {
                let _ = fs::remove_file(&evicted.disk_path);
                let prev = self.total_bytes.load(Ordering::Relaxed);
                self.total_bytes
                    .store(prev.saturating_sub(evicted.size), Ordering::Relaxed);
            }
        }
    }

    pub fn notify_blob_ready(&self, cid: &str, tmp_path: &str, ok: bool, err: &str) -> bool {
        let inflight = {
            let map = self.in_flight.lock().unwrap();
            map.get(cid).cloned()
        };
        let Some(waiter) = inflight else {
            return false;
        };
        let resolved_tmp = if !tmp_path.trim().is_empty() {
            let candidate = PathBuf::from(tmp_path.trim());
            // Only accept a caller-provided path if it is inside our private cache dir
            if candidate.starts_with(&self.cache_dir) {
                candidate
            } else {
                waiter.tmp_path.clone()
            }
        } else {
            waiter.tmp_path.clone()
        };
        let mut slot = waiter.result.lock().unwrap();
        if slot.is_none() {
            *slot = Some(BlobReadySignal {
                ok,
                tmp_path: resolved_tmp,
                err: err.to_owned(),
            });
            waiter.cvar.notify_all();
        }
        true
    }

    pub fn fetch_verified(
        &self,
        cid: &str,
        expected_sha256: Option<&str>,
        expected_size: Option<usize>,
        backend: &str,
        storage_api: &str,
    ) -> Result<(Vec<u8>, String, bool), FetchFailure> {
        if !is_valid_cid(cid) {
            return Err(FetchFailure::Storage(format!("invalid CID: {cid}")));
        }
        if let Some(exp) = expected_sha256.filter(|s| !s.is_empty()) {
            if !is_valid_sha256(exp) {
                return Err(FetchFailure::Tampered(format!(
                    "invalid pinned SHA-256 `{exp}` for CID {cid}"
                )));
            }
        }

        // 1. Check verified LRU cache first
        match self.get_cached(cid, expected_sha256) {
            Ok(Some((bytes, sha, verified))) => {
                if let Some(exp_sz) = expected_size {
                    if bytes.len() != exp_sz {
                        return Err(FetchFailure::Tampered(format!(
                            "integrity mismatch for {cid}: expected {exp_sz} bytes, got {}",
                            bytes.len()
                        )));
                    }
                }
                return Ok((bytes, sha, verified));
            }
            Ok(None) => {}
            Err(e) => return Err(FetchFailure::Tampered(e)),
        }

        // 2. HTTP Storage backend
        if backend == "http" {
            let client = StorageClient::new(storage_api);
            let dl = client
                .download(cid, expected_sha256, expected_size)
                .map_err(|e| {
                    if e.contains("SHA-256 mismatch") || e.contains("integrity mismatch") {
                        FetchFailure::Tampered(e)
                    } else {
                        FetchFailure::Storage(e)
                    }
                })?;
            self.put_cached(cid, &dl.bytes, &dl.sha256);
            return Ok((dl.bytes, dl.sha256, dl.verified));
        }

        // 3. Basecamp `storage_module` backend (downloadToUrl -> private temp file -> site_blob_ready)
        if backend == "basecamp" {
            let (waiter, is_initiator) = {
                let mut map = self.in_flight.lock().unwrap();
                if let Some(existing) = map.get(cid) {
                    (Arc::clone(existing), false)
                } else {
                    let tmp_path = self.next_tmp_path(cid);
                    let created = Arc::new(InFlightBlob {
                        tmp_path,
                        result: Mutex::new(None),
                        cvar: Condvar::new(),
                    });
                    map.insert(cid.to_owned(), Arc::clone(&created));
                    (created, true)
                }
            };

            if is_initiator {
                if let Err(e) = (self.basecamp_downloader)(cid, &waiter.tmp_path) {
                    let _ = fs::remove_file(&waiter.tmp_path);
                    let mut slot = waiter.result.lock().unwrap();
                    if slot.is_none() {
                        *slot = Some(BlobReadySignal {
                            ok: false,
                            tmp_path: waiter.tmp_path.clone(),
                            err: e,
                        });
                        waiter.cvar.notify_all();
                    }
                    let mut map = self.in_flight.lock().unwrap();
                    map.remove(cid);
                }
            }

            let deadline = Instant::now() + Duration::from_secs(BASECAMP_BLOB_TIMEOUT_SECS);
            let signal = {
                let mut slot = waiter.result.lock().unwrap();
                while slot.is_none() {
                    let rem = deadline.saturating_duration_since(Instant::now());
                    if rem.is_zero() {
                        break;
                    }
                    let (guard, timeout_res) = waiter.cvar.wait_timeout(slot, rem).unwrap();
                    slot = guard;
                    if timeout_res.timed_out() {
                        break;
                    }
                }
                slot.clone()
            };

            if is_initiator {
                let mut map = self.in_flight.lock().unwrap();
                map.remove(cid);
            }

            let Some(sig) = signal else {
                let _ = fs::remove_file(&waiter.tmp_path);
                return Err(FetchFailure::Storage(format!(
                    "Timed out waiting for Basecamp Storage module to fetch CID {cid}"
                )));
            };

            if !sig.ok {
                let _ = fs::remove_file(&sig.tmp_path);
                let msg = if sig.err.trim().is_empty() {
                    format!("Basecamp Storage module failed to fetch CID {cid}")
                } else {
                    sig.err
                };
                return Err(FetchFailure::Storage(msg));
            }

            let bytes = match read_capped_file(&sig.tmp_path, MAX_DOWNLOAD_BYTES) {
                Ok(b) => b,
                Err(e) => {
                    let _ = fs::remove_file(&sig.tmp_path);
                    return Err(FetchFailure::Storage(e));
                }
            };
            let _ = fs::remove_file(&sig.tmp_path);

            if let Some(exp_sz) = expected_size {
                if bytes.len() != exp_sz {
                    return Err(FetchFailure::Tampered(format!(
                        "integrity mismatch for {cid}: expected {exp_sz} bytes, got {}",
                        bytes.len()
                    )));
                }
            }

            let actual = sha256_hex(&bytes);
            let mut verified = false;
            if let Some(exp) = expected_sha256.filter(|s| !s.is_empty()) {
                let exp_lower = exp.to_ascii_lowercase();
                if actual != exp_lower {
                    return Err(FetchFailure::Tampered(format!(
                        "SHA-256 mismatch for {cid}: expected {exp_lower}, got {actual}"
                    )));
                }
                verified = true;
            }
            self.put_cached(cid, &bytes, &actual);
            return Ok((bytes, actual, verified));
        }

        Err(FetchFailure::Storage(format!(
            "No storage backend configured to fetch CID {cid}"
        )))
    }

    pub fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.cache_dir);
    }
}

#[derive(Debug, Clone)]
pub enum FetchFailure {
    Storage(String),
    Tampered(String),
}

impl FetchFailure {
    pub fn message(&self) -> &str {
        match self {
            FetchFailure::Storage(s) | FetchFailure::Tampered(s) => s,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            FetchFailure::Storage(_) => "storage_error",
            FetchFailure::Tampered(_) => "tampered",
        }
    }
}

struct SiteRuntime {
    port: u16,
    token: String,
    spec: SiteSpec,
    shutdown: AtomicBool,
    active_conns: AtomicUsize,
    state: Mutex<SiteState>,
    blob_cache: Arc<VerifiedBlobCache>,
}

struct SiteServerHandle {
    runtime: Arc<SiteRuntime>,
    reuse_key: (String, String, String, String, String, String, String),
}

impl SiteServerHandle {
    fn shutdown(&self) {
        self.runtime.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept() loop on 127.0.0.1:<port>
        let addr = SocketAddr::from(([127, 0, 0, 1], self.runtime.port));
        let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
    }
}

pub struct SiteServerManager {
    blob_cache: Arc<VerifiedBlobCache>,
    sites: HashMap<String, SiteServerHandle>, // keyed by token
}

impl SiteServerManager {
    pub fn new(basecamp_downloader: BasecampDownloader) -> Self {
        let dir = default_private_cache_dir();
        Self::with_cache_dir(dir, basecamp_downloader)
    }

    pub fn with_cache_dir(cache_dir: PathBuf, basecamp_downloader: BasecampDownloader) -> Self {
        Self {
            blob_cache: Arc::new(VerifiedBlobCache::new(cache_dir, basecamp_downloader)),
            sites: HashMap::new(),
        }
    }

    pub fn site_open(&mut self, spec: SiteSpec) -> Result<Value, String> {
        let norm_initial = normalize_links_path(if spec.initial_path.trim().is_empty() {
            "/"
        } else {
            spec.initial_path.trim()
        })?;
        let reuse_key = spec.reuse_key();

        // Reuse an existing active listener for the exact same site (except on-chain HTML which may update)
        if spec.mode != "onchain-page" && spec.mode != "onchain-links" {
            if let Some(existing) = self.sites.values().find(|h| h.reuse_key == reuse_key) {
                let mut st = existing.runtime.state.lock().unwrap();
                st.last_used = Instant::now();
                let origin = format!("http://127.0.0.1:{}", existing.runtime.port);
                let base_url = format!("{origin}/{}", existing.runtime.token);
                let entry_url = format!("{base_url}{}", norm_initial.path);
                return Ok(json!({
                    "origin": origin,
                    "port": existing.runtime.port,
                    "token": existing.runtime.token,
                    "base_url": base_url,
                    "entry_url": entry_url,
                    "site_base": existing.runtime.spec.site_base,
                    "root_cid": existing.runtime.spec.root_cid,
                    "root_sha256": st.root_sha256,
                    "mode": st.resolved_mode,
                    "csp": STRICT_CSP,
                    "reused": true,
                }));
            }
        }

        // Evict LRU site if we hit MAX_ACTIVE_SITES
        while self.sites.len() >= MAX_ACTIVE_SITES {
            let oldest = self
                .sites
                .iter()
                .min_by_key(|(_, h)| h.runtime.state.lock().unwrap().last_used)
                .map(|(k, _)| k.clone());
            if let Some(tok) = oldest {
                if let Some(old) = self.sites.remove(&tok) {
                    old.shutdown();
                }
            } else {
                break;
            }
        }

        // Pre-validate on-chain roots immediately so errors surface early
        let (initial_root, initial_sha, initial_verified, initial_mode) = match spec.mode.as_str() {
            "onchain-page" => {
                let html = spec.onchain_html.clone().unwrap_or_default();
                let bytes = html.into_bytes();
                let sha = sha256_hex(&bytes);
                (
                    RootSource::OnChainHtml {
                        bytes,
                        sha256: sha.clone(),
                    },
                    sha,
                    true,
                    "onchain-page".to_owned(),
                )
            }
            "onchain-links" => {
                let raw = spec.onchain_links.clone().unwrap_or_default();
                let parsed = parse_links_list(&raw)?;
                let sha = sha256_hex(raw.as_bytes());
                (
                    RootSource::Links {
                        root_list: parsed,
                        root_verified: true,
                    },
                    sha,
                    true,
                    "links".to_owned(),
                )
            }
            _ => {
                if !is_valid_cid(&spec.root_cid) {
                    return Err(format!("invalid root_cid `{}`", spec.root_cid));
                }
                if !spec.root_sha256.is_empty() && !is_valid_sha256(&spec.root_sha256) {
                    return Err(format!("invalid root_sha256 `{}`", spec.root_sha256));
                }
                (
                    RootSource::Unloaded,
                    spec.root_sha256.to_ascii_lowercase(),
                    !spec.root_sha256.is_empty(),
                    if spec.site_type.is_empty() {
                        "cid".to_owned()
                    } else {
                        spec.site_type.clone()
                    },
                )
            }
        };

        // Bind strictly 127.0.0.1:0 (loopback only, ephemeral port)
        let listener = TcpListener::bind("127.0.0.1:0")
            .map_err(|e| format!("Failed to bind loopback HTTP server: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("Failed to read loopback port: {e}"))?
            .port();

        let token = generate_random_token_128();
        let initial_folder_files = match &initial_root {
            RootSource::Links { root_list, .. } => folder_entries_json("/", &root_list.entries),
            _ => Vec::new(),
        };

        let mut known_cid_sha256 = HashMap::new();
        let mut allowed_cids = HashSet::new();
        if let RootSource::Links { ref root_list, .. } = initial_root {
            for e in &root_list.entries {
                allowed_cids.insert(e.cid.clone());
                if let Some(ref s) = e.sha256 {
                    known_cid_sha256.insert(e.cid.clone(), s.clone());
                }
            }
        }

        let runtime = Arc::new(SiteRuntime {
            port,
            token: token.clone(),
            spec: spec.clone(),
            shutdown: AtomicBool::new(false),
            active_conns: AtomicUsize::new(0),
            state: Mutex::new(SiteState {
                root: initial_root,
                folder_cache: HashMap::new(),
                allowed_cids,
                known_cid_sha256,
                verified_files: BTreeMap::new(),
                folder_files: initial_folder_files,
                current_path: norm_initial.path.clone(),
                resolved_mode: initial_mode.clone(),
                root_sha256: initial_sha.clone(),
                root_verified: initial_verified,
                title: spec.title.clone(),
                last_error: None,
                events: VecDeque::new(),
                last_used: Instant::now(),
            }),
            blob_cache: Arc::clone(&self.blob_cache),
        });

        let accept_rt = Arc::clone(&runtime);
        thread::Builder::new()
            .name(format!("lns-http-{port}"))
            .spawn(move || accept_loop(listener, accept_rt))
            .map_err(|e| format!("Failed to spawn loopback server thread: {e}"))?;

        self.sites.insert(
            token.clone(),
            SiteServerHandle {
                runtime,
                reuse_key,
            },
        );

        let origin = format!("http://127.0.0.1:{port}");
        let base_url = format!("{origin}/{token}");
        let entry_url = format!("{base_url}{}", norm_initial.path);
        Ok(json!({
            "origin": origin,
            "port": port,
            "token": token,
            "base_url": base_url,
            "entry_url": entry_url,
            "site_base": spec.site_base,
            "root_cid": spec.root_cid,
            "root_sha256": initial_sha,
            "mode": initial_mode,
            "csp": STRICT_CSP,
            "reused": false,
        }))
    }

    pub fn site_close(&mut self, token: &str) -> bool {
        if let Some(handle) = self.sites.remove(token.trim()) {
            handle.shutdown();
            true
        } else {
            false
        }
    }

    pub fn site_close_all(&mut self) -> usize {
        let count = self.sites.len();
        for (_, handle) in self.sites.drain() {
            handle.shutdown();
        }
        count
    }

    pub fn site_blob_ready(&self, cid: &str, tmp_path: &str, ok: bool, err: &str) -> bool {
        self.blob_cache.notify_blob_ready(cid, tmp_path, ok, err)
    }

    pub fn site_stats(&self, token: &str) -> Result<Value, String> {
        let handle = self
            .sites
            .get(token.trim())
            .ok_or_else(|| "Unknown or closed site token".to_owned())?;
        Ok(build_stats_json(&handle.runtime))
    }

    pub fn site_poll_events(&self, token: &str) -> Result<Value, String> {
        let handle = self
            .sites
            .get(token.trim())
            .ok_or_else(|| "Unknown or closed site token".to_owned())?;
        let events: Vec<Value> = {
            let mut st = handle.runtime.state.lock().unwrap();
            st.last_used = Instant::now();
            st.events.drain(..).collect()
        };
        Ok(json!({
            "events": events,
            "stats": build_stats_json(&handle.runtime),
        }))
    }

    /// Resolves a download target (`cid`, `expected_sha256`, `filename`, `backend`, `storage_api`)
    /// from an active site's verified tree so downloads cannot spoof CIDs or skip SHA-256.
    pub fn resolve_site_download(
        &self,
        token: &str,
        cid: &str,
        rel_path: &str,
        filename: &str,
    ) -> Result<(String, String, String, String, String), String> {
        let handle = self
            .sites
            .get(token.trim())
            .ok_or_else(|| "Unknown or closed site token".to_owned())?;
        let rt = &handle.runtime;
        let clean_cid = cid.trim().to_owned();
        let clean_path = rel_path.trim().to_owned();

        // If rel_path is provided, resolve it through the site's root tree
        if !clean_path.is_empty() {
            ensure_root_loaded(rt).map_err(|e| e.message().to_owned())?;
            let (resolved_cid, resolved_sha, resolved_name) =
                resolve_download_from_path(rt, &clean_path)?;
            let final_name = if filename.trim().is_empty() {
                resolved_name
            } else {
                filename.trim().to_owned()
            };
            return Ok((
                resolved_cid,
                resolved_sha,
                final_name,
                rt.spec.backend.clone(),
                rt.spec.storage_api.clone(),
            ));
        }

        if !is_valid_cid(&clean_cid) {
            return Err(format!("Invalid download CID `{clean_cid}`"));
        }
        let expected_sha = {
            let st = rt.state.lock().unwrap();
            if !st.allowed_cids.contains(&clean_cid) && rt.spec.root_cid != clean_cid {
                return Err(format!(
                    "CID `{clean_cid}` is not listed or referenced by this site"
                ));
            }
            st.known_cid_sha256
                .get(&clean_cid)
                .cloned()
                .unwrap_or_default()
        };
        let final_name = if filename.trim().is_empty() {
            format!("{}.bin", &clean_cid[..clean_cid.len().min(12)])
        } else {
            filename.trim().to_owned()
        };
        Ok((
            clean_cid,
            expected_sha,
            final_name,
            rt.spec.backend.clone(),
            rt.spec.storage_api.clone(),
        ))
    }

    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.sites.len()
    }
}

impl Drop for SiteServerManager {
    fn drop(&mut self) {
        self.site_close_all();
        self.blob_cache.cleanup();
    }
}

fn build_stats_json(rt: &SiteRuntime) -> Value {
    let st = rt.state.lock().unwrap();
    let files: Vec<Value> = st
        .verified_files
        .values()
        .map(|f| {
            json!({
                "path": f.path,
                "cid": f.cid,
                "sha256": f.sha256,
                "size": f.size,
                "content_type": f.content_type,
                "verified": f.verified,
            })
        })
        .collect();
    let all_verified = st.root_verified
        && (files.is_empty() || files.iter().all(|f| f["verified"].as_bool() == Some(true)));
    let last_err = st.last_error.as_ref().map(|e| {
        json!({
            "kind": e.kind,
            "cid": e.cid,
            "path": e.path,
            "message": e.message,
        })
    });
    json!({
        "token": rt.token,
        "origin": format!("http://127.0.0.1:{}", rt.port),
        "port": rt.port,
        "site_base": rt.spec.site_base,
        "host": rt.spec.host,
        "kind": rt.spec.kind,
        "mode": st.resolved_mode,
        "root_cid": rt.spec.root_cid,
        "root_sha256": st.root_sha256,
        "root_verified": st.root_verified,
        "verified": all_verified,
        "csp": STRICT_CSP,
        "title": st.title,
        "current_path": st.current_path,
        "verified_files": files,
        "folder_files": st.folder_files,
        "last_error": last_err,
    })
}

fn push_event(rt: &SiteRuntime, event: Value) {
    let mut st = rt.state.lock().unwrap();
    if st.events.len() >= MAX_SITE_EVENTS {
        st.events.pop_front();
    }
    st.events.push_back(event);
}

fn accept_loop(listener: TcpListener, rt: Arc<SiteRuntime>) {
    for stream in listener.incoming() {
        if rt.shutdown.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else {
            continue;
        };
        if rt.active_conns.load(Ordering::Relaxed) >= MAX_CONNS_PER_SITE {
            let mut s = stream;
            let _ = write_http_response(
                &mut s,
                "503 Service Unavailable",
                "text/plain; charset=utf-8",
                b"Too many concurrent connections",
                false,
                &[],
            );
            continue;
        }
        rt.active_conns.fetch_add(1, Ordering::Relaxed);
        let conn_rt = Arc::clone(&rt);
        let _ = thread::Builder::new()
            .name(format!("lns-req-{}", rt.port))
            .spawn(move || {
                handle_connection(stream, &conn_rt);
                conn_rt.active_conns.fetch_sub(1, Ordering::Relaxed);
            });
    }
}

struct ParsedHttpRequest {
    method: String,
    target: String,
    host_headers: Vec<String>,
}

fn parse_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, &'static str> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    let header_end = loop {
        match stream.read(&mut tmp) {
            Ok(0) => return Err("empty request"),
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                if buf.len() > MAX_REQ_HEADER_BYTES {
                    return Err("headers too large");
                }
            }
            Err(_) => return Err("read error"),
        }
    };

    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| "non-utf8 headers")?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let mut parts = req_line.split(' ');
    let method = parts.next().ok_or("missing method")?.to_owned();
    let target = parts.next().ok_or("missing target")?.to_owned();
    let version = parts.next().ok_or("missing version")?;
    if parts.next().is_some() || (!version.starts_with("HTTP/1.")) {
        return Err("invalid request line");
    }

    let mut host_headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            // Deliberately ignore `Cookie` headers
            if k.trim().eq_ignore_ascii_case("host") {
                host_headers.push(v.trim().to_owned());
            }
        }
    }

    Ok(ParsedHttpRequest {
        method,
        target,
        host_headers,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn handle_connection(mut stream: TcpStream, rt: &SiteRuntime) {
    let req = match parse_http_request(&mut stream) {
        Ok(r) => r,
        Err(_) => {
            let _ = write_http_response(
                &mut stream,
                "400 Bad Request",
                "text/plain; charset=utf-8",
                b"Bad Request",
                false,
                &[],
            );
            return;
        }
    };

    // 1. Strict Host header check (anti-DNS-rebinding): must be exactly one `127.0.0.1:<port>`
    let expected_host = format!("127.0.0.1:{}", rt.port);
    if req.host_headers.len() != 1 || req.host_headers[0] != expected_host {
        let _ = write_http_response(
            &mut stream,
            "403 Forbidden",
            "text/plain; charset=utf-8",
            b"Forbidden: invalid Host header",
            req.method == "HEAD",
            &[],
        );
        return;
    }

    // 2. Method guard: GET and HEAD only
    let is_head = match req.method.as_str() {
        "GET" => false,
        "HEAD" => true,
        _ => {
            let _ = write_http_response(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                b"Method Not Allowed",
                false,
                &[("Allow", "GET, HEAD")],
            );
            return;
        }
    };

    // 3. Split path and query, validate raw target characters
    let (raw_path, raw_query) = match req.target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (req.target.as_str(), ""),
    };

    if !raw_path.starts_with('/') {
        let _ = write_http_response(
            &mut stream,
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"Bad Request: invalid path",
            is_head,
            &[],
        );
        return;
    }

    // 4. Token prefix check (constant-time)
    let after_first_slash = &raw_path[1..];
    let (req_token, rest_path) = match after_first_slash.find('/') {
        Some(idx) => (&after_first_slash[..idx], &after_first_slash[idx..]),
        None => (after_first_slash, ""),
    };

    if !constant_time_eq(req_token.as_bytes(), rt.token.as_bytes()) {
        let _ = write_http_response(
            &mut stream,
            "403 Forbidden",
            "text/plain; charset=utf-8",
            b"Forbidden: invalid session token",
            is_head,
            &[],
        );
        return;
    }

    // Redirect `/<token>` (no trailing slash) -> `/<token>/` so relative URLs resolve properly
    if rest_path.is_empty() {
        let loc = format!("/{}/", rt.token);
        let _ = write_http_response(
            &mut stream,
            "301 Moved Permanently",
            "text/plain; charset=utf-8",
            b"Moved Permanently",
            is_head,
            &[("Location", &loc)],
        );
        return;
    }

    // 5. Strict path traversal refusal BEFORE any normalization
    if has_path_traversal_or_illegal_chars(rest_path) {
        let _ = write_http_response(
            &mut stream,
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"Bad Request: path traversal refused",
            is_head,
            &[],
        );
        return;
    }

    {
        let mut st = rt.state.lock().unwrap();
        st.last_used = Instant::now();
    }

    // 6. Special browser-owned endpoints: /_ext, /_lns, /_dl, /_cid/<cid>
    if rest_path == "/_ext" {
        handle_ext_endpoint(&mut stream, rt, raw_query, is_head);
        return;
    }
    if rest_path == "/_lns" {
        handle_lns_endpoint(&mut stream, rt, raw_query, is_head);
        return;
    }
    if rest_path == "/_dl" {
        handle_dl_endpoint(&mut stream, rt, raw_query, is_head);
        return;
    }
    if let Some(cid_raw) = rest_path.strip_prefix("/_cid/") {
        handle_cid_endpoint(&mut stream, rt, cid_raw, is_head);
        return;
    }

    // 7. Serve verified site file for `rest_path`
    serve_site_path(&mut stream, rt, rest_path, is_head);
}

fn has_path_traversal_or_illegal_chars(raw_path: &str) -> bool {
    if raw_path.is_empty() || !raw_path.starts_with('/') {
        return true;
    }
    // Reject control characters, NUL, and raw backslashes
    if raw_path
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b == b'\\')
    {
        return true;
    }
    let lower = raw_path.to_ascii_lowercase();
    // Reject encoded NUL, slash, backslash
    if lower.contains("%00") || lower.contains("%2f") || lower.contains("%5c") {
        return true;
    }
    for raw_seg in raw_path.split('/') {
        if raw_seg == ".." {
            return true;
        }
        let Some(decoded) = percent_decode(raw_seg, false) else {
            return true;
        };
        if decoded == ".."
            || decoded.contains('/')
            || decoded.contains('\\')
            || decoded.chars().any(|c| c.is_control())
        {
            return true;
        }
    }
    false
}

fn handle_ext_endpoint(stream: &mut TcpStream, rt: &SiteRuntime, raw_query: &str, is_head: bool) {
    let params = parse_query(raw_query);
    if let Some(u) = params.get("u") {
        if crate::is_safe_external_https_url(u) {
            push_event(
                rt,
                json!({
                    "kind": "ext",
                    "url": u,
                }),
            );
        }
    }
    let _ = write_http_response(stream, "204 No Content", "text/plain; charset=utf-8", b"", is_head, &[]);
}

fn handle_lns_endpoint(stream: &mut TcpStream, rt: &SiteRuntime, raw_query: &str, is_head: bool) {
    let params = parse_query(raw_query);
    if let Some(u) = params.get("u") {
        if let Ok(parsed) = parse_url(u) {
            let full = match parsed.fragment {
                Some(ref f) => format!("{}{f}", parsed.canonical),
                None => parsed.canonical,
            };
            push_event(
                rt,
                json!({
                    "kind": "lns",
                    "url": full,
                }),
            );
        }
    }
    let _ = write_http_response(stream, "204 No Content", "text/plain; charset=utf-8", b"", is_head, &[]);
}

fn handle_dl_endpoint(stream: &mut TcpStream, rt: &SiteRuntime, raw_query: &str, is_head: bool) {
    let params = parse_query(raw_query);
    let raw_cid = params.get("cid").map(String::as_str).unwrap_or("");
    let raw_path = params.get("path").map(String::as_str).unwrap_or("");
    let raw_name = params.get("name").map(String::as_str).unwrap_or("");

    let mut cid = raw_cid.trim().to_owned();
    let mut sha256 = String::new();
    let mut name = raw_name.trim().to_owned();
    let path = raw_path.trim().to_owned();

    if !path.is_empty() && !has_path_traversal_or_illegal_chars(&path) {
        if let Ok((r_cid, r_sha, r_name)) = resolve_download_from_path(rt, &path) {
            cid = r_cid;
            sha256 = r_sha;
            if name.is_empty() {
                name = r_name;
            }
        }
    } else if !cid.is_empty() && is_valid_cid(&cid) {
        let st = rt.state.lock().unwrap();
        if st.allowed_cids.contains(&cid) {
            sha256 = st.known_cid_sha256.get(&cid).cloned().unwrap_or_default();
        } else {
            cid.clear();
        }
    }

    if !cid.is_empty() || !path.is_empty() {
        push_event(
            rt,
            json!({
                "kind": "dl",
                "cid": cid,
                "path": path,
                "sha256": sha256,
                "filename": name,
            }),
        );
    }
    let _ = write_http_response(stream, "204 No Content", "text/plain; charset=utf-8", b"", is_head, &[]);
}

fn handle_cid_endpoint(stream: &mut TcpStream, rt: &SiteRuntime, cid_raw: &str, is_head: bool) {
    let cid = cid_raw.trim();
    if cid.contains('/') || !is_valid_cid(cid) {
        let _ = write_http_response(
            stream,
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"Bad Request: invalid CID",
            is_head,
            &[],
        );
        return;
    }

    let (allowed, expected_sha) = {
        let st = rt.state.lock().unwrap();
        (
            st.allowed_cids.contains(cid),
            st.known_cid_sha256.get(cid).cloned(),
        )
    };
    if !allowed {
        let _ = write_http_response(
            stream,
            "403 Forbidden",
            "text/plain; charset=utf-8",
            b"Forbidden: CID not allowlisted for this site",
            is_head,
            &[],
        );
        return;
    }

    match rt.blob_cache.fetch_verified(
        cid,
        expected_sha.as_deref(),
        None,
        &rt.spec.backend,
        &rt.spec.storage_api,
    ) {
        Ok((bytes, actual_sha, verified)) => {
            let ct = sniff_asset_mime(&bytes, "application/octet-stream");
            let ct = neutralize_active_xml_mime(&ct, "");
            {
                let mut st = rt.state.lock().unwrap();
                st.verified_files.insert(
                    format!("/_cid/{cid}"),
                    VerifiedFileInfo {
                        path: format!("/_cid/{cid}"),
                        cid: cid.to_owned(),
                        sha256: actual_sha,
                        size: bytes.len(),
                        content_type: ct.clone(),
                        verified,
                    },
                );
            }
            let _ = write_http_response(stream, "200 OK", &ct, &bytes, is_head, &[]);
        }
        Err(fail) => {
            record_site_error(rt, fail.kind(), cid, &format!("/_cid/{cid}"), fail.message());
            let page = build_error_page_html(
                fail.kind(),
                &rt.spec.site_base,
                &format!("/_cid/{cid}"),
                cid,
                fail.message(),
                &rt.token,
            );
            let _ = write_http_response(
                stream,
                "502 Bad Gateway",
                "text/html; charset=utf-8",
                page.as_bytes(),
                is_head,
                &[],
            );
        }
    }
}

fn ensure_root_loaded(rt: &SiteRuntime) -> Result<(), FetchFailure> {
    {
        let st = rt.state.lock().unwrap();
        if !matches!(st.root, RootSource::Unloaded) {
            return Ok(());
        }
    }

    let expected_sha = if rt.spec.root_sha256.is_empty() {
        None
    } else {
        Some(rt.spec.root_sha256.as_str())
    };
    let (bytes, actual_sha, verified) = rt.blob_cache.fetch_verified(
        &rt.spec.root_cid,
        expected_sha,
        None,
        &rt.spec.backend,
        &rt.spec.storage_api,
    )?;

    // 1. Check `lns-links/1`
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if rt.spec.site_type == "links" || is_links_list_text(text) {
            let root_list = parse_links_list(text)
                .map_err(|e| FetchFailure::Storage(format!("Invalid lns-links/1 root list: {e}")))?;
            let folder_files = folder_entries_json("/", &root_list.entries);
            let mut st = rt.state.lock().unwrap();
            for e in &root_list.entries {
                st.allowed_cids.insert(e.cid.clone());
                if let Some(ref s) = e.sha256 {
                    st.known_cid_sha256.insert(e.cid.clone(), s.clone());
                }
            }
            if st.title.is_none() {
                st.title = root_list.title.clone();
            }
            st.folder_files = folder_files;
            st.root_sha256 = actual_sha;
            st.root_verified = verified;
            st.resolved_mode = "links".to_owned();
            st.root = RootSource::Links {
                root_list,
                root_verified: verified,
            };
            return Ok(());
        }
    }

    // 2. Check v1 JSON manifest
    if let Ok(Some(manifest)) = try_parse_manifest(&bytes) {
        let folder_files: Vec<Value> = manifest
            .files
            .iter()
            .map(|(p, entry)| {
                json!({
                    "path": p,
                    "name": p.rsplit('/').next().unwrap_or(p),
                    "kind": "file",
                    "cid": entry.cid,
                    "sha256": entry.sha256,
                })
            })
            .collect();
        let mut st = rt.state.lock().unwrap();
        for entry in manifest.files.values() {
            st.allowed_cids.insert(entry.cid.clone());
            if let Some(ref s) = entry.sha256 {
                st.known_cid_sha256.insert(entry.cid.clone(), s.clone());
            }
        }
        if st.title.is_none() {
            st.title = manifest.title.clone();
        }
        st.folder_files = folder_files;
        st.root_sha256 = actual_sha;
        st.root_verified = verified;
        st.resolved_mode = "manifest".to_owned();
        st.root = RootSource::Manifest {
            manifest,
            root_verified: verified,
        };
        return Ok(());
    }

    // 3. Single-file CID
    let ct = sniff_asset_mime(&bytes, &sniff_content_type(&bytes, "text/html; charset=utf-8"));
    let mut st = rt.state.lock().unwrap();
    st.root_sha256 = actual_sha.clone();
    st.root_verified = verified;
    st.resolved_mode = "single".to_owned();
    st.root = RootSource::SingleCid {
        bytes,
        content_type: ct,
        sha256: actual_sha,
        verified,
    };
    Ok(())
}

fn resolve_download_from_path(
    rt: &SiteRuntime,
    raw_path: &str,
) -> Result<(String, String, String), String> {
    let root = {
        let st = rt.state.lock().unwrap();
        st.root.clone()
    };
    match root {
        RootSource::Links { root_list, .. } => {
            let mut local_cache = {
                let st = rt.state.lock().unwrap();
                st.folder_cache.clone()
            };
            let outcome = resolve_links_tree(&root_list, raw_path, &mut local_cache, |dir_cid, dir_sha| {
                let (bytes, actual_sha, _) = rt
                    .blob_cache
                    .fetch_verified(dir_cid, dir_sha, None, &rt.spec.backend, &rt.spec.storage_api)
                    .map_err(|e| e.message().to_owned())?;
                let txt = String::from_utf8(bytes)
                    .map_err(|e| format!("Invalid UTF-8 in subfolder {dir_cid}: {e}"))?;
                let list = parse_links_list(&txt)?;
                Ok(CachedLinksList {
                    list,
                    sha256: Some(actual_sha),
                })
            })?;
            {
                let mut st = rt.state.lock().unwrap();
                st.folder_cache.extend(local_cache);
            }
            match outcome {
                ResolveOutcome::Found(f) => Ok((
                    f.entry.cid,
                    f.entry.sha256.unwrap_or_default(),
                    f.entry.name,
                )),
                ResolveOutcome::NotFound { .. } => {
                    Err(format!("Download path `{raw_path}` not found on this site"))
                }
            }
        }
        RootSource::Manifest { manifest, .. } => {
            let Some((resolved_path, entry)) = manifest.resolve(raw_path) else {
                return Err(format!("Download path `{raw_path}` not found in manifest"));
            };
            let name = resolved_path.rsplit('/').next().unwrap_or("download.bin").to_owned();
            Ok((
                entry.cid.clone(),
                entry.sha256.clone().unwrap_or_default(),
                name,
            ))
        }
        _ => Err("Current site does not support path-based downloads".to_owned()),
    }
}

fn serve_site_path(stream: &mut TcpStream, rt: &SiteRuntime, rest_path: &str, is_head: bool) {
    let Some(decoded_path) = percent_decode(rest_path, false) else {
        let _ = write_http_response(
            stream,
            "400 Bad Request",
            "text/plain; charset=utf-8",
            b"Bad Request: invalid percent-encoding",
            is_head,
            &[],
        );
        return;
    };

    if let Err(fail) = ensure_root_loaded(rt) {
        record_site_error(rt, fail.kind(), &rt.spec.root_cid, &decoded_path, fail.message());
        let page = build_error_page_html(
            fail.kind(),
            &rt.spec.site_base,
            &decoded_path,
            &rt.spec.root_cid,
            fail.message(),
            &rt.token,
        );
        let _ = write_http_response(
            stream,
            "502 Bad Gateway",
            "text/html; charset=utf-8",
            page.as_bytes(),
            is_head,
            &[],
        );
        return;
    }

    let root = {
        let st = rt.state.lock().unwrap();
        st.root.clone()
    };

    match root {
        RootSource::OnChainHtml { bytes, sha256 } => {
            if decoded_path != "/" && decoded_path != "/index.html" {
                send_not_found(stream, rt, &decoded_path, true, is_head);
                return;
            }
            serve_verified_body(
                stream,
                rt,
                "/",
                "",
                &sha256,
                true,
                "text/html; charset=utf-8",
                &bytes,
                is_head,
            );
        }

        RootSource::SingleCid {
            bytes,
            content_type,
            sha256,
            verified,
        } => {
            if decoded_path != "/" && decoded_path != "/index.html" {
                send_not_found(stream, rt, &decoded_path, true, is_head);
                return;
            }
            serve_verified_body(
                stream,
                rt,
                "/",
                &rt.spec.root_cid,
                &sha256,
                verified,
                &content_type,
                &bytes,
                is_head,
            );
        }

        RootSource::Links {
            root_list,
            root_verified,
            ..
        } => {
            let mut local_cache = {
                let st = rt.state.lock().unwrap();
                st.folder_cache.clone()
            };
            let mut fetch_err: Option<FetchFailure> = None;
            let outcome = resolve_links_tree(
                &root_list,
                &decoded_path,
                &mut local_cache,
                |dir_cid, dir_sha| match rt.blob_cache.fetch_verified(
                    dir_cid,
                    dir_sha,
                    None,
                    &rt.spec.backend,
                    &rt.spec.storage_api,
                ) {
                    Ok((bytes, actual_sha, _)) => {
                        let txt = String::from_utf8(bytes)
                            .map_err(|e| format!("Invalid UTF-8 in subfolder {dir_cid}: {e}"))?;
                        let list = parse_links_list(&txt)?;
                        Ok(CachedLinksList {
                            list,
                            sha256: Some(actual_sha),
                        })
                    }
                    Err(f) => {
                        let msg = f.message().to_owned();
                        fetch_err = Some(f);
                        Err(msg)
                    }
                },
            );
            {
                let mut st = rt.state.lock().unwrap();
                for (cid, cached) in &local_cache {
                    for e in &cached.list.entries {
                        st.allowed_cids.insert(e.cid.clone());
                        if let Some(ref s) = e.sha256 {
                            st.known_cid_sha256.insert(e.cid.clone(), s.clone());
                        }
                    }
                    st.folder_cache.insert(cid.clone(), cached.clone());
                }
            }

            let outcome = match outcome {
                Ok(o) => o,
                Err(e) => {
                    let fail = fetch_err.unwrap_or_else(|| {
                        if e.contains("SHA-256 mismatch") {
                            FetchFailure::Tampered(e)
                        } else {
                            FetchFailure::Storage(e)
                        }
                    });
                    record_site_error(rt, fail.kind(), &rt.spec.root_cid, &decoded_path, fail.message());
                    let page = build_error_page_html(
                        fail.kind(),
                        &rt.spec.site_base,
                        &decoded_path,
                        &rt.spec.root_cid,
                        fail.message(),
                        &rt.token,
                    );
                    let _ = write_http_response(
                        stream,
                        "502 Bad Gateway",
                        "text/html; charset=utf-8",
                        page.as_bytes(),
                        is_head,
                        &[],
                    );
                    return;
                }
            };

            match outcome {
                ResolveOutcome::NotFound {
                    requested_path,
                    canonical_url_path,
                    folder_entries,
                    ..
                } => {
                    if !folder_entries.is_empty() {
                        let dir_prefix = canonical_url_path.as_deref().unwrap_or("/");
                        let mut st = rt.state.lock().unwrap();
                        st.folder_files = folder_entries_json(dir_prefix, &folder_entries);
                    }
                    send_not_found(stream, rt, &requested_path, false, is_head);
                }
                ResolveOutcome::Found(resolved) => {
                    // Canonicalize folder paths without trailing slash (e.g. `/browser` -> `/<token>/browser/`)
                    if resolved.canonical_url_path.ends_with('/')
                        && !decoded_path.ends_with('/')
                    {
                        let loc = format!("/{}{}", rt.token, resolved.canonical_url_path);
                        let _ = write_http_response(
                            stream,
                            "301 Moved Permanently",
                            "text/plain; charset=utf-8",
                            b"Moved Permanently",
                            is_head,
                            &[("Location", &loc)],
                        );
                        return;
                    }

                    // Update folder file list & allowlist
                    {
                        let mut st = rt.state.lock().unwrap();
                        for e in &resolved.folder_entries {
                            st.allowed_cids.insert(e.cid.clone());
                            if let Some(ref s) = e.sha256 {
                                st.known_cid_sha256.insert(e.cid.clone(), s.clone());
                            }
                        }
                        if is_html_or_doc_path(&resolved.resolved_path) {
                            st.folder_files = folder_entries_json(
                                &resolved.canonical_dir,
                                &resolved.folder_entries,
                            );
                            if let Some(ref t) = resolved.folder_title {
                                st.title = Some(t.clone());
                            }
                        }
                    }

                    // If user navigated directly to a downloadable archive/installer (not `.wasm`),
                    // serve a download handoff page and emit a `dl` event rather than buffering a huge binary into WebKit.
                    if is_direct_download_handoff_path(&resolved.resolved_path) {
                        let dl_sha = resolved.entry.sha256.clone().unwrap_or_default();
                        push_event(
                            rt,
                            json!({
                                "kind": "dl",
                                "cid": resolved.entry.cid,
                                "path": resolved.resolved_path,
                                "sha256": dl_sha,
                                "filename": resolved.entry.name,
                            }),
                        );
                        let page = build_download_page_html(
                            &rt.token,
                            &rt.spec.site_base,
                            &resolved.resolved_path,
                            &resolved.entry.name,
                            &resolved.entry.cid,
                            &dl_sha,
                        );
                        let _ = write_http_response(
                            stream,
                            "200 OK",
                            "text/html; charset=utf-8",
                            page.as_bytes(),
                            is_head,
                            &[],
                        );
                        return;
                    }

                    match rt.blob_cache.fetch_verified(
                        &resolved.entry.cid,
                        resolved.entry.sha256.as_deref(),
                        None,
                        &rt.spec.backend,
                        &rt.spec.storage_api,
                    ) {
                        Ok((bytes, actual_sha, file_verified)) => {
                            let full_verified =
                                root_verified && resolved.folders_verified && file_verified;
                            let ct = mime_for_server_path(&resolved.resolved_path, &bytes);
                            serve_verified_body(
                                stream,
                                rt,
                                &resolved.resolved_path,
                                &resolved.entry.cid,
                                &actual_sha,
                                full_verified,
                                &ct,
                                &bytes,
                                is_head,
                            );
                        }
                        Err(fail) => {
                            record_site_error(
                                rt,
                                fail.kind(),
                                &resolved.entry.cid,
                                &resolved.resolved_path,
                                fail.message(),
                            );
                            let page = build_error_page_html(
                                fail.kind(),
                                &rt.spec.site_base,
                                &resolved.resolved_path,
                                &resolved.entry.cid,
                                fail.message(),
                                &rt.token,
                            );
                            let _ = write_http_response(
                                stream,
                                "502 Bad Gateway",
                                "text/html; charset=utf-8",
                                page.as_bytes(),
                                is_head,
                                &[],
                            );
                        }
                    }
                }
            }
        }

        RootSource::Manifest {
            manifest,
            root_verified,
            ..
        } => {
            let Some((resolved_path, entry)) = manifest.resolve(&decoded_path) else {
                send_not_found(stream, rt, &decoded_path, false, is_head);
                return;
            };
            let resolved_path = resolved_path.to_owned();
            let entry = entry.clone();

            match rt.blob_cache.fetch_verified(
                &entry.cid,
                entry.sha256.as_deref(),
                entry.size,
                &rt.spec.backend,
                &rt.spec.storage_api,
            ) {
                Ok((bytes, actual_sha, file_verified)) => {
                    let ct = neutralize_active_xml_mime(
                        &mime_for_server_path(&resolved_path, &bytes),
                        &resolved_path,
                    );
                    serve_verified_body(
                        stream,
                        rt,
                        &resolved_path,
                        &entry.cid,
                        &actual_sha,
                        root_verified && file_verified,
                        &ct,
                        &bytes,
                        is_head,
                    );
                }
                Err(fail) => {
                    record_site_error(rt, fail.kind(), &entry.cid, &resolved_path, fail.message());
                    let page = build_error_page_html(
                        fail.kind(),
                        &rt.spec.site_base,
                        &resolved_path,
                        &entry.cid,
                        fail.message(),
                        &rt.token,
                    );
                    let _ = write_http_response(
                        stream,
                        "502 Bad Gateway",
                        "text/html; charset=utf-8",
                        page.as_bytes(),
                        is_head,
                        &[],
                    );
                }
            }
        }

        RootSource::Unloaded => {
            let _ = write_http_response(
                stream,
                "500 Internal Server Error",
                "text/plain; charset=utf-8",
                b"Root not loaded",
                is_head,
                &[],
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_verified_body(
    stream: &mut TcpStream,
    rt: &SiteRuntime,
    resolved_path: &str,
    cid: &str,
    sha256: &str,
    verified: bool,
    raw_content_type: &str,
    bytes: &[u8],
    is_head: bool,
) {
    let ct = neutralize_active_xml_mime(raw_content_type, resolved_path);
    let lower_ct = ct.to_ascii_lowercase();
    let mut newly_allowed_cids: HashSet<String> = HashSet::new();

    let body: Vec<u8> = if lower_ct.starts_with("text/html") {
        let text = String::from_utf8_lossy(bytes);
        let rewritten =
            rewrite_html_for_loopback(&text, &rt.token, resolved_path, &mut newly_allowed_cids);
        rewritten.into_bytes()
    } else if lower_ct.starts_with("text/css") {
        let text = String::from_utf8_lossy(bytes);
        let rewritten = rewrite_css_for_loopback(&text, &rt.token, &mut newly_allowed_cids);
        rewritten.into_bytes()
    } else {
        bytes.to_vec()
    };

    {
        let mut st = rt.state.lock().unwrap();
        st.allowed_cids.extend(newly_allowed_cids);
        st.verified_files.insert(
            resolved_path.to_owned(),
            VerifiedFileInfo {
                path: resolved_path.to_owned(),
                cid: cid.to_owned(),
                sha256: sha256.to_owned(),
                size: bytes.len(),
                content_type: ct.clone(),
                verified,
            },
        );
        if lower_ct.starts_with("text/html") {
            st.current_path = resolved_path.to_owned();
            st.last_error = None;
        }
    }

    let _ = write_http_response(stream, "200 OK", &ct, &body, is_head, &[]);
}

fn send_not_found(
    stream: &mut TcpStream,
    rt: &SiteRuntime,
    requested_path: &str,
    single_page: bool,
    is_head: bool,
) {
    let msg = if single_page {
        format!("Path {requested_path} does not exist (single-page site).")
    } else {
        format!("Path {requested_path} was not found on {}.", rt.spec.site_base)
    };
    record_site_error(rt, "not_found", "", requested_path, &msg);
    let page = build_not_found_page_html(&rt.token, &rt.spec.site_base, requested_path, single_page);
    let _ = write_http_response(
        stream,
        "404 Not Found",
        "text/html; charset=utf-8",
        page.as_bytes(),
        is_head,
        &[],
    );
}

fn record_site_error(rt: &SiteRuntime, kind: &str, cid: &str, path: &str, message: &str) {
    {
        let mut st = rt.state.lock().unwrap();
        st.last_error = Some(SiteErrorInfo {
            kind: kind.to_owned(),
            cid: cid.to_owned(),
            path: path.to_owned(),
            message: message.to_owned(),
        });
    }
    push_event(
        rt,
        json!({
            "kind": kind,
            "cid": cid,
            "path": path,
            "message": message,
        }),
    );
}

/// Writes an HTTP/1.1 response with ALL mandatory security headers (PLAN5 §§1-2).
/// Never emits `Set-Cookie`.
fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    is_head: bool,
    extra_headers: &[(&str, &str)],
) -> std::io::Result<()> {
    let mut header = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Content-Security-Policy: {STRICT_CSP}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Cross-Origin-Resource-Policy: same-origin\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\n\
         Connection: close\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        // Guard against accidental Set-Cookie or CRLF injection
        if k.eq_ignore_ascii_case("set-cookie")
            || k.contains('\r')
            || k.contains('\n')
            || v.contains('\r')
            || v.contains('\n')
        {
            continue;
        }
        header.push_str(k);
        header.push_str(": ");
        header.push_str(v);
        header.push_str("\r\n");
    }
    header.push_str("\r\n");
    stream.write_all(header.as_bytes())?;
    if !is_head && !body.is_empty() {
        stream.write_all(body)?;
    }
    stream.flush()
}

// ── HTML & CSS Rewriters for Loopback Origin ──────────────────────────────

fn build_prelude_script(token: &str) -> String {
    format!(
        r#"<script>(function(){{try{{Object.defineProperty(window,"open",{{value:function(){{return null}},writable:false,configurable:false}})}}catch(e){{window.open=function(){{return null}}}}try{{Object.defineProperty(document,"cookie",{{get:function(){{return""}},set:function(){{}},configurable:false}})}}catch(e){{}}try{{var _p="/{token}",_f=window.fetch;if(typeof _f==="function"){{window.fetch=function(u,o){{if(typeof u==="string"&&u.charAt(0)==="/"&&u.charAt(1)!=="/"&&u.indexOf(_p+"/")!==0&&u!==_p){{u=_p+u}}return _f.call(this,u,o)}}}}}}catch(e){{}}}})();</script>"#
    )
}

/// Single-pass HTML rewriter that:
/// - Tracks rawtext/RCDATA tags (`script`, `style`, `textarea`, `title`, `xmp`, `plaintext`) and comments
///   so `<textarea><head>` cannot bypass `<head>` prelude injection.
/// - Strips `<meta http-equiv="refresh">`.
/// - Injects the `window.open` / `document.cookie` / root-relative `fetch` prelude into `<head>`.
/// - Rewrites `<a href="https://...">` -> `/<token>/_ext?u=...`, `lns://` -> `/<token>/_lns?u=...`,
///   `<a download>` / binary links -> `/<token>/_dl?...`, strips `target="_blank"`.
/// - Rewrites `cid://<cid>` -> `/<token>/_cid/<cid>` (and adds `<cid>` to `allowed_cids`).
/// - Rewrites root-relative `/...` URLs -> `/<token>/...`.
/// - Rewrites `<style>` bodies with `rewrite_css_for_loopback`.
pub fn rewrite_html_for_loopback(
    input: &str,
    token: &str,
    current_path: &str,
    allowed_cids: &mut HashSet<String>,
) -> String {
    let prelude = build_prelude_script(token);
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len() + prelude.len() + 256);
    let mut prelude_injected = false;
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'<' {
            let next_lt = input[i..].find('<').map(|o| i + o).unwrap_or(bytes.len());
            out.push_str(&input[i..next_lt]);
            i = next_lt;
            continue;
        }

        // HTML comment <!-- ... -->
        if input[i..].starts_with("<!--") {
            let end = input[i + 4..]
                .find("-->")
                .map(|o| i + 4 + o + 3)
                .unwrap_or(bytes.len());
            out.push_str(&input[i..end]);
            i = end;
            continue;
        }

        // Doctype / declaration / processing instruction
        if bytes.get(i + 1).is_some_and(|&b| b == b'!' || b == b'?') {
            let end = input[i + 2..]
                .find('>')
                .map(|o| i + 2 + o + 1)
                .unwrap_or(bytes.len());
            out.push_str(&input[i..end]);
            i = end;
            continue;
        }

        let Some(gt) = find_html_tag_end(bytes, i + 1) else {
            out.push_str(&input[i..]);
            break;
        };

        let raw_tag = &input[i..=gt];
        let tag_inner = input[i + 1..gt].trim();
        i = gt + 1;

        if tag_inner.is_empty() {
            out.push_str(raw_tag);
            continue;
        }

        let is_close = tag_inner.starts_with('/');
        let is_self_closing = !is_close && tag_inner.ends_with('/');
        let rest = if is_close {
            tag_inner[1..].trim_start()
        } else if is_self_closing {
            tag_inner[..tag_inner.len() - 1].trim()
        } else {
            tag_inner
        };
        let name_end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(rest.len());
        let tag_name = rest[..name_end].to_ascii_lowercase();
        let attrs_raw = &rest[name_end..];

        if is_close {
            out.push_str(raw_tag);
            continue;
        }

        // Rawtext / RCDATA elements: copy verbatim until matching `</tag[\s/>]` (rewrite CSS inside `<style>`)
        if matches!(
            tag_name.as_str(),
            "script" | "style" | "textarea" | "title" | "xmp" | "plaintext"
        ) {
            if tag_name == "script" {
                let rewritten_open = rewrite_tag_attrs(
                    &tag_name,
                    attrs_raw,
                    is_self_closing,
                    token,
                    current_path,
                    allowed_cids,
                );
                out.push_str(&rewritten_open);
            } else {
                out.push_str(raw_tag);
            }
            if !is_self_closing {
                if tag_name == "plaintext" {
                    out.push_str(&input[i..]);
                    break;
                }
                let (content_end, close_end) = find_rawtext_close(input, i, &tag_name);
                if tag_name == "style" {
                    let css_rw =
                        rewrite_css_for_loopback(&input[i..content_end], token, allowed_cids);
                    out.push_str(&css_rw);
                } else {
                    out.push_str(&input[i..content_end]);
                }
                out.push_str(&input[content_end..close_end]);
                i = close_end;
            }
            continue;
        }

        // Strip `<meta http-equiv="refresh" ...>`
        if tag_name == "meta" {
            let attrs = parse_html_attrs(attrs_raw);
            let is_refresh = attrs.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("http-equiv")
                    && v.as_deref()
                        .map(|val| val.trim().eq_ignore_ascii_case("refresh"))
                        .unwrap_or(false)
            });
            if is_refresh {
                continue;
            }
            out.push_str(raw_tag);
            continue;
        }

        // Strip `<base ...>` so pages cannot hijack relative URLs off-origin
        if tag_name == "base" {
            continue;
        }

        // Inject prelude inside `<head>` or right before `<body>`
        if tag_name == "head" {
            out.push_str(raw_tag);
            if !prelude_injected {
                out.push_str(&prelude);
                prelude_injected = true;
            }
            continue;
        }
        if tag_name == "body" && !prelude_injected {
            out.push_str(&prelude);
            prelude_injected = true;
        }

        if matches!(
            tag_name.as_str(),
            "a" | "area" | "link" | "img" | "source" | "audio" | "video" | "track" | "form"
        ) {
            let rewritten = rewrite_tag_attrs(
                &tag_name,
                attrs_raw,
                is_self_closing,
                token,
                current_path,
                allowed_cids,
            );
            out.push_str(&rewritten);
        } else {
            out.push_str(raw_tag);
        }
    }

    if !prelude_injected {
        out = format!("{prelude}{out}");
    }
    out
}

fn find_html_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i),
            None => {}
        }
        i += 1;
    }
    None
}

fn find_rawtext_close(input: &str, start: usize, tag_name: &str) -> (usize, usize) {
    let bytes = input.as_bytes();
    let needle = format!("</{tag_name}");
    let lower = input[start..].to_ascii_lowercase();
    let mut search_from = 0usize;
    while let Some(rel) = lower[search_from..].find(&needle) {
        let abs = start + search_from + rel;
        let after = abs + needle.len();
        let valid_boundary = bytes
            .get(after)
            .is_some_and(|&b| b.is_ascii_whitespace() || b == b'>' || b == b'/');
        if valid_boundary {
            let end_gt = input[after..]
                .find('>')
                .map(|o| after + o + 1)
                .unwrap_or(bytes.len());
            return (abs, end_gt);
        }
        search_from += rel + needle.len();
    }
    (bytes.len(), bytes.len())
}

fn parse_html_attrs(attrs_raw: &str) -> Vec<(String, Option<String>)> {
    let bytes = attrs_raw.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        let name = attrs_raw[name_start..i].to_owned();
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let val = if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                let v_start = i;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                let v = &attrs_raw[v_start..i];
                if i < bytes.len() {
                    i += 1;
                }
                v.to_owned()
            } else {
                let v_start = i;
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                attrs_raw[v_start..i].to_owned()
            };
            out.push((name, Some(val)));
        } else if !name.is_empty() {
            out.push((name, None));
        }
    }
    out
}

fn rewrite_tag_attrs(
    tag_name: &str,
    attrs_raw: &str,
    is_self_closing: bool,
    token: &str,
    current_path: &str,
    allowed_cids: &mut HashSet<String>,
) -> String {
    let attrs = parse_html_attrs(attrs_raw);
    let has_download = attrs
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("download"));
    let download_val = attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("download"))
        .and_then(|(_, v)| v.clone())
        .unwrap_or_default();

    let mut out = format!("<{tag_name}");
    for (k, v) in attrs {
        let low_k = k.to_ascii_lowercase();
        if tag_name == "a" || tag_name == "area" {
            // Strip `target` so clicks never spawn popups; strip `download` when we rewrite to `/_dl`
            if low_k == "target" || low_k == "download" {
                continue;
            }
            if low_k == "href" {
                let raw_val = v.unwrap_or_default();
                let decoded = decode_basic_entities(raw_val.trim());
                let rewritten = rewrite_anchor_href(
                    &decoded,
                    has_download,
                    &download_val,
                    token,
                    current_path,
                    allowed_cids,
                );
                out.push_str(" href=\"");
                out.push_str(&crate::escape_html_text(&rewritten));
                out.push('"');
                continue;
            }
        } else if matches!(low_k.as_str(), "src" | "href" | "poster" | "action") {
            let raw_val = v.unwrap_or_default();
            let decoded = decode_basic_entities(raw_val.trim());
            let rewritten = rewrite_resource_url(&decoded, token, allowed_cids);
            out.push(' ');
            out.push_str(&k);
            out.push_str("=\"");
            out.push_str(&crate::escape_html_text(&rewritten));
            out.push('"');
            continue;
        } else if low_k == "srcset" {
            let raw_val = v.unwrap_or_default();
            let rewritten = rewrite_srcset(&raw_val, token, allowed_cids);
            out.push_str(" srcset=\"");
            out.push_str(&crate::escape_html_text(&rewritten));
            out.push('"');
            continue;
        }

        out.push(' ');
        out.push_str(&k);
        if let Some(val) = v {
            out.push_str("=\"");
            out.push_str(&crate::escape_html_text(&decode_basic_entities(&val)));
            out.push('"');
        }
    }
    if is_self_closing {
        out.push_str(" /");
    }
    out.push('>');
    out
}

fn rewrite_anchor_href(
    href: &str,
    has_download: bool,
    download_val: &str,
    token: &str,
    current_path: &str,
    allowed_cids: &mut HashSet<String>,
) -> String {
    let trimmed = href.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return trimmed.to_owned();
    }
    let lower = trimmed.to_ascii_lowercase();

    // External https:// -> /<token>/_ext?u=...
    if lower.starts_with("https://") {
        if crate::is_safe_external_https_url(trimmed) {
            return format!("/{token}/_ext?u={}", percent_encode(trimmed));
        }
        return "#".to_owned();
    }

    // LNS link -> /<token>/_lns?u=...
    if lower.starts_with("lns://") || lower.starts_with("lns:") {
        if parse_url(trimmed).is_ok() {
            return format!("/{token}/_lns?u={}", percent_encode(trimmed));
        }
        return "#".to_owned();
    }

    // Direct CID link
    if lower.starts_with("cid://") {
        let rest = &trimmed[6..];
        let cid = rest.split(['/', '?', '#']).next().unwrap_or("");
        if !is_valid_cid(cid) {
            return "#".to_owned();
        }
        if has_download {
            allowed_cids.insert(cid.to_owned());
            let name = if !download_val.trim().is_empty() {
                download_val.trim().to_owned()
            } else {
                format!("{}.bin", &cid[..cid.len().min(12)])
            };
            return format!(
                "/{token}/_dl?cid={}&name={}",
                percent_encode(cid),
                percent_encode(&name)
            );
        }
        return format!("/{token}/_lns?u={}", percent_encode(trimmed));
    }

    // Block unsafe explicit schemes and protocol-relative URLs
    if trimmed.contains(':') || trimmed.starts_with("//") {
        return "#".to_owned();
    }

    // Same-site link (relative or root-relative)
    let resolved = resolve_site_relative(trimmed, current_path);
    if has_download || is_direct_download_handoff_path(&resolved) {
        let clean = resolved.split(['?', '#']).next().unwrap_or(&resolved);
        let fallback_name = clean.rsplit('/').next().unwrap_or("download.bin");
        let name = if !download_val.trim().is_empty() {
            download_val.trim()
        } else {
            fallback_name
        };
        return format!(
            "/{token}/_dl?path={}&name={}",
            percent_encode(clean),
            percent_encode(name)
        );
    }

    // Root-relative path `/foo` -> `/<token>/foo`
    if trimmed.starts_with('/') {
        let prefix = format!("/{token}/");
        if trimmed.starts_with(&prefix) || trimmed == format!("/{token}") {
            return trimmed.to_owned();
        }
        return format!("/{token}{trimmed}");
    }

    // Relative path `./page.html`, `about/`, `../guide.html` resolves naturally on loopback
    trimmed.to_owned()
}

fn rewrite_resource_url(
    url: &str,
    token: &str,
    allowed_cids: &mut HashSet<String>,
) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.len() >= 6 && trimmed[..6].eq_ignore_ascii_case("cid://") {
        let cid = trimmed[6..].split(['/', '?', '#']).next().unwrap_or("");
        if is_valid_cid(cid) {
            allowed_cids.insert(cid.to_owned());
            return format!("/{token}/_cid/{cid}");
        }
        return String::new();
    }
    if trimmed.starts_with('/') && !trimmed.starts_with("//") {
        let prefix = format!("/{token}/");
        if trimmed.starts_with(&prefix) || trimmed == format!("/{token}") {
            return trimmed.to_owned();
        }
        return format!("/{token}{trimmed}");
    }
    trimmed.to_owned()
}

fn rewrite_srcset(raw: &str, token: &str, allowed_cids: &mut HashSet<String>) -> String {
    let mut parts = Vec::new();
    for item in raw.split(',') {
        let t = item.trim();
        if t.is_empty() {
            continue;
        }
        let mut iter = t.splitn(2, char::is_whitespace);
        let u = iter.next().unwrap_or("");
        let rest = iter.next().unwrap_or("").trim();
        let rw = rewrite_resource_url(u, token, allowed_cids);
        if rest.is_empty() {
            parts.push(rw);
        } else {
            parts.push(format!("{rw} {rest}"));
        }
    }
    parts.join(", ")
}

pub fn rewrite_css_for_loopback(
    css: &str,
    token: &str,
    allowed_cids: &mut HashSet<String>,
) -> String {
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len() + 64);
    let mut i = 0usize;

    while i < bytes.len() {
        // Preserve CSS comments verbatim
        if css[i..].starts_with("/*") {
            let end = css[i + 2..]
                .find("*/")
                .map(|o| i + 2 + o + 2)
                .unwrap_or(bytes.len());
            out.push_str(&css[i..end]);
            i = end;
            continue;
        }
        // Match `url(` case-insensitively
        if bytes.len() >= i + 4 && css[i..i + 4].eq_ignore_ascii_case("url(") {
            let after_open = i + 4;
            if let Some(close_rel) = css[after_open..].find(')') {
                let inner_raw = css[after_open..after_open + close_rel].trim();
                let unquoted = inner_raw
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| inner_raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                    .unwrap_or(inner_raw)
                    .trim();
                let rw = rewrite_resource_url(unquoted, token, allowed_cids);
                if rw != unquoted {
                    out.push_str("url(\"");
                    out.push_str(&rw);
                    out.push_str("\")");
                } else {
                    out.push_str(&css[i..=after_open + close_rel]);
                }
                i = after_open + close_rel + 1;
                continue;
            }
        }
        let ch = css[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn resolve_site_relative(href: &str, current_path: &str) -> String {
    let joined = if href.starts_with('/') {
        href.to_owned()
    } else {
        let clean_cur = current_path.split(['?', '#']).next().unwrap_or("/");
        let dir = clean_cur
            .rsplit_once('/')
            .map(|(d, _)| d)
            .unwrap_or("");
        format!("{dir}/{href}")
    };
    normalize_links_path(&joined)
        .map(|n| n.path)
        .unwrap_or_else(|_| "/".to_owned())
}

fn decode_basic_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

// ── MIME, Error Pages & Small Helpers ─────────────────────────────────────

fn is_direct_download_handoff_path(path: &str) -> bool {
    let clean = path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    let file = clean.rsplit('/').next().unwrap_or("");
    let Some((_, ext)) = file.rsplit_once('.') else {
        return false;
    };
    // Keep `.wasm` directly servable for in-page WebAssembly; hand off packages/archives/installers.
    ext != "wasm" && is_binary_download_path(path)
}

fn is_html_or_doc_path(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    low.ends_with(".html") || low.ends_with(".htm") || low.ends_with(".md")
}

fn neutralize_active_xml_mime(ct: &str, path: &str) -> String {
    let low_path = path.to_ascii_lowercase();
    let blocked_ext = [".xhtml", ".xht", ".xml", ".xsl", ".xslt", ".shtml", ".svgz", ".mhtml", ".mht"]
        .iter()
        .any(|ext| low_path.ends_with(ext));
    let bare = ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    let blocked_mime = matches!(
        bare.as_str(),
        "application/xhtml+xml"
            | "application/xml"
            | "text/xml"
            | "application/xslt+xml"
            | "text/xsl"
    );
    if blocked_ext || blocked_mime {
        return "application/octet-stream".to_owned();
    }
    ct.to_owned()
}

fn mime_for_server_path(path: &str, bytes: &[u8]) -> String {
    let clean = path.split(['?', '#']).next().unwrap_or("");
    let ext = clean
        .rsplit('/')
        .next()
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let by_ext = match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        _ => mime_for_path(clean),
    };
    if by_ext == "application/octet-stream" {
        return sniff_asset_mime(bytes, by_ext);
    }
    by_ext.to_owned()
}

fn sniff_asset_mime(bytes: &[u8], fallback: &str) -> String {
    if bytes.len() >= 8 && &bytes[..4] == b"\x89PNG" {
        return "image/png".to_owned();
    }
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return "image/jpeg".to_owned();
    }
    if bytes.len() >= 6 && &bytes[..4] == b"GIF8" {
        return "image/gif".to_owned();
    }
    if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return "image/webp".to_owned();
    }
    if bytes.len() >= 4 && &bytes[..4] == b"wOF2" {
        return "font/woff2".to_owned();
    }
    if bytes.len() >= 4 && &bytes[..4] == b"wOFF" {
        return "font/woff".to_owned();
    }
    if bytes.len() >= 4 && &bytes[..4] == b"\x00asm" {
        return "application/wasm".to_owned();
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]);
    let trimmed = head.trim_start().to_ascii_lowercase();
    if trimmed.starts_with("<svg") {
        return "image/svg+xml".to_owned();
    }
    sniff_content_type(bytes, fallback)
}

fn build_not_found_page_html(
    token: &str,
    site_base: &str,
    requested_path: &str,
    single_page: bool,
) -> String {
    let esc_base = crate::escape_html_text(site_base);
    let esc_path = crate::escape_html_text(requested_path);
    let detail = if single_page {
        format!("Path <code>{esc_path}</code> does not exist (single-page site).")
    } else {
        format!("Path <code>{esc_path}</code> was not found on <code>{esc_base}</code>.")
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>No such page — {esc_base}</title>
<style>
body{{margin:0;padding:40px 24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0f141d;color:#e6edf7}}
.card{{max-width:560px;margin:48px auto;padding:28px;border-radius:14px;background:#171f2d;border:1px solid #2b364a}}
h1{{margin:0 0 10px;font-size:22px}}
p{{color:#a2b1c6;line-height:1.5;font-size:14px}}
code{{font-family:Menlo,monospace;color:#e6edf7;background:#0f141d;padding:2px 6px;border-radius:4px}}
a.btn{{display:inline-block;margin-top:16px;padding:10px 16px;border-radius:8px;background:#e5a93b;color:#0f141d;font-weight:600;text-decoration:none;font-size:13px}}
</style>
</head>
<body>
<div class="card">
<h1>No such page</h1>
<p>{detail}</p>
<a class="btn" href="/{token}/">Back to {esc_base}/</a>
</div>
</body>
</html>"#
    )
}

fn build_error_page_html(
    kind: &str,
    site_base: &str,
    path: &str,
    cid: &str,
    message: &str,
    token: &str,
) -> String {
    let heading = if kind == "tampered" {
        "Integrity check failed (SHA-256 mismatch)"
    } else {
        "Storage fetch failed"
    };
    let esc_base = crate::escape_html_text(site_base);
    let esc_path = crate::escape_html_text(path);
    let esc_cid = crate::escape_html_text(cid);
    let esc_msg = crate::escape_html_text(message);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{heading} — {esc_base}</title>
<style>
body{{margin:0;padding:40px 24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0f141d;color:#e6edf7}}
.card{{max-width:600px;margin:48px auto;padding:28px;border-radius:14px;background:#171f2d;border:1px solid #d9534f}}
h1{{margin:0 0 10px;font-size:20px;color:#ff7b72}}
p{{color:#a2b1c6;line-height:1.5;font-size:14px;word-break:break-word}}
code{{font-family:Menlo,monospace;color:#e6edf7;background:#0f141d;padding:2px 6px;border-radius:4px}}
a.btn{{display:inline-block;margin-top:16px;margin-right:10px;padding:10px 16px;border-radius:8px;background:#e5a93b;color:#0f141d;font-weight:600;text-decoration:none;font-size:13px}}
</style>
</head>
<body>
<div class="card">
<h1>{heading}</h1>
<p>Path: <code>{esc_path}</code><br>CID: <code>{esc_cid}</code></p>
<p>{esc_msg}</p>
<a class="btn" href="/{token}/">Back to {esc_base}/</a>
</div>
</body>
</html>"#
    )
}

fn build_download_page_html(
    token: &str,
    site_base: &str,
    path: &str,
    filename: &str,
    cid: &str,
    sha256: &str,
) -> String {
    let esc_base = crate::escape_html_text(site_base);
    let esc_name = crate::escape_html_text(filename);
    let esc_cid = crate::escape_html_text(cid);
    let esc_sha = if sha256.is_empty() {
        "unpinned".to_owned()
    } else {
        crate::escape_html_text(sha256)
    };
    let dl_url = format!(
        "/{token}/_dl?path={}&name={}",
        percent_encode(path),
        percent_encode(filename)
    );
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Download {esc_name} — {esc_base}</title>
<style>
body{{margin:0;padding:40px 24px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0f141d;color:#e6edf7}}
.card{{max-width:580px;margin:48px auto;padding:28px;border-radius:14px;background:#171f2d;border:1px solid #2b364a}}
h1{{margin:0 0 10px;font-size:20px}}
p{{color:#a2b1c6;line-height:1.5;font-size:13px;word-break:break-all}}
code{{font-family:Menlo,monospace;color:#e6edf7}}
a.btn{{display:inline-block;margin-top:16px;margin-right:10px;padding:10px 16px;border-radius:8px;background:#e5a93b;color:#0f141d;font-weight:600;text-decoration:none;font-size:13px}}
</style>
</head>
<body>
<div class="card">
<h1>Download {esc_name}</h1>
<p>CID: <code>{esc_cid}</code><br>SHA-256: <code>{esc_sha}</code></p>
<p>Downloads are fetched and verified through LNS Browser Core into your Downloads folder.</p>
<a class="btn" href="{dl_url}">Save to Downloads</a>
<a class="btn" href="/{token}/">Back to {esc_base}/</a>
</div>
</body>
</html>"#
    )
}

fn folder_entries_json(dir_prefix: &str, entries: &[LinksEntry]) -> Vec<Value> {
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

fn parse_query(raw_query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in raw_query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if let (Some(dk), Some(dv)) = (percent_decode(k, true), percent_decode(v, true)) {
            map.insert(dk, dv);
        }
    }
    map
}

pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn percent_decode(input: &str, plus_as_space: bool) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_val(bytes[i + 1])?;
            let lo = hex_val(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else if plus_as_space && bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn default_private_cache_dir() -> PathBuf {
    std::env::temp_dir().join(format!("lns-browser-{}", std::process::id()))
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn read_capped_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path).map_err(|e| format!("Cannot read downloaded blob: {e}"))?;
    let mut out = Vec::new();
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut out)
        .map_err(|e| format!("Failed reading downloaded blob: {e}"))?;
    if out.len() > max_bytes {
        return Err(format!("Downloaded blob exceeds {max_bytes} byte limit"));
    }
    Ok(out)
}

fn generate_random_token_128() -> String {
    let mut bytes = [0u8; 16];
    let mut filled = false;
    #[cfg(unix)]
    {
        if let Ok(mut f) = fs::File::open("/dev/urandom") {
            if f.read_exact(&mut bytes).is_ok() {
                filled = true;
            }
        }
    }
    if !filled {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut hasher = Sha256::new();
        hasher.update(now.to_le_bytes());
        hasher.update(std::process::id().to_le_bytes());
        hasher.update(c.to_le_bytes());
        hasher.update((&bytes as *const _ as usize).to_le_bytes());
        let digest = hasher.finalize();
        bytes.copy_from_slice(&digest[..16]);
    }
    let mut hex = String::with_capacity(32);
    for b in bytes {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID_ROOT: &str = "z4W2jSrvRoot00000000000000000000000000000000000";
    const CID_INDEX: &str = "z4W2jSrvIndex0000000000000000000000000000000000";
    const CID_APP_JS: &str = "z4W2jSrvAppJs0000000000000000000000000000000000";
    const CID_CSS: &str = "z4W2jSrvCss000000000000000000000000000000000000";
    const CID_IMG: &str = "z4W2jSrvImg000000000000000000000000000000000000";
    const CID_UNLISTED: &str = "z4W2jSrvSecret000000000000000000000000000000000";
    const CID_TAMPERED: &str = "z4W2jSrvTamper000000000000000000000000000000000";
    const CID_SUB_DIR: &str = "z4W2jSrvSubDir000000000000000000000000000000000";
    const CID_LGX: &str = "z4W2jSrvAppLgx000000000000000000000000000000000";

    fn noop_downloader() -> BasecampDownloader {
        Arc::new(|cid, _| Err(format!("unexpected basecamp download for {cid}")))
    }

    fn temp_cache_dir(label: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("lns-srv-test-{label}-{}-{n}", std::process::id()))
    }

    #[allow(dead_code)]
    struct RawHttpResp {
        status_line: String,
        status_code: u16,
        headers: HashMap<String, Vec<String>>,
        body: Vec<u8>,
    }

    fn send_raw_http(port: u16, raw_req: &str) -> RawHttpResp {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(raw_req.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut resp_bytes = Vec::new();
        stream.read_to_end(&mut resp_bytes).unwrap();
        let split = resp_bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("valid HTTP response");
        let head = String::from_utf8_lossy(&resp_bytes[..split]);
        let body = resp_bytes[split + 4..].to_vec();
        let mut lines = head.split("\r\n");
        let status_line = lines.next().unwrap_or("").to_owned();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        let mut headers: HashMap<String, Vec<String>> = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers
                    .entry(k.trim().to_ascii_lowercase())
                    .or_default()
                    .push(v.trim().to_owned());
            }
        }
        RawHttpResp {
            status_line,
            status_code,
            headers,
            body,
        }
    }

    fn assert_mandatory_security_headers(resp: &RawHttpResp) {
        let csp = resp
            .headers
            .get("content-security-policy")
            .and_then(|v| v.first())
            .expect("Content-Security-Policy header must be present");
        assert!(csp.contains("default-src 'none'"), "CSP missing default-src 'none': {csp}");
        assert!(csp.contains("connect-src 'self'"), "CSP missing connect-src 'self': {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "CSP missing frame-ancestors 'none'");
        assert!(csp.contains("form-action 'none'"), "CSP missing form-action 'none'");
        assert_eq!(
            resp.headers.get("x-content-type-options").and_then(|v| v.first()).map(String::as_str),
            Some("nosniff")
        );
        assert_eq!(
            resp.headers.get("referrer-policy").and_then(|v| v.first()).map(String::as_str),
            Some("no-referrer")
        );
        assert_eq!(
            resp.headers.get("cache-control").and_then(|v| v.first()).map(String::as_str),
            Some("no-store")
        );
        assert_eq!(
            resp.headers.get("cross-origin-resource-policy").and_then(|v| v.first()).map(String::as_str),
            Some("same-origin")
        );
        assert_eq!(
            resp.headers.get("cross-origin-opener-policy").and_then(|v| v.first()).map(String::as_str),
            Some("same-origin")
        );
        assert!(
            !resp.headers.contains_key("set-cookie"),
            "Set-Cookie must never be emitted"
        );
    }

    fn spawn_mock_storage(blobs: HashMap<String, Vec<u8>>) -> (String, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_bg.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(mut s) = stream else { break };
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let first = head.lines().next().unwrap_or("");
                let path = first.split_whitespace().nth(1).unwrap_or("");
                // Match `/data/<cid>/network/stream` or `/data/<cid>`
                let cid = path
                    .strip_prefix("/data/")
                    .map(|r| r.split('/').next().unwrap_or(""))
                    .unwrap_or("");
                if let Some(data) = blobs.get(cid) {
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        data.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.write_all(data);
                } else {
                    let body = b"not found";
                    let resp = format!(
                        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes());
                    let _ = s.write_all(body);
                }
                let _ = s.flush();
            }
        });
        (format!("http://{addr}"), stop)
    }

    #[test]
    fn headers_present_on_every_response_and_host_token_method_traversal_guarded() {
        let mut mgr = SiteServerManager::with_cache_dir(temp_cache_dir("guards"), noop_downloader());
        let site_a = mgr
            .site_open(SiteSpec {
                kind: "lns".to_owned(),
                host: "alice".to_owned(),
                site_base: "lns://alice".to_owned(),
                mode: "onchain-page".to_owned(),
                root_cid: String::new(),
                root_sha256: String::new(),
                site_type: String::new(),
                backend: "memory".to_owned(),
                storage_api: String::new(),
                onchain_html: Some("<!doctype html><html><head><title>Alice</title></head><body><h1>Hi Alice</h1></body></html>".to_owned()),
                onchain_links: None,
                title: Some("Alice".to_owned()),
                initial_path: "/".to_owned(),
            })
            .unwrap();
        let site_b = mgr
            .site_open(SiteSpec {
                kind: "lns".to_owned(),
                host: "bob".to_owned(),
                site_base: "lns://bob".to_owned(),
                mode: "onchain-page".to_owned(),
                root_cid: String::new(),
                root_sha256: String::new(),
                site_type: String::new(),
                backend: "memory".to_owned(),
                storage_api: String::new(),
                onchain_html: Some("<html><body>Bob</body></html>".to_owned()),
                onchain_links: None,
                title: Some("Bob".to_owned()),
                initial_path: "/".to_owned(),
            })
            .unwrap();

        let port_a = site_a["port"].as_u64().unwrap() as u16;
        let tok_a = site_a["token"].as_str().unwrap();
        let port_b = site_b["port"].as_u64().unwrap() as u16;
        let tok_b = site_b["token"].as_str().unwrap();

        // Separate ephemeral ports and distinct 128-bit tokens
        assert_ne!(port_a, port_b);
        assert_ne!(tok_a, tok_b);
        assert_eq!(tok_a.len(), 32);

        // 200 OK on valid GET (even with incoming Cookie header -> ignored, no Set-Cookie)
        let ok_resp = send_raw_http(
            port_a,
            &format!("GET /{tok_a}/ HTTP/1.1\r\nHost: 127.0.0.1:{port_a}\r\nCookie: sid=evil\r\n\r\n"),
        );
        assert_eq!(ok_resp.status_code, 200);
        assert_mandatory_security_headers(&ok_resp);
        let body_str = String::from_utf8_lossy(&ok_resp.body);
        assert!(body_str.contains("Hi Alice"));

        // 200 OK on HEAD with empty body and matching Content-Length
        let head_resp = send_raw_http(
            port_a,
            &format!("HEAD /{tok_a}/ HTTP/1.1\r\nHost: 127.0.0.1:{port_a}\r\n\r\n"),
        );
        assert_eq!(head_resp.status_code, 200);
        assert_mandatory_security_headers(&head_resp);
        assert!(head_resp.body.is_empty());
        assert_eq!(
            head_resp.headers.get("content-length").and_then(|v| v.first()).map(String::as_str),
            Some(ok_resp.body.len().to_string().as_str())
        );

        // Other site's token -> 403
        let other_tok = send_raw_http(
            port_a,
            &format!("GET /{tok_b}/ HTTP/1.1\r\nHost: 127.0.0.1:{port_a}\r\n\r\n"),
        );
        assert_eq!(other_tok.status_code, 403);
        assert_mandatory_security_headers(&other_tok);

        // Wrong Host headers -> 403 (DNS rebinding, localhost, other site's port, missing Host)
        for bad_host in [
            "Host: evil.example\r\n".to_owned(),
            format!("Host: localhost:{port_a}\r\n"),
            format!("Host: 127.0.0.1:{port_b}\r\n"),
            String::new(),
        ] {
            let r = send_raw_http(
                port_a,
                &format!("GET /{tok_a}/ HTTP/1.1\r\n{bad_host}\r\n"),
            );
            assert_eq!(r.status_code, 403, "expected 403 for {bad_host:?}");
            assert_mandatory_security_headers(&r);
        }

        // Non-GET/HEAD methods -> 405 Method Not Allowed
        for method in ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            let r = send_raw_http(
                port_a,
                &format!("{method} /{tok_a}/ HTTP/1.1\r\nHost: 127.0.0.1:{port_a}\r\n\r\n"),
            );
            assert_eq!(r.status_code, 405, "expected 405 for {method}");
            assert_mandatory_security_headers(&r);
            assert_eq!(
                r.headers.get("allow").and_then(|v| v.first()).map(String::as_str),
                Some("GET, HEAD")
            );
        }

        // Missing path -> 404 Not Found with "No such page" HTML + security headers
        let nf = send_raw_http(
            port_a,
            &format!("GET /{tok_a}/missing/page.html HTTP/1.1\r\nHost: 127.0.0.1:{port_a}\r\n\r\n"),
        );
        assert_eq!(nf.status_code, 404);
        assert_mandatory_security_headers(&nf);
        let nf_body = String::from_utf8_lossy(&nf.body);
        assert!(nf_body.contains("No such page"));
        assert!(nf_body.contains(&format!("/{tok_a}/")));

        // Path traversal refused -> 400 Bad Request + security headers
        for bad_path in [
            format!("/{tok_a}/../etc/passwd"),
            format!("/{tok_a}/a/../../etc/passwd"),
            format!("/{tok_a}/%2e%2e/secret"),
            format!("/{tok_a}/..%2fsecret"),
            format!("/{tok_a}/foo%5cbar"),
            format!("/{tok_a}/bad%00file"),
        ] {
            let r = send_raw_http(
                port_a,
                &format!("GET {bad_path} HTTP/1.1\r\nHost: 127.0.0.1:{port_a}\r\n\r\n"),
            );
            assert_eq!(r.status_code, 400, "expected 400 for traversal {bad_path}");
            assert_mandatory_security_headers(&r);
        }

        assert!(mgr.site_close(tok_a));
        assert!(mgr.site_close(tok_b));
    }

    #[test]
    fn links_site_verifies_sha256_refuses_tampered_bytes_rewrites_html_and_handles_special_endpoints() {
        let index_html = format!(
            concat!(
                "<!doctype html><html><head>",
                "<meta http-equiv=\"refresh\" content=\"0;url=https://evil.example\">",
                "<title>Demo</title>",
                "<link rel=\"stylesheet\" href=\"/style.css\">",
                "</head><body>",
                "<textarea><head></textarea>",
                "<img src=\"cid://{CID_IMG}\">",
                "<a href=\"https://nameswallet.app/browser\" target=\"_blank\">Web</a>",
                "<a href=\"lns://jef/about\">Jef</a>",
                "<a href=\"sub/app.lgx\">DL</a>",
                "<script type=\"module\" src=\"/app.js\"></script>",
                "</body></html>"
            ),
            CID_IMG = CID_IMG
        );
        let css_bytes = format!("body{{background:url(/bg.png)}} .pic{{background:url(cid://{CID_IMG})}}");
        let js_bytes = b"export const ok = true;\n".to_vec();
        let png_bytes = vec![0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00];
        let real_tampered_expected = sha256_hex(b"GENUINE FILE");
        let fake_tampered_bytes = b"EVIL TAMPERED BYTES".to_vec();

        let sub_list = format!(
            "# lns-links/1\napp.lgx {CID_LGX} {}\n",
            sha256_hex(b"LGX-PAYLOAD")
        );
        let root_list = format!(
            "# lns-links/1\n# title Demo Site\napp.js {CID_APP_JS} {}\nindex.html {CID_INDEX} {}\nstyle.css {CID_CSS} {}\nsub/ {CID_SUB_DIR} {}\ntampered.html {CID_TAMPERED} {real_tampered_expected}\n",
            sha256_hex(&js_bytes),
            sha256_hex(index_html.as_bytes()),
            sha256_hex(css_bytes.as_bytes()),
            sha256_hex(sub_list.as_bytes()),
        );
        let root_sha = sha256_hex(root_list.as_bytes());

        let mut blobs = HashMap::new();
        blobs.insert(CID_ROOT.to_owned(), root_list.into_bytes());
        blobs.insert(CID_INDEX.to_owned(), index_html.into_bytes());
        blobs.insert(CID_APP_JS.to_owned(), js_bytes);
        blobs.insert(CID_CSS.to_owned(), css_bytes.into_bytes());
        blobs.insert(CID_IMG.to_owned(), png_bytes.clone());
        blobs.insert(CID_UNLISTED.to_owned(), b"SECRET".to_vec());
        blobs.insert(CID_TAMPERED.to_owned(), fake_tampered_bytes);
        blobs.insert(CID_SUB_DIR.to_owned(), sub_list.into_bytes());
        blobs.insert(CID_LGX.to_owned(), b"LGX-PAYLOAD".to_vec());

        let (storage_url, _stop) = spawn_mock_storage(blobs);
        let mut mgr = SiteServerManager::with_cache_dir(temp_cache_dir("links"), noop_downloader());
        let opened = mgr
            .site_open(SiteSpec {
                kind: "lns".to_owned(),
                host: "nameswallet".to_owned(),
                site_base: "lns://nameswallet".to_owned(),
                mode: "cid".to_owned(),
                root_cid: CID_ROOT.to_owned(),
                root_sha256: root_sha,
                site_type: "links".to_owned(),
                backend: "http".to_owned(),
                storage_api: storage_url,
                onchain_html: None,
                onchain_links: None,
                title: None,
                initial_path: "/".to_owned(),
            })
            .unwrap();

        let port = opened["port"].as_u64().unwrap() as u16;
        let tok = opened["token"].as_str().unwrap();

        // 1. Fetch `/` -> 200 OK with HTML rewrites, meta refresh stripped, window.open stubbed
        let idx = send_raw_http(
            port,
            &format!("GET /{tok}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(idx.status_code, 200);
        assert_mandatory_security_headers(&idx);
        let html = String::from_utf8_lossy(&idx.body);
        assert!(!html.to_ascii_lowercase().contains("http-equiv=\"refresh\""));
        assert!(html.contains("Object.defineProperty(window,\"open\""));
        assert!(html.contains("Object.defineProperty(document,\"cookie\""));
        assert!(html.contains(&format!("href=\"/{tok}/style.css\"")));
        assert!(html.contains(&format!("src=\"/{tok}/app.js\"")));
        assert!(html.contains(&format!("src=\"/{tok}/_cid/{CID_IMG}\"")));
        assert!(html.contains(&format!(
            "href=\"/{tok}/_ext?u=https%3A%2F%2Fnameswallet.app%2Fbrowser\""
        )));
        assert!(!html.contains("target=\"_blank\""));
        assert!(html.contains(&format!("href=\"/{tok}/_lns?u=lns%3A%2F%2Fjef%2Fabout\"")));
        assert!(html.contains(&format!(
            "href=\"/{tok}/_dl?path=%2Fsub%2Fapp.lgx&amp;name=app.lgx\""
        )));

        // 2. Fetch CSS -> rewrites root-relative url() and cid://
        let css = send_raw_http(
            port,
            &format!("GET /{tok}/style.css HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(css.status_code, 200);
        assert_mandatory_security_headers(&css);
        let css_str = String::from_utf8_lossy(&css.body);
        assert!(css_str.contains(&format!("url(\"/{tok}/bg.png\")")));
        assert!(css_str.contains(&format!("url(\"/{tok}/_cid/{CID_IMG}\")")));

        // 3. Allowlisted `/_cid/<CID_IMG>` serves PNG; unlisted `/_cid/<CID_UNLISTED>` returns 403
        let img = send_raw_http(
            port,
            &format!("GET /{tok}/_cid/{CID_IMG} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(img.status_code, 200);
        assert_mandatory_security_headers(&img);
        assert_eq!(img.body, png_bytes);

        let forbidden_cid = send_raw_http(
            port,
            &format!("GET /{tok}/_cid/{CID_UNLISTED} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(forbidden_cid.status_code, 403);
        assert_mandatory_security_headers(&forbidden_cid);

        // 4. Tampered file refused with 502 and tampered bytes never returned
        let tampered = send_raw_http(
            port,
            &format!("GET /{tok}/tampered.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(tampered.status_code, 502);
        assert_mandatory_security_headers(&tampered);
        let tampered_body = String::from_utf8_lossy(&tampered.body);
        assert!(!tampered_body.contains("EVIL TAMPERED BYTES"));
        assert!(tampered_body.contains("SHA-256 mismatch"));

        // 5. Missing subfolder index `/sub/` -> 404 page
        let sub404 = send_raw_http(
            port,
            &format!("GET /{tok}/sub/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(sub404.status_code, 404);
        assert_mandatory_security_headers(&sub404);
        assert!(String::from_utf8_lossy(&sub404.body).contains("No such page"));

        // 6. `/_ext`, `/_lns`, `/_dl` return 204 + security headers + record events
        let ext = send_raw_http(
            port,
            &format!("GET /{tok}/_ext?u=https%3A%2F%2Fnameswallet.app%2Fbrowser HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(ext.status_code, 204);
        assert_mandatory_security_headers(&ext);

        let lns = send_raw_http(
            port,
            &format!("GET /{tok}/_lns?u=lns%3A%2F%2Fjef%2Fabout HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(lns.status_code, 204);
        assert_mandatory_security_headers(&lns);

        let dl = send_raw_http(
            port,
            &format!("GET /{tok}/_dl?path=%2Fsub%2Fapp.lgx&name=app.lgx HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        );
        assert_eq!(dl.status_code, 204);
        assert_mandatory_security_headers(&dl);

        let polled = mgr.site_poll_events(tok).unwrap();
        let events = polled["events"].as_array().unwrap();
        assert!(events.iter().any(|e| e["kind"] == "ext" && e["url"] == "https://nameswallet.app/browser"));
        assert!(events.iter().any(|e| e["kind"] == "lns" && e["url"] == "lns://jef/about"));
        assert!(events.iter().any(|e| e["kind"] == "dl" && e["cid"] == CID_LGX && e["filename"] == "app.lgx"));

        let stats = mgr.site_stats(tok).unwrap();
        assert_eq!(stats["mode"], "links");
        assert!(stats["verified_files"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn basecamp_storage_module_blob_ready_and_tamper_refusal() {
        let html = b"<!doctype html><html><body><h1>From Storage Module</h1></body></html>";
        let good_sha = sha256_hex(html);
        let pending_paths: Arc<Mutex<HashMap<String, PathBuf>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let paths_cb = Arc::clone(&pending_paths);

        let downloader: BasecampDownloader = Arc::new(move |cid, tmp_path| {
            paths_cb.lock().unwrap().insert(cid.to_owned(), tmp_path.to_path_buf());
            Ok(())
        });

        let mut mgr = SiteServerManager::with_cache_dir(temp_cache_dir("bc"), downloader);
        let opened = mgr
            .site_open(SiteSpec {
                kind: "cid".to_owned(),
                host: CID_INDEX.to_owned(),
                site_base: format!("cid://{CID_INDEX}"),
                mode: "cid".to_owned(),
                root_cid: CID_INDEX.to_owned(),
                root_sha256: good_sha,
                site_type: "single".to_owned(),
                backend: "basecamp".to_owned(),
                storage_api: String::new(),
                onchain_html: None,
                onchain_links: None,
                title: None,
                initial_path: "/".to_owned(),
            })
            .unwrap();
        let port = opened["port"].as_u64().unwrap() as u16;
        let tok = opened["token"].as_str().unwrap().to_owned();
        let tok_req = tok.clone();

        let client_handle = thread::spawn(move || {
            send_raw_http(
                port,
                &format!("GET /{tok_req}/ HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
            )
        });

        // Wait briefly for the downloader hook to receive the temp path, write verified bytes, and call site_blob_ready
        let tmp_path = loop {
            if let Some(p) = pending_paths.lock().unwrap().get(CID_INDEX).cloned() {
                break p;
            }
            thread::sleep(Duration::from_millis(10));
        };
        fs::write(&tmp_path, html).unwrap();
        assert!(mgr.site_blob_ready(CID_INDEX, "", true, ""));

        let resp = client_handle.join().unwrap();
        assert_eq!(resp.status_code, 200);
        assert_mandatory_security_headers(&resp);
        assert!(String::from_utf8_lossy(&resp.body).contains("From Storage Module"));

        // Now test tampered bytes via site_blob_ready on a second site
        let opened_bad = mgr
            .site_open(SiteSpec {
                kind: "cid".to_owned(),
                host: CID_TAMPERED.to_owned(),
                site_base: format!("cid://{CID_TAMPERED}"),
                mode: "cid".to_owned(),
                root_cid: CID_TAMPERED.to_owned(),
                root_sha256: "f".repeat(64),
                site_type: "single".to_owned(),
                backend: "basecamp".to_owned(),
                storage_api: String::new(),
                onchain_html: None,
                onchain_links: None,
                title: None,
                initial_path: "/".to_owned(),
            })
            .unwrap();
        let port_bad = opened_bad["port"].as_u64().unwrap() as u16;
        let tok_bad = opened_bad["token"].as_str().unwrap().to_owned();
        let tok_bad_req = tok_bad.clone();

        let bad_client = thread::spawn(move || {
            send_raw_http(
                port_bad,
                &format!("GET /{tok_bad_req}/ HTTP/1.1\r\nHost: 127.0.0.1:{port_bad}\r\n\r\n"),
            )
        });

        let bad_tmp = loop {
            if let Some(p) = pending_paths.lock().unwrap().get(CID_TAMPERED).cloned() {
                break p;
            }
            thread::sleep(Duration::from_millis(10));
        };
        fs::write(&bad_tmp, b"TAMPERED STORAGE MODULE BYTES").unwrap();
        assert!(mgr.site_blob_ready(CID_TAMPERED, "", true, ""));

        let bad_resp = bad_client.join().unwrap();
        assert_eq!(bad_resp.status_code, 502);
        assert_mandatory_security_headers(&bad_resp);
        assert!(!String::from_utf8_lossy(&bad_resp.body).contains("TAMPERED STORAGE MODULE BYTES"));
        assert!(!bad_tmp.exists());
    }
}
