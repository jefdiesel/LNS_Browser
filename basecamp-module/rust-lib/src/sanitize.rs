//! Strict allowlist HTML & Markdown sanitizer for native Basecamp QML RichText rendering.
//!
//! Security properties:
//! - Strips `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<input>`, `<foreignObject>`,
//!   event handlers (`on*=`), and all external network subresources (`<img src="https://...">`,
//!   CSS `url(...)`, `@import`, etc.).
//! - Safely extracts page palette (`bg_color`, `fg_color`, `link_color`) and safe inline CSS
//!   properties (`color`, `background-color`, `font-size`, `font-weight`, `font-style`,
//!   `font-family`, `text-align`, `text-decoration`) from `<style>` and inline `style=""` so pages
//!   keep their colors and typography with zero JavaScript and zero external requests.
//! - Safely converts clean inline `<svg>` (no scripts, event handlers, foreignObject, or external
//!   URLs) and `data:image/*` inline images into ordered `RenderBlock` items rendered natively by
//!   QML `Image`.
//! - Allows `<a href>` ONLY for `lns://...`, `cid://...`, relative site paths (rewritten against
//!   `site_base` + `current_path`), and well-formed `https://...` outbound links (handled by QML
//!   via a click-to-confirm bar — never auto-fetched). Rejects `http://`, `javascript:`, `data:`,
//!   `file:`, `mailto:`, and credentialed URLs (`https://user:pass@...`).

use std::collections::{HashMap, HashSet};

pub const MAX_INPUT: usize = 128 * 1024;
pub const MAX_OUTPUT: usize = 256 * 1024;
const MAX_DEPTH: usize = 32;
const MAX_TITLE: usize = 200;
const MAX_HREF: usize = 1024;
const MAX_SVG_BYTES: usize = 64 * 1024;
const MAX_DATA_IMG_BYTES: usize = 128 * 1024;

const ALLOWED: [&str; 29] = [
    "h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "ol", "li", "b", "strong", "i", "em", "code",
    "pre", "blockquote", "table", "thead", "tbody", "tr", "th", "td", "span", "div", "a", "u",
    "small", "font",
];
const VOID: [&str; 2] = ["br", "hr"];
const STRIP_CONTENT: [&str; 10] = [
    "script", "textarea", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext", "math",
    "head",
];

#[derive(Debug, Clone, PartialEq)]
pub struct SvgOp {
    pub op: String, // "path" | "rect" | "circle" | "polygon"
    pub d: Option<String>,
    pub x: f64,
    pub y: f64,
    pub w: Option<f64>,
    pub h: Option<f64>,
    pub r: Option<f64>,
    pub points: Option<String>,
    pub fill: String,
    pub opacity: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DownloadLink {
    pub href: String,
    pub cid: Option<String>,
    pub path: Option<String>,
    pub filename: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderBlock {
    pub kind: String, // "html" | "svg" | "image"
    pub html: Option<String>,
    pub data_uri: Option<String>,
    pub src_cid: Option<String>,
    pub src_path: Option<String>,
    pub alt: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub vb_x: Option<f64>,
    pub vb_y: Option<f64>,
    pub vb_w: Option<f64>,
    pub vb_h: Option<f64>,
    pub ops: Vec<SvgOp>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sanitized {
    pub html: String,
    pub title: Option<String>,
    pub truncated: bool,
    pub bg_color: Option<String>,
    pub fg_color: Option<String>,
    pub link_color: Option<String>,
    pub blocks: Vec<RenderBlock>,
    pub downloads: Vec<DownloadLink>,
}

#[derive(Default, Debug, Clone)]
struct StyleSheet {
    bg_color: Option<String>,
    fg_color: Option<String>,
    link_color: Option<String>,
    tag_styles: HashMap<String, HashMap<String, String>>,
    class_styles: HashMap<String, HashMap<String, String>>,
    hidden_classes: HashSet<String>,
}

/// Sanitizes untrusted HTML into safe Qt RichText, extracted safe palette, and ordered render blocks.
pub fn sanitize_html(source: &str, site_base: &str, current_path: &str) -> Sanitized {
    let mut cut = source.len().min(MAX_INPUT);
    while !source.is_char_boundary(cut) {
        cut -= 1;
    }
    let input = &source[..cut];
    let mut sheet = extract_stylesheets(input);
    let has_safe_svg = input.to_ascii_lowercase().contains("<svg");

    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut blocks: Vec<RenderBlock> = Vec::new();
    let mut downloads: Vec<DownloadLink> = Vec::new();
    let mut open: Vec<&'static str> = Vec::new();
    let mut title: Option<String> = None;
    let mut truncated = cut < source.len();
    let mut skip_hidden_depth: usize = 0;
    let mut i = 0;

    while i < bytes.len() {
        if out.len() >= MAX_OUTPUT {
            truncated = true;
            break;
        }
        if bytes[i] != b'<' {
            let end = memchr(bytes, i, b'<').unwrap_or(bytes.len());
            if skip_hidden_depth == 0 {
                push_escaped(&mut out, &decode_entities(&input[i..end]));
            }
            i = end;
            continue;
        }
        // HTML comment <!-- ... -->
        if input[i..].starts_with("<!--") {
            i = input[i + 4..]
                .find("-->")
                .map(|off| i + 4 + off + 3)
                .unwrap_or(bytes.len());
            continue;
        }
        // Doctype / declaration <! ... > or processing instruction <? ... >
        if bytes.get(i + 1).is_some_and(|&b| b == b'!' || b == b'?') {
            i = memchr(bytes, i + 2, b'>').map(|p| p + 1).unwrap_or(bytes.len());
            continue;
        }
        let Some(gt) = find_tag_end(bytes, i + 1) else {
            if skip_hidden_depth == 0 {
                push_escaped(&mut out, &input[i..]);
            }
            break;
        };
        let tag_start = i;
        let tag_body = input[i + 1..gt].trim();
        i = gt + 1;

        if tag_body.is_empty() {
            continue;
        }
        let is_close = tag_body.starts_with('/');
        let is_self_closing = !is_close && tag_body.ends_with('/');
        let rest = if is_close {
            tag_body[1..].trim_start()
        } else {
            tag_body.trim_end_matches('/').trim()
        };
        let name_end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(rest.len());
        let tag_name = rest[..name_end].to_ascii_lowercase();
        let attrs = &rest[name_end..];

        // Extract <title> even inside <head>, and skip <style> (already parsed)
        if !is_close && tag_name == "title" {
            let (content_end, next_i) = find_raw_close(input, i, "title");
            if title.is_none() {
                let raw_t = decode_entities(input[i..content_end].trim());
                let clean_t: String = raw_t.chars().take(MAX_TITLE).collect();
                if !clean_t.is_empty() {
                    title = Some(clean_t);
                }
            }
            i = next_i;
            continue;
        }
        if !is_close && tag_name == "style" {
            let (_, next_i) = find_raw_close(input, i, "style");
            i = next_i;
            continue;
        }
        if !is_close && tag_name == "head" {
            // Walk inside <head> only to capture <title>; skip other head tags.
            let (head_end, next_i) = find_raw_close(input, i, "head");
            if title.is_none() {
                title = extract_title_from_slice(&input[i..head_end]);
            }
            i = next_i;
            continue;
        }
        if !is_close && STRIP_CONTENT.contains(&tag_name.as_str()) {
            let (_, next_i) = find_raw_close(input, i, &tag_name);
            i = next_i;
            continue;
        }

        // Capture body background/color attributes
        if !is_close && tag_name == "body" {
            if let Some(bg) = extract_attr(attrs, "bgcolor").and_then(|v| sanitize_color(&v)) {
                sheet.bg_color = Some(bg);
            }
            if let Some(fg) = extract_attr(attrs, "text").and_then(|v| sanitize_color(&v)) {
                sheet.fg_color = Some(fg);
            }
            if let Some(st) = extract_attr(attrs, "style") {
                for (k, v) in parse_css_declarations(&st) {
                    if (k == "background" || k == "background-color") && sheet.bg_color.is_none() {
                        if let Some(c) = sanitize_color(&v) {
                            sheet.bg_color = Some(c);
                        }
                    } else if k == "color" && sheet.fg_color.is_none() {
                        if let Some(c) = sanitize_color(&v) {
                            sheet.fg_color = Some(c);
                        }
                    }
                }
            }
            continue;
        }

        // Handle safe inline <svg>...</svg>
        if !is_close && tag_name == "svg" {
            let (svg_block, next_i) = if is_self_closing {
                (&input[tag_start..gt + 1], gt + 1)
            } else {
                let (_, end_i) = find_raw_close(input, i, "svg");
                (&input[tag_start..end_i], end_i)
            };
            i = next_i;
            if skip_hidden_depth == 0 {
                if let Some(img_block) = sanitize_svg_block(svg_block, attrs, &sheet) {
                    flush_html_block(&mut out, &mut open, &mut blocks);
                    blocks.push(img_block);
                }
            }
            continue;
        }

        // Handle safe inline <img src="data:image/...">, <img src="cid://...">, and relative <img src="./...">
        // (strictly blocks external http:// / https:// URLs)
        if !is_close && tag_name == "img" {
            if skip_hidden_depth == 0 {
                if let Some(img_block) = sanitize_img_block(attrs, site_base, current_path) {
                    flush_html_block(&mut out, &mut open, &mut blocks);
                    blocks.push(img_block);
                }
            }
            continue;
        }

        // Track skipped hidden blocks (e.g. `.sr` screen-reader fallback when SVG is present)
        if skip_hidden_depth > 0 {
            if is_close {
                skip_hidden_depth -= 1;
            } else if !is_self_closing && !VOID.contains(&tag_name.as_str()) {
                skip_hidden_depth += 1;
            }
            continue;
        }

        if is_close {
            if let Some(pos) = open.iter().rposition(|&t| t == tag_name) {
                for popped in open.drain(pos..).rev() {
                    out.push_str("</");
                    out.push_str(popped);
                    out.push('>');
                }
            }
            continue;
        }

        // Skip screen-reader-only / display:none elements (when an SVG graphic is present or display:none)
        if is_element_hidden(attrs, &sheet, has_safe_svg) && !is_self_closing {
            skip_hidden_depth = 1;
            continue;
        }

        if let Some(&void_tag) = VOID.iter().find(|&&t| t == tag_name) {
            out.push('<');
            out.push_str(void_tag);
            out.push('>');
            continue;
        }

        let Some(&allowed) = ALLOWED.iter().find(|&&t| t == tag_name) else {
            continue;
        };
        if open.len() >= MAX_DEPTH {
            continue;
        }

        let inline_style = compute_safe_style(allowed, attrs, &sheet);

        if allowed == "a" {
            if let Some(raw_href) = extract_attr(attrs, "href") {
                if let Some(safe_href) = resolve_safe_link(&raw_href, site_base, current_path) {
                    if let Some(dl) = extract_download_link(&safe_href, attrs, site_base) {
                        downloads.push(dl);
                    }
                    out.push_str("<a href=\"");
                    push_escaped(&mut out, &safe_href);
                    out.push('"');
                    if let Some(st) = inline_style {
                        out.push_str(" style=\"");
                        push_escaped(&mut out, &st);
                        out.push('"');
                    }
                    out.push('>');
                    if !is_self_closing {
                        open.push("a");
                    } else {
                        out.push_str("</a>");
                    }
                }
            }
        } else {
            out.push('<');
            out.push_str(allowed);
            if let Some(st) = inline_style {
                out.push_str(" style=\"");
                push_escaped(&mut out, &st);
                out.push('"');
            }
            out.push('>');
            if !is_self_closing {
                open.push(allowed);
            } else {
                out.push_str("</");
                out.push_str(allowed);
                out.push('>');
            }
        }
    }

    for popped in open.drain(..).rev() {
        out.push_str("</");
        out.push_str(popped);
        out.push('>');
    }

    if !out.trim().is_empty() {
        blocks.push(RenderBlock {
            kind: "html".to_owned(),
            html: Some(out.clone()),
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
        });
    }

    // Build combined HTML string for backward compatibility with older QML builds
    let combined_html = blocks
        .iter()
        .filter_map(|b| b.html.as_deref())
        .collect::<Vec<_>>()
        .join("");

    Sanitized {
        html: combined_html,
        title,
        truncated,
        bg_color: sheet.bg_color,
        fg_color: sheet.fg_color,
        link_color: sheet.link_color,
        blocks,
        downloads,
    }
}

/// Converts simple Markdown into safe Qt RichText with `lns://`, `cid://`, `https://`, and relative links.
pub fn markdown_to_safe_html(source: &str, site_base: &str, current_path: &str) -> Sanitized {
    let mut cut = source.len().min(MAX_INPUT);
    while !source.is_char_boundary(cut) {
        cut -= 1;
    }
    let truncated = cut < source.len();
    let input = &source[..cut];

    let mut out = String::new();
    let mut title = None;
    let mut in_code = false;
    let mut in_list = false;

    for line in input.lines() {
        if out.len() >= MAX_OUTPUT {
            break;
        }
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            if in_code {
                out.push_str("</code></pre>");
                in_code = false;
            } else {
                out.push_str("<pre><code>");
                in_code = true;
            }
            continue;
        }
        if in_code {
            push_escaped(&mut out, line);
            out.push('\n');
            continue;
        }
        if trimmed.is_empty() {
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("# ") {
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            if title.is_none() {
                title = Some(rest.chars().take(MAX_TITLE).collect());
            }
            out.push_str("<h1>");
            push_md_inline(&mut out, rest, site_base, current_path);
            out.push_str("</h1>");
        } else if let Some(rest) = trimmed.strip_prefix("## ") {
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            out.push_str("<h2>");
            push_md_inline(&mut out, rest, site_base, current_path);
            out.push_str("</h2>");
        } else if let Some(rest) = trimmed.strip_prefix("### ") {
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            out.push_str("<h3>");
            push_md_inline(&mut out, rest, site_base, current_path);
            out.push_str("</h3>");
        } else if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* "))
        {
            if !in_list {
                out.push_str("<ul>");
                in_list = true;
            }
            out.push_str("<li>");
            push_md_inline(&mut out, rest, site_base, current_path);
            out.push_str("</li>");
        } else {
            if in_list {
                out.push_str("</ul>");
                in_list = false;
            }
            out.push_str("<p>");
            push_md_inline(&mut out, trimmed, site_base, current_path);
            out.push_str("</p>");
        }
    }
    if in_list {
        out.push_str("</ul>");
    }
    if in_code {
        out.push_str("</code></pre>");
    }
    let blocks = if out.trim().is_empty() {
        Vec::new()
    } else {
        vec![RenderBlock {
            kind: "html".to_owned(),
            html: Some(out.clone()),
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
        }]
    };
    Sanitized {
        html: out,
        title,
        truncated,
        bg_color: None,
        fg_color: None,
        link_color: None,
        blocks,
        downloads: Vec::new(),
    }
}

/// Resolves a link href to a safe `lns://`, `cid://`, relative site URL, or click-to-confirm `https://` URL.
/// Rejects `http://`, `javascript:`, `data:`, `file:`, `mailto:`, `basecamp:`, and credentialed URLs.
pub fn resolve_safe_link(raw: &str, site_base: &str, current_path: &str) -> Option<String> {
    let trimmed = decode_entities(raw.trim());
    if trimmed.is_empty() || trimmed.len() > MAX_HREF {
        return None;
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("lns://") || lower.starts_with("cid://") {
        return Some(trimmed);
    }
    if lower.starts_with("https://") {
        let rest = &trimmed[8..];
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        // Require a non-empty hostname without whitespace, embedded user:pass@, or weird chars
        if authority.is_empty()
            || authority.contains('@')
            || authority.chars().any(|c| c.is_whitespace())
            || !authority.contains('.')
        {
            return None;
        }
        return Some(trimmed);
    }
    // Reject any other explicit scheme (http:, javascript:, data:, file:, mailto:, basecamp:, etc.)
    if trimmed.contains(':') || trimmed.starts_with("//") || trimmed.starts_with('#') {
        return None;
    }
    // Relative path within the same LNS / CID site
    let base = site_base.trim_end_matches('/');
    if base.is_empty() {
        return None;
    }
    let (without_frag, fragment) = match trimmed.find('#') {
        Some(idx) => (&trimmed[..idx], &trimmed[idx..]),
        None => (trimmed.as_str(), ""),
    };
    if fragment
        .chars()
        .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>'))
    {
        return None;
    }
    let path_only = without_frag.split('?').next().unwrap_or("");
    let raw_joined = if path_only.starts_with('/') {
        path_only.to_owned()
    } else {
        let clean_cur = current_path.split(['?', '#']).next().unwrap_or("/");
        let dir = clean_cur
            .rsplit_once('/')
            .map(|(d, _)| d)
            .unwrap_or("");
        format!("{dir}/{path_only}")
    };
    let norm = crate::links::normalize_links_path(&raw_joined).ok()?;
    Some(format!("{base}{}{fragment}", norm.path))
}

pub fn normalize_site_path(raw: &str) -> String {
    let clean = raw.split(['?', '#']).next().unwrap_or("/");
    let mut parts: Vec<&str> = Vec::new();
    for seg in clean.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    format!("/{}", parts.join("/"))
}

fn flush_html_block(out: &mut String, open: &mut Vec<&'static str>, blocks: &mut Vec<RenderBlock>) {
    if out.trim().is_empty() {
        out.clear();
        return;
    }
    let saved = open.clone();
    for popped in open.drain(..).rev() {
        out.push_str("</");
        out.push_str(popped);
        out.push('>');
    }
    blocks.push(RenderBlock {
        kind: "html".to_owned(),
        html: Some(std::mem::take(out)),
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
    });
    // Re-open surrounding container tags for the next HTML chunk
    for tag in saved {
        if tag != "a" {
            out.push('<');
            out.push_str(tag);
            out.push('>');
            open.push(tag);
        }
    }
}

fn find_raw_close(input: &str, start: usize, tag_name: &str) -> (usize, usize) {
    let bytes = input.as_bytes();
    let close_needle = format!("</{tag_name}");
    let lower_rem = input[start..].to_ascii_lowercase();
    if let Some(pos) = lower_rem.find(&close_needle) {
        let after = start + pos + close_needle.len();
        let end_gt = memchr(bytes, after, b'>').map(|p| p + 1).unwrap_or(bytes.len());
        (start + pos, end_gt)
    } else {
        (bytes.len(), bytes.len())
    }
}

fn extract_title_from_slice(slice: &str) -> Option<String> {
    let lower = slice.to_ascii_lowercase();
    let start_tag = lower.find("<title")?;
    let gt = slice[start_tag..].find('>')? + start_tag + 1;
    let end_tag = lower[gt..].find("</title")? + gt;
    let raw_t = decode_entities(slice[gt..end_tag].trim());
    let clean_t: String = raw_t.chars().take(MAX_TITLE).collect();
    if clean_t.is_empty() {
        None
    } else {
        Some(clean_t)
    }
}

fn extract_stylesheets(input: &str) -> StyleSheet {
    let mut sheet = StyleSheet::default();
    let lower = input.to_ascii_lowercase();
    let mut pos = 0;
    while let Some(rel) = lower[pos..].find("<style") {
        let tag_start = pos + rel;
        let Some(gt_rel) = input[tag_start..].find('>') else {
            break;
        };
        let content_start = tag_start + gt_rel + 1;
        let (content_end, next_i) = find_raw_close(input, content_start, "style");
        parse_css_sheet(&input[content_start..content_end], &mut sheet);
        pos = next_i;
    }
    sheet
}

fn strip_css_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        if let Some(end) = rest[start + 2..].find("*/") {
            rest = &rest[start + 2 + end + 2..];
        } else {
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    out
}

fn parse_css_sheet(raw_css: &str, sheet: &mut StyleSheet) {
    let css = strip_css_comments(raw_css);
    let mut rest = css.as_str();
    while let Some(open_brace) = rest.find('{') {
        let selector_raw = rest[..open_brace].trim();
        let after_open = &rest[open_brace + 1..];
        let Some(close_brace) = after_open.find('}') else {
            break;
        };
        let decl_block = &after_open[..close_brace];
        rest = &after_open[close_brace + 1..];

        // Skip @-rules like @media, @keyframes, @font-face, @import
        if selector_raw.starts_with('@') {
            continue;
        }
        let decls = parse_css_declarations(decl_block);
        if decls.is_empty() {
            continue;
        }

        let is_hidden_rule = decls.iter().any(|(k, v)| {
            (k == "display" && v.eq_ignore_ascii_case("none"))
                || (k == "clip" && v.contains("rect(0"))
                || (k == "visibility" && v.eq_ignore_ascii_case("hidden"))
        });

        for sel_part in selector_raw.split(',') {
            let sel = sel_part.trim().to_ascii_lowercase();
            if sel.is_empty() || sel.contains(':') {
                continue;
            }
            if sel == "body" || sel == "html" || sel == "html, body" {
                for (k, v) in &decls {
                    if k == "background" || k == "background-color" {
                        if let Some(c) = sanitize_color(v) {
                            sheet.bg_color = Some(c);
                        }
                    } else if k == "color" {
                        if let Some(c) = sanitize_color(v) {
                            sheet.fg_color = Some(c);
                        }
                    }
                }
            } else if sel == "a" || sel.ends_with(" a") {
                for (k, v) in &decls {
                    if k == "color" {
                        if let Some(c) = sanitize_color(v) {
                            sheet.link_color = Some(c);
                        }
                    }
                }
                if sel == "a" {
                    merge_safe_decls(sheet.tag_styles.entry("a".to_owned()).or_default(), &decls);
                }
            } else if let Some(cls) = sel.strip_prefix('.') {
                if cls.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                    if is_hidden_rule {
                        sheet.hidden_classes.insert(cls.to_owned());
                    }
                    merge_safe_decls(
                        sheet.class_styles.entry(cls.to_owned()).or_default(),
                        &decls,
                    );
                }
            } else if sel.chars().all(|c| c.is_ascii_alphanumeric()) {
                merge_safe_decls(sheet.tag_styles.entry(sel).or_default(), &decls);
            }
        }
    }
}

fn parse_css_declarations(block: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in block.split(';') {
        let Some((k, v)) = part.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().trim_end_matches("!important").trim();
        if key.is_empty() || val.is_empty() {
            continue;
        }
        let lower_v = val.to_ascii_lowercase();
        // Hard block any external / script CSS constructs
        if lower_v.contains("url(")
            || lower_v.contains("expression(")
            || lower_v.contains("javascript:")
            || lower_v.contains("http://")
            || lower_v.contains("https://")
            || lower_v.contains("@import")
            || val.contains('<')
            || val.contains('>')
            || val.contains('"')
        {
            continue;
        }
        out.push((key, val.to_owned()));
    }
    out
}

fn merge_safe_decls(target: &mut HashMap<String, String>, decls: &[(String, String)]) {
    for (k, v) in decls {
        if let Some((sk, sv)) = sanitize_css_prop(k, v) {
            target.insert(sk.to_owned(), sv);
        }
    }
}

fn sanitize_css_prop(key: &str, val: &str) -> Option<(&'static str, String)> {
    match key {
        "color" => sanitize_color(val).map(|c| ("color", c)),
        "fill" => sanitize_color(val).map(|c| ("fill", c)),
        "opacity" | "fill-opacity" => val
            .trim()
            .parse::<f64>()
            .ok()
            .map(|n| ("opacity", format!("{}", n.clamp(0.0, 1.0)))),
        "background" | "background-color" => sanitize_color(val).map(|c| ("background-color", c)),
        "font-weight" => {
            let l = val.to_ascii_lowercase();
            if matches!(
                l.as_str(),
                "normal" | "bold" | "100" | "200" | "300" | "400" | "500" | "600" | "700" | "800" | "900"
            ) {
                Some(("font-weight", l))
            } else {
                None
            }
        }
        "font-style" => {
            let l = val.to_ascii_lowercase();
            if matches!(l.as_str(), "normal" | "italic" | "oblique") {
                Some(("font-style", l))
            } else {
                None
            }
        }
        "text-align" => {
            let l = val.to_ascii_lowercase();
            if matches!(l.as_str(), "left" | "right" | "center" | "justify") {
                Some(("text-align", l))
            } else {
                None
            }
        }
        "text-decoration" => {
            let l = val.to_ascii_lowercase();
            if matches!(l.as_str(), "none" | "underline" | "line-through") {
                Some(("text-decoration", l))
            } else {
                None
            }
        }
        "font-size" => sanitize_font_size(val).map(|s| ("font-size", s)),
        "font-family" => {
            let clean: String = val
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | ',' | '-'))
                .take(80)
                .collect();
            if clean.trim().is_empty() {
                None
            } else {
                Some(("font-family", clean.trim().to_owned()))
            }
        }
        _ => None,
    }
}

fn sanitize_font_size(val: &str) -> Option<String> {
    let l = val.trim().to_ascii_lowercase();
    if let Some(num) = l.strip_suffix("px") {
        let px: f32 = num.trim().parse().ok()?;
        let clamped = px.clamp(10.0, 48.0).round() as u32;
        return Some(format!("{clamped}px"));
    }
    if let Some(num) = l.strip_suffix("rem").or_else(|| l.strip_suffix("em")) {
        let em: f32 = num.trim().parse().ok()?;
        let clamped = (em * 16.0).clamp(10.0, 48.0).round() as u32;
        return Some(format!("{clamped}px"));
    }
    None
}

fn sanitize_color(raw: &str) -> Option<String> {
    // Allow first token for shorthand `background: #ffffff none ...`
    let token = raw.split_whitespace().next()?.trim().to_ascii_lowercase();
    if let Some(hex) = token.strip_prefix('#') {
        if hex.len() == 3 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let chars: Vec<char> = hex.chars().collect();
            return Some(format!(
                "#{0}{0}{1}{1}{2}{2}",
                chars[0], chars[1], chars[2]
            ));
        }
        if hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(format!("#{hex}"));
        }
        return None;
    }
    let named = match token.as_str() {
        "white" => "#ffffff",
        "black" => "#000000",
        "red" => "#dc2626",
        "blue" => "#0055ff",
        "green" => "#16a34a",
        "yellow" => "#eab308",
        "orange" => "#ea580c",
        "purple" => "#9333ea",
        "gray" | "grey" => "#6b7280",
        "navy" => "#1e3a8a",
        "teal" => "#0d9488",
        "cyan" | "aqua" => "#06b6d4",
        "magenta" | "fuchsia" => "#d946ef",
        "silver" => "#cbd5e1",
        "maroon" => "#7f1d1d",
        _ => return None,
    };
    Some(named.to_owned())
}

fn is_element_hidden(attrs: &str, sheet: &StyleSheet, has_svg: bool) -> bool {
    if let Some(st) = extract_attr(attrs, "style") {
        for (k, v) in parse_css_declarations(&st) {
            if k == "display" && v.eq_ignore_ascii_case("none") {
                return true;
            }
        }
    }
    if has_svg {
        if let Some(cls_attr) = extract_attr(attrs, "class") {
            for cls in cls_attr.split_whitespace() {
                let low = cls.to_ascii_lowercase();
                if sheet.hidden_classes.contains(&low)
                    || matches!(low.as_str(), "sr" | "sr-only" | "visually-hidden")
                {
                    return true;
                }
            }
        }
    }
    false
}

fn compute_safe_style(tag: &str, attrs: &str, sheet: &StyleSheet) -> Option<String> {
    let mut merged: HashMap<String, String> = HashMap::new();
    if let Some(tag_map) = sheet.tag_styles.get(tag) {
        for (k, v) in tag_map {
            if k != "fill" {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(cls_attr) = extract_attr(attrs, "class") {
        for cls in cls_attr.split_whitespace() {
            if let Some(cls_map) = sheet.class_styles.get(&cls.to_ascii_lowercase()) {
                for (k, v) in cls_map {
                    if k != "fill" {
                        merged.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    if tag == "font" {
        if let Some(c) = extract_attr(attrs, "color").and_then(|v| sanitize_color(&v)) {
            merged.insert("color".to_owned(), c);
        }
    }
    if let Some(st) = extract_attr(attrs, "style") {
        for (k, v) in parse_css_declarations(&st) {
            if let Some((sk, sv)) = sanitize_css_prop(&k, &v) {
                if sk != "fill" {
                    merged.insert(sk.to_owned(), sv);
                }
            }
        }
    }
    if merged.is_empty() {
        return None;
    }
    let mut keys: Vec<&String> = merged.keys().collect();
    keys.sort();
    let joined: Vec<String> = keys
        .into_iter()
        .map(|k| format!("{k}:{}", merged[k]))
        .collect();
    Some(joined.join(";"))
}

fn sanitize_svg_block(raw_svg: &str, attrs: &str, sheet: &StyleSheet) -> Option<RenderBlock> {
    if raw_svg.len() > MAX_SVG_BYTES {
        return None;
    }
    let lower = raw_svg.to_ascii_lowercase();
    // Hard security gate: reject scripts, event handlers, foreignObject, external refs, entities
    const FORBIDDEN_SVG: [&str; 17] = [
        "<script",
        "<foreignobject",
        "<iframe",
        "<embed",
        "<object",
        "<image",
        "<animate",
        "<set",
        "<!entity",
        "<!doctype",
        "javascript:",
        "http://",
        "https://",
        "data:",
        "file:",
        "url(http",
        "url(data",
    ];
    if FORBIDDEN_SVG.iter().any(|bad| lower.contains(bad)) {
        return None;
    }
    if contains_event_handler(&lower) {
        return None;
    }

    // Determine fill color from inline attributes or stylesheet rules
    let mut resolved_fill: Option<String> = extract_attr(attrs, "fill").and_then(|v| sanitize_color(&v));
    if resolved_fill.is_none() {
        if let Some(cls_attr) = extract_attr(attrs, "class") {
            for cls in cls_attr.split_whitespace() {
                if let Some(cls_map) = sheet.class_styles.get(&cls.to_ascii_lowercase()) {
                    if let Some(c) = cls_map.get("fill").or_else(|| cls_map.get("color")) {
                        resolved_fill = Some(c.clone());
                    }
                }
            }
        }
    }
    if resolved_fill.is_none() {
        if let Some(svg_map) = sheet.tag_styles.get("svg") {
            resolved_fill = svg_map
                .get("fill")
                .or_else(|| svg_map.get("color"))
                .cloned();
        }
    }
    if resolved_fill.is_none() {
        resolved_fill = sheet.fg_color.clone();
    }

    // Parse viewBox or width/height so QML Canvas can size cleanly
    let (vb_x, vb_y, vb_w, vb_h) = extract_attr(attrs, "viewBox")
        .and_then(|vb| parse_viewbox_full(&vb))
        .unwrap_or((0.0, 0.0, 600.0, 120.0));
    let width = extract_attr(attrs, "width")
        .and_then(|v| parse_px_u32(&v))
        .unwrap_or_else(|| {
            if vb_w < 120.0 {
                ((vb_w * 10.0).ceil() as u32).min(760)
            } else {
                (vb_w.ceil() as u32).min(760)
            }
        });
    let height = extract_attr(attrs, "height")
        .and_then(|v| parse_px_u32(&v))
        .unwrap_or_else(|| {
            if vb_w > 0.0 {
                (((width as f64) * vb_h / vb_w).round() as u32).max(24)
            } else {
                120
            }
        });

    let alt = extract_attr(attrs, "aria-label").map(|a| decode_entities(&a));
    let default_fill = resolved_fill
        .clone()
        .or_else(|| sheet.link_color.clone())
        .or_else(|| sheet.fg_color.clone())
        .unwrap_or_else(|| "#0055ff".to_owned());

    // Extract safe geometric Canvas draw ops (works natively in QtQuick Canvas with zero QtSvg dependency)
    let ops = extract_svg_canvas_ops(raw_svg, &default_fill, sheet);
    if ops.is_empty() {
        // Fallback: if no drawable primitives were found, render aria-label text if present
        if let Some(ref label) = alt {
            if !label.trim().is_empty() {
                let mut h = String::from("<h2>");
                push_escaped(&mut h, label.trim());
                h.push_str("</h2>");
                return Some(RenderBlock {
                    kind: "html".to_owned(),
                    html: Some(h),
                    data_uri: None,
                    src_cid: None,
                    src_path: None,
                    alt,
                    width: None,
                    height: None,
                    vb_x: None,
                    vb_y: None,
                    vb_w: None,
                    vb_h: None,
                    ops: Vec::new(),
                });
            }
        }
        return None;
    }

    // Patch <svg ...> opening tag for optional data_uri fallback
    let mut clean_svg = raw_svg.to_owned();
    if let Some(first_gt) = clean_svg.find('>') {
        let mut extra = String::new();
        let open_lower = clean_svg[..first_gt].to_ascii_lowercase();
        if !open_lower.contains("xmlns=") {
            extra.push_str(r#" xmlns="http://www.w3.org/2000/svg""#);
        }
        if !open_lower.contains("fill=") {
            extra.push_str(&format!(r#" fill="{default_fill}""#));
        }
        if !open_lower.contains("width=") {
            extra.push_str(&format!(r#" width="{width}""#));
        }
        if !open_lower.contains("height=") {
            extra.push_str(&format!(r#" height="{height}""#));
        }
        if !extra.is_empty() {
            clean_svg.insert_str(first_gt, &extra);
        }
    }
    clean_svg = clean_svg
        .replace("currentColor", &default_fill)
        .replace("currentcolor", &default_fill);

    let b64 = base64_encode(clean_svg.as_bytes());
    Some(RenderBlock {
        kind: "svg".to_owned(),
        html: None,
        data_uri: Some(format!("data:image/svg+xml;base64,{b64}")),
        src_cid: None,
        src_path: None,
        alt,
        width: Some(width),
        height: Some(height),
        vb_x: Some(vb_x),
        vb_y: Some(vb_y),
        vb_w: Some(vb_w),
        vb_h: Some(vb_h),
        ops,
    })
}

fn resolve_elem_fill(attrs: &str, default_fill: &str, sheet: &StyleSheet) -> Option<String> {
    if let Some(f) = extract_attr(attrs, "fill") {
        let low = f.trim().to_ascii_lowercase();
        if low == "none" || low == "transparent" {
            return None;
        }
        if low == "currentcolor" {
            return Some(default_fill.to_owned());
        }
        if let Some(c) = sanitize_color(&f) {
            return Some(c);
        }
    }
    if let Some(st) = extract_attr(attrs, "style") {
        for (k, v) in parse_css_declarations(&st) {
            if k == "fill" {
                let low = v.trim().to_ascii_lowercase();
                if low == "none" || low == "transparent" {
                    return None;
                }
                if let Some(c) = sanitize_color(&v) {
                    return Some(c);
                }
            }
        }
    }
    if let Some(cls_attr) = extract_attr(attrs, "class") {
        for cls in cls_attr.split_whitespace() {
            if let Some(cls_map) = sheet.class_styles.get(&cls.to_ascii_lowercase()) {
                if let Some(c) = cls_map.get("fill").or_else(|| cls_map.get("color")) {
                    return Some(c.clone());
                }
            }
        }
    }
    Some(default_fill.to_owned())
}

fn resolve_elem_opacity(attrs: &str, sheet: &StyleSheet) -> f64 {
    for key in ["opacity", "fill-opacity"] {
        if let Some(v) = extract_attr(attrs, key) {
            if let Ok(n) = v.trim().parse::<f64>() {
                return n.clamp(0.0, 1.0);
            }
        }
    }
    if let Some(st) = extract_attr(attrs, "style") {
        for (k, v) in parse_css_declarations(&st) {
            if k == "opacity" || k == "fill-opacity" {
                if let Ok(n) = v.trim().parse::<f64>() {
                    return n.clamp(0.0, 1.0);
                }
            }
        }
    }
    if let Some(cls_attr) = extract_attr(attrs, "class") {
        for cls in cls_attr.split_whitespace() {
            if let Some(cls_map) = sheet.class_styles.get(&cls.to_ascii_lowercase()) {
                if let Some(v) = cls_map.get("opacity") {
                    if let Ok(n) = v.parse::<f64>() {
                        return n.clamp(0.0, 1.0);
                    }
                }
            }
        }
    }
    1.0
}

fn parse_translate(transform: &str) -> (f64, f64) {
    let low = transform.to_ascii_lowercase();
    let Some(pos) = low.find("translate(") else {
        return (0.0, 0.0);
    };
    let after = &transform[pos + 10..];
    let Some(end) = after.find(')') else {
        return (0.0, 0.0);
    };
    let nums: Vec<f64> = after[..end]
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<f64>().ok())
        .collect();
    match nums.len() {
        0 => (0.0, 0.0),
        1 => (nums[0], 0.0),
        _ => (nums[0], nums[1]),
    }
}

fn extract_svg_canvas_ops(raw_svg: &str, default_fill: &str, sheet: &StyleSheet) -> Vec<SvgOp> {
    let mut defs: HashMap<String, String> = HashMap::new();
    let mut ops: Vec<SvgOp> = Vec::new();
    let bytes = raw_svg.as_bytes();
    let mut in_defs = false;
    let mut i = 0;

    while i < bytes.len() && ops.len() < 512 {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let Some(gt) = find_tag_end(bytes, i + 1) else {
            break;
        };
        let tag_body = raw_svg[i + 1..gt].trim();
        i = gt + 1;
        if tag_body.is_empty() || tag_body.starts_with('!') || tag_body.starts_with('?') {
            continue;
        }
        let is_close = tag_body.starts_with('/');
        let rest = if is_close {
            tag_body[1..].trim_start()
        } else {
            tag_body.trim_end_matches('/').trim()
        };
        let name_end = rest
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(rest.len());
        let tag = rest[..name_end].to_ascii_lowercase();
        let attrs = &rest[name_end..];

        if tag == "defs" {
            in_defs = !is_close;
            continue;
        }
        if is_close {
            continue;
        }

        if tag == "path" {
            let Some(d) = extract_attr(attrs, "d") else {
                continue;
            };
            if let Some(id) = extract_attr(attrs, "id") {
                defs.insert(id.trim().to_owned(), d.clone());
            }
            if in_defs {
                continue;
            }
            let Some(fill) = resolve_elem_fill(attrs, default_fill, sheet) else {
                continue;
            };
            let (tx, ty) = extract_attr(attrs, "transform")
                .map(|t| parse_translate(&t))
                .unwrap_or((0.0, 0.0));
            ops.push(SvgOp {
                op: "path".to_owned(),
                d: Some(d),
                x: tx,
                y: ty,
                w: None,
                h: None,
                r: None,
                points: None,
                fill,
                opacity: resolve_elem_opacity(attrs, sheet),
            });
        } else if tag == "use" && !in_defs {
            let href = extract_attr(attrs, "href")
                .or_else(|| extract_attr(attrs, "xlink:href"))
                .unwrap_or_default();
            let id = href.trim().trim_start_matches('#');
            let Some(d) = defs.get(id).cloned() else {
                continue;
            };
            let Some(fill) = resolve_elem_fill(attrs, default_fill, sheet) else {
                continue;
            };
            let x = extract_attr(attrs, "x")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let y = extract_attr(attrs, "y")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let (tx, ty) = extract_attr(attrs, "transform")
                .map(|t| parse_translate(&t))
                .unwrap_or((0.0, 0.0));
            ops.push(SvgOp {
                op: "path".to_owned(),
                d: Some(d),
                x: x + tx,
                y: y + ty,
                w: None,
                h: None,
                r: None,
                points: None,
                fill,
                opacity: resolve_elem_opacity(attrs, sheet),
            });
        } else if tag == "rect" && !in_defs {
            let Some(fill) = resolve_elem_fill(attrs, default_fill, sheet) else {
                continue;
            };
            let x = extract_attr(attrs, "x")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let y = extract_attr(attrs, "y")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let Some(w) = extract_attr(attrs, "width").and_then(|v| v.trim().trim_end_matches("px").parse::<f64>().ok()) else {
                continue;
            };
            let Some(h) = extract_attr(attrs, "height").and_then(|v| v.trim().trim_end_matches("px").parse::<f64>().ok()) else {
                continue;
            };
            if w > 0.0 && h > 0.0 {
                ops.push(SvgOp {
                    op: "rect".to_owned(),
                    d: None,
                    x,
                    y,
                    w: Some(w),
                    h: Some(h),
                    r: None,
                    points: None,
                    fill,
                    opacity: resolve_elem_opacity(attrs, sheet),
                });
            }
        } else if tag == "circle" && !in_defs {
            let Some(fill) = resolve_elem_fill(attrs, default_fill, sheet) else {
                continue;
            };
            let cx = extract_attr(attrs, "cx")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let cy = extract_attr(attrs, "cy")
                .and_then(|v| v.trim().parse::<f64>().ok())
                .unwrap_or(0.0);
            let Some(r) = extract_attr(attrs, "r").and_then(|v| v.trim().parse::<f64>().ok()) else {
                continue;
            };
            if r > 0.0 {
                ops.push(SvgOp {
                    op: "circle".to_owned(),
                    d: None,
                    x: cx,
                    y: cy,
                    w: None,
                    h: None,
                    r: Some(r),
                    points: None,
                    fill,
                    opacity: resolve_elem_opacity(attrs, sheet),
                });
            }
        } else if tag == "polygon" && !in_defs {
            let Some(fill) = resolve_elem_fill(attrs, default_fill, sheet) else {
                continue;
            };
            let Some(pts) = extract_attr(attrs, "points") else {
                continue;
            };
            if !pts.trim().is_empty() {
                ops.push(SvgOp {
                    op: "polygon".to_owned(),
                    d: None,
                    x: 0.0,
                    y: 0.0,
                    w: None,
                    h: None,
                    r: None,
                    points: Some(pts),
                    fill,
                    opacity: resolve_elem_opacity(attrs, sheet),
                });
            }
        }
    }
    ops
}

fn sanitize_img_block(attrs: &str, site_base: &str, current_path: &str) -> Option<RenderBlock> {
    if let Some(data_img) = sanitize_data_img(attrs) {
        return Some(data_img);
    }
    let raw_src = extract_attr(attrs, "src")?;
    let src = decode_entities(raw_src.trim());
    if src.is_empty() || src.len() > MAX_HREF || src.chars().any(|c| c.is_control()) {
        return None;
    }
    let alt = extract_attr(attrs, "alt").map(|a| decode_entities(&a));
    let width = extract_attr(attrs, "width").and_then(|v| parse_px_u32(&v));
    let height = extract_attr(attrs, "height").and_then(|v| parse_px_u32(&v));

    if src.len() >= 6 && src[..6].eq_ignore_ascii_case("cid://") {
        let cid = src[6..].split(['/', '?', '#']).next().unwrap_or("");
        if !crate::storage::is_valid_cid(cid) {
            return None;
        }
        return Some(RenderBlock {
            kind: "image".to_owned(),
            html: None,
            data_uri: None,
            src_cid: Some(cid.to_owned()),
            src_path: None,
            alt,
            width,
            height,
            vb_x: None,
            vb_y: None,
            vb_w: None,
            vb_h: None,
            ops: Vec::new(),
        });
    }

    if src.contains(':') || src.starts_with("//") || src.starts_with('#') || site_base.trim().is_empty() {
        return None;
    }
    let path_only = src.split(['?', '#']).next().unwrap_or("");
    if path_only.is_empty() {
        return None;
    }
    let resolved = if path_only.starts_with('/') {
        normalize_site_path(path_only)
    } else {
        let dir = current_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        normalize_site_path(&format!("{dir}/{path_only}"))
    };
    Some(RenderBlock {
        kind: "image".to_owned(),
        html: None,
        data_uri: None,
        src_cid: None,
        src_path: Some(resolved),
        alt,
        width,
        height,
        vb_x: None,
        vb_y: None,
        vb_w: None,
        vb_h: None,
        ops: Vec::new(),
    })
}

fn has_attr_flag(attrs: &str, target: &str) -> bool {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        let name = &attrs[name_start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let matched = name.eq_ignore_ascii_case(target);
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
                let q = bytes[i];
                i += 1;
                while i < bytes.len() && bytes[i] != q {
                    i += 1;
                }
                if i < bytes.len() {
                    i += 1;
                }
            } else {
                while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
            }
        }
        if matched {
            return true;
        }
    }
    false
}

fn extract_download_link(safe_href: &str, attrs: &str, site_base: &str) -> Option<DownloadLink> {
    let explicit_dl = has_attr_flag(attrs, "download");
    let dl_val = extract_attr(attrs, "download")
        .map(|v| decode_entities(v.trim()))
        .unwrap_or_default();

    if safe_href.len() >= 6 && safe_href[..6].eq_ignore_ascii_case("cid://") {
        let cid = safe_href[6..].split(['/', '?', '#']).next().unwrap_or("");
        if !crate::storage::is_valid_cid(cid) || !explicit_dl {
            return None;
        }
        let filename = if !dl_val.is_empty() {
            dl_val
        } else {
            format!("{}.bin", &cid[..cid.len().min(12)])
        };
        return Some(DownloadLink {
            href: format!("cid://{cid}"),
            cid: Some(cid.to_owned()),
            path: None,
            label: filename.clone(),
            filename,
        });
    }

    let base = site_base.trim_end_matches('/');
    if !base.is_empty() {
        if let Some(rel) = safe_href.strip_prefix(base).filter(|r| r.starts_with('/')) {
            let clean_rel = rel.split(['?', '#']).next().unwrap_or("");
            if !explicit_dl && !crate::links::is_binary_download_path(clean_rel) {
                return None;
            }
            let fallback_name = clean_rel.rsplit('/').next().unwrap_or("download.bin");
            let filename = if !dl_val.is_empty() {
                dl_val
            } else {
                fallback_name.to_owned()
            };
            return Some(DownloadLink {
                href: safe_href.to_owned(),
                cid: None,
                path: Some(clean_rel.to_owned()),
                label: filename.clone(),
                filename,
            });
        }
    }

    None
}

fn sanitize_data_img(attrs: &str) -> Option<RenderBlock> {
    let src = extract_attr(attrs, "src")?.trim().to_owned();
    if src.len() > MAX_DATA_IMG_BYTES {
        return None;
    }
    let lower = src.to_ascii_lowercase();
    let allowed_prefix = [
        "data:image/png;base64,",
        "data:image/jpeg;base64,",
        "data:image/gif;base64,",
        "data:image/webp;base64,",
    ]
    .iter()
    .find(|&&p| lower.starts_with(p))?;
    let payload = &src[allowed_prefix.len()..];
    if payload.is_empty()
        || !payload
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n' | b'\r'))
    {
        return None;
    }
    let alt = extract_attr(attrs, "alt").map(|a| decode_entities(&a));
    let width = extract_attr(attrs, "width").and_then(|v| parse_px_u32(&v));
    let height = extract_attr(attrs, "height").and_then(|v| parse_px_u32(&v));
    Some(RenderBlock {
        kind: "image".to_owned(),
        html: None,
        data_uri: Some(src),
        src_cid: None,
        src_path: None,
        alt,
        width,
        height,
        vb_x: None,
        vb_y: None,
        vb_w: None,
        vb_h: None,
        ops: Vec::new(),
    })
}

fn contains_event_handler(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i].is_ascii_whitespace() && bytes[i + 1] == b'o' && bytes[i + 2] == b'n' {
            let mut j = i + 3;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j > i + 3 && j < bytes.len() && bytes[j] == b'=' {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn parse_viewbox_full(vb: &str) -> Option<(f64, f64, f64, f64)> {
    let nums: Vec<f64> = vb
        .split(|c: char| c.is_ascii_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<f64>().ok())
        .collect();
    if nums.len() == 4 && nums[2] > 0.0 && nums[3] > 0.0 {
        Some((nums[0], nums[1], nums[2], nums[3]))
    } else {
        None
    }
}

fn parse_px_u32(raw: &str) -> Option<u32> {
    let clean = raw.trim().trim_end_matches("px").trim();
    let v: f32 = clean.parse().ok()?;
    if v > 0.0 && v <= 2000.0 {
        Some(v.round() as u32)
    } else {
        None
    }
}

pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn push_md_inline(out: &mut String, text: &str, site_base: &str, current_path: &str) {
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(open_b) = rest.find('[') {
            push_escaped(out, &rest[..open_b]);
            let after_open = &rest[open_b + 1..];
            if let Some(close_b) = after_open.find("](") {
                let label = &after_open[..close_b];
                let after_mid = &after_open[close_b + 2..];
                if let Some(close_p) = after_mid.find(')') {
                    let href = &after_mid[..close_p];
                    if let Some(safe) = resolve_safe_link(href, site_base, current_path) {
                        out.push_str("<a href=\"");
                        push_escaped(out, &safe);
                        out.push_str("\">");
                        push_escaped(out, label);
                        out.push_str("</a>");
                    } else {
                        push_escaped(out, label);
                    }
                    rest = &after_mid[close_p + 1..];
                    continue;
                }
            }
            push_escaped(out, "[");
            rest = after_open;
        } else {
            push_escaped(out, rest);
            break;
        }
    }
}

fn memchr(bytes: &[u8], start: usize, needle: u8) -> Option<usize> {
    bytes[start..]
        .iter()
        .position(|&b| b == needle)
        .map(|off| start + off)
}

fn find_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote: Option<u8> = None;
    let mut i = start;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            None if b == b'"' || b == b'\'' => quote = Some(b),
            None if b == b'>' => return Some(i),
            _ => {}
        }
        i += 1;
    }
    None
}

fn extract_attr(attrs: &str, target: &str) -> Option<String> {
    let bytes = attrs.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < bytes.len()
            && !bytes[i].is_ascii_whitespace()
            && bytes[i] != b'='
            && bytes[i] != b'/'
        {
            i += 1;
        }
        let name = &attrs[name_start..i];
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            continue;
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let val = if bytes[i] == b'"' || bytes[i] == b'\'' {
            let q = bytes[i];
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != q {
                i += 1;
            }
            let slice = &attrs[start..i];
            if i < bytes.len() {
                i += 1;
            }
            slice
        } else {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            &attrs[start..i]
        };
        if name.eq_ignore_ascii_case(target) {
            return Some(val.to_owned());
        }
    }
    None
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        if let Some(semi) = after.find(';') {
            let ent = &after[..semi];
            if let Some(decoded) = decode_single_entity(ent) {
                out.push_str(&decoded);
                rest = &after[semi + 1..];
                continue;
            }
        }
        out.push('&');
        rest = after;
    }
    out.push_str(rest);
    out
}

fn decode_single_entity(ent: &str) -> Option<String> {
    if let Some(hex) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
        let code = u32::from_str_radix(hex, 16).ok()?;
        let ch = char::from_u32(code)?;
        return if ch.is_control() && ch != '\n' && ch != '\t' {
            None
        } else {
            Some(ch.to_string())
        };
    }
    if let Some(dec) = ent.strip_prefix('#') {
        let code = dec.parse::<u32>().ok()?;
        let ch = char::from_u32(code)?;
        return if ch.is_control() && ch != '\n' && ch != '\t' {
            None
        } else {
            Some(ch.to_string())
        };
    }
    let mapped = match ent {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{00A0}",
        "rarr" => "→",
        "larr" => "←",
        "uarr" => "↑",
        "darr" => "↓",
        "harr" => "↔",
        "mdash" => "—",
        "ndash" => "–",
        "hellip" => "…",
        "middot" => "·",
        "bull" => "•",
        "copy" => "©",
        "reg" => "®",
        "trade" => "™",
        "lsquo" => "‘",
        "rsquo" => "’",
        "ldquo" => "“",
        "rdquo" => "”",
        "times" => "×",
        "check" => "✓",
        _ => return None,
    };
    Some(mapped.to_owned())
}

fn push_escaped(out: &mut String, text: &str) {
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_scripts_iframes_and_unsafe_links_while_allowing_lns_relative_and_https() {
        let html = r#"
            <html><head><title>Demo</title><script>fetch('https://evil.com')</script><style>body{background:#fff;color:#111;background-image:url(https://track.me)} a{color:#0055ff}</style></head>
            <body>
              <h1>Hello</h1>
              <iframe src="https://evil.com">bad</iframe>
              <img src="https://track.me/pixel.png" alt="tracker">
              <p>
                <a href="about.html">About</a>
                <a href="../top.html">Top</a>
                <a href="lns://logos">Logos</a>
                <a href="https://nameswallet.app/browser">Browser &rarr;</a>
                <a href="http://insecure.example">HTTP</a>
                <a href="https://user:pass@phish.example">Creds</a>
                <a href="javascript:alert(1)">XSS</a>
                <a href="data:text/html,boom">Data</a>
              </p>
            </body></html>
        "#;
        let s = sanitize_html(html, "lns://jef", "/docs/index.html");
        assert_eq!(s.title.as_deref(), Some("Demo"));
        assert_eq!(s.bg_color.as_deref(), Some("#ffffff"));
        assert_eq!(s.fg_color.as_deref(), Some("#111111"));
        assert_eq!(s.link_color.as_deref(), Some("#0055ff"));
        assert!(!s.html.contains("script"));
        assert!(!s.html.contains("evil.com"));
        assert!(!s.html.contains("track.me"));
        assert!(!s.html.contains("insecure.example"));
        assert!(!s.html.contains("phish.example"));
        assert!(!s.html.contains("javascript:"));
        assert!(!s.html.contains("data:text/html"));
        assert!(s.html.contains(r#"<a href="lns://jef/docs/about.html""#));
        assert!(s.html.contains(r#"<a href="lns://jef/top.html""#));
        assert!(s.html.contains(r#"<a href="lns://logos""#));
        assert!(s.html.contains(r#"<a href="https://nameswallet.app/browser""#));
        assert!(s.html.contains("Browser →"));
    }

    #[test]
    fn renders_safe_inline_svg_as_canvas_ops_and_rejects_malicious_svg() {
        let html = r##"
            <html><head><style>
              body { background: #ffffff; color: #18202c; }
              .sr { position: absolute; clip: rect(0,0,0,0); }
              .hero { fill: #0055ff; }
              .shadow { fill: #b8d0ff; }
            </style></head>
            <body>
              <h1 class="sr">Hello World</h1>
              <svg class="hero" viewBox="0 0 63 8" aria-label="HELLO WORLD">
                <defs><path id="px" d="M0 0h1v7h-1z"/></defs>
                <use class="shadow" href="#px" x="0.6" y="0.6"/>
                <use href="#px" x="0" y="0"/>
              </svg>
              <svg><script>alert(1)</script><rect width="10" height="10"/></svg>
              <svg onclick="alert(1)"><rect width="10" height="10"/></svg>
              <p>Body text</p>
            </body></html>
        "##;
        let s = sanitize_html(html, "lns://helloworld", "/");
        assert_eq!(s.bg_color.as_deref(), Some("#ffffff"));
        assert_eq!(s.fg_color.as_deref(), Some("#18202c"));
        let svgs: Vec<&RenderBlock> = s.blocks.iter().filter(|b| b.kind == "svg").collect();
        assert_eq!(svgs.len(), 1);
        assert_eq!(svgs[0].alt.as_deref(), Some("HELLO WORLD"));
        assert_eq!(svgs[0].vb_w, Some(63.0));
        assert_eq!(svgs[0].vb_h, Some(8.0));
        assert_eq!(svgs[0].ops.len(), 2);
        assert_eq!(svgs[0].ops[0].fill, "#b8d0ff");
        assert_eq!(svgs[0].ops[0].x, 0.6);
        assert_eq!(svgs[0].ops[1].fill, "#0055ff");
        assert_eq!(svgs[0].ops[1].d.as_deref(), Some("M0 0h1v7h-1z"));
        // Screen-reader-only h1 hidden because hero SVG rendered
        assert!(!s.html.contains("<h1>Hello World</h1>"));
        assert!(s.html.contains("<p>Body text</p>"));
    }

    #[test]
    fn markdown_converts_and_allows_https_but_blocks_http_and_js() {
        let md = "# Title\n\n- [Next](next.md)\n- [Browser](https://nameswallet.app/browser)\n- [Bad](http://evil.com)\n- [XSS](javascript:alert(1))\n";
        let s = markdown_to_safe_html(md, "lns://jef", "/");
        assert_eq!(s.title.as_deref(), Some("Title"));
        assert!(s.html.contains(r#"<a href="lns://jef/next.md">Next</a>"#));
        assert!(s.html.contains(r#"<a href="https://nameswallet.app/browser">Browser</a>"#));
        assert!(!s.html.contains("evil.com"));
        assert!(!s.html.contains("javascript:"));
    }

    #[test]
    fn extracts_cid_and_relative_images_and_download_links_while_blocking_external_images() {
        let html = r#"
            <html><body>
              <img src="cid://z4W2jBrowserShot0000000000000000000000000000000000" alt="Shot">
              <img src="./thumb.png" alt="Thumb">
              <img src="https://evil.example/pixel.png" alt="Blocked">
              <a href="cid://z4W2jBrowserUiLgx00000000000000000000000000000000" download="lns-browser-0.2.8.lgx">Download UI</a>
              <a href="./files/core.lgx">Core</a>
            </body></html>
        "#;
        let s = sanitize_html(html, "lns://nameswallet", "/browser/index.html");
        let imgs: Vec<&RenderBlock> = s.blocks.iter().filter(|b| b.kind == "image").collect();
        assert_eq!(imgs.len(), 2);
        assert_eq!(
            imgs[0].src_cid.as_deref(),
            Some("z4W2jBrowserShot0000000000000000000000000000000000")
        );
        assert_eq!(imgs[1].src_path.as_deref(), Some("/browser/thumb.png"));
        assert_eq!(s.downloads.len(), 2);
        assert_eq!(s.downloads[0].filename, "lns-browser-0.2.8.lgx");
        assert_eq!(
            s.downloads[0].cid.as_deref(),
            Some("z4W2jBrowserUiLgx00000000000000000000000000000000")
        );
        assert_eq!(s.downloads[1].path.as_deref(), Some("/browser/files/core.lgx"));
        assert_eq!(s.downloads[1].filename, "core.lgx");
    }

    #[test]
    fn finding17_cross_site_prefix_not_matched_and_fragment_trailing_slash_preserved() {
        // Cross-site link `lns://alice/app.lgx` on site `lns://a` must NOT match as local download
        let html = r#"<html><body><a href="lns://alice/app.lgx">App</a><a href="./docs/#intro">Docs</a></body></html>"#;
        let s = sanitize_html(html, "lns://a", "/index.html");
        assert_eq!(s.downloads.len(), 0);
        assert!(s.html.contains(r#"href="lns://a/docs/#intro""#));

        assert_eq!(
            resolve_safe_link("/browser/", "lns://nameswallet", "/index.html").as_deref(),
            Some("lns://nameswallet/browser/")
        );
        assert_eq!(
            resolve_safe_link("./guide.html#section-2", "lns://nameswallet", "/browser/index.html").as_deref(),
            Some("lns://nameswallet/browser/guide.html#section-2")
        );
    }
}
