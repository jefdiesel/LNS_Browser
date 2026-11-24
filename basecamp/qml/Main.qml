import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Logos.Theme
import "logic.mjs" as Logic

// Native Basecamp LNS + Logos Storage CID Web Browser.
// Security & Storage model:
// - Resolves LNS names through Basecamp's built-in `names` core module (LEZ 0.4).
// - Uses Basecamp's bundled P2P `storage_module` automatically when installed; NEVER defaults to
//   http://127.0.0.1:8080 (which is the Logos Blockchain node's port). If `storage_module` is
//   absent, the user explicitly picks a real Logos Storage node URL in Settings.
// - Verifies SHA-256 commitments before rendering, renders with zero JS and zero external network
//   subresources, and pauses on `https://` clicks with a confirmation strip (`Open` / `Copy`).
// - On-chain site updates hand off via Basecamp's `names.publish_site` intent so Names verifies
//   ownership and shows a single-click approval sheet before signing.
Item {
    id: root
    readonly property bool bridgeReady: typeof logos !== "undefined" && logos !== null

    property string urlInput: ""
    property var history: []
    property int historyIdx: -1
    property bool loading: false
    property string problem: ""
    property string notice: ""
    property string pendingExternalUrl: ""

    property var parsedUrl: null
    property var siteInfo: null
    property var pageData: null

    // Storage backend state: "checking" | "basecamp" | "http" | "none"
    property string storageBackend: "checking"
    property bool basecampStorageInstalled: false
    property bool basecampStorageRunning: false
    property bool basecampStorageStarting: false
    property string basecampPeerId: ""
    property string basecampNetwork: ""
    property var storageInfo: null
    property string storageApiInput: "" // NEVER defaults to 127.0.0.1:8080 (Logos Blockchain port)

    // Active storage_module async download / upload state
    property var activeDownload: null  // { cid, expectedSha256, siteBase, path, chunks, manifestRoot }
    property var activeUpload: null    // { sessionId, name, sha256, mode, sentChunk }

    property bool settingsOpen: false
    property bool publishOpen: false
    property bool filesOpen: false

    property string pubName: ""
    property string pubTitle: ""
    property string pubLocalPath: ""
    property string pubMode: "page" // defaults to On-Chain HTML (<= 78 KB); switches to "cid" if storage is ready
    property string pubHtml: "<!doctype html>\n<html>\n<head>\n  <meta charset=\"utf-8\">\n  <title>Hello Logos</title>\n  <style>body{background:#ffffff;color:#18202c} a{color:#0055ff}</style>\n</head>\n<body>\n  <h1 style=\"color:#0055ff\">Hello from LNS + Logos Storage</h1>\n  <p>Resolved on LEZ 0.4 and verified by SHA-256.</p>\n  <p><a href=\"lns://jef\">Visit lns://jef</a> &middot; <a href=\"https://nameswallet.app/browser\">nameswallet.app/browser &rarr;</a></p>\n</body>\n</html>"
    property var lastPublished: null
    property string lastDeepLink: ""

    readonly property color slate: Theme.palette.background
    readonly property color card: Theme.palette.backgroundSecondary
    readonly property color raised: Theme.isDark ? Theme.palette.surface : Theme.palette.backgroundButton
    readonly property color line: Theme.palette.border
    readonly property color ink: Theme.palette.text
    readonly property color dim: Theme.palette.textSecondary
    readonly property color brass: Theme.isDark ? Theme.palette.warning : Theme.palette.primary
    readonly property color alarm: Theme.palette.error
    readonly property color good: Theme.palette.success
    function px(size) { return Math.round(size * (Theme.typography.scale || 1)) }
    readonly property string sans: "Avenir Next"
    readonly property string mono: "Menlo"

    readonly property color pageBg: (pageData && pageData.bg_color) ? pageData.bg_color : root.card
    readonly property color pageFg: (pageData && pageData.fg_color) ? pageData.fg_color : root.ink
    readonly property color pageLink: (pageData && pageData.link_color) ? pageData.link_color : root.brass
    readonly property bool pageIsLight: pageData && pageData.bg_color ? (pageBg.r * 0.299 + pageBg.g * 0.587 + pageBg.b * 0.114) > 0.55 : !Theme.isDark
    readonly property color pageDim: pageData && pageData.bg_color ? (pageIsLight ? "#526075" : "#9aa7b8") : root.dim

    Component.onCompleted: {
        initStorage()
    }

    Timer {
        id: downloadTimeoutTimer
        interval: 25000
        repeat: false
        onTriggered: {
            if (root.activeDownload !== null) {
                var cid = root.activeDownload.cid
                root.activeDownload = null
                root.loading = false
                root.pageData = null
                root.problem = Logic.formatUnreachableCidError(cid, "timed out waiting for Logos Storage peers")
            }
        }
    }

    // Handle incoming `lns.browse` intents and `storage_module` streaming events
    Connections {
        target: root.bridgeReady ? logos : null
        ignoreUnknownSignals: true

        function onIntentRequested(requestId, intent, params, requesterName) {
            if (intent !== "lns.browse")
                return
            var wanted = String(params && params.url ? params.url : "")
            if (wanted !== "") root.navigate(wanted)
            if (logos.respond) logos.respond(requestId, true, { url: wanted }, "")
        }

        function onModuleEventReceived(moduleName, eventName, data) {
            if (moduleName !== "storage_module")
                return
            var payload = Logic.parseStorageEventPayload(data)
            if (!payload) return

            if (eventName === "storageStart") {
                root.basecampStorageStarting = false
                if (payload.success) {
                    root.basecampStorageRunning = true
                    root.storageBackend = "basecamp"
                    root.readBasecampStorageIdentity()
                } else {
                    root.basecampStorageRunning = false
                    root.problem = "Basecamp Storage module failed to start: " + String(payload.message || "unknown error")
                }
                return
            }

            if (eventName === "storageDownloadProgress" && root.activeDownload !== null) {
                if (String(payload.sessionId || "") === root.activeDownload.cid && payload.chunk) {
                    root.activeDownload.chunks.push(String(payload.chunk))
                }
                return
            }

            if (eventName === "storageDownloadDone" && root.activeDownload !== null) {
                if (String(payload.sessionId || "") !== root.activeDownload.cid)
                    return
                downloadTimeoutTimer.stop()
                var dl = root.activeDownload
                root.activeDownload = null
                if (!payload.success) {
                    root.loading = false
                    root.pageData = null
                    root.problem = Logic.formatUnreachableCidError(dl.cid, payload.error || "not found on network")
                    return
                }
                root.finishBasecampDownload(dl)
                return
            }

            if (eventName === "storageUploadProgress" && root.activeUpload !== null) {
                var up = root.activeUpload
                if (String(payload.sessionId || "") !== up.sessionId) return
                if (!payload.success) {
                    root.activeUpload = null
                    root.loading = false
                    root.problem = "Basecamp Storage upload failed: " + String(payload.error || "unknown error")
                    return
                }
                if (up.mode === "chunks" && up.sentChunk) {
                    // Chunk stored — finalize to get real P2P CID
                    up.mode = "finalizing"
                    root.callCore("storage_module", "uploadFinalize", [up.sessionId], function(cid) {
                        var doneUp = root.activeUpload
                        root.activeUpload = null
                        if (!doneUp) return
                        root.handoffToNames({
                            name: doneUp.name,
                            cid: String(cid || "").trim(),
                            sha256: doneUp.sha256,
                            site_type: "single",
                            return_app: "lns_browser"
                        }, "Uploaded to Basecamp Logos Storage (" + Logic.shortHash(cid) + ").")
                    }, function(err) {
                        root.activeUpload = null
                        root.loading = false
                        root.problem = "Basecamp Storage finalize failed: " + err
                    }, 30000)
                }
                return
            }

            if (eventName === "storageUploadDone" && root.activeUpload !== null) {
                var upDone = root.activeUpload
                if (String(payload.sessionId || "") !== upDone.sessionId) return
                root.activeUpload = null
                if (!payload.success || !payload.cid) {
                    root.loading = false
                    root.problem = "Basecamp Storage upload failed: " + String(payload.error || "no CID returned")
                    return
                }
                root.handoffToNames({
                    name: upDone.name,
                    cid: String(payload.cid).trim(),
                    sha256: upDone.sha256 || "",
                    site_type: "single",
                    return_app: "lns_browser"
                }, "Uploaded to Basecamp Logos Storage (" + Logic.shortHash(payload.cid) + ").")
            }
        }
    }

    TextEdit { id: clipHelper; visible: false }

    function copyText(str) {
        clipHelper.text = String(str || "")
        clipHelper.selectAll()
        clipHelper.copy()
        notice = "Copied to clipboard."
    }

    function openExternalUrl(rawUrl) {
        var target = String(rawUrl || "").trim()
        if (!Logic.isExternalHttpsUrl(target)) {
            problem = "Only https:// external links can be opened."
            return
        }
        var opened = false
        try {
            opened = Qt.openUrlExternally(target)
        } catch (e) {
            opened = false
        }
        if (opened) {
            pendingExternalUrl = ""
            notice = "Opened " + target + " in your browser."
        } else {
            // Basecamp's plugin sandbox refuses https:// in Qt.openUrlExternally — copy cleanly instead
            copyText(target)
            notice = "Basecamp's sandbox blocks opening external https:// links directly — copied " + target + " to your clipboard so you can paste it into your browser."
        }
    }

    function callCore(moduleName, method, args, done, failed, timeoutMs) {
        if (!bridgeReady) {
            Qt.callLater(function() { failed("Run inside Basecamp with `" + moduleName + "` loaded.") })
            return
        }
        logos.callModuleAsync(moduleName, method, args, function(reply) {
            var res = Logic.answer(reply)
            if (res.ok) done(res.value)
            else failed(res.error)
        }, timeoutMs || 30000)
    }

    function initStorage() {
        storageBackend = "checking"
        if (bridgeReady && logos.onModuleEvent) {
            logos.onModuleEvent("storage_module", "storageStart")
            logos.onModuleEvent("storage_module", "storageDownloadProgress")
            logos.onModuleEvent("storage_module", "storageDownloadDone")
            logos.onModuleEvent("storage_module", "storageUploadProgress")
            logos.onModuleEvent("storage_module", "storageUploadDone")
        }
        // 1. Prefer Basecamp's bundled P2P storage_module when installed
        callCore("storage_module", "isRunning", [], function(running) {
            basecampStorageInstalled = true
            basecampStorageRunning = (running === true)
            storageBackend = "basecamp"
            if (basecampStorageRunning) {
                readBasecampStorageIdentity()
            } else {
                startBasecampStorage()
            }
        }, function() {
            // 2. storage_module not installed: check if the user explicitly configured an HTTP node
            basecampStorageInstalled = false
            basecampStorageRunning = false
            refreshHttpStorageStatus()
        }, 5000)
    }

    function startBasecampStorage() {
        if (!basecampStorageInstalled || basecampStorageStarting) return
        basecampStorageStarting = true
        callCore("storage_module", "loadConfigOrDefault", [], function(cfg) {
            var cfgStr = typeof cfg === "string" ? cfg : JSON.stringify(cfg || {})
            callCore("storage_module", "init", [cfgStr], function() {
                callCore("storage_module", "start", [], function() {}, function(err) {
                    basecampStorageStarting = false
                    if (String(err).toLowerCase().indexOf("already") !== -1) {
                        basecampStorageRunning = true
                        readBasecampStorageIdentity()
                    }
                }, 15000)
            }, function() {
                // "already initialized" is expected when Basecamp shares one node across apps
                callCore("storage_module", "start", [], function() {}, function(err) {
                    basecampStorageStarting = false
                    if (String(err).toLowerCase().indexOf("already") !== -1) {
                        basecampStorageRunning = true
                        readBasecampStorageIdentity()
                    }
                }, 15000)
            }, 15000)
        }, function() {
            basecampStorageStarting = false
        }, 10000)
    }

    function readBasecampStorageIdentity() {
        callCore("storage_module", "peerId", [], function(pid) {
            basecampPeerId = String(pid || "")
        }, function() {}, 5000)
        callCore("storage_module", "network", [], function(net) {
            basecampNetwork = String(net || "")
        }, function() {}, 5000)
    }

    function refreshHttpStorageStatus() {
        callCore("lns_browser_core", "storage_status", [], function(v) {
            storageInfo = v
            var api = v && v.storage_api ? String(v.storage_api).trim() : ""
            // Never auto-adopt port 8080 from an older core build (8080 is Logos Blockchain)
            if (api !== "" && !Logic.isPort8080Url(api)) {
                storageApiInput = api
                if (!basecampStorageInstalled) storageBackend = "http"
            } else {
                storageApiInput = ""
                if (!basecampStorageInstalled) {
                    storageBackend = "none"
                    pubMode = "page"
                }
            }
        }, function() {
            if (!basecampStorageInstalled) {
                storageBackend = "none"
                pubMode = "page"
            }
        }, 5000)
    }

    function pushHistory(canonical) {
        var next = history.slice(0, historyIdx + 1)
        next.push(canonical)
        history = next
        historyIdx = next.length - 1
    }

    function goBack() {
        if (historyIdx > 0) {
            historyIdx -= 1
            navigate(history[historyIdx], false)
        }
    }

    function goForward() {
        if (historyIdx >= 0 && historyIdx < history.length - 1) {
            historyIdx += 1
            navigate(history[historyIdx], false)
        }
    }

    function activateLink(link) {
        var s = String(link || "").trim()
        if (!s) return
        if (Logic.isExternalHttpsUrl(s)) {
            pendingExternalUrl = s
            return
        }
        pendingExternalUrl = ""
        navigate(s)
    }

    function renderHtmlSafely(rawHtml, meta) {
        callCore("lns_browser_core", "render_html", [rawHtml, meta.siteBase, meta.path || "/"], function(rendered) {
            loading = false
            pageData = Object.assign({}, rendered, {
                mode: meta.mode || rendered.mode,
                cid: meta.cid || "",
                sha256: meta.sha256 || "",
                verified: !!meta.verified,
                files: meta.files || []
            })
            filesOpen = !!(meta.files && meta.files.length > 1)
        }, function() {
            // Older lns_browser_core without render_html: use safe JS fallback with colors + SVG + https://
            var clean = Logic.sanitizeHtmlFallback(rawHtml, meta.siteBase)
            loading = false
            pageData = {
                mode: meta.mode || "single",
                kind: "html",
                title: clean.title || meta.title || "",
                path: meta.path || "/",
                cid: meta.cid || "",
                sha256: meta.sha256 || "",
                verified: !!meta.verified,
                html: clean.html,
                bg_color: clean.bg_color,
                fg_color: clean.fg_color,
                link_color: clean.link_color,
                blocks: clean.blocks,
                files: meta.files || []
            }
            filesOpen = !!(meta.files && meta.files.length > 1)
        })
    }

    function finishBasecampDownload(dl) {
        var allBytes = []
        for (var i = 0; i < dl.chunks.length; i++) {
            var part = Logic.base64ToBytes(dl.chunks[i])
            for (var j = 0; j < part.length; j++) allBytes.push(part[j])
        }
        if (allBytes.length === 0) {
            loading = false
            pageData = null
            problem = Logic.formatUnreachableCidError(dl.cid, "empty payload")
            return
        }
        var actualHash = Logic.sha256HexBytes(allBytes)
        var verified = false
        if (dl.expectedSha256 && dl.expectedSha256.length === 64) {
            if (actualHash !== dl.expectedSha256.toLowerCase()) {
                loading = false
                pageData = null
                problem = "SHA-256 mismatch for CID " + Logic.shortHash(dl.cid) + ": on-chain expected " + Logic.shortHash(dl.expectedSha256) + ", got " + Logic.shortHash(actualHash)
                return
            }
            verified = true
        }
        var text = Logic.bytesToUtf8(allBytes)

        // Check if this is a v1 site manifest (only on root fetch)
        if (!dl.manifestFiles) {
            var manifest = Logic.tryParseManifestJson(text)
            if (manifest) {
                var filesList = []
                for (var p in manifest.files) {
                    filesList.push({ path: p, cid: manifest.files[p].cid, sha256: manifest.files[p].sha256 || "" })
                }
                var wantPath = dl.path && dl.path !== "/" ? dl.path : (manifest.index || "/index.html")
                var entry = manifest.files[wantPath] || manifest.files["/index.html"]
                if (!entry || !entry.cid) {
                    loading = false
                    pageData = null
                    problem = wantPath + " not found in site manifest."
                    return
                }
                startBasecampDownload(entry.cid, entry.sha256 || "", dl.siteBase, wantPath, filesList, verified)
                return
            }
        }

        renderHtmlSafely(text, {
            mode: dl.manifestFiles ? "manifest" : "single",
            cid: dl.cid,
            sha256: actualHash,
            verified: dl.manifestFiles ? (dl.rootVerified && verified) : verified,
            siteBase: dl.siteBase,
            path: dl.path,
            files: dl.manifestFiles || []
        })
    }

    function startBasecampDownload(cid, expectedSha256, siteBase, path, manifestFiles, rootVerified) {
        activeDownload = {
            cid: cid,
            expectedSha256: expectedSha256 || "",
            siteBase: siteBase,
            path: path || "/",
            chunks: [],
            manifestFiles: manifestFiles || null,
            rootVerified: !!rootVerified
        }
        downloadTimeoutTimer.restart()
        callCore("storage_module", "downloadChunks", [cid, false, 65536, false, true], function() {}, function(err) {
            downloadTimeoutTimer.stop()
            activeDownload = null
            loading = false
            pageData = null
            problem = Logic.formatUnreachableCidError(cid, err)
        }, 30000)
    }

    function navigate(raw, recordHistory) {
        var shouldPush = recordHistory === undefined ? true : recordHistory
        var parsed = Logic.parseUrl(raw)
        if (!parsed.ok) {
            problem = parsed.error
            return
        }
        parsedUrl = parsed
        urlInput = parsed.canonical
        problem = ""
        notice = ""
        pendingExternalUrl = ""
        loading = true

        if (shouldPush) pushHistory(parsed.canonical)

        if (parsed.kind === "cid") {
            siteInfo = { name: "", display: "Direct CID", bio: "", cid: parsed.cid, sha256: "", siteType: "", hasSite: true, texts: {} }
            fetchCidPage(parsed.cid, "", parsed.siteBase, parsed.path)
            return
        }

        callCore("names", "resolve", [parsed.name], function(record) {
            if (!record) {
                loading = false
                siteInfo = null
                pageData = null
                problem = "LNS name not registered on LEZ: " + parsed.name
                return
            }
            var info = Logic.extractSiteInfo(record)
            siteInfo = info
            pubName = parsed.name
            if (info.hasSite) {
                fetchCidPage(info.cid, info.sha256, parsed.siteBase, parsed.path)
                return
            }
            // Fallback: on-chain SetPage HTML stored directly on LEZ 0.4
            callCore("names", "page", [parsed.name], function(pg) {
                if (pg && pg.text && pg.text.length > 0) {
                    renderHtmlSafely(pg.text, {
                        mode: "onchain-page",
                        title: info.display || parsed.name,
                        cid: "",
                        sha256: "",
                        verified: true,
                        siteBase: parsed.siteBase,
                        path: parsed.path,
                        files: []
                    })
                } else {
                    loading = false
                    pageData = null
                }
            }, function() {
                loading = false
                pageData = null
            })
        }, function(err) {
            loading = false
            problem = err
            siteInfo = null
            pageData = null
        })
    }

    function fetchCidPage(cid, expectedSha256, siteBase, path) {
        if (storageBackend === "basecamp") {
            if (!basecampStorageRunning) {
                loading = false
                pageData = null
                problem = "Basecamp's Storage node is still starting. Click 'Start Storage Node' in Settings or try again in a few seconds."
                startBasecampStorage()
                return
            }
            startBasecampDownload(cid, expectedSha256, siteBase, path, null, false)
            return
        }
        if (storageBackend === "http" && storageApiInput.trim() !== "") {
            callCore("lns_browser_core", "fetch_site", [cid, expectedSha256 || "", siteBase, path || "/"], function(data) {
                loading = false
                pageData = data
                filesOpen = data && data.files && data.files.length > 1
            }, function(err) {
                loading = false
                pageData = null
                problem = Logic.formatUnreachableCidError(cid, err)
            }, 45000)
            return
        }
        loading = false
        pageData = null
        problem = "Cannot load CID " + Logic.shortHash(cid) + ": no Logos Storage module is installed in Basecamp and no external Storage node is configured. On-Chain HTML (≤ 78 KB) sites work without a storage node; to open CID sites, configure a real Logos Storage node in Settings."
    }

    function handoffToNames(intentParams, summaryLabel) {
        lastDeepLink = Logic.buildPublishDeepLink(intentParams)
        if (!bridgeReady || !logos.request) {
            loading = false
            problem = "Basecamp intent bridge unavailable. Copy the deep link below to finish in Names."
            return
        }
        notice = summaryLabel + " Opening Names to verify ownership & approve..."
        logos.request("names.publish_site", intentParams, function(ok, data, err) {
            loading = false
            if (ok) {
                problem = ""
                notice = "Published on-chain to lns://" + intentParams.name + "!"
                publishOpen = false
                navigate("lns://" + intentParams.name, true)
            } else {
                problem = err ? String(err) : "Publish was cancelled or refused in Names."
            }
        })
    }

    function publishAndBind() {
        var name = Logic.normalizeName(pubName)
        if (!name || !Logic.isValidName(name)) {
            problem = "Enter a valid LNS name (e.g. helloworld)."
            return
        }
        pubName = name
        loading = true
        problem = ""
        notice = ""
        lastDeepLink = ""

        callCore("names", "resolve", [name], function(record) {
            if (!record) {
                loading = false
                problem = "LNS name \"" + name + "\" is not registered on LEZ yet. Register it in Names first."
                return
            }

            if (pubMode === "page") {
                if (!pubHtml.trim()) {
                    loading = false
                    problem = "Paste HTML content first."
                    return
                }
                if (Logic.utf8ToBytes(pubHtml).length > 78 * 1024) {
                    loading = false
                    problem = "HTML exceeds the 78 KB on-chain SetPage limit. Switch to Logos Storage CID mode."
                    return
                }
                handoffToNames({
                    name: name,
                    html: pubHtml,
                    return_app: "lns_browser"
                }, "Prepared on-chain HTML page.")
                return
            }

            // CID publish MUST go to a real Logos Storage node (never a stand-in stub)
            if (storageBackend === "basecamp") {
                if (!basecampStorageRunning) {
                    loading = false
                    problem = "Basecamp's Storage node is not running yet. Start it in Settings or switch to On-Chain HTML (≤ 78 KB)."
                    return
                }
                if (pubLocalPath.trim().length > 0) {
                    callCore("storage_module", "uploadUrl", [pubLocalPath.trim(), 65536, true], function(sessionId) {
                        activeUpload = { sessionId: String(sessionId), name: name, sha256: "", mode: "url", sentChunk: true }
                        notice = "Uploading file to Basecamp Logos Storage (advertising to P2P network)..."
                    }, function(err) {
                        loading = false
                        problem = "Basecamp Storage upload failed: " + err
                    }, 30000)
                } else {
                    if (!pubHtml.trim()) {
                        loading = false
                        problem = "Paste HTML content or enter a file path first."
                        return
                    }
                    var hashHex = Logic.sha256HexUtf8(pubHtml)
                    callCore("storage_module", "uploadInit", ["index.html", 65536, true], function(sessionId) {
                        var sid = String(sessionId)
                        activeUpload = { sessionId: sid, name: name, sha256: hashHex, mode: "chunks", sentChunk: true }
                        notice = "Uploading HTML to Basecamp Logos Storage (advertising to P2P network)..."
                        callCore("storage_module", "uploadChunk", [sid, pubHtml], function() {}, function(err) {
                            activeUpload = null
                            loading = false
                            problem = "Basecamp Storage uploadChunk failed: " + err
                        }, 30000)
                    }, function(err) {
                        loading = false
                        problem = "Basecamp Storage uploadInit failed: " + err
                    }, 30000)
                }
                return
            }

            if (storageBackend === "http" && storageApiInput.trim() !== "") {
                if (storageInfo && storageInfo.mock) {
                    loading = false
                    problem = "Refused to publish to the local stand-in mock (nobody else can open its CIDs). Use Basecamp's built-in Storage module, a real Logos Storage node, or On-Chain HTML (≤ 78 KB)."
                    return
                }
                var doneUpload = function(uploaded) {
                    lastPublished = uploaded
                    var built = Logic.buildProfileEntries(uploaded.root_cid, uploaded.sha256, uploaded.mode)
                    if (!built.ok) {
                        loading = false
                        problem = built.error
                        return
                    }
                    handoffToNames({
                        name: name,
                        cid: uploaded.root_cid,
                        sha256: uploaded.sha256,
                        site_type: uploaded.mode || "single",
                        return_app: "lns_browser"
                    }, "Uploaded to Logos Storage (" + Logic.shortHash(uploaded.root_cid) + ").")
                }
                if (pubLocalPath.trim().length > 0) {
                    callCore("lns_browser_core", "publish_path", [pubLocalPath.trim(), pubTitle.trim()], doneUpload, function(err) {
                        loading = false
                        problem = err
                    }, 120000)
                } else {
                    callCore("lns_browser_core", "publish_html", [pubHtml, pubTitle.trim()], doneUpload, function(err) {
                        loading = false
                        problem = err
                    }, 60000)
                }
                return
            }

            loading = false
            problem = "No real Logos Storage node is configured. Install Basecamp's Storage module, enter a real Logos Storage URL in Settings, or switch to On-Chain HTML (≤ 78 KB)."
        }, function(err) {
            loading = false
            problem = "Could not check LNS name: " + err
        })
    }

    function saveSettings() {
        var trimmed = storageApiInput.trim()
        if (Logic.isPort8080Url(trimmed)) {
            problem = "Port 8080 is used by the Logos Blockchain node, not Logos Storage. Leave blank to use Basecamp's built-in Storage module, or enter your real Logos Storage API port."
            return
        }
        if (trimmed === "") {
            callCore("lns_browser_core", "config_set", [JSON.stringify({ storage_api: "" })], function() {}, function() {})
            if (basecampStorageInstalled) {
                storageBackend = "basecamp"
                notice = "Using Basecamp's built-in Logos Storage module."
            } else {
                storageBackend = "none"
                notice = "Cleared external Storage URL."
            }
            settingsOpen = false
            return
        }
        callCore("lns_browser_core", "config_set", [JSON.stringify({ storage_api: trimmed })], function(v) {
            storageApiInput = v.storage_api || trimmed
            storageBackend = "http"
            problem = ""
            notice = "Saved external Logos Storage API: " + storageApiInput
            settingsOpen = false
            refreshHttpStorageStatus()
        }, function(err) {
            problem = err
        })
    }

    Rectangle {
        anchors.fill: parent
        color: root.slate

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: px(16)
            spacing: px(12)

            // ── Browser Chrome Bar ──────────────────────────────────────
            RowLayout {
                Layout.fillWidth: true
                spacing: px(6)

                Rectangle {
                    width: px(32); height: px(34); radius: px(7)
                    color: root.raised; border.color: root.line
                    opacity: root.historyIdx > 0 ? 1.0 : 0.4
                    Text { anchors.centerIn: parent; text: "←"; color: root.ink; font.pixelSize: px(14) }
                    MouseArea { anchors.fill: parent; enabled: root.historyIdx > 0; cursorShape: Qt.PointingHandCursor; onClicked: root.goBack() }
                }
                Rectangle {
                    width: px(32); height: px(34); radius: px(7)
                    color: root.raised; border.color: root.line
                    opacity: (root.historyIdx >= 0 && root.historyIdx < root.history.length - 1) ? 1.0 : 0.4
                    Text { anchors.centerIn: parent; text: "→"; color: root.ink; font.pixelSize: px(14) }
                    MouseArea { anchors.fill: parent; enabled: root.historyIdx >= 0 && root.historyIdx < root.history.length - 1; cursorShape: Qt.PointingHandCursor; onClicked: root.goForward() }
                }
                Rectangle {
                    width: px(32); height: px(34); radius: px(7)
                    color: root.raised; border.color: root.line
                    Text { anchors.centerIn: parent; text: "↻"; color: root.ink; font.pixelSize: px(14) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.navigate(root.urlInput, false) }
                }

                Rectangle {
                    Layout.fillWidth: true
                    height: px(34)
                    radius: px(8)
                    color: root.card
                    border.color: urlEdit.activeFocus ? root.brass : root.line

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: px(8)
                        anchors.rightMargin: px(8)
                        spacing: px(8)

                        Rectangle {
                            visible: !!root.pageData
                            implicitWidth: badgeTxt.implicitWidth + px(12)
                            height: px(20)
                            radius: px(10)
                            color: root.pageData && root.pageData.verified ? root.good : root.raised
                            Text {
                                id: badgeTxt
                                anchors.centerIn: parent
                                text: root.pageData && root.pageData.mode === "onchain-page"
                                    ? "ON-CHAIN ✓"
                                    : (root.pageData && root.pageData.verified ? "SHA-256 ✓" : "CID")
                                color: root.pageData && root.pageData.verified ? root.slate : root.dim
                                font.family: root.mono
                                font.pixelSize: px(10)
                                font.bold: true
                            }
                        }

                        TextInput {
                            id: urlEdit
                            Layout.fillWidth: true
                            verticalAlignment: TextInput.AlignVCenter
                            color: root.ink
                            font.family: root.mono
                            font.pixelSize: px(13)
                            text: root.urlInput
                            onTextEdited: root.urlInput = text
                            onAccepted: root.navigate(text)
                        }
                    }
                }

                Rectangle {
                    width: px(56); height: px(34); radius: px(7); color: root.brass
                    Text { anchors.centerIn: parent; text: root.loading ? "..." : "Go"; color: root.slate; font.bold: true; font.pixelSize: px(12) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.navigate(root.urlInput) }
                }

                Rectangle {
                    width: px(74); height: px(34); radius: px(7)
                    color: root.publishOpen ? root.brass : root.raised; border.color: root.line
                    Text { anchors.centerIn: parent; text: "Publish"; color: root.publishOpen ? root.slate : root.ink; font.bold: true; font.pixelSize: px(12) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.publishOpen = !root.publishOpen; root.settingsOpen = false } }
                }

                Rectangle {
                    width: px(74); height: px(34); radius: px(7)
                    color: root.settingsOpen ? root.brass : root.raised; border.color: root.line
                    Text { anchors.centerIn: parent; text: "Settings"; color: root.settingsOpen ? root.slate : root.ink; font.pixelSize: px(12) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.settingsOpen = !root.settingsOpen; root.publishOpen = false } }
                }
            }

            // ── External HTTPS Link Confirmation Bar ────────────────────
            Rectangle {
                visible: root.pendingExternalUrl.length > 0
                Layout.fillWidth: true
                implicitHeight: extRow.implicitHeight + px(16)
                radius: px(8)
                color: root.card
                border.color: root.brass

                RowLayout {
                    id: extRow
                    anchors.fill: parent
                    anchors.margins: px(8)
                    spacing: px(8)

                    Text {
                        Layout.fillWidth: true
                        text: "External web link: " + root.pendingExternalUrl
                        color: root.ink
                        font.family: root.mono
                        font.pixelSize: px(11)
                        elide: Text.ElideMiddle
                    }
                    Rectangle {
                        implicitWidth: copyExtTxt.implicitWidth + px(16); height: px(26); radius: px(6); color: root.brass
                        Text { id: copyExtTxt; anchors.centerIn: parent; text: "Copy Link"; color: root.slate; font.bold: true; font.pixelSize: px(11) }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: { root.copyText(root.pendingExternalUrl); root.notice = "Copied " + root.pendingExternalUrl + " — paste it into your browser." }
                        }
                    }
                    Rectangle {
                        implicitWidth: openExtTxt.implicitWidth + px(16); height: px(26); radius: px(6); color: root.raised; border.color: root.line
                        Text { id: openExtTxt; anchors.centerIn: parent; text: "Open in Browser"; color: root.ink; font.pixelSize: px(11) }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: root.openExternalUrl(root.pendingExternalUrl)
                        }
                    }
                    Rectangle {
                        implicitWidth: px(26); height: px(26); radius: px(6); color: root.raised; border.color: root.line
                        Text { anchors.centerIn: parent; text: "✕"; color: root.dim; font.pixelSize: px(11) }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.pendingExternalUrl = "" }
                    }
                }
            }

            // ── Status / Error Strip ────────────────────────────────────
            Text {
                visible: root.problem.length > 0
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                text: root.problem
                color: root.alarm
                font.pixelSize: px(12)
            }
            Text {
                visible: root.notice.length > 0
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                text: root.notice
                color: root.good
                font.pixelSize: px(12)
            }

            // ── Settings Panel ──────────────────────────────────────────
            Rectangle {
                visible: root.settingsOpen
                Layout.fillWidth: true
                implicitHeight: cfgCol.implicitHeight + px(24)
                radius: px(10); color: root.card; border.color: root.line

                ColumnLayout {
                    id: cfgCol
                    anchors.fill: parent; anchors.margins: px(12); spacing: px(8)

                    Text { text: "Logos Storage Node"; color: root.ink; font.bold: true; font.pixelSize: px(13) }
                    Text {
                        Layout.fillWidth: true; wrapMode: Text.WordWrap; color: root.dim; font.pixelSize: px(11)
                        text: root.basecampStorageInstalled
                            ? ("Basecamp's built-in Logos Storage module is installed (" + (root.basecampStorageRunning ? "running" : "stopped") + "). It is used automatically unless you enter an external Storage API URL below.")
                            : "No Logos Storage module is installed in this Basecamp build. You can still browse and publish On-Chain HTML (≤ 78 KB) sites directly on LEZ 0.4 with no storage node. For CID sites, enter a real Logos Storage node URL below (port 8080 is Logos Blockchain, not Storage)."
                    }
                    RowLayout {
                        visible: root.basecampStorageInstalled
                        spacing: px(8)
                        Rectangle {
                            visible: !root.basecampStorageRunning
                            implicitWidth: startStTxt.implicitWidth + px(18); height: px(30); radius: px(7); color: root.brass
                            Text { id: startStTxt; anchors.centerIn: parent; text: root.basecampStorageStarting ? "Starting..." : "Start Basecamp Storage"; color: root.slate; font.bold: true; font.pixelSize: px(11) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.startBasecampStorage() }
                        }
                        Rectangle {
                            visible: root.storageBackend !== "basecamp"
                            implicitWidth: useBcTxt.implicitWidth + px(18); height: px(30); radius: px(7); color: root.raised; border.color: root.line
                            Text { id: useBcTxt; anchors.centerIn: parent; text: "Use Basecamp Storage Module"; color: root.ink; font.pixelSize: px(11) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.storageApiInput = ""; root.saveSettings() } }
                        }
                    }

                    Text { text: "External Logos Storage REST API URL (optional override — never port 8080):"; color: root.dim; font.pixelSize: px(11) }
                    Rectangle {
                        Layout.fillWidth: true; height: px(32); radius: px(6); color: root.slate; border.color: root.line
                        TextInput {
                            anchors.fill: parent; anchors.margins: px(7); color: root.ink; font.family: root.mono; font.pixelSize: px(12)
                            text: root.storageApiInput; onTextEdited: root.storageApiInput = text
                        }
                    }
                    RowLayout {
                        spacing: px(8)
                        Rectangle {
                            width: px(120); height: px(32); radius: px(7); color: root.brass
                            Text { anchors.centerIn: parent; text: "Save"; color: root.slate; font.bold: true; font.pixelSize: px(12) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.saveSettings() }
                        }
                        Rectangle {
                            visible: root.storageApiInput.length > 0
                            width: px(100); height: px(32); radius: px(7); color: root.raised; border.color: root.line
                            Text { anchors.centerIn: parent; text: "Clear URL"; color: root.ink; font.pixelSize: px(12) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.storageApiInput = ""; root.saveSettings() } }
                        }
                    }
                }
            }

            // ── Publish Panel (Real Logos Storage CID or On-Chain SetPage → Names Deep Link) ──
            Rectangle {
                visible: root.publishOpen
                Layout.fillWidth: true
                implicitHeight: pubCol.implicitHeight + px(24)
                radius: px(10); color: root.card; border.color: root.brass

                ColumnLayout {
                    id: pubCol
                    anchors.fill: parent; anchors.margins: px(12); spacing: px(8)

                    Text { text: "Publish LNS Website (hands off to Names to verify ownership & sign)"; color: root.ink; font.bold: true; font.pixelSize: px(13); Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    RowLayout {
                        spacing: px(8)
                        Rectangle {
                            implicitWidth: cidModeTxt.implicitWidth + px(18); height: px(28); radius: px(6)
                            color: root.pubMode === "cid" ? root.brass : root.raised; border.color: root.line
                            Text { id: cidModeTxt; anchors.centerIn: parent; text: "Logos Storage CID (P2P)"; color: root.pubMode === "cid" ? root.slate : root.ink; font.bold: root.pubMode === "cid"; font.pixelSize: px(11) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.pubMode = "cid" }
                        }
                        Rectangle {
                            implicitWidth: pageModeTxt.implicitWidth + px(18); height: px(28); radius: px(6)
                            color: root.pubMode === "page" ? root.brass : root.raised; border.color: root.line
                            Text { id: pageModeTxt; anchors.centerIn: parent; text: "On-Chain HTML (≤ 78 KB)"; color: root.pubMode === "page" ? root.slate : root.ink; font.bold: root.pubMode === "page"; font.pixelSize: px(11) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.pubMode = "page" }
                        }
                    }

                    Text {
                        visible: root.pubMode === "cid" && root.storageBackend === "none"
                        Layout.fillWidth: true; wrapMode: Text.WordWrap; color: root.alarm; font.pixelSize: px(11)
                        text: "No Logos Storage module is installed in Basecamp and no external Storage node is configured. Use On-Chain HTML (≤ 78 KB) above so anyone can open your page right away, or set a real Logos Storage node in Settings."
                    }

                    RowLayout {
                        Layout.fillWidth: true; spacing: px(8)
                        Text { text: "LNS Name:"; color: root.dim; font.pixelSize: px(12); Layout.preferredWidth: px(80) }
                        Rectangle {
                            Layout.fillWidth: true; height: px(30); radius: px(6); color: root.slate; border.color: root.line
                            TextInput { anchors.fill: parent; anchors.margins: px(6); color: root.ink; font.family: root.mono; font.pixelSize: px(12); text: root.pubName; onTextEdited: root.pubName = text }
                        }
                    }

                    RowLayout {
                        visible: root.pubMode === "cid"
                        Layout.fillWidth: true; spacing: px(8)
                        Text { text: "File path:"; color: root.dim; font.pixelSize: px(12); Layout.preferredWidth: px(80) }
                        Rectangle {
                            Layout.fillWidth: true; height: px(30); radius: px(6); color: root.slate; border.color: root.line
                            TextInput { anchors.fill: parent; anchors.margins: px(6); color: root.ink; font.family: root.mono; font.pixelSize: px(12); text: root.pubLocalPath; onTextEdited: root.pubLocalPath = text }
                        }
                    }

                    Text {
                        text: root.pubMode === "cid"
                            ? "Or paste HTML directly (uploaded to a real Logos Storage node when File path is blank):"
                            : ("HTML stored directly on LEZ (" + Logic.utf8ToBytes(root.pubHtml).length + " / 79,872 bytes — readable by everyone without a storage node):")
                        color: root.dim; font.pixelSize: px(11); wrapMode: Text.WordWrap; Layout.fillWidth: true
                    }
                    Rectangle {
                        Layout.fillWidth: true; height: px(110); radius: px(6); color: root.slate; border.color: root.line
                        Flickable {
                            anchors.fill: parent; anchors.margins: px(6); contentHeight: htmlEdit.implicitHeight; clip: true
                            TextEdit {
                                id: htmlEdit
                                width: parent.width
                                color: root.ink; font.family: root.mono; font.pixelSize: px(11); wrapMode: TextEdit.Wrap
                                text: root.pubHtml; onTextChanged: root.pubHtml = text
                            }
                        }
                    }

                    RowLayout {
                        spacing: px(8)
                        Rectangle {
                            implicitWidth: pubBtnTxt.implicitWidth + px(24); height: px(34); radius: px(7); color: root.brass
                            Text {
                                id: pubBtnTxt
                                anchors.centerIn: parent
                                text: root.loading
                                    ? "Publishing..."
                                    : (root.pubMode === "cid" ? "Upload to Logos Storage & Publish" : "Publish On-Chain in Names")
                                color: root.slate; font.bold: true; font.pixelSize: px(12)
                            }
                            MouseArea { anchors.fill: parent; enabled: !root.loading; cursorShape: Qt.PointingHandCursor; onClicked: root.publishAndBind() }
                        }
                        Rectangle {
                            visible: root.lastDeepLink.length > 0
                            implicitWidth: copyLinkTxt.implicitWidth + px(18); height: px(34); radius: px(7); color: root.raised; border.color: root.line
                            Text { id: copyLinkTxt; anchors.centerIn: parent; text: "Copy Names Deep Link"; color: root.ink; font.pixelSize: px(11) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.copyText(root.lastDeepLink) }
                        }
                    }
                }
            }

            // ── Main Content Area ───────────────────────────────────────
            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: px(12)

                Rectangle {
                    visible: root.filesOpen && !!root.pageData && root.pageData.files && root.pageData.files.length > 0
                    Layout.preferredWidth: px(210)
                    Layout.fillHeight: true
                    radius: px(10); color: root.card; border.color: root.line

                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: px(10); spacing: px(6)
                        Text { text: "Site Files"; color: root.dim; font.bold: true; font.pixelSize: px(12) }

                        ListView {
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: px(4)
                            model: (root.pageData && root.pageData.files) ? root.pageData.files : []
                            delegate: Rectangle {
                                width: ListView.view.width; height: px(28); radius: px(6)
                                color: (root.pageData && root.pageData.path === modelData.path) ? root.raised : "transparent"
                                Text {
                                    anchors.verticalCenter: parent.verticalCenter; anchors.left: parent.left; anchors.leftMargin: px(8)
                                    text: modelData.path; color: root.ink; font.family: root.mono; font.pixelSize: px(11); elide: Text.ElideMiddle
                                }
                                MouseArea {
                                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                    onClicked: { if (root.parsedUrl) root.navigate(root.parsedUrl.siteBase + modelData.path) }
                                }
                            }
                        }
                    }
                }

                // Native Zero-JS, Zero-Network-Leak Page Viewport
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    radius: px(12)
                    color: root.pageBg
                    border.color: root.line

                    Flickable {
                        anchors.fill: parent
                        anchors.margins: px(24)
                        contentWidth: width
                        contentHeight: pageCol.implicitHeight
                        clip: true

                        ColumnLayout {
                            id: pageCol
                            width: Math.min(parent.width, px(780))
                            anchors.horizontalCenter: parent.horizontalCenter
                            spacing: px(12)

                            Text {
                                visible: !!root.pageData
                                text: root.pageData
                                    ? (root.pageData.mode === "onchain-page"
                                        ? "Stored directly on LEZ · verified on-chain"
                                        : ("CID: " + Logic.shortHash(root.pageData.cid, 12, 8) + "  ·  SHA-256: " + Logic.shortHash(root.pageData.sha256, 10, 8) + (root.pageData.verified ? "  ·  verified on-chain" : "")))
                                    : ""
                                color: root.pageDim
                                font.family: root.mono
                                font.pixelSize: px(11)
                                wrapMode: Text.WrapAnywhere
                                Layout.fillWidth: true
                            }

                            Repeater {
                                model: (root.pageData && root.pageData.blocks && root.pageData.blocks.length > 0)
                                    ? root.pageData.blocks
                                    : (root.pageData && root.pageData.html ? [{ kind: "html", html: root.pageData.html }] : [])

                                delegate: Item {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    implicitHeight: modelData.kind === "svg"
                                        ? svgCanvas.height
                                        : (modelData.kind === "image" ? imgItem.height : txtItem.implicitHeight)

                                    Canvas {
                                        id: svgCanvas
                                        visible: modelData.kind === "svg"
                                        width: Math.min(parent.width, modelData.width ? px(modelData.width) : parent.width)
                                        height: (modelData.vb_w && modelData.vb_h && modelData.vb_w > 0)
                                            ? Math.max(px(24), Math.round(width * modelData.vb_h / modelData.vb_w))
                                            : px(100)
                                        renderStrategy: Canvas.Cooperative
                                        onPaint: {
                                            if (modelData.kind !== "svg") return
                                            var ctx = getContext("2d")
                                            Logic.drawSvgToCanvas(ctx, modelData, width, height)
                                        }
                                        onWidthChanged: if (visible) requestPaint()
                                        onHeightChanged: if (visible) requestPaint()
                                        Component.onCompleted: if (visible) requestPaint()
                                    }

                                    Image {
                                        id: imgItem
                                        visible: modelData.kind === "image"
                                        width: Math.min(parent.width, modelData.width ? px(modelData.width) : parent.width)
                                        height: (modelData.width && modelData.height && modelData.width > 0)
                                            ? Math.round(width * modelData.height / modelData.width)
                                            : implicitHeight
                                        source: modelData.kind === "image" && modelData.data_uri ? modelData.data_uri : ""
                                        fillMode: Image.PreserveAspectFit
                                        smooth: false
                                        asynchronous: false
                                    }

                                    Text {
                                        id: txtItem
                                        visible: modelData.kind !== "image" && modelData.kind !== "svg"
                                        width: parent.width
                                        textFormat: Text.RichText
                                        wrapMode: Text.WordWrap
                                        color: root.pageFg
                                        linkColor: root.pageLink
                                        font.family: root.sans
                                        font.pixelSize: px(15)
                                        lineHeight: 1.45
                                        text: modelData.html ? modelData.html : ""
                                        onLinkActivated: function(link) { root.activateLink(link) }
                                    }
                                }
                            }

                            // Fallback when an LNS name exists but has no CID or on-chain page yet
                            ColumnLayout {
                                visible: !root.pageData && !!root.siteInfo && !root.siteInfo.hasSite
                                Layout.fillWidth: true
                                spacing: px(8)
                                Text { text: root.siteInfo ? root.siteInfo.display : ""; color: root.ink; font.pixelSize: px(18); font.bold: true }
                                Text { visible: !!root.siteInfo && root.siteInfo.bio.length > 0; text: root.siteInfo ? root.siteInfo.bio : ""; color: root.dim; wrapMode: Text.WordWrap; Layout.fillWidth: true }
                                Text { text: "This LNS name has no website published yet. Click Publish to bind one."; color: root.dim; font.pixelSize: px(12) }
                            }

                            // Home / empty state
                            ColumnLayout {
                                visible: !root.pageData && !root.siteInfo
                                Layout.fillWidth: true
                                spacing: px(10)
                                Text { text: "Logos Native LNS Browser"; color: root.ink; font.pixelSize: px(20); font.bold: true }
                                Text {
                                    Layout.fillWidth: true; wrapMode: Text.WordWrap; color: root.dim; font.pixelSize: px(13)
                                    text: "Browse lns://<name> sites natively inside Basecamp. Content is fetched from LEZ or Logos Storage (via Basecamp's built-in Storage module), verified on-chain, and rendered with zero JavaScript and zero external network connections."
                                }
                            }
                        }
                    }
                }
            }

            // ── Bottom Status Bar ───────────────────────────────────────
            RowLayout {
                Layout.fillWidth: true
                Text {
                    text: root.storageBackend === "basecamp"
                        ? (root.basecampStorageRunning
                            ? ("Logos Storage: Basecamp node online" + (root.basecampPeerId ? (" (" + Logic.shortHash(root.basecampPeerId, 10, 6) + (root.basecampNetwork ? " · " + root.basecampNetwork : "") + ")") : ""))
                            : (root.basecampStorageStarting ? "Logos Storage: Starting Basecamp Storage node..." : "Logos Storage: Basecamp Storage node stopped (open Settings to start)"))
                        : root.storageBackend === "http"
                            ? (root.storageInfo && root.storageInfo.online
                                ? (root.storageInfo.mock
                                    ? ("Logos Storage: Stand-in mock (" + root.storageApiInput + ") — publishing blocked")
                                    : ("Logos Storage: External node online (" + root.storageApiInput + ")"))
                                : ("Logos Storage: External node unreachable (" + root.storageApiInput + ")"))
                            : root.storageBackend === "checking"
                                ? "Logos Storage: Checking Basecamp Storage module..."
                                : "No Logos Storage module installed — On-Chain HTML (≤ 78 KB) works now; configure Storage in Settings for CIDs"
                    color: (root.storageBackend === "basecamp" && root.basecampStorageRunning)
                        || (root.storageBackend === "http" && root.storageInfo && root.storageInfo.online && !root.storageInfo.mock)
                        ? root.good : root.dim
                    font.family: root.mono
                    font.pixelSize: px(11)
                }
                Item { Layout.fillWidth: true }
                Text {
                    text: "In-Basecamp sandbox · Zero JS · Click-to-confirm https://"
                    color: root.dim
                    font.family: root.mono
                    font.pixelSize: px(11)
                }
            }
        }
    }
}
