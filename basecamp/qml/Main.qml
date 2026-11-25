import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Logos.Theme
import "logic.mjs" as Logic

// Basecamp LNS Browser Start Page & Core/Storage Host.
// Architecture (Round 6):
// - The Basecamp tab is the Start Page (address box, bookmarks, history, recently opened sites,
//   "Open Browser Window" button, Publish panel, Settings panel).
// - Pages open in `BrowserWindow.qml`: a normal titled macOS/desktop Window containing QtWebView
//   backed by the per-site loopback HTTP/1.1 server in `lns_browser_core` (strict CSP, isolated
//   ephemeral 127.0.0.1:<port>/<token>/ origin, verified SHA-256 bytes, sterilised JS ON by default,
//   one-click Reader Mode fallback inside the same window).
// - Unloading the app closes the browser window and shuts down all loopback servers.
Item {
    id: root
    readonly property bool bridgeReady: typeof logos !== "undefined" && logos !== null

    property string startUrlInput: ""
    property bool loading: false
    property string problem: ""
    property string notice: ""

    // Persisted browser data (stored via lns_browser_core in ~/.config/lns-browser/)
    property var bookmarks: []
    property var browsingHistory: []
    property var recentSites: []
    property bool defaultReaderMode: false

    // Reader Mode caches & state (per-folder `lns-links/1` + raster image cache)
    property var linksCache: ({})
    property var imageCache: ({})
    property var activeRootList: null
    property var activeWalk: null
    property var pendingImages: []
    property var activeImageTask: null
    property var activeSave: null
    property string downloadsDir: ""

    // Storage backend state: "checking" | "basecamp" | "http" | "none"
    property string storageBackend: "checking"
    property bool basecampStorageInstalled: false
    property bool basecampStorageRunning: false
    property bool basecampStorageReady: false
    property bool basecampStorageStarting: false
    property string basecampPeerId: ""
    property string basecampNetwork: ""
    property var storageInfo: null
    property string storageApiInput: ""   // NEVER defaults to 127.0.0.1:8080 (Logos Blockchain port)
    property string storagePeersInput: "" // One per line: "peerId /ip4/…/tcp/…"
    property string peerConnectStatus: ""
    property var peerConnectQueue: null

    // Active storage_module async download / upload state
    property var activeDownload: null
    property var activeUpload: null
    property var pendingResolve: null
    property int resolveSeq: 0
    property int readerTabId: -1
    property int readerNavSeq: 0
    property var readerPageData: null
    property var readerSiteInfo: null
    property string readerSiteBase: ""

    property bool settingsOpen: false
    property bool publishOpen: false

    property string pubName: ""
    property string pubTitle: ""
    property string pubLocalPath: ""
    property string pubMode: "page"
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

    BrowserWindow {
        id: browserWindow
        host: root
    }

    Component.onCompleted: {
        linksCache = Logic.createSafeMap()
        imageCache = Logic.createSafeMap()
        initStorage()
        loadPersistedBrowserData()
    }

    Component.onDestruction: {
        browserWindow.shutdownOnAppUnload()
        if (bridgeReady) {
            callCore("lns_browser_core", "site_close_all", [], function() {}, function() {}, 2000)
        }
    }

    Timer {
        id: saveTimeoutTimer
        interval: 30000
        repeat: false
        onTriggered: {
            if (root.activeSave !== null) {
                var sv = root.activeSave
                root.activeSave = null
                root.loading = false
                var svMsg = Logic.formatStorageFetchError(sv.cid, sv.path || sv.filename, "timed out saving file from Logos Storage")
                root.problem = svMsg
                browserWindow.onCoreDownloadFinished(false, sv.filename, sv.savePath, false, svMsg)
            }
        }
    }

    Timer {
        id: downloadTimeoutTimer
        interval: 25000
        repeat: false
        onTriggered: {
            if (root.activeDownload !== null) {
                var dl = root.activeDownload
                root.activeDownload = null
                if (dl.navSeq !== root.readerNavSeq || dl.tabId !== root.readerTabId) return
                if (dl.purpose === "image" || dl.purpose === "image_dir") {
                    root.activeImageTask = null
                    root.fetchNextQueuedImage()
                    return
                }
                root.activeWalk = null
                var errMsg = Logic.formatStorageFetchError(dl.cid, dl.requestedPath || dl.path || "/", "timed out waiting for Logos Storage peers")
                browserWindow.attachTabStorageError(dl.tabId, dl.navSeq, dl.cid, dl.requestedPath || dl.path || "/", errMsg)
            }
        }
    }

    Timer {
        id: peerConnectTimeoutTimer
        interval: 6000
        repeat: false
        onTriggered: {
            if (root.peerConnectQueue !== null) {
                var q = root.peerConnectQueue
                var peer = q.peers[q.idx]
                q.errors.push("Timed out connecting to storage peer " + Logic.shortHash(peer.peerId, 10, 6))
                q.idx += 1
                root.stepPeerConnectQueue()
            }
        }
    }

    Timer {
        id: resolveRetryTimer
        interval: 1000
        repeat: false
        onTriggered: root.runPendingResolve()
    }

    // Handle incoming `lns.browse` intents and `storage_module` events
    Connections {
        target: root.bridgeReady ? logos : null
        ignoreUnknownSignals: true

        function onIntentRequested(requestId, intent, params, requesterName) {
            if (intent !== "lns.browse")
                return
            var wanted = String(params && params.url ? params.url : "")
            if (wanted !== "") root.openInBrowserWindow(wanted)
            else browserWindow.openAndRaise()
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
                    root.verifyBasecampStorageReadyAndConnect()
                } else {
                    root.basecampStorageRunning = false
                    root.basecampStorageReady = false
                    var startErr = String(payload.message || payload.error || JSON.stringify(payload))
                    console.log("lns_browser: storageStart failed:", startErr)
                    root.problem = "Basecamp Storage module failed to start: " + startErr
                }
                return
            }

            if (eventName === "storageConnect" && root.peerConnectQueue !== null) {
                peerConnectTimeoutTimer.stop()
                var q = root.peerConnectQueue
                var peer = q.peers[q.idx]
                if (payload.success === true) {
                    q.connected += 1
                } else {
                    var detail = String(payload.message || payload.error || JSON.stringify(payload))
                    q.errors.push("Could not connect to storage peer " + Logic.shortHash(peer.peerId, 10, 6) + ": " + detail)
                }
                q.idx += 1
                root.stepPeerConnectQueue()
                return
            }

            if (eventName === "storageDownloadProgress" && root.activeDownload !== null) {
                if (root.activeDownload.navSeq !== root.readerNavSeq || root.activeDownload.tabId !== root.readerTabId) {
                    root.activeDownload = null
                    downloadTimeoutTimer.stop()
                    return
                }
                if (String(payload.sessionId || "") === root.activeDownload.cid && payload.chunk) {
                    var chunkStr = String(payload.chunk)
                    var chunkBytes = Logic.base64DecodedLength(chunkStr)
                    root.activeDownload.receivedBytes += chunkBytes
                    if (root.activeDownload.receivedBytes > root.activeDownload.maxBytes) {
                        downloadTimeoutTimer.stop()
                        var overDl = root.activeDownload
                        root.activeDownload = null
                        if (overDl.purpose === "image" || overDl.purpose === "image_dir") {
                            root.activeImageTask = null
                            root.fetchNextQueuedImage()
                            return
                        }
                        root.activeWalk = null
                        browserWindow.attachTabStorageError(
                            overDl.tabId,
                            overDl.navSeq,
                            overDl.cid,
                            overDl.requestedPath || overDl.path || "/",
                            "Download exceeds limit of " + overDl.maxBytes + " bytes"
                        )
                        return
                    }
                    root.activeDownload.chunks.push(chunkStr)
                }
                return
            }

            if (eventName === "storageDownloadDone") {
                var sid = String(payload.sessionId || "")

                // 1. User binary download save (through core -> ~/Downloads)
                if (root.activeSave !== null && sid === root.activeSave.cid) {
                    saveTimeoutTimer.stop()
                    var sv = root.activeSave
                    root.activeSave = null
                    if (payload.success) {
                        if (sv.sha256 && sv.sha256.length === 64) {
                            root.callCore("lns_browser_core", "verify_saved_file", [sv.savePath, sv.sha256], function() {
                                root.loading = false
                                var okMsg = "Saved and verified " + sv.filename + " to " + sv.savePath
                                root.notice = okMsg
                                browserWindow.onCoreDownloadFinished(true, sv.filename, sv.savePath, true, okMsg)
                            }, function(verErr) {
                                root.loading = false
                                root.problem = verErr
                                browserWindow.onCoreDownloadFinished(false, sv.filename, sv.savePath, false, verErr)
                            }, 30000)
                        } else {
                            root.loading = false
                            var unpinnedMsg = "Saved " + sv.filename + " to " + sv.savePath + " (unpinned CID — no SHA-256 in list)"
                            root.notice = unpinnedMsg
                            browserWindow.onCoreDownloadFinished(true, sv.filename, sv.savePath, false, unpinnedMsg)
                        }
                    } else {
                        root.loading = false
                        var svErr = Logic.formatStorageFetchError(sv.cid, sv.path || sv.filename, payload.error || "download failed")
                        root.problem = svErr
                        browserWindow.onCoreDownloadFinished(false, sv.filename, sv.savePath, false, svErr)
                    }
                    return
                }

                // 2. Reader Mode chunked download
                if (root.activeDownload !== null && sid === root.activeDownload.cid) {
                    downloadTimeoutTimer.stop()
                    var dl = root.activeDownload
                    root.activeDownload = null
                    if (dl.navSeq !== root.readerNavSeq || dl.tabId !== root.readerTabId)
                        return
                    if (!payload.success) {
                        if (dl.purpose === "image" || dl.purpose === "image_dir") {
                            root.activeImageTask = null
                            root.fetchNextQueuedImage()
                            return
                        }
                        root.activeWalk = null
                        var failMsg = Logic.formatStorageFetchError(dl.cid, dl.requestedPath || dl.path || "/", payload.error || "not found on network")
                        browserWindow.attachTabStorageError(dl.tabId, dl.navSeq, dl.cid, dl.requestedPath || dl.path || "/", failMsg)
                        return
                    }
                    root.finishBasecampDownload(dl)
                    return
                }

                // 3. Loopback HTTP server `downloadToUrl` completion -> wake Rust core directly (zero bytes through QML!)
                if (sid !== "" && browserWindow.hasAnyLoopbackSite()) {
                    root.callCore(
                        "lns_browser_core",
                        "site_blob_ready",
                        [sid, "", payload.success ? "true" : "false", String(payload.error || "")],
                        function() {},
                        function() {},
                        5000
                    )
                }
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

    function openInBrowserWindow(rawUrl) {
        var clean = String(rawUrl || "").trim()
        if (!clean) {
            browserWindow.openAndRaise()
            return
        }
        var parsed = Logic.parseUrl(clean)
        if (!parsed.ok) {
            problem = parsed.error
            return
        }
        problem = ""
        startUrlInput = parsed.canonical
        browserWindow.openUrlFromExternal(parsed.canonical)
    }

    // ── Core Persistence (Bookmarks, History, Window Geometry) ───────────
    function loadPersistedBrowserData() {
        callCore("lns_browser_core", "bookmarks_get", [], function(list) {
            bookmarks = Logic.toArray(list)
        }, function() {}, 5000)
        callCore("lns_browser_core", "history_get", [], function(list) {
            var arr = Logic.toArray(list)
            browsingHistory = arr
            recentSites = Logic.extractRecentSites(arr, 8)
        }, function() {}, 5000)
        callCore("lns_browser_core", "browser_state_get", [], function(st) {
            if (st && typeof st.reader_mode === "boolean") {
                defaultReaderMode = st.reader_mode
            }
            browserWindow.applySavedGeometry(st && st.window ? st.window : null)
        }, function() {
            browserWindow.applySavedGeometry(null)
        }, 5000)
    }

    function saveBrowserState(patch) {
        callCore("lns_browser_core", "browser_state_set", [JSON.stringify(patch || {})], function() {}, function() {}, 5000)
    }

    function toggleBookmarkEntry(entry) {
        var res = Logic.toggleBookmark(bookmarks, entry)
        bookmarks = res.bookmarks
        callCore("lns_browser_core", "bookmarks_set", [JSON.stringify(bookmarks)], function(saved) {
            if (saved) bookmarks = Logic.toArray(saved)
        }, function() {}, 5000)
    }

    function removeBookmarkUrl(url) {
        toggleBookmarkEntry({ url: url })
    }

    function recordVisitedPage(entry) {
        browsingHistory = Logic.recordHistoryEntry(browsingHistory, entry, 200)
        recentSites = Logic.extractRecentSites(browsingHistory, 8)
        callCore("lns_browser_core", "history_add", [JSON.stringify(entry)], function(saved) {
            if (saved) {
                var arr = Logic.toArray(saved)
                browsingHistory = arr
                recentSites = Logic.extractRecentSites(arr, 8)
            }
        }, function() {}, 5000)
    }

    function clearBrowsingHistory() {
        browsingHistory = []
        recentSites = []
        callCore("lns_browser_core", "history_clear", [], function() {}, function() {}, 5000)
    }

    function closeLoopbackSite(token) {
        if (!token) return
        callCore("lns_browser_core", "site_close", [String(token)], function() {}, function() {}, 4000)
    }

    function startCoreDownload(token, cid, relPath, filename, pinnedSha256, onStarted, onError) {
        callCore("lns_browser_core", "site_download_file", [String(token || ""), String(cid || ""), String(relPath || ""), String(filename || "")], function(info) {
            if (info && info.done) {
                if (onStarted) onStarted(info)
                return
            }
            if (info && info.cid) {
                activeSave = {
                    cid: info.cid,
                    sha256: info.sha256 || pinnedSha256 || "",
                    filename: info.filename || filename || "download",
                    savePath: info.path || "",
                    path: relPath || info.filename || filename || ""
                }
                saveTimeoutTimer.restart()
                if (onStarted) onStarted(info)
            } else if (onError) {
                onError("Unexpected download reply from core")
            }
        }, function(errMsg) {
            if (onError) onError(errMsg)
        }, 60000)
    }

    function openExternalUrl(rawUrl) {
        var target = String(rawUrl || "").trim()
        if (!Logic.isExternalHttpsUrl(target)) {
            problem = "Only https:// external links can be opened."
            return
        }
        callCore("lns_browser_core", "open_external_url", [target], function() {
            problem = ""
            notice = "Opened " + target + " in your browser."
        }, function(err) {
            var opened = false
            try { opened = Qt.openUrlExternally(target) } catch (e) { opened = false }
            if (opened) {
                notice = "Opened " + target + " in your browser."
            } else {
                copyText(target)
                notice = "Could not launch browser (" + err + ") — copied " + target + " to your clipboard."
            }
        }, 10000)
    }

    function callCore(moduleName, method, args, done, failed, timeoutMs) {
        if (!bridgeReady) {
            Qt.callLater(function() { failed("Run inside Basecamp with `" + moduleName + "` loaded.") })
            return
        }
        logos.callModuleAsync(moduleName, method, args, function(reply) {
            var res = Logic.answer(reply)
            if (res.ok) {
                done(res.value)
            } else {
                var rawStr = ""
                try { rawStr = typeof reply === "string" ? reply : JSON.stringify(reply) } catch (e) { rawStr = String(reply) }
                console.log("lns_browser: " + moduleName + "." + method + " failed: " + res.error + " (raw=" + rawStr + ")")
                failed(res.error)
            }
        }, timeoutMs || 30000)
    }

    function callNamesWithRetry(method, name, onResult, onError) {
        resolveRetryTimer.stop()
        resolveSeq += 1
        pendingResolve = {
            seq: resolveSeq,
            method: method,
            name: name,
            attempt: 0,
            onResult: onResult,
            onError: onError
        }
        runPendingResolve()
    }

    function resolveNameWithRetry(name, onResult, onError) {
        callNamesWithRetry("resolve", name, onResult, onError)
    }

    function pageNameWithRetry(name, onResult, onError) {
        callNamesWithRetry("page", name, onResult, onError)
    }

    function runPendingResolve() {
        var req = pendingResolve
        if (req === null) return
        if (!bridgeReady) {
            pendingResolve = null
            req.onError("Run inside Basecamp with `names` loaded.")
            return
        }
        var seq = req.seq
        logos.callModuleAsync("names", req.method, [req.name], function(reply) {
            if (pendingResolve === null || pendingResolve.seq !== seq) return
            var res = Logic.answer(reply)
            if (Logic.isBusyReply(reply, res.ok ? "" : res.error)) {
                if (req.attempt < 20) {
                    req.attempt += 1
                    notice = "Names is busy — retrying (" + req.attempt + "/20)..."
                    resolveRetryTimer.restart()
                    return
                }
                pendingResolve = null
                req.onError("Names module stayed busy after 20 retries (" + req.method + ").")
                return
            }
            if (res.ok) {
                pendingResolve = null
                req.onResult(res.value)
                return
            }
            pendingResolve = null
            req.onError(res.error)
        }, 30000)
    }

    // ── Storage Lifecycle ────────────────────────────────────────────────
    function initStorage() {
        storageBackend = "checking"
        if (bridgeReady && logos.onModuleEvent) {
            logos.onModuleEvent("storage_module", "storageStart")
            logos.onModuleEvent("storage_module", "storageConnect")
            logos.onModuleEvent("storage_module", "storageDownloadProgress")
            logos.onModuleEvent("storage_module", "storageDownloadDone")
            logos.onModuleEvent("storage_module", "storageUploadProgress")
            logos.onModuleEvent("storage_module", "storageUploadDone")
        }
        callCore("lns_browser_core", "config_get", [], function(cfg) {
            if (cfg && typeof cfg.storage_peers_text === "string") storagePeersInput = cfg.storage_peers_text
            if (cfg && typeof cfg.downloads_dir === "string") downloadsDir = cfg.downloads_dir
            probeStorageBackends()
        }, function() {
            probeStorageBackends()
        }, 5000)
    }

    function probeStorageBackends() {
        callCore("storage_module", "isRunning", [], function(running) {
            basecampStorageInstalled = true
            basecampStorageRunning = (running === true)
            storageBackend = "basecamp"
            if (basecampStorageRunning) {
                verifyBasecampStorageReadyAndConnect()
            } else {
                basecampStorageReady = false
                startBasecampStorage()
            }
        }, function() {
            basecampStorageInstalled = false
            basecampStorageRunning = false
            basecampStorageReady = false
            refreshHttpStorageStatus()
        }, 5000)
    }

    function verifyBasecampStorageReadyAndConnect() {
        callCore("storage_module", "peerId", [], function(pid) {
            var cleanPid = String(pid || "").trim()
            if (cleanPid !== "") {
                basecampPeerId = cleanPid
                basecampStorageRunning = true
                basecampStorageReady = true
                callCore("storage_module", "network", [], function(net) {
                    basecampNetwork = String(net || "")
                }, function() {}, 5000)
                connectStoragePeers(null)
            } else {
                basecampStorageReady = false
            }
        }, function() {
            basecampStorageReady = false
        }, 5000)
    }

    function connectStoragePeers(onDone) {
        var parsed = Logic.parseStoragePeers(storagePeersInput)
        if (!parsed.ok) {
            peerConnectStatus = parsed.errors.join("; ")
            problem = "Storage peers config error: " + peerConnectStatus
            if (onDone) onDone(false, peerConnectStatus)
            return
        }
        if (parsed.peers.length === 0) {
            peerConnectStatus = ""
            if (onDone) onDone(true, "")
            return
        }
        if (!basecampStorageReady) {
            peerConnectStatus = "Waiting for Basecamp Storage node to finish starting..."
            if (onDone) onDone(false, peerConnectStatus)
            return
        }
        peerConnectQueue = { peers: parsed.peers, idx: 0, errors: [], connected: 0, onDone: onDone }
        stepPeerConnectQueue()
    }

    function stepPeerConnectQueue() {
        var q = peerConnectQueue
        if (q === null) return
        if (q.idx >= q.peers.length) {
            peerConnectTimeoutTimer.stop()
            peerConnectQueue = null
            var errMsg = q.errors.join(" · ")
            if (q.errors.length > 0 && q.connected === 0) {
                peerConnectStatus = errMsg
            } else if (q.errors.length > 0) {
                peerConnectStatus = "Connected to " + q.connected + "/" + q.peers.length + " peers (" + errMsg + ")"
            } else {
                peerConnectStatus = "Connected to " + q.connected + " storage peer" + (q.connected === 1 ? "" : "s")
            }
            if (q.onDone) q.onDone(q.errors.length === 0 || q.connected > 0, errMsg)
            return
        }
        var peer = q.peers[q.idx]
        peerConnectTimeoutTimer.restart()
        callCore("lns_browser_core", "storage_connect_peer", [peer.peerId, JSON.stringify(peer.addrs)], function() {}, function(err) {
            peerConnectTimeoutTimer.stop()
            q.errors.push("Could not connect to storage peer " + Logic.shortHash(peer.peerId, 10, 6) + ": " + String(err || "error"))
            q.idx += 1
            stepPeerConnectQueue()
        }, 12000)
    }

    function startBasecampStorage() {
        if (!basecampStorageInstalled || basecampStorageStarting) return
        basecampStorageStarting = true
        basecampStorageReady = false
        callCore("storage_module", "loadConfigOrDefault", [], function(cfg) {
            var cfgStr = typeof cfg === "string" ? cfg : JSON.stringify(cfg || {})
            callCore("storage_module", "init", [cfgStr], function() {
                callCore("storage_module", "start", [], function() {}, function(err) {
                    basecampStorageStarting = false
                    if (String(err).toLowerCase().indexOf("already") !== -1) {
                        basecampStorageRunning = true
                        verifyBasecampStorageReadyAndConnect()
                    }
                }, 15000)
            }, function() {
                callCore("storage_module", "start", [], function() {}, function(err) {
                    basecampStorageStarting = false
                    if (String(err).toLowerCase().indexOf("already") !== -1) {
                        basecampStorageRunning = true
                        verifyBasecampStorageReadyAndConnect()
                    }
                }, 15000)
            }, 15000)
        }, function() {
            basecampStorageStarting = false
        }, 10000)
    }

    function refreshHttpStorageStatus() {
        callCore("lns_browser_core", "storage_status", [], function(v) {
            storageInfo = v
            var api = v && v.storage_api ? String(v.storage_api).trim() : ""
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

    // ── Tab Navigation (WebKit Loopback Mode + Reader Mode Fallback) ─────
    function openLoopbackForTab(tabId, navSeq, spec, siteInfoObj) {
        callCore("lns_browser_core", "site_open", [JSON.stringify(spec)], function(openInfo) {
            browserWindow.attachLoopbackSite(tabId, navSeq, openInfo, siteInfoObj)
        }, function(errMsg) {
            browserWindow.attachTabStorageError(tabId, navSeq, spec.root_cid || "", spec.path || "/", "Could not start local site server: " + errMsg)
        }, 15000)
    }

    function loadTabNavigation(tabId, navSeq, parsed, useReaderMode) {
        resolveRetryTimer.stop()
        pendingResolve = null

        if (useReaderMode) {
            downloadTimeoutTimer.stop()
            activeDownload = null
            activeWalk = null
            activeRootList = null
            pendingImages = []
            activeImageTask = null
            readerTabId = tabId
            readerNavSeq = navSeq
            readerPageData = null
            readerSiteBase = parsed.siteBase
        }

        if (parsed.kind === "cid") {
            var cidInfo = { name: "", display: "Direct CID", bio: "", cid: parsed.cid, sha256: "", siteType: "", hasSite: true, texts: {} }
            if (useReaderMode) {
                readerSiteInfo = cidInfo
                fetchCidPageReader(tabId, navSeq, parsed.cid, "", parsed.siteBase, parsed.path, "", cidInfo)
                return
            }
            openCidInLoopback(tabId, navSeq, parsed, parsed.cid, "", "", cidInfo)
            return
        }

        resolveNameWithRetry(parsed.name, function(record) {
            if (!record) {
                browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, "LNS name not registered on LEZ: " + parsed.name)
                return
            }
            var info = Logic.extractSiteInfo(record)
            pubName = parsed.name
            if (info.hasSite) {
                if (useReaderMode) {
                    readerSiteInfo = info
                    fetchCidPageReader(tabId, navSeq, info.cid, info.sha256, parsed.siteBase, parsed.path, info.siteType, info)
                    return
                }
                openCidInLoopback(tabId, navSeq, parsed, info.cid, info.sha256, info.siteType, info)
                return
            }

            // Fallback: on-chain SetPage (HTML or < 10 KB lns-links/1)
            pageNameWithRetry(parsed.name, function(pg) {
                if (pg && pg.text && pg.text.length > 0) {
                    var pgCt = pg.content_type || pg.contentType || ""
                    if (Logic.isLinksContentType(pgCt) || Logic.isLinksListText(pg.text)) {
                        var byteLen = Logic.utf8ToBytes(pg.text).length
                        if (byteLen >= Logic.MAX_ONCHAIN_LINKS_BYTES) {
                            browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, "On-chain lns-links/1 list exceeds the 10 KB limit (" + byteLen + " bytes).")
                            return
                        }
                        var parsedRoot = Logic.parseLinksList(pg.text)
                        if (!parsedRoot.ok) {
                            browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, "Invalid on-chain lns-links/1 list: " + parsedRoot.error)
                            return
                        }
                        if (storageBackend === "basecamp" && !basecampStorageReady) {
                            browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, "Basecamp's Storage node is still starting. Start it in Settings or click Retry.")
                            if (!basecampStorageStarting) startBasecampStorage()
                            return
                        }
                        if (storageBackend === "none") {
                            browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, "On-chain links list requires Basecamp's Storage module or an external Storage node.")
                            return
                        }
                        if (useReaderMode) {
                            readerSiteInfo = info
                            if (storageBackend === "basecamp") {
                                connectStoragePeers(function() {
                                    startLinksWalkReader(tabId, navSeq, parsedRoot, parsed.siteBase, parsed.path, "", Logic.sha256HexUtf8(pg.text), true, info)
                                })
                                return
                            }
                            browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, "Reader Mode on-chain links list requires Basecamp's Storage module (switch off Reader Mode to use HTTP Storage).")
                            return
                        }
                        var launchOnchainLinks = function() {
                            openLoopbackForTab(tabId, navSeq, {
                                kind: "lns",
                                host: parsed.name,
                                site_base: parsed.siteBase,
                                mode: "onchain-links",
                                links_text: pg.text,
                                path: parsed.path,
                                backend: storageBackend,
                                storage_api: storageApiInput.trim(),
                                title: info.display || parsed.name
                            }, info)
                        }
                        if (storageBackend === "basecamp") {
                            connectStoragePeers(function() { launchOnchainLinks() })
                        } else {
                            launchOnchainLinks()
                        }
                        return
                    }

                    // Single-page on-chain HTML
                    if (parsed.path !== "/" && parsed.path !== "/index.html") {
                        browserWindow.attachTabNotFound(tabId, navSeq, parsed.path, parsed.siteBase, true)
                        return
                    }
                    if (useReaderMode) {
                        readerSiteInfo = info
                        renderHtmlSafelyReader(tabId, navSeq, pg.text, {
                            mode: "onchain-page",
                            title: info.display || parsed.name,
                            cid: "",
                            sha256: "",
                            verified: true,
                            siteBase: parsed.siteBase,
                            path: parsed.path,
                            files: []
                        }, info)
                        return
                    }
                    openLoopbackForTab(tabId, navSeq, {
                        kind: "lns",
                        host: parsed.name,
                        site_base: parsed.siteBase,
                        mode: "onchain-page",
                        html: pg.text,
                        path: "/",
                        backend: "memory",
                        title: info.display || parsed.name
                    }, info)
                } else {
                    browserWindow.attachTabNoSite(tabId, navSeq, info)
                }
            }, function(err) {
                browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, String(err || "Could not fetch on-chain page"))
            })
        }, function(err) {
            browserWindow.attachTabStorageError(tabId, navSeq, "", parsed.path, String(err || "Could not resolve LNS name"))
        })
    }

    function openCidInLoopback(tabId, navSeq, parsed, cid, sha256, siteType, siteInfoObj) {
        if (storageBackend === "basecamp") {
            if (!basecampStorageReady) {
                browserWindow.attachTabStorageError(tabId, navSeq, cid, parsed.path || "/", "Basecamp's Storage node is still starting. Start it in Settings or click Retry.")
                if (!basecampStorageStarting) startBasecampStorage()
                return
            }
            connectStoragePeers(function() {
                openLoopbackForTab(tabId, navSeq, {
                    kind: parsed.kind,
                    host: parsed.kind === "lns" ? parsed.name : parsed.cid,
                    site_base: parsed.siteBase,
                    mode: "cid",
                    root_cid: cid,
                    root_sha256: sha256 || "",
                    site_type: siteType || "",
                    path: parsed.path || "/",
                    backend: "basecamp",
                    title: siteInfoObj ? siteInfoObj.display : ""
                }, siteInfoObj)
            })
            return
        }
        if (storageBackend === "http" && storageApiInput.trim() !== "") {
            openLoopbackForTab(tabId, navSeq, {
                kind: parsed.kind,
                host: parsed.kind === "lns" ? parsed.name : parsed.cid,
                site_base: parsed.siteBase,
                mode: "cid",
                root_cid: cid,
                root_sha256: sha256 || "",
                site_type: siteType || "",
                path: parsed.path || "/",
                backend: "http",
                storage_api: storageApiInput.trim(),
                title: siteInfoObj ? siteInfoObj.display : ""
            }, siteInfoObj)
            return
        }
        if (storageBackend === "checking") {
            browserWindow.attachTabStorageError(tabId, navSeq, cid, parsed.path || "/", "Logos Storage is still initializing. Wait a moment and click Retry.")
            return
        }
        browserWindow.attachTabStorageError(tabId, navSeq, cid, parsed.path || "/", "No Logos Storage module is installed in Basecamp and no external Storage node is configured.")
    }

    // ── Reader Mode (Zero-JS) Fetch & Render Pipeline ────────────────────
    function folderEntriesToSidebar(dirPrefix, entries) {
        var base = String(dirPrefix || "/").replace(/\/+$/, "")
        var list = Logic.toArray(entries)
        var out = []
        for (var i = 0; i < list.length; i++) {
            var e = list[i]
            var suffix = e.kind === "dir" ? "/" : ""
            out.push({
                path: (base ? base + "/" : "/") + e.name + suffix,
                name: e.name,
                kind: e.kind,
                cid: e.cid,
                sha256: e.sha256 || ""
            })
        }
        return out
    }

    function fetchCidPageReader(tabId, navSeq, cid, expectedSha256, siteBase, path, siteType, siteInfoObj) {
        if (storageBackend === "basecamp") {
            if (!basecampStorageReady) {
                browserWindow.attachTabStorageError(tabId, navSeq, cid, path || "/", "Basecamp's Storage node is still starting. Start it in Settings or click Retry.")
                if (!basecampStorageStarting) startBasecampStorage()
                return
            }
            var cachedRoot = Logic.getCachedLinksEntry(linksCache, cid, expectedSha256 || "")
            if (cachedRoot.mismatch) {
                browserWindow.attachTabStorageError(tabId, navSeq, cid, path || "/", cachedRoot.error)
                return
            }
            if (cachedRoot.hit) {
                var rootPinVerified = !!expectedSha256 && cachedRoot.sha256 === String(expectedSha256).trim().toLowerCase()
                connectStoragePeers(function() {
                    if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
                    startLinksWalkReader(tabId, navSeq, cachedRoot.list, siteBase, path || "/", cid, cachedRoot.sha256, rootPinVerified, siteInfoObj)
                })
                return
            }
            connectStoragePeers(function() {
                if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
                startBasecampDownload(tabId, navSeq, cid, expectedSha256, siteBase, path, null, false, {
                    purpose: siteType === "links" ? "links_dir" : "page",
                    siteType: siteType || "",
                    requestedPath: path || "/"
                })
            })
            return
        }
        if (storageBackend === "http" && storageApiInput.trim() !== "") {
            callCore("lns_browser_core", "fetch_site", [cid, expectedSha256 || "", siteBase, path || "/"], function(data) {
                if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
                if (data && data.not_found) {
                    browserWindow.attachTabNotFound(tabId, navSeq, data.path || path || "/", siteBase, !!data.single_page)
                    return
                }
                readerPageData = data
                browserWindow.attachReaderPage(tabId, navSeq, data, siteInfoObj)
            }, function(err) {
                if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
                browserWindow.attachTabStorageError(tabId, navSeq, cid, path || "/", err)
            }, 45000)
            return
        }
        browserWindow.attachTabStorageError(tabId, navSeq, cid, path || "/", "No Logos Storage module is installed in Basecamp and no external Storage node is configured.")
    }

    function renderHtmlSafelyReader(tabId, navSeq, rawHtml, meta, siteInfoObj) {
        var normFiles = Logic.toArray(meta.files)
        callCore("lns_browser_core", "render_html", [rawHtml, meta.siteBase, meta.path || "/"], function(rendered) {
            if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
            var pd = Object.assign({}, rendered, {
                mode: meta.mode || rendered.mode,
                cid: meta.cid || "",
                sha256: meta.sha256 || "",
                verified: !!meta.verified,
                blocks: Logic.toArray(rendered && rendered.blocks),
                downloads: Logic.toArray(rendered && rendered.downloads),
                files: normFiles
            })
            readerPageData = pd
            browserWindow.attachReaderPage(tabId, navSeq, pd, siteInfoObj)
            queuePageImages()
        }, function() {
            if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
            var clean = Logic.sanitizeHtmlFallback(rawHtml, meta.siteBase, meta.path || "/")
            var pd = {
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
                blocks: Logic.toArray(clean.blocks),
                downloads: Logic.toArray(clean.downloads),
                files: normFiles
            }
            readerPageData = pd
            browserWindow.attachReaderPage(tabId, navSeq, pd, siteInfoObj)
            queuePageImages()
        })
    }

    function startLinksWalkReader(tabId, navSeq, rootList, siteBase, rawPath, rootCid, rootSha256, rootVerified, siteInfoObj) {
        activeRootList = rootList
        var norm = Logic.normalizePath(rawPath || "/")
        if (!norm.ok) {
            browserWindow.attachTabStorageError(tabId, navSeq, rootCid || "", rawPath || "/", norm.error)
            return
        }
        activeWalk = {
            tabId: tabId,
            navSeq: navSeq,
            siteBase: siteBase,
            siteInfo: siteInfoObj,
            rootCid: rootCid || "",
            rootSha256: rootSha256 || "",
            rootVerified: !!rootVerified,
            segments: norm.segments,
            trailingSlash: norm.trailingSlash,
            stepIndex: 0,
            requestedPath: norm.path,
            depth: 0
        }
        advanceLinksWalk(rootList)
    }

    function advanceLinksWalk(list) {
        var walk = activeWalk
        if (!walk) return
        var step = Logic.stepLinksResolve(list, walk.segments, walk.stepIndex, walk.trailingSlash)
        if (step.action === "not_found") {
            activeWalk = null
            browserWindow.attachTabNotFound(walk.tabId, walk.navSeq, walk.requestedPath, walk.siteBase, false)
            return
        }
        if (step.action === "fetch_dir") {
            walk.depth += 1
            if (walk.depth > Logic.MAX_LINKS_DEPTH) {
                activeWalk = null
                browserWindow.attachTabStorageError(walk.tabId, walk.navSeq, step.cid, walk.requestedPath, "Folder nesting exceeds limit")
                return
            }
            walk.stepIndex = step.nextIndex
            if (!step.sha256) walk.rootVerified = false
            var cachedSub = Logic.getCachedLinksEntry(linksCache, step.cid, step.sha256 || "")
            if (cachedSub.mismatch) {
                activeWalk = null
                browserWindow.attachTabStorageError(walk.tabId, walk.navSeq, step.cid, walk.requestedPath, cachedSub.error)
                return
            }
            if (cachedSub.hit) {
                advanceLinksWalk(cachedSub.list)
                return
            }
            startBasecampDownload(walk.tabId, walk.navSeq, step.cid, step.sha256 || "", walk.siteBase, walk.requestedPath, null, walk.rootVerified, {
                purpose: "links_dir",
                requestedPath: walk.requestedPath
            })
            return
        }
        activeWalk = null
        var sidebarFiles = folderEntriesToSidebar(step.canonicalDir, step.folderEntries)
        if (Logic.isBinaryDownloadPath(step.resolvedPath)) {
            var binPd = {
                mode: "links",
                kind: "binary",
                can_save: true,
                filename: step.entry.name,
                title: step.entry.name,
                path: step.resolvedPath,
                cid: step.entry.cid,
                sha256: step.entry.sha256 || "",
                verified: walk.rootVerified && !!step.entry.sha256,
                html: "<p>Binary download: <code>" + Logic.escapeHtml(step.entry.name) + "</code></p>",
                blocks: [],
                downloads: [{
                    href: "cid://" + step.entry.cid,
                    cid: step.entry.cid,
                    sha256: step.entry.sha256 || "",
                    path: step.resolvedPath,
                    filename: step.entry.name,
                    label: step.entry.name
                }],
                files: sidebarFiles
            }
            readerPageData = binPd
            browserWindow.attachReaderPage(walk.tabId, walk.navSeq, binPd, walk.siteInfo)
            return
        }
        startBasecampDownload(walk.tabId, walk.navSeq, step.entry.cid, step.entry.sha256 || "", walk.siteBase, step.resolvedPath, sidebarFiles, walk.rootVerified, {
            purpose: "page",
            fromLinks: true,
            requestedPath: walk.requestedPath,
            folderTitle: step.folderTitle || ""
        })
    }

    function startBasecampDownload(tabId, navSeq, cid, expectedSha256, siteBase, path, manifestFiles, rootVerified, opts) {
        var extra = opts || {}
        var purpose = extra.purpose || "page"
        var maxBytes = (purpose === "links_dir" || purpose === "image_dir") ? Logic.MAX_LINKS_LIST_BYTES : (4 * 1024 * 1024)
        activeDownload = {
            tabId: tabId,
            navSeq: navSeq,
            cid: cid,
            expectedSha256: expectedSha256 || "",
            siteBase: siteBase,
            path: path || "/",
            requestedPath: extra.requestedPath || path || "/",
            chunks: [],
            receivedBytes: 0,
            maxBytes: maxBytes,
            manifestFiles: manifestFiles || null,
            rootVerified: !!rootVerified,
            purpose: purpose,
            fromLinks: !!extra.fromLinks,
            siteType: extra.siteType || "",
            folderTitle: extra.folderTitle || "",
            blockIndex: extra.blockIndex !== undefined ? extra.blockIndex : -1
        }
        downloadTimeoutTimer.restart()
        callCore("lns_browser_core", "storage_download_chunks", [cid, "false", "65536", "false", "true"], function() {}, function(err) {
            if (tabId !== root.readerTabId || navSeq !== root.readerNavSeq) return
            downloadTimeoutTimer.stop()
            var failedDl = activeDownload
            activeDownload = null
            if (failedDl && (failedDl.purpose === "image" || failedDl.purpose === "image_dir")) {
                activeImageTask = null
                fetchNextQueuedImage()
                return
            }
            activeWalk = null
            browserWindow.attachTabStorageError(tabId, navSeq, cid, extra.requestedPath || path || "/", err)
        }, 30000)
    }

    function finishBasecampDownload(dl) {
        if (dl.tabId !== root.readerTabId || dl.navSeq !== root.readerNavSeq) return
        var allBytes = []
        var maxBytes = dl.maxBytes || (4 * 1024 * 1024)
        for (var i = 0; i < dl.chunks.length; i++) {
            var part = Logic.base64ToBytes(dl.chunks[i])
            if (allBytes.length + part.length > maxBytes) {
                if (dl.purpose === "image" || dl.purpose === "image_dir") {
                    activeImageTask = null
                    fetchNextQueuedImage()
                    return
                }
                activeWalk = null
                browserWindow.attachTabStorageError(dl.tabId, dl.navSeq, dl.cid, dl.requestedPath || dl.path || "/", "Download exceeds limit of " + maxBytes + " bytes")
                return
            }
            for (var j = 0; j < part.length; j++) allBytes.push(part[j])
        }
        if (allBytes.length === 0) {
            if (dl.purpose === "image" || dl.purpose === "image_dir") {
                activeImageTask = null
                fetchNextQueuedImage()
                return
            }
            activeWalk = null
            browserWindow.attachTabStorageError(dl.tabId, dl.navSeq, dl.cid, dl.requestedPath || dl.path || "/", "empty payload")
            return
        }
        var actualHash = Logic.sha256HexBytes(allBytes)
        var verified = false
        if (dl.expectedSha256 && dl.expectedSha256.length === 64) {
            if (actualHash !== dl.expectedSha256.toLowerCase()) {
                if (dl.purpose === "image" || dl.purpose === "image_dir") {
                    activeImageTask = null
                    fetchNextQueuedImage()
                    return
                }
                activeWalk = null
                browserWindow.attachTabStorageError(
                    dl.tabId,
                    dl.navSeq,
                    dl.cid,
                    dl.requestedPath || dl.path || "/",
                    "SHA-256 mismatch: expected " + Logic.shortHash(dl.expectedSha256) + ", got " + Logic.shortHash(actualHash)
                )
                return
            }
            verified = true
        }

        if (dl.purpose === "image") {
            var mime = Logic.sniffImageMimeBytes(allBytes)
            if (mime) {
                var uri = "data:" + mime + ";base64," + Logic.bytesToBase64(allBytes)
                Logic.safeMapSet(imageCache, dl.cid, { uri: uri, sha256: actualHash })
                applyImageDataUri(dl.blockIndex, uri)
            }
            activeImageTask = null
            fetchNextQueuedImage()
            return
        }

        if (dl.purpose === "image_dir") {
            var imgDirUtf8 = Logic.bytesToUtf8Strict(allBytes)
            if (imgDirUtf8.ok) {
                var imgDir = Logic.parseLinksList(imgDirUtf8.text)
                if (imgDir.ok) {
                    Logic.safeMapSet(linksCache, dl.cid, { list: imgDir, sha256: actualHash })
                    stepImageResolve(imgDir)
                    return
                }
            }
            activeImageTask = null
            fetchNextQueuedImage()
            return
        }

        var strictDecoded = Logic.bytesToUtf8Strict(allBytes)
        var text = strictDecoded.ok ? strictDecoded.text : Logic.bytesToUtf8(allBytes)

        if (dl.purpose === "links_dir" || (!dl.manifestFiles && !dl.fromLinks && (dl.siteType === "links" || (strictDecoded.ok && Logic.isLinksListText(strictDecoded.text))))) {
            if (!strictDecoded.ok) {
                activeWalk = null
                browserWindow.attachTabStorageError(dl.tabId, dl.navSeq, dl.cid, dl.requestedPath || dl.path || "/", "invalid UTF-8 in lns-links/1 list: " + strictDecoded.error)
                return
            }
            var parsedList = Logic.parseLinksList(strictDecoded.text)
            if (!parsedList.ok) {
                activeWalk = null
                browserWindow.attachTabStorageError(dl.tabId, dl.navSeq, dl.cid, dl.requestedPath || dl.path || "/", "invalid lns-links/1 list: " + parsedList.error)
                return
            }
            Logic.safeMapSet(linksCache, dl.cid, { list: parsedList, sha256: actualHash })
            if (activeWalk === null) {
                startLinksWalkReader(dl.tabId, dl.navSeq, parsedList, dl.siteBase, dl.path || "/", dl.cid, actualHash, verified, readerSiteInfo)
            } else {
                activeWalk.rootVerified = activeWalk.rootVerified && verified
                advanceLinksWalk(parsedList)
            }
            return
        }

        if (!dl.manifestFiles && !dl.fromLinks) {
            var manifest = Logic.tryParseManifestJson(text)
            if (manifest) {
                var filesList = []
                for (var p in manifest.files) {
                    filesList.push({ path: p, cid: manifest.files[p].cid, sha256: manifest.files[p].sha256 || "" })
                }
                var wantPath = dl.path && dl.path !== "/" ? dl.path : (manifest.index || "/index.html")
                var entry = manifest.files[wantPath] || (wantPath.charAt(wantPath.length - 1) === "/" ? manifest.files[wantPath + "index.html"] : manifest.files[wantPath + "/index.html"])
                if (!entry || !entry.cid) {
                    browserWindow.attachTabNotFound(dl.tabId, dl.navSeq, wantPath, dl.siteBase, false)
                    return
                }
                startBasecampDownload(dl.tabId, dl.navSeq, entry.cid, entry.sha256 || "", dl.siteBase, wantPath, filesList, verified, {
                    purpose: "page",
                    requestedPath: wantPath
                })
                return
            }
            if (dl.path && dl.path !== "/" && dl.path !== "/index.html") {
                browserWindow.attachTabNotFound(dl.tabId, dl.navSeq, dl.path, dl.siteBase, true)
                return
            }
        }

        renderHtmlSafelyReader(dl.tabId, dl.navSeq, text, {
            mode: dl.fromLinks ? "links" : (dl.manifestFiles ? "manifest" : "single"),
            title: dl.folderTitle || "",
            cid: dl.cid,
            sha256: actualHash,
            verified: (dl.fromLinks || dl.manifestFiles) ? (dl.rootVerified && verified) : verified,
            siteBase: dl.siteBase,
            path: dl.path,
            files: dl.manifestFiles || []
        }, readerSiteInfo)
    }

    function queuePageImages() {
        if (storageBackend !== "basecamp" || !basecampStorageReady || !readerPageData) return
        var blocks = Logic.toArray(readerPageData.blocks)
        var queue = []
        var changed = false
        for (var i = 0; i < blocks.length; i++) {
            var b = blocks[i]
            if (!b || b.kind !== "image" || b.data_uri) continue
            if (b.src_cid) {
                var cachedImg = Logic.getCachedImageEntry(imageCache, b.src_cid, "")
                if (cachedImg.hit) {
                    blocks[i] = Object.assign({}, b, { data_uri: cachedImg.uri })
                    changed = true
                    continue
                }
            }
            if (b.src_cid || (b.src_path && activeRootList)) {
                queue.push({ blockIndex: i, srcCid: b.src_cid || "", srcPath: b.src_path || "" })
            }
        }
        if (changed) {
            readerPageData = Object.assign({}, readerPageData, { blocks: blocks })
            browserWindow.attachReaderPage(readerTabId, readerNavSeq, readerPageData, readerSiteInfo)
        }
        pendingImages = queue
        activeImageTask = null
        fetchNextQueuedImage()
    }

    function fetchNextQueuedImage() {
        if (activeImageTask !== null || activeDownload !== null) return
        if (!pendingImages || pendingImages.length === 0) return
        var next = pendingImages.shift()
        if (next.srcCid) {
            var cachedImg = Logic.getCachedImageEntry(imageCache, next.srcCid, "")
            if (cachedImg.hit) {
                applyImageDataUri(next.blockIndex, cachedImg.uri)
                fetchNextQueuedImage()
                return
            }
            activeImageTask = { blockIndex: next.blockIndex, cid: next.srcCid, expectedSha256: "" }
            startBasecampDownload(readerTabId, readerNavSeq, next.srcCid, "", readerSiteBase, next.srcPath || "/", null, false, {
                purpose: "image",
                blockIndex: next.blockIndex
            })
            return
        }
        if (next.srcPath && activeRootList) {
            var norm = Logic.normalizePath(next.srcPath)
            if (!norm.ok) { fetchNextQueuedImage(); return }
            activeImageTask = { blockIndex: next.blockIndex, segments: norm.segments, trailingSlash: norm.trailingSlash, stepIndex: 0, depth: 0 }
            stepImageResolve(activeRootList)
            return
        }
        fetchNextQueuedImage()
    }

    function stepImageResolve(list) {
        var task = activeImageTask
        if (!task) return
        var step = Logic.stepLinksResolve(list, task.segments, task.stepIndex, task.trailingSlash)
        if (step.action === "found") {
            var cachedImg = Logic.getCachedImageEntry(imageCache, step.entry.cid, step.entry.sha256 || "")
            if (cachedImg.mismatch) { activeImageTask = null; fetchNextQueuedImage(); return }
            if (cachedImg.hit) {
                var idx = task.blockIndex
                activeImageTask = null
                applyImageDataUri(idx, cachedImg.uri)
                fetchNextQueuedImage()
                return
            }
            task.cid = step.entry.cid
            task.expectedSha256 = step.entry.sha256 || ""
            startBasecampDownload(readerTabId, readerNavSeq, step.entry.cid, step.entry.sha256 || "", readerSiteBase, step.resolvedPath, null, false, {
                purpose: "image",
                blockIndex: task.blockIndex
            })
            return
        }
        if (step.action === "fetch_dir") {
            task.depth += 1
            if (task.depth > Logic.MAX_LINKS_DEPTH) { activeImageTask = null; fetchNextQueuedImage(); return }
            task.stepIndex = step.nextIndex
            var cachedDir = Logic.getCachedLinksEntry(linksCache, step.cid, step.sha256 || "")
            if (cachedDir.mismatch) { activeImageTask = null; fetchNextQueuedImage(); return }
            if (cachedDir.hit) { stepImageResolve(cachedDir.list); return }
            startBasecampDownload(readerTabId, readerNavSeq, step.cid, step.sha256 || "", readerSiteBase, "/" + task.segments.join("/"), null, false, { purpose: "image_dir" })
            return
        }
        activeImageTask = null
        fetchNextQueuedImage()
    }

    function applyImageDataUri(blockIndex, dataUri) {
        if (!readerPageData || !dataUri) return
        var blocks = Logic.toArray(readerPageData.blocks).slice()
        if (blockIndex < 0 || blockIndex >= blocks.length) return
        blocks[blockIndex] = Object.assign({}, blocks[blockIndex], { data_uri: dataUri })
        readerPageData = Object.assign({}, readerPageData, { blocks: blocks })
        browserWindow.attachReaderPage(readerTabId, readerNavSeq, readerPageData, readerSiteInfo)
    }

    // ── Publish & Settings (Preserved Intact) ────────────────────────────
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
                openInBrowserWindow("lns://" + intentParams.name)
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

        resolveNameWithRetry(name, function(record) {
            if (!record) {
                loading = false
                problem = "LNS name \"" + name + "\" is not registered on LEZ yet. Register it in Names first."
                return
            }

            if (pubMode === "page") {
                if (!pubHtml.trim()) { loading = false; problem = "Paste HTML content first."; return }
                if (Logic.utf8ToBytes(pubHtml).length > 78 * 1024) {
                    loading = false
                    problem = "HTML exceeds the 78 KB on-chain SetPage limit. Switch to Logos Storage CID mode."
                    return
                }
                handoffToNames({ name: name, html: pubHtml, return_app: "lns_browser" }, "Prepared on-chain HTML page.")
                return
            }

            if (storageBackend === "basecamp") {
                if (!basecampStorageReady) {
                    loading = false
                    problem = "Basecamp's Storage node is not ready yet. Start it in Settings or switch to On-Chain HTML (≤ 78 KB)."
                    return
                }
                if (pubLocalPath.trim().length > 0) {
                    callCore("lns_browser_core", "storage_upload_url", [pubLocalPath.trim(), "65536", "true"], function(sessionId) {
                        activeUpload = { sessionId: String(sessionId), name: name, sha256: "", mode: "url", sentChunk: true }
                        notice = "Uploading file to Basecamp Logos Storage (advertising to P2P network)..."
                    }, function(err) {
                        loading = false
                        problem = "Basecamp Storage upload failed: " + err
                    }, 30000)
                } else {
                    if (!pubHtml.trim()) { loading = false; problem = "Paste HTML content or enter a file path first."; return }
                    var hashHex = Logic.sha256HexUtf8(pubHtml)
                    callCore("lns_browser_core", "storage_upload_init", ["index.html", "65536", "true"], function(sessionId) {
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
                    problem = "Refused to publish to the local stand-in mock. Use Basecamp's built-in Storage module, a real Logos Storage node, or On-Chain HTML."
                    return
                }
                var doneUpload = function(uploaded) {
                    lastPublished = uploaded
                    var built = Logic.buildProfileEntries(uploaded.root_cid, uploaded.sha256, uploaded.mode)
                    if (!built.ok) { loading = false; problem = built.error; return }
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
                        loading = false; problem = err
                    }, 120000)
                } else {
                    callCore("lns_browser_core", "publish_html", [pubHtml, pubTitle.trim()], doneUpload, function(err) {
                        loading = false; problem = err
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
            problem = "Port 8080 is used by the Logos Blockchain node, not Logos Storage."
            return
        }
        var peersParsed = Logic.parseStoragePeers(storagePeersInput)
        if (!peersParsed.ok) {
            problem = "Storage peers invalid: " + peersParsed.errors.join("; ")
            return
        }
        var payload = JSON.stringify({
            storage_api: trimmed,
            storage_peers_text: peersParsed.peers.map(function(p) { return p.line }).join("\n")
        })
        saveBrowserState({ reader_mode: defaultReaderMode })
        callCore("lns_browser_core", "config_set", [payload], function(v) {
            storageApiInput = v && v.storage_api ? v.storage_api : ""
            if (v && typeof v.storage_peers_text === "string") storagePeersInput = v.storage_peers_text
            problem = ""
            if (storageApiInput === "") {
                storageBackend = basecampStorageInstalled ? "basecamp" : "none"
                notice = basecampStorageInstalled ? "Saved settings (using Basecamp's built-in Logos Storage module)." : "Saved settings."
                if (basecampStorageReady && peersParsed.peers.length > 0) connectStoragePeers(null)
            } else {
                storageBackend = "http"
                notice = "Saved settings (external Storage API: " + storageApiInput + ")."
                refreshHttpStorageStatus()
            }
            settingsOpen = false
        }, function(err) {
            problem = err
        })
    }

    // ── Basecamp Tab Start Page UI (Zero WebView inside Basecamp tab) ────
    Rectangle {
        anchors.fill: parent
        color: root.slate

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: px(18)
            spacing: px(14)

            // Header Row
            RowLayout {
                Layout.fillWidth: true
                spacing: px(8)

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text { text: "LNS Browser"; color: root.ink; font.pixelSize: px(20); font.bold: true }
                    Text {
                        text: "Modern WebKit sites in their own window · Per-site loopback CSP · SHA-256 verified"
                        color: root.dim; font.pixelSize: px(11)
                    }
                }

                Rectangle {
                    implicitWidth: openWinTxt.implicitWidth + px(22); height: px(34); radius: px(8)
                    color: root.brass
                    Text {
                        id: openWinTxt; anchors.centerIn: parent
                        text: browserWindow.tabs.length > 0
                            ? ("Open Browser Window (" + browserWindow.tabs.length + ")")
                            : "Open Browser Window"
                        color: root.slate; font.bold: true; font.pixelSize: px(12)
                    }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: browserWindow.openAndRaise()
                    }
                }

                Rectangle {
                    width: px(76); height: px(34); radius: px(8)
                    color: root.publishOpen ? root.brass : root.raised; border.color: root.line
                    Text { anchors.centerIn: parent; text: "Publish"; color: root.publishOpen ? root.slate : root.ink; font.bold: true; font.pixelSize: px(12) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.publishOpen = !root.publishOpen; root.settingsOpen = false } }
                }

                Rectangle {
                    width: px(76); height: px(34); radius: px(8)
                    color: root.settingsOpen ? root.brass : root.raised; border.color: root.line
                    Text { anchors.centerIn: parent; text: "Settings"; color: root.settingsOpen ? root.slate : root.ink; font.pixelSize: px(12) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { root.settingsOpen = !root.settingsOpen; root.publishOpen = false } }
                }
            }

            // Start Page Address Box
            RowLayout {
                Layout.fillWidth: true
                spacing: px(8)

                Rectangle {
                    Layout.fillWidth: true
                    height: px(40)
                    radius: px(10)
                    color: root.card
                    border.color: startUrlEdit.activeFocus ? root.brass : root.line

                    TextInput {
                        id: startUrlEdit
                        anchors.fill: parent
                        anchors.leftMargin: px(12); anchors.rightMargin: px(12)
                        verticalAlignment: TextInput.AlignVCenter
                        color: root.ink
                        font.family: root.mono
                        font.pixelSize: px(13)
                        selectByMouse: true
                        text: root.startUrlInput
                        onTextEdited: root.startUrlInput = text
                        onAccepted: root.openInBrowserWindow(text)

                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            visible: startUrlEdit.text.length === 0
                            text: "Enter LNS address (nameswallet/browser, lns://helloworld, cid://...)"
                            color: root.dim
                            font.family: root.mono
                            font.pixelSize: px(12)
                        }
                    }
                }

                Rectangle {
                    width: px(78); height: px(40); radius: px(10); color: root.brass
                    Text { anchors.centerIn: parent; text: "Open"; color: root.slate; font.bold: true; font.pixelSize: px(13) }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: root.openInBrowserWindow(root.startUrlInput)
                    }
                }
            }

            // Status / Error Strip
            Text {
                visible: root.problem.length > 0
                Layout.fillWidth: true; wrapMode: Text.WordWrap
                text: root.problem; color: root.alarm; font.pixelSize: px(12)
            }
            Text {
                visible: root.notice.length > 0
                Layout.fillWidth: true; wrapMode: Text.WordWrap
                text: root.notice; color: root.good; font.pixelSize: px(12)
            }

            // Settings Panel
            Rectangle {
                visible: root.settingsOpen
                Layout.fillWidth: true
                implicitHeight: cfgCol.implicitHeight + px(24)
                radius: px(10); color: root.card; border.color: root.line

                ColumnLayout {
                    id: cfgCol
                    anchors.fill: parent; anchors.margins: px(12); spacing: px(8)

                    Text { text: "Browser & Logos Storage Settings"; color: root.ink; font.bold: true; font.pixelSize: px(13) }
                    RowLayout {
                        spacing: px(8)
                        Rectangle {
                            implicitWidth: rmPrefTxt.implicitWidth + px(16); height: px(28); radius: px(6)
                            color: root.defaultReaderMode ? root.brass : root.raised; border.color: root.line
                            Text {
                                id: rmPrefTxt; anchors.centerIn: parent
                                text: root.defaultReaderMode ? "Default Mode: Reader (JS Off)" : "Default Mode: WebKit (Sterilised JS On)"
                                color: root.defaultReaderMode ? root.slate : root.ink; font.pixelSize: px(11); font.bold: true
                            }
                            MouseArea {
                                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                onClicked: root.defaultReaderMode = !root.defaultReaderMode
                            }
                        }
                    }

                    Text {
                        Layout.fillWidth: true; wrapMode: Text.WordWrap; color: root.dim; font.pixelSize: px(11)
                        text: root.basecampStorageInstalled
                            ? ("Basecamp's built-in Logos Storage module is installed (" + (root.basecampStorageRunning ? "running" : "stopped") + "). It is used automatically unless you enter an external Storage API URL below.")
                            : "No Logos Storage module is installed in this Basecamp build. On-Chain HTML (≤ 78 KB) works now; for CID sites, enter a real Logos Storage node URL below (port 8080 is Logos Blockchain, not Storage)."
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

                    Text { text: "Storage peers (one per line: peerId /ip4/…/tcp/… — workaround for discovery #1556):"; color: root.dim; font.pixelSize: px(11); wrapMode: Text.WordWrap; Layout.fillWidth: true }
                    Rectangle {
                        Layout.fillWidth: true; height: px(72); radius: px(6); color: root.slate; border.color: root.line
                        Flickable {
                            anchors.fill: parent; anchors.margins: px(6); contentHeight: peersEdit.implicitHeight; clip: true
                            TextEdit {
                                id: peersEdit
                                width: parent.width
                                color: root.ink; font.family: root.mono; font.pixelSize: px(11); wrapMode: TextEdit.Wrap
                                text: root.storagePeersInput; onTextChanged: root.storagePeersInput = text
                            }
                        }
                    }
                    Text {
                        visible: root.peerConnectStatus.length > 0
                        Layout.fillWidth: true; wrapMode: Text.WordWrap; color: root.dim; font.family: root.mono; font.pixelSize: px(11)
                        text: root.peerConnectStatus
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

            // Publish Panel
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
                            ? "Or paste HTML directly (uploaded to Logos Storage when File path is blank):"
                            : ("HTML stored directly on LEZ (" + Logic.utf8ToBytes(root.pubHtml).length + " / 79,872 bytes):")
                        color: root.dim; font.pixelSize: px(11); wrapMode: Text.WordWrap; Layout.fillWidth: true
                    }
                    Rectangle {
                        Layout.fillWidth: true; height: px(104); radius: px(6); color: root.slate; border.color: root.line
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
                                id: pubBtnTxt; anchors.centerIn: parent
                                text: root.loading ? "Publishing..." : (root.pubMode === "cid" ? "Upload to Logos Storage & Publish" : "Publish On-Chain in Names")
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

            // Start Page Main Content: Recently Opened Sites, Bookmarks, History
            Flickable {
                Layout.fillWidth: true
                Layout.fillHeight: true
                contentWidth: width
                contentHeight: startContentCol.implicitHeight
                clip: true

                ColumnLayout {
                    id: startContentCol
                    width: parent.width
                    spacing: px(18)

                    // Recently Opened Sites (or quick-start suggestions when empty)
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: px(8)

                        Text {
                            text: root.recentSites.length > 0 ? "Recently Opened Sites" : "Quick Open"
                            color: root.dim; font.bold: true; font.pixelSize: px(12)
                        }

                        Flow {
                            Layout.fillWidth: true
                            spacing: px(8)

                            Repeater {
                                model: root.recentSites.length > 0
                                    ? root.recentSites
                                    : [
                                        { siteBase: "lns://nameswallet", title: "Names Wallet" },
                                        { siteBase: "lns://nameswallet/browser/", title: "Names Wallet / Browser" },
                                        { siteBase: "lns://helloworld", title: "Hello World" }
                                    ]
                                delegate: Rectangle {
                                    required property var modelData
                                    implicitWidth: Math.max(px(160), recCardCol.implicitWidth + px(24))
                                    height: px(54)
                                    radius: px(10)
                                    color: root.card
                                    border.color: root.line

                                    ColumnLayout {
                                        id: recCardCol
                                        anchors.verticalCenter: parent.verticalCenter
                                        anchors.left: parent.left; anchors.right: parent.right
                                        anchors.margins: px(10)
                                        spacing: 2
                                        Text { text: modelData.title || modelData.siteBase; color: root.ink; font.bold: true; font.pixelSize: px(12); elide: Text.ElideRight }
                                        Text { text: modelData.siteBase; color: root.dim; font.family: root.mono; font.pixelSize: px(11); elide: Text.ElideMiddle }
                                    }

                                    MouseArea {
                                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                        onClicked: root.openInBrowserWindow(modelData.siteBase)
                                    }
                                }
                            }
                        }
                    }

                    // Bookmarks & History Two-Column Section
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: px(14)

                        // Bookmarks Card
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.alignment: Qt.AlignTop
                            implicitHeight: bmCardCol.implicitHeight + px(24)
                            radius: px(10); color: root.card; border.color: root.line

                            ColumnLayout {
                                id: bmCardCol
                                anchors.fill: parent; anchors.margins: px(12); spacing: px(8)

                                Text { text: "Bookmarks (" + root.bookmarks.length + ")"; color: root.ink; font.bold: true; font.pixelSize: px(13) }
                                Text {
                                    visible: root.bookmarks.length === 0
                                    text: "No bookmarks yet. Click the ☆ star in the browser window's address bar to save a site."
                                    color: root.dim; font.pixelSize: px(11); wrapMode: Text.WordWrap; Layout.fillWidth: true
                                }
                                Repeater {
                                    model: root.bookmarks
                                    delegate: Rectangle {
                                        required property var modelData
                                        Layout.fillWidth: true; height: px(38); radius: px(7)
                                        color: root.slate; border.color: root.line
                                        RowLayout {
                                            anchors.fill: parent; anchors.leftMargin: px(10); anchors.rightMargin: px(6); spacing: px(6)
                                            Text { text: "★"; color: root.brass; font.pixelSize: px(12) }
                                            ColumnLayout {
                                                Layout.fillWidth: true; spacing: 1
                                                Text { Layout.fillWidth: true; text: modelData.title || modelData.url; color: root.ink; font.pixelSize: px(11); font.bold: true; elide: Text.ElideRight }
                                                Text { Layout.fillWidth: true; text: modelData.url; color: root.dim; font.family: root.mono; font.pixelSize: px(10); elide: Text.ElideMiddle }
                                            }
                                            Rectangle {
                                                width: px(22); height: px(22); radius: px(4); color: "transparent"
                                                Text { anchors.centerIn: parent; text: "✕"; color: root.dim; font.pixelSize: px(10) }
                                                MouseArea {
                                                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                                    onClicked: function(mouse) { mouse.accepted = true; root.removeBookmarkUrl(modelData.url) }
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent; anchors.rightMargin: px(28); cursorShape: Qt.PointingHandCursor
                                            onClicked: root.openInBrowserWindow(modelData.url)
                                        }
                                    }
                                }
                            }
                        }

                        // History Card
                        Rectangle {
                            Layout.fillWidth: true
                            Layout.alignment: Qt.AlignTop
                            implicitHeight: histCardCol.implicitHeight + px(24)
                            radius: px(10); color: root.card; border.color: root.line

                            ColumnLayout {
                                id: histCardCol
                                anchors.fill: parent; anchors.margins: px(12); spacing: px(8)

                                RowLayout {
                                    Layout.fillWidth: true
                                    Text { text: "History (" + root.browsingHistory.length + ")"; color: root.ink; font.bold: true; font.pixelSize: px(13); Layout.fillWidth: true }
                                    Rectangle {
                                        visible: root.browsingHistory.length > 0
                                        implicitWidth: spClearTxt.implicitWidth + px(12); height: px(24); radius: px(5)
                                        color: root.raised; border.color: root.line
                                        Text { id: spClearTxt; anchors.centerIn: parent; text: "Clear"; color: root.dim; font.pixelSize: px(10) }
                                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.clearBrowsingHistory() }
                                    }
                                }
                                Text {
                                    visible: root.browsingHistory.length === 0
                                    text: "No browsing history yet. Sites you open appear here automatically."
                                    color: root.dim; font.pixelSize: px(11); wrapMode: Text.WordWrap; Layout.fillWidth: true
                                }
                                Repeater {
                                    model: root.browsingHistory.slice(0, 15)
                                    delegate: Rectangle {
                                        required property var modelData
                                        Layout.fillWidth: true; height: px(38); radius: px(7)
                                        color: root.slate; border.color: root.line
                                        ColumnLayout {
                                            anchors.fill: parent; anchors.margins: px(6); spacing: 1
                                            Text { Layout.fillWidth: true; text: modelData.title || modelData.url; color: root.ink; font.pixelSize: px(11); font.bold: true; elide: Text.ElideRight }
                                            Text { Layout.fillWidth: true; text: modelData.url; color: root.dim; font.family: root.mono; font.pixelSize: px(10); elide: Text.ElideMiddle }
                                        }
                                        MouseArea {
                                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                            onClicked: root.openInBrowserWindow(modelData.url)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Bottom Status Bar
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
                    text: "Own-window WebKit · Sterilised JS · Loopback CSP · Click-to-confirm https://"
                    color: root.dim
                    font.family: root.mono
                    font.pixelSize: px(11)
                }
            }
        }
    }
}
