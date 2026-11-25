import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import "logic.mjs" as Logic

// Standalone titled macOS/desktop browser window for LNS + Logos Storage CID sites.
// Native-view containment rule:
// - All browser chrome (tabs, toolbar, progress, find, confirm strip, downloads, side drawers)
//   lives strictly ABOVE or BESIDE `webViewport` — never overlapping the native WKWebView.
// - When Reader Mode, New Tab, or any error/empty card is shown, `webViewObj` is hidden and
//   sized to 0x0 so the native view cannot draw over QML content.
Window {
    id: browserWin

    required property var host

    flags: Qt.Window
    visible: false
    minimumWidth: 720
    minimumHeight: 480
    width: 1120
    height: 760
    x: 120
    y: 80
    color: host ? host.slate : "#0f141d"
    title: Logic.formatWindowTitle(activeTab)

    // Tab model & active tab state
    property var tabs: []
    property int activeTabIndex: -1
    property int nextTabId: 1
    readonly property var activeTab: (activeTabIndex >= 0 && activeTabIndex < tabs.length) ? tabs[activeTabIndex] : null

    property string urlInput: ""
    property string pendingExternalUrl: ""
    property string bannerProblem: ""
    property string bannerNotice: ""
    property var downloadBanner: null // { cid, filename, path, status, message, active, verified, relPath, token }

    // Docked strips & side drawers (never overlap WebView)
    property bool findOpen: false
    property string findQuery: ""
    property string findStatus: ""
    property bool filesDrawerOpen: false
    property bool verifiedDrawerOpen: false
    property bool libraryDrawerOpen: false
    property string libraryTab: "bookmarks" // "bookmarks" | "history"

    // Native QtWebView runtime state
    property var webViewObj: null
    property bool webViewAvailable: false
    property bool webViewProbed: false
    property string lastHandledEventKey: ""
    property double lastHandledEventTs: 0
    property bool geometryReady: false
    property bool shuttingDown: false

    readonly property bool activeTabHasSite: activeTab !== null && activeTab.url !== ""
    readonly property bool activeTabIsNewTab: activeTab === null || (activeTab.url === "" && !activeTab.loading && !activeTab.notFoundState && !activeTab.storageError)
    readonly property bool activeTabNoSite: activeTab !== null && !activeTab.loading && !activeTab.notFoundState && !activeTab.storageError && activeTab.siteInfo !== null && !activeTab.siteInfo.hasSite && activeTab.pageData === null && activeTab.loopbackUrl === ""
    readonly property bool activeTabReaderActive: activeTab !== null && (activeTab.readerMode || !webViewAvailable)
    readonly property bool webViewActive: visible
        && webViewAvailable
        && webViewObj !== null
        && activeTab !== null
        && !activeTabReaderActive
        && activeTab.loopbackUrl !== ""
        && !activeTab.notFoundState
        && !activeTab.storageError
        && !activeTabNoSite
        && !activeTabIsNewTab

    readonly property var activeTabFiles: {
        if (!activeTab) return []
        if (activeTab.siteStats && activeTab.siteStats.folder_files) {
            var sf = Logic.toArray(activeTab.siteStats.folder_files)
            if (sf.length > 0) return sf
        }
        if (activeTab.pageData && activeTab.pageData.files) {
            return Logic.toArray(activeTab.pageData.files)
        }
        return []
    }

    readonly property var activeVerifiedFiles: {
        if (!activeTab || !activeTab.siteStats || !activeTab.siteStats.verified_files) return []
        return Logic.toArray(activeTab.siteStats.verified_files)
    }

    readonly property bool activeTabVerified: {
        if (!activeTab) return false
        if (activeTabReaderActive && activeTab.pageData) return !!activeTab.pageData.verified
        if (activeTab.siteStats && activeTab.siteStats.verified !== undefined) return !!activeTab.siteStats.verified
        return !!activeTab.verified
    }

    readonly property string activeTabMode: {
        if (!activeTab) return ""
        if (activeTab.siteStats && activeTab.siteStats.mode) return String(activeTab.siteStats.mode)
        if (activeTab.pageData && activeTab.pageData.mode) return String(activeTab.pageData.mode)
        return String(activeTab.mode || "")
    }

    readonly property color pageBg: (activeTab && activeTab.pageData && activeTab.pageData.bg_color) ? activeTab.pageData.bg_color : (host ? host.card : "#171f2d")
    readonly property color pageFg: (activeTab && activeTab.pageData && activeTab.pageData.fg_color) ? activeTab.pageData.fg_color : (host ? host.ink : "#e6edf7")
    readonly property color pageLink: (activeTab && activeTab.pageData && activeTab.pageData.link_color) ? activeTab.pageData.link_color : (host ? host.brass : "#e5a93b")
    readonly property bool pageIsLight: activeTab && activeTab.pageData && activeTab.pageData.bg_color
        ? (pageBg.r * 0.299 + pageBg.g * 0.587 + pageBg.b * 0.114) > 0.55
        : false
    readonly property color pageDim: activeTab && activeTab.pageData && activeTab.pageData.bg_color
        ? (pageIsLight ? "#526075" : "#9aa7b8")
        : (host ? host.dim : "#8a99ad")

    function px(size) {
        return host ? host.px(size) : size
    }

    function hasAnyLoopbackSite() {
        for (var i = 0; i < tabs.length; i++) {
            if (tabs[i] && tabs[i].loopbackToken) return true
        }
        return false
    }

    function applySavedGeometry(geom) {
        var c = Logic.clampWindowGeometry(geom)
        geometryReady = false
        x = c.x
        y = c.y
        width = c.width
        height = c.height
        geometryReady = true
    }

    function persistGeometryNow() {
        if (!host || !geometryReady || shuttingDown) return
        if (visibility === Window.Minimized) return
        host.saveBrowserState({
            window: Logic.clampWindowGeometry({ x: x, y: y, width: width, height: height })
        })
    }

    Timer {
        id: geomSaveTimer
        interval: 400
        repeat: false
        onTriggered: browserWin.persistGeometryNow()
    }

    onXChanged: if (visible && geometryReady) geomSaveTimer.restart()
    onYChanged: if (visible && geometryReady) geomSaveTimer.restart()
    onWidthChanged: if (visible && geometryReady) geomSaveTimer.restart()
    onHeightChanged: if (visible && geometryReady) geomSaveTimer.restart()

    onVisibleChanged: {
        if (visible) {
            ensureWebView()
            if (tabs.length === 0) {
                openNewTab("", false)
            }
            syncWebViewBounds()
            syncWebViewToActiveTab()
        } else {
            syncWebViewBounds()
        }
    }

    onWebViewActiveChanged: syncWebViewBounds()

    onClosing: function(close) {
        persistGeometryNow()
        if (!shuttingDown) {
            // Hide cleanly instead of destroying window component so Start Page "Open" raises it seamlessly
            close.accepted = false
            visible = false
        }
    }

    function shutdownOnAppUnload() {
        shuttingDown = true
        pollEventsTimer.stop()
        geomSaveTimer.stop()
        visible = false
        close()
    }

    function openAndRaise() {
        // Show the real window first: macOS WebKit can drop the first URL it is given if it is
        // created before its window is on screen (needed an extra "Go", 2026-11-25).
        visible = true
        show()
        raise()
        requestActivate()
        ensureWebView()
        if (tabs.length === 0) {
            openNewTab("", false)
        }
        syncWebViewBounds()
    }

    function ensureWebView() {
        if (webViewProbed) return
        webViewProbed = true
        var qmlFull =
            'import QtQuick\n' +
            'import QtWebView\n' +
            'WebView {\n' +
            '  property var hostWindow: null\n' +
            '  x: 0; y: 0; width: 0; height: 0; visible: false\n' +
            '  settings.javaScriptEnabled: true\n' +
            '  settings.localStorageEnabled: false\n' +
            '  settings.allowFileAccess: false\n' +
            '  settings.localContentCanAccessFileUrls: false\n' +
            '  onLoadingChanged: function(loadRequest) {\n' +
            '    if (!hostWindow) return\n' +
            '    var st = loadRequest.status === WebView.LoadStartedStatus ? "started"\n' +
            '      : (loadRequest.status === WebView.LoadSucceededStatus ? "succeeded"\n' +
            '      : (loadRequest.status === WebView.LoadFailedStatus ? "failed" : "stopped"))\n' +
            '    hostWindow.handleWebViewLoadingChanged(st, String(loadRequest.url || ""), String(loadRequest.errorString || ""))\n' +
            '  }\n' +
            '  onLoadProgressChanged: if (hostWindow) hostWindow.handleWebViewProgress(loadProgress)\n' +
            '  onTitleChanged: if (hostWindow) hostWindow.handleWebViewTitle(String(title || ""))\n' +
            '}\n'
        var qmlCompat =
            'import QtQuick\n' +
            'import QtWebView\n' +
            'WebView {\n' +
            '  property var hostWindow: null\n' +
            '  x: 0; y: 0; width: 0; height: 0; visible: false\n' +
            '  onLoadingChanged: function(loadRequest) {\n' +
            '    if (!hostWindow) return\n' +
            '    var st = loadRequest.status === WebView.LoadStartedStatus ? "started"\n' +
            '      : (loadRequest.status === WebView.LoadSucceededStatus ? "succeeded"\n' +
            '      : (loadRequest.status === WebView.LoadFailedStatus ? "failed" : "stopped"))\n' +
            '    hostWindow.handleWebViewLoadingChanged(st, String(loadRequest.url || ""), String(loadRequest.errorString || ""))\n' +
            '  }\n' +
            '  onLoadProgressChanged: if (hostWindow) hostWindow.handleWebViewProgress(loadProgress)\n' +
            '  onTitleChanged: if (hostWindow) hostWindow.handleWebViewTitle(String(title || ""))\n' +
            '}\n'
        try {
            var obj = Qt.createQmlObject(qmlFull, webViewport, "LnsWebView")
            obj.hostWindow = browserWin
            webViewObj = obj
            webViewAvailable = true
            return
        } catch (e1) {
            console.log("lns_browser: QtWebView full settings init fallback:", e1)
        }
        try {
            var obj2 = Qt.createQmlObject(qmlCompat, webViewport, "LnsWebViewCompat")
            obj2.hostWindow = browserWin
            // No runtime settings writes (see applyWebViewJsSetting).
            webViewObj = obj2
            webViewAvailable = true
        } catch (e2) {
            console.log("lns_browser: QtWebView unavailable, using Reader Mode:", e2)
            webViewObj = null
            webViewAvailable = false
        }
    }

    function syncWebViewBounds() {
        if (!webViewObj) return
        if (webViewActive) {
            webViewObj.visible = true
            webViewObj.x = 0
            webViewObj.y = 0
            webViewObj.width = Math.max(0, webViewport.width)
            webViewObj.height = Math.max(0, webViewport.height)
        } else {
            webViewObj.visible = false
            webViewObj.width = 0
            webViewObj.height = 0
        }
    }

    function applyWebViewJsSetting(jsEnabled) {
        // Intentionally a no-op. Writing WebView.settings at runtime crashes Qt's macOS WebView
        // (SIGSEGV in QDarwinWebViewSettingsPrivate, seen 2026-11-25). Settings are fixed once when the
        // view is created; Reader Mode hides the WebView and shows the rich-text view instead.
    }

    function replaceTabAt(idx, updated) {
        if (idx < 0 || idx >= tabs.length) return
        var copy = tabs.slice()
        copy[idx] = updated
        tabs = copy
    }

    function findTabIndexById(tabId) {
        for (var i = 0; i < tabs.length; i++) {
            if (tabs[i] && tabs[i].id === tabId) return i
        }
        return -1
    }

    function patchTabById(tabId, patch) {
        var idx = findTabIndexById(tabId)
        if (idx === -1) return null
        var merged = Object.assign({}, tabs[idx], patch)
        replaceTabAt(idx, merged)
        if (idx === activeTabIndex && patch.url !== undefined) {
            urlInput = merged.url
        }
        syncWebViewBounds()
        return merged
    }

    function openNewTab(initialUrl, focusAddress) {
        var tab = Logic.createTab(nextTabId++, {
            readerMode: host ? host.defaultReaderMode : false
        })
        var copy = tabs.slice()
        copy.push(tab)
        tabs = copy
        activeTabIndex = copy.length - 1
        urlInput = initialUrl ? String(initialUrl) : ""
        pendingExternalUrl = ""
        bannerProblem = ""
        bannerNotice = ""
        if (initialUrl && String(initialUrl).trim() !== "") {
            navigateInActiveTab(String(initialUrl), true)
        } else {
            syncWebViewToActiveTab()
            if (focusAddress !== false) {
                Qt.callLater(function() {
                    urlEdit.forceActiveFocus()
                    urlEdit.selectAll()
                })
            }
        }
        return tab.id
    }

    function openUrlFromExternal(rawUrl) {
        openAndRaise()
        if (activeTab === null) {
            openNewTab(rawUrl, false)
            return
        }
        if (activeTab.url === "") {
            navigateInActiveTab(rawUrl, true)
        } else {
            openNewTab(rawUrl, false)
        }
    }

    function selectTab(idx) {
        if (idx < 0 || idx >= tabs.length) return
        activeTabIndex = idx
        var t = tabs[idx]
        urlInput = t ? t.url : ""
        pendingExternalUrl = ""
        bannerProblem = ""
        syncWebViewToActiveTab()
    }

    function closeTabAt(idx) {
        var res = Logic.closeTabState(tabs, activeTabIndex, idx)
        if (res.closedTab && res.closedTab.loopbackToken) {
            // Only close loopback server if no other tab shares that token
            var stillUsed = false
            for (var i = 0; i < res.tabs.length; i++) {
                if (res.tabs[i] && res.tabs[i].loopbackToken === res.closedTab.loopbackToken) {
                    stillUsed = true
                    break
                }
            }
            if (!stillUsed && host) {
                host.closeLoopbackSite(res.closedTab.loopbackToken)
            }
        }
        tabs = res.tabs
        activeTabIndex = res.activeIndex
        if (res.shouldCloseWindow) {
            urlInput = ""
            if (webViewObj) {
                try { webViewObj.url = "about:blank" } catch (e) {}
            }
            persistGeometryNow()
            visible = false
            return
        }
        urlInput = activeTab ? activeTab.url : ""
        syncWebViewToActiveTab()
    }

    function syncWebViewToActiveTab() {
        ensureWebView()
        syncWebViewBounds()
        if (!webViewObj) return
        if (!activeTab || activeTabReaderActive || !activeTab.loopbackUrl || activeTab.notFoundState || activeTab.storageError) {
            applyWebViewJsSetting(activeTab ? !activeTab.readerMode : true)
            if (String(webViewObj.url || "") !== "about:blank") {
                try { webViewObj.url = "about:blank" } catch (e) {}
            }
            return
        }
        applyWebViewJsSetting(!activeTab.readerMode)
        if (String(webViewObj.url || "") !== activeTab.loopbackUrl) {
            console.log("lns_browser: webview load " + activeTab.url)
            webViewObj.url = activeTab.loopbackUrl
            pendingLoadUrl = activeTab.loopbackUrl
            pendingLoadRetries = 0
            loadStartWatch.restart()
        }
    }

    // If WebKit never reports "started" for a URL we gave it, give it again (at most 3 times).
    property string pendingLoadUrl: ""
    property int pendingLoadRetries: 0
    Timer {
        id: loadStartWatch
        interval: 1000
        repeat: false
        onTriggered: {
            if (!browserWin.webViewObj || browserWin.pendingLoadUrl === "") return
            if (!browserWin.activeTab || browserWin.activeTab.loopbackUrl !== browserWin.pendingLoadUrl) { browserWin.pendingLoadUrl = ""; return }
            if (browserWin.pendingLoadRetries >= 3) { console.log("lns_browser: webview never started loading"); browserWin.pendingLoadUrl = ""; return }
            browserWin.pendingLoadRetries += 1
            console.log("lns_browser: webview did not start, retry " + browserWin.pendingLoadRetries)
            var u = browserWin.pendingLoadUrl
            try { browserWin.webViewObj.url = "about:blank" } catch (e) {}
            Qt.callLater(function() { if (browserWin.webViewObj) browserWin.webViewObj.url = u })
            loadStartWatch.restart()
        }
    }

    function navigateInActiveTab(rawUrl, recordHistory) {
        if (activeTab === null) {
            openNewTab(rawUrl, false)
            return
        }
        var shouldPush = recordHistory === undefined ? true : recordHistory
        var parsed = Logic.parseUrl(rawUrl)
        if (!parsed.ok) {
            bannerProblem = parsed.error
            return
        }
        var t = activeTab
        var nextSeq = t.navSeq + 1
        var histState = shouldPush
            ? Logic.pushTabHistory(t, parsed.canonical)
            : { history: t.history, historyIdx: t.historyIdx }

        bannerProblem = ""
        bannerNotice = ""
        pendingExternalUrl = ""
        urlInput = parsed.canonical

        var sameActiveSite = t.loopbackOrigin !== ""
            && t.loopbackToken !== ""
            && t.siteBase === parsed.siteBase
            && !t.readerMode
            && webViewAvailable
            && !t.storageError

        var updated = Object.assign({}, t, {
            url: parsed.canonical,
            siteBase: parsed.siteBase,
            host: parsed.kind === "lns" ? parsed.name : parsed.cid,
            kind: parsed.kind,
            path: parsed.path,
            navSeq: nextSeq,
            history: histState.history,
            historyIdx: histState.historyIdx,
            loading: true,
            loadProgress: 12,
            notFoundState: null,
            storageError: null,
        })
        replaceTabAt(activeTabIndex, updated)

        // Fast path: navigating to another path on the SAME already-mounted loopback site!
        if (sameActiveSite) {
            var nextLbUrl = Logic.buildLoopbackEntryUrl(updated.loopbackOrigin, updated.loopbackToken, parsed.path + (parsed.fragment || ""))
            patchTabById(updated.id, { loopbackUrl: nextLbUrl })
            if (webViewObj) {
                applyWebViewJsSetting(true)
                webViewObj.url = nextLbUrl
            }
            return
        }

        // Release old site token if switching to a different site and no other tab uses it
        if (t.loopbackToken && t.siteBase !== parsed.siteBase) {
            var shared = false
            for (var i = 0; i < tabs.length; i++) {
                if (tabs[i] && tabs[i].id !== t.id && tabs[i].loopbackToken === t.loopbackToken) {
                    shared = true
                    break
                }
            }
            if (!shared && host) {
                host.closeLoopbackSite(t.loopbackToken)
            }
            patchTabById(updated.id, { loopbackOrigin: "", loopbackToken: "", loopbackUrl: "", siteStats: null })
        }

        if (host) {
            host.loadTabNavigation(updated.id, nextSeq, parsed, updated.readerMode || !webViewAvailable)
        }
    }

    function goBack() {
        if (!Logic.canTabGoBack(activeTab)) return
        var nextIdx = activeTab.historyIdx - 1
        var target = activeTab.history[nextIdx]
        patchTabById(activeTab.id, { historyIdx: nextIdx })
        navigateInActiveTab(target, false)
    }

    function goForward() {
        if (!Logic.canTabGoForward(activeTab)) return
        var nextIdx = activeTab.historyIdx + 1
        var target = activeTab.history[nextIdx]
        patchTabById(activeTab.id, { historyIdx: nextIdx })
        navigateInActiveTab(target, false)
    }

    function reloadOrStop() {
        if (!activeTab) return
        if (activeTab.loading) {
            if (webViewObj && !activeTabReaderActive) {
                try { webViewObj.stop() } catch (e) {}
            }
            patchTabById(activeTab.id, { loading: false, loadProgress: 0 })
            return
        }
        if (activeTab.url !== "") {
            if (!activeTabReaderActive && webViewObj && activeTab.loopbackUrl !== "" && !activeTab.notFoundState && !activeTab.storageError) {
                patchTabById(activeTab.id, { loading: true, loadProgress: 15 })
                webViewObj.reload()
            } else {
                navigateInActiveTab(activeTab.url, false)
            }
        }
    }

    function toggleReaderMode() {
        if (!activeTab) return
        if (!webViewAvailable) {
            bannerNotice = "QtWebView is unavailable on this platform — Reader Mode is active."
            return
        }
        var nextReader = !activeTab.readerMode
        patchTabById(activeTab.id, {
            readerMode: nextReader,
            notFoundState: null,
            storageError: null,
        })
        if (nextReader) {
            applyWebViewJsSetting(false)
            if (webViewObj) {
                try { webViewObj.stop(); webViewObj.url = "about:blank" } catch (e) {}
            }
        } else {
            applyWebViewJsSetting(true)
        }
        syncWebViewBounds()
        if (activeTab.url !== "") {
            navigateInActiveTab(activeTab.url, false)
        }
    }

    function setZoom(pct) {
        if (!activeTab) return
        var clamped = Logic.clampZoomPercent(pct)
        patchTabById(activeTab.id, { zoomPercent: clamped })
        applyZoomToWebView(clamped)
    }

    function applyZoomToWebView(pct) {
        if (!webViewObj || !webViewActive) return
        var val = Logic.clampZoomPercent(pct !== undefined ? pct : (activeTab ? activeTab.zoomPercent : 100))
        try {
            webViewObj.runJavaScript("document.documentElement.style.zoom='" + val + "%'")
        } catch (e) {}
    }

    function runFind(backwards) {
        var q = findQuery.trim()
        if (!q) {
            findStatus = ""
            return
        }
        if (activeTabReaderActive) {
            var html = activeTab && activeTab.pageData ? (activeTab.pageData.html || "") : ""
            var count = Logic.countTextMatches(html, q)
            findStatus = count + (count === 1 ? " match" : " matches")
            return
        }
        if (webViewObj && webViewActive) {
            var js = "window.find(" + JSON.stringify(q) + ", false, " + (backwards ? "true" : "false") + ", true, false, true, false)"
            try {
                webViewObj.runJavaScript(js, function(found) {
                    findStatus = found ? "Match found" : "No match"
                })
            } catch (e) {
                findStatus = ""
            }
        }
    }

    function toggleCurrentBookmark() {
        if (!host || !activeTab || !activeTab.url) return
        host.toggleBookmarkEntry({
            url: activeTab.url,
            title: activeTab.title || activeTab.host || activeTab.url,
            name: activeTab.host || ""
        })
    }

    function shouldDedupeEvent(key) {
        var now = Date.now()
        if (key === lastHandledEventKey && (now - lastHandledEventTs) < 800) {
            return true
        }
        lastHandledEventKey = key
        lastHandledEventTs = now
        return false
    }

    // Called from dynamic WebView.onLoadingChanged
    function handleWebViewLoadingChanged(status, rawUrl, errorString) {
        if (status === "started" || status === "succeeded") { pendingLoadUrl = ""; loadStartWatch.stop() }
        if (status !== "started") console.log("lns_browser: webview " + status + (errorString ? " " + errorString : ""))
        if (!activeTab || activeTabReaderActive) return
        if (status === "started") {
            var decision = Logic.classifyWebViewUrl(rawUrl, activeTab.loopbackOrigin, activeTab.loopbackToken, activeTab.siteBase)
            if (decision.action === "ignore") return
            if (decision.action === "ext") {
                try { webViewObj.stop() } catch (e) {}
                if (!shouldDedupeEvent("ext:" + decision.url)) {
                    pendingExternalUrl = decision.url
                }
                patchTabById(activeTab.id, { loading: false, loadProgress: 0 })
                return
            }
            if (decision.action === "lns") {
                try { webViewObj.stop() } catch (e) {}
                if (!shouldDedupeEvent("lns:" + decision.url)) {
                    navigateInActiveTab(decision.url, true)
                }
                return
            }
            if (decision.action === "dl") {
                try { webViewObj.stop() } catch (e) {}
                var dlKey = "dl:" + decision.cid + ":" + decision.path + ":" + decision.filename
                if (!shouldDedupeEvent(dlKey)) {
                    startSiteDownload(activeTab.loopbackToken, decision.cid, decision.path, decision.filename)
                }
                patchTabById(activeTab.id, { loading: false, loadProgress: 0 })
                return
            }
            if (decision.action === "block") {
                try { webViewObj.stop() } catch (e) {}
                bannerProblem = decision.reason
                patchTabById(activeTab.id, { loading: false, loadProgress: 0 })
                return
            }
            if (decision.action === "allow") {
                var histState
                var curHist = Logic.toArray(activeTab.history)
                var curIdx = activeTab.historyIdx
                var curEntry = (curIdx >= 0 && curIdx < curHist.length) ? curHist[curIdx] : ""
                if (curEntry && (curEntry === decision.canonical || curEntry + "/" === decision.canonical || curEntry === decision.canonical + "/")) {
                    var updatedHist = curHist.slice()
                    updatedHist[curIdx] = decision.canonical
                    histState = { history: updatedHist, historyIdx: curIdx }
                } else {
                    histState = Logic.pushTabHistory(activeTab, decision.canonical)
                }
                patchTabById(activeTab.id, {
                    url: decision.canonical,
                    path: decision.sitePath,
                    loopbackUrl: rawUrl,
                    history: histState.history,
                    historyIdx: histState.historyIdx,
                    loading: true,
                    loadProgress: 20,
                    notFoundState: null,
                    storageError: null,
                })
                urlInput = decision.canonical
                return
            }
        }
        if (status === "succeeded") {
            patchTabById(activeTab.id, { loading: false, loadProgress: 100 })
            applyZoomToWebView(activeTab.zoomPercent)
            pollActiveSiteEvents()
            if (host && activeTab.url) {
                host.recordVisitedPage({
                    url: activeTab.url,
                    title: activeTab.title || activeTab.host || activeTab.url,
                    name: activeTab.host || ""
                })
            }
            return
        }
        if (status === "failed") {
            patchTabById(activeTab.id, { loading: false, loadProgress: 0 })
            pollActiveSiteEvents()
            if (errorString && errorString.toLowerCase().indexOf("cancel") === -1) {
                bannerProblem = "Page load failed: " + errorString
            }
            return
        }
        if (status === "stopped") {
            patchTabById(activeTab.id, { loading: false, loadProgress: 0 })
        }
    }

    function handleWebViewProgress(progress) {
        if (!activeTab || activeTabReaderActive) return
        patchTabById(activeTab.id, { loadProgress: Math.max(0, Math.min(100, Number(progress) || 0)) })
    }

    function handleWebViewTitle(t) {
        if (!activeTab || activeTabReaderActive) return
        var clean = String(t || "").trim()
        if (clean !== "" && clean !== activeTab.title) {
            patchTabById(activeTab.id, { title: clean })
        }
    }

    // Called by Main.qml when `site_open` succeeds for a tab
    function attachLoopbackSite(tabId, navSeq, openInfo, siteInfoObj) {
        var idx = findTabIndexById(tabId)
        if (idx === -1) return
        var t = tabs[idx]
        if (t.navSeq !== navSeq) return
        var updated = patchTabById(tabId, {
            loopbackOrigin: String(openInfo.origin || ""),
            loopbackToken: String(openInfo.token || ""),
            loopbackUrl: String(openInfo.entry_url || ""),
            mode: String(openInfo.mode || t.mode || ""),
            rootCid: String(openInfo.root_cid || t.rootCid || ""),
            rootSha256: String(openInfo.root_sha256 || t.rootSha256 || ""),
            siteInfo: siteInfoObj || t.siteInfo,
            notFoundState: null,
            storageError: null,
            loading: true,
            loadProgress: 25,
        })
        if (idx === activeTabIndex && updated && !updated.readerMode && webViewAvailable) {
            syncWebViewToActiveTab()
        }
    }

    // Called by Main.qml when Reader Mode renders a page
    function attachReaderPage(tabId, navSeq, pageDataObj, siteInfoObj) {
        var idx = findTabIndexById(tabId)
        if (idx === -1) return
        var t = tabs[idx]
        if (t.navSeq !== navSeq) return
        patchTabById(tabId, {
            loading: false,
            loadProgress: 100,
            pageData: pageDataObj,
            siteInfo: siteInfoObj || t.siteInfo,
            title: (pageDataObj && pageDataObj.title) ? pageDataObj.title : (t.title || t.host),
            mode: (pageDataObj && pageDataObj.mode) ? pageDataObj.mode : t.mode,
            rootCid: (pageDataObj && (pageDataObj.root_cid || pageDataObj.cid)) ? (pageDataObj.root_cid || pageDataObj.cid) : t.rootCid,
            rootSha256: (pageDataObj && (pageDataObj.root_sha256 || pageDataObj.sha256)) ? (pageDataObj.root_sha256 || pageDataObj.sha256) : t.rootSha256,
            verified: !!(pageDataObj && pageDataObj.verified),
            notFoundState: null,
            storageError: null,
        })
        if (host && t.url) {
            host.recordVisitedPage({
                url: t.url,
                title: (pageDataObj && pageDataObj.title) ? pageDataObj.title : (t.host || t.url),
                name: t.host || ""
            })
        }
    }

    function attachTabNotFound(tabId, navSeq, requestedPath, siteBase, singlePage) {
        var idx = findTabIndexById(tabId)
        if (idx === -1) return
        if (navSeq !== -1 && tabs[idx].navSeq !== navSeq) return
        patchTabById(tabId, {
            loading: false,
            loadProgress: 0,
            pageData: null,
            storageError: null,
            notFoundState: {
                requestedPath: requestedPath || "/",
                siteBase: siteBase || tabs[idx].siteBase,
                singlePage: !!singlePage
            }
        })
        if (idx === activeTabIndex && webViewObj) {
            try { webViewObj.stop(); webViewObj.url = "about:blank" } catch (e) {}
        }
    }

    function attachTabStorageError(tabId, navSeq, cid, path, message) {
        var idx = findTabIndexById(tabId)
        if (idx === -1) return
        if (navSeq !== -1 && tabs[idx].navSeq !== navSeq) return
        patchTabById(tabId, {
            loading: false,
            loadProgress: 0,
            pageData: null,
            notFoundState: null,
            storageError: {
                cid: cid || "",
                path: path || "/",
                message: message || "Storage fetch failed"
            }
        })
        if (idx === activeTabIndex && webViewObj) {
            try { webViewObj.stop(); webViewObj.url = "about:blank" } catch (e) {}
        }
    }

    function attachTabNoSite(tabId, navSeq, siteInfoObj) {
        var idx = findTabIndexById(tabId)
        if (idx === -1) return
        if (navSeq !== -1 && tabs[idx].navSeq !== navSeq) return
        patchTabById(tabId, {
            loading: false,
            loadProgress: 0,
            pageData: null,
            loopbackUrl: "",
            siteInfo: siteInfoObj,
            notFoundState: null,
            storageError: null,
        })
    }

    function startSiteDownload(token, cid, relPath, filename, pinnedSha256) {
        if (!host) return
        downloadBanner = {
            token: token || "",
            cid: cid || "",
            relPath: relPath || "",
            filename: filename || "download",
            pinnedSha256: pinnedSha256 || "",
            path: "",
            status: "Downloading...",
            message: "Fetching " + (filename || cid) + " through LNS Browser Core...",
            active: true,
            verified: false,
            failed: false,
        }
        host.startCoreDownload(token || "", cid || "", relPath || "", filename || "", pinnedSha256 || "", function(info) {
            if (info && info.done) {
                downloadBanner = {
                    token: token || "",
                    cid: info.cid || cid || "",
                    relPath: relPath || "",
                    filename: info.filename || filename || "download",
                    path: info.path || "",
                    status: info.verified ? "Saved & verified ✓" : "Saved",
                    message: (info.verified ? "Saved & verified " : "Saved ") + (info.filename || filename) + " to " + (info.path || "~/Downloads"),
                    active: false,
                    verified: !!info.verified,
                    failed: false,
                }
            } else if (info) {
                downloadBanner = {
                    token: token || "",
                    cid: info.cid || cid || "",
                    relPath: relPath || "",
                    filename: info.filename || filename || "download",
                    path: info.path || "",
                    status: "Downloading...",
                    message: "Saving " + (info.filename || filename) + " to " + (info.path || "~/Downloads") + "...",
                    active: true,
                    verified: false,
                    failed: false,
                }
            }
        }, function(errMsg) {
            downloadBanner = {
                token: token || "",
                cid: cid || "",
                relPath: relPath || "",
                filename: filename || "download",
                path: "",
                status: "Failed",
                message: String(errMsg || "Download failed"),
                active: false,
                verified: false,
                failed: true,
            }
        })
    }

    function onCoreDownloadFinished(ok, filename, path, verified, message) {
        if (!downloadBanner) return
        downloadBanner = Object.assign({}, downloadBanner, {
            filename: filename || downloadBanner.filename,
            path: path || downloadBanner.path,
            status: ok ? (verified ? "Saved & verified ✓" : "Saved") : "Failed",
            message: message || (ok ? ("Saved " + filename) : "Download failed"),
            active: false,
            verified: !!verified,
            failed: !ok,
        })
    }

    function pollActiveSiteEvents() {
        if (!host || !activeTab || !activeTab.loopbackToken || activeTabReaderActive) return
        var tabId = activeTab.id
        var tok = activeTab.loopbackToken
        host.callCore("lns_browser_core", "site_poll_events", [tok], function(res) {
            var idx = findTabIndexById(tabId)
            if (idx === -1) return
            var t = tabs[idx]
            if (t.loopbackToken !== tok) return
            if (res && res.stats) {
                var st = res.stats
                patchTabById(tabId, {
                    siteStats: st,
                    verified: !!st.verified,
                    mode: st.mode || t.mode,
                    rootCid: st.root_cid || t.rootCid,
                    rootSha256: st.root_sha256 || t.rootSha256,
                    title: (st.title && String(st.title).trim()) ? st.title : t.title,
                })
            }
            var events = Logic.toArray(res && res.events)
            for (var i = 0; i < events.length; i++) {
                var ev = events[i]
                if (!ev || !ev.kind) continue
                if (ev.kind === "ext" && ev.url) {
                    if (!shouldDedupeEvent("ext:" + ev.url)) pendingExternalUrl = ev.url
                } else if (ev.kind === "lns" && ev.url) {
                    if (!shouldDedupeEvent("lns:" + ev.url)) navigateInActiveTab(ev.url, true)
                } else if (ev.kind === "dl") {
                    var dk = "dl:" + (ev.cid || "") + ":" + (ev.path || "") + ":" + (ev.filename || "")
                    if (!shouldDedupeEvent(dk)) {
                        startSiteDownload(tok, ev.cid || "", ev.path || "", ev.filename || "")
                    }
                } else if (ev.kind === "not_found" && idx === activeTabIndex && ev.path === t.path) {
                    attachTabNotFound(tabId, -1, ev.path || t.path, t.siteBase, t.mode === "onchain-page" || t.mode === "single")
                } else if (ev.kind === "tampered" && idx === activeTabIndex) {
                    attachTabStorageError(tabId, -1, ev.cid || t.rootCid, ev.path || t.path, ev.message || "SHA-256 integrity mismatch")
                } else if (ev.kind === "storage_error" && idx === activeTabIndex && (ev.path === t.path || ev.cid === t.rootCid || t.path === "/")) {
                    attachTabStorageError(tabId, -1, ev.cid || t.rootCid, ev.path || t.path, ev.message || "Storage error")
                }
            }
        }, function() {}, 4000)
    }

    Timer {
        id: pollEventsTimer
        interval: 350
        repeat: true
        running: browserWin.visible && browserWin.activeTab !== null && browserWin.activeTab.loopbackToken !== "" && !browserWin.activeTabReaderActive
        onTriggered: browserWin.pollActiveSiteEvents()
    }

    // ── Keyboard Shortcuts (Cmd maps to Ctrl in Qt on macOS) ─────────────
    Shortcut {
        sequences: ["Ctrl+L"]
        context: Qt.WindowShortcut
        onActivated: { urlEdit.forceActiveFocus(); urlEdit.selectAll() }
    }
    Shortcut {
        sequences: ["Ctrl+T"]
        context: Qt.WindowShortcut
        onActivated: browserWin.openNewTab("", true)
    }
    Shortcut {
        sequences: ["Ctrl+W"]
        context: Qt.WindowShortcut
        onActivated: if (browserWin.activeTabIndex >= 0) browserWin.closeTabAt(browserWin.activeTabIndex)
    }
    Shortcut {
        sequences: ["Ctrl+R"]
        context: Qt.WindowShortcut
        onActivated: browserWin.reloadOrStop()
    }
    Shortcut {
        sequences: ["Ctrl+["]
        context: Qt.WindowShortcut
        onActivated: browserWin.goBack()
    }
    Shortcut {
        sequences: ["Ctrl+]"]
        context: Qt.WindowShortcut
        onActivated: browserWin.goForward()
    }
    Shortcut {
        sequences: ["Ctrl+F"]
        context: Qt.WindowShortcut
        onActivated: {
            browserWin.findOpen = true
            Qt.callLater(function() { findInput.forceActiveFocus(); findInput.selectAll() })
        }
    }
    Shortcut {
        sequences: ["Ctrl++", "Ctrl+="]
        context: Qt.WindowShortcut
        onActivated: if (browserWin.activeTab) browserWin.setZoom(browserWin.activeTab.zoomPercent + 10)
    }
    Shortcut {
        sequences: ["Ctrl+-"]
        context: Qt.WindowShortcut
        onActivated: if (browserWin.activeTab) browserWin.setZoom(browserWin.activeTab.zoomPercent - 10)
    }
    Shortcut {
        sequences: ["Ctrl+0"]
        context: Qt.WindowShortcut
        onActivated: if (browserWin.activeTab) browserWin.setZoom(100)
    }
    Shortcut {
        sequences: ["Escape"]
        context: Qt.WindowShortcut
        onActivated: {
            if (browserWin.findOpen) browserWin.findOpen = false
            else if (browserWin.pendingExternalUrl !== "") browserWin.pendingExternalUrl = ""
            else if (browserWin.verifiedDrawerOpen) browserWin.verifiedDrawerOpen = false
            else if (browserWin.libraryDrawerOpen) browserWin.libraryDrawerOpen = false
        }
    }

    // ── Main Window Layout (All Chrome Above or Beside WebView) ──────────
    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // 1. Tab Strip
        Rectangle {
            Layout.fillWidth: true
            height: px(36)
            color: host ? host.card : "#171f2d"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: px(8)
                anchors.rightMargin: px(8)
                spacing: px(4)

                Flickable {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    contentWidth: tabRow.implicitWidth
                    clip: true

                    Row {
                        id: tabRow
                        height: parent.height
                        spacing: px(4)
                        y: px(4)

                        Repeater {
                            model: browserWin.tabs
                            delegate: Rectangle {
                                required property var modelData
                                required property int index
                                readonly property bool isCurrent: index === browserWin.activeTabIndex
                                width: Math.max(px(120), Math.min(px(210), tabTitleTxt.implicitWidth + px(44)))
                                height: px(28)
                                radius: px(7)
                                color: isCurrent ? (host ? host.slate : "#0f141d") : (host ? host.raised : "#202b3d")
                                border.color: isCurrent ? (host ? host.brass : "#e5a93b") : (host ? host.line : "#2b364a")

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: px(8)
                                    anchors.rightMargin: px(6)
                                    spacing: px(4)

                                    Text {
                                        id: tabTitleTxt
                                        Layout.fillWidth: true
                                        text: (modelData.loading ? "◌ " : "") + Logic.formatTabTitle(modelData)
                                        color: host ? host.ink : "#e6edf7"
                                        font.pixelSize: px(11)
                                        font.bold: isCurrent
                                        elide: Text.ElideRight
                                    }

                                    Rectangle {
                                        width: px(18); height: px(18); radius: px(4)
                                        color: "transparent"
                                        Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(10) }
                                        MouseArea {
                                            anchors.fill: parent
                                            cursorShape: Qt.PointingHandCursor
                                            onClicked: function(mouse) { mouse.accepted = true; browserWin.closeTabAt(index) }
                                        }
                                    }
                                }

                                MouseArea {
                                    anchors.fill: parent
                                    anchors.rightMargin: px(24)
                                    cursorShape: Qt.PointingHandCursor
                                    onClicked: browserWin.selectTab(index)
                                }
                            }
                        }
                    }
                }

                // New Tab button (+)
                Rectangle {
                    width: px(28); height: px(26); radius: px(6)
                    color: host ? host.raised : "#202b3d"
                    border.color: host ? host.line : "#2b364a"
                    Text { anchors.centerIn: parent; text: "+"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(15); font.bold: true }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.openNewTab("", true) }
                }
            }

            Rectangle {
                anchors.left: parent.left; anchors.right: parent.right; anchors.bottom: parent.bottom
                height: 1; color: host ? host.line : "#2b364a"
            }
        }

        // 2. Navigation Toolbar
        Rectangle {
            Layout.fillWidth: true
            height: px(44)
            color: host ? host.slate : "#0f141d"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: px(10)
                anchors.rightMargin: px(10)
                spacing: px(6)

                // Back
                Rectangle {
                    width: px(30); height: px(30); radius: px(6)
                    color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    opacity: Logic.canTabGoBack(browserWin.activeTab) ? 1.0 : 0.4
                    Text { anchors.centerIn: parent; text: "←"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(13) }
                    MouseArea { anchors.fill: parent; enabled: Logic.canTabGoBack(browserWin.activeTab); cursorShape: Qt.PointingHandCursor; onClicked: browserWin.goBack() }
                }

                // Forward
                Rectangle {
                    width: px(30); height: px(30); radius: px(6)
                    color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    opacity: Logic.canTabGoForward(browserWin.activeTab) ? 1.0 : 0.4
                    Text { anchors.centerIn: parent; text: "→"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(13) }
                    MouseArea { anchors.fill: parent; enabled: Logic.canTabGoForward(browserWin.activeTab); cursorShape: Qt.PointingHandCursor; onClicked: browserWin.goForward() }
                }

                // Reload / Stop
                Rectangle {
                    width: px(30); height: px(30); radius: px(6)
                    color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    Text {
                        anchors.centerIn: parent
                        text: (browserWin.activeTab && browserWin.activeTab.loading) ? "✕" : "↻"
                        color: host ? host.ink : "#e6edf7"
                        font.pixelSize: px(13)
                    }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.reloadOrStop() }
                }

                // Address Bar (with clickable Verified Badge + Bookmark Star)
                Rectangle {
                    Layout.fillWidth: true
                    height: px(32)
                    radius: px(8)
                    color: host ? host.card : "#171f2d"
                    border.color: urlEdit.activeFocus ? (host ? host.brass : "#e5a93b") : (host ? host.line : "#2b364a")

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: px(6)
                        anchors.rightMargin: px(6)
                        spacing: px(6)

                        // Verified Badge Pill (click to open Verified Inspector drawer)
                        Rectangle {
                            visible: browserWin.activeTabHasSite
                            implicitWidth: verTxt.implicitWidth + px(12)
                            height: px(20)
                            radius: px(10)
                            color: browserWin.activeTabVerified ? (host ? host.good : "#16a34a") : (host ? host.raised : "#202b3d")
                            border.color: browserWin.verifiedDrawerOpen ? (host ? host.brass : "#e5a93b") : "transparent"

                            Text {
                                id: verTxt
                                anchors.centerIn: parent
                                text: browserWin.activeTabMode === "onchain-page"
                                    ? "ON-CHAIN ✓"
                                    : (browserWin.activeTabVerified ? "VERIFIED ✓" : "CID")
                                color: browserWin.activeTabVerified ? (host ? host.slate : "#0f141d") : (host ? host.dim : "#8a99ad")
                                font.family: host ? host.mono : "Menlo"
                                font.pixelSize: px(10)
                                font.bold: true
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    browserWin.verifiedDrawerOpen = !browserWin.verifiedDrawerOpen
                                    if (browserWin.verifiedDrawerOpen) browserWin.libraryDrawerOpen = false
                                }
                            }
                        }

                        TextInput {
                            id: urlEdit
                            Layout.fillWidth: true
                            verticalAlignment: TextInput.AlignVCenter
                            color: host ? host.ink : "#e6edf7"
                            font.family: host ? host.mono : "Menlo"
                            font.pixelSize: px(12)
                            selectByMouse: true
                            text: browserWin.urlInput
                            onTextEdited: browserWin.urlInput = text
                            onAccepted: browserWin.navigateInActiveTab(text, true)
                        }

                        // Bookmark star
                        Rectangle {
                            visible: browserWin.activeTabHasSite
                            width: px(24); height: px(24); radius: px(5)
                            color: "transparent"
                            readonly property bool starred: host && browserWin.activeTab ? Logic.isBookmarked(host.bookmarks, browserWin.activeTab.url) : false
                            Text {
                                anchors.centerIn: parent
                                text: parent.starred ? "★" : "☆"
                                color: parent.starred ? (host ? host.brass : "#e5a93b") : (host ? host.dim : "#8a99ad")
                                font.pixelSize: px(14)
                            }
                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: browserWin.toggleCurrentBookmark()
                            }
                        }
                    }
                }

                // Go button
                Rectangle {
                    width: px(42); height: px(30); radius: px(6)
                    color: host ? host.brass : "#e5a93b"
                    Text { anchors.centerIn: parent; text: "Go"; color: host ? host.slate : "#0f141d"; font.bold: true; font.pixelSize: px(11) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.navigateInActiveTab(browserWin.urlInput, true) }
                }

                // Reader Mode toggle (JS Off vs Sterilised JS On)
                Rectangle {
                    implicitWidth: readerBtnTxt.implicitWidth + px(14); height: px(30); radius: px(6)
                    color: browserWin.activeTabReaderActive ? (host ? host.brass : "#e5a93b") : (host ? host.raised : "#202b3d")
                    border.color: host ? host.line : "#2b364a"
                    Text {
                        id: readerBtnTxt
                        anchors.centerIn: parent
                        text: browserWin.activeTabReaderActive ? "Reader (JS Off)" : "Reader"
                        color: browserWin.activeTabReaderActive ? (host ? host.slate : "#0f141d") : (host ? host.ink : "#e6edf7")
                        font.bold: browserWin.activeTabReaderActive
                        font.pixelSize: px(11)
                    }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.toggleReaderMode() }
                }

                // Zoom Badge (click to reset to 100%)
                Rectangle {
                    visible: browserWin.activeTab !== null && browserWin.activeTab.zoomPercent !== 100
                    implicitWidth: zoomTxt.implicitWidth + px(12); height: px(30); radius: px(6)
                    color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    Text {
                        id: zoomTxt
                        anchors.centerIn: parent
                        text: browserWin.activeTab ? (browserWin.activeTab.zoomPercent + "%") : "100%"
                        color: host ? host.ink : "#e6edf7"
                        font.family: host ? host.mono : "Menlo"
                        font.pixelSize: px(11)
                    }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.setZoom(100) }
                }

                // Find toggle
                Rectangle {
                    width: px(30); height: px(30); radius: px(6)
                    color: browserWin.findOpen ? (host ? host.brass : "#e5a93b") : (host ? host.raised : "#202b3d")
                    border.color: host ? host.line : "#2b364a"
                    Text { anchors.centerIn: parent; text: "⌕"; color: browserWin.findOpen ? (host ? host.slate : "#0f141d") : (host ? host.ink : "#e6edf7"); font.pixelSize: px(14) }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            browserWin.findOpen = !browserWin.findOpen
                            if (browserWin.findOpen) Qt.callLater(function() { findInput.forceActiveFocus(); findInput.selectAll() })
                        }
                    }
                }

                // Site Files drawer toggle
                Rectangle {
                    visible: browserWin.activeTabFiles.length > 0
                    implicitWidth: filesBtnTxt.implicitWidth + px(12); height: px(30); radius: px(6)
                    color: browserWin.filesDrawerOpen ? (host ? host.brass : "#e5a93b") : (host ? host.raised : "#202b3d")
                    border.color: host ? host.line : "#2b364a"
                    Text {
                        id: filesBtnTxt
                        anchors.centerIn: parent
                        text: "Files"
                        color: browserWin.filesDrawerOpen ? (host ? host.slate : "#0f141d") : (host ? host.ink : "#e6edf7")
                        font.pixelSize: px(11)
                    }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.filesDrawerOpen = !browserWin.filesDrawerOpen }
                }

                // Bookmarks & History drawer toggle
                Rectangle {
                    implicitWidth: libBtnTxt.implicitWidth + px(12); height: px(30); radius: px(6)
                    color: browserWin.libraryDrawerOpen ? (host ? host.brass : "#e5a93b") : (host ? host.raised : "#202b3d")
                    border.color: host ? host.line : "#2b364a"
                    Text {
                        id: libBtnTxt
                        anchors.centerIn: parent
                        text: "Library"
                        color: browserWin.libraryDrawerOpen ? (host ? host.slate : "#0f141d") : (host ? host.ink : "#e6edf7")
                        font.pixelSize: px(11)
                    }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            browserWin.libraryDrawerOpen = !browserWin.libraryDrawerOpen
                            if (browserWin.libraryDrawerOpen) browserWin.verifiedDrawerOpen = false
                        }
                    }
                }
            }
        }

        // 3. 2px Progress Bar
        Rectangle {
            Layout.fillWidth: true
            height: 2
            color: host ? host.line : "#2b364a"
            Rectangle {
                height: parent.height
                width: (browserWin.activeTab && browserWin.activeTab.loading)
                    ? parent.width * Math.max(0.08, Math.min(1.0, (browserWin.activeTab.loadProgress || 10) / 100.0))
                    : 0
                color: host ? host.brass : "#e5a93b"
                Behavior on width { NumberAnimation { duration: 120 } }
            }
        }

        // 4. Docked Find Bar (Cmd-F)
        Rectangle {
            visible: browserWin.findOpen
            Layout.fillWidth: true
            height: px(38)
            color: host ? host.card : "#171f2d"
            border.color: host ? host.line : "#2b364a"

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: px(12); anchors.rightMargin: px(12)
                spacing: px(8)

                Text { text: "Find:"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(12) }
                Rectangle {
                    Layout.preferredWidth: px(260); height: px(26); radius: px(6)
                    color: host ? host.slate : "#0f141d"; border.color: host ? host.line : "#2b364a"
                    TextInput {
                        id: findInput
                        anchors.fill: parent; anchors.margins: px(5)
                        color: host ? host.ink : "#e6edf7"; font.pixelSize: px(12)
                        selectByMouse: true
                        text: browserWin.findQuery
                        onTextEdited: { browserWin.findQuery = text; browserWin.runFind(false) }
                        onAccepted: browserWin.runFind(false)
                    }
                }
                Rectangle {
                    width: px(26); height: px(26); radius: px(5); color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    Text { anchors.centerIn: parent; text: "↑"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(11) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.runFind(true) }
                }
                Rectangle {
                    width: px(26); height: px(26); radius: px(5); color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    Text { anchors.centerIn: parent; text: "↓"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(11) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.runFind(false) }
                }
                Text { text: browserWin.findStatus; color: host ? host.dim : "#8a99ad"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(11) }
                Item { Layout.fillWidth: true }
                Rectangle {
                    width: px(24); height: px(24); radius: px(5); color: host ? host.raised : "#202b3d"
                    Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(11) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.findOpen = false }
                }
            }
        }

        // 5. Docked External HTTPS Link Confirmation Strip
        Rectangle {
            visible: browserWin.pendingExternalUrl.length > 0
            Layout.fillWidth: true
            implicitHeight: extConfirmRow.implicitHeight + px(14)
            color: host ? host.card : "#171f2d"
            border.color: host ? host.brass : "#e5a93b"

            RowLayout {
                id: extConfirmRow
                anchors.fill: parent; anchors.margins: px(7); spacing: px(8)

                Text {
                    Layout.fillWidth: true
                    text: "External web link: " + browserWin.pendingExternalUrl
                    color: host ? host.ink : "#e6edf7"
                    font.family: host ? host.mono : "Menlo"
                    font.pixelSize: px(11)
                    elide: Text.ElideMiddle
                }
                Rectangle {
                    implicitWidth: openExtBtnTxt.implicitWidth + px(14); height: px(26); radius: px(6)
                    color: host ? host.brass : "#e5a93b"
                    Text { id: openExtBtnTxt; anchors.centerIn: parent; text: "Open in Browser"; color: host ? host.slate : "#0f141d"; font.bold: true; font.pixelSize: px(11) }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            if (host) host.openExternalUrl(browserWin.pendingExternalUrl)
                            browserWin.pendingExternalUrl = ""
                        }
                    }
                }
                Rectangle {
                    implicitWidth: copyExtBtnTxt.implicitWidth + px(12); height: px(26); radius: px(6)
                    color: host ? host.raised : "#202b3d"; border.color: host ? host.line : "#2b364a"
                    Text { id: copyExtBtnTxt; anchors.centerIn: parent; text: "Copy Link"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(11) }
                    MouseArea {
                        anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                        onClicked: {
                            if (host) host.copyText(browserWin.pendingExternalUrl)
                            browserWin.bannerNotice = "Copied " + browserWin.pendingExternalUrl
                        }
                    }
                }
                Rectangle {
                    width: px(24); height: px(24); radius: px(5); color: host ? host.raised : "#202b3d"
                    Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(11) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.pendingExternalUrl = "" }
                }
            }
        }

        // 6. Docked Download Progress Strip (downloads through core with SHA-256 verification)
        Rectangle {
            visible: browserWin.downloadBanner !== null
            Layout.fillWidth: true
            implicitHeight: dlStripCol.implicitHeight + px(14)
            color: host ? host.card : "#171f2d"
            border.color: browserWin.downloadBanner && browserWin.downloadBanner.failed
                ? (host ? host.alarm : "#dc2626")
                : (browserWin.downloadBanner && browserWin.downloadBanner.verified ? (host ? host.good : "#16a34a") : (host ? host.line : "#2b364a"))

            ColumnLayout {
                id: dlStripCol
                anchors.fill: parent; anchors.margins: px(7); spacing: px(4)

                RowLayout {
                    Layout.fillWidth: true; spacing: px(8)
                    Text {
                        text: browserWin.downloadBanner ? browserWin.downloadBanner.status : ""
                        color: browserWin.downloadBanner && browserWin.downloadBanner.failed
                            ? (host ? host.alarm : "#dc2626")
                            : (browserWin.downloadBanner && browserWin.downloadBanner.verified ? (host ? host.good : "#16a34a") : (host ? host.brass : "#e5a93b"))
                        font.bold: true; font.pixelSize: px(11)
                    }
                    Text {
                        Layout.fillWidth: true
                        text: browserWin.downloadBanner ? browserWin.downloadBanner.message : ""
                        color: host ? host.ink : "#e6edf7"
                        font.family: host ? host.mono : "Menlo"
                        font.pixelSize: px(11)
                        elide: Text.ElideMiddle
                    }
                    Rectangle {
                        visible: !!browserWin.downloadBanner && !!browserWin.downloadBanner.failed
                        implicitWidth: dlRetryTxt.implicitWidth + px(12); height: px(24); radius: px(5)
                        color: host ? host.brass : "#e5a93b"
                        Text { id: dlRetryTxt; anchors.centerIn: parent; text: "Retry"; color: host ? host.slate : "#0f141d"; font.bold: true; font.pixelSize: px(11) }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: if (browserWin.downloadBanner) {
                                var b = browserWin.downloadBanner
                                browserWin.startSiteDownload(b.token, b.cid, b.relPath, b.filename)
                            }
                        }
                    }
                    Rectangle {
                        width: px(24); height: px(24); radius: px(5); color: host ? host.raised : "#202b3d"
                        Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(11) }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.downloadBanner = null }
                    }
                }
                ProgressBar {
                    visible: !!browserWin.downloadBanner && !!browserWin.downloadBanner.active
                    Layout.fillWidth: true
                    indeterminate: true
                }
            }
        }

        // 7. Docked Status / Error Banner
        Rectangle {
            visible: browserWin.bannerProblem.length > 0 || browserWin.bannerNotice.length > 0
            Layout.fillWidth: true
            implicitHeight: statusBannerRow.implicitHeight + px(10)
            color: host ? host.card : "#171f2d"
            border.color: browserWin.bannerProblem.length > 0 ? (host ? host.alarm : "#dc2626") : (host ? host.good : "#16a34a")

            RowLayout {
                id: statusBannerRow
                anchors.fill: parent; anchors.margins: px(5); spacing: px(8)
                Text {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: browserWin.bannerProblem.length > 0 ? browserWin.bannerProblem : browserWin.bannerNotice
                    color: browserWin.bannerProblem.length > 0 ? (host ? host.alarm : "#dc2626") : (host ? host.good : "#16a34a")
                    font.pixelSize: px(11)
                }
                Rectangle {
                    width: px(22); height: px(22); radius: px(4); color: host ? host.raised : "#202b3d"
                    Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(10) }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: { browserWin.bannerProblem = ""; browserWin.bannerNotice = "" } }
                }
            }
        }

        // 8. Main Content Area (Docked Side Drawers + Dedicated Viewport)
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            // Docked Left Drawer: Site Files
            Rectangle {
                visible: browserWin.filesDrawerOpen && browserWin.activeTabFiles.length > 0
                Layout.preferredWidth: px(220)
                Layout.fillHeight: true
                color: host ? host.card : "#171f2d"
                border.color: host ? host.line : "#2b364a"

                ColumnLayout {
                    anchors.fill: parent; anchors.margins: px(10); spacing: px(6)
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Site Files"; color: host ? host.ink : "#e6edf7"; font.bold: true; font.pixelSize: px(12); Layout.fillWidth: true }
                        Rectangle {
                            width: px(22); height: px(22); radius: px(4); color: host ? host.raised : "#202b3d"
                            Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(10) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.filesDrawerOpen = false }
                        }
                    }
                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: px(3)
                        model: browserWin.activeTabFiles
                        delegate: Rectangle {
                            required property var modelData
                            width: ListView.view.width; height: px(28); radius: px(6)
                            color: (browserWin.activeTab && browserWin.activeTab.path === modelData.path) ? (host ? host.raised : "#202b3d") : "transparent"
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.left: parent.left; anchors.right: parent.right; anchors.margins: px(8)
                                text: modelData.path || modelData.name || ""
                                color: host ? host.ink : "#e6edf7"
                                font.family: host ? host.mono : "Menlo"
                                font.pixelSize: px(11)
                                elide: Text.ElideMiddle
                            }
                            MouseArea {
                                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                onClicked: if (browserWin.activeTab && browserWin.activeTab.siteBase) {
                                    browserWin.navigateInActiveTab(browserWin.activeTab.siteBase + modelData.path, true)
                                }
                            }
                        }
                    }
                }
            }

            // Center Viewport (WebView OR Reader Mode OR Error/Empty/NewTab Card — never overlapping!)
            Item {
                id: viewportFrame
                Layout.fillWidth: true
                Layout.fillHeight: true

                // Dedicated native WebView host
                Item {
                    id: webViewport
                    anchors.fill: parent
                    onWidthChanged: browserWin.syncWebViewBounds()
                    onHeightChanged: browserWin.syncWebViewBounds()
                }

                // Reader Mode (Zero-JS RichText + SVG Canvas + Raster Images + Downloads)
                Rectangle {
                    visible: browserWin.activeTab !== null
                        && browserWin.activeTabReaderActive
                        && !!browserWin.activeTab.pageData
                        && !browserWin.activeTab.notFoundState
                        && !browserWin.activeTab.storageError
                    anchors.fill: parent
                    color: browserWin.pageBg

                    Flickable {
                        anchors.fill: parent
                        anchors.margins: px(24)
                        contentWidth: width
                        contentHeight: readerCol.implicitHeight
                        clip: true

                        ColumnLayout {
                            id: readerCol
                            width: Math.min(parent.width, px(780))
                            anchors.horizontalCenter: parent.horizontalCenter
                            spacing: px(12)

                            Text {
                                readonly property var pd: browserWin.activeTab ? browserWin.activeTab.pageData : null
                                visible: !!pd
                                text: pd
                                    ? ("Reader Mode (JS Off)  ·  " + (pd.mode === "onchain-page"
                                        ? "Stored directly on LEZ · verified on-chain"
                                        : ("CID: " + Logic.shortHash(pd.cid, 12, 8) + "  ·  SHA-256: " + Logic.shortHash(pd.sha256, 10, 8) + (pd.verified ? "  ·  verified on-chain" : ""))))
                                    : ""
                                color: browserWin.pageDim
                                font.family: host ? host.mono : "Menlo"
                                font.pixelSize: px(11)
                                wrapMode: Text.WrapAnywhere
                                Layout.fillWidth: true
                            }

                            Repeater {
                                model: {
                                    var pd = browserWin.activeTab ? browserWin.activeTab.pageData : null
                                    if (!pd) return []
                                    var blks = Logic.toArray(pd.blocks)
                                    if (blks.length > 0) return blks
                                    return pd.html ? [{ kind: "html", html: pd.html }] : []
                                }
                                delegate: Item {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    implicitHeight: modelData.kind === "svg"
                                        ? rSvgCanvas.height
                                        : (modelData.kind === "image" ? rImgItem.height : rTxtItem.implicitHeight)

                                    Canvas {
                                        id: rSvgCanvas
                                        property var svgBlock: modelData
                                        visible: modelData.kind === "svg"
                                        width: Math.min(parent.width, modelData.width ? px(modelData.width) : parent.width)
                                        height: (modelData.vb_w && modelData.vb_h && modelData.vb_w > 0)
                                            ? Math.max(px(24), Math.round(width * modelData.vb_h / modelData.vb_w))
                                            : px(100)
                                        renderStrategy: Canvas.Cooperative
                                        onPaint: {
                                            if (!visible || !modelData || modelData.kind !== "svg") return
                                            var ctx = getContext("2d")
                                            Logic.drawSvgToCanvas(ctx, modelData, width, height)
                                        }
                                        onAvailableChanged: if (available && visible) requestPaint()
                                        onSvgBlockChanged: if (visible) requestPaint()
                                        onWidthChanged: if (visible) requestPaint()
                                        onHeightChanged: if (visible) requestPaint()
                                        Component.onCompleted: if (visible) requestPaint()
                                    }

                                    Image {
                                        id: rImgItem
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
                                        id: rTxtItem
                                        visible: modelData.kind !== "image" && modelData.kind !== "svg"
                                        width: parent.width
                                        textFormat: Text.RichText
                                        wrapMode: Text.WordWrap
                                        color: browserWin.pageFg
                                        linkColor: browserWin.pageLink
                                        font.family: host ? host.sans : "Avenir Next"
                                        font.pixelSize: Math.round(px(15) * ((browserWin.activeTab ? browserWin.activeTab.zoomPercent : 100) / 100.0))
                                        lineHeight: 1.45
                                        text: modelData.html ? modelData.html : ""
                                        onLinkActivated: function(link) {
                                            var s = String(link || "").trim()
                                            if (!s) return
                                            if (Logic.isExternalHttpsUrl(s)) {
                                                browserWin.pendingExternalUrl = s
                                                return
                                            }
                                            var pd = browserWin.activeTab ? browserWin.activeTab.pageData : null
                                            if (pd && pd.downloads) {
                                                var dls = Logic.toArray(pd.downloads)
                                                for (var i = 0; i < dls.length; i++) {
                                                    if (dls[i] && dls[i].href === s && dls[i].cid) {
                                                        var pin = dls[i].sha256 || Logic.findPinnedSha256(dls[i].cid, dls[i].path || "", pd)
                                                        browserWin.startSiteDownload("", dls[i].cid, dls[i].path || "", dls[i].filename || dls[i].label || "download.lgx", pin)
                                                        return
                                                    }
                                                }
                                            }
                                            browserWin.navigateInActiveTab(s, true)
                                        }
                                    }
                                }
                            }

                            // Reader Mode Downloads Card
                            Rectangle {
                                id: rDlCard
                                readonly property var dls: (browserWin.activeTab && browserWin.activeTab.pageData) ? Logic.toArray(browserWin.activeTab.pageData.downloads) : []
                                visible: dls.length > 0
                                Layout.fillWidth: true
                                implicitHeight: rDlCol.implicitHeight + px(20)
                                radius: px(10)
                                color: host ? host.card : "#171f2d"
                                border.color: host ? host.line : "#2b364a"

                                ColumnLayout {
                                    id: rDlCol
                                    anchors.fill: parent; anchors.margins: px(10); spacing: px(8)
                                    Text { text: "Downloads"; color: host ? host.dim : "#8a99ad"; font.bold: true; font.pixelSize: px(12) }
                                    Repeater {
                                        model: rDlCard.dls
                                        delegate: RowLayout {
                                            required property var modelData
                                            Layout.fillWidth: true; spacing: px(8)
                                            Text {
                                                Layout.fillWidth: true
                                                text: (modelData.filename || modelData.label || "file") + (modelData.cid ? ("  (" + Logic.shortHash(modelData.cid, 10, 6) + ")") : "")
                                                color: host ? host.ink : "#e6edf7"
                                                font.family: host ? host.mono : "Menlo"
                                                font.pixelSize: px(11)
                                                elide: Text.ElideMiddle
                                            }
                                            Rectangle {
                                                implicitWidth: rSaveTxt.implicitWidth + px(16); height: px(26); radius: px(6)
                                                color: host ? host.brass : "#e5a93b"
                                                Text { id: rSaveTxt; anchors.centerIn: parent; text: "Save"; color: host ? host.slate : "#0f141d"; font.bold: true; font.pixelSize: px(11) }
                                                MouseArea {
                                                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                                    onClicked: browserWin.startSiteDownload(
                                                        browserWin.activeTab ? browserWin.activeTab.loopbackToken : "",
                                                        modelData.cid || "",
                                                        modelData.path || "",
                                                        modelData.filename || modelData.label || "download.lgx",
                                                        modelData.sha256 || Logic.findPinnedSha256(modelData.cid || "", modelData.path || "", browserWin.activeTab ? browserWin.activeTab.pageData : null)
                                                    )
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Error Card: "No such page"
                Rectangle {
                    visible: browserWin.activeTab !== null && !!browserWin.activeTab.notFoundState
                    anchors.fill: parent
                    color: host ? host.slate : "#0f141d"

                    Rectangle {
                        anchors.centerIn: parent
                        width: Math.min(parent.width - px(48), px(540))
                        implicitHeight: nfCardCol.implicitHeight + px(36)
                        radius: px(12); color: host ? host.card : "#171f2d"; border.color: host ? host.line : "#2b364a"

                        ColumnLayout {
                            id: nfCardCol
                            anchors.fill: parent; anchors.margins: px(18); spacing: px(10)
                            Text { text: "No such page"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(18); font.bold: true }
                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WordWrap
                                color: host ? host.dim : "#8a99ad"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(12)
                                text: (browserWin.activeTab && browserWin.activeTab.notFoundState)
                                    ? (browserWin.activeTab.notFoundState.singlePage
                                        ? ("Path " + browserWin.activeTab.notFoundState.requestedPath + " does not exist (single-page site).")
                                        : ("Path " + browserWin.activeTab.notFoundState.requestedPath + " was not found on " + browserWin.activeTab.notFoundState.siteBase + "."))
                                    : ""
                            }
                            Rectangle {
                                implicitWidth: nfBtnTxt.implicitWidth + px(20); height: px(32); radius: px(7); color: host ? host.brass : "#e5a93b"
                                Text {
                                    id: nfBtnTxt; anchors.centerIn: parent
                                    text: (browserWin.activeTab && browserWin.activeTab.notFoundState) ? ("Back to " + browserWin.activeTab.notFoundState.siteBase + "/") : "Back to root"
                                    color: host ? host.slate : "#0f141d"; font.bold: true; font.pixelSize: px(12)
                                }
                                MouseArea {
                                    anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                    onClicked: if (browserWin.activeTab && browserWin.activeTab.notFoundState) {
                                        browserWin.navigateInActiveTab(browserWin.activeTab.notFoundState.siteBase + "/", true)
                                    }
                                }
                            }
                        }
                    }
                }

                // Error Card: "Storage fetch failed" (with CID, path, and Retry)
                Rectangle {
                    visible: browserWin.activeTab !== null && !browserWin.activeTab.notFoundState && !!browserWin.activeTab.storageError
                    anchors.fill: parent
                    color: host ? host.slate : "#0f141d"

                    Rectangle {
                        anchors.centerIn: parent
                        width: Math.min(parent.width - px(48), px(580))
                        implicitHeight: seCardCol.implicitHeight + px(36)
                        radius: px(12); color: host ? host.card : "#171f2d"; border.color: host ? host.alarm : "#dc2626"

                        ColumnLayout {
                            id: seCardCol
                            anchors.fill: parent; anchors.margins: px(18); spacing: px(10)
                            Text { text: "Storage fetch failed"; color: host ? host.alarm : "#dc2626"; font.pixelSize: px(17); font.bold: true }
                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WrapAnywhere
                                color: host ? host.ink : "#e6edf7"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(11)
                                text: (browserWin.activeTab && browserWin.activeTab.storageError)
                                    ? ("Path: " + browserWin.activeTab.storageError.path + (browserWin.activeTab.storageError.cid ? ("\nCID:  " + browserWin.activeTab.storageError.cid) : ""))
                                    : ""
                            }
                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WordWrap
                                color: host ? host.dim : "#8a99ad"; font.pixelSize: px(12)
                                text: (browserWin.activeTab && browserWin.activeTab.storageError) ? browserWin.activeTab.storageError.message : ""
                            }
                            RowLayout {
                                spacing: px(8)
                                Rectangle {
                                    implicitWidth: seRetryTxt.implicitWidth + px(22); height: px(32); radius: px(7); color: host ? host.brass : "#e5a93b"
                                    Text { id: seRetryTxt; anchors.centerIn: parent; text: "Retry"; color: host ? host.slate : "#0f141d"; font.bold: true; font.pixelSize: px(12) }
                                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: if (browserWin.activeTab) browserWin.navigateInActiveTab(browserWin.activeTab.url, false) }
                                }
                            }
                        }
                    }
                }

                // LNS Name has no website published yet
                Rectangle {
                    visible: browserWin.activeTabNoSite
                    anchors.fill: parent
                    color: host ? host.slate : "#0f141d"

                    Rectangle {
                        anchors.centerIn: parent
                        width: Math.min(parent.width - px(48), px(520))
                        implicitHeight: nsCol.implicitHeight + px(36)
                        radius: px(12); color: host ? host.card : "#171f2d"; border.color: host ? host.line : "#2b364a"
                        ColumnLayout {
                            id: nsCol
                            anchors.fill: parent; anchors.margins: px(18); spacing: px(8)
                            Text { text: (browserWin.activeTab && browserWin.activeTab.siteInfo) ? browserWin.activeTab.siteInfo.display : ""; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(18); font.bold: true }
                            Text {
                                visible: !!(browserWin.activeTab && browserWin.activeTab.siteInfo && browserWin.activeTab.siteInfo.bio)
                                text: (browserWin.activeTab && browserWin.activeTab.siteInfo) ? browserWin.activeTab.siteInfo.bio : ""
                                color: host ? host.dim : "#8a99ad"; wrapMode: Text.WordWrap; Layout.fillWidth: true
                            }
                            Text { text: "This LNS name has no website published yet."; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(12) }
                        }
                    }
                }

                // New Tab Page (Bookmarks & Recently Opened Sites)
                Rectangle {
                    visible: browserWin.activeTabIsNewTab
                    anchors.fill: parent
                    color: host ? host.slate : "#0f141d"

                    Flickable {
                        anchors.fill: parent; anchors.margins: px(28)
                        contentWidth: width; contentHeight: ntCol.implicitHeight; clip: true

                        ColumnLayout {
                            id: ntCol
                            width: Math.min(parent.width, px(720))
                            anchors.horizontalCenter: parent.horizontalCenter
                            spacing: px(18)

                            Text { text: "New Tab — LNS Browser"; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(20); font.bold: true }
                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WordWrap; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(12)
                                text: "Enter an LNS address (nameswallet/browser, lns://helloworld) or cid:// in the address bar above. Sites load in an isolated loopback origin with strict CSP, verified SHA-256 bytes, and zero external network access."
                            }

                            // Recent Sites
                            ColumnLayout {
                                visible: host && Logic.toArray(host.recentSites).length > 0
                                Layout.fillWidth: true; spacing: px(8)
                                Text { text: "Recently Opened Sites"; color: host ? host.dim : "#8a99ad"; font.bold: true; font.pixelSize: px(12) }
                                Flow {
                                    Layout.fillWidth: true; spacing: px(8)
                                    Repeater {
                                        model: host ? Logic.toArray(host.recentSites) : []
                                        delegate: Rectangle {
                                            required property var modelData
                                            implicitWidth: ntRecTxt.implicitWidth + px(22); height: px(34); radius: px(8)
                                            color: host ? host.card : "#171f2d"; border.color: host ? host.line : "#2b364a"
                                            Text { id: ntRecTxt; anchors.centerIn: parent; text: modelData.siteBase; color: host ? host.ink : "#e6edf7"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(12) }
                                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.navigateInActiveTab(modelData.siteBase, true) }
                                        }
                                    }
                                }
                            }

                            // Bookmarks
                            ColumnLayout {
                                visible: host && Logic.toArray(host.bookmarks).length > 0
                                Layout.fillWidth: true; spacing: px(8)
                                Text { text: "Bookmarks"; color: host ? host.dim : "#8a99ad"; font.bold: true; font.pixelSize: px(12) }
                                Repeater {
                                    model: host ? Logic.toArray(host.bookmarks) : []
                                    delegate: Rectangle {
                                        required property var modelData
                                        Layout.fillWidth: true; height: px(36); radius: px(8)
                                        color: host ? host.card : "#171f2d"; border.color: host ? host.line : "#2b364a"
                                        RowLayout {
                                            anchors.fill: parent; anchors.leftMargin: px(12); anchors.rightMargin: px(12); spacing: px(8)
                                            Text { text: "★"; color: host ? host.brass : "#e5a93b"; font.pixelSize: px(12) }
                                            Text { text: modelData.title || modelData.url; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(12); font.bold: true }
                                            Text { Layout.fillWidth: true; text: modelData.url; color: host ? host.dim : "#8a99ad"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(11); elide: Text.ElideMiddle }
                                        }
                                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.navigateInActiveTab(modelData.url, true) }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Docked Right Drawer: Verified Badge Inspector
            Rectangle {
                visible: browserWin.verifiedDrawerOpen && browserWin.activeTabHasSite
                Layout.preferredWidth: px(320)
                Layout.fillHeight: true
                color: host ? host.card : "#171f2d"
                border.color: host ? host.line : "#2b364a"

                ColumnLayout {
                    anchors.fill: parent; anchors.margins: px(12); spacing: px(8)
                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Verified Site Inspector"; color: host ? host.ink : "#e6edf7"; font.bold: true; font.pixelSize: px(13); Layout.fillWidth: true }
                        Rectangle {
                            width: px(22); height: px(22); radius: px(4); color: host ? host.raised : "#202b3d"
                            Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(10) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.verifiedDrawerOpen = false }
                        }
                    }

                    Flickable {
                        Layout.fillWidth: true; Layout.fillHeight: true
                        contentWidth: width; contentHeight: verCol.implicitHeight; clip: true

                        ColumnLayout {
                            id: verCol
                            width: parent.width; spacing: px(8)

                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WrapAnywhere
                                color: browserWin.activeTabVerified ? (host ? host.good : "#16a34a") : (host ? host.dim : "#8a99ad")
                                font.bold: true; font.pixelSize: px(12)
                                text: browserWin.activeTabVerified
                                    ? "✓ Verified against on-chain LNS commitment"
                                    : "Unpinned CID (no SHA-256 commitment in record)"
                            }
                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WrapAnywhere
                                color: host ? host.ink : "#e6edf7"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(11)
                                text: "Site:   " + (browserWin.activeTab ? browserWin.activeTab.siteBase : "")
                                    + "\nMode:   " + browserWin.activeTabMode
                                    + "\nOrigin: " + (browserWin.activeTab && browserWin.activeTab.loopbackOrigin ? browserWin.activeTab.loopbackOrigin : "(Reader Mode)")
                                    + (browserWin.activeTab && browserWin.activeTab.rootCid ? ("\nRoot CID:\n" + browserWin.activeTab.rootCid) : "")
                                    + (browserWin.activeTab && browserWin.activeTab.rootSha256 ? ("\nRoot SHA-256:\n" + browserWin.activeTab.rootSha256) : "")
                            }

                            Text { text: "Active Security Policy"; color: host ? host.dim : "#8a99ad"; font.bold: true; font.pixelSize: px(11) }
                            Text {
                                Layout.fillWidth: true; wrapMode: Text.WordWrap
                                color: host ? host.dim : "#8a99ad"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(10)
                                text: (browserWin.activeTab && browserWin.activeTab.siteStats && browserWin.activeTab.siteStats.csp)
                                    ? browserWin.activeTab.siteStats.csp
                                    : "Zero JS Reader Mode · Zero external network"
                            }

                            Text {
                                text: "Verified Files Loaded (" + browserWin.activeVerifiedFiles.length + ")"
                                color: host ? host.dim : "#8a99ad"; font.bold: true; font.pixelSize: px(11)
                            }
                            Repeater {
                                model: browserWin.activeVerifiedFiles
                                delegate: Rectangle {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    implicitHeight: vfTxt.implicitHeight + px(10)
                                    radius: px(6); color: host ? host.slate : "#0f141d"; border.color: host ? host.line : "#2b364a"
                                    Text {
                                        id: vfTxt
                                        anchors.fill: parent; anchors.margins: px(5)
                                        wrapMode: Text.WrapAnywhere
                                        color: host ? host.ink : "#e6edf7"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(10)
                                        text: (modelData.verified ? "✓ " : "• ") + modelData.path
                                            + "\n  " + Logic.shortHash(modelData.sha256 || "", 12, 8) + " · " + (modelData.size || 0) + " B"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Docked Right Drawer: Bookmarks & History
            Rectangle {
                visible: browserWin.libraryDrawerOpen
                Layout.preferredWidth: px(300)
                Layout.fillHeight: true
                color: host ? host.card : "#171f2d"
                border.color: host ? host.line : "#2b364a"

                ColumnLayout {
                    anchors.fill: parent; anchors.margins: px(10); spacing: px(8)

                    RowLayout {
                        Layout.fillWidth: true; spacing: px(6)
                        Rectangle {
                            implicitWidth: bmTabTxt.implicitWidth + px(14); height: px(26); radius: px(6)
                            color: browserWin.libraryTab === "bookmarks" ? (host ? host.brass : "#e5a93b") : (host ? host.raised : "#202b3d")
                            Text { id: bmTabTxt; anchors.centerIn: parent; text: "Bookmarks"; color: browserWin.libraryTab === "bookmarks" ? (host ? host.slate : "#0f141d") : (host ? host.ink : "#e6edf7"); font.pixelSize: px(11); font.bold: browserWin.libraryTab === "bookmarks" }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.libraryTab = "bookmarks" }
                        }
                        Rectangle {
                            implicitWidth: histTabTxt.implicitWidth + px(14); height: px(26); radius: px(6)
                            color: browserWin.libraryTab === "history" ? (host ? host.brass : "#e5a93b") : (host ? host.raised : "#202b3d")
                            Text { id: histTabTxt; anchors.centerIn: parent; text: "History"; color: browserWin.libraryTab === "history" ? (host ? host.slate : "#0f141d") : (host ? host.ink : "#e6edf7"); font.pixelSize: px(11); font.bold: browserWin.libraryTab === "history" }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.libraryTab = "history" }
                        }
                        Item { Layout.fillWidth: true }
                        Rectangle {
                            visible: browserWin.libraryTab === "history" && host && Logic.toArray(host.browsingHistory).length > 0
                            implicitWidth: clrHistTxt.implicitWidth + px(10); height: px(24); radius: px(5)
                            color: host ? host.raised : "#202b3d"
                            Text { id: clrHistTxt; anchors.centerIn: parent; text: "Clear"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(10) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: if (host) host.clearBrowsingHistory() }
                        }
                        Rectangle {
                            width: px(22); height: px(22); radius: px(4); color: host ? host.raised : "#202b3d"
                            Text { anchors.centerIn: parent; text: "✕"; color: host ? host.dim : "#8a99ad"; font.pixelSize: px(10) }
                            MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: browserWin.libraryDrawerOpen = false }
                        }
                    }

                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: px(4)
                        model: host
                            ? (browserWin.libraryTab === "bookmarks" ? Logic.toArray(host.bookmarks) : Logic.toArray(host.browsingHistory))
                            : []
                        delegate: Rectangle {
                            required property var modelData
                            width: ListView.view.width
                            height: px(42); radius: px(6)
                            color: host ? host.slate : "#0f141d"; border.color: host ? host.line : "#2b364a"
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: px(6); spacing: 2
                                Text { Layout.fillWidth: true; text: modelData.title || modelData.url; color: host ? host.ink : "#e6edf7"; font.pixelSize: px(11); font.bold: true; elide: Text.ElideRight }
                                Text { Layout.fillWidth: true; text: modelData.url; color: host ? host.dim : "#8a99ad"; font.family: host ? host.mono : "Menlo"; font.pixelSize: px(10); elide: Text.ElideMiddle }
                            }
                            MouseArea {
                                anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                                onClicked: browserWin.navigateInActiveTab(modelData.url, true)
                            }
                        }
                    }
                }
            }
        }
    }
}
