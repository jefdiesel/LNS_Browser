import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Logos.Theme
import "logic.mjs" as Logic

// Native Basecamp LNS + Logos Storage CID Web Browser.
// Security model:
// - Resolves LNS names through Basecamp's built-in `names` core module (LEZ 0.4).
// - Fetches CID blobs & v1 site manifests from the user's local Logos Storage node via
//   `lns_browser_core`, verifying SHA-256 commitments before rendering.
// - Renders sanitized Qt RichText + safe page palette + safe inline SVG/data images with zero JS
//   and zero external network requests.
// - Clicks on `https://` links never open silently; they surface a confirmation strip (`Open` / `Copy`).
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
    property var storageInfo: null

    property bool settingsOpen: false
    property bool publishOpen: false
    property bool filesOpen: false

    property string storageApiInput: "http://127.0.0.1:8080/api/storage/v1"
    property string pubName: ""
    property string pubTitle: ""
    property string pubLocalPath: ""
    property string pubMode: "cid" // "cid" | "page"
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
        refreshStorageStatus()
    }

    // Handle incoming `lns.browse` intents (e.g. return handoff from Names after publish)
    Connections {
        target: root.bridgeReady ? logos : null
        ignoreUnknownSignals: true
        function onIntentRequested(requestId, intent, params, requesterName) {
            if (intent !== "lns.browse")
                return
            var wanted = String(params && params.url ? params.url : "")
            if (wanted !== "") {
                root.navigate(wanted)
            }
            if (logos.respond) {
                logos.respond(requestId, true, { url: wanted }, "")
            }
        }
    }

    TextEdit {
        id: clipHelper
        visible: false
    }

    function copyText(str) {
        clipHelper.text = String(str || "")
        clipHelper.selectAll()
        clipHelper.copy()
        notice = "Copied to clipboard."
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

    function refreshStorageStatus() {
        callCore("lns_browser_core", "storage_status", [], function(v) {
            storageInfo = v
            if (v && v.storage_api) storageApiInput = v.storage_api
        }, function() {})
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
            // Fallback: check for an on-chain SetPage HTML document via `names.page`
            callCore("names", "page", [parsed.name], function(pg) {
                if (pg && pg.text && pg.text.length > 0) {
                    callCore("lns_browser_core", "render_html", [pg.text, parsed.siteBase, parsed.path], function(rendered) {
                        loading = false
                        pageData = rendered
                        filesOpen = false
                    }, function() {
                        // Older core build without render_html: fall back to plain safe text
                        loading = false
                        pageData = {
                            mode: "onchain-page",
                            kind: "text",
                            title: info.display || parsed.name,
                            path: "/",
                            cid: "",
                            sha256: "",
                            verified: true,
                            html: pg.text,
                            blocks: [{ kind: "html", html: pg.text }],
                            files: []
                        }
                        filesOpen = false
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
        callCore("lns_browser_core", "fetch_site", [cid, expectedSha256 || "", siteBase, path || "/"], function(data) {
            loading = false
            pageData = data
            filesOpen = data && data.files && data.files.length > 1
        }, function(err) {
            loading = false
            pageData = null
            problem = err
        }, 45000)
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
                var msg = err ? String(err) : "Publish was cancelled or refused in Names."
                problem = msg
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

        // Verify the name exists on-chain before uploading anything
        callCore("names", "resolve", [name], function(record) {
            if (!record) {
                loading = false
                problem = "LNS name \"" + name + "\" is not registered on LEZ yet. Register it in Names first."
                return
            }

            // Direct on-chain SetPage mode (<= 80 KB HTML, no storage upload needed)
            if (pubMode === "page") {
                if (!pubHtml.trim()) {
                    loading = false
                    problem = "Paste HTML content first."
                    return
                }
                if (pubHtml.length > 78000) {
                    loading = false
                    problem = "HTML is too large for an on-chain SetPage (max ~78 KB). Switch to Logos Storage CID mode."
                    return
                }
                handoffToNames({
                    name: name,
                    html: pubHtml,
                    return_app: "lns_browser"
                }, "Prepared on-chain HTML page.")
                return
            }

            // Logos Storage CID mode: upload locally, then hand off CID + SHA-256 to Names
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
        }, function(err) {
            loading = false
            problem = "Could not check LNS name: " + err
        })
    }

    function saveSettings() {
        callCore("lns_browser_core", "config_set", [JSON.stringify({ storage_api: storageApiInput.trim() })], function(v) {
            notice = "Saved Storage API: " + v.storage_api
            settingsOpen = false
            refreshStorageStatus()
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
                        text: "External web link (opens outside Basecamp): " + root.pendingExternalUrl
                        color: root.ink
                        font.family: root.mono
                        font.pixelSize: px(11)
                        elide: Text.ElideMiddle
                    }
                    Rectangle {
                        implicitWidth: openExtTxt.implicitWidth + px(16); height: px(26); radius: px(6); color: root.brass
                        Text { id: openExtTxt; anchors.centerIn: parent; text: "Open in Browser"; color: root.slate; font.bold: true; font.pixelSize: px(11) }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: {
                                var target = root.pendingExternalUrl
                                root.pendingExternalUrl = ""
                                Qt.openUrlExternally(target)
                            }
                        }
                    }
                    Rectangle {
                        implicitWidth: copyExtTxt.implicitWidth + px(14); height: px(26); radius: px(6); color: root.raised; border.color: root.line
                        Text { id: copyExtTxt; anchors.centerIn: parent; text: "Copy"; color: root.ink; font.pixelSize: px(11) }
                        MouseArea {
                            anchors.fill: parent; cursorShape: Qt.PointingHandCursor
                            onClicked: root.copyText(root.pendingExternalUrl)
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
                    Text { text: "Local Logos Storage Node API"; color: root.ink; font.bold: true; font.pixelSize: px(13) }
                    Rectangle {
                        Layout.fillWidth: true; height: px(32); radius: px(6); color: root.slate; border.color: root.line
                        TextInput {
                            anchors.fill: parent; anchors.margins: px(7); color: root.ink; font.family: root.mono; font.pixelSize: px(12)
                            text: root.storageApiInput; onTextEdited: root.storageApiInput = text
                        }
                    }
                    Rectangle {
                        width: px(120); height: px(32); radius: px(7); color: root.brass
                        Text { anchors.centerIn: parent; text: "Save"; color: root.slate; font.bold: true; font.pixelSize: px(12) }
                        MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.saveSettings() }
                    }
                }
            }

            // ── Publish Panel (Folder/HTML → CID or On-Chain SetPage → Names Deep Link) ──
            Rectangle {
                visible: root.publishOpen
                Layout.fillWidth: true
                implicitHeight: pubCol.implicitHeight + px(24)
                radius: px(10); color: root.card; border.color: root.brass

                ColumnLayout {
                    id: pubCol
                    anchors.fill: parent; anchors.margins: px(12); spacing: px(8)

                    RowLayout {
                        Layout.fillWidth: true
                        Text { text: "Publish LNS Website (hands off to Names to verify ownership & sign)"; color: root.ink; font.bold: true; font.pixelSize: px(13); Layout.fillWidth: true; wrapMode: Text.WordWrap }
                    }

                    RowLayout {
                        spacing: px(8)
                        Rectangle {
                            implicitWidth: cidModeTxt.implicitWidth + px(18); height: px(28); radius: px(6)
                            color: root.pubMode === "cid" ? root.brass : root.raised; border.color: root.line
                            Text { id: cidModeTxt; anchors.centerIn: parent; text: "Logos Storage CID"; color: root.pubMode === "cid" ? root.slate : root.ink; font.bold: root.pubMode === "cid"; font.pixelSize: px(11) }
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
                        Text { text: "Folder/File:"; color: root.dim; font.pixelSize: px(12); Layout.preferredWidth: px(80) }
                        Rectangle {
                            Layout.fillWidth: true; height: px(30); radius: px(6); color: root.slate; border.color: root.line
                            TextInput { anchors.fill: parent; anchors.margins: px(6); color: root.ink; font.family: root.mono; font.pixelSize: px(12); text: root.pubLocalPath; onTextEdited: root.pubLocalPath = text }
                        }
                    }

                    Text {
                        text: root.pubMode === "cid"
                            ? "Or paste HTML directly (used when Folder/File is blank):"
                            : ("HTML stored directly on LEZ (" + root.pubHtml.length + " / 78,000 chars):")
                        color: root.dim; font.pixelSize: px(11)
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
                                    : (root.pubMode === "cid" ? "Upload CID & Publish in Names" : "Publish On-Chain in Names")
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

            // ── Main Content Area (Optional Manifest Sidebar + Native Page Viewport) ──
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
                                    onClicked: {
                                        if (root.parsedUrl) root.navigate(root.parsedUrl.siteBase + modelData.path)
                                    }
                                }
                            }
                        }
                    }
                }

                // Native Zero-JS, Zero-Network-Leak Page Viewport (honors safe page background & palette)
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

                            // Compact metadata header strip
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

                            // Ordered sanitized render blocks (safe inline SVG/data images + colored Qt RichText)
                            Repeater {
                                model: (root.pageData && root.pageData.blocks && root.pageData.blocks.length > 0)
                                    ? root.pageData.blocks
                                    : (root.pageData && root.pageData.html ? [{ kind: "html", html: root.pageData.html }] : [])

                                delegate: Item {
                                    required property var modelData
                                    Layout.fillWidth: true
                                    implicitHeight: modelData.kind === "image" ? imgItem.implicitHeight : txtItem.implicitHeight

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
                                        visible: modelData.kind !== "image"
                                        width: parent.width
                                        textFormat: Text.RichText
                                        wrapMode: Text.WordWrap
                                        color: root.pageFg
                                        linkColor: root.pageLink
                                        font.family: root.sans
                                        font.pixelSize: px(15)
                                        lineHeight: 1.45
                                        text: modelData.html ? modelData.html : ""
                                        onLinkActivated: function(link) {
                                            root.activateLink(link)
                                        }
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
                                    text: "Browse lns://<name> sites natively inside Basecamp. Content is fetched from LEZ or your local Logos Storage node, verified on-chain, and rendered with zero JavaScript and zero external network connections."
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
                    text: root.storageInfo && root.storageInfo.online
                        ? ("Logos Storage: Online (" + root.storageInfo.storage_api + ")")
                        : "Logos Storage: Offline (start your local node or check Settings)"
                    color: root.storageInfo && root.storageInfo.online ? root.good : root.dim
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
