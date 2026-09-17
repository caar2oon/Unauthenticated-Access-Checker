# -*- coding: utf-8 -*-
# =============================================================================
# UnauthenticatedAccessChecker - Burp Suite Extension  v1.3.0
# =============================================================================
# v1.3.0 improvements
# --------------------
#  1. FILTER BAR  -- Filter by result state (All / PROTECTED / ACCESSIBLE /
#     POSSIBLY_ACCESSIBLE / INCONCLUSIVE / NOT_TESTED / ERROR / SKIPPED)
#     plus a free-text search box (host, method, endpoint, notes).
#     Both filters combine with AND.  TableRowSorter drives all filtering so
#     the underlying model is never touched -- existing row-index cache stays
#     valid.
#
#  2. HISTORY IMPORT FIX -- Previous version silently dropped entries when
#     getResponse() returned None (request-only entries in history).  Now
#     request-only entries are still captured for endpoint discovery; the
#     response is filled in later if seen.  Also added per-tool source label
#     (Proxy / Repeater / Scanner) and removed the early-exit on scope_only
#     during import so all history is enumerated first, then scope-filtered.
#
#  3. METHOD SKIP LIST -- Configurable set of HTTP methods to NEVER capture
#     or check.  Defaults: OPTIONS, HEAD (noise).  POST/PUT/PATCH/DELETE stay
#     in the table but are gated by allow_state_changing at check time.
#     Users can also add POST to skip_methods to exclude it entirely from
#     discovery.
# =============================================================================

from burp import (
    IBurpExtender, IHttpListener, ITab,
    IExtensionStateListener, IBurpExtenderCallbacks,
    IMessageEditorController, IContextMenuFactory
)

from javax.swing import (
    JPanel, JScrollPane, JTable, JButton, JLabel, JTextField,
    JCheckBox, JSpinner, SpinnerNumberModel, JTextArea, JTabbedPane,
    JSplitPane, JPopupMenu, JMenuItem, JFileChooser, JOptionPane,
    SwingUtilities, BorderFactory, Box, JProgressBar, JComboBox, RowFilter
)
from javax.swing.table import (
    DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
)
from javax.swing.border import TitledBorder
from javax.swing.event import ListSelectionListener as _LSL, DocumentListener as _DL

from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints,
    FlowLayout, Color, Font, Dimension, Insets, Toolkit
)
from java.awt.datatransfer import StringSelection

import re
import difflib
import traceback
import codecs
from threading import RLock, Thread

# =============================================================================
# Constants
# =============================================================================

EXTENSION_NAME = "Unauthenticated Access Checker"
VERSION        = "1.1"

STATE_NOT_TESTED          = "NOT_TESTED"
STATE_PROTECTED           = "PROTECTED"
STATE_POSSIBLY_ACCESSIBLE = "POSSIBLY_ACCESSIBLE"
STATE_ACCESSIBLE          = "ACCESSIBLE"
STATE_ERROR               = "ERROR"
STATE_INCONCLUSIVE        = "INCONCLUSIVE"
STATE_SKIPPED             = "SKIPPED"

ALL_STATES = [
    "All",
    STATE_ACCESSIBLE,
    STATE_POSSIBLY_ACCESSIBLE,
    STATE_INCONCLUSIVE,
    STATE_NOT_TESTED,
    STATE_PROTECTED,
    STATE_ERROR,
    STATE_SKIPPED,
]

STATE_COLORS = {
    STATE_NOT_TESTED:          Color(210, 210, 210),
    STATE_PROTECTED:           Color(144, 238, 144),
    STATE_POSSIBLY_ACCESSIBLE: Color(255, 200,   0),
    STATE_ACCESSIBLE:          Color(255, 100, 100),
    STATE_ERROR:               Color(180, 180, 255),
    STATE_INCONCLUSIVE:        Color(210, 210, 210),
    STATE_SKIPPED:             Color(210, 210, 210),
}

# ---- Auth headers stripped by default ---------------------------------------
DEFAULT_AUTH_HEADERS = [
    "authorization", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-access-token",
    "x-session-token", "x-amz-security-token",
    "x-token", "x-id-token",
    "x-csrf-token-auth",
    "token", "bearer",
]

# ---- Auth cookies stripped by default ---------------------------------------
DEFAULT_AUTH_COOKIES = [
    "session", "sessionid", "sess", "sessid",
    "auth", "authenticated",
    "token", "access_token", "id_token", "refresh_token",
    "jwt", "jwttoken", "authtoken", "auth_token",
    "rememberme", "remember_token", "remember_me",
    "user_session", "logged_in",
    "api_key", "apikey",
    "phpsessid", "jsessionid",
    "asp.net_sessionid", "aspnet_sessionstate",
    ".aspnetcore.cookies", ".aspnetcore.session",
    "connect.sid", "_session_id",
    "sessionid", "laravel_session",
    "spring_security_remember_me_cookie",
    "wordpress_logged_in", "wordpress_sec", "wp-settings",
    "sso_token", "oauth_token", "oidc",
]

# ---- Methods skipped at capture time (not stored at all) --------------------
# POST/DELETE are NOT here by default -- they are stored but gated at check time.
DEFAULT_SKIP_METHODS = {"OPTIONS", "HEAD"}

# ---- CSRF patterns kept by default ------------------------------------------
CSRF_PATTERNS = [
    re.compile(r'^csrf',      re.IGNORECASE),
    re.compile(r'^xsrf',      re.IGNORECASE),
    re.compile(r'_csrf$',     re.IGNORECASE),
    re.compile(r'csrftoken$', re.IGNORECASE),
    re.compile(r'xsrftoken$', re.IGNORECASE),
]

# ---- File extensions to skip at capture time --------------------------------
# Stored as the runtime-configurable self.skip_extensions set.
# Users can add/remove entries in Settings without reloading the extension.
DEFAULT_SKIP_EXTENSIONS = {
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp', '.tiff',
    # Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    # Styles / source maps
    '.css', '.map', '.less', '.scss',
    # Documents / archives
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
    # Media
    '.mp4', '.mp3', '.avi', '.mov', '.webm',
}

# ---- Login body patterns ----------------------------------------------------
LOGIN_BODY_PATTERNS = [
    re.compile(r'login\s+required',                          re.IGNORECASE),
    re.compile(r'please\s+log\s*in',                         re.IGNORECASE),
    re.compile(r'authentication\s+required',                  re.IGNORECASE),
    re.compile(r'\bunauthorized\b',                           re.IGNORECASE),
    re.compile(r'access\s+denied',                            re.IGNORECASE),
    re.compile(r'"authenticated"\s*:\s*false',                re.IGNORECASE),
    re.compile(r'"logged_?in"\s*:\s*false',                   re.IGNORECASE),
    re.compile(r'"isLoggedIn"\s*:\s*false',                   re.IGNORECASE),
    re.compile(r'"error"\s*:\s*"unauthenticated"',            re.IGNORECASE),
    re.compile(r'"status"\s*:\s*"unauthenticated"',           re.IGNORECASE),
    re.compile(r'"message"\s*:\s*"[^"]*unauthorized[^"]*"',   re.IGNORECASE),
    re.compile(r'"message"\s*:\s*"[^"]*not\s+authenticated[^"]*"', re.IGNORECASE),
    re.compile(r'session\s+expired',                          re.IGNORECASE),
    re.compile(r'you\s+must\s+(be\s+)?logged?\s*in',         re.IGNORECASE),
    re.compile(r'<title>[^<]*login[^<]*</title>',             re.IGNORECASE),
    re.compile(r'<title>[^<]*sign\s*in[^<]*</title>',         re.IGNORECASE),
    re.compile(r'window\.location.*login',                    re.IGNORECASE),
]

# ---- Path normalisation -----------------------------------------------------
UUID_RE    = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE)
NUMERIC_RE = re.compile(r'^\d+$')
MONGO_RE   = re.compile(r'^[0-9a-f]{24}$', re.IGNORECASE)
HEX_ID_RE  = re.compile(r'^[0-9a-f]{24,}$', re.IGNORECASE)

# ---- Table column indices ---------------------------------------------------
COL_HOST       = 0
COL_METHOD     = 1
COL_ENDPOINT   = 2
COL_SOURCE     = 3
COL_AUTH_ST    = 4
COL_UNAUTH_ST  = 5
COL_RESULT     = 6
COL_AUTH_LEN   = 7
COL_UNAUTH_LEN = 8
COL_NOTES      = 9

COL_NAMES = ["Host", "Method", "Endpoint", "Source",
             "Auth Status", "Unauth Status", "Result",
             "Auth Len", "Unauth Len", "Notes"]


# =============================================================================
# Module-level Java proxy classes (must NOT be inner classes in Jython 2.7)
# =============================================================================

class _ResultRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value,
                                      selected, focused, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, selected, focused, row, col)
        if not selected:
            comp.setBackground(STATE_COLORS.get(str(value), Color.WHITE))
            comp.setForeground(Color.BLACK)
        return comp


class _RowSelectionListener(_LSL):
    def __init__(self, ext):
        self.ext = ext

    def valueChanged(self, e):
        if not e.getValueIsAdjusting():
            self.ext._onRowSelected()


class _SearchDocListener(_DL):
    """Triggers live search filtering whenever the text field changes."""
    def __init__(self, ext):
        self.ext = ext

    def insertUpdate(self, e):
        self.ext._applyFilters()

    def removeUpdate(self, e):
        self.ext._applyFilters()

    def changedUpdate(self, e):
        self.ext._applyFilters()


# =============================================================================
# BurpExtender
# =============================================================================

class BurpExtender(IBurpExtender, IHttpListener, ITab,
                   IExtensionStateListener, IMessageEditorController,
                   IContextMenuFactory):

    # =========================================================================
    # Burp entry point
    # =========================================================================
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        self.lock      = RLock()

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerContextMenuFactory(self)

        # ---- Runtime config -------------------------------------------------
        self.scope_only             = True
        self.auto_check_get         = False
        self.allow_state_changing   = False
        self.keep_csrf              = True
        self.cookie_substring_match = True
        self.auth_headers_set       = set(DEFAULT_AUTH_HEADERS)
        self.auth_cookies_set       = set(DEFAULT_AUTH_COOKIES)
        # Methods to silently ignore during capture (never stored or checked)
        self.skip_methods           = set(DEFAULT_SKIP_METHODS)
        # File extensions to silently ignore during capture
        self.skip_extensions        = set(DEFAULT_SKIP_EXTENSIONS)

        # ---- Data stores ----------------------------------------------------
        self.endpoints   = {}   # (host, method, norm_path) -> record dict
        self.ep_rows     = {}   # key -> model row index
        self.in_progress = set()

        # ---- UI -------------------------------------------------------------
        self.panel = JPanel(BorderLayout())
        self._buildUI()

        callbacks.customizeUiComponent(self.panel)
        callbacks.addSuiteTab(self)
        print("[+] " + EXTENSION_NAME + " v" + VERSION + " loaded. Created by caar2oon")

    def extensionUnloaded(self):
        print("[-] " + EXTENSION_NAME + " unloaded.")

    # =========================================================================
    # ITab
    # =========================================================================
    def getTabCaption(self):
        return "Unauth Checker"

    def getUiComponent(self):
        return self.panel

    # =========================================================================
    # IMessageEditorController
    # =========================================================================
    def getHttpService(self):
        rec = self._selectedRecord()
        return rec["service"] if rec else None

    def getRequest(self):
        rec = self._selectedRecord()
        return rec["auth_req"] if rec else None

    def getResponse(self):
        rec = self._selectedRecord()
        return rec["auth_resp"] if rec else None

    # =========================================================================
    # EDT helper
    # =========================================================================
    def runOnEdt(self, func):
        if SwingUtilities.isEventDispatchThread():
            func()
        else:
            SwingUtilities.invokeLater(func)

    # =========================================================================
    # UI construction
    # =========================================================================
    def _buildUI(self):
        tabs = JTabbedPane()
        tabs.addTab("Endpoints", self._buildEndpointPanel())
        tabs.addTab("Settings",  self._buildSettingsPanel())
        tabs.addTab("About",     self._buildAboutPanel())
        self.panel.add(tabs, BorderLayout.CENTER)

    # ---- Endpoint tab -------------------------------------------------------
    def _buildEndpointPanel(self):
        panel = JPanel(BorderLayout())

        # -- Top area: toolbar + filter bar stacked --
        topArea = JPanel(BorderLayout())

        # Toolbar row
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 4, 4))
        self.progressBar = JProgressBar()
        self.progressBar.setStringPainted(True)
        self.progressBar.setPreferredSize(Dimension(150, 22))

        toolbar.add(JButton("Import History",  actionPerformed=self._onImportHistory))
        toolbar.add(self.progressBar)
        toolbar.add(Box.createHorizontalStrut(6))
        toolbar.add(JButton("Check Selected",  actionPerformed=self._onCheckSelected))
        toolbar.add(JButton("Check All",       actionPerformed=self._onCheckAll))
        toolbar.add(JButton("Cancel",          actionPerformed=self._onCancelChecks))
        toolbar.add(Box.createHorizontalStrut(6))
        toolbar.add(JButton("Export CSV",      actionPerformed=self._onExport))
        toolbar.add(JButton("Clear All",       actionPerformed=self._onClear))
        self.countLabel = JLabel("  0 endpoints")
        toolbar.add(self.countLabel)

        # Filter row
        filterBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        filterBar.setBorder(BorderFactory.createEtchedBorder())

        filterBar.add(JLabel("Result Filter:"))
        self.stateCombo = JComboBox(ALL_STATES)
        self.stateCombo.setPreferredSize(Dimension(170, 24))
        # ActionListener via actionPerformed keyword arg
        self.stateCombo.addActionListener(
            _ComboActionListener(self._applyFilters))
        filterBar.add(self.stateCombo)

        filterBar.add(Box.createHorizontalStrut(12))
        filterBar.add(JLabel("Search:"))
        self.searchField = JTextField(22)
        self.searchField.setToolTipText(
            "Live search across Host, Method, Endpoint, Source, Notes")
        self.searchField.getDocument().addDocumentListener(
            _SearchDocListener(self))
        filterBar.add(self.searchField)

        filterBar.add(JButton("Clear Filters",
                               actionPerformed=self._onClearFilters))

        topArea.add(toolbar,   BorderLayout.NORTH)
        topArea.add(filterBar, BorderLayout.SOUTH)
        panel.add(topArea, BorderLayout.NORTH)

        # -- Table --
        self.tableModel = DefaultTableModel(COL_NAMES, 0)
        self.tableModel.setColumnCount(len(COL_NAMES))

        self.table = JTable(self.tableModel)
        self.table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self.table.setFillsViewportHeight(True)

        for i, w in enumerate([160, 65, 270, 80, 80, 90, 160, 70, 80, 250]):
            self.table.getColumnModel().getColumn(i).setPreferredWidth(w)

        self.table.getColumnModel().getColumn(COL_RESULT).setCellRenderer(
            _ResultRenderer())

        # TableRowSorter drives both column sorting AND our result/search filters
        self.sorter = TableRowSorter(self.tableModel)
        self.table.setRowSorter(self.sorter)

        self._addPopupMenu(self.table)
        self.table.getSelectionModel().addListSelectionListener(
            _RowSelectionListener(self))

        tableScroll = JScrollPane(self.table)
        tableScroll.setPreferredSize(Dimension(0, 300))

        # -- Detail pane --
        detailTabs = JTabbedPane()
        self.authReqViewer    = self.callbacks.createMessageEditor(self, False)
        self.authRespViewer   = self.callbacks.createMessageEditor(self, False)
        self.unauthReqViewer  = self.callbacks.createMessageEditor(self, False)
        self.unauthRespViewer = self.callbacks.createMessageEditor(self, False)
        detailTabs.addTab("Auth Request",    self.authReqViewer.getComponent())
        detailTabs.addTab("Auth Response",   self.authRespViewer.getComponent())
        detailTabs.addTab("Unauth Request",  self.unauthReqViewer.getComponent())
        detailTabs.addTab("Unauth Response", self.unauthRespViewer.getComponent())
        self.notesArea = JTextArea(4, 60)
        detailTabs.addTab("Notes", JScrollPane(self.notesArea))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailTabs)
        split.setDividerLocation(320)
        split.setResizeWeight(0.5)
        panel.add(split, BorderLayout.CENTER)
        return panel

    # ---- Settings tab -------------------------------------------------------
    def _buildSettingsPanel(self):
        outer = JPanel(BorderLayout())
        outer.setBorder(TitledBorder("Settings"))
        center = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.fill   = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(3, 6, 3, 6)
        row = [0]

        def addRow(lbl, widget):
            gbc.gridx = 0; gbc.gridy = row[0]; gbc.weightx = 0.3; gbc.gridwidth = 1
            center.add(JLabel(lbl), gbc)
            gbc.gridx = 1; gbc.weightx = 0.7
            center.add(widget, gbc)
            row[0] += 1

        def addWide(widget):
            gbc.gridx = 0; gbc.gridy = row[0]; gbc.gridwidth = 2; gbc.weightx = 1.0
            center.add(widget, gbc)
            row[0] += 1

        self.chkScope       = JCheckBox("Only collect/check in-scope targets",
                                        self.scope_only)
        self.chkAutoGet     = JCheckBox("Auto-check GET requests on discovery",
                                        self.auto_check_get)
        self.chkStateChange = JCheckBox(
            "Allow active checks for POST / PUT / PATCH / DELETE",
            self.allow_state_changing)
        self.chkCsrf        = JCheckBox(
            "Preserve CSRF cookies/headers (recommended)", self.keep_csrf)
        self.chkSubstring   = JCheckBox(
            "Strip cookies whose name CONTAINS an auth keyword (recommended)",
            self.cookie_substring_match)

        addRow("Scope:",           self.chkScope)
        addRow("Auto check:",      self.chkAutoGet)
        addRow("State-changing:",  self.chkStateChange)
        addRow("CSRF tokens:",     self.chkCsrf)
        addRow("Cookie matching:", self.chkSubstring)

        # Skip methods
        addWide(JLabel(
            "Methods to SKIP entirely (never captured or checked) -- one per line:"))
        self.skipMethodsArea = JTextArea(
            "\n".join(sorted(self.skip_methods)), 3, 40)
        self.skipMethodsArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.skipMethodsArea.setToolTipText(
            "e.g. OPTIONS, HEAD, POST  -- upper-case, one per line")
        addWide(JScrollPane(self.skipMethodsArea))

        addWide(JLabel(
            "File Extensions to SKIP (never captured) -- one per line, with dot:"))
        self.skipExtArea = JTextArea(
            "\n".join(sorted(self.skip_extensions)), 5, 40)
        self.skipExtArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self.skipExtArea.setToolTipText(
            "e.g. .png, .css, .pdf  -- include the dot, one per line")
        addWide(JScrollPane(self.skipExtArea))

        addWide(JLabel("Auth Headers to Strip (one per line, lower-case):"))
        self.headersArea = JTextArea(
            "\n".join(sorted(self.auth_headers_set)), 5, 40)
        self.headersArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        addWide(JScrollPane(self.headersArea))

        addWide(JLabel("Auth Cookies to Strip (one per line, lower-case):"))
        self.cookiesArea = JTextArea(
            "\n".join(sorted(self.auth_cookies_set)), 8, 40)
        self.cookiesArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        addWide(JScrollPane(self.cookiesArea))

        addWide(JButton("Apply Settings", actionPerformed=self._onApplySettings))

        outer.add(JScrollPane(center), BorderLayout.CENTER)
        return outer

    # ---- About tab ----------------------------------------------------------
    def _buildAboutPanel(self):
        area = JTextArea()
        area.setEditable(False)
        area.setFont(Font("Monospaced", Font.PLAIN, 12))
        area.setText(
            "=======================================================\n"
            "  " + EXTENSION_NAME + " v" + VERSION + "\n"
            "  Created by caar2oon\n"
            "=======================================================\n\n"
            "How to use:\n"
            "  1. Browse the target with Burp Proxy active.\n"
            "  2. Click 'Import History' to pull in existing traffic.\n"
            "  3. Use the Result Filter dropdown and Search box to focus on\n"
            "     specific states (e.g. ACCESSIBLE, POSSIBLY_ACCESSIBLE).\n"
            "  4. Select rows, click 'Check Selected' or 'Check All'.\n"
            "  5. Inspect the 'Unauth Request' tab to confirm session stripped.\n"
            "  6. Export to CSV for reporting.\n\n"
            "Filter bar:\n"
            "  Result Filter -- show only rows with a specific result state.\n"
            "  Search        -- live text search across host/method/endpoint/notes.\n"
            "  Both filters combine (AND).  Column headers are also clickable to sort.\n\n"
            "Method skip list (Settings):\n"
            "  Methods listed here are ignored at capture time -- not stored.\n"
            "  Default: OPTIONS, HEAD (high-noise, low-value for auth testing).\n"
            "  Add POST here to exclude POST requests entirely from discovery.\n\n"
            "Result states:\n"
            "  NOT_TESTED           No check run yet.\n"
            "  PROTECTED            401/403, login redirect, or body indicator.\n"
            "  POSSIBLY_ACCESSIBLE  Same status, partial body match -- review.\n"
            "  ACCESSIBLE           Status + body materially equivalent.\n"
            "  INCONCLUSIVE         Mixed signals -- manual review required.\n"
            "  ERROR                Network error or no response.\n"
            "  SKIPPED              State-changing method, safety lock on.\n\n"
            "For authorised security testing only.\n"
        )
        return JScrollPane(area)

    # ---- Context menu -------------------------------------------------------
    def _addPopupMenu(self, table):
        popup = JPopupMenu()
        popup.add(JMenuItem("Check Unauthenticated Access",
                            actionPerformed=lambda e: self._checkSelectedRows()))
        popup.add(JMenuItem("Send Auth Request to Repeater",
                            actionPerformed=lambda e: self._sendToRepeater(auth=True)))
        popup.add(JMenuItem("Send Unauth Request to Repeater",
                            actionPerformed=lambda e: self._sendToRepeater(auth=False)))
        popup.add(JMenuItem("Send Unauth Request to Intruder",
                            actionPerformed=lambda e: self._sendToIntruder()))
        popup.add(JMenuItem("Copy URL",
                            actionPerformed=lambda e: self._copyUrl()))
        popup.add(JMenuItem("Mark as False Positive",
                            actionPerformed=lambda e: self._markRow("FALSE_POSITIVE")))
        popup.add(JMenuItem("Mark as Confirmed",
                            actionPerformed=lambda e: self._markRow("CONFIRMED")))
        table.setComponentPopupMenu(popup)

    # =========================================================================
    # Filter logic (TableRowSorter)
    # =========================================================================
    def _applyFilters(self):
        """Build a combined RowFilter from the state combo + search text."""
        filters = []

        # 1. State filter
        selected = str(self.stateCombo.getSelectedItem())
        if selected and selected != "All":
            # Exact match on the Result column
            filters.append(
                RowFilter.regexFilter("^" + re.escape(selected) + "$",
                                      COL_RESULT))

        # 2. Free-text search across host / method / endpoint / source / notes
        txt = self.searchField.getText().strip()
        if txt:
            try:
                pattern = "(?i)" + re.escape(txt)
                filters.append(RowFilter.regexFilter(
                    pattern,
                    COL_HOST, COL_METHOD, COL_ENDPOINT, COL_SOURCE, COL_NOTES))
            except Exception:
                pass

        if not filters:
            self.sorter.setRowFilter(None)
        elif len(filters) == 1:
            self.sorter.setRowFilter(filters[0])
        else:
            self.sorter.setRowFilter(RowFilter.andFilter(filters))

        # Update count label to reflect visible rows
        visible = self.table.getRowCount()
        total   = self.tableModel.getRowCount()
        self.countLabel.setText(
            "  %d / %d endpoints" % (visible, total)
            if visible != total
            else "  %d endpoints" % total)

    def _onClearFilters(self, event):
        self.stateCombo.setSelectedIndex(0)   # "All"
        self.searchField.setText("")
        self.sorter.setRowFilter(None)
        self._applyFilters()

    # =========================================================================
    # IContextMenuFactory
    # =========================================================================
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return []
        def send():
            for msg in messages:
                self._processMessage(msg, source="ContextMenu")
        return [JMenuItem("Send to Unauth Checker",
                          actionPerformed=lambda e: send())]

    # =========================================================================
    # IHttpListener
    # =========================================================================
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Capture responses from Proxy only (live traffic)
        if toolFlag != IBurpExtenderCallbacks.TOOL_PROXY:
            return
        if messageIsRequest:
            return
        rec = self._processMessage(messageInfo, source="Proxy")
        if rec and self.auto_check_get and rec.get("result") == STATE_NOT_TESTED:
            if rec.get("method", "").upper() in ("GET",):
                self._submitCheck(rec)

    # =========================================================================
    # Core message processing
    # =========================================================================
    def _processMessage(self, messageInfo, source="Proxy"):
        """
        Extracts, deduplicates, and stores one endpoint from a
        IHttpRequestResponse.  Works for both live traffic and history import.

        History-import fix: we no longer require a response to store an entry.
        Request-only history entries (common for POST / redirected requests)
        are now captured and their response field is left None until seen later.
        """
        try:
            request = messageInfo.getRequest()
            if not request:
                return None
            service  = messageInfo.getHttpService()
            info     = self.helpers.analyzeRequest(service, request)
            url      = info.getUrl()
            method   = info.getMethod().upper()
            rawPath  = url.getPath() or "/"
            host     = service.getHost()
        except Exception:
            self.callbacks.printError(traceback.format_exc())
            return None

        # ---- Method skip list -----------------------------------------------
        # Skip entirely -- not stored, not shown, not checked.
        if method in self.skip_methods:
            return None

        # ---- Scope check ----------------------------------------------------
        try:
            if self.scope_only and not self.callbacks.isInScope(url):
                return None
        except Exception:
            return None

        # ---- Static resource filter -----------------------------------------
        if self._isStatic(rawPath):
            return None

        normPath = self._normalizePath(rawPath)
        key      = (host, method, normPath)

        # getResponse() returns None for request-only history entries --
        # that is fine; we store None and fill it in if we see it later.
        response = messageInfo.getResponse()

        with self.lock:
            if key in self.endpoints:
                rec    = self.endpoints[key]
                is_new = False
                # Fill in missing request / response if we now have them
                if rec.get("auth_req") is None:
                    rec["auth_req"] = request
                    rec["service"]  = service
                if rec.get("auth_resp") is None and response is not None:
                    rec["auth_resp"]   = response
                    rec["auth_status"] = self._statusOf(response)
                    rec["auth_len"]    = len(response)
            else:
                rec = {
                    "key":           key,
                    "host":          host,
                    "method":        method,
                    "path":          normPath,
                    "source":        source,
                    "service":       service,
                    "auth_req":      request,
                    "auth_resp":     response,              # may be None
                    "auth_status":   self._statusOf(response) if response else None,
                    "auth_len":      len(response) if response else None,
                    "unauth_req":    None,
                    "unauth_resp":   None,
                    "unauth_status": None,
                    "unauth_len":    None,
                    "result":        STATE_NOT_TESTED,
                    "notes":         "",
                }
                self.endpoints[key] = rec
                is_new = True

        rec_ref = rec
        if is_new:
            def addRow():
                r = self.tableModel.getRowCount()
                self.ep_rows[key] = r
                self.tableModel.addRow([
                    host, method, normPath, source,
                    str(rec_ref["auth_status"]) if rec_ref["auth_status"] else "-",
                    "-", STATE_NOT_TESTED,
                    str(rec_ref["auth_len"]) if rec_ref["auth_len"] else "-",
                    "-", ""
                ])
                self._updateCount()
                self._applyFilters()
            self.runOnEdt(addRow)
        else:
            self._refreshRow(key)

        # JS endpoint extraction
        if response is not None and self._isJS(rawPath):
            self._extractJSEndpoints(messageInfo, host)

        return rec

    # =========================================================================
    # Auth stripping
    # =========================================================================
    def _stripAuth(self, requestBytes):
        try:
            analyzed   = self.helpers.analyzeRequest(requestBytes)
            headers    = list(analyzed.getHeaders())
            bodyOffset = analyzed.getBodyOffset()
            body       = requestBytes[bodyOffset:]
        except Exception as e:
            self.callbacks.printError("_stripAuth parse error: " + str(e))
            return requestBytes, []

        newHeaders = []
        removed    = []

        for i, header in enumerate(headers):
            if i == 0:
                newHeaders.append(header)
                continue

            colonIdx = header.find(":")
            if colonIdx < 0:
                newHeaders.append(header)
                continue

            nameLower = header[:colonIdx].strip().lower()

            if nameLower in self.auth_headers_set:
                removed.append("Header:" + header[:colonIdx].strip())
                print("[UnAuth] STRIP header: " + header[:colonIdx].strip())
                continue

            if nameLower == "cookie":
                kept, removedCookies = self._filterCookies(header)
                for cn in removedCookies:
                    removed.append("Cookie:" + cn)
                    print("[UnAuth] STRIP cookie: " + cn)
                if kept and kept.strip() and kept.strip() != "Cookie:":
                    newHeaders.append(kept)
                else:
                    print("[UnAuth] All cookies stripped -- omitting Cookie header")
                continue

            newHeaders.append(header)

        try:
            rebuilt = self.helpers.buildHttpMessage(newHeaders, body)
        except Exception as e:
            self.callbacks.printError("buildHttpMessage error: " + str(e))
            return requestBytes, removed

        return rebuilt, removed

    def _filterCookies(self, cookieHeader):
        colonIdx  = cookieHeader.find(":")
        valuePart = cookieHeader[colonIdx + 1:] if colonIdx >= 0 else cookieHeader

        kept    = []
        removed = []

        for pair in valuePart.split(";"):
            pair = pair.strip()
            if not pair:
                continue

            eqIdx     = pair.find("=")
            name      = pair[:eqIdx].strip() if eqIdx >= 0 else pair.strip()
            nameLower = name.lower()

            # 1. CSRF -- keep
            if any(p.search(name) for p in CSRF_PATTERNS) and self.keep_csrf:
                kept.append(pair)
                continue

            # 2. Exact match
            if nameLower in self.auth_cookies_set:
                removed.append(name)
                continue

            # 3. Substring match
            if self.cookie_substring_match:
                matched = False
                for authName in self.auth_cookies_set:
                    if authName and authName in nameLower:
                        removed.append(name)
                        matched = True
                        break
                if matched:
                    continue

            kept.append(pair)

        rebuilt = ("Cookie: " + "; ".join(kept)) if kept else ""
        return rebuilt, removed

    # =========================================================================
    # Response comparison & classification
    # =========================================================================
    def _compareAndClassify(self, authResp, unauthResp, method):
        if authResp is None:
            return STATE_ERROR, "No authenticated response stored"
        if unauthResp is None:
            return STATE_ERROR, "No unauthenticated response received"

        try:
            authInfo   = self.helpers.analyzeResponse(authResp)
            unauthInfo = self.helpers.analyzeResponse(unauthResp)
        except Exception as e:
            return STATE_ERROR, "Response parse error: " + str(e)

        authStatus   = authInfo.getStatusCode()
        unauthStatus = unauthInfo.getStatusCode()

        unauthLocation = None
        wwwAuth        = None
        for h in unauthInfo.getHeaders():
            hl = h.lower()
            if hl.startswith("location:"):
                unauthLocation = h[9:].strip()
            elif hl.startswith("www-authenticate:"):
                wwwAuth = h[17:].strip()

        try:
            authBodyStr   = self.helpers.bytesToString(
                authResp[authInfo.getBodyOffset():])
        except Exception:
            authBodyStr   = ""

        try:
            unauthBodyStr = self.helpers.bytesToString(
                unauthResp[unauthInfo.getBodyOffset():])
        except Exception:
            unauthBodyStr = ""

        loginIndicator = self._hasLoginIndicator(unauthBodyStr)
        similarity     = self._similarity(authBodyStr, unauthBodyStr)

        # --- Decision tree ---
        if unauthStatus in (401, 403):
            return STATE_PROTECTED, "Unauth response: %d" % unauthStatus

        if wwwAuth:
            return STATE_PROTECTED, "WWW-Authenticate present"

        if unauthStatus in (301, 302, 303, 307, 308) and unauthLocation:
            loc = unauthLocation.lower()
            if any(kw in loc for kw in ("login", "signin", "auth", "session", "logon")):
                return STATE_PROTECTED, "Login redirect -> " + unauthLocation

        if loginIndicator:
            return STATE_PROTECTED, "Login indicator in unauth body"

        if unauthStatus and unauthStatus >= 500:
            return STATE_INCONCLUSIVE, "Unauth server error: %d" % unauthStatus

        if unauthStatus in (301, 302, 303, 307, 308):
            return STATE_INCONCLUSIVE, "Redirect (non-login): " + str(unauthLocation)

        if unauthStatus == authStatus:
            if similarity >= 0.90:
                return STATE_ACCESSIBLE, \
                    "Status+body match (sim=%.2f)" % similarity
            elif similarity >= 0.60:
                return STATE_POSSIBLY_ACCESSIBLE, \
                    "Same status, partial body (sim=%.2f)" % similarity
            else:
                return STATE_POSSIBLY_ACCESSIBLE, \
                    "Same status, bodies differ (sim=%.2f)" % similarity

        if authStatus and unauthStatus:
            return STATE_INCONCLUSIVE, \
                "Auth %d / Unauth %d" % (authStatus, unauthStatus)

        return STATE_INCONCLUSIVE, "Insufficient signals"

    def _hasLoginIndicator(self, bodyStr):
        sample = bodyStr[:8192]
        return any(p.search(sample) for p in LOGIN_BODY_PATTERNS)

    def _similarity(self, a, b):
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        try:
            return difflib.SequenceMatcher(None, a[:4096], b[:4096]).ratio()
        except Exception:
            la, lb = len(a), len(b)
            mx = max(la, lb)
            return float(min(la, lb)) / mx if mx > 0 else 1.0

    # =========================================================================
    # Check execution
    # =========================================================================
    def _submitCheck(self, rec):
        key = rec["key"]
        with self.lock:
            if key in self.in_progress:
                return
            if rec.get("auth_req") is None or rec.get("service") is None:
                rec["result"] = STATE_ERROR
                rec["notes"]  = "No original request captured"
                self._refreshRow(key)
                return
            self.in_progress.add(key)

        t = Thread(target=self._runCheck, args=(rec,))
        t.setDaemon(True)
        t.start()

    def _runCheck(self, rec):
        key = rec["key"]
        try:
            method = rec["method"].upper()

            if method in ("POST", "PUT", "PATCH", "DELETE") \
               and not self.allow_state_changing:
                rec["result"] = STATE_SKIPPED
                rec["notes"]  = "State-changing method -- enable in Settings"
                self._refreshRow(key)
                return

            unauthReq, removed = self._stripAuth(rec["auth_req"])
            if not removed:
                print("[UnAuth] WARNING: nothing stripped for %s%s -- "
                      "verify cookie names in Settings" % (rec["host"], rec["path"]))

            rec["unauth_req"] = unauthReq

            try:
                httpResult  = self.callbacks.makeHttpRequest(rec["service"], unauthReq)
                unauthResp  = httpResult.getResponse() if httpResult else None
            except Exception as e:
                rec["result"] = STATE_ERROR
                rec["notes"]  = "Request failed: " + str(e)
                self._refreshRow(key)
                return

            if unauthResp is None:
                rec["result"] = STATE_ERROR
                rec["notes"]  = "No response received"
                self._refreshRow(key)
                return

            unauthStatus = self._statusOf(unauthResp)
            unauthLen    = len(unauthResp)

            state, notes = self._compareAndClassify(
                rec["auth_resp"], unauthResp, method)

            if removed:
                notes += " | Stripped: " + ", ".join(removed[:8])
            else:
                notes += " | WARNING: nothing stripped"

            rec["unauth_resp"]   = unauthResp
            rec["unauth_status"] = unauthStatus
            rec["unauth_len"]    = unauthLen
            rec["result"]        = state
            rec["notes"]         = notes

            self._refreshRow(key)
            print("[UnAuth] %s %s%s -> %s/%s -> %s" % (
                method, rec["host"], rec["path"],
                rec["auth_status"], unauthStatus, state))

        except Exception as e:
            rec["result"] = STATE_ERROR
            rec["notes"]  = str(e)
            self.callbacks.printError(traceback.format_exc())
            self._refreshRow(key)
        finally:
            with self.lock:
                self.in_progress.discard(key)

    # =========================================================================
    # Table helpers
    # =========================================================================
    def _refreshRow(self, key):
        rec = self.endpoints.get(key)
        if rec is None:
            return
        r = rec
        def run():
            row = self.ep_rows.get(key)
            if row is None:
                return
            self.tableModel.setValueAt(r["host"],   row, COL_HOST)
            self.tableModel.setValueAt(r["method"], row, COL_METHOD)
            self.tableModel.setValueAt(r["path"],   row, COL_ENDPOINT)
            self.tableModel.setValueAt(r["source"], row, COL_SOURCE)
            self.tableModel.setValueAt(
                str(r["auth_status"])   if r["auth_status"]   else "-", row, COL_AUTH_ST)
            self.tableModel.setValueAt(
                str(r["unauth_status"]) if r["unauth_status"] else "-", row, COL_UNAUTH_ST)
            self.tableModel.setValueAt(r["result"], row, COL_RESULT)
            self.tableModel.setValueAt(
                str(r["auth_len"])   if r["auth_len"]   else "-", row, COL_AUTH_LEN)
            self.tableModel.setValueAt(
                str(r["unauth_len"]) if r["unauth_len"] else "-", row, COL_UNAUTH_LEN)
            self.tableModel.setValueAt(
                r["notes"][:120] if r["notes"] else "", row, COL_NOTES)
            # Re-apply filters so the row immediately appears/disappears
            self._applyFilters()
        self.runOnEdt(run)

    def _updateCount(self):
        total   = self.tableModel.getRowCount()
        visible = self.table.getRowCount()
        if visible != total:
            self.countLabel.setText("  %d / %d endpoints" % (visible, total))
        else:
            self.countLabel.setText("  %d endpoints" % total)

    def _selectedRecord(self):
        row = self.table.getSelectedRow()
        if row < 0:
            return None
        # table.getSelectedRow() is a VIEW index; convert to model index
        modelRow = self.table.convertRowIndexToModel(row)
        return self.endpoints.get(self._keyAtModelRow(modelRow))

    def _keyAtModelRow(self, modelRow):
        """Look up the endpoint key from a model-row index."""
        for key, r in self.ep_rows.items():
            if r == modelRow:
                return key
        try:
            return (
                self.tableModel.getValueAt(modelRow, COL_HOST),
                self.tableModel.getValueAt(modelRow, COL_METHOD),
                self.tableModel.getValueAt(modelRow, COL_ENDPOINT),
            )
        except Exception:
            return None

    def _keyAtRow(self, viewRow):
        """Convert a view-row index (sorted/filtered) to endpoint key."""
        try:
            modelRow = self.table.convertRowIndexToModel(viewRow)
            return self._keyAtModelRow(modelRow)
        except Exception:
            return None

    # =========================================================================
    # Path / type helpers
    # =========================================================================
    def _normalizePath(self, path):
        path = path.split("?")[0].split("#")[0]
        parts = path.split("/")
        out = []
        for seg in parts:
            if not seg:
                out.append(seg)
            elif UUID_RE.match(seg):
                out.append("{uuid}")
            elif MONGO_RE.match(seg):
                out.append("{objectId}")
            elif NUMERIC_RE.match(seg):
                out.append("{id}")
            elif HEX_ID_RE.match(seg):
                out.append("{hex_id}")
            else:
                out.append(seg)
        return "/".join(out) or "/"

    def _isStatic(self, path):
        low = path.lower().split("?")[0]
        return any(low.endswith(ext) for ext in self.skip_extensions)

    def _isJS(self, path):
        return path.lower().split("?")[0].endswith(".js")

    def _statusOf(self, responseBytes):
        try:
            return self.helpers.analyzeResponse(responseBytes).getStatusCode()
        except Exception:
            return None

    # =========================================================================
    # JS endpoint extraction
    # =========================================================================
    def _extractJSEndpoints(self, messageInfo, host):
        JS_XHR   = re.compile(
            r'\.open\s*\(\s*[\'\"](GET|POST|PUT|PATCH|DELETE)[\'\"]\s*,\s*[\'\"]([^\'\"]+)[\'\"]',
            re.IGNORECASE)
        JS_AXIOS = re.compile(
            r'axios\.(get|post|put|patch|delete)\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
            re.IGNORECASE)
        JS_FETCH = re.compile(
            r'fetch\s*\(\s*[\'\"`]([^\'\"` ]+)[\'\"`]', re.IGNORECASE)
        JS_METH  = re.compile(
            r'method\s*:\s*[\'\"]([A-Z]+)[\'\"]', re.IGNORECASE)
        JS_PATH  = re.compile(
            r'[\'\"](/(?:api|v\d+|rest|graphql|gql)[^\'\"\s]{0,150})[\'\"]',
            re.IGNORECASE)
        try:
            resp = messageInfo.getResponse()
            if resp is None:
                return
            text = self.helpers.bytesToString(resp)
        except Exception:
            return

        found = set()
        for m in JS_XHR.finditer(text):
            p = m.group(2)
            if p.startswith("/") and len(p) < 200:
                found.add((m.group(1).upper(), p))
        for m in JS_AXIOS.finditer(text):
            p = m.group(2)
            if p.startswith("/") and len(p) < 200:
                found.add((m.group(1).upper(), p))
        for m in JS_FETCH.finditer(text):
            p = m.group(1)
            if not p.startswith("/") or len(p) >= 200:
                continue
            ctx  = text[max(0, m.start()-50):min(len(text), m.end()+200)]
            mm   = JS_METH.search(ctx)
            found.add((mm.group(1).upper() if mm else "UNKNOWN", p))
        for m in JS_PATH.finditer(text):
            p = m.group(1)
            if len(p) < 200:
                found.add(("UNKNOWN", p))

        for method, rawPath in found:
            if method in self.skip_methods:
                continue
            normPath = self._normalizePath(rawPath)
            key      = (host, method, normPath)
            with self.lock:
                if key not in self.endpoints:
                    rec = {
                        "key": key, "host": host, "method": method,
                        "path": normPath, "source": "JS",
                        "service": None, "auth_req": None, "auth_resp": None,
                        "auth_status": None, "auth_len": None,
                        "unauth_req": None, "unauth_resp": None,
                        "unauth_status": None, "unauth_len": None,
                        "result": STATE_NOT_TESTED, "notes": "",
                    }
                    self.endpoints[key] = rec
                    def addJsRow(r=rec, k=key):
                        row = self.tableModel.getRowCount()
                        self.ep_rows[k] = row
                        self.tableModel.addRow([
                            r["host"], r["method"], r["path"], "JS",
                            "-", "-", STATE_NOT_TESTED, "-", "-", ""])
                        self._updateCount()
                        self._applyFilters()
                    self.runOnEdt(addJsRow)

    # =========================================================================
    # Button handlers
    # =========================================================================
    def _onImportHistory(self, event):
        def doImport():
            try:
                history = self.callbacks.getProxyHistory()
                total   = len(history)
                print("[UnAuth] Importing %d history entries..." % total)
                imported = [0]
                for i, entry in enumerate(history):
                    self._processMessage(entry, source="History")
                    imported[0] += 1
                    if total > 0 and i % 100 == 0:
                        pct = int(100.0 * i / total)
                        d, t = i, total
                        def prog(p=pct, d=d, t=t):
                            self.progressBar.setValue(p)
                            self.progressBar.setString("%d / %d" % (d, t))
                        self.runOnEdt(prog)
                n = imported[0]
                def finish():
                    self.progressBar.setValue(100)
                    self.progressBar.setString("Done (%d)" % n)
                    self._applyFilters()
                self.runOnEdt(finish)
                print("[UnAuth] Import done. %d entries processed, "
                      "%d unique endpoints." % (n, len(self.endpoints)))
            except Exception:
                self.callbacks.printError(traceback.format_exc())

        self.runOnEdt(lambda: (
            self.progressBar.setValue(0),
            self.progressBar.setString("Importing...")))
        t = Thread(target=doImport)
        t.setDaemon(True)
        t.start()

    def _onCheckSelected(self, event):
        self._checkSelectedRows()

    def _checkSelectedRows(self):
        rows = self.table.getSelectedRows()
        if not rows or len(rows) == 0:
            JOptionPane.showMessageDialog(self.panel, "Select one or more rows first.")
            return
        for viewRow in rows:
            key = self._keyAtRow(viewRow)
            if key:
                rec = self.endpoints.get(key)
                if rec:
                    self._submitCheck(rec)

    def _onCheckAll(self, event):
        with self.lock:
            recs = list(self.endpoints.values())
        if not recs:
            JOptionPane.showMessageDialog(self.panel, "No endpoints yet.")
            return
        sc  = [r for r in recs
               if r["method"].upper() in ("POST","PUT","PATCH","DELETE")]
        msg = "Check all %d endpoints?" % len(recs)
        if sc and not self.allow_state_changing:
            msg += "\n(%d state-changing will be skipped)" % len(sc)
        if JOptionPane.showConfirmDialog(
                self.panel, msg, "Confirm",
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION:
            for rec in recs:
                self._submitCheck(rec)

    def _onCancelChecks(self, event):
        with self.lock:
            self.in_progress.clear()

    def _onExport(self, event):
        fc = JFileChooser()
        if fc.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
            return
        path = fc.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".csv"):
            path += ".csv"
        with self.lock:
            recs = list(self.endpoints.values())
        try:
            f = codecs.open(path, "w", "utf-8")
            self._writeCsvRow(f, ["Host","Method","Endpoint","Source",
                                   "Auth Status","Unauth Status","Result",
                                   "Auth Len","Unauth Len","Notes"])
            for rec in recs:
                self._writeCsvRow(f, [
                    rec["host"], rec["method"], rec["path"], rec["source"],
                    str(rec["auth_status"]   or ""),
                    str(rec["unauth_status"] or ""),
                    rec["result"],
                    str(rec["auth_len"]   or ""),
                    str(rec["unauth_len"] or ""),
                    rec["notes"],
                ])
            f.close()
            JOptionPane.showMessageDialog(self.panel, "Exported to " + path)
        except Exception as e:
            JOptionPane.showMessageDialog(
                self.panel, "Export failed: " + str(e),
                "Error", JOptionPane.ERROR_MESSAGE)

    def _onClear(self, event):
        if JOptionPane.showConfirmDialog(
                self.panel, "Clear all endpoints?", "Confirm",
                JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION:
            return
        with self.lock:
            self.endpoints.clear()
            self.in_progress.clear()
        def run():
            self.ep_rows.clear()
            self.tableModel.setRowCount(0)
            self._updateCount()
            self._applyFilters()
        self.runOnEdt(run)

    def _onApplySettings(self, event):
        self.scope_only             = self.chkScope.isSelected()
        self.auto_check_get         = self.chkAutoGet.isSelected()
        self.allow_state_changing   = self.chkStateChange.isSelected()
        self.keep_csrf              = self.chkCsrf.isSelected()
        self.cookie_substring_match = self.chkSubstring.isSelected()
        self.skip_methods = set(
            m.strip().upper()
            for m in self.skipMethodsArea.getText().splitlines()
            if m.strip())
        self.skip_extensions = set(
            e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
            for e in self.skipExtArea.getText().splitlines()
            if e.strip())
        self.auth_headers_set = set(
            h.strip().lower()
            for h in self.headersArea.getText().splitlines() if h.strip())
        self.auth_cookies_set = set(
            c.strip().lower()
            for c in self.cookiesArea.getText().splitlines() if c.strip())
        JOptionPane.showMessageDialog(
            self.panel, "Settings applied.", "OK",
            JOptionPane.INFORMATION_MESSAGE)

    def _onRowSelected(self):
        rec = self._selectedRecord()
        if not rec:
            return
        self.authReqViewer.setMessage(   rec.get("auth_req"),    True)
        self.authRespViewer.setMessage(  rec.get("auth_resp"),   False)
        self.unauthReqViewer.setMessage( rec.get("unauth_req"),  True)
        self.unauthRespViewer.setMessage(rec.get("unauth_resp"), False)
        self.notesArea.setText(rec.get("notes", ""))

    def _sendToRepeater(self, auth=True):
        rec = self._selectedRecord()
        if not rec:
            return
        req = rec.get("auth_req") if auth else rec.get("unauth_req")
        svc = rec.get("service")
        if req is None or svc is None:
            JOptionPane.showMessageDialog(self.panel, "No request available.")
            return
        self.callbacks.sendToRepeater(
            svc.getHost(), svc.getPort(), svc.getProtocol() == "https",
            req, ("Auth " if auth else "Unauth ") + rec["path"])

    def _sendToIntruder(self):
        rec = self._selectedRecord()
        if not rec:
            return
        req = rec.get("unauth_req") or rec.get("auth_req")
        svc = rec.get("service")
        if req is None or svc is None:
            JOptionPane.showMessageDialog(self.panel, "No request available.")
            return
        self.callbacks.sendToIntruder(
            svc.getHost(), svc.getPort(), svc.getProtocol() == "https", req)

    def _copyUrl(self):
        rec = self._selectedRecord()
        if not rec:
            return
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            StringSelection(rec["method"] + " " + rec["host"] + rec["path"]),
            None)

    def _markRow(self, flag):
        rec = self._selectedRecord()
        if not rec:
            return
        prefix = "[FALSE POSITIVE] " if flag == "FALSE_POSITIVE" else "[CONFIRMED] "
        rec["notes"] = prefix + rec.get("notes", "")
        self._refreshRow(rec["key"])

    # =========================================================================
    # CSV helpers
    # =========================================================================
    def _csvEscape(self, val):
        val = "" if val is None else str(val)
        val = val.replace('"', '""')
        if any(c in val for c in (',', '"', '\n', '\r')):
            val = '"' + val + '"'
        return val

    def _writeCsvRow(self, handle, values):
        handle.write(",".join(self._csvEscape(v) for v in values) + "\n")


# =============================================================================
# Additional module-level Java proxy -- ActionListener for JComboBox
# Must be at module level for Jython 2.7 proxy generation.
# =============================================================================
from java.awt.event import ActionListener as _AL

class _ComboActionListener(_AL):
    def __init__(self, fn):
        self.fn = fn

    def actionPerformed(self, e):
        try:
            self.fn()
        except Exception:
            pass
