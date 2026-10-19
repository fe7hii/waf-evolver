"""
validators.py
Category-specific validation that closes the gap between "bypassed the WAF"
and "a genuinely working exploit".

Three levels:
1. STATIC  - no dependencies; structural checks (regex/parsing).
2. ACTIVE  - sends extra confirmation probes (boolean/time differential for
   SQLi) through a prober callback. This proves CONTROL over the query, not
   just that an error was triggered. Strongest non-browser proof for SQLi.
3. DYNAMIC - for XSS, renders in a real headless Chromium and observes an
   actual JS dialog firing (requires Playwright).
"""
import difflib
import logging
import re
import urllib.parse

logger = logging.getLogger("waf_evolve.validators")

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


_VALID_SCRIPT_TAG = re.compile(
    r"<\s*script\b[^>]*>.*?</\s*script\s*>", re.IGNORECASE | re.DOTALL
)
_VALID_EVENT_HANDLER = re.compile(
    r"<\s*[a-z][a-z0-9]*\b[^>]*\bon[a-z]+\s*=\s*['\"]?[^'\">]+", re.IGNORECASE
)
_VALID_JAVASCRIPT_URI = re.compile(
    r"(?:href|src)\s*=\s*['\"]?\s*javascript:", re.IGNORECASE
)
_VALID_SVG_ONLOAD = re.compile(
    r"<\s*svg\b[^>]*\bonload\s*=", re.IGNORECASE
)


def xss_signature(payload: str) -> str:
    """A distinctive fragment of the payload used to ATTRIBUTE an executable
    structure in the response to our payload (not to the app's own markup)."""
    m = re.search(r"(?:alert|confirm|prompt)\s*\([^)]*\)", payload, re.IGNORECASE)
    if m:
        return m.group(0)
    m = re.search(r"on[a-z]+\s*=\s*[^\s>]+", payload, re.IGNORECASE)
    if m:
        return m.group(0)
    toks = re.findall(r"[A-Za-z0-9]{3,}", payload)
    return max(toks, key=len) if toks else payload


def xss_reflection_context(response_text: str, payload: str) -> str:
    """Best-effort: where does the payload reflect? html | attribute | script
    | comment | none. Helps explain/triage a finding."""
    sig = xss_signature(payload)
    idx = response_text.find(sig)
    if idx < 0 and payload:
        idx = response_text.find(payload)
    if idx < 0:
        return "none"
    before = response_text[max(0, idx - 200):idx].lower()
    last_script = before.rfind("<script")
    last_script_end = before.rfind("</script")
    if last_script > last_script_end:
        return "script"
    last_comment = before.rfind("<!--")
    last_comment_end = before.rfind("-->")
    if last_comment > last_comment_end:
        return "comment"
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        return "attribute"
    return "html"


def validate_xss_static(response_text: str, payload: str) -> tuple[bool, str]:
    """True only if the payload forms a structure that WOULD execute AND that
    structure is attributable to our payload (its signature appears inside the
    matched region) - this avoids matching the application's own scripts."""
    sig = xss_signature(payload).lower()

    def attributed(pattern, label):
        for m in pattern.finditer(response_text):
            if sig and sig in m.group(0).lower():
                return True, f"attributed {label} (contains payload signature {sig!r})"
        return False, None

    for pattern, label in (
        (_VALID_SCRIPT_TAG, "valid <script> tag"),
        (_VALID_SVG_ONLOAD, "valid <svg onload=...>"),
        (_VALID_EVENT_HANDLER, "valid event handler (onXXX=)"),
        (_VALID_JAVASCRIPT_URI, "valid javascript: URI"),
    ):
        ok, reason = attributed(pattern, label)
        if ok:
            return True, reason
    return False, "no executable structure attributable to the payload (encoded, broken, or only the app's own markup)"


class BrowserSession:
    """A single reused Playwright/Chromium instance for the whole GA run."""

    def __init__(self, timeout_ms: int = 2000, proxy: str = None, ignore_https_errors: bool = False):
        self.timeout_ms = timeout_ms
        self.proxy = proxy
        self.ignore_https_errors = ignore_https_errors
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None

    @property
    def available(self) -> bool:
        return PLAYWRIGHT_AVAILABLE and self._page is not None

    def __enter__(self):
        if not PLAYWRIGHT_AVAILABLE:
            return self
        try:
            self._playwright = sync_playwright().start()
            launch_kwargs = {"headless": True}
            if self.proxy:
                launch_kwargs["proxy"] = {"server": self.proxy}
            self._browser = self._playwright.chromium.launch(**launch_kwargs)
            self._context = self._browser.new_context(ignore_https_errors=self.ignore_https_errors)
            self._page = self._context.new_page()
        except Exception as e:
            logger.warning(f"Could not start a browser ({e}); dynamic validation unavailable, falling back to static.")
            self._page = None
        return self

    def __exit__(self, *args):
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()

    def _watch_dialogs(self):
        state = {"value": False, "message": ""}

        def on_dialog(dialog):
            state["value"] = True
            state["message"] = dialog.message
            try:
                dialog.dismiss()
            except Exception:
                pass

        return state, on_dialog

    def check(self, response_text: str) -> tuple[bool, str]:
        """Static-render mode: renders the captured response body and observes
        whether a JS dialog fires."""
        if not PLAYWRIGHT_AVAILABLE or self._page is None:
            return False, "Playwright not installed or session not started"

        state, on_dialog = self._watch_dialogs()
        html_content = response_text
        if "<html" not in html_content.lower():
            html_content = f"<html><body>{html_content}</body></html>"
        try:
            self._page.on("dialog", on_dialog)
            self._page.set_content(html_content, timeout=self.timeout_ms)
            self._page.wait_for_timeout(200)
            self._page.remove_listener("dialog", on_dialog)
            if state["value"]:
                return True, f"REAL JS EXECUTION PROVEN (rendered) - dialog: {state['message']!r}"
            return False, "page rendered but no JS dialog was triggered"
        except Exception as e:
            return False, f"dynamic validation error: {e}"

    def check_live(self, url, method, param, payload, headers=None, stored=False) -> tuple[bool, str]:
        """Live mode: drives a real browser to the actual target with the
        payload, so real parsing and any server-set CSP apply - the strongest
        proof. GET navigates directly; POST auto-submits a form. When `stored`
        is set, the payload is assumed already persisted and the browser just
        visits `url` (second-order / stored XSS)."""
        if not PLAYWRIGHT_AVAILABLE or self._page is None:
            return False, "Playwright not installed or session not started"

        state, on_dialog = self._watch_dialogs()
        try:
            if headers:
                try:
                    self._page.set_extra_http_headers({str(k): str(v) for k, v in headers.items()})
                except Exception:
                    pass
            self._page.on("dialog", on_dialog)
            if stored:
                self._page.goto(url, timeout=self.timeout_ms + 3000, wait_until="load")
            elif (method or "GET").upper() == "GET":
                sep = "&" if "?" in url else "?"
                full = url + sep + urllib.parse.urlencode({param: payload})
                self._page.goto(full, timeout=self.timeout_ms + 3000, wait_until="load")
            else:
                form = (
                    "<html><body><form id='f' method='POST' action="
                    + '"' + url.replace('"', "&quot;") + '">'
                    + f"<input name='{param}' value=\"{payload.replace(chr(34), '&quot;')}\">"
                    + "</form><script>document.getElementById('f').submit()</script></body></html>"
                )
                self._page.set_content(form, timeout=self.timeout_ms)
                self._page.wait_for_timeout(500)
            self._page.wait_for_timeout(250)
            self._page.remove_listener("dialog", on_dialog)
            mode_label = "stored" if stored else (method or "GET").upper()
            if state["value"]:
                return True, f"REAL JS EXECUTION PROVEN (live {mode_label}) - dialog: {state['message']!r}"
            return False, "live navigation done but no JS dialog was triggered"
        except Exception as e:
            return False, f"live dynamic validation error: {e}"


def validate_xss_dynamic(response_text: str, timeout_ms: int = 3000) -> tuple[bool, str]:
    if not PLAYWRIGHT_AVAILABLE:
        return False, "Playwright not installed, dynamic validation skipped"
    with BrowserSession(timeout_ms=timeout_ms) as session:
        return session.check(response_text)


KNOWN_FILE_SIGNATURES = {
    "/etc/passwd": [
        re.compile(r"root:.*:0:0:", re.IGNORECASE),
        re.compile(r"/bin/(ba)?sh"),
    ],
    "/etc/shadow": [
        re.compile(r"root:\$\d\$"),
    ],
    "win.ini": [
        re.compile(r"\[fonts\]", re.IGNORECASE),
        re.compile(r"\[extensions\]", re.IGNORECASE),
    ],
    "php_source": [
        re.compile(r"<\?php"),
        re.compile(r"<\?=\s"),
    ],
}


def validate_lfi(response_text: str) -> tuple[bool, str]:
    for file_hint, patterns in KNOWN_FILE_SIGNATURES.items():
        matches = [p for p in patterns if p.search(response_text)]
        if matches:
            return True, f"real file-content signature found ({file_hint}): {len(matches)} pattern(s) matched"
    if re.search(r"[A-Za-z0-9+/]{100,}={0,2}", response_text):
        return True, "possible base64-encoded file content (php://filter?), MANUAL CHECK REQUIRED"
    return False, "no known file-content signature (may be only a path reflection)"


SQL_ERROR_SIGNATURES = [
    re.compile(r"sql syntax", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"you have an error in your sql", re.IGNORECASE),
    re.compile(r"ORA-\d{5}"),
    re.compile(r"PostgreSQL.*ERROR", re.IGNORECASE),
    re.compile(r"SQLite3?::", re.IGNORECASE),
    re.compile(r"SQLITE_ERROR", re.IGNORECASE),
    re.compile(r"sqlite3\.OperationalError", re.IGNORECASE),
    re.compile(r"near \".*\": syntax error", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
]


def validate_sqli(response_text: str) -> tuple[bool, str]:
    matches = [p.pattern for p in SQL_ERROR_SIGNATURES if p.search(response_text)]
    if matches:
        return True, f"real SQL error signature: {matches[0]}"
    return False, "no SQL error signature (not blocked, but no proof of injection)"


def encoding_depth(payload: str) -> int:
    """Number of percent-encode layers on top of the plain form."""
    depth, s = 0, payload
    for _ in range(6):
        if "%" not in s:
            break
        try:
            dec = urllib.parse.unquote(s)
        except Exception:
            break
        if dec == s:
            break
        s, depth = dec, depth + 1
    return depth


def _reencode(logical: str, depth: int) -> str:
    out = logical
    for _ in range(depth):
        out = urllib.parse.quote(out, safe="")
    return out


_TAUTOLOGY = re.compile(r"(['\"]?)(\d+)(['\"]?)\s*=\s*(['\"]?)(\d+)(['\"]?)")
_SLEEPY = re.compile(r"(sleep|benchmark|pg_sleep|waitfor\s+delay)", re.IGNORECASE)


def looks_injectable_sqli(logical: str) -> bool:
    """Cheap structural gate so we only spend active probes on plausible payloads."""
    if "'" not in logical and '"' not in logical:
        return False
    return bool(_TAUTOLOGY.search(logical) or _SLEEPY.search(logical)
                or re.search(r"\bunion\b", logical, re.IGNORECASE)
                or re.search(r"\bor\b|\band\b", logical, re.IGNORECASE))


def _make_boolean_siblings(logical: str):
    """Return (true_variant, false_variant) differing only in truth value, or
    None. Builds a definitely-TRUE (n=n) and a definitely-FALSE (n!=n+1)
    comparison, preserving whatever quoting the operands used."""
    m = _TAUTOLOGY.search(logical)
    if not m:
        return None
    ql, n1, qr, ql2, n2, qr2 = m.groups()
    true_cmp = f"{ql}{n1}{qr}={ql2}{n1}{qr2}"
    false_cmp = f"{ql}{n1}{qr}={ql2}{int(n1) + 1}{qr2}"
    true_variant = logical[:m.start()] + true_cmp + logical[m.end():]
    false_variant = logical[:m.start()] + false_cmp + logical[m.end():]
    return true_variant, false_variant


def _make_time_siblings(logical: str):
    """Return (fast_variant sleep(0), slow_variant sleep(SLOW)), or None."""
    m = re.search(r"(sleep|pg_sleep)\s*\(\s*\d+(\.\d+)?\s*\)", logical, re.IGNORECASE)
    if not m:
        return None
    fast = logical[:m.start()] + re.sub(r"\d+(\.\d+)?", "0", m.group(0), count=1) + logical[m.end():]
    slow = logical[:m.start()] + re.sub(r"\d+(\.\d+)?", str(TIME_SLOW_SEC), m.group(0), count=1) + logical[m.end():]
    return fast, slow


TIME_SLOW_SEC = 3
TIME_MARGIN_SEC = 1.8
BOOL_DIFF_MAX_RATIO = 0.95


def confirm_sqli_active(prober, payload: str, baseline_stats: dict) -> tuple[bool, str]:
    """Actively confirm a SQLi by differential probing.

    prober(raw_payload) -> requests.Response (already handles delay/budget).
    Returns (confirmed, reason). Confirmation means the query's behavior
    changed in a controlled, logic-dependent way - i.e. real injection,
    not merely a triggered error.
    """
    logical, depth = payload, encoding_depth(payload)
    for _ in range(depth):
        logical = urllib.parse.unquote(logical)

    if not looks_injectable_sqli(logical):
        return False, "not structurally injectable, active probe skipped"

    time_sib = _make_time_siblings(logical)
    if time_sib:
        fast_p, slow_p = _reencode(time_sib[0], depth), _reencode(time_sib[1], depth)
        base_elapsed = (baseline_stats or {}).get("median_elapsed", 0.0) or 0.0
        margin = max(TIME_MARGIN_SEC, base_elapsed * 3 + 1.0)
        deltas = []
        ok = True
        for _ in range(2):
            r_fast = prober(fast_p)
            r_slow = prober(slow_p)
            if r_fast is None or r_slow is None \
               or r_fast.status_code in (403, 406) or r_slow.status_code in (403, 406):
                ok = False
                break
            deltas.append(r_slow.elapsed.total_seconds() - r_fast.elapsed.total_seconds())
        if ok and deltas and all(d >= margin for d in deltas):
            avg = sum(deltas) / len(deltas)
            return True, (f"TIME-BASED blind SQLi confirmed: sleep({TIME_SLOW_SEC}) delayed response "
                          f"by ~{avg:.2f}s vs sleep(0) across {len(deltas)} trials (margin {margin:.2f}s)")

    bool_sib = _make_boolean_siblings(logical)
    if bool_sib:
        true_p, false_p = _reencode(bool_sib[0], depth), _reencode(bool_sib[1], depth)
        r_true = prober(true_p)
        r_false = prober(false_p)
        if r_true is not None and r_false is not None \
           and r_true.status_code not in (403, 406) and r_false.status_code not in (403, 406):
            ratio = difflib.SequenceMatcher(None, r_true.text, r_false.text).ratio()
            base_text = (baseline_stats or {}).get("text", "")
            true_vs_base = difflib.SequenceMatcher(None, r_true.text, base_text).ratio() if base_text else 0
            if ratio < BOOL_DIFF_MAX_RATIO:
                return True, (f"BOOLEAN-based blind SQLi confirmed: TRUE and FALSE conditions "
                              f"produced different responses (similarity {ratio:.2f}, "
                              f"true-vs-baseline {true_vs_base:.2f})")

    return False, "active probe ran but no controlled boolean/time difference observed"


def validate(category: str, response_text: str, payload: str, use_dynamic: bool = False,
             prober=None, baseline_stats=None):
    """category: 'xss' | 'lfi' | 'sqli' | 'generic'. Returns (is_valid, reason)."""
    if category == "xss":
        if use_dynamic and PLAYWRIGHT_AVAILABLE:
            valid, reason = validate_xss_dynamic(response_text)
            if valid:
                return valid, reason
        return validate_xss_static(response_text, payload)

    elif category == "lfi":
        return validate_lfi(response_text)

    elif category == "sqli":
        if prober is not None:
            confirmed, reason = confirm_sqli_active(prober, payload, baseline_stats or {})
            if confirmed:
                return True, reason
        return validate_sqli(response_text)

    else:
        return None, "generic category - no specific validation"
